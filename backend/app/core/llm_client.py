"""LLM client wrapper for OpenAI-compatible protocol agents."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict

from openai import OpenAI

from .config import settings

logger = logging.getLogger(__name__)

_runtime = threading.local()

MAX_RETRIES = 5
RETRY_BASE_DELAY = 2.0


def get_client() -> OpenAI:
    client = getattr(_runtime, "client", None)
    api_key = getattr(_runtime, "api_key", settings.OPENAI_API_KEY)
    base_url = getattr(_runtime, "base_url", settings.OPENAI_BASE_URL)
    timeout = getattr(_runtime, "timeout", settings.OPENAI_TIMEOUT_SECONDS)
    client_key = (api_key, base_url, timeout)
    if client is None or getattr(_runtime, "client_key", None) != client_key:
        client = OpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=0,
        )
        _runtime.client = client
        _runtime.client_key = client_key
    return client


def reset_client() -> None:
    """Force the next request to rebuild the client from current settings."""
    _runtime.client = None


def set_runtime_config(
    *,
    api_key: str,
    base_url: str,
    model: str,
    timeout_seconds: float,
    stream: bool,
    temperature: float | None = None,
    top_p: float | None = None,
    max_tokens: int | None = None,
    max_retries: int | None = None,
    extra_body: dict | None = None,
) -> None:
    """Set thread-local LLM configuration for concurrent experiment runs."""
    _runtime.api_key = api_key
    _runtime.base_url = base_url
    _runtime.model = model
    _runtime.timeout = timeout_seconds
    _runtime.stream = stream
    _runtime.temperature = settings.OPENAI_TEMPERATURE if temperature is None else temperature
    _runtime.top_p = settings.OPENAI_TOP_P if top_p is None else top_p
    _runtime.max_tokens = settings.OPENAI_MAX_TOKENS if max_tokens is None else max_tokens
    _runtime.max_retries = settings.OPENAI_MAX_RETRIES if max_retries is None else max_retries
    _runtime.extra_body = extra_body or {}
    _runtime.usage_records = []
    reset_client()


def _runtime_model(default: str | None = None) -> str:
    return default or getattr(_runtime, "model", settings.OPENAI_MODEL)


def _runtime_stream() -> bool:
    return getattr(_runtime, "stream", settings.OPENAI_STREAM)


def _runtime_retry_count() -> int:
    return int(getattr(_runtime, "max_retries", settings.OPENAI_MAX_RETRIES))


def _completion_options() -> dict:
    options = {
        "temperature": getattr(_runtime, "temperature", settings.OPENAI_TEMPERATURE),
        "top_p": getattr(_runtime, "top_p", settings.OPENAI_TOP_P),
        "max_tokens": getattr(_runtime, "max_tokens", settings.OPENAI_MAX_TOKENS),
    }
    extra_body = getattr(_runtime, "extra_body", None)
    if extra_body:
        options["extra_body"] = extra_body
    return options


def _record_usage(response) -> None:
    usage = getattr(response, "usage", None)
    if usage is None:
        return
    records = getattr(_runtime, "usage_records", [])
    records.append({
        "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
        "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
        "total_tokens": getattr(usage, "total_tokens", 0) or 0,
        "reasoning_tokens": getattr(getattr(usage, "completion_tokens_details", None), "reasoning_tokens", 0) or 0,
    })
    _runtime.usage_records = records


def get_runtime_usage_summary() -> dict:
    records = getattr(_runtime, "usage_records", [])
    return {
        "calls": len(records),
        "prompt_tokens": sum(item.get("prompt_tokens", 0) for item in records),
        "completion_tokens": sum(item.get("completion_tokens", 0) for item in records),
        "total_tokens": sum(item.get("total_tokens", 0) for item in records),
        "reasoning_tokens": sum(item.get("reasoning_tokens", 0) for item in records),
    }


def _parse_tool_call(name: str, arguments: str) -> dict:
    try:
        args = json.loads(arguments)
    except json.JSONDecodeError:
        args = {"raw": arguments}
    if not isinstance(args, dict):
        args = {"raw": args}
    return {"tool": name, "args": args}


def _extract_streamed_tool_calls(stream) -> list[dict]:
    calls: dict[int, dict] = defaultdict(lambda: {"name": "", "arguments": ""})
    finish_reason = None
    content_parts: list[str] = []

    for chunk in stream:
        if not chunk.choices:
            continue
        choice = chunk.choices[0]
        finish_reason = choice.finish_reason or finish_reason
        delta = choice.delta
        if getattr(delta, "content", None):
            content_parts.append(delta.content)
        for tc in getattr(delta, "tool_calls", None) or []:
            idx = tc.index
            fn = getattr(tc, "function", None)
            if fn and getattr(fn, "name", None):
                calls[idx]["name"] += fn.name
            if fn and getattr(fn, "arguments", None):
                calls[idx]["arguments"] += fn.arguments

    if not calls:
        raise RuntimeError(
            f"LLM returned no streamed tool calls (finish_reason={finish_reason!r}, "
            f"content={''.join(content_parts)!r})"
        )

    return [
        _parse_tool_call(calls[idx]["name"], calls[idx]["arguments"])
        for idx in sorted(calls)
    ]


def call_with_tools(
    system_prompt: str,
    user_message: str,
    tools: list[dict],
    max_iterations: int = 1,
    model: str | None = None,
) -> list[dict]:
    """Call LLM with function-calling tools and return normalized tool calls."""
    client = get_client()
    model_name = _runtime_model(model)

    last_exc: Exception | None = None
    retry_count = _runtime_retry_count()
    for attempt in range(1, retry_count + 1):
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                tools=tools,
                tool_choice="required",
                stream=_runtime_stream(),
                **_completion_options(),
            )

            if _runtime_stream():
                all_tool_calls = _extract_streamed_tool_calls(response)
                logger.info(
                    "LLM collected %d streamed tool calls (attempt %d)",
                    len(all_tool_calls),
                    attempt,
                )
                return all_tool_calls

            _record_usage(response)
            choice = response.choices[0]
            message = choice.message
            if not message.tool_calls:
                raise RuntimeError(
                    f"LLM returned no tool calls (finish_reason={choice.finish_reason!r}, "
                    f"content={message.content!r})"
                )

            all_tool_calls = [
                _parse_tool_call(tc.function.name, tc.function.arguments)
                for tc in message.tool_calls
            ]
            logger.info("LLM collected %d tool calls (attempt %d)", len(all_tool_calls), attempt)
            return all_tool_calls

        except Exception as exc:
            last_exc = exc
            if attempt < retry_count:
                delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
                logger.warning(
                    "LLM call failed (attempt %d/%d): %s; retrying in %.1fs",
                    attempt,
                    retry_count,
                    exc,
                    delay,
                )
                time.sleep(delay)
            else:
                logger.error(
                    "LLM call failed after %d attempts: %s; aborting",
                    retry_count,
                    exc,
                )

    raise RuntimeError(f"LLM call_with_tools failed after {retry_count} attempts") from last_exc


def call_simple(
    system_prompt: str,
    user_message: str,
    model: str | None = None,
) -> str:
    """Simple LLM call without tools; returns text content."""
    client = get_client()
    model_name = _runtime_model(model)
    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        stream=_runtime_stream(),
        **_completion_options(),
    )
    if _runtime_stream():
        parts: list[str] = []
        for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content:
                parts.append(chunk.choices[0].delta.content)
        return "".join(parts)
    _record_usage(response)
    return response.choices[0].message.content or ""
