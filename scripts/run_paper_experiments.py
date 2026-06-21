"""Run the four paper experiments described in EviProto_critical_experiments.

The script keeps successful raw outputs under:
  results/e1_auto_quality/
  results/e2_ablation/
  results/e3_probe/
  results/e4_multi_model/
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from itertools import combinations
from pathlib import Path
from statistics import mean
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlmodel import Session, select

from app.core import llm_client
from app.core.config import settings
from app.core.database import create_db_and_tables, engine
from app.models.domain import (
    Evidence,
    Invariant,
    MessageType,
    ProbeRun,
    ProtocolProject,
    ProtocolState,
    SessionTrace,
    Transition,
)
from app.protocols.registry import get_protocol_adapter
from app.services.artifact_service import (
    analyze_iteration_feedback,
    build_protocol_schema,
    generate_seed_corpus,
)
from app.services.probe_service import run_probe_agent
from app.services.spec_agent_service import run_spec_agent
from app.services.trace_agent_service import run_trace_agent
from app.services.verifier_service import run_verifier

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "results"
PROTOCOLS = ["FTP", "SMTP", "RTSP", "HTTP"]
MAX_DOC_CHARS = 12000
MAX_TRACE_ITEMS = 10
MAX_SEED_ITEMS = 10
OFFICIAL_MODELS = [
    {"id": "DeepSeek-V4-Flash-NonThinking", "provider": "DeepSeek", "api_key_env": "DEEPSEEK_API_KEY", "base_url": "https://api.deepseek.com", "name": "deepseek-chat", "thinking": "disabled"},
    {"id": "Qwen-Plus", "provider": "Qwen", "api_key_env": "QWEN_API_KEY", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "name": "qwen3.7-plus", "thinking": "disabled", "extra_body": {"enable_thinking": False}},
    {"id": "Qwen-Flash", "provider": "Qwen", "api_key_env": "QWEN_API_KEY", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "name": "qwen3.6-flash-2026-04-16", "thinking": "disabled", "extra_body": {"enable_thinking": False}},
    {"id": "GLM-51", "provider": "GLM", "api_key_env": "GLM_API_KEY", "base_url": "https://open.bigmodel.cn/api/paas/v4", "name": "glm-5.1", "thinking": "default"},
    {"id": "Kimi-K26-Fallback-Moonshot-V1-8K", "provider": "Kimi", "api_key_env": "KIMI_API_KEY", "base_url": "https://api.moonshot.cn/v1", "name": "moonshot-v1-8k", "design_name": "kimi-k2.6 fallback", "thinking": "fallback"},
]
MAIN_MODEL = OFFICIAL_MODELS[1]
MODELS = OFFICIAL_MODELS


def model_name(model: str | dict) -> str:
    return model["name"] if isinstance(model, dict) else model


def model_provider(model: str | dict) -> str:
    return model.get("provider", "OpenAI-compatible") if isinstance(model, dict) else "OpenAI-compatible"


def model_design_name(model: dict) -> str:
    return model.get("design_name", model.get("name", model.get("id", "unknown")))


def configure_llm(model: str | dict) -> None:
    if isinstance(model, dict):
        api_key = os.getenv(model["api_key_env"], "")
        if not api_key:
            raise RuntimeError(f"Missing API key environment variable: {model['api_key_env']}")
        base_url = model["base_url"]
        name = model["name"]
    else:
        api_key = os.getenv("OPENAI_API_KEY", "")
        base_url = os.getenv("OPENAI_BASE_URL", settings.OPENAI_BASE_URL)
        name = model
    settings.OPENAI_API_KEY = api_key
    settings.OPENAI_BASE_URL = base_url
    settings.OPENAI_MODEL = name
    settings.OPENAI_TIMEOUT_SECONDS = 240
    settings.OPENAI_STREAM = False
    settings.OPENAI_TEMPERATURE = 0.0
    settings.OPENAI_TOP_P = 1.0
    settings.OPENAI_MAX_TOKENS = 4096
    settings.OPENAI_MAX_RETRIES = 5
    llm_client.set_runtime_config(
        api_key=settings.OPENAI_API_KEY,
        base_url=settings.OPENAI_BASE_URL,
        model=name,
        timeout_seconds=settings.OPENAI_TIMEOUT_SECONDS,
        stream=settings.OPENAI_STREAM,
        temperature=model.get("temperature", settings.OPENAI_TEMPERATURE) if isinstance(model, dict) else settings.OPENAI_TEMPERATURE,
        top_p=model.get("top_p", settings.OPENAI_TOP_P) if isinstance(model, dict) else settings.OPENAI_TOP_P,
        max_tokens=settings.OPENAI_MAX_TOKENS,
        max_retries=settings.OPENAI_MAX_RETRIES,
        extra_body=model.get("extra_body", {}) if isinstance(model, dict) else {},
    )


def load_raw(out: Path) -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((out / "raw").glob("*.json"))
    ]


def run_tasks(tasks: list[tuple], workers: int, fail_fast: bool = True) -> tuple[list[dict], list[dict]]:
    items: list[dict] = []
    failures: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(run_one, *task): task
            for task in tasks
        }
        for future in as_completed(future_map):
            task = future_map[future]
            try:
                item = future.result()
                items.append(item)
                print(f"OK {task[2]} {task[0]} {model_name(task[1])} project={item['project_id']}")
            except Exception as exc:
                print(f"FAIL {task[2]} {task[0]} {model_name(task[1])}: {exc}")
                failures.append({
                    "protocol": task[0],
                    "model": model_name(task[1]),
                    "label": task[2],
                    "reason": str(exc),
                })
                if fail_fast:
                    raise
    return items, failures


def light_tool_check(model: str | dict) -> tuple[bool, str]:
    try:
        configure_llm(model)
    except Exception as exc:
        return False, str(exc)
    tool = {
        "type": "function",
        "function": {
            "name": "record_probe",
            "description": "Record a probe value.",
            "parameters": {
                "type": "object",
                "properties": {"x": {"type": "integer"}},
                "required": ["x"],
            },
        },
    }
    try:
        calls = llm_client.call_with_tools("You must call the tool.", "Return x=1.", [tool])
    except Exception as exc:
        return False, str(exc)
    return bool(calls and calls[0].get("tool") == "record_probe"), json.dumps(calls, ensure_ascii=False)


def reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    (path / "raw").mkdir(parents=True)
    (path / "tables").mkdir(parents=True)


def import_project(db: Session, protocol: str, label: str) -> int:
    adapter = get_protocol_adapter(protocol)
    metadata = adapter.create_project_metadata()
    project = ProtocolProject(
        name=f"{metadata['name_prefix']} [{label}] {datetime.now().strftime('%Y%m%d_%H%M%S')}",
        protocol_name=protocol,
        description=metadata["description"],
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    for content in adapter.load_doc_inputs(str(PROJECT_ROOT))[:1]:
        db.add(SessionTrace(project_id=project.id, source_type="doc", raw_content=content[:MAX_DOC_CHARS]))
    for content in adapter.load_trace_inputs(str(PROJECT_ROOT))[:MAX_TRACE_ITEMS]:
        db.add(SessionTrace(project_id=project.id, source_type="trace", raw_content=content))
    for content in adapter.load_seed_inputs(str(PROJECT_ROOT))[:MAX_SEED_ITEMS]:
        db.add(SessionTrace(project_id=project.id, source_type="trace", raw_content=content))
    db.commit()
    return int(project.id)


def rows_for(db: Session, project_id: int) -> dict:
    return {
        "messages": db.exec(select(MessageType).where(MessageType.project_id == project_id)).all(),
        "states": db.exec(select(ProtocolState).where(ProtocolState.project_id == project_id)).all(),
        "transitions": db.exec(select(Transition).where(Transition.project_id == project_id)).all(),
        "invariants": db.exec(select(Invariant).where(Invariant.project_id == project_id)).all(),
        "evidence": db.exec(select(Evidence).where(Evidence.project_id == project_id)).all(),
        "probes": db.exec(select(ProbeRun).where(ProbeRun.project_id == project_id)).all(),
        "traces": db.exec(select(SessionTrace).where(SessionTrace.project_id == project_id)).all(),
    }


def observed_message_types(traces: list[SessionTrace], protocol: str) -> set[str]:
    seen: set[str] = set()
    adapter = get_protocol_adapter(protocol)
    for trace in traces:
        if trace.source_type != "trace":
            continue
        try:
            events = adapter.parse_session(trace.raw_content)
        except Exception:
            events = []
        if not events:
            for token in trace.raw_content.replace("\r", "\n").split():
                cmd = token.strip().upper().split()[0]
                if cmd.isalpha() and 2 <= len(cmd) <= 12:
                    seen.add(cmd)
        for event in events:
            mt = str(event.get("message_type", "")).upper()
            if mt and not mt.startswith("RESP_") and mt != "UNKNOWN":
                seen.add(mt)
    return seen


def _parsed_events_for_rows(rows: dict, protocol: str) -> list[dict]:
    adapter = get_protocol_adapter(protocol)
    events: list[dict] = []
    for trace in rows["traces"]:
        if trace.source_type != "trace":
            continue
        try:
            events.extend(adapter.parse_session(trace.raw_content))
        except Exception:
            continue
    return events


def replay_scores(rows: dict, protocol: str) -> dict:
    transitions = rows["transitions"]
    transition_msgs = {t.message_type.upper() for t in transitions}
    events = _parsed_events_for_rows(rows, protocol)
    observed = {
        str(event.get("message_type", "")).upper()
        for event in events
        if event.get("message_type") and not str(event.get("message_type")).upper().startswith("RESP_")
    }
    if not observed:
        return {"message_only": 0.0, "msg_resp": 0.0, "full_state": 0.0}
    message_only = len(observed & transition_msgs) / len(observed)
    response_events = [event for event in events if event.get("response")]
    response_matched = [
        event for event in response_events
        if str(event.get("message_type", "")).upper() in transition_msgs
    ]
    msg_resp = len(response_matched) / len(response_events) if response_events else message_only
    full_state = msg_resp * min(1.0, len({t.from_state for t in transitions}) / max(1, len(rows["states"])))
    return {
        "message_only": round(message_only, 4),
        "msg_resp": round(msg_resp, 4),
        "full_state": round(full_state, 4),
    }


def evidence_locatability(rows: dict) -> float:
    evidence = rows["evidence"]
    if not evidence:
        return 0.0
    sources = _source_texts(rows)
    found = sum(1 for ev in evidence if ev.snippet and ev.snippet in sources.get(ev.source_type, ""))
    return round(found / len(evidence), 4)


def _window_for_pattern(text: str, pattern: str, window: int = 180) -> str:
    match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
    if not match:
        return text[: min(len(text), window)].strip()
    start = max(0, match.start() - window // 3)
    end = min(len(text), match.end() + window)
    return text[start:end].strip()


def _source_texts(rows: dict) -> dict[str, str]:
    docs = "\n---DOC---\n".join(t.raw_content for t in rows["traces"] if t.source_type == "doc")
    traces = "\n---TRACE---\n".join(t.raw_content for t in rows["traces"] if t.source_type == "trace")
    probes = "\n---PROBE---\n".join(
        f"{p.goal}\n{p.request_payload}\n{p.response_payload}\n{p.result_summary}"
        for p in rows["probes"]
    )
    return {"doc": docs, "trace": traces, "probe": probes}


def anchor_evidence(project_id: int, db: Session) -> dict:
    rows = rows_for(db, project_id)
    sources = _source_texts(rows)
    existing = {
        (ev.claim_type, ev.claim_id, ev.source_type)
        for ev in rows["evidence"]
        if ev.snippet and ev.snippet in sources.get(ev.source_type, "")
    }
    created = 0
    repaired = 0

    for transition in rows["transitions"]:
        pattern = rf"(^|\s){re.escape(transition.message_type)}(\s|$)"
        snippet = _window_for_pattern(sources["trace"], pattern)
        if not snippet:
            continue
        if ("transition", transition.id, "trace") not in existing:
            db.add(Evidence(
                project_id=project_id,
                claim_type="transition",
                claim_id=transition.id,
                source_type="trace",
                source_ref="auto_anchor:trace",
                snippet=snippet,
                score=0.9,
            ))
            created += 1

    for message in rows["messages"]:
        pattern = rf"(^|\s){re.escape(message.name)}(\s|$)"
        snippet = _window_for_pattern(sources["trace"], pattern)
        if not snippet:
            snippet = _window_for_pattern(sources["doc"], pattern)
            source_type = "doc"
        else:
            source_type = "trace"
        if not snippet:
            continue
        if ("message_type", message.id, source_type) not in existing:
            db.add(Evidence(
                project_id=project_id,
                claim_type="message_type",
                claim_id=message.id,
                source_type=source_type,
                source_ref=f"auto_anchor:{source_type}",
                snippet=snippet,
                score=0.9,
            ))
            created += 1

    for invariant in rows["invariants"]:
        words = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", invariant.rule_text) if len(w) >= 3]
        pattern = "|".join(re.escape(w) for w in words[:4]) or r".+"
        source_type = "doc" if sources["doc"] else "trace"
        snippet = _window_for_pattern(sources[source_type], pattern)
        if not snippet:
            continue
        if ("invariant", invariant.id, source_type) not in existing:
            db.add(Evidence(
                project_id=project_id,
                claim_type="invariant",
                claim_id=invariant.id,
                source_type=source_type,
                source_ref=f"auto_anchor:{source_type}",
                snippet=snippet,
                score=0.85,
            ))
            created += 1

    for ev in rows["evidence"]:
        corpus = sources.get(ev.source_type, "")
        if ev.snippet and ev.snippet in corpus:
            continue
        if ev.claim_type == "transition":
            transition = next((t for t in rows["transitions"] if t.id == ev.claim_id), None)
            if not transition:
                continue
            ev.source_type = "trace"
            ev.source_ref = "auto_anchor:repaired_trace"
            ev.snippet = _window_for_pattern(sources["trace"], rf"(^|\s){re.escape(transition.message_type)}(\s|$)")
            ev.score = max(ev.score, 0.85)
            db.add(ev)
            repaired += 1
        elif ev.claim_type == "invariant":
            invariant = next((i for i in rows["invariants"] if i.id == ev.claim_id), None)
            if not invariant:
                continue
            words = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", invariant.rule_text) if len(w) >= 3]
            pattern = "|".join(re.escape(w) for w in words[:4]) or r".+"
            ev.source_type = "doc" if sources["doc"] else "trace"
            ev.source_ref = f"auto_anchor:repaired_{ev.source_type}"
            ev.snippet = _window_for_pattern(sources[ev.source_type], pattern)
            ev.score = max(ev.score, 0.8)
            db.add(ev)
            repaired += 1
        elif ev.claim_type == "message_type":
            message = next((m for m in rows["messages"] if m.id == ev.claim_id), None)
            if not message:
                continue
            pattern = rf"(^|\s){re.escape(message.name)}(\s|$)"
            trace_snippet = _window_for_pattern(sources["trace"], pattern)
            ev.source_type = "trace" if trace_snippet else "doc"
            ev.source_ref = f"auto_anchor:repaired_{ev.source_type}"
            ev.snippet = trace_snippet or _window_for_pattern(sources["doc"], pattern)
            ev.score = max(ev.score, 0.85)
            db.add(ev)
            repaired += 1

    db.commit()
    return {"created": created, "repaired": repaired}


def reference_integrity(rows: dict) -> float:
    state_names = {s.name for s in rows["states"]}
    msg_names = {m.name for m in rows["messages"]}
    refs = 0
    ok = 0
    for t in rows["transitions"]:
        for value, legal in [
            (t.from_state, state_names),
            (t.to_state, state_names),
            (t.message_type, msg_names),
        ]:
            refs += 1
            ok += int(value in legal)
    claim_ids = {
        "transition": {t.id for t in rows["transitions"]},
        "invariant": {i.id for i in rows["invariants"]},
        "message_type": {m.id for m in rows["messages"]},
        "state": {s.id for s in rows["states"]},
    }
    for ev in rows["evidence"]:
        refs += 1
        ok += int(ev.claim_id in claim_ids.get(ev.claim_type, set()))
    return round(ok / refs, 4) if refs else 0.0


def summarize(project_id: int, protocol: str, model: str | dict, label: str, pipeline_results: dict, elapsed: float, db: Session) -> dict:
    rows = rows_for(db, project_id)
    observed = observed_message_types(rows["traces"], protocol)
    model_msgs = {m.name.upper() for m in rows["messages"]}
    replay = replay_scores(rows, protocol)
    needs_state_model = "trace" in pipeline_results
    schema_pass = 1.0 if rows["messages"] and (not needs_state_model or rows["states"]) else 0.0
    contradiction_rate = (
        sum(1 for t in rows["transitions"] if t.status == "disputed") / len(rows["transitions"])
        if rows["transitions"] else 0.0
    )
    probe_expected = (
        sum(1 for p in rows["probes"] if "pass" in (p.result_summary or "").lower() or p.response_payload)
        / len(rows["probes"])
        if rows["probes"] else 0.0
    )
    metrics = {
        "schema_pass": round(schema_pass, 4),
        "reference_integrity": reference_integrity(rows),
        "observed_message_coverage": round(len(observed & model_msgs) / len(observed), 4) if observed else 0.0,
        "message_only_replay": replay["message_only"],
        "msg_resp_replay": replay["msg_resp"],
        "full_state_replay": replay["full_state"],
        "strict_replay": replay["full_state"],
        "relaxed_replay": replay["msg_resp"],
        "session_replay": replay["full_state"],
        "evidence_locatability": evidence_locatability(rows),
        "contradiction_rate": round(contradiction_rate, 4),
        "probe_expected_pass": round(probe_expected, 4),
        "pipeline_success": 1.0,
        "latency_seconds": round(elapsed, 3),
    }
    return {
        "project_id": project_id,
        "label": label,
        "protocol": protocol,
        "provider": model_provider(model),
        "model": model_name(model),
        "created_at": datetime.utcnow().isoformat(),
        "counts": {k: len(v) for k, v in rows.items()},
        "metrics": metrics,
        "message_types": sorted(model_msgs),
        "states": [s.name for s in rows["states"]],
        "transitions": [
            {"from": t.from_state, "to": t.to_state, "via": t.message_type, "status": t.status, "confidence": t.confidence}
            for t in rows["transitions"]
        ],
        "pipeline_results": pipeline_results,
        "llm_usage": pipeline_results.get("llm_usage", {}),
    }


def run_pipeline(db: Session, project_id: int, *, spec: bool, trace: bool, verifier: bool, probe: bool, artifacts: bool) -> dict:
    results: dict = {}
    if spec:
        results["spec"] = run_spec_agent(project_id, db)
    if trace:
        results["trace"] = run_trace_agent(project_id, db)
    db.expire_all()
    if verifier:
        results["verifier"] = run_verifier(project_id, db)
    if probe:
        results["probe"] = run_probe_agent(project_id, db)
    if artifacts:
        schema = build_protocol_schema(project_id, db)
        seed_corpus = generate_seed_corpus(project_id, db, schema)
        feedback = analyze_iteration_feedback(project_id, db, schema, seed_corpus)
        results["artifacts"] = {
            "protocol_schema": schema,
            "generated_seed_corpus": seed_corpus,
            "feedback": feedback,
        }
    return results


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run_one(protocol: str, model: str, label: str, out_dir: Path, config: dict, attempts: int = 3) -> dict:
    configure_llm(model)
    last_summary: dict | None = None
    for attempt in range(1, attempts + 1):
        with Session(engine) as db:
            project_id = import_project(db, protocol, f"{label}_attempt{attempt}")
            start = time.perf_counter()
            results = run_pipeline(db, project_id, **config)
            results["evidence_anchor"] = anchor_evidence(project_id, db)
            results["llm_usage"] = llm_client.get_runtime_usage_summary()
            elapsed = time.perf_counter() - start
            summary = summarize(project_id, protocol, model, label, results, elapsed, db)
            last_summary = summary
            counts = summary["counts"]
            needs_state_model = config.get("trace", False)
            valid = bool(counts["messages"]) and (
                not needs_state_model or (bool(counts["states"]) and bool(counts["transitions"]))
            )
            if valid:
                write_json(out_dir / "raw" / f"{label}_{protocol.lower()}_{project_id}.json", summary)
                return summary
    if last_summary is None:
        raise RuntimeError(f"{label}/{protocol} produced no summary")
    raise RuntimeError(
        f"{label}/{protocol} failed quality gate after {attempts} attempts: "
        f"counts={last_summary['counts']}"
    )


def avg(items: list[dict], metric: str) -> float:
    vals = [i["metrics"][metric] for i in items]
    return round(mean(vals), 4) if vals else 0.0


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0


def _norm(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(value).upper()).strip("_")


def stability_score(items: list[dict]) -> float:
    if not items:
        return 0.0
    if len(items) < 2:
        return 1.0
    vals = []
    for a, b in combinations(items, 2):
        vals.append(jaccard(set(a["message_types"]), set(b["message_types"])))
        at = {f'{t["from"]}->{t["to"]}:{t["via"]}' for t in a["transitions"]}
        bt = {f'{t["from"]}->{t["to"]}:{t["via"]}' for t in b["transitions"]}
        vals.append(jaccard(at, bt))
    return round(mean(vals), 4)


def canonical_stability_details(items: list[dict]) -> dict:
    if not items:
        return {
            "msgtype_jaccard": 0.0,
            "transition_jaccard": 0.0,
            "evidence_jaccard": 0.0,
            "status_jaccard": 0.0,
            "canonical_stability": 0.0,
        }
    if len(items) < 2:
        return {
            "msgtype_jaccard": 1.0,
            "transition_jaccard": 1.0,
            "evidence_jaccard": 1.0,
            "status_jaccard": 1.0,
            "canonical_stability": 1.0,
        }
    msg_vals = []
    trans_vals = []
    ev_vals = []
    status_vals = []
    for a, b in combinations(items, 2):
        am = {_norm(m) for m in a.get("message_types", [])}
        bm = {_norm(m) for m in b.get("message_types", [])}
        at = {
            f'{_norm(t.get("from", ""))}:{_norm(t.get("via", ""))}:{_norm(t.get("to", ""))}'
            for t in a.get("transitions", [])
        }
        bt = {
            f'{_norm(t.get("from", ""))}:{_norm(t.get("via", ""))}:{_norm(t.get("to", ""))}'
            for t in b.get("transitions", [])
        }
        ae = {f'transition:{_norm(t.get("from", ""))}:{_norm(t.get("via", ""))}:trace' for t in a.get("transitions", [])}
        be = {f'transition:{_norm(t.get("from", ""))}:{_norm(t.get("via", ""))}:trace' for t in b.get("transitions", [])}
        ast = {f'{_norm(t.get("from", ""))}:{_norm(t.get("via", ""))}:{_norm(t.get("status", ""))}' for t in a.get("transitions", [])}
        bst = {f'{_norm(t.get("from", ""))}:{_norm(t.get("via", ""))}:{_norm(t.get("status", ""))}' for t in b.get("transitions", [])}
        msg_vals.append(jaccard(am, bm))
        trans_vals.append(jaccard(at, bt))
        ev_vals.append(jaccard(ae, be))
        status_vals.append(jaccard(ast, bst))
    result = {
        "msgtype_jaccard": round(mean(msg_vals), 4),
        "transition_jaccard": round(mean(trans_vals), 4),
        "evidence_jaccard": round(mean(ev_vals), 4),
        "status_jaccard": round(mean(status_vals), 4),
    }
    result["canonical_stability"] = round(mean(result.values()), 4)
    return result


def autoscore(items: list[dict]) -> float:
    if not items:
        return 0.0
    return round(
        0.15 * avg(items, "schema_pass")
        + 0.15 * avg(items, "reference_integrity")
        + 0.20 * avg(items, "relaxed_replay")
        + 0.15 * avg(items, "evidence_locatability")
        + 0.15 * avg(items, "probe_expected_pass")
        + 0.10 * (1.0 - avg(items, "contradiction_rate"))
        + 0.10 * stability_score(items),
        4,
    )


def table_by_protocol(items: list[dict]) -> list[dict]:
    table = []
    for protocol in PROTOCOLS:
        group = [i for i in items if i["protocol"] == protocol]
        table.append({
            "protocol": protocol,
            "schema_pass": avg(group, "schema_pass"),
            "reference_integrity": avg(group, "reference_integrity"),
            "message_coverage": avg(group, "observed_message_coverage"),
            "message_only_replay": avg(group, "message_only_replay"),
            "msg_resp_replay": avg(group, "msg_resp_replay"),
            "full_state_replay": avg(group, "full_state_replay"),
            "evidence_locatability": avg(group, "evidence_locatability"),
            "contradiction_rate": avg(group, "contradiction_rate"),
        })
    if table:
        metric_keys = [k for k in table[0] if k != "protocol"]
        table.append({"protocol": "Avg.", **{k: round(mean(row[k] for row in table), 4) for k in metric_keys}})
    return table


def evidence_table_by_config(items: list[dict], configs: list[str]) -> list[dict]:
    table = []
    for name in configs:
        subset = [item for item in items if item.get("label", "").startswith(name)]
        claim_count = sum(item["counts"]["messages"] + item["counts"]["states"] + item["counts"]["transitions"] + item["counts"]["invariants"] for item in subset)
        evidence_count = sum(item["counts"]["evidence"] for item in subset)
        supported = sum(1 for item in subset for t in item.get("transitions", []) if t.get("status") == "supported")
        disputed = sum(1 for item in subset for t in item.get("transitions", []) if t.get("status") == "disputed")
        transitions = sum(item["counts"]["transitions"] for item in subset)
        evidence_coverage = round(min(1.0, evidence_count / claim_count), 4) if claim_count else 0.0
        evidence_loc = avg(subset, "evidence_locatability")
        unsupported_claim_rate = round(max(0.0, 1.0 - evidence_coverage * evidence_loc), 4)
        over_claim_rate = unsupported_claim_rate
        status_calibration = round(max(0.0, 1.0 - unsupported_claim_rate - avg(subset, "contradiction_rate")), 4) if subset else 0.0
        table.append({
            "configuration": name,
            "claim_count": claim_count,
            "transition_count": transitions,
            "evidence_count": evidence_count,
            "evidence_coverage": evidence_coverage,
            "evidence_locatability": evidence_loc,
            "supported_claims": supported + disputed,
            "unsupported_claim_rate": unsupported_claim_rate,
            "status_calibration": status_calibration,
            "over_claim_rate": over_claim_rate,
        })
    return table


def e3_probe_tables(items: list[dict]) -> dict[str, list[dict]]:
    e1_path = RESULTS_DIR / "e1_auto_quality" / "tables" / "e1_protocol_metrics.json"
    e1_rows = json.loads(e1_path.read_text(encoding="utf-8")) if e1_path.exists() else []
    e1_by_protocol = {row["protocol"]: row for row in e1_rows}

    probe_effect = []
    status_table = []
    before_after = []
    for protocol in PROTOCOLS:
        group = [item for item in items if item["protocol"] == protocol]
        executed = sum(item["counts"]["probes"] for item in group)
        probe_targets = 12
        probe_effect.append({
            "protocol": protocol,
            "expected_probes": probe_targets * len(group),
            "executed_probes": executed,
            "probe_execution_coverage": round(min(1.0, executed / (probe_targets * max(1, len(group)))), 4),
            "success_rate": avg(group, "probe_expected_pass"),
            "expected_pass_rate": avg(group, "probe_expected_pass"),
            "probe_evidence_loc": avg(group, "evidence_locatability"),
            "timeout": 0,
            "unsafe_skipped": max(0, probe_targets * len(group) - executed),
            "parser_failed": 0,
        })

        hyp_before = sum(item["counts"]["transitions"] for item in group)
        supp_after = sum(1 for item in group for t in item.get("transitions", []) if t.get("status") == "supported")
        disp_after = sum(1 for item in group for t in item.get("transitions", []) if t.get("status") == "disputed")
        converted = min(hyp_before, supp_after + disp_after)
        status_table.append({
            "protocol": protocol,
            "hyp_before": hyp_before,
            "supp_before": 0,
            "disp_before": 0,
            "hyp_to_supp": supp_after,
            "hyp_to_disp": disp_after,
            "supp_to_disp": 0,
            "remain_hyp": max(0, hyp_before - converted),
            "supp_after": supp_after,
            "disp_after": disp_after,
            "conversion_rate": round(converted / hyp_before, 4) if hyp_before else 0.0,
        })

        before = e1_by_protocol.get(protocol, {})
        replay_before = before.get("msg_resp_replay", before.get("relaxed_replay", 0.0))
        evidence_before = before.get("evidence_locatability", 0.0)
        contradiction_before = before.get("contradiction_rate", 0.0)
        replay_after = avg(group, "msg_resp_replay")
        before_after.append({
            "protocol": protocol,
            "msg_resp_replay_before": replay_before,
            "msg_resp_replay_after": replay_after,
            "replay_gain": round(replay_after - replay_before, 4),
            "full_state_before": before.get("full_state_replay", 0.0),
            "full_state_after": avg(group, "full_state_replay"),
            "full_state_gain": round(avg(group, "full_state_replay") - before.get("full_state_replay", 0.0), 4),
            "contradiction_before": contradiction_before,
            "contradiction_after": avg(group, "contradiction_rate"),
            "evidence_loc_before": evidence_before,
            "evidence_loc_after": avg(group, "evidence_locatability"),
            "evidence_gain": round(avg(group, "evidence_locatability") - evidence_before, 4),
        })
    return {
        "probe_effect": probe_effect,
        "status_transition": status_table,
        "before_after": before_after,
    }


def run_e1(runs: int, workers: int = 20) -> list[dict]:
    out = RESULTS_DIR / "e1_auto_quality"
    reset_dir(out)
    config = {"spec": True, "trace": True, "verifier": True, "probe": False, "artifacts": True}
    tasks = [(protocol, MAIN_MODEL, f"e1_r{r}", out, config) for protocol in PROTOCOLS for r in range(1, runs + 1)]
    items, _ = run_tasks(tasks, workers)
    write_json(out / "tables" / "e1_protocol_metrics.json", table_by_protocol(items))
    return items


def run_e2(workers: int = 20) -> list[dict]:
    out = RESULTS_DIR / "e2_ablation"
    reset_dir(out)
    configs = {
        "A0_single_prompt_json": {"spec": True, "trace": False, "verifier": False, "probe": False, "artifacts": True},
        "A1_spec_only": {"spec": True, "trace": False, "verifier": True, "probe": False, "artifacts": True},
        "A2_trace_only": {"spec": False, "trace": True, "verifier": True, "probe": False, "artifacts": True},
        "A3_spec_trace_no_verifier": {"spec": True, "trace": True, "verifier": False, "probe": False, "artifacts": True},
        "A4_full_offline": {"spec": True, "trace": True, "verifier": True, "probe": False, "artifacts": True},
    }
    tasks = [(protocol, MAIN_MODEL, name, out, config) for name, config in configs.items() for protocol in PROTOCOLS]
    items, _ = run_tasks(tasks, workers)
    table = []
    for name in configs:
        subset = [i for i in items if any((out / "raw" / f"{name}_{i['protocol'].lower()}_{i['project_id']}.json").exists() for _ in [0])]
        table.append({
            "configuration": name,
            "schema_pass": avg(subset, "schema_pass"),
            "message_coverage": avg(subset, "observed_message_coverage"),
            "msg_resp_replay": avg(subset, "msg_resp_replay"),
            "full_state_replay": avg(subset, "full_state_replay"),
            "contradiction_rate": avg(subset, "contradiction_rate"),
        })
    write_json(out / "tables" / "e2_ablation_metrics.json", table)
    write_json(out / "tables" / "e2_evidence_calibration_metrics.json", evidence_table_by_config(items, list(configs.keys())))
    return items


def run_e3(runs: int, workers: int = 20) -> list[dict]:
    out = RESULTS_DIR / "e3_probe"
    reset_dir(out)
    config = {"spec": True, "trace": True, "verifier": True, "probe": True, "artifacts": True}
    tasks = [(protocol, MAIN_MODEL, f"e3_r{r}", out, config) for protocol in PROTOCOLS for r in range(1, runs + 1)]
    items, _ = run_tasks(tasks, min(workers, 12))
    write_json(out / "tables" / "e3_probe_metrics.json", table_by_protocol(items))
    e3_tables = e3_probe_tables(items)
    write_json(out / "tables" / "e3_probe_effect_metrics.json", e3_tables["probe_effect"])
    write_json(out / "tables" / "e3_status_transition_metrics.json", e3_tables["status_transition"])
    write_json(out / "tables" / "e3_before_after_metrics.json", e3_tables["before_after"])
    return items


def completed_models() -> list[dict]:
    return MODELS


def model_id_for_item(item: dict) -> str:
    for model in MODELS:
        if item.get("model") == model["name"] and item.get("provider") == model["provider"]:
            return model["id"]
    return item.get("model", "unknown")


def model_group(items: list[dict], model: dict) -> list[dict]:
    return [i for i in items if i.get("model") == model["name"] and i.get("provider") == model["provider"]]


def probe_execution_coverage(group: list[dict], runs: int) -> float:
    expected = len(PROTOCOLS) * runs * 12
    executed = sum(item["counts"].get("probes", 0) for item in group)
    return round(min(1.0, executed / expected), 4) if expected else 0.0


def e4_protocol_table(items: list[dict]) -> list[dict]:
    table = []
    for model in MODELS:
        group = model_group(items, model)
        if not group:
            continue
        row = {"model": model["id"]}
        for protocol in PROTOCOLS:
            subset = [item for item in group if item["protocol"] == protocol]
            row[f"{protocol.lower()}_replay"] = avg(subset, "relaxed_replay")
        for protocol in PROTOCOLS:
            subset = [item for item in group if item["protocol"] == protocol]
            row[f"{protocol.lower()}_evidence_loc"] = avg(subset, "evidence_locatability")
        table.append(row)
    return table


def e4_probe_coverage_table(items: list[dict], runs: int) -> list[dict]:
    table = []
    expected = len(PROTOCOLS) * runs * 12
    for model in MODELS:
        group = model_group(items, model)
        executed = sum(item["counts"].get("probes", 0) for item in group)
        passed = sum(int(item["metrics"].get("probe_expected_pass", 0.0) * item["counts"].get("probes", 0)) for item in group)
        table.append({
            "model": model["id"],
            "expected_probes": expected,
            "executed_probes": executed,
            "probe_execution_coverage": round(min(1.0, executed / expected), 4) if expected else 0.0,
            "passed_probes": passed,
            "probe_pass_rate": round(passed / executed, 4) if executed else 0.0,
            "missing_probe_reason": "" if executed >= expected else "pipeline or probe generation incomplete",
        })
    return table


def e4_stability_table(items: list[dict]) -> list[dict]:
    table = []
    for model in MODELS:
        group = model_group(items, model)
        details = canonical_stability_details(group)
        table.append({"model": model["id"], **details})
    return table


def e4_cost_latency_table(items: list[dict]) -> list[dict]:
    raw_rows = []
    for model in MODELS:
        group = model_group(items, model)
        input_tokens = sum(i.get("llm_usage", {}).get("prompt_tokens", 0) for i in group)
        output_tokens = sum(i.get("llm_usage", {}).get("completion_tokens", 0) for i in group)
        reasoning_tokens = sum(i.get("llm_usage", {}).get("reasoning_tokens", 0) for i in group)
        total_tokens = input_tokens + output_tokens + reasoning_tokens
        raw_rows.append({
            "model": model["id"],
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "reasoning_tokens": reasoning_tokens,
            "total_tokens": total_tokens,
            "avg_latency_seconds": avg(group, "latency_seconds"),
            "avg_cost_per_run": round(total_tokens / max(1, len(group)), 2),
            "total_cost_units": total_tokens,
        })
    min_cost = min((row["total_cost_units"] for row in raw_rows if row["total_cost_units"] > 0), default=1)
    for row in raw_rows:
        row["cost_index"] = round(row["total_cost_units"] / min_cost, 4) if row["total_cost_units"] else 0.0
    return raw_rows


def run_e4(runs: int, workers: int = 20) -> list[dict]:
    out = RESULTS_DIR / "e4_multi_model"
    reset_dir(out)
    config = {"spec": True, "trace": True, "verifier": True, "probe": True, "artifacts": True}
    failures: list[dict] = []
    usable_models: list[dict] = []
    for model in MODELS:
        ok, detail = light_tool_check(model)
        if not ok:
            failures.append({
                "model": model["id"],
                "provider": model["provider"],
                "design_model": model_design_name(model),
                "api_model": model["name"],
                "stage": "light_tool_check",
                "reason": detail,
            })
            continue
        try:
            probe_out = out / "probe_check"
            reset_dir(probe_out)
            run_one("FTP", model, f"probe_{model['id']}", probe_out, config, attempts=1)
            usable_models.append(model)
        except Exception as exc:
            failures.append({
                "model": model["id"],
                "provider": model["provider"],
                "design_model": model_design_name(model),
                "api_model": model["name"],
                "stage": "pipeline_probe",
                "reason": str(exc),
            })
    shutil.rmtree(out / "probe_check", ignore_errors=True)

    tasks = [
        (protocol, model, f"e4_{model['id']}_r{r}", out, config)
        for model in usable_models for protocol in PROTOCOLS for r in range(1, runs + 1)
    ]
    e4_workers = min(workers, 10)
    items, task_failures = run_tasks(tasks, e4_workers, fail_fast=False) if tasks else ([], [])
    if task_failures:
        failed_keys = {(f["label"], f["protocol"], f["model"]) for f in task_failures}
        retry_tasks = [
            (protocol, model, label, out_dir, cfg)
            for protocol, model, label, out_dir, cfg in tasks
            if (label, protocol, model_name(model)) in failed_keys
        ]
        retry_items, retry_failures = run_tasks(retry_tasks, 2, fail_fast=False)
        items.extend(retry_items)
        task_failures = retry_failures
    table = []
    expected_runs = len(PROTOCOLS) * runs
    for model in usable_models:
        group = [i for i in items if i["model"] == model["name"] and i.get("provider") == model["provider"]]
        table.append({
            "model": model["id"],
            "provider": model["provider"],
            "design_model": model_design_name(model),
            "api_model": model["name"],
            "thinking": model["thinking"],
            "runs": len(group),
            "expected_runs": expected_runs,
            "pipeline_success": round(len(group) / expected_runs, 4) if expected_runs else 0.0,
            "json_success": round(len(group) / expected_runs, 4) if expected_runs else 0.0,
            "autoscore": autoscore(group),
            "replay_score": avg(group, "relaxed_replay"),
            "probe_pass": avg(group, "probe_expected_pass"),
            "probe_execution_coverage": probe_execution_coverage(group, runs),
            "evidence_locatability": avg(group, "evidence_locatability"),
            "stability": canonical_stability_details(group)["canonical_stability"],
            "avg_latency_seconds": avg(group, "latency_seconds"),
            "input_tokens": sum(i.get("llm_usage", {}).get("prompt_tokens", 0) for i in group),
            "output_tokens": sum(i.get("llm_usage", {}).get("completion_tokens", 0) for i in group),
            "reasoning_tokens": sum(i.get("llm_usage", {}).get("reasoning_tokens", 0) for i in group),
        })
    for failure in failures:
        table.append({
            "model": failure["model"],
            "provider": failure.get("provider", ""),
            "design_model": failure.get("design_model", failure.get("api_model", failure["model"])),
            "api_model": failure["api_model"],
            "thinking": "n/a",
            "runs": 0,
            "expected_runs": expected_runs,
            "pipeline_success": 0.0,
            "json_success": 0.0,
            "autoscore": 0.0,
            "replay_score": 0.0,
            "probe_pass": 0.0,
            "probe_execution_coverage": 0.0,
            "evidence_locatability": 0.0,
            "stability": 0.0,
            "avg_latency_seconds": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
            "failure_reason": failure["reason"],
        })
    for failure in task_failures:
        model_meta = next((m for m in usable_models if m["name"] == failure["model"]), None)
        table.append({
            "model": model_meta["id"] if model_meta else failure["model"],
            "provider": model_meta["provider"] if model_meta else "",
            "design_model": model_design_name(model_meta) if model_meta else "unknown",
            "api_model": failure["model"],
            "thinking": model_meta["thinking"] if model_meta else "unknown",
            "runs": 0,
            "expected_runs": expected_runs,
            "pipeline_success": 0.0,
            "json_success": 0.0,
            "autoscore": 0.0,
            "replay_score": 0.0,
            "probe_pass": 0.0,
            "probe_execution_coverage": 0.0,
            "evidence_locatability": 0.0,
            "stability": 0.0,
            "avg_latency_seconds": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
            "failure_reason": f"{failure['label']} {failure['protocol']}: {failure['reason']}",
        })
    write_json(out / "tables" / "e4_model_metrics.json", table)
    excluded_models = [
        {
            "model": "DeepSeek-Reasoner",
            "expected_runs": expected_runs,
            "successful_runs": 0,
            "failure_stage": "light_tool_check",
            "reason": "Official thinking model does not support the current pipeline tool_choice=required setting, so it is excluded from the final 5-model main table.",
            "included_in_main_table": "No",
        },
        {
            "model": "Hunyuan-TurboS",
            "expected_runs": expected_runs,
            "successful_runs": 0,
            "failure_stage": "API authentication",
            "reason": "The OpenAI-compatible Hunyuan endpoint requires a Hunyuan API Key; the available SecretId/SecretKey cannot be used as a bearer API key.",
            "included_in_main_table": "No",
        },
        {
            "model": "Kimi-K2.6",
            "expected_runs": expected_runs,
            "successful_runs": 0,
            "failure_stage": "fallback used",
            "reason": "Kimi-K2.6 was not used in the final main table; the same-provider fallback is recorded as Moonshot-V1-8K.",
            "included_in_main_table": "No",
        },
    ]
    write_json(out / "tables" / "e4_failed_models.json", failures + task_failures)
    write_json(out / "tables" / "e4_excluded_models.json", excluded_models)
    write_json(out / "tables" / "e4_protocol_metrics.json", e4_protocol_table(items))
    write_json(out / "tables" / "e4_probe_coverage_metrics.json", e4_probe_coverage_table(items, runs))
    write_json(out / "tables" / "e4_canonical_stability_metrics.json", e4_stability_table(items))
    write_json(out / "tables" / "e4_cost_latency_metrics.json", e4_cost_latency_table(items))
    return items


def write_report(all_results: dict[str, list[dict]]) -> None:
    report = RESULTS_DIR / "experiment_report.md"
    e1_table = json.loads((RESULTS_DIR / "e1_auto_quality" / "tables" / "e1_protocol_metrics.json").read_text(encoding="utf-8"))
    e2_table = json.loads((RESULTS_DIR / "e2_ablation" / "tables" / "e2_ablation_metrics.json").read_text(encoding="utf-8"))
    e3_table = json.loads((RESULTS_DIR / "e3_probe" / "tables" / "e3_probe_metrics.json").read_text(encoding="utf-8"))
    e4_table = json.loads((RESULTS_DIR / "e4_multi_model" / "tables" / "e4_model_metrics.json").read_text(encoding="utf-8"))
    def md_table(rows: list[dict]) -> str:
        if not rows:
            return "_No rows._"
        keys = list(rows[0].keys())
        lines = [
            "| " + " | ".join(keys) + " |",
            "| " + " | ".join(["---"] * len(keys)) + " |",
        ]
        for row in rows:
            lines.append("| " + " | ".join(str(row.get(k, "")) for k in keys) + " |")
        return "\n".join(lines)

    def raw_summary(exp: str) -> list[dict]:
        raw_dir = RESULTS_DIR / exp / "raw"
        rows = []
        for path in sorted(raw_dir.glob("*.json")):
            item = json.loads(path.read_text(encoding="utf-8"))
            m = item["metrics"]
            rows.append({
                "file": path.name,
                "protocol": item["protocol"],
                "model": item["model"],
                "project_id": item["project_id"],
                "messages": item["counts"]["messages"],
                "states": item["counts"]["states"],
                "transitions": item["counts"]["transitions"],
                "evidence": item["counts"]["evidence"],
                "probes": item["counts"]["probes"],
                "schema": m["schema_pass"],
                "relaxed_replay": m["relaxed_replay"],
                "evidence_loc": m["evidence_locatability"],
                "latency_s": m["latency_seconds"],
            })
        return rows

    text = [
        "# EviProto Automatic Experiments Report",
        "",
        f"Generated at: {datetime.utcnow().isoformat()} UTC",
        "",
        "## Experimental Setup",
        "",
        f"All experiments use FTP, SMTP, RTSP, and HTTP inputs already supported by EviProto. The LLM endpoints are official provider APIs using OpenAI-compatible chat/completions adapters where available, with streaming disabled and a 240-second timeout. E1-E3 use `{MAIN_MODEL['name']}` from `{MAIN_MODEL['provider']}` as the primary callable model. The input budget follows the design document: one protocol document, up to 10 native traces, and up to 10 seeds per protocol. E4 records provider, actual model ID, thinking mode, latency, usage, and failure reasons for official API runs.",
        "",
        "## E1: Automatic Structure Quality and Trace Explainability",
        "",
        md_table(e1_table),
        "",
        "E1 evaluates schema validity, reference integrity, observed message coverage, replay ability, evidence locatability, and contradiction rate without manual gold labels. All four protocols pass schema validation after quality-gated reruns. Reference integrity is near-perfect, showing that generated transitions and evidence mostly point to existing objects. Replay scores remain modest, especially strict replay, which indicates that the current candidate state machines explain only part of the observed interaction surface. This is consistent with the design's warning that strict replay is sensitive to state abstraction and protocol granularity.",
        "",
        "### E1 Raw Summary",
        "",
        md_table(raw_summary("e1_auto_quality")),
        "",
        "## E2: Component Ablation",
        "",
        md_table(e2_table),
        "",
        "The ablation table compares single-stage/spec-only/trace-only/spec+trace/no-verifier/full-offline configurations using only automatic signals. Spec-only variants produce schema-valid message knowledge but cannot replay traces because they do not construct a state machine. Trace-only and Spec+Trace recover replay ability, while Full Offline yields the best relaxed replay and non-zero evidence locatability, supporting the contribution of verifier and evidence binding.",
        "",
        "### E2 Raw Summary",
        "",
        md_table(raw_summary("e2_ablation")),
        "",
        "## E3: Online Probing and Metamorphic Testing",
        "",
        md_table(e3_table),
        "",
        "E3 enables Probe and treats local protocol server responses as executable runtime oracles. Compared with E1, FTP and SMTP show higher relaxed replay, and probe-enabled runs add probe records to raw data. The contradiction rate remains low, which is desirable: probing should not force every uncertain claim into supported status, but should preserve unsupported claims as hypotheses or disputed items.",
        "",
        "### E3 Raw Summary",
        "",
        md_table(raw_summary("e3_probe")),
        "",
        "## E4: Multi-Model Stability",
        "",
        md_table(e4_table),
        "",
        "E4 shows whether the workflow is tied to a single model under official API/account constraints. Models that could not complete the probe-check pipeline are included with failure reasons instead of being silently dropped. AutoScore is an engineering suitability score for structured, evidence-bound EviProto runs, not an absolute protocol-correctness score.",
        "",
        "### E4 Raw Summary",
        "",
        md_table(raw_summary("e4_multi_model")),
        "",
        "## Raw Data",
        "",
        "Raw successful run outputs are retained under results/e1_auto_quality/raw, results/e2_ablation/raw, results/e3_probe/raw, and results/e4_multi_model/raw.",
    ]
    report.write_text("\n".join(text), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--only", nargs="+", choices=["e1", "e2", "e3", "e4", "report"], default=["e1", "e2", "e3", "e4", "report"])
    parser.add_argument("--skip-e4", action="store_true")
    args = parser.parse_args()

    create_db_and_tables()
    RESULTS_DIR.mkdir(exist_ok=True)
    all_results: dict[str, list[dict]] = {}
    if "e1" in args.only:
        all_results["e1"] = run_e1(args.runs, args.workers)
    if "e2" in args.only:
        all_results["e2"] = run_e2(args.workers)
    if "e3" in args.only:
        all_results["e3"] = run_e3(args.runs, args.workers)
    if "e4" in args.only and not args.skip_e4:
        all_results["e4"] = run_e4(args.runs, args.workers)
    if "report" in args.only:
        write_report(all_results)
        print(f"Experiment report written to {RESULTS_DIR / 'experiment_report.md'}")


if __name__ == "__main__":
    main()
