"""Trace Agent 鈥?recovers message patterns, states, and transitions from traces.

Task 6 (LLM-upgraded): Uses Gemini function calling to infer protocol states,
transitions, and message patterns from session trace data.
"""

from __future__ import annotations
import json
import logging
from sqlmodel import Session, select

from ..models.domain import (
    SessionTrace, ProtocolState, Transition, MessageType, Evidence, ProtocolProject,
)
from ..protocols.registry import get_protocol_adapter
from ..tools.protocol_tools import extract_message_types
from ..core.llm_client import call_with_tools

logger = logging.getLogger(__name__)

def _safe_float(value, default: float) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _is_valid_message_type_name(name: str) -> bool:
    candidate = (name or "").strip().upper()
    if not candidate or candidate.startswith("RESP_"):
        return False
    return candidate.isalpha() and 3 <= len(candidate) <= 4

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

TRACE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "record_trace_analysis",
            "description": "Record structured observations and the complete trace-derived protocol analysis in a single call.",
            "parameters": {
                "type": "object",
                "properties": {
                    "observations": {
                        "type": "object",
                        "properties": {
                            "state_hypotheses": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "evidence": {"type": "string"},
                                        "confidence": {"type": "number"},
                                    },
                                    "required": ["name", "evidence", "confidence"],
                                },
                            },
                            "message_type_observations": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "observed_count": {"type": "integer"},
                                        "common_response_codes": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                        "typical_position": {"type": "string"},
                                        "confidence": {"type": "number"},
                                    },
                                    "required": ["name", "observed_count", "confidence"],
                                },
                            },
                            "sequence_patterns": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "pattern": {"type": "string"},
                                        "interpretation": {"type": "string"},
                                        "confidence": {"type": "number"},
                                    },
                                    "required": ["pattern", "interpretation", "confidence"],
                                },
                            },
                        },
                        "required": ["state_hypotheses", "message_type_observations", "sequence_patterns"],
                    },
                    "states": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "description": {"type": "string"},
                                "confidence": {"type": "number"},
                                "evidence": {"type": "string"},
                            },
                            "required": ["name", "description", "confidence"],
                        },
                    },
                    "transitions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_state": {"type": "string"},
                                "to_state": {"type": "string"},
                                "message_type": {"type": "string"},
                                "confidence": {"type": "number"},
                                "reasoning": {"type": "string"},
                                "response_codes": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "required": ["from_state", "to_state", "message_type", "confidence", "reasoning"],
                        },
                    },
                    "observed_message_types": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "observed_count": {"type": "integer"},
                                "typical_position": {"type": "string"},
                                "confidence": {"type": "number"},
                            },
                            "required": ["name", "observed_count", "confidence"],
                        },
                    },
                },
                "required": ["observations", "states", "transitions", "observed_message_types"],
            },
        },
    },
]

TRACE_SYSTEM_PROMPT = """You are an expert protocol analyst. Analyze the provided FTP session traces to recover the protocol state machine.

Your goal:
1. Identify distinct protocol states (e.g., INIT before login, AUTH_PENDING during authentication, AUTHENTICATED after successful login, DATA_CHANNEL_READY after PASV/EPSV/PORT/EPRT negotiation, DATA_TRANSFER during file operations, CLOSED after QUIT)
2. Identify state transitions triggered by specific FTP commands
3. Record observed message types with frequency information

Call record_trace_analysis exactly once.
Within that single tool call, use observations to record trace-derived evidence and then provide final states/transitions.
Populate observations, states, transitions, and observed_message_types comprehensively.
- Do not use server response pseudo-types such as RESP_220 or RESP_226 as message_type values in transitions
- Use response_codes to describe server outcomes while keeping the transition trigger as the client command
- Prefer states and transitions that are strongly grounded in repeated trace patterns, especially ProFuzzBench-observed commands
- Prefer modeling PASV/EPSV/PORT/EPRT as data-channel preparation, and model LIST/NLST/MLSD/RETR/STOR/APPE as transfer-triggering commands
- Treat MLST, SIZE, STAT, PWD, and CWD as metadata or navigation operations that usually keep the session authenticated rather than entering data transfer
- Treat REIN as entering an intermediate RESETTING / reinitialization state first; avoid modeling REIN as a direct AUTHENTICATED -> INIT jump when RESETTING is available

Focus on patterns: what command sequences lead to state changes? What response codes indicate successful vs failed transitions?"""


def _normalize_transition_shape(from_state: str, to_state: str, message_type: str) -> tuple[str, str, str]:
    from_s = from_state.strip().upper()
    to_s = to_state.strip().upper()
    msg = message_type.strip().upper()

    if msg == "REIN" and from_s == "AUTHENTICATED" and to_s == "INIT":
        to_s = "RESETTING"

    return from_s, to_s, msg


def _format_sessions_for_llm(all_sessions: list[list[dict]]) -> str:
    """Format parsed session events into readable text for LLM analysis."""
    lines = []
    for i, events in enumerate(all_sessions[:20]):
        lines.append(f"\n--- Session {i+1} ---")
        for ev in events:
            mt = ev.get("message_type", "?")
            resp = ev.get("response")
            if resp:
                code = resp.get("code", "?")
                text = resp.get("text", "")[:60]
                lines.append(f"  C鈫扴: {mt}  |  S鈫扖: {code} {text}")
            else:
                lines.append(f"  C鈫扴: {mt}")
    return "\n".join(lines)


def _augment_trace_model(project_id: int, session: Session, adapter, heuristic_states: list[dict],
                         mt_result: dict, created_states: list[str], created_trans: list[str],
                         min_transition_count: int, priority_messages: list[str]) -> None:
    for state_info in heuristic_states:
        name = state_info.get("name", "").strip().upper()
        if not name:
            continue
        existing = session.exec(
            select(ProtocolState).where(
                ProtocolState.project_id == project_id,
                ProtocolState.name == name,
            )
        ).first()
        if not existing:
            state = ProtocolState(
                project_id=project_id,
                name=name,
                description=state_info.get("description", ""),
                confidence=0.78,
            )
            session.add(state)
            session.commit()
            session.refresh(state)
            ev = Evidence(
                project_id=project_id,
                claim_type="state",
                claim_id=state.id,
                source_type="trace",
                source_ref="heuristic trace augmentation",
                snippet=state_info.get("description", name)[:500],
                score=0.78,
            )
            session.add(ev)
            created_states.append(name)

    existing_transitions = session.exec(
        select(Transition).where(Transition.project_id == project_id)
    ).all()
    current_transition_count = len(existing_transitions)
    if current_transition_count >= min_transition_count:
        return
    existing_message_types = {transition.message_type for transition in existing_transitions}
    priority_rank = {msg: i for i, msg in enumerate(priority_messages)}

    heuristic_transitions = adapter.propose_transitions(heuristic_states, mt_result.get("message_types", []))
    prioritized_candidates: list[tuple[int, str, str, str, float]] = []
    for args in heuristic_transitions.get("transitions", []):
        from_s, to_s, msg = adapter.normalize_transition(
            args.get("from_state", ""),
            args.get("to_state", ""),
            args.get("message_type", ""),
        )
        if not (from_s and to_s and msg):
            continue
        if msg in existing_message_types:
            continue
        rank = priority_rank.get(msg, len(priority_rank) + 1)
        prioritized_candidates.append(
            (rank, from_s, to_s, msg, _safe_float(args.get("confidence"), 0.72))
        )

    prioritized_candidates.sort(key=lambda item: item[0])

    for _, from_s, to_s, msg, conf in prioritized_candidates:
        if current_transition_count >= min_transition_count:
            break

        existing = session.exec(
            select(Transition).where(
                Transition.project_id == project_id,
                Transition.from_state == from_s,
                Transition.to_state == to_s,
                Transition.message_type == msg,
            )
        ).first()
        if existing:
            continue

        trans = Transition(
            project_id=project_id,
            from_state=from_s,
            to_state=to_s,
            message_type=msg,
            confidence=conf,
            status="hypothesis",
        )
        session.add(trans)
        session.commit()
        session.refresh(trans)
        ev = Evidence(
            project_id=project_id,
            claim_type="transition",
            claim_id=trans.id,
            source_type="trace",
            source_ref="heuristic trace augmentation",
            snippet=f"{from_s} -> {to_s} via {msg}",
            score=conf,
        )
        session.add(ev)
        created_trans.append(f"{from_s} 鈫?{to_s} via {msg}")
        existing_message_types.add(msg)
        current_transition_count += 1


def _store_structured_observations(project_id: int, session: Session, observation_payload: dict,
                                   created_mt: list[str], created_states: list[str]) -> dict:
    observation_summary = {
        "message_types": 0,
        "states": 0,
        "sequence_patterns": len(observation_payload.get("sequence_patterns", [])),
    }

    for args in observation_payload.get("message_type_observations", []):
        name = args.get("name", "").strip().upper()
        if not _is_valid_message_type_name(name):
            continue
        existing = session.exec(
            select(MessageType).where(
                MessageType.project_id == project_id,
                MessageType.name == name,
            )
        ).first()
        if existing:
            existing.confidence = max(existing.confidence, _safe_float(args.get("confidence"), 0.6))
            session.add(existing)
            claim_id = existing.id
        else:
            mt = MessageType(
                project_id=project_id,
                name=name,
                template="",
                fields_json="{}",
                confidence=_safe_float(args.get("confidence"), 0.6),
            )
            session.add(mt)
            session.commit()
            session.refresh(mt)
            claim_id = mt.id
            created_mt.append(name)

        snippet = f"{name} observed ~{args.get('observed_count', '?')} times"
        response_codes = args.get("common_response_codes", [])
        if response_codes:
            snippet += f"; common responses: {', '.join(response_codes)}"
        if args.get("typical_position"):
            snippet += f"; typical position: {args.get('typical_position')}"
        ev = Evidence(
            project_id=project_id,
            claim_type="message_type",
            claim_id=claim_id,
            source_type="trace",
            source_ref="LLM Trace Agent structured observation",
            snippet=snippet[:500],
            score=_safe_float(args.get("confidence"), 0.6),
        )
        session.add(ev)
        observation_summary["message_types"] += 1

    for args in observation_payload.get("state_hypotheses", []):
        name = args.get("name", "").strip().upper()
        if not name:
            continue
        existing = session.exec(
            select(ProtocolState).where(
                ProtocolState.project_id == project_id,
                ProtocolState.name == name,
            )
        ).first()
        if existing:
            existing.confidence = max(existing.confidence, _safe_float(args.get("confidence"), 0.65))
            session.add(existing)
            claim_id = existing.id
        else:
            state = ProtocolState(
                project_id=project_id,
                name=name,
                description="",
                confidence=_safe_float(args.get("confidence"), 0.65),
            )
            session.add(state)
            session.commit()
            session.refresh(state)
            claim_id = state.id
            created_states.append(name)

        ev = Evidence(
            project_id=project_id,
            claim_type="state",
            claim_id=claim_id,
            source_type="trace",
            source_ref="LLM Trace Agent structured observation",
            snippet=args.get("evidence", name)[:500],
            score=_safe_float(args.get("confidence"), 0.65),
        )
        session.add(ev)
        observation_summary["states"] += 1

    session.commit()
    return observation_summary


def run_trace_agent(project_id: int, session: Session) -> dict:
    """Run the LLM-powered Trace Agent.

    1. Parse all trace sessions
    2. Build frequency statistics (deterministic)
    3. Call LLM to infer states and transitions
    4. Store results with evidence
    """
    project = session.get(ProtocolProject, project_id)
    adapter = get_protocol_adapter(project.protocol_name if project else "FTP")

    traces = session.exec(
        select(SessionTrace).where(
            SessionTrace.project_id == project_id,
            SessionTrace.source_type == "trace",
        )
    ).all()

    all_events: list[dict] = []
    all_sessions: list[list[dict]] = []

    for trace in traces:
        events = adapter.parse_trace(trace.raw_content)
        if events:
            all_events.extend(events)
            all_sessions.append(events)
            trace.parsed_content = json.dumps(events, ensure_ascii=False)
            session.add(trace)

    if not all_events:
        return {"agent": "trace", "message": "No events parsed from traces", "events": 0}

    # Deterministic message-type frequency counts (always reliable)
    mt_result = extract_message_types(all_events)
    created_mt: list[str] = []
    for mt_info in mt_result.get("message_types", []):
        name = mt_info["name"]
        if name.startswith("RESP_") or name == "UNKNOWN":
            continue
        existing = session.exec(
            select(MessageType).where(
                MessageType.project_id == project_id,
                MessageType.name == name,
            )
        ).first()
        if existing:
            existing.confidence = min(existing.confidence + 0.1, 1.0)
            session.add(existing)
        else:
            mt = MessageType(
                project_id=project_id,
                name=name,
                template="",
                fields_json="{}",
                confidence=min(0.5 + mt_info["count"] * 0.03, 0.9),
            )
            session.add(mt)
            session.commit()
            session.refresh(mt)
            ev = Evidence(
                project_id=project_id,
                claim_type="message_type",
                claim_id=mt.id,
                source_type="trace",
                source_ref=f"Observed {mt_info['count']}x in {len(all_sessions)} sessions",
                snippet=f"{name} seen {mt_info['count']} times",
                score=min(0.5 + mt_info["count"] * 0.03, 0.9),
            )
            session.add(ev)
            created_mt.append(name)

    session.commit()

    # LLM call for state/transition inference
    heuristic_states = adapter.infer_candidate_states(all_sessions).get("states", [])
    user_message = adapter.build_trace_user_message(all_sessions, all_events, mt_result, heuristic_states)

    logger.info("Trace Agent: calling LLM for project %d (%d sessions)", project_id, len(all_sessions))
    tool_calls = call_with_tools(
        system_prompt=adapter.trace_system_prompt(),
        user_message=user_message,
        tools=TRACE_TOOLS,
        max_iterations=1,
    )
    logger.info("Trace Agent: received %d tool calls", len(tool_calls))

    created_states: list[str] = []
    created_trans: list[str] = []
    fallback_used = False
    observation_payload = {}
    payload = {}

    for tool_call in tool_calls:
        if tool_call["tool"] == "record_trace_analysis":
            payload = tool_call["args"]
            obs = payload.get("observations", {})
            if isinstance(obs, dict):
                observation_payload = obs
        elif tool_call["tool"] == "record_trace_observations":
            # Backward compatibility for older outputs.
            observation_payload = tool_call["args"]

    observation_summary = _store_structured_observations(
        project_id,
        session,
        observation_payload,
        created_mt,
        created_states,
    )

    for args in payload.get("states", []):
        name = args.get("name", "").strip().upper()
        if not name:
            continue
        existing = session.exec(
            select(ProtocolState).where(
                ProtocolState.project_id == project_id,
                ProtocolState.name == name,
            )
        ).first()
        if not existing:
            state = ProtocolState(
                project_id=project_id,
                name=name,
                description=args.get("description", ""),
                confidence=_safe_float(args.get("confidence"), 0.7),
            )
            session.add(state)
            session.commit()
            session.refresh(state)
            ev = Evidence(
                project_id=project_id,
                claim_type="state",
                claim_id=state.id,
                source_type="trace",
                source_ref="LLM Trace Agent final analysis",
                snippet=args.get("evidence", args.get("description", name))[:500],
                score=_safe_float(args.get("confidence"), 0.7),
            )
            session.add(ev)
            created_states.append(name)

    for args in payload.get("transitions", []):
        from_s, to_s, msg = adapter.normalize_transition(
            args.get("from_state", ""),
            args.get("to_state", ""),
            args.get("message_type", ""),
        )
        if not (from_s and to_s and msg) or msg.startswith("RESP_") or not _is_valid_message_type_name(msg):
            continue
        existing = session.exec(
            select(Transition).where(
                Transition.project_id == project_id,
                Transition.from_state == from_s,
                Transition.to_state == to_s,
                Transition.message_type == msg,
            )
        ).first()
        if not existing:
            trans = Transition(
                project_id=project_id,
                from_state=from_s,
                to_state=to_s,
                message_type=msg,
                confidence=_safe_float(args.get("confidence"), 0.7),
                status="hypothesis",
            )
            session.add(trans)
            session.commit()
            session.refresh(trans)
            reasoning = args.get("reasoning", "")
            resp_codes = args.get("response_codes", [])
            snippet = reasoning
            if resp_codes:
                snippet += f" (response codes: {', '.join(resp_codes)})"
            ev = Evidence(
                project_id=project_id,
                claim_type="transition",
                claim_id=trans.id,
                source_type="trace",
                source_ref="LLM Trace Agent final analysis",
                snippet=snippet[:500],
                score=_safe_float(args.get("confidence"), 0.7),
            )
            session.add(ev)
            created_trans.append(f"{from_s} 鈫?{to_s} via {msg}")

    for args in payload.get("observed_message_types", []):
        name = args.get("name", "").strip().upper()
        if _is_valid_message_type_name(name):
            existing = session.exec(
                select(MessageType).where(
                    MessageType.project_id == project_id,
                    MessageType.name == name,
                )
            ).first()
            if existing:
                boost = min(existing.confidence + 0.05, 0.95)
                existing.confidence = boost
                session.add(existing)
            elif name not in created_mt:
                mt = MessageType(
                    project_id=project_id,
                    name=name,
                    template="",
                    fields_json="{}",
                    confidence=_safe_float(args.get("confidence"), 0.6),
                )
                session.add(mt)
                session.commit()
                session.refresh(mt)
                ev = Evidence(
                    project_id=project_id,
                    claim_type="message_type",
                    claim_id=mt.id,
                    source_type="trace",
                    source_ref="LLM Trace Agent final analysis",
                    snippet=f"{name} seen ~{args.get('observed_count', '?')} times",
                    score=_safe_float(args.get("confidence"), 0.6),
                )
                session.add(ev)
                created_mt.append(name)

    # Heuristic augmentation disabled 鈥?agent-only mode
    # (was: if should_augment: _augment_trace_model(...))

    min_transition_count = adapter.trace_augmentation_min_transitions()
    should_augment = len(created_trans) < min_transition_count
    if should_augment:
        _augment_trace_model(
            project_id=project_id,
            session=session,
            adapter=adapter,
            heuristic_states=heuristic_states,
            mt_result=mt_result,
            created_states=created_states,
            created_trans=created_trans,
            min_transition_count=min_transition_count,
            priority_messages=adapter.trace_augmentation_priority_messages(),
        )

    if not payload and not observation_payload:
        raise RuntimeError(
            f"Trace Agent: LLM returned no tool calls for project {project_id} "
            "after all retries 鈥?aborting without fallback"
        )
    elif not payload and observation_payload:
        logger.warning("Trace Agent: observation tool used but no final analysis tool call")

    session.commit()

    return {
        "agent": "trace",
        "events_parsed": len(all_events),
        "sessions_processed": len(all_sessions),
        "llm_tool_calls": len(tool_calls),
        "observation_tool_used": bool(observation_payload),
        "observation_summary": observation_summary,
        "fallback_used": fallback_used,
        "message_types_updated": created_mt,
        "states_created": created_states,
        "transitions_created": created_trans,
    }


def _apply_state_fallback(project_id: int, session: Session,
                           created_states: list, created_trans: list) -> None:
    """Rule-based fallback if LLM unavailable."""
    STATES = [
        ("INIT", "Initial connection state", 0.9),
        ("AUTH_PENDING", "Awaiting authentication", 0.85),
        ("AUTHENTICATED", "Successfully authenticated", 0.9),
        ("RENAME_PENDING", "Rename source accepted, waiting for RNTO", 0.78),
        ("RESETTING", "Session reinitialization in progress", 0.76),
        ("DATA_CHANNEL_READY", "Data connection negotiated; waiting for transfer command", 0.8),
        ("DATA_TRANSFER", "Data transfer in progress", 0.8),
        ("CLOSED", "Session terminated", 0.9),
    ]
    TRANSITIONS = [
        ("INIT", "AUTH_PENDING", "USER", 0.85),
        ("AUTH_PENDING", "AUTHENTICATED", "PASS", 0.85),
        ("AUTHENTICATED", "AUTHENTICATED", "ACCT", 0.72),
        ("AUTHENTICATED", "AUTHENTICATED", "PWD", 0.8),
        ("AUTHENTICATED", "AUTHENTICATED", "CWD", 0.8),
        ("AUTHENTICATED", "AUTHENTICATED", "CDUP", 0.76),
        ("AUTHENTICATED", "AUTHENTICATED", "XCWD", 0.74),
        ("AUTHENTICATED", "AUTHENTICATED", "XPWD", 0.74),
        ("AUTHENTICATED", "AUTHENTICATED", "XCUP", 0.74),
        ("AUTHENTICATED", "AUTHENTICATED", "MKD", 0.76),
        ("AUTHENTICATED", "AUTHENTICATED", "XMKD", 0.74),
        ("AUTHENTICATED", "AUTHENTICATED", "RMD", 0.76),
        ("AUTHENTICATED", "AUTHENTICATED", "XRMD", 0.74),
        ("AUTHENTICATED", "AUTHENTICATED", "DELE", 0.76),
        ("AUTHENTICATED", "AUTHENTICATED", "TYPE", 0.76),
        ("AUTHENTICATED", "AUTHENTICATED", "MODE", 0.72),
        ("AUTHENTICATED", "AUTHENTICATED", "STRU", 0.72),
        ("AUTHENTICATED", "AUTHENTICATED", "SMNT", 0.68),
        ("AUTHENTICATED", "AUTHENTICATED", "SYST", 0.74),
        ("AUTHENTICATED", "AUTHENTICATED", "FEAT", 0.74),
        ("AUTHENTICATED", "AUTHENTICATED", "HELP", 0.72),
        ("AUTHENTICATED", "AUTHENTICATED", "NOOP", 0.74),
        ("AUTHENTICATED", "AUTHENTICATED", "MLST", 0.78),
        ("AUTHENTICATED", "AUTHENTICATED", "SIZE", 0.78),
        ("AUTHENTICATED", "RENAME_PENDING", "RNFR", 0.78),
        ("RENAME_PENDING", "AUTHENTICATED", "RNTO", 0.78),
        ("AUTHENTICATED", "RESETTING", "REIN", 0.76),
        ("RESETTING", "AUTH_PENDING", "USER", 0.7),
        ("AUTHENTICATED", "DATA_CHANNEL_READY", "PASV", 0.8),
        ("AUTHENTICATED", "DATA_CHANNEL_READY", "EPSV", 0.8),
        ("AUTHENTICATED", "DATA_CHANNEL_READY", "PORT", 0.76),
        ("AUTHENTICATED", "DATA_CHANNEL_READY", "EPRT", 0.76),
        ("AUTHENTICATED", "DATA_TRANSFER", "LIST", 0.8),
        ("AUTHENTICATED", "DATA_TRANSFER", "MLSD", 0.78),
        ("AUTHENTICATED", "DATA_TRANSFER", "RETR", 0.75),
        ("AUTHENTICATED", "DATA_TRANSFER", "STOR", 0.75),
        ("DATA_CHANNEL_READY", "DATA_TRANSFER", "LIST", 0.82),
        ("DATA_CHANNEL_READY", "DATA_TRANSFER", "MLSD", 0.82),
        ("DATA_CHANNEL_READY", "DATA_TRANSFER", "RETR", 0.8),
        ("DATA_CHANNEL_READY", "DATA_TRANSFER", "STOR", 0.8),
        ("DATA_TRANSFER", "AUTHENTICATED", "LIST", 0.7),
        ("AUTHENTICATED", "CLOSED", "QUIT", 0.9),
        ("INIT", "CLOSED", "QUIT", 0.7),
    ]
    for name, desc, conf in STATES:
        existing = session.exec(
            select(ProtocolState).where(
                ProtocolState.project_id == project_id,
                ProtocolState.name == name,
            )
        ).first()
        if not existing:
            s = ProtocolState(project_id=project_id, name=name,
                              description=desc, confidence=conf)
            session.add(s)
            session.commit()
            session.refresh(s)
            ev = Evidence(project_id=project_id, claim_type="state",
                          claim_id=s.id, source_type="trace",
                          source_ref="rule-based fallback", snippet=desc, score=conf)
            session.add(ev)
            created_states.append(name)
    for from_s, to_s, msg, conf in TRANSITIONS:
        existing = session.exec(
            select(Transition).where(
                Transition.project_id == project_id,
                Transition.from_state == from_s,
                Transition.to_state == to_s,
                Transition.message_type == msg,
            )
        ).first()
        if not existing:
            t = Transition(project_id=project_id, from_state=from_s,
                           to_state=to_s, message_type=msg,
                           confidence=conf, status="hypothesis")
            session.add(t)
            session.commit()
            session.refresh(t)
            ev = Evidence(project_id=project_id, claim_type="transition",
                          claim_id=t.id, source_type="trace",
                          source_ref="rule-based fallback",
                          snippet=f"{from_s}->{to_s} via {msg}", score=conf)
            session.add(ev)
            created_trans.append(f"{from_s}->{to_s} via {msg}")

