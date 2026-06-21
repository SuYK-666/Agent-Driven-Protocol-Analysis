"""Spec Agent 鈥?extracts protocol knowledge from documentation summaries.

Task 5 (LLM-upgraded): Uses Gemini function calling to extract message types,
field semantics, ordering rules, and candidate protocol rules from docs and
observed trace patterns.
"""

from __future__ import annotations
from collections import Counter
import json
import logging
from sqlmodel import Session, select

from ..models.domain import SessionTrace, MessageType, Invariant, Evidence, ProtocolProject
from ..protocols.registry import get_protocol_adapter
from ..tools.ftp_parser import parse_ftp_session
from ..core.llm_client import call_with_tools

logger = logging.getLogger(__name__)

def _safe_float(value, default: float) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default

# ---------------------------------------------------------------------------
# Tool schemas for LLM function calling
# ---------------------------------------------------------------------------

SPEC_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "record_spec_analysis",
            "description": "Record the complete protocol spec analysis in a single call.",
            "parameters": {
                "type": "object",
                "properties": {
                    "message_types": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "template": {"type": "string"},
                                "fields": {
                                    "type": "object",
                                    "additionalProperties": {"type": "string"},
                                },
                                "description": {"type": "string"},
                                "confidence": {"type": "number"},
                            },
                            "required": ["name", "template", "fields", "description", "confidence"],
                        },
                    },
                    "ordering_rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "rule_text": {"type": "string"},
                                "rule_type": {
                                    "type": "string",
                                    "enum": ["ordering", "field_constraint", "conditional", "state_requirement"],
                                },
                                "confidence": {"type": "number"},
                                "evidence_snippet": {"type": "string"},
                            },
                            "required": ["rule_text", "rule_type", "confidence"],
                        },
                    },
                    "field_constraints": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "message_type": {"type": "string"},
                                "field_name": {"type": "string"},
                                "constraint": {"type": "string"},
                                "confidence": {"type": "number"},
                            },
                            "required": ["message_type", "field_name", "constraint", "confidence"],
                        },
                    },
                },
                "required": ["message_types", "ordering_rules", "field_constraints"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are an expert protocol analyst specializing in network protocol state machine extraction.

Your task: analyze the provided FTP protocol documentation and session trace summaries, then call the provided tool exactly once to record ALL discovered protocol knowledge.

Guidelines:
- Include EVERY discovered FTP command in message_types
- Include EVERY sequencing constraint in ordering_rules
- Include every specific field requirement in field_constraints
- Include commands observed in traces even if they are extension commands from server-specific implementations
- Do not record server response pseudo-types such as RESP_220 or RESP_530 as message_types
- Set confidence based on how strongly the evidence supports the claim (0.7-0.9 for doc evidence, 0.8-0.95 for observed traces)
- Be thorough 鈥?extract all commands and rules you can identify
- Return one comprehensive batch, not many small calls"""


def _format_trace_summary(traces: list) -> str:
    """Format trace sessions into a readable command-sequence summary."""
    if not traces:
        return "(no trace data available)"
    summary_parts = []
    for i, trace in enumerate(traces[:10]):
        events = []
        try:
            ev_list = parse_ftp_session(trace.raw_content)
            for ev in ev_list:
                mt = ev.get("message_type", "?")
                resp = ev.get("response")
                code = resp.get("code", "?") if resp else "?"
                events.append(f"  {mt} 鈫?{code}")
        except Exception:
            raw = trace.raw_content[:200]
            events = [f"  (raw): {raw}"]
        summary_parts.append(f"Session {i+1}:\n" + "\n".join(events[:15]))
    return "\n\n".join(summary_parts)


def _summarize_observed_commands(traces: list) -> str:
    counts: Counter[str] = Counter()
    for trace in traces:
        try:
            ev_list = parse_ftp_session(trace.raw_content)
        except Exception:
            ev_list = []
        for ev in ev_list:
            mt = ev.get("message_type", "")
            if mt and not mt.startswith("RESP_") and mt != "UNKNOWN":
                counts[mt] += 1
    if not counts:
        return "(no observed command summary available)"
    return "\n".join(f"- {name}: {count}" for name, count in counts.most_common())


def run_spec_agent(project_id: int, session: Session) -> dict:
    """Run the LLM-powered Spec Agent.

    1. Loads doc sources and trace summaries as context
    2. Calls Gemini via function calling to extract protocol knowledge
    3. Stores MessageType and Invariant records with evidence
    """
    project = session.get(ProtocolProject, project_id)
    adapter = get_protocol_adapter(project.protocol_name if project else "FTP")

    docs = session.exec(
        select(SessionTrace).where(
            SessionTrace.project_id == project_id,
            SessionTrace.source_type == "doc",
        )
    ).all()

    traces = session.exec(
        select(SessionTrace).where(
            SessionTrace.project_id == project_id,
            SessionTrace.source_type == "trace",
        )
    ).all()

    doc_content = "\n\n".join(d.raw_content for d in docs) if docs else "(no documentation provided)"
    user_message = adapter.build_spec_user_message(doc_content, traces)

    logger.info("Spec Agent: calling LLM for project %d", project_id)
    tool_calls = call_with_tools(
        system_prompt=adapter.spec_system_prompt(),
        user_message=user_message,
        tools=SPEC_TOOLS,
        max_iterations=1,
    )
    logger.info("Spec Agent: received %d tool calls", len(tool_calls))

    created_message_types: list[str] = []
    created_invariants: list[str] = []
    fallback_used = False
    payload = {}

    if tool_calls and tool_calls[0]["tool"] == "record_spec_analysis":
        payload = tool_calls[0]["args"]

    for args in payload.get("message_types", []):
        name = args.get("name", "").upper().strip()
        if not name or name.startswith("RESP_"):
            continue
        existing = session.exec(
            select(MessageType).where(
                MessageType.project_id == project_id,
                MessageType.name == name,
            )
        ).first()
        if not existing:
            mt = MessageType(
                project_id=project_id,
                name=name,
                template=args.get("template", ""),
                fields_json=json.dumps(args.get("fields", {})),
                confidence=_safe_float(args.get("confidence"), 0.7),
            )
            session.add(mt)
            session.commit()
            session.refresh(mt)
            ev = Evidence(
                project_id=project_id,
                claim_type="message_type",
                claim_id=mt.id,
                source_type="doc",
                source_ref="LLM Spec Agent (Gemini function calling)",
                snippet=args.get("description", name),
                score=_safe_float(args.get("confidence"), 0.7),
            )
            session.add(ev)
            created_message_types.append(name)

    for args in payload.get("ordering_rules", []):
        rule_text = args.get("rule_text", "").strip()
        if not rule_text:
            continue
        existing = session.exec(
            select(Invariant).where(
                Invariant.project_id == project_id,
                Invariant.rule_text == rule_text,
            )
        ).first()
        if not existing:
            inv = Invariant(
                project_id=project_id,
                rule_text=rule_text,
                rule_type=args.get("rule_type", "ordering"),
                confidence=_safe_float(args.get("confidence"), 0.7),
                status="hypothesis",
            )
            session.add(inv)
            session.commit()
            session.refresh(inv)
            snippet = args.get("evidence_snippet", rule_text)
            ev = Evidence(
                project_id=project_id,
                claim_type="invariant",
                claim_id=inv.id,
                source_type="doc",
                source_ref="LLM Spec Agent (Gemini function calling)",
                snippet=snippet[:500],
                score=_safe_float(args.get("confidence"), 0.7),
            )
            session.add(ev)
            created_invariants.append(rule_text)

    for args in payload.get("field_constraints", []):
        msg_type = args.get("message_type", "").upper()
        field = args.get("field_name", "")
        constraint = args.get("constraint", "")
        if msg_type and field and constraint:
            rule_text = f"{msg_type}.{field}: {constraint}"
            existing = session.exec(
                select(Invariant).where(
                    Invariant.project_id == project_id,
                    Invariant.rule_text == rule_text,
                )
            ).first()
            if not existing:
                inv = Invariant(
                    project_id=project_id,
                    rule_text=rule_text,
                    rule_type="field_constraint",
                    confidence=_safe_float(args.get("confidence"), 0.7),
                    status="hypothesis",
                )
                session.add(inv)
                session.commit()
                session.refresh(inv)
                ev = Evidence(
                    project_id=project_id,
                    claim_type="invariant",
                    claim_id=inv.id,
                    source_type="doc",
                    source_ref="LLM Spec Agent field analysis",
                    snippet=rule_text,
                    score=_safe_float(args.get("confidence"), 0.7),
                )
                session.add(ev)
                created_invariants.append(rule_text)

    if not payload:
        raise RuntimeError(
            f"Spec Agent: LLM returned no usable tool calls for project {project_id} "
            "after all retries 鈥?aborting without fallback"
        )

    session.commit()

    return {
        "agent": "spec",
        "llm_tool_calls": len(tool_calls),
        "fallback_used": fallback_used,
        "message_types_created": created_message_types,
        "invariants_created": created_invariants,
        "docs_processed": len(docs),
        "traces_summarized": len(traces),
    }


def _apply_fallback(project_id: int, session: Session,
                    created_mt: list, created_inv: list) -> None:
    """Rule-based fallback if LLM is unavailable."""
    BASELINE_MT = [
        ("USER", "USER <username>", {"username": "string"}, 0.8),
        ("PASS", "PASS <password>", {"password": "string"}, 0.8),
        ("QUIT", "QUIT", {}, 0.9),
        ("LIST", "LIST [<path>]", {"path": "string"}, 0.8),
        ("RETR", "RETR <filename>", {"filename": "string"}, 0.8),
        ("STOR", "STOR <filename>", {"filename": "string"}, 0.8),
        ("PWD", "PWD", {}, 0.8),
        ("CWD", "CWD <directory>", {"directory": "string"}, 0.8),
        ("PASV", "PASV", {}, 0.75),
        ("SYST", "SYST", {}, 0.75),
        ("FEAT", "FEAT", {}, 0.75),
        ("NOOP", "NOOP", {}, 0.75),
        ("TYPE", "TYPE <A|I>", {"transfer_type": "string"}, 0.75),
        ("DELE", "DELE <filename>", {"filename": "string"}, 0.7),
    ]
    BASELINE_RULES = [
        ("PASS must appear after USER", "ordering", 0.9),
        ("LIST, RETR, STOR require prior successful authentication", "ordering", 0.85),
        ("QUIT terminates the session from any state", "ordering", 0.9),
        ("DATA commands typically require PASV or PORT first", "ordering", 0.7),
    ]
    for name, template, fields, conf in BASELINE_MT:
        existing = session.exec(
            select(MessageType).where(
                MessageType.project_id == project_id,
                MessageType.name == name,
            )
        ).first()
        if not existing:
            mt = MessageType(project_id=project_id, name=name,
                             template=template, fields_json=json.dumps(fields),
                             confidence=conf)
            session.add(mt)
            session.commit()
            session.refresh(mt)
            ev = Evidence(project_id=project_id, claim_type="message_type",
                          claim_id=mt.id, source_type="doc",
                          source_ref="rule-based fallback", snippet=name, score=conf)
            session.add(ev)
            created_mt.append(name)
    for rule_text, rule_type, conf in BASELINE_RULES:
        existing = session.exec(
            select(Invariant).where(
                Invariant.project_id == project_id,
                Invariant.rule_text == rule_text,
            )
        ).first()
        if not existing:
            inv = Invariant(project_id=project_id, rule_text=rule_text,
                            rule_type=rule_type, confidence=conf, status="hypothesis")
            session.add(inv)
            session.commit()
            session.refresh(inv)
            ev = Evidence(project_id=project_id, claim_type="invariant",
                          claim_id=inv.id, source_type="doc",
                          source_ref="rule-based fallback", snippet=rule_text, score=conf)
            session.add(ev)
            created_inv.append(rule_text)

