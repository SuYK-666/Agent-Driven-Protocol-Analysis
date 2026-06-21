"""SMTP-specific protocol adapter with dedicated parser and probe executor."""
from __future__ import annotations

import re
import socket
from collections import Counter
from pathlib import Path

from ..generic_text_adapter import GenericTextProtocolAdapter
from ...core.config import settings


# SMTP commands that are valid client-to-server messages
_SMTP_COMMANDS = frozenset([
    "EHLO", "HELO", "MAIL", "RCPT", "DATA", "RSET", "QUIT",
    "NOOP", "VRFY", "EXPN", "AUTH", "STARTTLS", "HELP",
])

# Patterns for recognising SMTP response lines (3-digit code)
_SMTP_RESP_RE = re.compile(r"^(\d{3})[\s-](.*)")

# Pattern to detect server greeting lines (start of session)
_SMTP_GREETING_RE = re.compile(r"^220\s")


def _classify_smtp_state(events: list[dict]) -> list[str]:
    """Heuristic: assign a state label to each event given its sequence."""
    states: list[str] = []
    current = "INIT"
    for ev in events:
        cmd = ev.get("message_type", "")
        code = (ev.get("response") or {}).get("code", "")
        if cmd in ("EHLO", "HELO"):
            current = "GREETED" if code == "250" else current
        elif cmd == "AUTH" and code == "235":
            current = "AUTHENTICATED"
        elif cmd == "MAIL":
            current = "MAIL_PENDING" if code == "250" else current
        elif cmd == "RCPT":
            if code == "250":
                current = "RCPT_PENDING"
        elif cmd == "DATA" and code == "354":
            current = "DATA_PENDING"
        elif cmd == "RSET":
            current = "GREETED"
        elif cmd == "QUIT":
            current = "CLOSED"
        states.append(current)
    return states


class SMTPProtocolAdapter(GenericTextProtocolAdapter):
    """SMTP-specific adapter: richer parser, state heuristics, live probe."""

    def __init__(self) -> None:
        super().__init__(
            name="SMTP",
            display_name="Simple Mail Transfer Protocol",
            default_port=25,
        )

    # ------------------------------------------------------------------
    # Parser
    # ------------------------------------------------------------------

    def parse_session(self, raw_text: str) -> list[dict]:
        """Parse an SMTP session trace into structured events.

        Handles:
        - EHLO / HELO with optional continuation lines (250-...)
        - MAIL FROM: / RCPT TO: addressing
        - DATA + body accumulation until "."
        - Multi-line server responses (3xx-5xx)
        - AUTH challenge/response sequences
        """
        events: list[dict] = []
        lines = raw_text.splitlines()
        i = 0
        in_data_body = False
        current_cmd_event: dict | None = None

        while i < len(lines):
            line = lines[i].rstrip()
            i += 1

            if not line:
                continue

            # Inside DATA body – look for terminating "."
            if in_data_body:
                if line.strip() == ".":
                    in_data_body = False
                    if current_cmd_event is not None:
                        # Next server response goes to this event
                        pass
                continue

            # Server response (3-digit code)
            m_resp = _SMTP_RESP_RE.match(line)
            if m_resp:
                code = m_resp.group(1)
                text = m_resp.group(2)[:200]
                # Multi-line continuation: 250-xxx means more lines follow
                continuation = []
                while line[3:4] == "-":
                    if i >= len(lines):
                        break
                    line = lines[i].rstrip()
                    i += 1
                    m2 = _SMTP_RESP_RE.match(line)
                    if m2:
                        continuation.append(m2.group(2))
                    # else raw continuation (AUTH base64 challenges etc.)
                if events:
                    events[-1]["response"] = {
                        "code": code,
                        "text": text,
                        "continuation": continuation,
                    }
                continue

            # Client command
            upper = line.upper()
            cmd_match = re.match(r"^([A-Z]+)(?:\s+(.*))?$", upper)
            if not cmd_match:
                continue
            verb = cmd_match.group(1)
            args_raw = (cmd_match.group(2) or "").strip()

            if verb not in _SMTP_COMMANDS:
                # Might be AUTH base64 challenge response – skip
                continue

            fields: dict = {}

            if verb == "EHLO" or verb == "HELO":
                fields["domain"] = args_raw

            elif verb == "MAIL":
                # MAIL FROM:<addr>
                addr_m = re.search(r"FROM:\s*<([^>]*)>", line, re.IGNORECASE)
                fields["from"] = addr_m.group(1) if addr_m else args_raw
                # SIZE extension
                size_m = re.search(r"SIZE=(\d+)", line, re.IGNORECASE)
                if size_m:
                    fields["size"] = size_m.group(1)

            elif verb == "RCPT":
                addr_m = re.search(r"TO:\s*<([^>]*)>", line, re.IGNORECASE)
                fields["to"] = addr_m.group(1) if addr_m else args_raw

            elif verb == "AUTH":
                parts = args_raw.split()
                fields["mechanism"] = parts[0] if parts else ""

            elif verb == "DATA":
                in_data_body = True  # body follows after 354
                current_cmd_event = {"message_type": "DATA", "fields": fields}
                events.append(current_cmd_event)
                continue

            else:
                if args_raw:
                    fields["args"] = args_raw

            ev = {"message_type": verb, "fields": fields}
            events.append(ev)
            current_cmd_event = ev

        return events

    # ------------------------------------------------------------------
    # State inference
    # ------------------------------------------------------------------

    def infer_candidate_states(self, sessions: list[list[dict]]) -> dict:
        return {
            "states": [
                {"name": "INIT", "description": "TCP connected, awaiting banner"},
                {"name": "CONNECTED", "description": "220 banner received"},
                {"name": "GREETED", "description": "EHLO/HELO accepted"},
                {"name": "AUTHENTICATED", "description": "AUTH succeeded"},
                {"name": "MAIL_PENDING", "description": "MAIL FROM accepted"},
                {"name": "RCPT_PENDING", "description": "≥1 RCPT TO accepted"},
                {"name": "DATA_PENDING", "description": "354 received, sending body"},
                {"name": "MESSAGE_SENT", "description": "250 after DATA body"},
                {"name": "CLOSED", "description": "QUIT sent / connection closed"},
            ]
        }

    def propose_transitions(self, states: list[dict], messages: list[dict]) -> dict:
        transitions = [
            {"from_state": "INIT", "to_state": "CONNECTED", "message_type": "BANNER", "confidence": 0.95},
            {"from_state": "CONNECTED", "to_state": "GREETED", "message_type": "EHLO", "confidence": 0.95},
            {"from_state": "CONNECTED", "to_state": "GREETED", "message_type": "HELO", "confidence": 0.85},
            {"from_state": "GREETED", "to_state": "AUTHENTICATED", "message_type": "AUTH", "confidence": 0.85},
            {"from_state": "GREETED", "to_state": "MAIL_PENDING", "message_type": "MAIL", "confidence": 0.90},
            {"from_state": "AUTHENTICATED", "to_state": "MAIL_PENDING", "message_type": "MAIL", "confidence": 0.90},
            {"from_state": "MAIL_PENDING", "to_state": "RCPT_PENDING", "message_type": "RCPT", "confidence": 0.90},
            {"from_state": "RCPT_PENDING", "to_state": "RCPT_PENDING", "message_type": "RCPT", "confidence": 0.85},
            {"from_state": "RCPT_PENDING", "to_state": "DATA_PENDING", "message_type": "DATA", "confidence": 0.90},
            {"from_state": "DATA_PENDING", "to_state": "MESSAGE_SENT", "message_type": "DATA_END", "confidence": 0.85},
            {"from_state": "MESSAGE_SENT", "to_state": "MAIL_PENDING", "message_type": "MAIL", "confidence": 0.80},
            {"from_state": "MAIL_PENDING", "to_state": "GREETED", "message_type": "RSET", "confidence": 0.85},
            {"from_state": "RCPT_PENDING", "to_state": "GREETED", "message_type": "RSET", "confidence": 0.85},
            {"from_state": "GREETED", "to_state": "GREETED", "message_type": "NOOP", "confidence": 0.80},
            {"from_state": "GREETED", "to_state": "GREETED", "message_type": "VRFY", "confidence": 0.70},
            {"from_state": "GREETED", "to_state": "CLOSED", "message_type": "QUIT", "confidence": 0.95},
            {"from_state": "CONNECTED", "to_state": "CLOSED", "message_type": "QUIT", "confidence": 0.80},
            {"from_state": "MESSAGE_SENT", "to_state": "CLOSED", "message_type": "QUIT", "confidence": 0.90},
        ]
        return {"transitions": transitions}

    def trace_augmentation_min_transitions(self) -> int:
        return 12

    def trace_augmentation_priority_messages(self) -> list[str]:
        return ["EHLO", "HELO", "MAIL", "RCPT", "DATA", "RSET", "QUIT", "AUTH", "NOOP", "STARTTLS", "VRFY"]

    # ------------------------------------------------------------------
    # Prompts
    # ------------------------------------------------------------------

    def spec_system_prompt(self) -> str:
        return (
            "You are an expert SMTP (RFC 5321) protocol analyst. "
            "Extract all message types, their field constraints, and ordering rules. "
            "Pay attention to the mail transaction sequence: EHLO→MAIL→RCPT→DATA. "
            "Call the provided tool exactly once with comprehensive results."
        )

    def probe_system_prompt(self) -> str:
        return (
            "You are a conservative SMTP probe planner (RFC 5321). "
            "Choose up to twelve probes that test state transitions, "
            "such as sending RCPT before MAIL, or DATA before RCPT. "
            "Call the tool exactly once."
        )

    # ------------------------------------------------------------------
    # Live probe executor
    # ------------------------------------------------------------------

    def select_probe_targets(self, transitions: list, invariants: list) -> list[dict]:
        """Select up to 12 SMTP probe targets with preference for verifiable sequencing rules."""
        fixed_targets: list[dict] = []

        # 1. DATA requires prior MAIL + RCPT — probe by sending DATA immediately after EHLO
        data_trans = next(
            (t for t in transitions if t.message_type == "DATA"),
            None
        )
        if data_trans and len(fixed_targets) < 12:
            fixed_targets.append({
                "type": "transition",
                "claim": data_trans,
                "description": f"{data_trans.from_state} -> {data_trans.to_state} via DATA (dependency: MAIL+RCPT must precede)",
            })

        # 2. QUIT reachable from GREETED state
        quit_trans = next(
            (t for t in transitions if t.message_type == "QUIT" and t.from_state == "GREETED"),
            None
        )
        if quit_trans and len(fixed_targets) < 12:
            fixed_targets.append({
                "type": "transition",
                "claim": quit_trans,
                "description": f"{quit_trans.from_state} -> {quit_trans.to_state} via QUIT",
            })

        # 3. RCPT before MAIL — should produce 503 error
        rcpt_trans = next(
            (t for t in transitions if t.message_type == "RCPT"),
            None
        )
        if rcpt_trans and len(fixed_targets) < 12:
            fixed_targets.append({
                "type": "transition",
                "claim": rcpt_trans,
                "description": f"RCPT ordering: must follow MAIL FROM (probe sends RCPT without MAIL)",
            })

        if fixed_targets:
            probe_targets = list(fixed_targets)
        else:
            probe_targets = []

        # Fallback: hypothesis transitions
        for t in transitions:
            if t.status == "hypothesis":
                probe_targets.append({
                    "type": "transition",
                    "claim": t,
                    "description": f"{t.from_state} -> {t.to_state} via {t.message_type}",
                })
                if len(probe_targets) >= 12:
                    break
        return probe_targets[:12]

    def generate_probe_commands(self, target: dict) -> list[str]:
        """Generate SMTP command sequences for a given probe target."""
        desc = target.get("description", "")
        claim = target["claim"]
        mt = getattr(claim, "message_type", "") if target["type"] == "transition" else ""

        # DATA dependency probe: send DATA before MAIL/RCPT — expect 503
        if mt == "DATA" or "DATA" in desc.upper():
            return ["EHLO probe.test", "DATA"]

        # QUIT from GREETED
        if mt == "QUIT" or "QUIT" in desc.upper():
            return ["EHLO probe.test", "QUIT"]

        # RCPT before MAIL — expect 503
        if "RCPT" in desc.upper() and "ordering" in desc.lower():
            return ["EHLO probe.test", "RCPT TO:<test@test.com>"]

        # MAIL→RCPT→DATA full flow
        if mt == "MAIL":
            return ["EHLO probe.test", "MAIL FROM:<sender@test.com>", "RCPT TO:<rcpt@test.com>", "DATA"]

        # EHLO/HELO
        if mt in ("EHLO", "HELO"):
            return [f"{mt} probe.test"]

        # RSET
        if mt == "RSET":
            return ["EHLO probe.test", "MAIL FROM:<sender@test.com>", "RSET"]

        # NOOP / VRFY
        if mt in ("NOOP", "VRFY"):
            return ["EHLO probe.test", mt if mt == "NOOP" else "VRFY postmaster"]

        # Default
        return ["EHLO probe.test"]

    def execute_probe(self, commands: list[str]) -> list[dict]:
        host = settings.SMTP_PROBE_HOST
        port = settings.SMTP_PROBE_PORT
        return self._smtp_exchange(host, port, commands)

    def probe_target_host(self) -> str:
        return settings.SMTP_PROBE_HOST

    def probe_target_port(self) -> int:
        return settings.SMTP_PROBE_PORT
