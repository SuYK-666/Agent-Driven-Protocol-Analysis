from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import socket

from ...core.config import settings
from ...tools.ftp_parser import parse_ftp_session, parse_ftp_session_pairs
from ...tools.protocol_tools import extract_message_types, infer_candidate_states, propose_transitions

TRANSFER_COMMANDS = {"LIST", "NLST", "MLSD", "RETR", "STOR", "APPE"}

_SPEC_SYSTEM_PROMPT = """You are an expert protocol analyst specializing in network protocol state machine extraction.

Your task: analyze the provided FTP protocol documentation and session trace summaries, then call the provided tool exactly once to record ALL discovered protocol knowledge.

Guidelines:
- Include EVERY discovered FTP command in message_types
- Include EVERY sequencing constraint in ordering_rules
- Include every specific field requirement in field_constraints
- Include commands observed in traces even if they are extension commands from server-specific implementations
- Do not record server response pseudo-types such as RESP_220 or RESP_530 as message_types
- Set confidence based on how strongly the evidence supports the claim (0.7-0.9 for doc evidence, 0.8-0.95 for observed traces)
- Be thorough — extract all commands and rules you can identify
- Return one comprehensive batch, not many small calls"""

_TRACE_SYSTEM_PROMPT = """You are an expert protocol analyst. Analyze the provided FTP session traces to recover the protocol state machine.

Your goal:
1. Identify distinct protocol states (e.g., INIT before login, AUTH_PENDING during authentication, AUTHENTICATED after successful login, DATA_CHANNEL_READY after PASV/EPSV/PORT/EPRT negotiation, DATA_TRANSFER during file operations, CLOSED after QUIT)
2. Identify state transitions triggered by specific FTP commands
3. Record observed message types with frequency information

In the same response, call `record_trace_analysis` exactly once.
Within that single tool call:
- `observations` must capture concrete message frequencies, common response patterns, candidate states, and recurring sequence interpretations.
- `states`, `transitions`, and `observed_message_types` must contain the final synthesized state-machine analysis after reasoning over observations.

Populate all sections comprehensively.
- Do not use server response pseudo-types such as RESP_220 or RESP_226 as message_type values in transitions
- Use response_codes to describe server outcomes while keeping the transition trigger as the client command
- Prefer states and transitions that are strongly grounded in repeated trace patterns, especially ProFuzzBench-observed commands
- Prefer modeling PASV/EPSV/PORT/EPRT as data-channel preparation, and model LIST/NLST/MLSD/RETR/STOR/APPE as transfer-triggering commands
- Treat MLST, SIZE, STAT, PWD, and CWD as metadata or navigation operations that usually keep the session authenticated rather than entering data transfer
- Treat REIN as entering an intermediate RESETTING / reinitialization state first; avoid modeling REIN as a direct AUTHENTICATED -> INIT jump when RESETTING is available

Focus on patterns: what command sequences lead to state changes? What response codes indicate successful vs failed transitions?"""

_PROBE_SYSTEM_PROMPT = """You are a conservative FTP probe planner.

Choose up to twelve high-value probes that can be executed against a local FTP server.
Call the tool exactly once.

Guidelines:
- Prefer short command sequences that validate sequencing or authorization assumptions
- Use realistic FTP commands only
- Keep descriptions exactly unchanged so they can be matched back to claims
- Avoid destructive or risky operations when a cheaper probe can answer the same question
- Prefer commands compatible with standard FTP servers and ProFuzzBench-observed message types"""


class FTPProtocolAdapter:
    name = "FTP"
    display_name = "File Transfer Protocol"

    def create_project_metadata(self) -> dict[str, str]:
        return {
            "name_prefix": "FTP Protocol Analysis — ProFuzzBench Run",
            "description": "LLM-driven protocol analysis using ProFuzzBench seed corpus + FTP RFC traces",
        }

    def load_doc_inputs(self, project_root: str) -> list[str]:
        data_dir = Path(project_root) / "data"
        doc_path = data_dir / "docs" / "ftp_summary.md"
        if not doc_path.exists():
            return []
        return [doc_path.read_text(encoding="utf-8")]

    def load_trace_inputs(self, project_root: str) -> list[str]:
        data_dir = Path(project_root) / "data"
        trace_path = data_dir / "traces" / "ftp_sessions.txt"
        if not trace_path.exists():
            return []
        text = trace_path.read_text(encoding="utf-8")
        return [session.strip() for session in text.split("---") if session.strip()]

    def load_seed_inputs(self, project_root: str) -> list[str]:
        data_dir = Path(project_root) / "data"
        seed_dir = data_dir / "traces" / "profuzzbench"
        if not seed_dir.exists():
            return []
        sessions = []
        for seed_file in sorted(seed_dir.glob("*.raw")):
            try:
                content = seed_file.read_bytes().decode("utf-8", errors="replace")
                content = content.replace("\r\n", "\n").replace("\r", "\n").strip()
                if content:
                    sessions.append(content)
            except Exception:
                continue
        return sessions

    def spec_system_prompt(self) -> str:
        return _SPEC_SYSTEM_PROMPT

    def build_spec_user_message(self, docs_text: str, traces: list) -> str:
        return f"""## Protocol Documentation

{docs_text}

## Observed FTP Commands Across All Traces

{self.summarize_observed_messages(traces)}

## Observed Session Trace Patterns (first 10 sessions)

{self.format_trace_summary(traces)}

Please analyze the above and record all FTP message types, ordering rules, and field constraints you can identify."""

    def trace_system_prompt(self) -> str:
        return _TRACE_SYSTEM_PROMPT

    def build_trace_user_message(self, all_sessions: list[list[dict]], all_events: list[dict], mt_result: dict, heuristic_states: list[dict]) -> str:
        mt_freq = "\n".join(
            f"  {m['name']}: {m['count']} occurrences"
            for m in mt_result.get("message_types", [])
            if not m["name"].startswith("RESP_")
        )
        heuristic_state_text = "\n".join(
            f"  - {s['name']}: {s['description']}" for s in heuristic_states
        ) or "  (none)"
        return f"""## FTP Session Trace Data

Total sessions: {len(all_sessions)}
Total events: {len(all_events)}

### Message Type Frequency
{mt_freq}

### Heuristic Candidate States
{heuristic_state_text}

### Session Command/Response Sequences
{self._format_sessions_for_llm(all_sessions)}

Analyze these traces and record all protocol states and transitions you can identify."""

    def probe_system_prompt(self) -> str:
        return _PROBE_SYSTEM_PROMPT

    def parse_session(self, raw_text: str) -> list[dict]:
        return parse_ftp_session(raw_text)

    def parse_session_pairs(self, raw_text: str) -> list[dict]:
        return parse_ftp_session_pairs(raw_text)

    def parse_trace(self, raw_text: str) -> list[dict]:
        events = self.parse_session(raw_text)
        if not events:
            events = self.parse_session_pairs(raw_text)
        return events

    def format_trace_summary(self, traces: list) -> str:
        if not traces:
            return "(no trace data available)"
        summary_parts = []
        for i, trace in enumerate(traces[:10]):
            events = []
            try:
                ev_list = self.parse_session(trace.raw_content)
                for ev in ev_list:
                    mt = ev.get("message_type", "?")
                    resp = ev.get("response")
                    code = resp.get("code", "?") if resp else "?"
                    events.append(f"  {mt} → {code}")
            except Exception:
                raw = trace.raw_content[:200]
                events = [f"  (raw): {raw}"]
            summary_parts.append(f"Session {i + 1}:\n" + "\n".join(events[:15]))
        return "\n\n".join(summary_parts)

    def summarize_observed_messages(self, traces: list) -> str:
        counts: Counter[str] = Counter()
        for trace in traces:
            try:
                ev_list = self.parse_session(trace.raw_content)
            except Exception:
                ev_list = []
            for ev in ev_list:
                mt = ev.get("message_type", "")
                if mt and not mt.startswith("RESP_") and mt != "UNKNOWN":
                    counts[mt] += 1
        if not counts:
            return "(no observed command summary available)"
        return "\n".join(f"- {name}: {count}" for name, count in counts.most_common())

    def infer_candidate_states(self, sessions: list[list[dict]]) -> dict:
        return infer_candidate_states(sessions)

    def propose_transitions(self, states: list[dict], messages: list[dict]) -> dict:
        return propose_transitions(states, messages)

    def normalize_transition(self, from_state: str, to_state: str, message_type: str) -> tuple[str, str, str]:
        from_s = from_state.strip().upper()
        to_s = to_state.strip().upper()
        msg = message_type.strip().upper()
        if msg == "REIN" and from_s == "AUTHENTICATED" and to_s == "INIT":
            to_s = "RESETTING"
        return from_s, to_s, msg

    def trace_augmentation_min_transitions(self) -> int:
        # Guardrail for sparse LLM outputs: only augment when below this size.
        return 20

    def trace_augmentation_priority_messages(self) -> list[str]:
        # Prefer protocol-critical transitions first when filling gaps.
        return [
            "USER", "PASS", "REIN", "RNFR", "RNTO",
            "PASV", "EPSV", "PORT", "EPRT",
            "LIST", "NLST", "MLSD", "RETR", "STOR", "APPE",
            "PWD", "CWD", "QUIT",
        ]

    def select_probe_targets(self, transitions: list, invariants: list) -> list[dict]:
        # ---------------------------------------------------------------
        # Fixed high-value targets: always probe these first if they exist
        # They yield concrete supported/disputed evidence for the demo
        # ---------------------------------------------------------------
        fixed_targets: list[dict] = []

        # 1. LIST requires authentication — probe by sending LIST before any USER/PASS
        list_auth_inv = next(
            (inv for inv in invariants
             if "LIST" in inv.rule_text.upper() and "auth" in inv.rule_text.lower()),
            None
        )
        if list_auth_inv and len(fixed_targets) < 3:
            fixed_targets.append({
                "type": "invariant",
                "claim": list_auth_inv,
                "description": list_auth_inv.rule_text,
            })

        # 2. RNTO depends on RNFR — probe by sending RNTO without preceding RNFR
        rnto_trans = next(
            (t for t in transitions if t.message_type == "RNTO"),
            None
        )
        if rnto_trans and len(fixed_targets) < 3:
            fixed_targets.append({
                "type": "transition",
                "claim": rnto_trans,
                "description": f"{rnto_trans.from_state} -> {rnto_trans.to_state} via {rnto_trans.message_type} (dependency: RNFR must precede)",
            })

        # 3. QUIT reachable from any authenticated state
        quit_trans = next(
            (t for t in transitions if t.message_type == "QUIT" and t.from_state == "AUTHENTICATED"),
            None
        )
        if quit_trans and len(fixed_targets) < 3:
            fixed_targets.append({
                "type": "transition",
                "claim": quit_trans,
                "description": f"{quit_trans.from_state} -> {quit_trans.to_state} via QUIT",
            })

        if len(fixed_targets) >= 12:
            return fixed_targets[:12]

        # ---------------------------------------------------------------
        # Fallback to existing selection logic if fixed targets < 3
        # ---------------------------------------------------------------
        probe_targets = list(fixed_targets)
        for transition in transitions:
            if transition.status == "disputed" or transition.confidence < 0.5:
                probe_targets.append({
                    "type": "transition",
                    "claim": transition,
                    "description": f"{transition.from_state} -> {transition.to_state} via {transition.message_type}",
                })
        for invariant in invariants:
            if invariant.status == "disputed" or invariant.confidence < 0.5:
                probe_targets.append({
                    "type": "invariant",
                    "claim": invariant,
                    "description": invariant.rule_text,
                })

        if not probe_targets:
            for transition in transitions:
                if transition.status == "hypothesis":
                    probe_targets.append({
                        "type": "transition",
                        "claim": transition,
                        "description": f"{transition.from_state} -> {transition.to_state} via {transition.message_type}",
                    })
                    if len(probe_targets) >= 12:
                        break

        if not probe_targets:
            priority_messages = {"USER", "PASS", "PASV", "EPSV", "PORT", "EPRT", "MLSD", "MLST", "LIST", "RETR", "STOR", "RNFR", "RNTO", "QUIT", "REIN"}
            ranked_transitions = sorted(
                transitions,
                key=lambda t: (
                    0 if t.message_type in priority_messages else 1,
                    t.confidence,
                ),
            )
            for transition in ranked_transitions:
                if transition.confidence < 0.95:
                    probe_targets.append({
                        "type": "transition",
                        "claim": transition,
                        "description": f"{transition.from_state} -> {transition.to_state} via {transition.message_type}",
                    })
                if len(probe_targets) >= 12:
                    break

        if not probe_targets:
            ranked_invariants = sorted(invariants, key=lambda inv: inv.confidence)
            for invariant in ranked_invariants:
                if invariant.confidence < 0.95:
                    probe_targets.append({
                        "type": "invariant",
                        "claim": invariant,
                        "description": invariant.rule_text,
                    })
                if len(probe_targets) >= 12:
                    break
        return probe_targets[:12]

    def generate_probe_commands(self, target: dict) -> list[str]:
        claim = target["claim"]
        if target["type"] == "transition":
            mt = claim.message_type
            if claim.from_state == "RESETTING" and mt == "USER":
                return ["USER anonymous", "PASS anonymous@test.com", "REIN", "USER anonymous"]
            if claim.from_state == "INIT" and mt == "USER":
                return ["USER anonymous"]
            if claim.from_state == "AUTH_PENDING" and mt == "PASS":
                return ["USER anonymous", "PASS anonymous@test.com"]
            if mt == "PASV":
                return ["USER anonymous", "PASS anonymous@test.com", "PASV"]
            if mt == "EPSV":
                return ["USER anonymous", "PASS anonymous@test.com", "EPSV"]
            if mt == "PORT":
                return ["USER anonymous", "PASS anonymous@test.com", "PORT_AUTO"]
            if mt == "EPRT":
                return ["USER anonymous", "PASS anonymous@test.com", "EPRT_AUTO"]
            if mt in ("LIST", "PWD", "XPWD", "CWD", "XCWD", "STAT", "SYST", "FEAT", "HELP"):
                prefix = ["USER anonymous", "PASS anonymous@test.com"]
                if claim.from_state == "DATA_CHANNEL_READY" and mt == "LIST":
                    prefix.append("PASV")
                return prefix + [mt if mt != "CWD" else "CWD /"]
            if mt in ("SIZE", "RETR", "MLST"):
                prefix = ["USER anonymous", "PASS anonymous@test.com"]
                if mt == "RETR" and claim.from_state == "DATA_CHANNEL_READY":
                    prefix.append("PASV")
                return prefix + [f"{mt} readme.txt"]
            if mt in ("NLST", "MLSD"):
                prefix = ["USER anonymous", "PASS anonymous@test.com"]
                if claim.from_state == "DATA_CHANNEL_READY":
                    prefix.append("PASV")
                elif mt == "MLSD":
                    prefix.append("EPSV")
                return prefix + [f"{mt} pub"]
            if mt in ("MKD", "XMKD"):
                return ["USER anonymous", "PASS anonymous@test.com", f"{mt} scratchdir"]
            if mt in ("RMD", "XRMD"):
                return ["USER anonymous", "PASS anonymous@test.com", "MKD scratchdir", f"{mt} scratchdir"]
            if mt == "ACCT":
                return ["USER anonymous", "PASS anonymous@test.com", "ACCT billing"]
            if mt == "SMNT":
                return ["USER anonymous", "PASS anonymous@test.com", "SMNT /pub"]
            if mt in ("RNFR", "RNTO"):
                return ["USER anonymous", "PASS anonymous@test.com", "RNFR readme.txt", "RNTO readme_renamed.txt"]
            if mt == "REIN":
                prefix = ["USER anonymous", "PASS anonymous@test.com", "REIN"]
                if claim.to_state == "AUTH_PENDING":
                    prefix.append("USER anonymous")
                return prefix
            if mt in ("TYPE", "MODE", "STRU"):
                arg = {"TYPE": "I", "MODE": "S", "STRU": "F"}[mt]
                return ["USER anonymous", "PASS anonymous@test.com", f"{mt} {arg}"]
            if mt == "NOOP":
                return ["USER anonymous", "PASS anonymous@test.com", "NOOP"]
            if mt == "QUIT":
                return ["QUIT"]
            return ["USER anonymous", "PASS anonymous@test.com", mt]
        if target["type"] == "invariant":
            rule = target["claim"].rule_text
            if "PASS" in rule and "USER" in rule:
                return ["PASS testpass"]
            if "LIST" in rule and "auth" in rule.lower():
                return ["LIST"]
            return ["USER anonymous", "PASS anonymous@test.com"]
        return ["NOOP"]

    def execute_probe(self, commands: list[str]) -> list[dict]:
        return self._ftp_exchange(settings.FTP_PROBE_HOST, settings.FTP_PROBE_PORT, commands)

    def probe_target_host(self) -> str:
        return settings.FTP_PROBE_HOST

    def probe_target_port(self) -> int:
        return settings.FTP_PROBE_PORT

    def _format_sessions_for_llm(self, all_sessions: list[list[dict]]) -> str:
        lines = []
        for i, events in enumerate(all_sessions[:20]):
            lines.append(f"\n--- Session {i + 1} ---")
            for ev in events:
                mt = ev.get("message_type", "?")
                resp = ev.get("response")
                if resp:
                    code = resp.get("code", "?")
                    text = resp.get("text", "")[:60]
                    lines.append(f"  C→S: {mt}  |  S→C: {code} {text}")
                else:
                    lines.append(f"  C→S: {mt}")
        return "\n".join(lines)

    def _read_socket_text(self, sock: socket.socket, timeout: float = 1.5) -> str:
        sock.settimeout(timeout)
        chunks: list[str] = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data.decode("utf-8", errors="replace"))
            if len(data) < 4096:
                break
        return "".join(chunks).strip()

    def _parse_pasv_endpoint(self, response: str) -> tuple[str, int] | None:
        match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", response)
        if not match:
            return None
        host = ".".join(match.group(i) for i in range(1, 5))
        port = int(match.group(5)) * 256 + int(match.group(6))
        return host, port

    def _parse_epsv_port(self, response: str) -> int | None:
        match = re.search(r"\(\|\|\|(\d+)\|\)", response)
        if not match:
            return None
        return int(match.group(1))

    def _open_active_listener(self) -> tuple[socket.socket, str, str]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()
        p1, p2 = divmod(port, 256)
        port_cmd = f"PORT {host.replace('.', ',')},{p1},{p2}"
        eprt_cmd = f"EPRT |1|{host}|{port}|"
        return listener, port_cmd, eprt_cmd

    def _ftp_exchange(self, host: str, port: int, commands: list[str], timeout: float = 5.0) -> list[dict]:
        results = []
        active_listener = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            greeting = self._read_socket_text(sock, timeout=timeout)
            results.append({"command": "(connect)", "response": greeting})
            for cmd in commands:
                cmd_upper = cmd.strip().upper()
                if cmd_upper in {"PORT_AUTO", "EPRT_AUTO"}:
                    if active_listener:
                        try:
                            active_listener.close()
                        except Exception:
                            pass
                    active_listener, port_cmd, eprt_cmd = self._open_active_listener()
                    cmd = port_cmd if cmd_upper == "PORT_AUTO" else eprt_cmd
                sock.sendall((cmd + "\r\n").encode("utf-8"))
                response = self._read_socket_text(sock, timeout=timeout)
                results.append({"command": cmd, "response": response})

                data_payload = ""
                if cmd.split(" ", 1)[0].upper() in TRANSFER_COMMANDS:
                    previous_response = results[-2]["response"] if len(results) >= 2 else ""
                    if previous_response.startswith("227"):
                        endpoint = self._parse_pasv_endpoint(previous_response)
                        if endpoint:
                            try:
                                data_sock = socket.create_connection(endpoint, timeout=timeout)
                                data_payload = self._read_socket_text(data_sock, timeout=1.0)
                                data_sock.close()
                            except Exception as exc:
                                data_payload = f"data_connect_error: {exc}"
                    elif previous_response.startswith("229"):
                        pasv_port = self._parse_epsv_port(previous_response)
                        if pasv_port is not None:
                            try:
                                data_sock = socket.create_connection((host, pasv_port), timeout=timeout)
                                data_payload = self._read_socket_text(data_sock, timeout=1.0)
                                data_sock.close()
                            except Exception as exc:
                                data_payload = f"data_connect_error: {exc}"
                    elif active_listener is not None:
                        try:
                            active_listener.settimeout(timeout)
                            conn, _ = active_listener.accept()
                            data_payload = self._read_socket_text(conn, timeout=1.0)
                            conn.close()
                        except Exception as exc:
                            data_payload = f"data_accept_error: {exc}"
                    if data_payload:
                        results.append({"command": "(data)", "response": data_payload})
            sock.sendall(b"QUIT\r\n")
            try:
                final = self._read_socket_text(sock, timeout=timeout)
                results.append({"command": "QUIT", "response": final})
            except Exception:
                pass
            sock.close()
        except Exception as exc:
            results.append({"command": "(error)", "response": str(exc)})
        finally:
            if active_listener is not None:
                try:
                    active_listener.close()
                except Exception:
                    pass
        return results
