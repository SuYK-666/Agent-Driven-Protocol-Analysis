from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import socket

from ..core.config import settings


class GenericTextProtocolAdapter:
    def __init__(
        self,
        name: str,
        display_name: str,
        default_port: int,
        doc_filename: str | None = None,
        trace_filename: str | None = None,
    ) -> None:
        self.name = name.upper()
        self.display_name = display_name
        self.default_port = default_port
        self.doc_filename = doc_filename or f"{self.name.lower()}_summary.md"
        self.trace_filename = trace_filename or f"{self.name.lower()}_sessions.txt"

    def create_project_metadata(self) -> dict[str, str]:
        return {
            "name_prefix": f"{self.name} Protocol Analysis",
            "description": f"LLM-driven protocol analysis for {self.display_name}",
        }

    def load_doc_inputs(self, project_root: str) -> list[str]:
        data_dir = Path(project_root) / "data"
        path = data_dir / "docs" / self.doc_filename
        if path.exists():
            return [path.read_text(encoding="utf-8")]
        return []

    def load_trace_inputs(self, project_root: str) -> list[str]:
        data_dir = Path(project_root) / "data"
        path = data_dir / "traces" / self.trace_filename
        if not path.exists():
            return []
        text = path.read_text(encoding="utf-8")
        return [session.strip() for session in text.split("---") if session.strip()]

    def load_seed_inputs(self, project_root: str) -> list[str]:
        data_dir = Path(project_root) / "data"
        protocol_seed_dir = data_dir / "traces" / "profuzzbench" / self.name.lower()
        sessions: list[str] = []
        if protocol_seed_dir.exists():
            for seed_file in sorted(protocol_seed_dir.glob("*.raw")):
                content = seed_file.read_bytes().decode("utf-8", errors="replace").strip()
                if content:
                    sessions.append(content)
            return sessions
        return []

    def spec_system_prompt(self) -> str:
        return (
            f"You are an expert {self.name} protocol analyst. "
            "Extract message types, ordering rules, and field constraints. "
            "Call the provided tool exactly once with comprehensive results."
        )

    def build_spec_user_message(self, docs_text: str, traces: list) -> str:
        return (
            "## Protocol Documentation\n\n"
            f"{docs_text}\n\n"
            f"## Observed {self.name} Messages\n\n"
            f"{self.summarize_observed_messages(traces)}\n\n"
            "## Session Summary\n\n"
            f"{self.format_trace_summary(traces)}"
        )

    def trace_system_prompt(self) -> str:
        return (
            f"You are an expert {self.name} protocol analyst. "
            "Recover states and transitions from traces. "
            "Call record_trace_analysis exactly once with observations, states, transitions, and observed_message_types."
        )

    def build_trace_user_message(
        self,
        all_sessions: list[list[dict]],
        all_events: list[dict],
        mt_result: dict,
        heuristic_states: list[dict],
    ) -> str:
        mt_freq = "\n".join(
            f"  {m['name']}: {m['count']} occurrences"
            for m in mt_result.get("message_types", [])
            if not m["name"].startswith("RESP_")
        )
        states = "\n".join(f"  - {s['name']}: {s['description']}" for s in heuristic_states) or "  (none)"
        sessions_text = self._format_sessions_for_llm(all_sessions)
        return (
            f"## {self.name} Trace Data\n\n"
            f"Total sessions: {len(all_sessions)}\n"
            f"Total events: {len(all_events)}\n\n"
            f"### Message Type Frequency\n{mt_freq}\n\n"
            f"### Candidate States\n{states}\n\n"
            f"### Session Sequences\n{sessions_text}\n"
        )

    def probe_system_prompt(self) -> str:
        return (
            f"You are a conservative {self.name} probe planner. "
            "Choose up to twelve high-value probes and call the tool exactly once."
        )

    def parse_session(self, raw_text: str) -> list[dict]:
        events: list[dict] = []
        command_re = re.compile(r"^\s*([A-Za-z]{3,10})(?:\s+(.*))?$")
        response_re = re.compile(r"^\s*(\d{3})[\s-](.*)$")

        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue

            if self.name == "HTTP":
                m_http = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)", line, re.IGNORECASE)
                if m_http:
                    method = m_http.group(1).upper()
                    path = m_http.group(2)
                    events.append({"message_type": method, "fields": {"path": path}})
                    continue

            m_resp = response_re.match(line)
            if m_resp and events:
                events[-1]["response"] = {"code": m_resp.group(1), "text": m_resp.group(2)[:200]}
                continue

            m_cmd = command_re.match(line)
            if m_cmd:
                cmd = m_cmd.group(1).upper()
                args = (m_cmd.group(2) or "").strip()
                fields = {"args": args} if args else {}
                events.append({"message_type": cmd, "fields": fields})

        return events

    def parse_session_pairs(self, raw_text: str) -> list[dict]:
        return self.parse_session(raw_text)

    def parse_trace(self, raw_text: str) -> list[dict]:
        return self.parse_session(raw_text)

    def format_trace_summary(self, traces: list) -> str:
        if not traces:
            return "(no trace data available)"
        parts: list[str] = []
        for i, trace in enumerate(traces[:10]):
            events = self.parse_session(getattr(trace, "raw_content", ""))
            lines = []
            for ev in events[:15]:
                mt = ev.get("message_type", "?")
                resp = ev.get("response", {})
                code = resp.get("code", "?") if resp else "?"
                lines.append(f"  {mt} -> {code}")
            parts.append(f"Session {i + 1}:\n" + "\n".join(lines))
        return "\n\n".join(parts)

    def summarize_observed_messages(self, traces: list) -> str:
        counts: Counter[str] = Counter()
        for trace in traces:
            events = self.parse_session(getattr(trace, "raw_content", ""))
            for ev in events:
                mt = ev.get("message_type", "")
                if mt and not mt.startswith("RESP_"):
                    counts[mt] += 1
        if not counts:
            return "(no observed message summary available)"
        return "\n".join(f"- {name}: {count}" for name, count in counts.most_common())

    def infer_candidate_states(self, sessions: list[list[dict]]) -> dict:
        states = [
            {"name": "INIT", "description": "Initial protocol state"},
            {"name": "ESTABLISHED", "description": "Session established"},
            {"name": "CLOSED", "description": "Session closed"},
        ]
        return {"states": states}

    def propose_transitions(self, states: list[dict], messages: list[dict]) -> dict:
        transitions = []
        for m in messages:
            name = m.get("name", "").upper()
            if not name or name.startswith("RESP_"):
                continue
            if name in {"QUIT", "BYE", "TEARDOWN"}:
                transitions.append({
                    "from_state": "ESTABLISHED",
                    "to_state": "CLOSED",
                    "message_type": name,
                    "confidence": 0.7,
                })
            elif name in {"USER", "HELO", "EHLO", "OPTIONS", "DESCRIBE", "SETUP"}:
                transitions.append({
                    "from_state": "INIT",
                    "to_state": "ESTABLISHED",
                    "message_type": name,
                    "confidence": 0.72,
                })
            else:
                transitions.append({
                    "from_state": "ESTABLISHED",
                    "to_state": "ESTABLISHED",
                    "message_type": name,
                    "confidence": 0.65,
                })
        return {"transitions": transitions}

    def normalize_transition(self, from_state: str, to_state: str, message_type: str) -> tuple[str, str, str]:
        return from_state.strip().upper(), to_state.strip().upper(), message_type.strip().upper()

    def trace_augmentation_min_transitions(self) -> int:
        return 16

    def trace_augmentation_priority_messages(self) -> list[str]:
        return ["USER", "PASS", "HELO", "EHLO", "SETUP", "DESCRIBE", "GET", "POST", "QUIT", "TEARDOWN"]

    def select_probe_targets(self, transitions: list, invariants: list) -> list[dict]:
        targets = []
        for t in transitions:
            if t.status == "disputed" or t.confidence < 0.6:
                targets.append({"type": "transition", "claim": t, "description": f"{t.from_state} -> {t.to_state} via {t.message_type}"})
        if not targets:
            for t in transitions:
                if t.status == "hypothesis":
                    targets.append({"type": "transition", "claim": t, "description": f"{t.from_state} -> {t.to_state} via {t.message_type}"})
                    if len(targets) >= 12:
                        break
        return targets[:12]

    def generate_probe_commands(self, target: dict) -> list[str]:
        claim = target["claim"]
        return [claim.message_type]

    def execute_probe(self, commands: list[str]) -> list[dict]:
        host = self.probe_target_host()
        port = self.probe_target_port()
        if self.name == "SMTP":
            return self._smtp_exchange(host, port, commands)
        if self.name == "HTTP":
            return self._http_exchange(host, port, commands)
        if self.name == "RTSP":
            return self._rtsp_exchange(host, port, commands)
        return [{"command": "(unsupported)", "response": f"No probe executor for protocol {self.name}"}]

    def probe_target_host(self) -> str:
        if self.name == "SMTP":
            return settings.SMTP_PROBE_HOST
        if self.name == "HTTP":
            return settings.HTTP_PROBE_HOST
        if self.name == "RTSP":
            return settings.RTSP_PROBE_HOST
        return settings.FTP_PROBE_HOST

    def probe_target_port(self) -> int:
        if self.name == "SMTP":
            return settings.SMTP_PROBE_PORT
        if self.name == "HTTP":
            return settings.HTTP_PROBE_PORT
        if self.name == "RTSP":
            return settings.RTSP_PROBE_PORT
        return self.default_port

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

    def _smtp_exchange(self, host: str, port: int, commands: list[str], timeout: float = 5.0) -> list[dict]:
        results: list[dict] = []
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            greeting = self._read_socket_text(sock, timeout=timeout)
            results.append({"command": "(connect)", "response": greeting})
            for cmd in commands:
                line = cmd.strip()
                if not line:
                    continue
                sock.sendall((line + "\r\n").encode("utf-8"))
                results.append({"command": line, "response": self._read_socket_text(sock, timeout=timeout)})
            if not any(c.upper().startswith("QUIT") for c in commands):
                sock.sendall(b"QUIT\r\n")
                results.append({"command": "QUIT", "response": self._read_socket_text(sock, timeout=timeout)})
            sock.close()
        except Exception as exc:
            results.append({"command": "(error)", "response": str(exc)})
        return results

    def _http_exchange(self, host: str, port: int, commands: list[str], timeout: float = 5.0) -> list[dict]:
        results: list[dict] = []
        try:
            for cmd in commands:
                parts = cmd.strip().split()
                method = (parts[0] if parts else "GET").upper()
                path = parts[1] if len(parts) >= 2 else "/"
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: ProtocolAnalyzer/1.0\r\n"
                    "Connection: close\r\n\r\n"
                )
                sock = socket.create_connection((host, port), timeout=timeout)
                sock.sendall(request.encode("utf-8"))
                response = self._read_socket_text(sock, timeout=timeout)
                sock.close()
                results.append({"command": f"{method} {path}", "response": response[:2000]})
        except Exception as exc:
            results.append({"command": "(error)", "response": str(exc)})
        return results

    def _rtsp_exchange(self, host: str, port: int, commands: list[str], timeout: float = 5.0) -> list[dict]:
        results: list[dict] = []
        cseq = 1
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            for cmd in commands:
                parts = cmd.strip().split()
                method = (parts[0] if parts else "OPTIONS").upper()
                uri = parts[1] if len(parts) >= 2 else f"rtsp://{host}:{port}/media"
                request = (
                    f"{method} {uri} RTSP/1.0\r\n"
                    f"CSeq: {cseq}\r\n"
                    "User-Agent: ProtocolAnalyzer/1.0\r\n\r\n"
                )
                sock.sendall(request.encode("utf-8"))
                response = self._read_socket_text(sock, timeout=timeout)
                results.append({"command": f"{method} {uri}", "response": response[:2000]})
                cseq += 1
            sock.close()
        except Exception as exc:
            results.append({"command": "(error)", "response": str(exc)})
        return results

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
                    lines.append(f"  C->S: {mt}  |  S->C: {code} {text}")
                else:
                    lines.append(f"  C->S: {mt}")
        return "\n".join(lines)
