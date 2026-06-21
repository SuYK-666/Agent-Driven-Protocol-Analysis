"""Probe Agent — generates discriminative probes and executes them online."""

from __future__ import annotations
import json
import logging
import re
import socket
from sqlmodel import Session, select
from ..models.domain import Transition, Invariant, Evidence, ProbeRun, ProtocolProject
from ..core.config import settings
from ..core.llm_client import call_with_tools
from ..protocols.registry import get_protocol_adapter

logger = logging.getLogger(__name__)

TRANSFER_COMMANDS = {"LIST", "NLST", "MLSD", "RETR", "STOR", "APPE"}
MIN_PROBES_PER_RUN = 12


PROBE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "record_probe_plan",
            "description": "Record the probe plan for selected claims in one batch.",
            "parameters": {
                "type": "object",
                "properties": {
                    "probes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string"},
                                "commands": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "rationale": {"type": "string"},
                            },
                            "required": ["description", "commands", "rationale"],
                        },
                    },
                },
                "required": ["probes"],
            },
        },
    }
]

PROBE_SYSTEM_PROMPT = """You are a conservative FTP probe planner.

Choose up to twelve high-value probes that can be executed against the local protocol server.
Call the tool exactly once.

Guidelines:
- Prefer short command sequences that validate sequencing or authorization assumptions
- Use realistic FTP commands only
- Keep descriptions exactly unchanged so they can be matched back to claims
- Avoid destructive or risky operations when a cheaper probe can answer the same question
- Prefer commands compatible with standard FTP servers and ProFuzzBench-observed message types"""


def _read_socket_text(sock: socket.socket, timeout: float = 1.5) -> str:
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


def _parse_pasv_endpoint(response: str) -> tuple[str, int] | None:
    match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", response)
    if not match:
        return None
    host = ".".join(match.group(i) for i in range(1, 5))
    port = int(match.group(5)) * 256 + int(match.group(6))
    return host, port


def _parse_epsv_port(response: str) -> int | None:
    match = re.search(r"\(\|\|\|(\d+)\|\)", response)
    if not match:
        return None
    return int(match.group(1))


def _open_active_listener() -> tuple[socket.socket, str, str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    p1, p2 = divmod(port, 256)
    port_cmd = f"PORT {host.replace('.', ',')},{p1},{p2}"
    eprt_cmd = f"EPRT |1|{host}|{port}|"
    return listener, port_cmd, eprt_cmd


def _ftp_exchange(host: str, port: int, commands: list[str], timeout: float = 5.0) -> list[dict]:
    results = []
    active_listener = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        greeting = _read_socket_text(sock, timeout=timeout)
        results.append({"command": "(connect)", "response": greeting})
        for cmd in commands:
            cmd_upper = cmd.strip().upper()
            if cmd_upper == "PORT_AUTO" or cmd_upper == "EPRT_AUTO":
                if active_listener:
                    try:
                        active_listener.close()
                    except Exception:
                        pass
                active_listener, port_cmd, eprt_cmd = _open_active_listener()
                cmd = port_cmd if cmd_upper == "PORT_AUTO" else eprt_cmd
            sock.sendall((cmd + "\r\n").encode("utf-8"))
            response = _read_socket_text(sock, timeout=timeout)
            results.append({"command": cmd, "response": response})

            data_payload = ""
            if cmd.split(" ", 1)[0].upper() in TRANSFER_COMMANDS:
                previous_response = results[-2]["response"] if len(results) >= 2 else ""
                if previous_response.startswith("227"):
                    endpoint = _parse_pasv_endpoint(previous_response)
                    if endpoint:
                        try:
                            data_sock = socket.create_connection(endpoint, timeout=timeout)
                            data_payload = _read_socket_text(data_sock, timeout=1.0)
                            data_sock.close()
                        except Exception as exc:
                            data_payload = f"data_connect_error: {exc}"
                elif previous_response.startswith("229"):
                    pasv_port = _parse_epsv_port(previous_response)
                    if pasv_port is not None:
                        try:
                            data_sock = socket.create_connection((host, pasv_port), timeout=timeout)
                            data_payload = _read_socket_text(data_sock, timeout=1.0)
                            data_sock.close()
                        except Exception as exc:
                            data_payload = f"data_connect_error: {exc}"
                elif active_listener is not None:
                    try:
                        active_listener.settimeout(timeout)
                        conn, _ = active_listener.accept()
                        data_payload = _read_socket_text(conn, timeout=1.0)
                        conn.close()
                    except Exception as exc:
                        data_payload = f"data_accept_error: {exc}"
                if data_payload:
                    results.append({"command": "(data)", "response": data_payload})
        sock.sendall(b"QUIT\r\n")
        try:
            final = _read_socket_text(sock, timeout=timeout)
            results.append({"command": "QUIT", "response": final})
        except Exception:
            pass
        sock.close()
    except Exception as e:
        results.append({"command": "(error)", "response": str(e)})
    finally:
        if active_listener is not None:
            try:
                active_listener.close()
            except Exception:
                pass
    return results


def _generate_probe_commands(target: dict) -> list[str]:
    claim = target["claim"]
    if target["type"] == "transition":
        mt = claim.message_type
        if claim.from_state == "RESETTING" and mt == "USER":
            return ["USER anonymous", "PASS anonymous@test.com", "REIN", "USER anonymous"]
        if claim.from_state == "INIT" and mt == "USER":
            return ["USER anonymous"]
        elif claim.from_state == "AUTH_PENDING" and mt == "PASS":
            return ["USER anonymous", "PASS anonymous@test.com"]
        elif mt == "PASV":
            return ["USER anonymous", "PASS anonymous@test.com", "PASV"]
        elif mt == "EPSV":
            return ["USER anonymous", "PASS anonymous@test.com", "EPSV"]
        elif mt == "PORT":
            return ["USER anonymous", "PASS anonymous@test.com", "PORT_AUTO"]
        elif mt == "EPRT":
            return ["USER anonymous", "PASS anonymous@test.com", "EPRT_AUTO"]
        elif mt in ("LIST", "PWD", "XPWD", "CWD", "XCWD", "STAT", "SYST", "FEAT", "HELP"):
            prefix = ["USER anonymous", "PASS anonymous@test.com"]
            if claim.from_state == "DATA_CHANNEL_READY" and mt == "LIST":
                prefix.append("PASV")
            return prefix + [mt if mt != "CWD" else "CWD /"]
        elif mt in ("SIZE", "RETR", "MLST"):
            prefix = ["USER anonymous", "PASS anonymous@test.com"]
            if mt == "RETR" and claim.from_state == "DATA_CHANNEL_READY":
                prefix.append("PASV")
            return prefix + [f"{mt} readme.txt"]
        elif mt in ("NLST", "MLSD"):
            prefix = ["USER anonymous", "PASS anonymous@test.com"]
            if claim.from_state == "DATA_CHANNEL_READY":
                prefix.append("PASV")
            elif mt == "MLSD":
                prefix.append("EPSV")
            return prefix + [f"{mt} pub"]
        elif mt in ("MKD", "XMKD"):
            return ["USER anonymous", "PASS anonymous@test.com", f"{mt} scratchdir"]
        elif mt in ("RMD", "XRMD"):
            return ["USER anonymous", "PASS anonymous@test.com", "MKD scratchdir", f"{mt} scratchdir"]
        elif mt == "ACCT":
            return ["USER anonymous", "PASS anonymous@test.com", "ACCT billing"]
        elif mt == "SMNT":
            return ["USER anonymous", "PASS anonymous@test.com", "SMNT /pub"]
        elif mt == "RNFR":
            return ["USER anonymous", "PASS anonymous@test.com", "RNFR readme.txt", "RNTO readme_renamed.txt"]
        elif mt == "RNTO":
            return ["USER anonymous", "PASS anonymous@test.com", "RNFR readme.txt", "RNTO readme_renamed.txt"]
        elif mt == "REIN":
            prefix = ["USER anonymous", "PASS anonymous@test.com", "REIN"]
            if claim.to_state == "AUTH_PENDING":
                prefix.append("USER anonymous")
            return prefix
        elif mt in ("TYPE", "MODE", "STRU"):
            arg = {"TYPE": "I", "MODE": "S", "STRU": "F"}[mt]
            return ["USER anonymous", "PASS anonymous@test.com", f"{mt} {arg}"]
        elif mt == "NOOP":
            return ["USER anonymous", "PASS anonymous@test.com", "NOOP"]
        elif mt == "QUIT":
            return ["QUIT"]
        else:
            return ["USER anonymous", "PASS anonymous@test.com", mt]
    elif target["type"] == "invariant":
        rule = target["claim"].rule_text
        if "PASS" in rule and "USER" in rule:
            return ["PASS testpass"]
        elif "LIST" in rule and "auth" in rule.lower():
            return ["LIST"]
        return ["USER anonymous", "PASS anonymous@test.com"]
    return ["NOOP"]


def _llm_plan_probes(system_prompt: str, targets: list[dict]) -> tuple[dict[str, dict], int]:
    if not targets:
        return {}, 0
    user_message = "## Candidate Claims For Probe Planning\n\n"
    for target in targets:
        claim = target["claim"]
        confidence = getattr(claim, "confidence", 0.0)
        status = getattr(claim, "status", "hypothesis")
        user_message += (
            f"- description: {target['description']}\n"
            f"  type: {target['type']}\n"
            f"  status: {status}\n"
            f"  confidence: {confidence}\n"
        )
    tool_calls = call_with_tools(
        system_prompt=system_prompt,
        user_message=user_message,
        tools=PROBE_TOOLS,
        max_iterations=1,
    )
    if not tool_calls or tool_calls[0]["tool"] != "record_probe_plan":
        raise RuntimeError(
            f"Probe LLM returned unexpected tool calls: {[t['tool'] for t in tool_calls]}"
        )
    probes = tool_calls[0]["args"].get("probes", [])
    return {probe.get("description", ""): probe for probe in probes if probe.get("description")}, len(tool_calls)


def _pad_probe_targets(targets: list[dict], minimum: int = MIN_PROBES_PER_RUN) -> list[dict]:
    if not targets or len(targets) >= minimum:
        return targets[:minimum]

    padded = list(targets)
    idx = 0
    while len(padded) < minimum:
        source = targets[idx % len(targets)]
        clone = dict(source)
        clone["description"] = f"{source['description']} [replicate {len(padded) + 1}]"
        clone["replicate"] = True
        padded.append(clone)
        idx += 1
    return padded


def run_probe_agent(project_id: int, session: Session) -> dict:
    results = {
        "agent": "probe",
        "probes_executed": 0,
        "model_updates": [],
        "llm_tool_calls": 0,
        "llm_plan_used": False,
    }
    project = session.get(ProtocolProject, project_id)
    adapter = get_protocol_adapter(project.protocol_name if project else "FTP")

    transitions = session.exec(select(Transition).where(Transition.project_id == project_id)).all()
    invariants = session.exec(select(Invariant).where(Invariant.project_id == project_id)).all()

    probe_targets = _pad_probe_targets(adapter.select_probe_targets(transitions, invariants))
    llm_probe_map, llm_tool_calls = _llm_plan_probes(adapter.probe_system_prompt(), probe_targets)
    results["llm_tool_calls"] = llm_tool_calls
    results["llm_plan_used"] = bool(llm_probe_map)

    for target in probe_targets:
        llm_probe = llm_probe_map.get(target["description"], {})
        cmds = llm_probe.get("commands") or adapter.generate_probe_commands(target)
        exchange = adapter.execute_probe(cmds)

        probe_run = ProbeRun(
            project_id=project_id, target_host=adapter.probe_target_host(),
            target_port=adapter.probe_target_port(), goal=f"Verify: {target['description']}",
            request_payload=json.dumps(cmds), response_payload=json.dumps(exchange),
            result_summary=llm_probe.get("rationale", f"Executed {len(exchange)} exchanges"),
        )
        session.add(probe_run)
        session.commit()
        session.refresh(probe_run)

        update = _apply_probe_result(target, exchange, session, project_id, probe_run.id)
        results["model_updates"].append(update)
        results["probes_executed"] += 1

    session.commit()
    return results


def _apply_probe_result(target, exchange, session, project_id, probe_id):
    update = {"target": target["description"], "action": "no_change"}
    has_error = any("error" in e.get("command", "") for e in exchange)
    if has_error:
        update["action"] = "probe_failed"
        return update

    claim = target["claim"]
    if target["type"] == "transition":
        for ex in exchange:
            cmd = ex.get("command", "")
            resp = ex.get("response", "")
            if cmd.upper().startswith(claim.message_type):
                code = resp[:3] if resp else ""
                if code.startswith(("2", "3")):
                    claim.status = "supported"
                    claim.confidence = min(claim.confidence + 0.15, 1.0)
                    update["action"] = "confirmed"
                elif code.startswith(("4", "5")):
                    claim.status = "disputed"
                    claim.confidence = max(claim.confidence - 0.1, 0.0)
                    update["action"] = "disputed"
                session.add(claim)
    elif target["type"] == "invariant":
        for ex in exchange:
            resp = ex.get("response", "")
            code = resp[:3] if resp else ""
            if code.startswith("5"):
                claim.status = "supported"
                claim.confidence = min(claim.confidence + 0.2, 1.0)
                update["action"] = "invariant_supported"
                session.add(claim)
                break
            elif code.startswith(("2", "3")):
                claim.status = "disputed"
                claim.confidence = max(claim.confidence - 0.2, 0.0)
                update["action"] = "invariant_disputed"
                session.add(claim)
                break

    ev = Evidence(
        project_id=project_id, claim_type=target["type"], claim_id=claim.id,
        source_type="probe", source_ref=f"probe_run:{probe_id}",
        snippet=json.dumps(exchange[-2:] if len(exchange) >= 2 else exchange),
        score=0.9 if "supported" in update["action"] or update["action"] == "confirmed" else 0.5,
    )
    session.add(ev)
    return update
