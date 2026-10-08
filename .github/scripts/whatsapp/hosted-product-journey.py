#!/usr/bin/env python3
"""Hosted real daemon/MCP/bridge journey; no linked account and no local execution."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pathlib
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

MODES = ("success", "tool_error", "disabled", "cancel")
MARKERS = {
    "channels_drained": b"shutdown checkpoint: channels and dispatch drained",
    "transports_drained": b"shutdown checkpoint: transports drained",
    "wal_senders_absent": b"shutdown checkpoint: WAL other senders absent",
    "wal_drained": b"WAL writer task drained cleanly",
    "panic": b"panicked at",
    "neoth_panic": b"[neoth panic]",
    "adapter_live": b"Baileys bridge adapter live",
    "pipeline_rejected": b"Baileys pipeline rejected inbound",
}
TOKEN = "w2511_loopback_only_bridge_token_0000000001"

class ContractFailure(RuntimeError):
    pass

def require(value, category):
    if not value:
        raise ContractFailure(category)

class Drain:
    """Drain continuously, retaining only fixed markers and a byte count."""
    def __init__(self, pipe):
        self.pipe, self.found, self.bytes = pipe, set(), 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        tail = b""
        while chunk := self.pipe.read(4096):
            self.bytes += len(chunk)
            window = tail + chunk
            for name, marker in MARKERS.items():
                if marker in window:
                    self.found.add(name)
            tail = window[-256:]

    def close(self):
        self.thread.join(5)
        return not self.thread.is_alive()

class Helper:
    def __init__(self, root, state, mode, env):
        self.process = subprocess.Popen(
            ["node", str(root / "bridges/whatsapp-baileys/fixtures/hosted-product-helper.mjs"),
             str(state), mode], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        self.errors = Drain(self.process.stderr)
        self.buffer = b""
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)

    def read(self, seconds=10):
        deadline = time.monotonic() + seconds
        while b"\n" not in self.buffer:
            require(time.monotonic() < deadline, "helper_deadline")
            require(self.selector.select(max(0, deadline - time.monotonic())), "helper_deadline")
            chunk = os.read(self.process.stdout.fileno(), 8192)
            require(chunk, "helper_closed")
            self.buffer += chunk
            require(len(self.buffer) <= 65536, "helper_response_cap")
        line, self.buffer = self.buffer.split(b"\n", 1)
        value = json.loads(line)
        require(isinstance(value, dict), "helper_response_shape")
        return value

    def command(self, op, seconds=10):
        self.process.stdin.write((json.dumps({"op": op}) + "\n").encode())
        self.process.stdin.flush()
        return self.read(seconds)

    def stop(self):
        graceful = True
        if self.process.poll() is None:
            try:
                self.process.stdin.write(b'{"op":"stop"}\n')
                self.process.stdin.flush()
                self.process.stdin.close()
                self.process.wait(45)
            except (subprocess.TimeoutExpired, BrokenPipeError):
                graceful = False
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(5)
        self.selector.close()
        drained = self.errors.close()
        return {"exit": self.process.returncode, "graceful": graceful,
                "stderrDrained": drained, "stderrBytes": self.errors.bytes}

def wait_until(predicate, seconds, category, serve=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        require(serve is None or serve.poll() is None, "serve_early_exit")
        time.sleep(0.1)
    raise ContractFailure(category)

def health(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False

def reserve_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]

def child_identities(home):
    file = home / "children.jsonl"
    return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

def same_child(value):
    try:
        birth = pathlib.Path(f"/proc/{value['pid']}/stat").read_text().rsplit(")", 1)[1].split()[19]
        return birth == value["birth"]
    except FileNotFoundError:
        return False

def shutdown(serve, drain):
    graceful = True
    if serve.poll() is None:
        serve.send_signal(signal.SIGTERM)
        try:
            serve.wait(120)
        except subprocess.TimeoutExpired:
            graceful = False
            os.killpg(serve.pid, signal.SIGKILL)
            serve.wait(5)
    return {"exit": serve.returncode, "graceful": graceful,
            "stdoutDrained": drain.close(), "markers": sorted(drain.found)}

def configure(root, home, ports, mode, health_port):
    for name in ("bridge", "provider"):
        require(type(ports.get(name)) is int and 0 < ports[name] < 65536, "loopback_port")
    endpoint = f"http://127.0.0.1:{ports['provider']}/v1"
    config = home / "freedom.yaml"
    config.write_text(
        "operator_id: w2511-hosted\nonboarding_complete: true\nsecrets_backend: file\n"
        "provider_kind: openai_compat\n" + f"provider_endpoint: {endpoint}\n"
        "provider_model: w2511-loopback\n"
        "autonomy: custom\ncustom_autonomy:\n  overrides:\n    unbounded_paid_provider_call: allow\n"
        f"observability_listen: 127.0.0.1:{health_port}\n"
        "security:\n  smart_approve: true\ncompanion:\n  enabled: false\n  p2p_enabled: false\n")
    (home / "credentials.yaml").write_text(
        "provider_key: w2511-loopback-only\n"
        f"whatsapp_baileys_url: http://127.0.0.1:{ports['bridge']}\n"
        f"whatsapp_baileys_token: {TOKEN}\n"
        'whatsapp_baileys_allowed_senders: "+491701234567"\n')
    args = [str(root / ".github/scripts/whatsapp/held-mcp.py"), str(home), mode]
    (home / "mcp_servers.yaml").write_text(
        "servers:\n  - id: w2511-held\n    description: hosted held tool\n"
        f"    command: {json.dumps(sys.executable)}\n    args: {json.dumps(args)}\n"
        "    env: {GITHUB_ACTIONS: 'true'}\n    enabled: true\n    allow_tools: [read]\n"
        "    trust_all_tools: false\n    smart_approve: true\n    autonomy_gate: null\n")
    return config

def scenario(root, binary, home, mode):
    home.mkdir(mode=0o700)
    env = {**os.environ, "NEOTH_HOME": str(home), "NEOTH_MCP_AUTOROUTE": "1",
           "NEOTH_WA_STATUS_EDIT_V1": "1", "NEOTH_WA_STATUS_EDIT_DAEMON_V1": "0" if mode == "disabled" else "1"}
    result = {"mode": mode, "accepted": False, "stage": "helper_start"}
    helper = serve = drain = None
    try:
        helper = Helper(root, home / "sidecar", mode, env)
        ports = helper.read(20)
        require(ports.get("ready") is True, "helper_not_ready")
        health_port = reserve_port()
        config = configure(root, home, ports, mode, health_port)
        result["stage"] = "provider_consent"
        consent = subprocess.run([str(binary), "--output", "json", "consent", "grant", "openai_compat"],
                                 env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=25)
        require(consent.returncode == 0, "consent_refused")
        result["stage"] = "daemon_ready"
        serve = subprocess.Popen([str(binary), "serve", "--config", str(config)], env=env,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 bufsize=0, start_new_session=True)
        drain = Drain(serve.stdout)
        # A health response alone does not prove the channel captured its initial cursor.
        wait_until(lambda: health(health_port) and
                   (home / "channel-state/whatsapp-baileys-cursor.json").is_file(),
                   70, "channel_ready_deadline", serve)
        helper.command("inject")
        result["stage"] = "tool_entered"
        wait_until(lambda: (home / "entered").is_file(), 45, "tool_enter_deadline", serve)
        held = helper.command("snapshot")
        if mode != "disabled":
            result["stage"] = "live_status"
            def started():
                value = helper.command("snapshot")
                return value if any(w["kind"] == "tool_start" for w in value["writes"]) else None
            held = wait_until(started, 15, "live_status_deadline", serve)
        require(held["providerCalls"] == 1 and held["promptVerified"]
                and not any(w["kind"] == "final" for w in held["writes"])
                and not (home / "release").exists(), "tool_hold_contract")
        result["held"] = held
        result["stage"] = "shutdown_held" if mode == "cancel" else "tool_release"
        if mode != "cancel":
            (home / "release").write_text("release\n")
            def settled():
                value = helper.command("snapshot")
                phase = "tool_error" if mode == "tool_error" else "tool_finish"
                return value if value["providerCalls"] == 2 and (
                    mode == "disabled" or any(w["kind"] == phase for w in value["writes"])) else None
            completed = wait_until(settled, 30, "tool_settlement_deadline", serve)
            require(completed["resultVerified"], "result_not_returned_to_provider")
            helper.command("finish")
            result["stage"] = "final_delivery"
            def final():
                value = helper.command("snapshot")
                return value if any(w["kind"] == "final" for w in value["writes"]) else None
            final_snapshot = wait_until(final, 20, "final_deadline", serve)
            require(sum(w["kind"] == "final" for w in final_snapshot["writes"]) == 1, "final_count")
            if mode == "disabled":
                require(len(final_snapshot["writes"]) == 1, "disabled_sent_status")
            else:
                require(final_snapshot["writes"][-1]["closedBeforeSend"], "closure_not_before_final")
                result["late"] = helper.command("late")
                require(result["late"]["status"] == 409 and result["late"]["refused"]
                        and result["late"]["writesUnchanged"], "late_status_admitted")
            result["terminal"] = final_snapshot
        result["shutdown"] = shutdown(serve, drain)
        require(result["shutdown"]["graceful"] and result["shutdown"]["exit"] == 0
                and result["shutdown"]["stdoutDrained"], "daemon_shutdown_failed")
        require({"channels_drained", "transports_drained", "wal_senders_absent", "wal_drained"}
                .issubset(result["shutdown"]["markers"]), "shutdown_markers_missing")
        require(not {"panic", "neoth_panic"}.intersection(result["shutdown"]["markers"]), "daemon_panic")
        result["stage"] = "children_reaped"
        children = child_identities(home)
        require(children, "no_actual_mcp_child")
        wait_until(lambda: not any(same_child(child) for child in children), 5, "mcp_not_reaped")
        result["mcp"] = {"processes": len(children), "allReaped": True,
                         "calls": (home / "calls").read_text().splitlines().count("read")}
        require(result["mcp"]["calls"] == 1, "tool_retried")
        before = helper.command("snapshot")
        time.sleep(0.25)
        after = helper.command("snapshot")
        require(before == after and after["violations"] == 0, "writes_after_shutdown")
        if mode == "cancel":
            require(after["providerCalls"] == 1 and not (home / "release").exists()
                    and not any(w["kind"] in ("final", "tool_finish") for w in after["writes"]),
                    "cancelled_turn_completed")
        elif mode != "disabled":
            result["restartLate"] = helper.command("restart_late", 45)
            require(result["restartLate"]["status"] == 409 and result["restartLate"]["refused"]
                    and result["restartLate"]["writesUnchanged"], "restart_reopened_status")
        result["stableAfterShutdown"] = after
        result["stage"] = "accepted"
        result["accepted"] = True
    except Exception as error:
        # Closed categories/stage only; never emit provider payloads, credentials or daemon logs.
        result["failureType"] = type(error).__name__
        if isinstance(error, ContractFailure):
            result["failureCategory"] = str(error)
        if helper is not None and helper.process.poll() is None:
            try:
                result["failureSnapshot"] = helper.command("snapshot", 2)
            except Exception:
                result["failureSnapshotUnavailable"] = True
        result["accepted"] = False
    finally:
        if serve is not None:
            if "shutdown" not in result:
                result["shutdown"] = shutdown(serve, drain)
            result["shutdown"]["markers"] = sorted(drain.found)
        children = child_identities(home)
        survivors = [child for child in children if same_child(child)]
        result["forcedChildCleanup"] = len(survivors)
        for child in survivors:
            try:
                os.kill(child["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        if survivors:
            result["accepted"] = False
        if helper is not None:
            try:
                result["helperCleanup"] = helper.stop()
            except Exception as error:
                result["helperCleanup"] = {"failureType": type(error).__name__}
            if result["helperCleanup"].get("exit") != 0 or not result["helperCleanup"].get("graceful"):
                result["accepted"] = False
    return result

def main():
    require(os.environ.get("GITHUB_ACTIONS") == "true" and sys.platform == "linux",
            "hosted_linux_required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[3]
    binary = args.binary.resolve()
    require(binary.is_file(), "binary_missing")
    receipt = {"schema": "neoth.whatsapp.product-journey.v1",
               "producer": os.environ["GITHUB_SHA"], "run": os.environ["GITHUB_RUN_ID"],
               "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest().upper(),
               "scope": "actual NEOTH serve/MCP/BridgeClient/API/journals; controlled provider, held MCP tool and WhatsApp socket; no linked-account/device delivery",
               "scenarios": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="neoth-wa-journey-") as temporary:
        for mode in MODES:
            result = scenario(root, binary, pathlib.Path(temporary) / mode, mode)
            receipt["scenarios"].append(result)
            args.output.write_text(json.dumps(receipt, indent=2) + "\n")
            print(json.dumps({"scenario": mode, "accepted": result["accepted"], "stage": result["stage"]}), flush=True)
    return 0 if all(value["accepted"] for value in receipt["scenarios"]) else 1

if __name__ == "__main__":
    sys.exit(main())
