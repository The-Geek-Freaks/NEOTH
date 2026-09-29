#!/usr/bin/env python3
"""Hosted proof that the daemon adopts a real public BlueBubbles relink."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

try:
    import fcntl
except ImportError:  # The hosted canary is deliberately POSIX-only.
    fcntl = None


LIMIT = 256 * 1024
# Canary budget: 90s SelfMap shutdown drain plus traced 10s dispatch drain and
# margin; it is not a universal daemon-shutdown bound.
GRACEFUL_SHUTDOWN_TIMEOUT = 120
FORCED_REAP_TIMEOUT = 5
DAEMON_DIAGNOSTIC_HASH_DOMAIN = b"neoth-bluebubbles-daemon-diagnostic-v1\0"
TARGET = "iMessage;-;+491701234567"
WRONG_TARGET = "iMessage;-;+491700000000"
PASSWORD = "bluebubbles-daemon-canary-password"
SENDER = "+491701234567"
RELOAD = ".reload-requested"
DESTINATION = {"channel_id": "imessage_bluebubbles", "account_id": "default"}
SHA256 = re.compile(r"[0-9a-f]{64}")
FAILURE_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}")
ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SIGTERM_EVENT_LINE = re.compile(r"^.*\bneothd::shutdown:\s+SIGTERM\s*$")
DAEMON_DIAGNOSTIC_MARKERS = (
    ("recover interrupted NEOTH installation before startup", "process", "interrupted_install_recovery"),
    ("build the tokio runtime", "process", "tokio_runtime"),
    ("spawn the neoth main worker thread", "process", "main_worker_spawn"),
    ("neoth main worker thread panicked", "process", "main_worker_panic"),
    ("runtime config pair at ", "config", "runtime_config_pair"),
    ("operator hooks at ", "config", "startup_hooks"),
    ("GOLD-ADAPT-OH-03: onboarding incomplete", "onboarding", "onboarding_incomplete"),
    ("consent gate (V03-08 + A-2)", "consent", "provider_consent"),
    ("daemon startup cannot retain Allow Once consent", "consent", "ephemeral_consent"),
    ("write BOOT WAL frame", "wal", "boot_write"),
    ("start daemon membership/audit RPC", "authority", "audit_rpc"),
    ("start mandatory daemon audit RPC", "authority", "audit_rpc"),
    ("load skill registry for daemon instance", "runtime", "skill_registry"),
)
SHUTDOWN_PROGRESS_MARKERS = (
    ("serve_shutdown_entered", "shutdown signal received; aborting channels + draining WAL writer"),
    ("webhook_drain_timeout", "webhook drain timed out — abandoning remaining connections"),
    ("webhook_dispatch_drain_timeout", "COR-34: webhook dispatch drain timed out"),
    ("self_map_draining", "SelfMap cron is still draining; retaining owner and suppressing replacement"),
    ("self_map_timeout", "SelfMap did not quiesce during shutdown"),
    ("wal_drained", "WAL writer task drained cleanly"),
)


class Failure(RuntimeError):
    pass


def failure_code(error: Failure | None) -> str | None:
    """Expose only fixed canary failure codes in retained diagnostics."""
    if error is None:
        return None
    value = str(error)
    return value if FAILURE_CODE.fullmatch(value) else "unexpected_failure"


def regular(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
    except OSError:
        return False


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(path: Path) -> str:
    return sha256(path.read_bytes())


def daemon_log_snapshot(log: Path) -> dict:
    """Read daemon output once, with a hard bound suitable for retention."""
    if not regular(log):
        return {"log_present": False, "log_size": 0, "raw": None, "log_exceeds_bound": False}
    try:
        observed_size = log.stat().st_size
        with log.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
    except OSError:
        return {"log_present": False, "log_size": 0, "raw": None, "log_exceeds_bound": False}
    if len(raw) > LIMIT:
        return {"log_present": True, "log_size": observed_size, "raw": None, "log_exceeds_bound": True}
    return {"log_present": True, "log_size": observed_size, "raw": raw, "log_exceeds_bound": False}


def daemon_failure_diagnostic(snapshot: dict) -> dict:
    """Retain an allowlisted startup cause, never daemon log text."""
    if not snapshot["log_present"]:
        return {"stage": "unknown", "reason": "log_unavailable", "log_fingerprint_sha256": None}
    if snapshot["log_exceeds_bound"]:
        fingerprint = sha256(DAEMON_DIAGNOSTIC_HASH_DOMAIN + b"oversized\0" + str(snapshot["log_size"]).encode("ascii"))
        return {"stage": "unknown", "reason": "log_exceeds_bound", "log_fingerprint_sha256": fingerprint}
    raw = snapshot["raw"]
    assert raw is not None
    fingerprint = sha256(DAEMON_DIAGNOSTIC_HASH_DOMAIN + raw)
    rendered = raw.decode("utf-8", "replace")
    for marker, stage, reason in DAEMON_DIAGNOSTIC_MARKERS:
        if marker in rendered:
            return {"stage": stage, "reason": reason, "log_fingerprint_sha256": fingerprint}
    return {"stage": "unknown", "reason": "unknown", "log_fingerprint_sha256": fingerprint}


def daemon_shutdown_progress(snapshot: dict) -> dict[str, str]:
    """Retain fixed shutdown observations, never matched daemon log text."""
    names = ("sigterm_event",) + tuple(name for name, _ in SHUTDOWN_PROGRESS_MARKERS)
    if not snapshot["log_present"]:
        return {"state": "unavailable", **{name: "unavailable" for name in names}}
    if snapshot["log_exceeds_bound"]:
        return {"state": "oversized", **{name: "oversized" for name in names}}
    raw = snapshot["raw"]
    assert raw is not None
    rendered = raw.decode("utf-8", "replace")
    progress = {
        "sigterm_event": "observed" if any(SIGTERM_EVENT_LINE.fullmatch(ANSI_CSI.sub("", line)) for line in rendered.splitlines()) else "not_observed"
    }
    progress.update({name: "observed" if marker in rendered else "not_observed" for name, marker in SHUTDOWN_PROGRESS_MARKERS})
    return {"state": "observed" if "observed" in progress.values() else "unknown", **progress}


def contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def snapshot(path: Path) -> tuple[bool, bytes]:
    if path.is_symlink():
        raise Failure("snapshot_invalid")
    return path.exists(), path.read_bytes() if path.exists() else b""


def pair_commitment(home: Path) -> str:
    return pair_from_snapshots(snapshot(home / "freedom.yaml"), snapshot(home / "credentials.yaml"))


def pair_from_snapshots(freedom: tuple[bool, bytes], credentials: tuple[bool, bytes]) -> str:
    value = hashlib.sha256(b"neoth-converted-relink-pair-v1\0")
    for name, member in (("freedom.yaml", freedom), ("credentials.yaml", credentials)):
        present, raw = member
        value.update(name.encode() + b"\0")
        value.update(b"\x01" + len(raw).to_bytes(8, "little") + raw if present else b"\0")
    return value.hexdigest()


def material_commitment(port: int, watched_chat_guid: str, outbound_target: str) -> str:
    value = hashlib.sha256(b"neoth-converted-relink-material-v1\0")
    value.update(b"imessage_bluebubbles\0")
    value.update(outbound_target.encode())
    value.update(b"\0")
    for field in (f"http://127.0.0.1:{port}", PASSWORD, watched_chat_guid, SENDER):
        raw = field.encode()
        value.update(len(raw).to_bytes(8, "little"))
        value.update(raw)
    return value.hexdigest()


def command(argv: list[str], env: dict[str, str], stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    process = None
    selector = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        assert process.stdin and process.stdout and process.stderr
        process.stdin.write(stdin)
        process.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        output = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + 60
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Failure("command_timeout")
            for key, _ in selector.select(remaining):
                chunk = key.fileobj.read1(8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if len(output[key.data]) > LIMIT:
                    raise Failure("command_output_limit")
        return subprocess.CompletedProcess(argv, process.wait(timeout=10), bytes(output["stdout"]), bytes(output["stderr"]))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Failure("command_unavailable") from error
    finally:
        if selector is not None:
            selector.close()
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                raise Failure("command_kill_timeout") from error
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def one_json(raw: bytes, failure: str) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except Exception as error:
        raise Failure(failure) from error
    if not isinstance(value, dict):
        raise Failure(failure)
    return value


def read_json(path: Path, failure: str) -> dict:
    if not regular(path):
        raise Failure(failure)
    return one_json(path.read_bytes(), failure)


class LoopbackServices:
    """BlueBubbles accepts only probes and empty polls; provider traffic is denied."""
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: list[str] = []
        self.started = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def record(self, event: str) -> None:
        with self.lock:
            self.events.append(event)

    def handler(self):
        parent = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                return
            def reply(self, status: int, value: dict) -> None:
                raw = json.dumps(value, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def do_GET(self) -> None:
                split = urlsplit(self.path)
                query = parse_qs(split.query, keep_blank_values=True)
                path = unquote(split.path)
                if path == "/api/v1/ping" and query == {"password": [PASSWORD]}:
                    parent.record("ping")
                    self.reply(200, {"status": 200})
                elif path == "/api/v1/chat/" + TARGET and query == {"password": [PASSWORD]}:
                    parent.record("target")
                    self.reply(200, {"status": 200, "data": {"guid": TARGET}})
                elif path.startswith("/api/v1/chat/"):
                    parent.record("wrong_target")
                    self.reply(404, {"status": 404})
                else:
                    parent.record("unexpected")
                    self.reply(404, {})
            def do_POST(self) -> None:
                split = urlsplit(self.path)
                if split.path == "/api/v1/message/query" and parse_qs(split.query, keep_blank_values=True) == {"password": [PASSWORD]}:
                    try:
                        body = one_json(self.rfile.read(int(self.headers.get("Content-Length", "0"))), "poll_body_invalid")
                    except Failure:
                        parent.record("invalid_poll")
                        self.reply(400, {})
                        return
                    if set(body) == {"after", "limit", "offset", "sort", "with"} and body.get("limit") == 1000 and body.get("offset") == 0 and body.get("sort") == "ASC" and body.get("with") == ["chats"] and isinstance(body.get("after"), int):
                        parent.record("empty_poll")
                        self.reply(200, {"status": 200, "data": [], "metadata": {"total": 0}})
                        return
                    parent.record("invalid_poll")
                    self.reply(400, {})
                    return
                if split.path.startswith("/v1/"):
                    parent.record("provider_request")
                    self.reply(503, {})
                    return
                parent.record("message_or_other_post")
                self.reply(405, {})
        return Handler

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def stop(self) -> bool:
        if self.started:
            self.server.shutdown()
            self.thread.join(10)
        self.server.server_close()
        return not self.thread.is_alive()

    def counts(self) -> dict[str, int]:
        with self.lock:
            return {name: self.events.count(name) for name in ("ping", "target", "wrong_target", "empty_poll", "invalid_poll", "provider_request", "message_or_other_post", "unexpected")}


def configure_loopback_provider(home: Path, port: int) -> None:
    """Align legacy and effective single-mode provider routes before consent."""
    config = home / "freedom.yaml"
    if not regular(config):
        raise Failure("provider_config_missing")
    values = {
        "provider_kind": "openai_compat",
        "provider_endpoint": f"http://127.0.0.1:{port}/v1",
        "provider_model": "daemon-canary-model",
    }
    raw = config.read_text(encoding="utf-8")
    for key, value in values.items():
        pattern = re.compile(rf"(?m)^{re.escape(key)}:.*$")
        replacement = f"{key}: {value}"
        if pattern.search(raw):
            raw = pattern.sub(replacement, raw, count=1)
        else:
            raw += "" if raw.endswith("\n") else "\n"
            raw += replacement + "\n"
    endpoint = values["provider_endpoint"]
    topology = (
        "inference:\n"
        "  mode: single\n"
        "  default_slot:\n"
        "    provider: openai_compat\n"
        f"    model: {values['provider_model']}\n"
        f"    endpoint: {endpoint}\n"
    )
    inference_block = re.compile(r"(?m)^inference:\n(?:(?:^[ \t][^\n]*(?:\n|$))|^\n)*")
    if inference_block.search(raw):
        raw = inference_block.sub(topology, raw, count=1)
    else:
        raw += "" if raw.endswith("\n") else "\n"
        raw += topology
    config.write_text(raw, encoding="utf-8")


def complete_daemon_test_onboarding(home: Path) -> None:
    """Mark this fresh, channel-free canary home as intentionally daemon-ready."""
    config = home / "freedom.yaml"
    if not regular(config):
        raise Failure("provider_config_missing")
    raw = config.read_text(encoding="utf-8")
    pattern = re.compile(r"(?m)^onboarding_complete:.*$")
    if pattern.search(raw):
        raw = pattern.sub("onboarding_complete: true", raw, count=1)
    else:
        raw += "" if raw.endswith("\n") else "\n"
        raw += "onboarding_complete: true\n"
    config.write_text(raw, encoding="utf-8")


def init_home(binary: Path, home: Path, env: dict[str, str], port: int) -> None:
    if not home.is_dir() or home.is_symlink() or any(home.iterdir()):
        raise Failure("init_home_not_fresh")
    argv = [str(binary), "init", "--non-interactive", "--cli", "--accept-license", "--operator-id", "bluebubbles-daemon-canary", "--provider", "skip"]
    if command(argv, env).returncode:
        raise Failure("init_failed")
    master = home / "wal" / "master.key"
    if not regular(master) or master.stat().st_size != 32 or master.stat().st_mode & 0o077:
        raise Failure("init_identity_invalid")
    configure_loopback_provider(home, port)
    # The canary deliberately starts before its converted relink creates a
    # channel. Persist the documented completion flag only in this fresh,
    # isolated daemon test home; production still rejects incomplete homes.
    complete_daemon_test_onboarding(home)


def grant_loopback_provider_consent(binary: Path, env: dict[str, str], port: int) -> None:
    """Record the real endpoint-bound OpenAI-compatible consent before serve."""
    granted = command([str(binary), "--output", "json", "consent", "grant", "openai_compat"], env)
    if granted.returncode:
        raise Failure("provider_consent_grant_failed")
    receipt = one_json(granted.stdout, "provider_consent_grant_output_invalid")
    origin = f"http://127.0.0.1:{port}"
    if receipt.get("provider") != "openai_compat" or receipt.get("status") != "applied" or receipt.get("authority_persisted") is not True or receipt.get("failure") is not None or receipt.get("configured_endpoint_origins") != [origin] or receipt.get("endpoint_origins") != [origin] or receipt.get("added_endpoint_origins") != [origin]:
        raise Failure("provider_consent_grant_invalid")


def source(path: Path) -> None:
    if path.exists() or path.is_symlink() or path.name != "openclaw.json":
        raise Failure("source_path_invalid")
    path.write_text('{"channels":{"imessage":{"accounts":{"personal":{"cliPath":"/usr/bin/imsg"}}}}}\n', encoding="utf-8")
    os.chmod(path, 0o600)


def envelope(port: int) -> bytes:
    fields = {"url": f"http://127.0.0.1:{port}", "password": PASSWORD, "allowed_sender": SENDER, "channels_csv": TARGET}
    return json.dumps({"schema_version": 1, "channel": "imessage_bluebubbles", "fields": fields}, separators=(",", ":")).encode()


def relink_argv(binary: Path, source_path: Path, target: str) -> list[str]:
    return [str(binary), "--output", "json", "channel", "relink-openclaw", "imessage_bluebubbles", "--config", str(source_path), "--source-account", "personal", "--target", target]


def validate_output(raw: bytes, already_ready: bool, identity: str | None = None) -> str:
    value = one_json(raw, "cli_json_invalid")
    if set(value) != {"channel", "account", "relink_id", "state", "already_ready", "reload_requested"} or value.get("channel") != "imessage_bluebubbles" or value.get("account") != "default" or value.get("state") != "ready" or value.get("already_ready") is not already_ready or value.get("reload_requested") is not True:
        raise Failure("cli_output_invalid")
    result = value.get("relink_id")
    if not isinstance(result, str) or not SHA256.fullmatch(result) or identity is not None and result != identity:
        raise Failure("cli_identity_invalid")
    return result


def require_pending_without_poll(home: Path, before: dict[str, tuple[bool, bytes]], services: LoopbackServices) -> dict:
    if any(snapshot(home / name) != value for name, value in before.items()):
        raise Failure("wrong_target_mutated_state")
    if (home / RELOAD).exists() or (home / ".channel-relink-imessage.transaction.json").exists():
        raise Failure("wrong_target_published_ready")
    index = read_json(home / "channel_relinks.json", "pending_index_invalid")
    pending = index.get("pending")
    records = [item for item in pending if isinstance(item, dict) and item.get("destination") == DESTINATION] if isinstance(pending, list) else []
    counts = services.counts()
    if len(records) != 1 or records[0].get("state") != "pending" or counts["ping"] < 1 or counts["wrong_target"] < 1 or counts["empty_poll"] != 0:
        raise Failure("wrong_target_pending_invalid")
    return {"pending_id": records[0].get("id"), "source_set_sha256": records[0].get("source_set_sha256")}


def require_ready(home: Path, identity: str, expected_material: str, source_digest: str, pair_before: str, routing_before: str) -> dict[str, str]:
    routing_raw = (home / "channel_routing.json").read_bytes()
    routing = one_json(routing_raw, "routing_invalid")
    if routing.get("destinations", {}).get("imessage_chat_guid") != TARGET:
        raise Failure("routing_target_invalid")
    index = read_json(home / "channel_relinks.json", "index_invalid")
    pending = index.get("pending")
    records = [item for item in pending if isinstance(item, dict) and item.get("destination") == DESTINATION] if isinstance(pending, list) else []
    if len(records) != 1:
        raise Failure("ready_identity_invalid")
    entry = records[0]
    if entry.get("id") != identity or entry.get("state") != "ready" or entry.get("bound_material_sha256") != expected_material or entry.get("completion_request_material_sha256") != expected_material or not isinstance(entry.get("source_set_sha256"), str) or not SHA256.fullmatch(entry["source_set_sha256"]) or digest(home.parent / "openclaw.json") != source_digest:
        raise Failure("ready_binding_invalid")
    transaction = read_json(home / ".channel-relink-imessage.transaction.json", "transaction_invalid")
    if transaction.get("pending_id") != identity or transaction.get("destination") != DESTINATION or transaction.get("request_material_sha256") != expected_material or transaction.get("target_sha256") != sha256(TARGET.encode()) or transaction.get("pair_before_sha256") != pair_before or transaction.get("routing_before_sha256") != routing_before or transaction.get("phase") != "routing_committed" or transaction.get("pair_after_sha256") != pair_commitment(home) or transaction.get("routing_after_sha256") != sha256(routing_raw):
        raise Failure("transaction_invalid")
    return {"routing_sha256": sha256(routing_raw), "pair_sha256": pair_commitment(home), "source_set_sha256": entry["source_set_sha256"]}


def ready_bytes(home: Path) -> dict[str, bytes]:
    names = ("freedom.yaml", "credentials.yaml", "channel_routing.json", "channel_relinks.json", ".channel-relink-imessage.transaction.json")
    paths = {name: home / name for name in names}
    if any(not regular(path) for path in paths.values()):
        raise Failure("ready_bytes_missing")
    return {name: path.read_bytes() for name, path in paths.items()}


def start_daemon(binary: Path, home: Path, env: dict[str, str], log: Path) -> subprocess.Popen[bytes]:
    sink = log.open("xb")
    try:
        process = subprocess.Popen([str(binary), "serve", "--config", str(home / "freedom.yaml")], stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT, env=env)
    except OSError as error:
        raise Failure("daemon_spawn_failed") from error
    finally:
        sink.close()
    return process


def require_daemon_pid_lock(process: subprocess.Popen[bytes], home: Path) -> int:
    """Prove the launched serve owns the stable canonical Unix PID lock."""
    require_live(process)
    if fcntl is None:
        raise Failure("daemon_pid_lock_platform_unsupported")
    pidfile = home / "neothd.pid"
    if not regular(pidfile):
        raise Failure("daemon_pidfile_invalid")
    try:
        inode = pidfile.stat().st_ino
        first_line = pidfile.read_text(encoding="utf-8").splitlines()[0]
    except (OSError, UnicodeError, IndexError) as error:
        raise Failure("daemon_pidfile_unreadable") from error
    if first_line != str(process.pid):
        raise Failure("daemon_pidfile_owner_mismatch")
    fd = None
    try:
        fd = os.open(pidfile, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EAGAIN, errno.EACCES):
                raise Failure("daemon_pidfile_lock_probe_failed") from error
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            raise Failure("daemon_pidfile_unlocked")
    except OSError as error:
        raise Failure("daemon_pidfile_open_failed") from error
    finally:
        if fd is not None:
            os.close(fd)
    require_live(process)
    return inode


def validate_daemon_status(status: object) -> None:
    """Reject offline/fallback shapes; status must be the public live wire envelope."""
    if not isinstance(status, dict) or set(status) != {"wire_version", "operation", "membership", "runtime"}:
        raise Failure("daemon_status_envelope_invalid")
    if status.get("wire_version") != 1 or status.get("operation") != "cluster.status":
        raise Failure("daemon_status_envelope_invalid")
    membership = status.get("membership")
    if not isinstance(membership, dict) or set(membership) != {"wire_version", "operation", "snapshot_version", "snapshot_digest", "snapshot"}:
        raise Failure("daemon_status_membership_invalid")
    if membership.get("wire_version") != 1 or membership.get("operation") != "cluster.membership.snapshot" or membership.get("snapshot_version") != 1 or not isinstance(membership.get("snapshot_digest"), str) or not SHA256.fullmatch(membership["snapshot_digest"]) or not isinstance(membership.get("snapshot"), dict):
        raise Failure("daemon_status_membership_invalid")
    runtime = status.get("runtime")
    expected_runtime = {"version", "mode", "policy", "conflict_count", "operator_id", "node_id", "cluster_name", "cluster_passphrase_set", "cluster_identity_configured", "cluster_enabled", "restart_required", "transport_active", "transport", "listen_port", "mdns_enabled", "trusted_ssids", "gossip"}
    if not isinstance(runtime, dict) or set(runtime) != expected_runtime or runtime.get("version") != 1 or runtime.get("mode") not in {"cluster", "single-node"} or runtime.get("policy") not in {"local-only", "discovery-off", "announce-any-network", "announce-trusted-wifi-only"} or not isinstance(runtime.get("conflict_count"), int) or isinstance(runtime.get("conflict_count"), bool) or not isinstance(runtime.get("operator_id"), str) or not runtime["operator_id"].strip() or not isinstance(runtime.get("node_id"), str) or not runtime["node_id"].strip() or not isinstance(runtime.get("transport"), str) or not runtime["transport"].strip() or not isinstance(runtime.get("listen_port"), int) or isinstance(runtime.get("listen_port"), bool) or runtime["listen_port"] <= 0 or not all(isinstance(runtime.get(key), bool) for key in ("cluster_passphrase_set", "cluster_identity_configured", "cluster_enabled", "restart_required", "transport_active", "mdns_enabled")) or not isinstance(runtime.get("trusted_ssids"), list) or not all(isinstance(item, str) and item.strip() == item and item for item in runtime["trusted_ssids"]) or not isinstance(runtime.get("gossip"), dict) or set(runtime["gossip"]) != {"replicate_raw_ingress", "replay_budget_days"} or not isinstance(runtime["gossip"].get("replicate_raw_ingress"), bool) or not isinstance(runtime["gossip"].get("replay_budget_days"), int) or isinstance(runtime["gossip"].get("replay_budget_days"), bool):
        raise Failure("daemon_status_runtime_invalid")
    if runtime["transport_active"] and (not runtime["cluster_enabled"] or runtime["restart_required"]):
        raise Failure("daemon_status_runtime_invalid")


def wait_for_daemon_ready(process: subprocess.Popen[bytes], home: Path, binary: Path, env: dict[str, str]) -> None:
    """Status may certify readiness only while the launched daemon holds its PID lock."""
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        require_live(process)
        try:
            before_inode = require_daemon_pid_lock(process, home)
        except Failure as error:
            # Serve creates and locks this file during startup. Absence before
            # that point is not readiness, but it is transient rather than a
            # verdict on the launched child.
            if str(error) in {"daemon_pidfile_invalid", "daemon_pidfile_unreadable"}:
                time.sleep(0.2)
                continue
            raise
        inspected = command([str(binary), "--output", "json", "cluster", "status"], env)
        if inspected.returncode == 0:
            status = one_json(inspected.stdout, "daemon_ready_output_invalid")
            validate_daemon_status(status)
            after_inode = require_daemon_pid_lock(process, home)
            if after_inode == before_inode:
                return
            raise Failure("daemon_pidfile_inode_changed")
        time.sleep(0.2)
    raise Failure("daemon_ready_timeout")


def require_live(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        raise Failure("daemon_exited_early")


def observe_pending_supervisor_window(process: subprocess.Popen[bytes], services: LoopbackServices, seconds: float = 3.0) -> None:
    """Observe a live post-refusal window; an instantaneous zero poll count is not evidence."""
    baseline = services.counts()["empty_poll"]
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        require_live(process)
        if services.counts()["empty_poll"] != baseline:
            raise Failure("pending_target_polled")
        time.sleep(0.2)
    require_live(process)


def wait_for_reload_adoption(home: Path, process: subprocess.Popen[bytes], services: LoopbackServices, baseline: int) -> None:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        require_live(process)
        if services.counts()["empty_poll"] > baseline:
            if (home / RELOAD).exists():
                raise Failure("reload_not_consumed_after_poll")
            return
        time.sleep(0.2)
    raise Failure("daemon_adoption_timeout")


def stop_daemon(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=GRACEFUL_SHUTDOWN_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=FORCED_REAP_TIMEOUT)
            except subprocess.TimeoutExpired as error:
                raise Failure("daemon_stop_timeout") from error
            raise Failure("daemon_stop_timeout")
    if process.returncode not in (0, -signal.SIGTERM):
        raise Failure("daemon_stop_failed")


def source_bindings(workflow: Path) -> dict[str, str]:
    relatives = (
        "packaging/bluebubbles_daemon_adoption_canary.py", "packaging/tests/test_bluebubbles_daemon_adoption_canary.py", "packaging/converted_channel_relink_product_canary.py", ".github/workflows/gchat-live-regressions.yml",
        "SRC/neothd/src/main.rs", "SRC/neothd/src/lib.rs", "SRC/neothd/src/shutdown.rs", "SRC/neothd/src/cli/channel_relink.rs", "SRC/neothd/src/cli/channel.rs", "SRC/neothd/src/cli/channel/converted_relink.rs", "SRC/neothd/src/cli/mod.rs", "SRC/neothd/src/cli/serve.rs", "SRC/neothd/src/cli/serve_tasks.rs", "SRC/neothd/src/cli/cluster.rs", "SRC/neothd/src/cli/consent.rs", "SRC/neothd/src/cli/consent_outbox.rs",
        "SRC/neothd/src/cli/init.rs", "SRC/neothd/src/cli/init/types.rs", "SRC/neothd/src/cli/init/io.rs", "SRC/neothd/src/cli/init/first_install_identity.rs", "SRC/neothd/src/cli/init/steps_identity.rs", "SRC/neothd/src/cli/init/steps_provider.rs",
        "SRC/neothd/src/channels/imessage_bluebubbles.rs", "SRC/neothd/src/channels/relink.rs", "SRC/neothd/src/channels/routing.rs", "SRC/neothd/src/channels/webhook_listener.rs", "SRC/neothd/src/config/mod.rs", "SRC/neothd/src/config/credentials.rs", "SRC/neothd/src/config/reload.rs", "SRC/neothd/src/config/wal.rs", "SRC/neothd/src/consent.rs", "SRC/neothd/src/wal/master_key.rs", "SRC/neothd/src/wal/writer.rs",
        "SRC/neothd/src/cluster/status_wire.rs", "SRC/neothd/src/cluster/membership.rs", "SRC/neothd/src/cluster/runtime_supervisor.rs", "SRC/neothd/src/daemon/pidfile.rs", "SRC/neothd/src/daemon/chat_runtime.rs", "SRC/neothd/src/daemon/gui_chat_runtime.rs", "SRC/neothd/src/daemon/webchat.rs", "SRC/neothd/src/daemon/channel_live_registry.rs", "SRC/neothd/src/daemon/audit_rpc/mod.rs", "SRC/neothd/src/daemon/audit_rpc/client.rs", "SRC/neothd/src/daemon/audit_rpc/server.rs", "SRC/neothd/src/daemon/audit_rpc/sidecar.rs", "SRC/neothd/src/daemon/audit_rpc/token.rs", "SRC/neothd/src/daemon/audit_rpc/transport/mod.rs", "SRC/neothd/src/daemon/audit_rpc/transport/unix.rs", "SRC/neothd/src/skills/store.rs",
        "SRC/neothd/src/providers/mod.rs", "SRC/neothd/src/providers/openai_api.rs", "SRC/neoth-openclaw-custody/src/lib.rs", "SRC/neoth-openclaw-custody/src/pinned_inventory.rs", "SRC/neoth-openclaw-custody/src/pinned_schema.rs", "SRC/neoth-openclaw-custody/src/fixtures/pinned_channel_inventory_v1.json", "SRC/neoth-openclaw-custody/src/fixtures/openclaw_upstream_evidence_v1.json", "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_v1.json", "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_migration_policy_v1.json", "SRC/neoth-openclaw-custody/Cargo.toml", "SRC/neothd/Cargo.toml", "SRC/Cargo.lock",
    )
    paths = {item: Path(item) for item in relatives}
    paths["SRC/neothd/src/util/locked_file.rs"] = Path("SRC/neothd/src/util/locked_file.rs")
    if workflow.resolve() != paths[".github/workflows/gchat-live-regressions.yml"].resolve() or any(not regular(path) for path in paths.values()):
        raise Failure("source_provenance_missing")
    return {item: digest(path) for item, path in paths.items()}


def retain_daemon_diagnostics(evidence: Path, log: Path, process: subprocess.Popen[bytes] | None, primary_failure: Failure | None = None, primary_phase: str | None = None, stop_failure: Failure | None = None, loopback_failure: Failure | None = None) -> None:
    """Keep only redacted lifecycle facts; the daemon log itself is removed."""
    log_snapshot = daemon_log_snapshot(log)
    raw = log_snapshot["raw"]
    diagnostic = {
        "log_present": log_snapshot["log_present"],
        "log_size": log_snapshot["log_size"],
        "log_sha256": sha256(raw) if raw is not None else None,
        "returncode": process.returncode if process is not None else None,
        "primary_failure": failure_code(primary_failure),
        "primary_phase": primary_phase if primary_failure is not None else None,
        "stop_failure": failure_code(stop_failure),
        "loopback_failure": failure_code(loopback_failure),
        "startup_cause": daemon_failure_diagnostic(log_snapshot),
        "shutdown_progress": daemon_shutdown_progress(log_snapshot),
    }
    (evidence / "daemon-diagnostics.json").write_text(json.dumps(diagnostic, sort_keys=True), encoding="utf-8")


def cleanup(root: Path, home: Path, source_path: Path, log: Path, process: subprocess.Popen[bytes] | None, evidence: Path) -> dict[str, bool]:
    flags = {}
    try:
        if process is not None:
            stop_daemon(process)
        flags["daemon_reaped"] = True
    except Exception:
        # Exit status and process containment are separate facts. A daemon
        # that exited non-zero after SIGTERM is still reaped; reporting it as
        # live would both misstate cleanup and obscure the retained diagnostic.
        flags["daemon_reaped"] = process is not None and process.poll() is not None
    for name, path in (("home_removed", home), ("source_removed", source_path), ("log_removed", log)):
        try:
            if not contained(path, root) or path.is_symlink():
                flags[name] = False
            elif path.exists():
                shutil.rmtree(path) if path.is_dir() else path.unlink()
                flags[name] = not path.exists()
            else:
                flags[name] = True
        except OSError:
            flags[name] = False
    flags["evidence_retained"] = evidence.is_dir() and contained(evidence, root)
    return flags


def raise_teardown_failure(stop_failure: Failure | None, loopback_failure: Failure | None) -> None:
    """Keep daemon-stop failure ahead of later loopback cleanup failure."""
    if stop_failure is not None:
        raise stop_failure
    if loopback_failure is not None:
        raise loopback_failure


def execute(binary: Path, root: Path, home: Path, source_path: Path, evidence: Path, workflow: Path, state: dict) -> dict:
    phase = "provenance"
    primary_failure = None
    bindings = {}
    services = LoopbackServices()
    process = None
    log = root / "daemon.log"
    home.mkdir()
    evidence.mkdir()
    source(source_path)
    env = dict(os.environ)
    env["NEOTH_HOME"] = str(home)
    try:
        bindings = source_bindings(workflow)
        phase = "init"
        services.start()
        init_home(binary, home, env, services.port)
        # `init` supplies the valid default WAL policy.  Do not enable the
        # currently unwired at-rest sealing policy here: the mandatory
        # standalone WAL audit for `consent grant` must be acknowledged before
        # the daemon may start, and the writer correctly refuses that policy.
        phase = "consent"
        grant_loopback_provider_consent(binary, env, services.port)
        phase = "start"
        process = start_daemon(binary, home, env, log)
        state["daemon"] = process
        # The process must cross an authenticated daemon-ready barrier before a
        # relink can claim a reload rather than initial startup adoption.
        phase = "readiness"
        wait_for_daemon_ready(process, home, binary, env)
        before = {name: snapshot(home / name) for name in ("freedom.yaml", "wal/master.key", "credentials.yaml", "channel_routing.json")}
        phase = "pending"
        wrong = command(relink_argv(binary, source_path, WRONG_TARGET), env, envelope(services.port))
        if wrong.returncode == 0:
            raise Failure("wrong_target_accepted")
        pending = require_pending_without_poll(home, before, services)
        observe_pending_supervisor_window(process, services)
        source_digest = digest(source_path)
        polls_before_reload = services.counts()["empty_poll"]
        phase = "relink"
        ready = command(relink_argv(binary, source_path, TARGET), env, envelope(services.port))
        if ready.returncode:
            raise Failure("relink_failed")
        identity = validate_output(ready.stdout, False)
        pair_before = pair_from_snapshots(before["freedom.yaml"], before["credentials.yaml"])
        routing_before = sha256(before["channel_routing.json"][1])
        durable = require_ready(home, identity, material_commitment(services.port, TARGET, TARGET), source_digest, pair_before, routing_before)
        phase = "adoption"
        wait_for_reload_adoption(home, process, services, polls_before_reload)
        before_retry = ready_bytes(home)
        phase = "retry"
        retry = command(relink_argv(binary, source_path, TARGET), env, envelope(services.port))
        if retry.returncode:
            raise Failure("retry_failed")
        validate_output(retry.stdout, True, identity)
        if require_ready(home, identity, material_commitment(services.port, TARGET, TARGET), source_digest, pair_before, routing_before) != durable or ready_bytes(home) != before_retry:
            raise Failure("retry_mutated_durable_state")
        counts = services.counts()
        if counts["empty_poll"] < 1 or counts["provider_request"] or counts["message_or_other_post"] or counts["invalid_poll"] or counts["unexpected"]:
            raise Failure("daemon_traffic_contract_invalid")
        result = {"relink_id": identity, "pending_negative": pending, "ready": durable, "requests": counts, "daemon_adoption": {"proven": True, "witness": "authenticated_empty_message_query"}, "source_bindings": bindings, "binary_sha256": digest(binary)}
        (evidence / "receipt-summary.json").write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        return result
    except Failure as caught:
        primary_failure = caught
        raise
    except Exception:
        primary_failure = Failure("unexpected_failure")
        raise
    finally:
        stop_failure = None
        loopback_failure = None
        if process is not None:
            try:
                stop_daemon(process)
            except Failure as caught:
                stop_failure = caught
            except Exception:
                stop_failure = Failure("daemon_stop_unexpected")
            if process.poll() is not None:
                state["daemon"] = None
        try:
            if not services.stop():
                loopback_failure = Failure("loopback_cleanup_failed")
        except Exception:
            loopback_failure = Failure("loopback_cleanup_failed")
        retain_daemon_diagnostics(evidence, log, process, primary_failure, phase, stop_failure, loopback_failure)
        if primary_failure is None:
            raise_teardown_failure(stop_failure, loopback_failure)


def receipt_payload(result: dict | None, error: str | None, flags: dict[str, bool], source_head: str) -> dict:
    payload = {"schema_version": 1, "outcome": "passed" if result and all(flags.values()) else "failed", "failure": error, "cleanup": flags, "source_head": source_head}
    if result:
        payload["daemon_adoption"] = result
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("--binary", "--root", "--home", "--source", "--evidence-dir", "--receipt", "--workflow"):
        parser.add_argument(name, required=True)
    args = parser.parse_args()
    root, home, source_path = Path(args.root).absolute(), Path(args.home).absolute(), Path(args.source).absolute()
    evidence, receipt, binary, workflow = Path(args.evidence_dir).absolute(), Path(args.receipt).absolute(), Path(args.binary).absolute(), Path(args.workflow).absolute()
    temp = Path(os.environ.get("RUNNER_TEMP", "")).absolute()
    valid = os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REF") == "refs/heads/main" and re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) and regular(binary) and root.is_dir() and not root.is_symlink() and not any(root.iterdir()) and contained(root, temp) and home == root / "neoth-home" and source_path == root / "openclaw.json" and evidence == root / "evidence" and receipt == root / "receipt" / "receipt.json" and workflow == Path(".github/workflows/gchat-live-regressions.yml").absolute()
    if not valid:
        raise Failure("hosted_guard_failed")
    result = None
    error = None
    state: dict = {"daemon": None}
    log = root / "daemon.log"
    try:
        result = execute(binary, root, home, source_path, evidence, workflow, state)
    except Failure as caught:
        error = str(caught)
    except Exception:
        error = "unexpected_failure"
    flags = cleanup(root, home, source_path, log, state["daemon"], evidence)
    payload = receipt_payload(result, error, flags, os.environ.get("GITHUB_SHA", ""))
    rendered = json.dumps(payload, sort_keys=True)
    if PASSWORD in rendered:
        raise Failure("receipt_secret_leak")
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(rendered, encoding="utf-8")
    return 0 if payload["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
