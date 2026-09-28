#!/usr/bin/env python3
"""Hosted public-CLI acceptance for the converted BlueBubbles relink.

This is deliberately a loopback transport canary.  It proves the compiled
public command's first-use, exact-target and retry lifecycle; it does not
claim a BlueBubbles installation, daemon reload, or external-provider test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


LIMIT = 256 * 1024
TARGET = "iMessage;-;+491701234567"
WRONG_TARGET = "iMessage;-;+491700000000"
PASSWORD = "converted-relink-canary-password"
RELOAD_SENTINEL = ".reload-requested"
DURABLE_NAMES = (
    "credentials.yaml",
    "freedom.yaml",
    "channel_routing.json",
    "channel_relinks.json",
    ".channel-relink-imessage.transaction.json",
)
SHA256 = re.compile(r"[0-9a-f]{64}")


class Failure(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_snapshot(path: Path) -> tuple[bool, bytes]:
    if path.is_symlink():
        raise Failure("snapshot_input_invalid")
    if not path.exists():
        return False, b""
    if not regular(path) or path.stat().st_size > LIMIT:
        raise Failure("snapshot_input_invalid")
    return True, path.read_bytes()


def pair_v1(freedom: tuple[bool, bytes], credentials: tuple[bool, bytes]) -> str:
    hash_value = hashlib.sha256(b"neoth-converted-relink-pair-v1\0")
    for name, snapshot in ((b"freedom.yaml", freedom), (b"credentials.yaml", credentials)):
        present, raw = snapshot
        hash_value.update(name); hash_value.update(b"\0")
        if present:
            hash_value.update(b"\x01"); hash_value.update(len(raw).to_bytes(8, "little")); hash_value.update(raw)
        else:
            hash_value.update(b"\0")
    return hash_value.hexdigest()


def imessage_request_v1(url: str, password: str, inbound_guid: str, sender: str) -> str:
    hash_value = hashlib.sha256(b"neoth-converted-relink-material-v1\0")
    hash_value.update(b"imessage_bluebubbles\0"); hash_value.update(TARGET.encode()); hash_value.update(b"\0")
    for value in (url, password, inbound_guid, sender):
        raw = value.encode(); hash_value.update(len(raw).to_bytes(8, "little")); hash_value.update(raw)
    return hash_value.hexdigest()


def expected_context(home: Path, port: int) -> dict[str, str]:
    freedom, credentials, routing = file_snapshot(home / "freedom.yaml"), file_snapshot(home / "credentials.yaml"), file_snapshot(home / "channel_routing.json")
    return {"pair_before_sha256": pair_v1(freedom, credentials), "routing_before_sha256": sha256(routing[1]),
            "target_sha256": sha256(TARGET.encode()),
            "request_material_sha256": imessage_request_v1(f"http://127.0.0.1:{port}", PASSWORD, TARGET, "+491701234567"),
            "freedom_before_state": "present" if freedom[0] else "missing", "credentials_before_state": "present" if credentials[0] else "missing", "routing_before_state": "present" if routing[0] else "missing"}


def contained(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def regular(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
    except OSError:
        return False


def require_hosted(root: Path, home: Path, source: Path, evidence: Path, receipt: Path) -> None:
    temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise Failure("hosted_guard_failed")
    if not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")):
        raise Failure("hosted_guard_failed")
    if not root.is_dir() or root.is_symlink() or not contained(root, temp) or any(root.iterdir()):
        raise Failure("isolated_root_invalid")
    if home != root / "neoth-home" or source != root / "openclaw.yaml":
        raise Failure("isolated_path_invalid")
    if evidence != root / "evidence" or receipt != root / "receipt" / "receipt.json":
        raise Failure("isolated_path_invalid")


def command(argv: list[str], env: dict[str, str], stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        process.stdin.write(stdin); process.stdin.close()
        streams = selectors.DefaultSelector()
        streams.register(process.stdout, selectors.EVENT_READ, "stdout")
        streams.register(process.stderr, selectors.EVENT_READ, "stderr")
        output = {"stdout": bytearray(), "stderr": bytearray()}; deadline = time.monotonic() + 60
        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill(); process.wait(timeout=10); raise Failure("command_timeout")
            for key, _ in streams.select(remaining):
                chunk = key.fileobj.read1(8192)
                if not chunk:
                    streams.unregister(key.fileobj); continue
                output[key.data].extend(chunk)
                if len(output[key.data]) > LIMIT:
                    process.kill(); process.wait(timeout=10); raise Failure("command_output_limit")
        returncode = process.wait(timeout=10)
        completed = subprocess.CompletedProcess(argv, returncode, bytes(output["stdout"]), bytes(output["stderr"]))
    except (OSError, subprocess.TimeoutExpired) as error:
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=10)
        raise Failure("command_unavailable") from error
    return completed


def initialize_fresh_home(binary: Path, home: Path, env: dict[str, str]) -> None:
    if not home.is_dir() or home.is_symlink() or any(home.iterdir()):
        raise Failure("init_home_not_fresh")
    completed = command([str(binary), "init", "--non-interactive", "--cli", "--accept-license",
                         "--operator-id", "converted-relink-canary", "--provider", "skip"], env)
    if completed.returncode != 0:
        raise Failure("init_failed")
    key = home / "wal" / "master.key"
    if not regular(key) or key.stat().st_size != 32 or key.stat().st_mode & 0o077:
        raise Failure("init_identity_invalid")


def write_source(path: Path) -> None:
    # This is OpenClaw custody provenance only.  The public NEOTH home remains
    # first-use and receives no hand-written configuration or restore seed.
    path.write_text("channels:\n  imessage:\n    accounts:\n      personal:\n        cliPath: /usr/bin/imsg\n", encoding="utf-8")
    os.chmod(path, 0o600)


class LoopbackBlueBubbles:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: list[str] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _handler(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                split = urlsplit(self.path)
                query = parse_qs(split.query, keep_blank_values=True)
                valid_password = query == {"password": [PASSWORD]}
                decoded_path = unquote(split.path)
                if decoded_path == "/api/v1/ping" and valid_password:
                    parent.record("ping")
                    self.reply(200, {"status": 200})
                elif decoded_path == "/api/v1/chat/" + TARGET and split.path.count("/") == 4 and valid_password:
                    parent.record("target")
                    self.reply(200, {"status": 200, "data": {"guid": TARGET}})
                elif split.path.startswith("/api/v1/chat/") and valid_password:
                    parent.record("wrong_target")
                    self.reply(404, {"status": 404})
                else:
                    parent.record("unexpected_get")
                    self.reply(404, {"status": 404})

            def do_POST(self) -> None:
                parent.record("post")
                self.reply(405, {"status": 405})

            def reply(self, status: int, value: dict) -> None:
                body = json.dumps(value, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler

    def record(self, event: str) -> None:
        with self.lock:
            self.events.append(event)

    def start(self) -> int:
        self.thread.start()
        return int(self.server.server_address[1])

    def stop(self) -> bool:
        try:
            self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=10)
            return not self.thread.is_alive()
        except Exception:
            return False

    def counts(self) -> dict[str, int]:
        with self.lock:
            return {event: self.events.count(event) for event in ("ping", "target", "wrong_target", "post", "unexpected_get")}


def envelope(port: int) -> bytes:
    return json.dumps({"schema_version": 1, "channel": "imessage_bluebubbles", "fields": {
        "url": f"http://127.0.0.1:{port}", "password": PASSWORD,
        "allowed_sender": "+491701234567", "channels_csv": TARGET,
    }}, separators=(",", ":")).encode()


def relink_argv(binary: Path, source: Path, target: str) -> list[str]:
    return [str(binary), "--output", "json", "channel", "relink-openclaw", "imessage_bluebubbles",
            "--config", str(source), "--source-account", "personal", "--target", target]


def no_duplicate_object(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def one_json(stdout: bytes) -> dict:
    try:
        value = json.loads(stdout, object_pairs_hook=no_duplicate_object)
    except Exception as error:
        raise Failure("cli_json_invalid") from error
    if not isinstance(value, dict):
        raise Failure("cli_json_invalid")
    return value


def validate_output(value: dict, *, already_ready: bool, expected_id: str | None = None) -> str:
    required = {"channel", "account", "relink_id", "state", "already_ready", "reload_requested"}
    if set(value) != required or value.get("channel") != "imessage_bluebubbles" or value.get("account") != "default":
        raise Failure("cli_schema_invalid")
    identity = value.get("relink_id")
    if value.get("state") != "ready" or value.get("already_ready") is not already_ready or value.get("reload_requested") is not True:
        raise Failure("cli_state_invalid")
    if not isinstance(identity, str) or not SHA256.fullmatch(identity):
        raise Failure("cli_identity_invalid")
    if expected_id is not None and identity != expected_id:
        raise Failure("cli_identity_changed")
    return identity


def load_json(path: Path, failure: str) -> dict:
    if not regular(path) or path.stat().st_size > LIMIT:
        raise Failure(failure)
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=no_duplicate_object)
    except Exception as error:
        raise Failure(failure) from error
    if not isinstance(value, dict):
        raise Failure(failure)
    return value


def require_ready_publication(home: Path, relink_id: str, expected: dict[str, str]) -> dict[str, bytes]:
    files = {name: home / name for name in DURABLE_NAMES}
    if any(not regular(path) for path in files.values()) or not regular(home / RELOAD_SENTINEL):
        raise Failure("ready_publication_missing")
    if not files["credentials.yaml"].read_bytes().startswith(b"NEOTH_CONF_ENCv1\n"):
        raise Failure("credentials_not_encrypted")
    routing = load_json(files["channel_routing.json"], "routing_invalid")
    destinations = routing.get("destinations")
    if not isinstance(destinations, dict) or destinations.get("imessage_chat_guid") != TARGET:
        raise Failure("routing_target_invalid")
    index = load_json(files["channel_relinks.json"], "relink_index_invalid")
    pending = index.get("pending")
    destination = {"channel_id": "imessage_bluebubbles", "account_id": "default"}
    matching = [row for row in pending if isinstance(row, dict) and row.get("destination") == destination] if isinstance(pending, list) else []
    if index.get("schema_version") != 1 or len(matching) != 1:
        raise Failure("relink_ready_invalid")
    entry = matching[0]
    material = entry.get("bound_material_sha256")
    if entry.get("id") != relink_id or entry.get("state") != "ready" or entry.get("completion_request_material_sha256") != material or material != expected["request_material_sha256"]:
        raise Failure("relink_ready_invalid")
    transaction = load_json(files[".channel-relink-imessage.transaction.json"], "relink_transaction_invalid")
    current_pair = pair_v1(file_snapshot(home / "freedom.yaml"), file_snapshot(home / "credentials.yaml"))
    current_routing = sha256(file_snapshot(home / "channel_routing.json")[1])
    expected_transaction = {name: expected[name] for name in ("pair_before_sha256", "routing_before_sha256", "target_sha256", "request_material_sha256")}
    expected_transaction.update({"pair_after_sha256": current_pair, "routing_after_sha256": current_routing})
    if transaction.get("version") != 1 or transaction.get("pending_id") != relink_id or transaction.get("destination") != destination or transaction.get("phase") != "routing_committed" or any(transaction.get(name) != value for name, value in expected_transaction.items()):
        raise Failure("relink_transaction_invalid")
    return {name: path.read_bytes() for name, path in files.items()}


def require_wrong_target_pending(home: Path) -> dict[str, bool]:
    flags = {"credentials_absent": not (home / "credentials.yaml").exists(),
             "routing_absent": not (home / "channel_routing.json").exists(),
             "reload_absent": not (home / RELOAD_SENTINEL).exists(),
             "ready_transaction_absent": not (home / ".channel-relink-imessage.transaction.json").exists()}
    index = load_json(home / "channel_relinks.json", "wrong_target_pending_missing")
    rows = index.get("pending")
    flags["pending_record_present"] = isinstance(rows, list) and any(isinstance(row, dict) and row.get("state") == "pending" for row in rows)
    if not all(flags.values()):
        raise Failure("wrong_target_publication_invalid")
    return flags


def source_bindings(workflow: Path) -> dict[str, str]:
    paths = {
        "packaging/converted_channel_relink_product_canary.py": Path(__file__),
        "packaging/tests/test_converted_channel_relink_product_canary.py": Path("packaging/tests/test_converted_channel_relink_product_canary.py"),
        ".github/workflows/gchat-live-regressions.yml": workflow,
        "SRC/neothd/src/cli/channel_relink.rs": Path("SRC/neothd/src/cli/channel_relink.rs"),
        "SRC/neothd/src/cli/channel.rs": Path("SRC/neothd/src/cli/channel.rs"), "SRC/neothd/src/cli/mod.rs": Path("SRC/neothd/src/cli/mod.rs"),
        "SRC/neothd/src/cli/channel/converted_relink.rs": Path("SRC/neothd/src/cli/channel/converted_relink.rs"),
        "SRC/neothd/src/channels/relink.rs": Path("SRC/neothd/src/channels/relink.rs"), "SRC/neothd/src/channels/routing.rs": Path("SRC/neothd/src/channels/routing.rs"),
        "SRC/neothd/src/config/credentials.rs": Path("SRC/neothd/src/config/credentials.rs"), "SRC/neothd/src/channels/imessage_bluebubbles.rs": Path("SRC/neothd/src/channels/imessage_bluebubbles.rs"),
        "SRC/neothd/src/cli/reload.rs": Path("SRC/neothd/src/cli/reload.rs"), "SRC/neothd/src/cli/init.rs": Path("SRC/neothd/src/cli/init.rs"),
        "SRC/neothd/src/cli/init/first_install_identity.rs": Path("SRC/neothd/src/cli/init/first_install_identity.rs"), "SRC/neothd/src/cli/init/io.rs": Path("SRC/neothd/src/cli/init/io.rs"),
        "SRC/neothd/src/cli/init/steps_identity.rs": Path("SRC/neothd/src/cli/init/steps_identity.rs"), "SRC/neothd/src/cli/init/steps_provider.rs": Path("SRC/neothd/src/cli/init/steps_provider.rs"),
        "SRC/neoth-openclaw-custody/src/lib.rs": Path("SRC/neoth-openclaw-custody/src/lib.rs"), "SRC/neoth-openclaw-custody/src/pinned_inventory.rs": Path("SRC/neoth-openclaw-custody/src/pinned_inventory.rs"), "SRC/neoth-openclaw-custody/src/pinned_schema.rs": Path("SRC/neoth-openclaw-custody/src/pinned_schema.rs"),
        "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_v1.json": Path("SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_v1.json"), "SRC/neoth-openclaw-custody/src/fixtures/openclaw_upstream_evidence_v1.json": Path("SRC/neoth-openclaw-custody/src/fixtures/openclaw_upstream_evidence_v1.json"), "SRC/neoth-openclaw-custody/src/fixtures/pinned_channel_inventory_v1.json": Path("SRC/neoth-openclaw-custody/src/fixtures/pinned_channel_inventory_v1.json"),
        "SRC/neoth-openclaw-custody/Cargo.toml": Path("SRC/neoth-openclaw-custody/Cargo.toml"),
        "SRC/neothd/Cargo.toml": Path("SRC/neothd/Cargo.toml"), "SRC/Cargo.lock": Path("SRC/Cargo.lock"),
    }
    if any(not regular(path) for path in paths.values()):
        raise Failure("source_provenance_missing")
    return {name: digest(path) for name, path in paths.items()}


def cleanup_owned(root: Path, home: Path, source: Path, evidence: Path) -> dict[str, bool]:
    flags: dict[str, bool] = {}
    for name, path in {"home_removed": home, "wrong_target_home_removed": root / "wrong-target-home", "source_removed": source}.items():
        try:
            if not contained(path, root) or path == root or path.is_symlink():
                flags[name] = False
            elif path.exists():
                shutil.rmtree(path) if path.is_dir() else path.unlink()
                flags[name] = not path.exists()
            else:
                flags[name] = True
        except Exception:
            flags[name] = False
    flags["evidence_retained"] = contained(evidence, root) and evidence.is_dir() and not evidence.is_symlink()
    return flags


def execute(binary: Path, root: Path, home: Path, source: Path, evidence: Path, workflow: Path) -> dict:
    if not regular(binary) or not regular(workflow):
        raise Failure("provenance_input_invalid")
    home.mkdir(); evidence.mkdir(parents=True); write_source(source)
    env = dict(os.environ); env["NEOTH_HOME"] = str(home)
    initialize_fresh_home(binary, home, env)
    server = LoopbackBlueBubbles(); port = server.start()
    try:
        expected = expected_context(home, port)
        wrong_home = root / "wrong-target-home"; wrong_home.mkdir()
        wrong_env = dict(os.environ); wrong_env["NEOTH_HOME"] = str(wrong_home)
        initialize_fresh_home(binary, wrong_home, wrong_env)
        wrong = command(relink_argv(binary, source, WRONG_TARGET), wrong_env, envelope(port))
        if wrong.returncode == 0 or PASSWORD in wrong.stdout.decode("utf-8", "replace") or PASSWORD in wrong.stderr.decode("utf-8", "replace"):
            raise Failure("wrong_target_command_invalid")
        wrong_flags = require_wrong_target_pending(wrong_home)
        first = command(relink_argv(binary, source, TARGET), env, envelope(port))
        if first.returncode != 0 or PASSWORD in first.stdout.decode("utf-8", "replace") or PASSWORD in first.stderr.decode("utf-8", "replace"):
            raise Failure("first_command_failed")
        relink_id = validate_output(one_json(first.stdout), already_ready=False)
        durable = require_ready_publication(home, relink_id, expected)
        if any(PASSWORD.encode() in raw for raw in (durable["channel_relinks.json"], durable[".channel-relink-imessage.transaction.json"])):
            raise Failure("secret_leaked_to_relink_records")
        before = {name: (raw, hashlib.sha256(raw).hexdigest()) for name, raw in durable.items()}
        retry = command(relink_argv(binary, source, TARGET), env, envelope(port))
        if retry.returncode != 0 or PASSWORD in retry.stdout.decode("utf-8", "replace") or PASSWORD in retry.stderr.decode("utf-8", "replace"):
            raise Failure("retry_command_failed")
        validate_output(one_json(retry.stdout), already_ready=True, expected_id=relink_id)
        after = require_ready_publication(home, relink_id, expected)
        if any(after[name] != raw for name, (raw, _hash) in before.items()):
            raise Failure("retry_rewrote_durable_bytes")
        counts = server.counts()
        if counts != {"ping": 3, "target": 2, "wrong_target": 1, "post": 0, "unexpected_get": 0}:
            raise Failure("loopback_request_contract_invalid")
        proof = {"sha256": {name: value[1] for name, value in before.items()}, "relink_id": relink_id,
                 "first": {"already_ready": False, "reload_requested": True},
                 "retry": {"already_ready": True, "reload_requested": True},
                 "wrong_target": wrong_flags, "requests": counts, "expected_bindings": expected}
        (evidence / "receipt-summary.json").write_text(json.dumps(proof, sort_keys=True), encoding="utf-8")
        return {"schema_version": 1, "source_head": os.environ["GITHUB_SHA"], "local_external_provider": False,
                "initial_setup": {"method": "neoth_init_cli_license_provider_skip", "created_without_restore": True},
                "relink": proof, "sha256": {"binary": digest(binary), "openclaw_source_fixture": digest(source), **source_bindings(workflow)}}
    finally:
        if not server.stop():
            raise Failure("loopback_cleanup_failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True); parser.add_argument("--root", required=True)
    parser.add_argument("--home", required=True); parser.add_argument("--source", required=True)
    parser.add_argument("--evidence-dir", required=True); parser.add_argument("--receipt", required=True)
    parser.add_argument("--workflow", required=True)
    args = parser.parse_args()
    binary, root, home, source = Path(args.binary).resolve(), Path(args.root).resolve(), Path(args.home).resolve(), Path(args.source).resolve()
    evidence, receipt, workflow = Path(args.evidence_dir).resolve(), Path(args.receipt).resolve(), Path(args.workflow).resolve()
    require_hosted(root, home, source, evidence, receipt); receipt.parent.mkdir(parents=True)
    if workflow != Path(".github/workflows/gchat-live-regressions.yml").resolve():
        raise Failure("workflow_binding_invalid")
    bindings = source_bindings(workflow)
    state = {"stage": "prepare"}; result: dict | None = None; error: str | None = None
    try:
        state["stage"] = "public_cli_lifecycle"; result = execute(binary, root, home, source, evidence, workflow)
    except Failure as caught:
        error = str(caught)
    except Exception:
        error = "unexpected_failure"
    cleanup = cleanup_owned(root, home, source, evidence)
    payload = {"schema_version": 1, "source_head": os.environ.get("GITHUB_SHA", ""),
               "outcome": "passed" if result is not None and all(cleanup.values()) else "failed",
               "stage": "cleanup" if result is not None else state["stage"], "failure": error,
               "cleanup": cleanup, "local_external_provider": False, "source_bindings": bindings}
    if result is not None:
        payload.update(result)
    encoded = json.dumps(payload, sort_keys=True)
    if PASSWORD in encoded:
        raise Failure("receipt_secret_leak")
    receipt.write_text(encoded, encoding="utf-8")
    return 0 if payload["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
