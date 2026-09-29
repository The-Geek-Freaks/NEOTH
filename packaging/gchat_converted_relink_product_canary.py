#!/usr/bin/env python3
"""Hosted public-CLI Google Chat converted-relink canary with loopback OAuth."""
from __future__ import annotations

import argparse
import base64
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
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

LIMIT = 256 * 1024
EMAIL = "bot@neoth-canary.invalid"
SUBSCRIPTION = "projects/neoth-canary/subscriptions/relink"
ALLOWED_SENDER = "users/neoth-canary"
SPACE = "spaces/AAAA_NEOTH_CANARY"
WRONG_SPACE = "spaces/AAAA_WRONG"
RELOAD = ".reload-requested"
# The relink CLI accepts google_chat; private envelopes, output, persisted
# ChannelRef values and material commitments use ChannelKind's wire ID gchat.
DESTINATION = {"channel_id": "gchat", "account_id": "default"}
DURABLE = ("credentials.yaml", "freedom.yaml", "channel_routing.json", "channel_relinks.json", ".channel-relink-google-chat.transaction.json")
SHA256 = re.compile(r"[0-9a-f]{64}")
REFUSAL_STAGES = frozenset(("wrong_target", "wrong_returned_space"))
REFUSAL_COUNTERS = ("token", "subscription", "space", "wrong_space", "bad_token", "bad_bearer", "forbidden_post", "unexpected_get")
REFUSAL_DIAGNOSTIC_STAGES = frozenset(("candidate", "gchat_prepare", "gchat_constructor", "gchat_bearer", "gchat_token", "gchat_subscription", "gchat_space", "gchat_probe", "unknown"))
REFUSAL_DIAGNOSTIC_REASONS = frozenset((
    "candidate_service_account_file",
    "candidate_subscription_resource",
    "canary_origin_invalid",
    "canary_origin_not_unicode",
    "canary_synthetic_key_or_token_uri",
    "constructor_subscription_resource",
    "subscription_forbidden",
    "subscription_http_status",
    "subscription_malformed_json",
    "subscription_identity_mismatch",
    "space_forbidden",
    "space_http_status",
    "space_malformed_json",
    "space_identity_mismatch",
    "constructor_feature_disabled",
    "constructor_token_uri",
    "constructor_key_read",
    "constructor_key_json",
    "constructor_http_client",
    "bearer_rsa_pem",
    "bearer_claims",
    "bearer_jwt_sign",
    "token_post",
    "token_body",
    "token_status",
    "token_json",
    "token_access_token",
    "subscription_request",
    "subscription_body",
    "space_path",
    "space_request",
    "space_body",
    "prepare_candidate",
    "prepare_material",
    "prepare_routing",
    "probe_execution",
    "unknown",
))
# Fixed codes emitted only by the gchat-product-canary feature. They never
# contain provider detail, endpoint text, key data, token material, or stderr.
GCHAT_CANARY_DIAGNOSTIC_CODES = {
    "prepare-candidate": ("gchat_prepare", "prepare_candidate"),
    "prepare-material": ("gchat_prepare", "prepare_material"),
    "prepare-routing": ("gchat_prepare", "prepare_routing"),
    "probe-execution": ("gchat_prepare", "probe_execution"),
    "constructor-origin-not-unicode": ("gchat_constructor", "canary_origin_not_unicode"),
    "constructor-origin-invalid": ("gchat_constructor", "canary_origin_invalid"),
    "constructor-feature": ("gchat_constructor", "constructor_feature_disabled"),
    "constructor-identity": ("gchat_constructor", "canary_synthetic_key_or_token_uri"),
    "constructor-token-uri": ("gchat_constructor", "constructor_token_uri"),
    "constructor-subscription": ("gchat_constructor", "constructor_subscription_resource"),
    "constructor-key-read": ("gchat_constructor", "constructor_key_read"),
    "constructor-key-json": ("gchat_constructor", "constructor_key_json"),
    "constructor-http-client": ("gchat_constructor", "constructor_http_client"),
    "bearer-rsa-pem": ("gchat_bearer", "bearer_rsa_pem"),
    "bearer-claims": ("gchat_bearer", "bearer_claims"),
    "bearer-jwt-sign": ("gchat_bearer", "bearer_jwt_sign"),
    "token-post": ("gchat_token", "token_post"),
    "token-body": ("gchat_token", "token_body"),
    "token-status": ("gchat_token", "token_status"),
    "token-json": ("gchat_token", "token_json"),
    "token-access-token": ("gchat_token", "token_access_token"),
    "subscription-request": ("gchat_subscription", "subscription_request"),
    "subscription-body": ("gchat_subscription", "subscription_body"),
    "subscription-forbidden": ("gchat_subscription", "subscription_forbidden"),
    "subscription-status": ("gchat_subscription", "subscription_http_status"),
    "subscription-json": ("gchat_subscription", "subscription_malformed_json"),
    "subscription-identity": ("gchat_subscription", "subscription_identity_mismatch"),
    "space-path": ("gchat_space", "space_path"),
    "space-request": ("gchat_space", "space_request"),
    "space-body": ("gchat_space", "space_body"),
    "space-forbidden": ("gchat_space", "space_forbidden"),
    "space-status": ("gchat_space", "space_http_status"),
    "space-json": ("gchat_space", "space_malformed_json"),
    "space-identity": ("gchat_space", "space_identity_mismatch"),
    "unknown": ("unknown", "unknown"),
}
REFUSAL_OUTPUT_HASH_DOMAIN = b"neoth-gchat-refusal-output-v1\0"
REFUSAL_ERROR_MARKERS = (
    ("Google Chat relink lacks service-account file", "candidate", "candidate_service_account_file"),
    ("subscription must be the full resource name", "candidate", "candidate_subscription_resource"),
    ("NEOTH_GCHAT_CANARY_ORIGIN is not Unicode", "gchat_constructor", "canary_origin_not_unicode"),
    ("NEOTH_GCHAT_CANARY_ORIGIN must be canonical loopback http origin with explicit port", "gchat_constructor", "canary_origin_invalid"),
    ("NEOTH_GCHAT_CANARY_ORIGIN must use canonical loopback spelling", "gchat_constructor", "canary_origin_invalid"),
    ("gchat canary key must use synthetic identity and canonical loopback token URI", "gchat_constructor", "canary_synthetic_key_or_token_uri"),
    ("gchat subscription must be `projects/<project>/subscriptions/<subscription>`", "gchat_constructor", "constructor_subscription_resource"),
    ("Google Chat service account cannot read the Pub/Sub subscription", "gchat_probe", "subscription_forbidden"),
    ("Google Chat subscription probe returned HTTP ", "gchat_probe", "subscription_http_status"),
    ("Google Chat subscription probe returned malformed JSON", "gchat_probe", "subscription_malformed_json"),
    ("Google Chat subscription probe returned `", "gchat_probe", "subscription_identity_mismatch"),
    ("Google Chat service account cannot read the configured space", "gchat_probe", "space_forbidden"),
    ("Google Chat space target probe returned HTTP ", "gchat_probe", "space_http_status"),
    ("Google Chat space target probe returned malformed JSON", "gchat_probe", "space_malformed_json"),
    ("Google Chat space target probe returned a different space", "gchat_probe", "space_identity_mismatch"),
)


class Failure(RuntimeError):
    def __init__(self, code: str, refusal_probe: dict | None = None) -> None:
        super().__init__(code)
        self.refusal_probe = refusal_probe


@dataclass(frozen=True)
class ExpectedReceipt:
    material_sha256: str
    pair_before_sha256: str
    routing_before_sha256: str
    pair_after_sha256: str
    routing_after_sha256: str
    source_sha256: str


def regular(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
    except OSError:
        return False


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def refusal_output_hash(process: subprocess.CompletedProcess[bytes]) -> str:
    stdout = process.stdout if isinstance(process.stdout, bytes) else b""
    stderr = process.stderr if isinstance(process.stderr, bytes) else b""
    return sha256_bytes(REFUSAL_OUTPUT_HASH_DOMAIN + stdout + b"\0" + stderr)


def refusal_failure_diagnostic(process: subprocess.CompletedProcess[bytes]) -> dict:
    """Classify bounded output without ever retaining its untrusted text."""
    output = b"\n".join(value for value in (process.stdout, process.stderr) if isinstance(value, bytes))
    rendered = output.decode("utf-8", "replace")
    stage, reason = "unknown", "unknown"
    match = re.search(r"gchat canary exact target (?:probe|preparation) diagnostic: ([a-z-]+)", rendered)
    if match is not None:
        stage, reason = GCHAT_CANARY_DIAGNOSTIC_CODES.get(match.group(1), ("unknown", "unknown"))
    else:
        for marker, candidate_stage, candidate_reason in REFUSAL_ERROR_MARKERS:
            if marker in rendered:
                stage, reason = candidate_stage, candidate_reason
                break
    return {
        "stage": stage,
        "reason": reason,
        "returncode": process.returncode if type(process.returncode) is int else -1,
        "output_sha256": refusal_output_hash(process),
    }


def refusal_probe_evidence(stage: str, counts: dict[str, int], process: subprocess.CompletedProcess[bytes]) -> dict:
    """A fixed, redacted receipt fragment; it can never carry request data."""
    if stage not in REFUSAL_STAGES or set(counts) != set(REFUSAL_COUNTERS):
        raise Failure("refusal_evidence_invalid")
    if any(type(counts[name]) is not int or counts[name] < 0 for name in REFUSAL_COUNTERS):
        raise Failure("refusal_evidence_invalid")
    diagnostic = refusal_failure_diagnostic(process)
    if diagnostic["stage"] not in REFUSAL_DIAGNOSTIC_STAGES or diagnostic["reason"] not in REFUSAL_DIAGNOSTIC_REASONS:
        raise Failure("refusal_evidence_invalid")
    return {
        "stage": stage,
        "counters": {name: counts[name] for name in REFUSAL_COUNTERS},
        "failure": diagnostic,
    }


def validate_receipt_redaction(encoded: str) -> None:
    if any(marker in encoded for marker in (EMAIL, "BEGIN PRIVATE KEY", "http://", "https://", "exception")):
        raise Failure("receipt_secret_leak")


def contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


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
    except Failure:
        raise
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


def initialize(binary: Path, home: Path, env: dict[str, str]) -> None:
    if not home.is_dir() or home.is_symlink() or any(home.iterdir()):
        raise Failure("init_home_not_fresh")
    arguments = [str(binary), "init", "--non-interactive", "--cli", "--accept-license", "--operator-id", "gchat-relink-canary", "--provider", "skip"]
    if command(arguments, env).returncode:
        raise Failure("init_failed")
    master = home / "wal" / "master.key"
    if not regular(master) or master.stat().st_size != 32 or master.stat().st_mode & 0o077:
        raise Failure("init_identity_invalid")


def enable_encryption(home: Path) -> None:
    config = home / "freedom.yaml"
    if not regular(config) or not regular(home / "wal" / "master.key"):
        raise Failure("encryption_setup_input_invalid")
    raw = config.read_bytes()
    old = b"wal:\n  compression: none\n  encryption: none\n"
    new = b"wal:\n  compression: none\n  encryption: aes256_gcm_siv\n"
    if b"wal:" not in raw:
        raw += b"" if raw.endswith(b"\n") else b"\n"
        raw += new
    elif raw.count(old) == 1:
        raw = raw.replace(old, new, 1)
    else:
        raise Failure("encryption_setup_policy_invalid")
    config.write_bytes(raw)


def source(path: Path) -> None:
    if path.name != "openclaw.json" or path.exists() or path.is_symlink():
        raise Failure("source_path_invalid")
    path.write_text('{"channels":{"googlechat":{"accounts":{"work":{"serviceAccount":{"source":"env","provider":"default","id":"CANARY"}}}}}}\n', encoding="utf-8")
    os.chmod(path, 0o600)


def b64(data: bytes) -> bytes:
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def make_key(root: Path, origin: str) -> Path:
    private = root / "canary-rsa.pem"
    public = root / "canary-rsa.pub"
    key = root / "service-account.json"
    if command(["openssl", "genrsa", "-out", str(private), "2048"], dict(os.environ)).returncode:
        raise Failure("rsa_generation_failed")
    if command(["openssl", "rsa", "-in", str(private), "-pubout", "-out", str(public)], dict(os.environ)).returncode:
        raise Failure("rsa_generation_failed")
    key.write_text(json.dumps({"type": "service_account", "client_email": EMAIL, "private_key": private.read_text(), "token_uri": origin + "/token"}), encoding="utf-8")
    os.chmod(key, 0o600)
    return public


def envelope(key: Path) -> bytes:
    fields = {"url": str(key), "server": SUBSCRIPTION, "allowed_sender": ALLOWED_SENDER}
    return json.dumps({"schema_version": 1, "channel": "gchat", "fields": fields}, separators=(",", ":")).encode()


def argv(binary: Path, source_path: Path, target: str) -> list[str]:
    return [str(binary), "--output", "json", "channel", "relink-openclaw", "google_chat", "--config", str(source_path), "--source-account", "work", "--target", target]


def one_json(raw: bytes) -> dict:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except Exception as error:
        raise Failure("cli_json_invalid") from error
    if not isinstance(value, dict):
        raise Failure("cli_json_invalid")
    return value


def read_json(path: Path, failure: str) -> dict:
    if not regular(path):
        raise Failure(failure)
    try:
        return one_json(path.read_bytes())
    except Failure as error:
        raise Failure(failure) from error


def validate_output(value: dict, already_ready: bool, expected: str | None = None) -> str:
    required = {"channel", "account", "relink_id", "state", "already_ready", "reload_requested"}
    if set(value) != required or value.get("channel") != "gchat" or value.get("account") != "default":
        raise Failure("cli_schema_invalid")
    identity = value.get("relink_id")
    if value.get("state") != "ready" or value.get("already_ready") is not already_ready or value.get("reload_requested") is not True or not isinstance(identity, str) or not SHA256.fullmatch(identity):
        raise Failure("cli_state_invalid")
    if expected is not None and identity != expected:
        raise Failure("cli_identity_changed")
    return identity


class FakeGoogle:
    def __init__(self, public: Path) -> None:
        self.public = public
        self.lock = threading.Lock()
        self.events: list[str] = []
        self.wrong_return = False
        self.started = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def handler(self):
        parent = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                return
            def record(self, name: str) -> None:
                with parent.lock:
                    parent.events.append(name)
            def reply(self, status: int, value: dict) -> None:
                raw = json.dumps(value, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def do_POST(self) -> None:
                if self.path != "/token":
                    self.record("forbidden_post")
                    self.reply(405, {})
                    return
                signature_path = parent.public.parent / "jwt-signature"
                try:
                    form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode(), keep_blank_values=True)
                    head, claims, signature = form.get("assertion", [""])[0].split(".")
                    claim = json.loads(b64(claims.encode()))
                    signature_path.write_bytes(b64(signature.encode()))
                    verified = command(["openssl", "dgst", "-sha256", "-verify", str(parent.public), "-signature", str(signature_path), "-"], dict(os.environ), f"{head}.{claims}".encode()).returncode == 0
                except Exception:
                    verified = False
                    claim = {}
                    form = {}
                finally:
                    signature_path.unlink(missing_ok=True)
                if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"] or claim.get("iss") != EMAIL or claim.get("aud") != f"http://127.0.0.1:{parent.port}/token" or not verified:
                    self.record("bad_token")
                    self.reply(400, {})
                    return
                self.record("token")
                self.reply(200, {"access_token": "canary-access-token", "expires_in": 3600})
            def do_GET(self) -> None:
                if self.headers.get("Authorization") != "Bearer canary-access-token":
                    self.record("bad_bearer")
                    self.reply(401, {})
                elif self.path == "/v1/" + SUBSCRIPTION:
                    self.record("subscription")
                    self.reply(200, {"name": SUBSCRIPTION})
                elif self.path == "/v1/" + SPACE:
                    self.record("space")
                    self.reply(200, {"name": WRONG_SPACE if parent.wrong_return else SPACE})
                elif self.path.startswith("/v1/spaces/"):
                    self.record("wrong_space")
                    self.reply(404, {})
                else:
                    self.record("unexpected_get")
                    self.reply(404, {})
        return Handler
    @property
    def port(self) -> int:
        return int(self.server.server_address[1])
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
            return {name: self.events.count(name) for name in ("token", "subscription", "space", "wrong_space", "bad_token", "bad_bearer", "forbidden_post", "unexpected_get")}


def snapshot(path: Path) -> tuple[bool, bytes]:
    if path.is_symlink():
        raise Failure("snapshot_invalid")
    return path.exists(), path.read_bytes() if path.exists() else b""


def pair_commitment(home: Path) -> str:
    value = hashlib.sha256(b"neoth-converted-relink-pair-v1\0")
    for name in ("freedom.yaml", "credentials.yaml"):
        present, raw = snapshot(home / name)
        value.update(name.encode() + b"\0")
        value.update(b"\x01" + len(raw).to_bytes(8, "little") + raw if present else b"\0")
    return value.hexdigest()


def material_commitment(key: Path, target: str) -> str:
    if not regular(key):
        raise Failure("service_account_missing")
    value = hashlib.sha256(b"neoth-converted-relink-material-v1\0")
    value.update(b"gchat\0")
    value.update(target.encode())
    value.update(b"\0")
    for field in (key.read_bytes(), SUBSCRIPTION.encode(), ALLOWED_SENDER.encode()):
        value.update(len(field).to_bytes(8, "little"))
        value.update(field)
    return value.hexdigest()


def expected_before(home: Path, key: Path, source_path: Path) -> ExpectedReceipt:
    return ExpectedReceipt(material_commitment(key, SPACE), pair_commitment(home), sha256_bytes(snapshot(home / "channel_routing.json")[1]), "", "", digest(source_path))


def expected_after(before: ExpectedReceipt, home: Path) -> ExpectedReceipt:
    return ExpectedReceipt(before.material_sha256, before.pair_before_sha256, before.routing_before_sha256, pair_commitment(home), sha256_bytes((home / "channel_routing.json").read_bytes()), before.source_sha256)


def require_pending_unchanged(home: Path, before: dict[str, tuple[bool, bytes]], stage: str, required_calls: int, expected_space_event: str, server: FakeGoogle, refusal_result: subprocess.CompletedProcess[bytes]) -> dict:
    if any(snapshot(home / name) != value for name, value in before.items()):
        raise Failure("refusal_mutated_existing_state")
    if (home / RELOAD).exists() or (home / ".channel-relink-google-chat.transaction.json").exists():
        raise Failure("refusal_published_state")
    index = read_json(home / "channel_relinks.json", "pending_index_invalid")
    pending = index.get("pending")
    matches = [item for item in pending if isinstance(item, dict) and item.get("destination") == DESTINATION] if isinstance(pending, list) else []
    if len(matches) != 1 or matches[0].get("state") != "pending":
        raise Failure("pending_identity_invalid")
    counts = server.counts()
    if counts["token"] < required_calls or counts["subscription"] < required_calls or counts[expected_space_event] < 1:
        raise Failure("refusal_probe_contract_invalid", refusal_probe_evidence(stage, counts, refusal_result))
    return {"pending_id": matches[0].get("id"), "source_set_sha256": matches[0].get("source_set_sha256")}


def ready_files(home: Path, identity: str, expected: ExpectedReceipt) -> dict[str, bytes]:
    paths = {name: home / name for name in DURABLE}
    if any(not regular(path) for path in paths.values()) or not regular(home / RELOAD):
        raise Failure("ready_publication_missing")
    if not paths["credentials.yaml"].read_bytes().startswith(b"NEOTH_CONF_ENCv1\n"):
        raise Failure("credentials_not_encrypted")
    route_raw = paths["channel_routing.json"].read_bytes()
    route = read_json(paths["channel_routing.json"], "routing_invalid")
    destinations = route.get("destinations")
    if not isinstance(destinations, dict) or destinations.get("gchat_space") != SPACE or "google_chat" in destinations:
        raise Failure("routing_target_invalid")
    index = read_json(paths["channel_relinks.json"], "relink_index_invalid")
    pending = index.get("pending")
    matches = [item for item in pending if isinstance(item, dict) and item.get("destination") == DESTINATION] if isinstance(pending, list) else []
    if len(matches) != 1:
        raise Failure("relink_index_identity_invalid")
    entry = matches[0]
    if entry.get("id") != identity or entry.get("state") != "ready" or entry.get("completion_request_material_sha256") != expected.material_sha256 or entry.get("bound_material_sha256") != expected.material_sha256 or not isinstance(entry.get("source_set_sha256"), str) or not SHA256.fullmatch(entry["source_set_sha256"]):
        raise Failure("ready_publication_invalid")
    if digest(home.parent / "openclaw.json") != expected.source_sha256:
        raise Failure("source_custody_changed")
    transaction = read_json(paths[".channel-relink-google-chat.transaction.json"], "relink_transaction_invalid")
    expected_transaction = {"version": 1, "pending_id": identity, "destination": DESTINATION, "target_sha256": sha256_bytes(SPACE.encode()), "request_material_sha256": expected.material_sha256, "pair_before_sha256": expected.pair_before_sha256, "routing_before_sha256": expected.routing_before_sha256, "pair_after_sha256": expected.pair_after_sha256, "routing_after_sha256": expected.routing_after_sha256, "phase": "routing_committed"}
    if set(transaction) != set(expected_transaction) or transaction != expected_transaction or pair_commitment(home) != expected.pair_after_sha256 or sha256_bytes(route_raw) != expected.routing_after_sha256:
        raise Failure("relink_transaction_invalid")
    return {name: path.read_bytes() for name, path in paths.items()}


def source_bindings(workflow: Path) -> dict[str, str]:
    relatives = (
        "packaging/gchat_converted_relink_product_canary.py",
        "packaging/tests/test_gchat_converted_relink_product_canary.py",
        ".github/workflows/gchat-live-regressions.yml",
        "SRC/Cargo.lock",
        "SRC/neothd/Cargo.toml",
        "SRC/neothd/src/cli/mod.rs",
        "SRC/neothd/src/cli/channel.rs",
        "SRC/neothd/src/cli/channel_relink.rs",
        "SRC/neothd/src/cli/channel/converted_relink.rs",
        "SRC/neothd/src/cli/init.rs",
        "SRC/neothd/src/cli/init/first_install_identity.rs",
        "SRC/neothd/src/cli/init/io.rs",
        "SRC/neothd/src/cli/init/steps_identity.rs",
        "SRC/neothd/src/cli/init/steps_provider.rs",
        "SRC/neothd/src/cli/reload.rs",
        "SRC/neothd/src/channels/relink.rs",
        "SRC/neothd/src/channels/routing.rs",
        "SRC/neothd/src/channels/gchat.rs",
        "SRC/neothd/src/channels/mod.rs",
        "SRC/neothd/src/channels/registry.rs",
        "SRC/neothd/src/config/credentials.rs",
        "SRC/neothd/src/config/wal.rs",
        "SRC/neothd/src/wal/master_key.rs",
        "SRC/neoth-openclaw-custody/Cargo.toml",
        "SRC/neoth-openclaw-custody/src/lib.rs",
        "SRC/neoth-openclaw-custody/src/pinned_inventory.rs",
        "SRC/neoth-openclaw-custody/src/pinned_schema.rs",
        "SRC/neoth-openclaw-custody/src/fixtures/pinned_channel_inventory_v1.json",
        "SRC/neoth-openclaw-custody/src/fixtures/openclaw_upstream_evidence_v1.json",
        "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_v1.json",
        "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_migration_policy_v1.json",
    )
    paths = {relative: Path(relative) for relative in relatives}
    if workflow.resolve() != paths[".github/workflows/gchat-live-regressions.yml"].resolve() or any(not regular(path) for path in paths.values()):
        raise Failure("source_provenance_missing")
    return {relative: digest(path) for relative, path in paths.items()}


def cleanup(root: Path, home: Path, source_path: Path, evidence: Path) -> dict[str, bool]:
    targets = {"home_removed": home, "wrong_home_removed": root / "wrong-home", "source_removed": source_path, "key_removed": root / "service-account.json", "private_key_removed": root / "canary-rsa.pem", "public_key_removed": root / "canary-rsa.pub", "jwt_signature_removed": root / "jwt-signature"}
    result = {}
    for name, path in targets.items():
        try:
            if not contained(path, root) or path.is_symlink():
                result[name] = False
            elif path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                result[name] = not path.exists()
            else:
                result[name] = True
        except OSError:
            result[name] = False
    result["evidence_retained"] = evidence.is_dir() and contained(evidence, root)
    return result


def execute(binary: Path, root: Path, home: Path, source_path: Path, evidence: Path, workflow: Path) -> dict:
    if not regular(binary):
        raise Failure("provenance_input_invalid")
    bindings = source_bindings(workflow)
    home.mkdir()
    evidence.mkdir()
    source(source_path)
    env = dict(os.environ)
    env["NEOTH_HOME"] = str(home)
    initialize(binary, home, env)
    enable_encryption(home)
    server = None
    try:
        server = FakeGoogle(root / "canary-rsa.pub")
        origin = f"http://127.0.0.1:{server.port}"
        server.public = make_key(root, origin)
        server.start()
        env["NEOTH_GCHAT_CANARY_ORIGIN"] = origin
        wrong = root / "wrong-home"
        wrong.mkdir()
        wrong_env = dict(env)
        wrong_env["NEOTH_HOME"] = str(wrong)
        initialize(binary, wrong, wrong_env)
        enable_encryption(wrong)
        wrong_before = {name: snapshot(wrong / name) for name in ("freedom.yaml", "wal/master.key", "credentials.yaml", "channel_routing.json")}
        wrong_result = command(argv(binary, source_path, WRONG_SPACE), wrong_env, envelope(root / "service-account.json"))
        if wrong_result.returncode == 0:
            raise Failure("wrong_target_accepted")
        wrong_pending = require_pending_unchanged(wrong, wrong_before, "wrong_target", 1, "wrong_space", server, wrong_result)
        returned_before = {name: snapshot(home / name) for name in ("freedom.yaml", "wal/master.key", "credentials.yaml", "channel_routing.json")}
        server.wrong_return = True
        try:
            returned = command(argv(binary, source_path, SPACE), env, envelope(root / "service-account.json"))
        finally:
            server.wrong_return = False
        if returned.returncode == 0:
            raise Failure("wrong_returned_space_accepted")
        returned_pending = require_pending_unchanged(home, returned_before, "wrong_returned_space", 2, "space", server, returned)
        before = expected_before(home, root / "service-account.json", source_path)
        first = command(argv(binary, source_path, SPACE), env, envelope(root / "service-account.json"))
        if first.returncode:
            raise Failure("first_command_failed")
        identity = validate_output(one_json(first.stdout), False)
        expected = expected_after(before, home)
        durable_before_retry = ready_files(home, identity, expected)
        retry = command(argv(binary, source_path, SPACE), env, envelope(root / "service-account.json"))
        if retry.returncode:
            raise Failure("retry_command_failed")
        validate_output(one_json(retry.stdout), True, identity)
        durable_after_retry = ready_files(home, identity, expected)
        if durable_before_retry != durable_after_retry:
            raise Failure("retry_rewrote_durable_bytes")
        counts = server.counts()
        if counts["wrong_space"] < 1 or counts["space"] < 3 or counts["subscription"] < 4 or counts["token"] < 4 or counts["forbidden_post"] or counts["unexpected_get"] or counts["bad_token"] or counts["bad_bearer"]:
            raise Failure("loopback_traffic_contract_invalid")
        proof = {"relink_id": identity, "wrong_target": wrong_pending, "wrong_returned_space": returned_pending, "requests": counts, "zero_message_pull_ack": True, "daemon_adoption": {"proven": False, "reason": "the public relink CLI publishes readiness but does not start the daemon"}, "durable_sha256": {name: sha256_bytes(value) for name, value in durable_before_retry.items()}, "source_bindings": bindings, "expected_receipt": expected.__dict__}
        (evidence / "receipt-summary.json").write_text(json.dumps(proof, sort_keys=True), encoding="utf-8")
        return proof
    finally:
        if server is not None and not server.stop():
            raise Failure("loopback_cleanup_failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    for argument in ("--binary", "--root", "--home", "--source", "--evidence-dir", "--receipt", "--workflow"):
        parser.add_argument(argument, required=True)
    args = parser.parse_args()
    root = Path(args.root).absolute()
    home = Path(args.home).absolute()
    source_path = Path(args.source).absolute()
    evidence = Path(args.evidence_dir).absolute()
    receipt = Path(args.receipt).absolute()
    binary = Path(args.binary).absolute()
    workflow = Path(args.workflow).absolute()
    temp = Path(os.environ.get("RUNNER_TEMP", "")).absolute()
    guarded = os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REF") == "refs/heads/main" and re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) and root.is_dir() and not root.is_symlink() and not any(root.iterdir()) and contained(root, temp) and home == root / "neoth-home" and source_path == root / "openclaw.json" and evidence == root / "evidence" and receipt == root / "receipt" / "receipt.json" and not any(path.is_symlink() for path in (home, source_path, evidence, receipt)) and workflow == Path(".github/workflows/gchat-live-regressions.yml").absolute()
    if not guarded:
        raise Failure("hosted_guard_failed")
    result = None
    error = None
    refusal_probe = None
    try:
        result = execute(binary, root, home, source_path, evidence, workflow)
    except Failure as caught:
        error = str(caught)
        refusal_probe = caught.refusal_probe
    except Exception:
        error = "unexpected_failure"
    flags = cleanup(root, home, source_path, evidence)
    payload = {"schema_version": 1, "outcome": "passed" if result and all(flags.values()) else "failed", "failure": error, "cleanup": flags, "local_external_provider": False, "source_head": os.environ.get("GITHUB_SHA", "")}
    if refusal_probe is not None:
        payload["refusal_probe"] = refusal_probe
    if result:
        payload["gchat_relink"] = result
    if regular(binary):
        payload["binary_sha256"] = digest(binary)
    encoded = json.dumps(payload, sort_keys=True)
    validate_receipt_redaction(encoded)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(encoded, encoding="utf-8")
    return 0 if payload["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
