#!/usr/bin/env python3
"""Hosted proof that a running daemon reloads a Ready Google Chat relink."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import bluebubbles_daemon_adoption_canary as daemon
import gchat_converted_relink_product_canary as cli


RELOAD = cli.RELOAD
DURABLE = cli.DURABLE
TRAFFIC_COUNTERS = (
    "token", "subscription", "space", "wrong_space", "pull",
    "nonempty_pull_response", "invalid_pull", "acknowledge", "message_post",
    "bad_token", "bad_bearer", "forbidden_post", "unexpected_get", "unexpected_post",
)


class Failure(RuntimeError):
    pass


def regular(path: Path) -> bool:
    return cli.regular(path)


def snapshot(path: Path) -> tuple[bool, bytes]:
    return cli.snapshot(path)


class LiveFakeGoogle:
    """A strict OAuth, probe, and empty-Pub/Sub-pull loopback fixture."""

    def __init__(self, public: Path | None = None) -> None:
        self.public = public
        self.lock = threading.Lock()
        self.events: list[str] = []
        self.wrong_return = False
        self.pull_response: dict = {}
        self.started = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def record(self, name: str) -> None:
        with self.lock:
            self.events.append(name)

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

            def require_bearer(self) -> bool:
                if self.headers.get("Authorization") == "Bearer canary-access-token":
                    return True
                parent.record("bad_bearer")
                self.reply(401, {})
                return False

            def do_POST(self) -> None:
                if self.path == "/token":
                    self.token()
                    return
                if self.path == f"/v1/{cli.SUBSCRIPTION}:pull":
                    self.pull()
                    return
                if self.path == f"/v1/{cli.SUBSCRIPTION}:acknowledge":
                    parent.record("acknowledge")
                    self.reply(405, {})
                    return
                if self.path.startswith("/v1/spaces/") and self.path.endswith("/messages"):
                    parent.record("message_post")
                    self.reply(405, {})
                    return
                parent.record("unexpected_post" if self.path.startswith("/v1/") else "forbidden_post")
                self.reply(405, {})

            def token(self) -> None:
                public = parent.public
                signature_path = public.parent / "jwt-signature" if public is not None else None
                try:
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    form = parse_qs(body.decode(), keep_blank_values=True)
                    head, claims, signature = form.get("assertion", [""])[0].split(".")
                    claim = json.loads(cli.b64(claims.encode()))
                    if public is None or signature_path is None:
                        verified = False
                    else:
                        signature_path.write_bytes(cli.b64(signature.encode()))
                        verified = cli.command(
                            ["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(signature_path), "-"],
                            dict(os.environ),
                            f"{head}.{claims}".encode(),
                        ).returncode == 0
                except Exception:
                    form, claim, verified = {}, {}, False
                finally:
                    if signature_path is not None:
                        signature_path.unlink(missing_ok=True)
                if (form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
                        or claim.get("iss") != cli.EMAIL
                        or claim.get("aud") != parent.origin + "/token" or not verified):
                    parent.record("bad_token")
                    self.reply(400, {})
                    return
                parent.record("token")
                self.reply(200, {"access_token": "canary-access-token", "expires_in": 3600})

            def pull(self) -> None:
                if not self.require_bearer():
                    return
                try:
                    body = cli.one_json(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                except cli.Failure:
                    body = None
                if body != {"maxMessages": 10}:
                    parent.record("invalid_pull")
                    self.reply(400, {})
                    return
                parent.record("pull")
                if parent.pull_response != {}:
                    parent.record("nonempty_pull_response")
                self.reply(200, parent.pull_response)

            def do_GET(self) -> None:
                if not self.require_bearer():
                    return
                if self.path == "/v1/" + cli.SUBSCRIPTION:
                    parent.record("subscription")
                    self.reply(200, {"name": cli.SUBSCRIPTION})
                elif self.path == "/v1/" + cli.SPACE:
                    parent.record("space")
                    self.reply(200, {"name": cli.WRONG_SPACE if parent.wrong_return else cli.SPACE})
                elif self.path.startswith("/v1/spaces/"):
                    parent.record("wrong_space")
                    self.reply(404, {})
                else:
                    parent.record("unexpected_get")
                    self.reply(404, {})

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
            return {name: self.events.count(name) for name in TRAFFIC_COUNTERS}


def validate_ready(home: Path, identity: str, expected: cli.ExpectedReceipt) -> dict[str, bytes]:
    """Validate durable Ready data independently of the daemon-owned sentinel."""
    paths = {name: home / name for name in DURABLE}
    if any(not regular(path) for path in paths.values()):
        raise Failure("ready_publication_missing")
    credentials = paths["credentials.yaml"].read_bytes()
    # The daemon fixture deliberately retains init's normal WAL policy. Under
    # that production policy credentials are UTF-8 YAML; CONF_MAGIC only
    # appears when WAL at-rest encryption is explicitly enabled.
    if credentials.startswith(b"NEOTH_CONF_ENCv1\n"):
        raise Failure("credentials_storage_policy_invalid")
    try:
        credentials.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Failure("credentials_storage_invalid") from error
    route_raw = paths["channel_routing.json"].read_bytes()
    route = cli.read_json(paths["channel_routing.json"], "routing_invalid")
    destinations = route.get("destinations")
    if not isinstance(destinations, dict) or destinations.get("gchat_space") != cli.SPACE or "google_chat" in destinations:
        raise Failure("routing_target_invalid")
    index = cli.read_json(paths["channel_relinks.json"], "relink_index_invalid")
    pending = index.get("pending")
    records = [item for item in pending if isinstance(item, dict) and item.get("destination") == cli.DESTINATION] if isinstance(pending, list) else []
    if len(records) != 1:
        raise Failure("relink_index_identity_invalid")
    entry = records[0]
    if (entry.get("id") != identity or entry.get("state") != "ready"
            or entry.get("completion_request_material_sha256") != expected.material_sha256
            or entry.get("bound_material_sha256") != expected.material_sha256
            or not isinstance(entry.get("source_set_sha256"), str)
            or not cli.SHA256.fullmatch(entry["source_set_sha256"])):
        raise Failure("ready_publication_invalid")
    if cli.digest(home.parent / "openclaw.json") != expected.source_sha256:
        raise Failure("source_custody_changed")
    transaction = cli.read_json(paths[".channel-relink-google-chat.transaction.json"], "relink_transaction_invalid")
    required = {
        "version": 1, "pending_id": identity, "destination": cli.DESTINATION,
        "target_sha256": cli.sha256_bytes(cli.SPACE.encode()),
        "request_material_sha256": expected.material_sha256,
        "pair_before_sha256": expected.pair_before_sha256,
        "routing_before_sha256": expected.routing_before_sha256,
        "pair_after_sha256": expected.pair_after_sha256,
        "routing_after_sha256": expected.routing_after_sha256,
        "phase": "routing_committed",
    }
    if (set(transaction) != set(required) or transaction != required
            or cli.pair_commitment(home) != expected.pair_after_sha256
            or cli.sha256_bytes(route_raw) != expected.routing_after_sha256):
        raise Failure("relink_transaction_invalid")
    return {name: path.read_bytes() for name, path in paths.items()}


def require_pending(home: Path, before: dict[str, tuple[bool, bytes]], server: LiveFakeGoogle) -> dict:
    if any(snapshot(home / name) != value for name, value in before.items()):
        raise Failure("wrong_target_mutated_state")
    if (home / RELOAD).exists() or (home / ".channel-relink-google-chat.transaction.json").exists():
        raise Failure("wrong_target_published_ready")
    index = cli.read_json(home / "channel_relinks.json", "pending_index_invalid")
    pending = index.get("pending")
    records = [item for item in pending if isinstance(item, dict) and item.get("destination") == cli.DESTINATION] if isinstance(pending, list) else []
    counts = server.counts()
    if (len(records) != 1 or records[0].get("state") != "pending" or counts["token"] < 1
            or counts["subscription"] < 1 or counts["wrong_space"] < 1 or counts["pull"] != 0):
        raise Failure("wrong_target_pending_invalid")
    return {"pending_id": records[0].get("id"), "source_set_sha256": records[0].get("source_set_sha256")}


def observe_pending_no_pull(process: object, server: LiveFakeGoogle, seconds: float = 3.0) -> None:
    baseline = server.counts()["pull"]
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        daemon.require_live(process)
        if server.counts()["pull"] != baseline:
            raise Failure("pending_target_pulled")
        time.sleep(0.2)
    daemon.require_live(process)


def wait_for_reload_adoption(home: Path, process: object, server: LiveFakeGoogle, baseline: int) -> None:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        daemon.require_live(process)
        if server.counts()["pull"] > baseline and not (home / RELOAD).exists():
            return
        time.sleep(0.2)
    raise Failure("daemon_adoption_timeout")


def wait_for_reload_consumption(home: Path, process: object) -> None:
    """An idempotent Ready retry is complete only after its reload is consumed."""
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        daemon.require_live(process)
        if not (home / RELOAD).exists():
            return
        time.sleep(0.2)
    raise Failure("retry_reload_not_consumed")


def validate_traffic(provider: daemon.LoopbackServices, server: LiveFakeGoogle, minimum_pulls: int = 1) -> dict[str, int]:
    counts = server.counts()
    provider_counts = provider.counts()
    forbidden = ("nonempty_pull_response", "invalid_pull", "acknowledge", "message_post", "bad_token", "bad_bearer", "forbidden_post", "unexpected_get", "unexpected_post")
    if (counts["token"] < 3 or counts["subscription"] < 2 or counts["space"] < 1
            or counts["wrong_space"] < 1 or counts["pull"] < minimum_pulls
            or any(counts[name] for name in forbidden)
            or any(provider_counts.values())):
        raise Failure("daemon_traffic_contract_invalid")
    return counts


def source_bindings(workflow: Path) -> dict[str, str]:
    relatives = (
        "packaging/gchat_daemon_adoption_canary.py",
        "packaging/tests/test_gchat_daemon_adoption_canary.py",
        "packaging/gchat_converted_relink_product_canary.py",
        "packaging/tests/test_gchat_converted_relink_product_canary.py",
        "packaging/bluebubbles_daemon_adoption_canary.py",
        "packaging/tests/test_bluebubbles_daemon_adoption_canary.py",
        ".github/workflows/gchat-live-regressions.yml",
        "SRC/neothd/src/main.rs", "SRC/neothd/src/lib.rs", "SRC/neothd/src/shutdown.rs",
        "SRC/neothd/src/channels/gchat.rs", "SRC/neothd/src/channels/gchat_api.rs", "SRC/neothd/src/channels/readiness.rs",
        "SRC/neothd/src/channels/relink.rs", "SRC/neothd/src/channels/routing.rs", "SRC/neothd/src/channels/registry.rs",
        "SRC/neothd/src/cli/mod.rs", "SRC/neothd/src/cli/channel_relink.rs", "SRC/neothd/src/cli/channel.rs", "SRC/neothd/src/cli/channel/converted_relink.rs",
        "SRC/neothd/src/cli/serve.rs", "SRC/neothd/src/cli/serve_tasks.rs", "SRC/neothd/src/cli/cluster.rs", "SRC/neothd/src/cli/consent.rs", "SRC/neothd/src/cli/consent_outbox.rs",
        "SRC/neothd/src/cli/init.rs", "SRC/neothd/src/cli/init/io.rs", "SRC/neothd/src/cli/init/steps_identity.rs", "SRC/neothd/src/cli/init/steps_provider.rs",
        "SRC/neothd/src/config/mod.rs", "SRC/neothd/src/config/credentials.rs", "SRC/neothd/src/config/reload.rs", "SRC/neothd/src/config/wal.rs",
        "SRC/neothd/src/consent.rs", "SRC/neothd/src/wal/master_key.rs", "SRC/neothd/src/wal/writer.rs", "SRC/neothd/src/util/locked_file.rs",
        "SRC/neothd/src/daemon/pidfile.rs", "SRC/neothd/src/daemon/channel_live_registry.rs", "SRC/neothd/src/daemon/chat_runtime.rs", "SRC/neothd/src/daemon/gui_chat_runtime.rs", "SRC/neothd/src/daemon/webchat.rs",
        "SRC/neothd/src/cluster/status_wire.rs", "SRC/neothd/src/cluster/membership.rs", "SRC/neothd/src/cluster/runtime_supervisor.rs",
        "SRC/neothd/src/daemon/audit_rpc/mod.rs", "SRC/neothd/src/daemon/audit_rpc/client.rs", "SRC/neothd/src/daemon/audit_rpc/server.rs", "SRC/neothd/src/daemon/audit_rpc/sidecar.rs", "SRC/neothd/src/daemon/audit_rpc/token.rs", "SRC/neothd/src/daemon/audit_rpc/transport/mod.rs", "SRC/neothd/src/daemon/audit_rpc/transport/unix.rs", "SRC/neothd/src/skills/store.rs",
        "SRC/neothd/src/providers/mod.rs", "SRC/neothd/src/providers/openai_api.rs",
        "SRC/neoth-openclaw-custody/Cargo.toml", "SRC/neoth-openclaw-custody/src/lib.rs",
        "SRC/neoth-openclaw-custody/src/pinned_inventory.rs", "SRC/neoth-openclaw-custody/src/pinned_schema.rs",
        "SRC/neoth-openclaw-custody/src/fixtures/pinned_channel_inventory_v1.json",
        "SRC/neoth-openclaw-custody/src/fixtures/openclaw_upstream_evidence_v1.json",
        "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_v1.json",
        "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_migration_policy_v1.json",
        "SRC/neothd/Cargo.toml", "SRC/Cargo.lock",
    )
    paths = {relative: Path(relative) for relative in relatives}
    expected_workflow = paths[".github/workflows/gchat-live-regressions.yml"]
    if workflow.resolve() != expected_workflow.resolve() or any(not regular(path) for path in paths.values()):
        raise Failure("source_provenance_missing")
    return {relative: cli.digest(path) for relative, path in paths.items()}


def diagnostic_failure(error: BaseException | None) -> daemon.Failure | None:
    """Convert local fixed failures to the daemon diagnostic's fixed vocabulary."""
    if error is None:
        return None
    code = str(error)
    return daemon.Failure(code if daemon.FAILURE_CODE.fullmatch(code) else "unexpected_failure")


def cleanup(root: Path, home: Path, source_path: Path, log: Path, process: object | None, evidence: Path) -> dict[str, bool]:
    targets = {
        "home_removed": home, "source_removed": source_path, "log_removed": log,
        "key_removed": root / "service-account.json", "private_key_removed": root / "canary-rsa.pem",
        "public_key_removed": root / "canary-rsa.pub", "jwt_signature_removed": root / "jwt-signature",
    }
    flags: dict[str, bool] = {}
    try:
        if process is not None:
            daemon.stop_daemon(process)
        flags["daemon_reaped"] = process is None or process.poll() is not None
    except Exception:
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=10)
            except Exception:
                pass
        flags["daemon_reaped"] = process is not None and process.poll() is not None
    if not flags["daemon_reaped"]:
        flags.update({name: False for name in targets})
        flags["evidence_retained"] = evidence.is_dir() and cli.contained(evidence, root)
        return flags
    for name, path in targets.items():
        try:
            if not cli.contained(path, root) or path.is_symlink():
                flags[name] = False
            elif path.exists():
                shutil.rmtree(path) if path.is_dir() else path.unlink()
                flags[name] = not path.exists()
            else:
                flags[name] = True
        except OSError:
            flags[name] = False
    flags["evidence_retained"] = evidence.is_dir() and cli.contained(evidence, root)
    return flags


def execute(binary: Path, root: Path, home: Path, source_path: Path, evidence: Path, workflow: Path, state: dict) -> dict:
    phase, primary_failure = "provenance", None
    provider, google, process = daemon.LoopbackServices(), LiveFakeGoogle(), None
    log = root / "daemon.log"
    home.mkdir()
    evidence.mkdir()
    cli.source(source_path)
    env = dict(os.environ)
    env["NEOTH_HOME"] = str(home)
    try:
        bindings = source_bindings(workflow)
        provider.start()
        public = cli.make_key(root, google.origin)
        google.public = public
        google.start()
        env["NEOTH_GCHAT_CANARY_ORIGIN"] = google.origin
        phase = "init"
        daemon.init_home(binary, home, env, provider.port)
        phase = "consent"
        daemon.grant_loopback_provider_consent(binary, env, provider.port)
        phase = "start"
        process = daemon.start_daemon(binary, home, env, log)
        state["daemon"] = process
        phase = "readiness"
        daemon.wait_for_daemon_ready(process, home, binary, env)
        before = {name: snapshot(home / name) for name in ("freedom.yaml", "wal/master.key", "credentials.yaml", "channel_routing.json")}
        phase = "pending"
        wrong = cli.command(cli.argv(binary, source_path, cli.WRONG_SPACE), env, cli.envelope(root / "service-account.json"))
        if wrong.returncode == 0:
            raise Failure("wrong_target_accepted")
        pending = require_pending(home, before, google)
        observe_pending_no_pull(process, google)
        expected = cli.expected_before(home, root / "service-account.json", source_path)
        baseline = google.counts()["pull"]
        phase = "relink"
        ready = cli.command(cli.argv(binary, source_path, cli.SPACE), env, cli.envelope(root / "service-account.json"))
        if ready.returncode:
            raise Failure("relink_failed")
        identity = cli.validate_output(cli.one_json(ready.stdout), False)
        expected = cli.expected_after(expected, home)
        # `reload_requested` in the public CLI result proves publication was
        # requested. A running daemon may consume the sentinel before this
        # process regains control, so only durable Ready state is checked here.
        durable = validate_ready(home, identity, expected)
        reload_sentinel_visible_after_cli = (home / RELOAD).exists()
        phase = "adoption"
        wait_for_reload_adoption(home, process, google, baseline)
        if validate_ready(home, identity, expected) != durable:
            raise Failure("adoption_mutated_durable_state")
        before_retry = dict(durable)
        phase = "retry"
        retry = cli.command(cli.argv(binary, source_path, cli.SPACE), env, cli.envelope(root / "service-account.json"))
        if retry.returncode:
            raise Failure("retry_failed")
        cli.validate_output(cli.one_json(retry.stdout), True, identity)
        wait_for_reload_consumption(home, process)
        daemon.require_live(process)
        if validate_ready(home, identity, expected) != before_retry:
            raise Failure("retry_mutated_durable_state")
        counts = validate_traffic(provider, google)
        result = {
            "relink_id": identity, "pending_negative": pending, "ready": {name: cli.sha256_bytes(raw) for name, raw in durable.items()},
            "requests": counts, "daemon_adoption": {"proven": True, "witness": "authenticated_empty_pubsub_pull", "reload_sentinel_visible_after_cli": reload_sentinel_visible_after_cli},
            "source_bindings": bindings, "binary_sha256": cli.digest(binary),
        }
        (evidence / "receipt-summary.json").write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        return result
    except Exception as caught:
        primary_failure = caught
        raise
    finally:
        stop_failure = None
        if process is not None:
            try:
                daemon.stop_daemon(process)
            except Exception as caught:
                stop_failure = caught
            if process.poll() is not None:
                state["daemon"] = None
        google_stop_failure = None
        provider_stop_failure = None
        try:
            if not google.stop():
                google_stop_failure = Failure("loopback_cleanup_failed")
        except Exception as caught:
            google_stop_failure = caught
        try:
            if not provider.stop():
                provider_stop_failure = Failure("loopback_cleanup_failed")
        except Exception as caught:
            provider_stop_failure = caught
        loopback_failure = google_stop_failure or provider_stop_failure
        daemon.retain_daemon_diagnostics(
            evidence, log, process, diagnostic_failure(primary_failure), phase,
            diagnostic_failure(stop_failure), diagnostic_failure(loopback_failure),
        )
        if primary_failure is None and (stop_failure is not None or loopback_failure is not None):
            raise Failure("daemon_stop_failed" if stop_failure is not None else "loopback_cleanup_failed")


def receipt_payload(result: dict | None, error: str | None, flags: dict[str, bool], source_head: str) -> dict:
    payload = {"schema_version": 1, "outcome": "passed" if result and all(flags.values()) else "failed", "failure": error, "cleanup": flags, "source_head": source_head}
    if result is not None:
        payload["daemon_adoption"] = result
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("--binary", "--root", "--home", "--source", "--evidence-dir", "--receipt", "--workflow"):
        parser.add_argument(name, required=True)
    args = parser.parse_args()
    root, home, source_path = Path(args.root).absolute(), Path(args.home).absolute(), Path(args.source).absolute()
    evidence, receipt = Path(args.evidence_dir).absolute(), Path(args.receipt).absolute()
    binary, workflow = Path(args.binary).absolute(), Path(args.workflow).absolute()
    temp = Path(os.environ.get("RUNNER_TEMP", "")).absolute()
    valid = (os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REF") == "refs/heads/main"
             and re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) and regular(binary)
             and root.is_dir() and not root.is_symlink() and not any(root.iterdir()) and cli.contained(root, temp)
             and home == root / "neoth-home" and source_path == root / "openclaw.json" and evidence == root / "evidence"
             and receipt == root / "receipt" / "receipt.json" and workflow == Path(".github/workflows/gchat-live-regressions.yml").absolute())
    if not valid:
        raise Failure("hosted_guard_failed")
    state: dict = {"daemon": None}
    result, error = None, None
    try:
        result = execute(binary, root, home, source_path, evidence, workflow, state)
    except Failure as caught:
        error = str(caught)
    except Exception:
        error = "unexpected_failure"
    flags = cleanup(root, home, source_path, root / "daemon.log", state["daemon"], evidence)
    payload = receipt_payload(result, error, flags, os.environ.get("GITHUB_SHA", ""))
    rendered = json.dumps(payload, sort_keys=True)
    if cli.EMAIL in rendered or "BEGIN PRIVATE KEY" in rendered or google_origin_leaked(rendered):
        raise Failure("receipt_secret_leak")
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(rendered, encoding="utf-8")
    return 0 if payload["outcome"] == "passed" else 1


def google_origin_leaked(rendered: str) -> bool:
    return "http://" in rendered or "https://" in rendered


if __name__ == "__main__":
    raise SystemExit(main())
