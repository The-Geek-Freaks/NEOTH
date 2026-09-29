"""Static contracts for the hosted BlueBubbles daemon-adoption canary."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bluebubbles_daemon_adoption_canary as canary


class BlueBubblesDaemonAdoptionCanaryTests(unittest.TestCase):
    class _Process:
        def __init__(self, pid: int, returncode: int | None = None) -> None:
            self.pid = pid
            self.returncode = returncode
            self.signals: list[int] = []
            self.wait_timeouts: list[float] = []

        def poll(self) -> int | None:
            return self.returncode

        def send_signal(self, value: int) -> None:
            self.signals.append(value)

        def wait(self, timeout: float) -> int:
            self.wait_timeouts.append(timeout)
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    @staticmethod
    def _live_status() -> dict:
        return {
            "wire_version": 1,
            "operation": "cluster.status",
            "membership": {
                "wire_version": 1,
                "operation": "cluster.membership.snapshot",
                "snapshot_version": 1,
                "snapshot_digest": "0" * 64,
                "snapshot": {},
            },
            "runtime": {
                "version": 1,
                "mode": "single-node",
                "policy": "local-only",
                "conflict_count": 0,
                "operator_id": "operator",
                "node_id": "node",
                "cluster_name": None,
                "cluster_passphrase_set": False,
                "cluster_identity_configured": False,
                "cluster_enabled": False,
                "restart_required": False,
                "transport_active": False,
                "transport": "peeroxide",
                "listen_port": 7700,
                "mdns_enabled": False,
                "trusted_ssids": [],
                "gossip": {"replicate_raw_ingress": False, "replay_budget_days": 14},
            },
        }

    def test_public_relink_envelope_and_argv_are_exact(self):
        payload = json.loads(canary.envelope(43123))
        self.assertEqual(payload["channel"], "imessage_bluebubbles")
        self.assertEqual(payload["fields"]["allowed_sender"], canary.SENDER)
        self.assertEqual(payload["fields"]["channels_csv"], canary.TARGET)
        argv = canary.relink_argv(Path("/bin/neoth"), Path("/tmp/openclaw.json"), canary.TARGET)
        self.assertEqual(argv[-4:], ["--source-account", "personal", "--target", canary.TARGET])

    def test_material_binding_has_real_rust_domain_and_order(self):
        actual = canary.material_commitment(1234, canary.TARGET, canary.TARGET)
        value = hashlib.sha256(b"neoth-converted-relink-material-v1\0")
        value.update(b"imessage_bluebubbles\0")
        value.update(canary.TARGET.encode())
        value.update(b"\0")
        for field in ("http://127.0.0.1:1234", canary.PASSWORD, canary.TARGET, canary.SENDER):
            raw = field.encode()
            value.update(len(raw).to_bytes(8, "little"))
            value.update(raw)
        self.assertEqual(actual, value.hexdigest())
        self.assertNotEqual(actual, canary.material_commitment(1235, canary.TARGET, canary.TARGET))
        self.assertNotEqual(actual, canary.material_commitment(1234, "iMessage;-;+491709999999", canary.TARGET))
        self.assertNotEqual(actual, canary.material_commitment(1234, canary.TARGET, "iMessage;-;+491709999999"))

    def test_loopback_provider_consent_uses_exact_public_cli_receipt_contract(self):
        binary = Path("/tmp/neoth")
        env = {"NEOTH_HOME": "/tmp/neoth-home"}
        output = {
            "provider": "openai_compat",
            "action": "granted",
            "status": "applied",
            "marker_path": "/tmp/neoth-home/consent/openai_compat.granted",
            "configured_endpoint_origins": ["http://127.0.0.1:43123"],
            "endpoint_origins": ["http://127.0.0.1:43123"],
            "added_endpoint_origins": ["http://127.0.0.1:43123"],
            "removed_endpoint_origins": [],
            "endpoint_delta_known": True,
            "marker_source_malformed": False,
            "audit_pending": False,
            "operation_id": "operation-id",
            "authority_persisted": True,
            "failure": None,
            "config_sha256": None,
            "route_set_sha256": None,
            "routes": [{"endpoint_origin": "http://127.0.0.1:43123"}],
        }
        completed = subprocess.CompletedProcess([], 0, json.dumps(output).encode(), b"")
        with patch.object(canary, "command", return_value=completed) as invoked:
            canary.grant_loopback_provider_consent(binary, env, 43123)
        invoked.assert_called_once_with([str(binary), "--output", "json", "consent", "grant", "openai_compat"], env)

    def test_loopback_provider_consent_rejects_cli_failure_or_unpersisted_authority(self):
        binary = Path("/tmp/neoth")
        with patch.object(canary, "command", return_value=subprocess.CompletedProcess([], 1, b"", b"")):
            with self.assertRaisesRegex(canary.Failure, "provider_consent_grant_failed"):
                canary.grant_loopback_provider_consent(binary, {}, 43123)
        incomplete = {"provider": "openai_compat", "status": "applied", "authority_persisted": False, "failure": None}
        with patch.object(canary, "command", return_value=subprocess.CompletedProcess([], 0, json.dumps(incomplete).encode(), b"")):
            with self.assertRaisesRegex(canary.Failure, "provider_consent_grant_invalid"):
                canary.grant_loopback_provider_consent(binary, {}, 43123)

    def test_loopback_provider_consent_rejects_each_nonexact_endpoint_receipt(self):
        origin, wrong_origin = "http://127.0.0.1:43123", "http://127.0.0.1:43124"
        base = {
            "provider": "openai_compat",
            "status": "applied",
            "authority_persisted": True,
            "failure": None,
            "configured_endpoint_origins": [origin],
            "endpoint_origins": [origin],
            "added_endpoint_origins": [origin],
        }
        variants = (("missing", []), ("wrong", [wrong_origin]), ("extra", [origin, wrong_origin]))
        for field in ("configured_endpoint_origins", "endpoint_origins", "added_endpoint_origins"):
            for label, value in variants:
                with self.subTest(field=field, variant=label):
                    receipt = dict(base)
                    receipt[field] = value
                    completed = subprocess.CompletedProcess([], 0, json.dumps(receipt).encode(), b"")
                    with patch.object(canary, "command", return_value=completed):
                        with self.assertRaisesRegex(canary.Failure, "provider_consent_grant_invalid"):
                            canary.grant_loopback_provider_consent(Path("/tmp/neoth"), {}, 43123)

    def test_loopback_provider_configuration_replaces_skip_topology_before_exact_consent(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / "freedom.yaml"
            config.write_text(
                "provider_kind: skip\n"
                "provider_model: null\n"
                "inference:\n"
                "  mode: single\n"
                "  default_slot:\n"
                "    provider: claude_cli\n"
                "    model: null\n"
                "    endpoint: null\n"
                "unrelated_setting: preserve-me\n",
                encoding="utf-8",
            )
            canary.configure_loopback_provider(home, 43123)
            rendered = config.read_text(encoding="utf-8")
            self.assertIn("provider_kind: openai_compat\n", rendered)
            self.assertIn("provider_endpoint: http://127.0.0.1:43123/v1\n", rendered)
            self.assertIn("provider_model: daemon-canary-model\n", rendered)
            self.assertIn("inference:\n  mode: single\n  default_slot:\n    provider: openai_compat\n    model: daemon-canary-model\n    endpoint: http://127.0.0.1:43123/v1\n", rendered)
            self.assertNotIn("provider: claude_cli", rendered)
            self.assertIn("unrelated_setting: preserve-me\n", rendered)

    def test_daemon_diagnostic_classifies_real_startup_markers_without_retaining_sensitive_log(self):
        secret = "https://127.0.0.1:43123/v1 bot@neoth-canary.invalid Bearer secret-token BEGIN PRIVATE KEY"
        cases = (
            ("process", "interrupted_install_recovery", "recover interrupted NEOTH installation before startup: failed\n" + secret),
            ("process", "tokio_runtime", "build the tokio runtime: failed\n" + secret),
            ("config", "runtime_config_pair", "runtime config pair at /private/home/freedom.yaml cannot be loaded\n" + secret),
            ("consent", "provider_consent", "consent gate (V03-08 + A-2): denied\n" + secret),
            ("wal", "boot_write", "write BOOT WAL frame: disk failure\n" + secret),
            ("authority", "audit_rpc", "start daemon membership/audit RPC: bind failed\n" + secret),
            ("authority", "audit_rpc", "start mandatory daemon audit RPC: bind failed\n" + secret),
        )
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "daemon.log"
            for expected_stage, expected_reason, raw in cases:
                with self.subTest(reason=expected_reason):
                    log.write_text(raw, encoding="utf-8")
                    diagnostic = canary.daemon_failure_diagnostic(canary.daemon_log_snapshot(log))
                    self.assertEqual(diagnostic["stage"], expected_stage)
                    self.assertEqual(diagnostic["reason"], expected_reason)
                    rendered = json.dumps(diagnostic, sort_keys=True)
                    self.assertNotIn(secret, rendered)
                    self.assertNotIn("https://", rendered)
                    self.assertNotIn(canary.PASSWORD, rendered)
                    self.assertRegex(diagnostic["log_fingerprint_sha256"], r"^[0-9a-f]{64}$")

    def test_daemon_diagnostic_keeps_unknown_and_oversized_logs_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "daemon.log"
            secret = "https://secret.invalid/path Bearer value"
            log.write_text(secret, encoding="utf-8")
            diagnostic = canary.daemon_failure_diagnostic(canary.daemon_log_snapshot(log))
            self.assertEqual(diagnostic["stage"], "unknown")
            self.assertEqual(diagnostic["reason"], "unknown")
            self.assertNotIn(secret, json.dumps(diagnostic, sort_keys=True))
            log.write_bytes(b"x" * (canary.LIMIT + 1))
            bounded = canary.daemon_failure_diagnostic(canary.daemon_log_snapshot(log))
            self.assertEqual(bounded["stage"], "unknown")
            self.assertEqual(bounded["reason"], "log_exceeds_bound")
            self.assertRegex(bounded["log_fingerprint_sha256"], r"^[0-9a-f]{64}$")

    def test_shutdown_progress_records_only_allowlisted_markers_and_rejects_idle_sigterm_banner(self):
        secret = "https://secret.invalid/path Bearer value"
        raw = (
            "\x1b[2m2026-09-29T12:00:00Z \x1b[32mINFO\x1b[0m neothd::shutdown: SIGTERM\x1b[0m\n"
            "shutdown signal received; aborting channels + draining WAL writer\n"
            "shutdown checkpoint: background entry\n"
            "shutdown checkpoint: generation effects retired\n"
            "shutdown checkpoint: channel revoke entry\n"
            "shutdown checkpoint: channels and dispatch drained\n"
            "shutdown checkpoint: updater shutdown entry\n"
            "shutdown checkpoint: retained updater joins entry\n"
            "shutdown checkpoint: cron fleet drained\n"
            "shutdown checkpoint: cluster drained\n"
            "shutdown checkpoint: outboxes drained\n"
            "shutdown checkpoint: core authority drained\n"
            "shutdown checkpoint: transports drained\n"
            "shutdown checkpoint: final pre-WAL tasks drained\n"
            "shutdown checkpoint: WAL other senders absent\n"
            "shutdown checkpoint: WAL join entry\n"
            "WAL writer diagnostic: receiver closed\n"
            "webhook drain timed out — abandoning remaining connections\n"
            "COR-34: webhook dispatch drain timed out — aborting remaining fan-out tasks\n"
            "SelfMap cron is still draining; retaining owner and suppressing replacement\n"
            "SelfMap did not quiesce during shutdown (phase: Persisting)\n"
            "WAL writer task drained cleanly\n"
            + secret
        )
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "daemon.log"
            log.write_text(raw, encoding="utf-8")
            progress = canary.daemon_shutdown_progress(canary.daemon_log_snapshot(log))
            self.assertEqual(progress["shutdown_wal_other_senders_present"], "not_observed")
            self.assertEqual(
                {
                    value
                    for name, value in progress.items()
                    if name != "shutdown_wal_other_senders_present"
                },
                {"observed"},
            )
            self.assertNotIn(secret, json.dumps(progress, sort_keys=True))
            log.write_text(
                "channels running; idling until shutdown signal (SIGTERM / Ctrl+C)\n"
                "2026-09-29T12:00:01Z INFO neothd::worker: failure SIGTERM\n",
                encoding="utf-8",
            )
            idle_progress = canary.daemon_shutdown_progress(canary.daemon_log_snapshot(log))
            self.assertEqual(idle_progress["state"], "unknown")
            self.assertEqual(idle_progress["sigterm_event"], "not_observed")

    def test_shutdown_progress_marks_unavailable_and_oversized_logs_without_retaining_content(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "daemon.log"
            unavailable = canary.daemon_shutdown_progress(canary.daemon_log_snapshot(log))
            self.assertEqual(set(unavailable.values()), {"unavailable"})
            log.write_bytes(b"secret" * ((canary.LIMIT // len(b"secret")) + 1))
            oversized = canary.daemon_shutdown_progress(canary.daemon_log_snapshot(log))
            self.assertEqual(set(oversized.values()), {"oversized"})

    def test_retain_daemon_diagnostics_bounds_oversized_log_without_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, log = root / "evidence", root / "daemon.log"
            evidence.mkdir()
            secret = b"https://secret.invalid/path Bearer private-token "
            log.write_bytes((secret * ((canary.LIMIT // len(secret)) + 2))[: canary.LIMIT + 1])
            with patch.object(canary, "digest", side_effect=AssertionError("retention must not full-hash daemon log")):
                canary.retain_daemon_diagnostics(evidence, log, self._Process(4242, returncode=1))
            diagnostic = json.loads((evidence / "daemon-diagnostics.json").read_text(encoding="utf-8"))
            self.assertTrue(diagnostic["log_present"])
            self.assertEqual(diagnostic["log_size"], canary.LIMIT + 1)
            self.assertIsNone(diagnostic["log_sha256"])
            self.assertEqual(diagnostic["startup_cause"]["stage"], "unknown")
            self.assertEqual(diagnostic["startup_cause"]["reason"], "log_exceeds_bound")
            self.assertRegex(diagnostic["startup_cause"]["log_fingerprint_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn(secret.decode("utf-8"), json.dumps(diagnostic, sort_keys=True))

    def test_init_home_marks_only_fresh_daemon_canary_onboarding_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "neoth-home"
            home.mkdir()
            binary = Path("/tmp/neoth")
            env = {"NEOTH_HOME": str(home)}

            def initialized(argv, received_env):
                self.assertEqual(argv, [str(binary), "init", "--non-interactive", "--cli", "--accept-license", "--operator-id", "bluebubbles-daemon-canary", "--provider", "skip"])
                self.assertEqual(received_env, env)
                (home / "freedom.yaml").write_text("unrelated_setting: preserve-me\nonboarding_complete: false\nprovider_kind: skip\n", encoding="utf-8")
                wal = home / "wal"
                wal.mkdir()
                master = wal / "master.key"
                master.write_bytes(b"x" * 32)
                os.chmod(master, 0o600)
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            with patch.object(canary, "command", side_effect=initialized) as invoked:
                canary.init_home(binary, home, env, 43123)

            invoked.assert_called_once()
            config = (home / "freedom.yaml").read_text(encoding="utf-8")
            self.assertIn("unrelated_setting: preserve-me\n", config)
            self.assertIn("onboarding_complete: true\n", config)
            self.assertEqual(config.count("onboarding_complete:"), 1)
            self.assertIn("provider_kind: openai_compat\n", config)
            self.assertIn("provider_endpoint: http://127.0.0.1:43123/v1\n", config)
            self.assertIn("provider_model: daemon-canary-model\n", config)
            self.assertNotIn("channels:", config)
            self.assertNotIn("one_shot", config)
            self.assertNotIn("allow_clock_rollback", config)
            self.assertNotIn("consent_bypass", config)

    def test_readiness_accepts_only_public_live_status_between_stable_owner_probes(self):
        process = self._Process(4242)
        home, binary, env = Path("/tmp/neoth-home"), Path("/tmp/neoth"), {"NEOTH_HOME": "/tmp/neoth-home"}
        completed = subprocess.CompletedProcess([str(binary)], 0, json.dumps(self._live_status()).encode(), b"")
        with patch.object(canary, "require_daemon_pid_lock", side_effect=[19, 19]) as locks, patch.object(canary, "command", return_value=completed) as invoked:
            canary.wait_for_daemon_ready(process, home, binary, env)
        self.assertEqual(locks.call_args_list, [call(process, home), call(process, home)])
        invoked.assert_called_once_with([str(binary), "--output", "json", "cluster", "status"], env)

    def test_readiness_rejects_status_when_pidfile_identity_changes_during_probe(self):
        process = self._Process(4242)
        completed = subprocess.CompletedProcess(["neoth"], 0, json.dumps(self._live_status()).encode(), b"")
        with patch.object(canary, "require_daemon_pid_lock", side_effect=[19, 20]), patch.object(canary, "command", return_value=completed):
            with self.assertRaisesRegex(canary.Failure, "daemon_pidfile_inode_changed"):
                canary.wait_for_daemon_ready(process, Path("/tmp/neoth-home"), Path("/tmp/neoth"), {})

    def test_offline_cluster_status_dictionary_is_rejected(self):
        with self.assertRaisesRegex(canary.Failure, "daemon_status_envelope_invalid"):
            canary.validate_daemon_status({"status": "offline", "membership": {}})

    def test_exited_child_is_rejected_before_status_or_pidfile_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            process = self._Process(os.getpid(), returncode=1)
            with self.assertRaisesRegex(canary.Failure, "daemon_exited_early"):
                canary.require_daemon_pid_lock(process, Path(directory))

    def test_nonzero_daemon_exit_is_retained_as_lifecycle_failure_but_not_reported_live(self):
        process = self._Process(4242, returncode=1)
        with self.assertRaisesRegex(canary.Failure, "daemon_stop_failed"):
            canary.stop_daemon(process)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home, source_path, log, evidence = root / "home", root / "source", root / "daemon.log", root / "evidence"
            home.mkdir()
            source_path.write_text("{}", encoding="utf-8")
            log.write_text("redacted", encoding="utf-8")
            evidence.mkdir()
            flags = canary.cleanup(root, home, source_path, log, process, evidence)
        self.assertTrue(flags["daemon_reaped"])

    def test_daemon_stop_uses_the_120_second_graceful_shutdown_budget(self):
        process = self._Process(4242)
        canary.stop_daemon(process)
        self.assertEqual(process.signals, [canary.signal.SIGTERM])
        self.assertEqual(process.wait_timeouts, [120])

    def test_daemon_stop_forced_reap_remains_fatal_after_the_child_is_reaped(self):
        class ForcedReapProcess(self._Process):
            def __init__(self) -> None:
                super().__init__(4242)
                self.killed = False

            def wait(self, timeout: float) -> int:
                self.wait_timeouts.append(timeout)
                if not self.killed:
                    raise subprocess.TimeoutExpired(["neoth"], timeout)
                self.returncode = -canary.signal.SIGKILL
                return self.returncode

            def kill(self) -> None:
                self.killed = True

        process = ForcedReapProcess()
        with self.assertRaisesRegex(canary.Failure, "daemon_stop_timeout"):
            canary.stop_daemon(process)
        self.assertTrue(process.killed)
        self.assertEqual(process.wait_timeouts, [120, 5])
        self.assertEqual(process.returncode, -canary.signal.SIGKILL)

    def test_daemon_stop_unreaped_child_remains_fatal_after_forced_kill(self):
        class UnreapedProcess(self._Process):
            def __init__(self) -> None:
                super().__init__(4242)
                self.killed = False

            def wait(self, timeout: float) -> int:
                self.wait_timeouts.append(timeout)
                raise subprocess.TimeoutExpired(["neoth"], timeout)

            def kill(self) -> None:
                self.killed = True

        process = UnreapedProcess()
        with self.assertRaisesRegex(canary.Failure, "daemon_stop_timeout"):
            canary.stop_daemon(process)
        self.assertTrue(process.killed)
        self.assertEqual(process.wait_timeouts, [120, 5])
        self.assertIsNone(process.returncode)

    def test_execute_preserves_primary_failure_over_all_teardown_failures(self):
        class Services:
            port = 43123

            def start(self) -> None:
                return

            def stop(self) -> bool:
                return False

        process = self._Process(4242)

        def stopped_nonzero(child: _Process) -> None:
            child.returncode = 1
            raise canary.Failure("daemon_stop_failed")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home, source_path, evidence = root / "neoth-home", root / "openclaw.json", root / "evidence"
            state = {"daemon": None}
            with patch.object(canary, "source_bindings", return_value={}), patch.object(canary, "LoopbackServices", return_value=Services()), patch.object(canary, "source"), patch.object(canary, "init_home"), patch.object(canary, "grant_loopback_provider_consent"), patch.object(canary, "start_daemon", return_value=process), patch.object(canary, "wait_for_daemon_ready", side_effect=canary.Failure("daemon_ready_timeout")), patch.object(canary, "stop_daemon", side_effect=stopped_nonzero):
                with self.assertRaisesRegex(canary.Failure, "daemon_ready_timeout"):
                    canary.execute(Path("/tmp/neoth"), root, home, source_path, evidence, Path("workflow.yml"), state)
            diagnostic = json.loads((evidence / "daemon-diagnostics.json").read_text(encoding="utf-8"))
            self.assertEqual(diagnostic["primary_failure"], "daemon_ready_timeout")
            self.assertEqual(diagnostic["primary_phase"], "readiness")
            self.assertEqual(diagnostic["stop_failure"], "daemon_stop_failed")
            self.assertEqual(diagnostic["loopback_failure"], "loopback_cleanup_failed")
            self.assertEqual(diagnostic["startup_cause"], {"stage": "unknown", "reason": "log_unavailable", "log_fingerprint_sha256": None})
            self.assertEqual(set(diagnostic["shutdown_progress"].values()), {"unavailable"})
            self.assertIsNone(state["daemon"])
            flags = canary.cleanup(root, home, source_path, root / "daemon.log", state["daemon"], evidence)
            self.assertTrue(flags["daemon_reaped"])
            self.assertEqual(canary.receipt_payload(None, "daemon_ready_timeout", flags, "0" * 40)["outcome"], "failed")

    def test_teardown_failures_remain_fatal_in_daemon_then_loopback_order(self):
        with self.assertRaisesRegex(canary.Failure, "daemon_stop_failed"):
            canary.raise_teardown_failure(canary.Failure("daemon_stop_failed"), canary.Failure("loopback_cleanup_failed"))
        with self.assertRaisesRegex(canary.Failure, "loopback_cleanup_failed"):
            canary.raise_teardown_failure(None, canary.Failure("loopback_cleanup_failed"))

    @unittest.skipUnless(canary.fcntl is not None, "Unix flock proof is hosted on Linux")
    def test_unlocked_pidfile_is_rejected_even_when_its_pid_is_live(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "neothd.pid").write_text(f"{os.getpid()}\n", encoding="utf-8")
            with self.assertRaisesRegex(canary.Failure, "daemon_pidfile_unlocked"):
                canary.require_daemon_pid_lock(self._Process(os.getpid()), home)

    def test_empty_poll_contract_rejects_send_and_provider_requests(self):
        import urllib.error
        import urllib.request
        server = canary.LoopbackServices()
        server.start()
        try:
            good = json.dumps({"after": 1, "limit": 1000, "offset": 0, "sort": "ASC", "with": ["chats"]}).encode()
            request = urllib.request.Request(f"http://127.0.0.1:{server.port}/api/v1/message/query?password={canary.PASSWORD}", data=good, method="POST")
            self.assertEqual(urllib.request.urlopen(request, timeout=5).status, 200)
            send = urllib.request.Request(f"http://127.0.0.1:{server.port}/api/v1/message/text", data=b"{}", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as sent:
                urllib.request.urlopen(send, timeout=5)
            self.assertEqual(sent.exception.code, 405)
            provider = urllib.request.Request(f"http://127.0.0.1:{server.port}/v1/chat/completions", data=b"{}", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(provider, timeout=5)
            self.assertEqual(refused.exception.code, 503)
            counts = server.counts()
            self.assertEqual(counts["empty_poll"], 1)
            self.assertEqual(counts["message_or_other_post"], 1)
            self.assertEqual(counts["provider_request"], 1)
        finally:
            self.assertTrue(server.stop())

    def test_strict_json_and_safe_unstarted_server_stop(self):
        with self.assertRaises(canary.Failure):
            canary.one_json(b'{"a":1,"a":2}', "duplicate")
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(canary.LoopbackServices().stop())
            path = Path(directory) / "openclaw.json"
            canary.source(path)
            self.assertEqual(json.loads(path.read_text())["channels"]["imessage"]["accounts"]["personal"]["cliPath"], "/usr/bin/imsg")


if __name__ == "__main__":
    unittest.main()
