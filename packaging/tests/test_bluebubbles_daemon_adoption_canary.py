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

        def poll(self) -> int | None:
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
            canary.grant_loopback_provider_consent(binary, env)
        invoked.assert_called_once_with([str(binary), "--output", "json", "consent", "grant", "openai_compat"], env)

    def test_loopback_provider_consent_rejects_cli_failure_or_unpersisted_authority(self):
        binary = Path("/tmp/neoth")
        with patch.object(canary, "command", return_value=subprocess.CompletedProcess([], 1, b"", b"")):
            with self.assertRaisesRegex(canary.Failure, "provider_consent_grant_failed"):
                canary.grant_loopback_provider_consent(binary, {})
        incomplete = {"provider": "openai_compat", "status": "applied", "authority_persisted": False, "failure": None}
        with patch.object(canary, "command", return_value=subprocess.CompletedProcess([], 0, json.dumps(incomplete).encode(), b"")):
            with self.assertRaisesRegex(canary.Failure, "provider_consent_grant_invalid"):
                canary.grant_loopback_provider_consent(binary, {})

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
