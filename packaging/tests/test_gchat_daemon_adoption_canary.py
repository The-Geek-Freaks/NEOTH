from __future__ import annotations

import http.client
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gchat_daemon_adoption_canary as canary
import gchat_converted_relink_product_canary as cli


class Process:
    def poll(self):
        return None


class Provider:
    def __init__(self) -> None:
        self.value = {
            "ping": 0, "target": 0, "wrong_target": 0, "empty_poll": 0,
            "invalid_poll": 0, "provider_request": 0, "message_or_other_post": 0,
            "unexpected": 0,
        }

    def counts(self) -> dict[str, int]:
        return dict(self.value)


class GChatDaemonAdoptionCanaryTests(unittest.TestCase):
    def request(self, server: canary.LiveFakeGoogle, method: str, path: str, body: bytes = b"", bearer: bool = True) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=3)
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        if bearer:
            headers["Authorization"] = "Bearer canary-access-token"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        return response.status, json.loads(raw)

    def ready_fixture(self, root: Path) -> tuple[Path, str, cli.ExpectedReceipt]:
        home = root / "neoth-home"
        home.mkdir()
        (root / "openclaw.json").write_text("{}\n", encoding="utf-8")
        (home / "freedom.yaml").write_text("wal:\n  encryption: none\n", encoding="utf-8")
        (home / "credentials.yaml").write_text("gchat_service_account_json: fixture\n", encoding="utf-8")
        route_raw = b'{"destinations":{"gchat_space":"spaces/AAAA_NEOTH_CANARY"}}'
        (home / "channel_routing.json").write_bytes(route_raw)
        identity = "a" * 64
        expected = cli.ExpectedReceipt(
            material_sha256="b" * 64,
            pair_before_sha256="c" * 64,
            routing_before_sha256="d" * 64,
            pair_after_sha256=cli.pair_commitment(home),
            routing_after_sha256=cli.sha256_bytes(route_raw),
            source_sha256=cli.digest(root / "openclaw.json"),
        )
        entry = {
            "id": identity, "state": "ready", "destination": cli.DESTINATION,
            "completion_request_material_sha256": expected.material_sha256,
            "bound_material_sha256": expected.material_sha256, "source_set_sha256": "e" * 64,
        }
        (home / "channel_relinks.json").write_text(json.dumps({"pending": [entry]}), encoding="utf-8")
        transaction = {
            "version": 1, "pending_id": identity, "destination": cli.DESTINATION,
            "target_sha256": cli.sha256_bytes(cli.SPACE.encode()),
            "request_material_sha256": expected.material_sha256,
            "pair_before_sha256": expected.pair_before_sha256,
            "routing_before_sha256": expected.routing_before_sha256,
            "pair_after_sha256": expected.pair_after_sha256,
            "routing_after_sha256": expected.routing_after_sha256,
            "phase": "routing_committed",
        }
        (home / ".channel-relink-google-chat.transaction.json").write_text(json.dumps(transaction), encoding="utf-8")
        return home, identity, expected

    def test_live_fake_google_accepts_only_authenticated_empty_pull(self) -> None:
        server = canary.LiveFakeGoogle()
        server.start()
        try:
            status, body = self.request(server, "POST", f"/v1/{cli.SUBSCRIPTION}:pull", b'{"maxMessages":10}')
            self.assertEqual((status, body), (200, {}))
            status, _ = self.request(server, "POST", f"/v1/{cli.SUBSCRIPTION}:pull", b'{"maxMessages":10}', bearer=False)
            self.assertEqual(status, 401)
            self.assertEqual(server.counts()["pull"], 1)
            self.assertEqual(server.counts()["bad_bearer"], 1)
        finally:
            self.assertTrue(server.stop())

    def test_live_fake_google_rejects_ack_send_nonempty_and_bad_pull(self) -> None:
        server = canary.LiveFakeGoogle()
        server.start()
        try:
            server.pull_response = {"receivedMessages": [{}]}
            self.assertEqual(self.request(server, "POST", f"/v1/{cli.SUBSCRIPTION}:pull", b'{"maxMessages":10}')[0], 200)
            self.assertEqual(self.request(server, "POST", f"/v1/{cli.SUBSCRIPTION}:acknowledge", b"{}")[0], 405)
            self.assertEqual(self.request(server, "POST", "/v1/spaces/AAAA/messages", b"{}")[0], 405)
            self.assertEqual(self.request(server, "POST", f"/v1/{cli.SUBSCRIPTION}:pull", b"{}")[0], 400)
            counts = server.counts()
            self.assertEqual(counts["nonempty_pull_response"], 1)
            self.assertEqual(counts["acknowledge"], 1)
            self.assertEqual(counts["message_post"], 1)
            self.assertEqual(counts["invalid_pull"], 1)
        finally:
            self.assertTrue(server.stop())

    def test_validate_ready_accepts_reload_sentinel_race(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home, identity, expected = self.ready_fixture(Path(raw))
            durable = canary.validate_ready(home, identity, expected)
            (home / cli.RELOAD).write_text("reload\n", encoding="utf-8")
            self.assertEqual(canary.validate_ready(home, identity, expected), durable)
            (home / cli.RELOAD).unlink()
            self.assertEqual(canary.validate_ready(home, identity, expected), durable)

    def test_retry_wait_requires_live_daemon_and_consumed_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            (home / cli.RELOAD).write_text("reload\n", encoding="utf-8")
            with patch.object(canary.time, "monotonic", side_effect=[0, 0, 26]), patch.object(canary.time, "sleep"):
                with self.assertRaisesRegex(canary.Failure, "retry_reload_not_consumed"):
                    canary.wait_for_reload_consumption(home, Process())
            (home / cli.RELOAD).unlink()
            canary.wait_for_reload_consumption(home, Process())

    def test_pending_window_rejects_pull_before_ready(self) -> None:
        server = canary.LiveFakeGoogle()
        before = {name: 0 for name in canary.TRAFFIC_COUNTERS}
        after = dict(before)
        after["pull"] = 1
        with patch.object(server, "counts", side_effect=[before, after]):
            with self.assertRaisesRegex(canary.Failure, "pending_target_pulled"):
                canary.observe_pending_no_pull(Process(), server, seconds=1)

    def test_reload_adoption_requires_pull_then_sentinel_removal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            server = canary.LiveFakeGoogle()
            counts = {name: 0 for name in canary.TRAFFIC_COUNTERS}
            counts["pull"] = 1
            (home / cli.RELOAD).write_text("reload\n", encoding="utf-8")
            with patch.object(server, "counts", return_value=counts), patch.object(canary.time, "monotonic", side_effect=[0, 0, 26]), patch.object(canary.time, "sleep"):
                with self.assertRaisesRegex(canary.Failure, "daemon_adoption_timeout"):
                    canary.wait_for_reload_adoption(home, Process(), server, 0)
            (home / cli.RELOAD).unlink()
            with patch.object(server, "counts", return_value=counts):
                canary.wait_for_reload_adoption(home, Process(), server, 0)

    def test_retry_traffic_allows_periodic_pull_only(self) -> None:
        server, provider = canary.LiveFakeGoogle(), Provider()
        for event, count in (("token", 3), ("subscription", 2), ("space", 1), ("wrong_space", 1), ("pull", 4)):
            for _ in range(count):
                server.record(event)
        self.assertEqual(canary.validate_traffic(provider, server)["pull"], 4)
        server.record("acknowledge")
        with self.assertRaisesRegex(canary.Failure, "daemon_traffic_contract_invalid"):
            canary.validate_traffic(provider, server)

    def test_source_bindings_include_imported_and_live_adoption_paths(self) -> None:
        workflow = Path(".github/workflows/gchat-live-regressions.yml").absolute()
        bindings = canary.source_bindings(workflow)
        for path in (
            "packaging/gchat_daemon_adoption_canary.py",
            "packaging/tests/test_gchat_daemon_adoption_canary.py",
            "packaging/gchat_converted_relink_product_canary.py",
            "packaging/bluebubbles_daemon_adoption_canary.py",
            "SRC/neothd/src/channels/gchat.rs",
            "SRC/neothd/src/daemon/audit_rpc/server.rs",
            "SRC/neothd/src/wal/writer.rs",
            "SRC/neoth-openclaw-custody/Cargo.toml",
            "SRC/neoth-openclaw-custody/src/lib.rs",
            "SRC/neoth-openclaw-custody/src/pinned_inventory.rs",
            "SRC/neoth-openclaw-custody/src/pinned_schema.rs",
            "SRC/neoth-openclaw-custody/src/fixtures/pinned_channel_inventory_v1.json",
            "SRC/neoth-openclaw-custody/src/fixtures/openclaw_upstream_evidence_v1.json",
            "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_v1.json",
            "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_migration_policy_v1.json",
        ):
            self.assertIn(path, bindings)


if __name__ == "__main__":
    unittest.main()
