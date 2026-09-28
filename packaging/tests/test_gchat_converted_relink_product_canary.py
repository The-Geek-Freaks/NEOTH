"""Static contract tests for the hosted Google Chat relink canary; not run locally."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gchat_converted_relink_product_canary as canary


class GChatRelinkCanaryTests(unittest.TestCase):
    def test_refusal_failure_evidence_is_fixed_numeric_and_redacted(self):
        counts = {name: offset for offset, name in enumerate(canary.REFUSAL_COUNTERS)}
        evidence = canary.refusal_probe_evidence("wrong_target", counts)
        self.assertEqual(evidence, {"stage": "wrong_target", "counters": counts})
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(canary.EMAIL, rendered)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("BEGIN PRIVATE KEY", rendered)
        self.assertNotIn("exception", rendered)
        canary.validate_receipt_redaction(rendered)
        for forbidden in (canary.EMAIL, "http://127.0.0.1:1", "https://example.invalid", "raw exception text", "BEGIN PRIVATE KEY"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaisesRegex(canary.Failure, "receipt_secret_leak"):
                    canary.validate_receipt_redaction(json.dumps({"failure": forbidden}))
        for invalid in (
            {**counts, "extra": 1},
            {name: (True if name == "token" else value) for name, value in counts.items()},
            {name: (-1 if name == "token" else value) for name, value in counts.items()},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(canary.Failure, "refusal_evidence_invalid"):
                    canary.refusal_probe_evidence("wrong_target", invalid)
        with self.assertRaisesRegex(canary.Failure, "refusal_evidence_invalid"):
            canary.refusal_probe_evidence("untrusted-stage", counts)

    def test_strict_google_chat_envelope_and_public_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key.json"
            payload = json.loads(canary.envelope(key))
            self.assertEqual(payload, {"schema_version": 1, "channel": "gchat", "fields": {"url": str(key), "server": canary.SUBSCRIPTION, "allowed_sender": canary.ALLOWED_SENDER}})
            arguments = canary.argv(Path("/bin/neoth"), Path("/tmp/openclaw.json"), canary.SPACE)
            self.assertEqual(arguments[-4:], ["--source-account", "work", "--target", canary.SPACE])
            self.assertIn("google_chat", arguments)

    def test_ready_output_rejects_wrong_channel_identity_and_retry(self):
        good = {"channel": "gchat", "account": "default", "relink_id": "a" * 64, "state": "ready", "already_ready": False, "reload_requested": True}
        self.assertEqual(canary.validate_output(good, False), "a" * 64)
        for value in ({**good, "channel": "google_chat"}, {**good, "channel": "imessage_bluebubbles"}, {**good, "relink_id": "bad"}, {**good, "state": "pending"}, {**good, "extra": True}):
            with self.subTest(value=value):
                with self.assertRaises(canary.Failure):
                    canary.validate_output(value, False)
        with self.assertRaises(canary.Failure):
            canary.validate_output({**good, "already_ready": True}, True, "b" * 64)

    def test_material_commitment_uses_service_account_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "service-account.json"
            key.write_bytes(b"first")
            first = canary.material_commitment(key, canary.SPACE)
            # Independent vector from relink.rs: canonical gchat wire ID,
            # exact target, then three little-endian length-framed fields.
            self.assertEqual(first, "2e42f746a3d15efd7dbcbdbbe1d385673c56e11ad8f6fd8e013f00054dea69f8")
            key.rename(Path(directory) / "renamed.json")
            renamed = Path(directory) / "renamed.json"
            self.assertEqual(first, canary.material_commitment(renamed, canary.SPACE))
            renamed.write_bytes(b"second")
            self.assertNotEqual(first, canary.material_commitment(renamed, canary.SPACE))

    def test_ready_files_requires_external_expected_hashes_and_gchat_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "neoth-home"
            home.mkdir()
            source = root / "openclaw.json"
            source.write_text("{}", encoding="utf-8")
            key = root / "service-account.json"
            key.write_text("{}", encoding="utf-8")
            (home / "freedom.yaml").write_text("freedom", encoding="utf-8")
            (home / "credentials.yaml").write_bytes(b"NEOTH_CONF_ENCv1\ncredentials")
            route = {"destinations": {"gchat_space": canary.SPACE}}
            route_raw = json.dumps(route, indent=2).encode()
            (home / "channel_routing.json").write_bytes(route_raw)
            expected = canary.ExpectedReceipt(canary.material_commitment(key, canary.SPACE), "b" * 64, "c" * 64, canary.pair_commitment(home), canary.sha256_bytes(route_raw), canary.digest(source))
            identity = "a" * 64
            entry = {"id": identity, "destination": canary.DESTINATION, "state": "ready", "completion_request_material_sha256": expected.material_sha256, "bound_material_sha256": expected.material_sha256, "source_set_sha256": "d" * 64}
            (home / "channel_relinks.json").write_text(json.dumps({"schema_version": 1, "pending": [entry]}), encoding="utf-8")
            transaction = {"version": 1, "pending_id": identity, "destination": canary.DESTINATION, "target_sha256": canary.sha256_bytes(canary.SPACE.encode()), "request_material_sha256": expected.material_sha256, "pair_before_sha256": expected.pair_before_sha256, "routing_before_sha256": expected.routing_before_sha256, "pair_after_sha256": expected.pair_after_sha256, "routing_after_sha256": expected.routing_after_sha256, "phase": "routing_committed"}
            (home / ".channel-relink-google-chat.transaction.json").write_text(json.dumps(transaction), encoding="utf-8")
            (home / canary.RELOAD).write_text("reload", encoding="utf-8")
            self.assertIn("credentials.yaml", canary.ready_files(home, identity, expected))
            changes = (("material_sha256", "e" * 64), ("pair_before_sha256", "e" * 64), ("routing_before_sha256", "e" * 64), ("pair_after_sha256", "e" * 64), ("routing_after_sha256", "e" * 64))
            for attribute, replacement in changes:
                with self.subTest(attribute=attribute):
                    mutated = canary.ExpectedReceipt(**{**expected.__dict__, attribute: replacement})
                    with self.assertRaises(canary.Failure):
                        canary.ready_files(home, identity, mutated)
            (home / "channel_routing.json").write_text(json.dumps({"destinations": {"google_chat": canary.SPACE}}), encoding="utf-8")
            with self.assertRaises(canary.Failure):
                canary.ready_files(home, identity, expected)

    def test_fake_rejects_wrong_bearer_and_stop_is_safe_before_start(self):
        with tempfile.TemporaryDirectory() as directory:
            server = canary.FakeGoogle(Path(directory) / "public.pem")
            self.assertTrue(server.stop())
        with tempfile.TemporaryDirectory() as directory:
            server = canary.FakeGoogle(Path(directory) / "public.pem")
            server.start()
            try:
                import urllib.request
                with self.assertRaises(Exception):
                    urllib.request.urlopen(f"http://127.0.0.1:{server.port}/v1/{canary.SUBSCRIPTION}", timeout=5)
                self.assertEqual(server.counts()["bad_bearer"], 1)
            finally:
                self.assertTrue(server.stop())

    def test_source_is_googlechat_custody_only_and_json_is_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openclaw.json"
            canary.source(path)
            value = json.loads(path.read_text())
            self.assertEqual(value["channels"]["googlechat"]["accounts"]["work"]["serviceAccount"]["id"], "CANARY")
        with self.assertRaises(canary.Failure):
            canary.one_json(b'{"a":1,"a":2}')


if __name__ == "__main__":
    unittest.main()
