from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import converted_channel_relink_product_canary as canary


class ConvertedRelinkProductCanaryTests(unittest.TestCase):
    def test_one_json_rejects_malformed_multiple_or_non_object_output(self) -> None:
        for raw in (b"", b"{", b"[]", b"{}\n{}", b'{"a":1,"a":2}'):
            with self.subTest(raw=raw), self.assertRaises(canary.Failure):
                canary.one_json(raw)

    def test_json_output_requires_the_complete_public_schema_and_stable_identity(self) -> None:
        valid = {"channel": "imessage_bluebubbles", "account": "default", "relink_id": "a" * 64,
                 "state": "ready", "already_ready": False, "reload_requested": True}
        self.assertEqual(canary.validate_output(valid, already_ready=False), "a" * 64)
        for mutate in (
            lambda value: value.pop("reload_requested"),
            lambda value: value.__setitem__("extra", True),
            lambda value: value.__setitem__("relink_id", "not-an-id"),
            lambda value: value.__setitem__("state", "pending"),
        ):
            candidate = dict(valid); mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(canary.Failure):
                canary.validate_output(candidate, already_ready=False)
        retry = dict(valid); retry["already_ready"] = True
        with self.assertRaises(canary.Failure):
            canary.validate_output(retry, already_ready=True, expected_id="b" * 64)

    def test_ready_publication_requires_exact_route_ready_identity_and_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            route = json.dumps({"destinations": {"imessage_chat_guid": canary.TARGET}}).encode()
            credentials = b"NEOTH_CONF_ENCv1\nencrypted-private-pair"
            expected = {"pair_before_sha256": canary.pair_v1((True, b"{}"), (False, b"")),
                        "routing_before_sha256": canary.sha256(b""), "target_sha256": canary.sha256(canary.TARGET.encode()),
                        "request_material_sha256": canary.imessage_request_v1("http://127.0.0.1:1234", canary.PASSWORD, canary.TARGET, "+491701234567")}
            raw = {
                "credentials.yaml": credentials, "freedom.yaml": b"{}", "channel_routing.json": route,
                "channel_relinks.json": json.dumps({"schema_version": 1, "pending": [{"id": "a" * 64, "state": "ready", "bound_material_sha256": expected["request_material_sha256"], "completion_request_material_sha256": expected["request_material_sha256"], "destination": {"channel_id": "imessage_bluebubbles", "account_id": "default"}}]}).encode(),
                ".channel-relink-imessage.transaction.json": json.dumps({"version": 1, "pending_id": "a" * 64, "destination": {"channel_id": "imessage_bluebubbles", "account_id": "default"}, "phase": "routing_committed", **expected, "pair_after_sha256": canary.pair_v1((True, b"{}"), (True, credentials)), "routing_after_sha256": canary.sha256(route)}).encode(),
            }
            for name, body in raw.items(): (home / name).write_bytes(body)
            (home / canary.RELOAD_SENTINEL).write_text("ts_unix=1\n", encoding="utf-8")
            self.assertEqual(canary.require_ready_publication(home, "a" * 64, expected), raw)
            transaction_path = home / ".channel-relink-imessage.transaction.json"
            transaction = json.loads(transaction_path.read_text())
            for field in (*expected, "pair_after_sha256", "routing_after_sha256"):
                changed = dict(transaction); changed[field] = "0" * 64 if changed[field] != "0" * 64 else "1" * 64
                transaction_path.write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(field=field), self.assertRaisesRegex(canary.Failure, "relink_transaction_invalid"):
                    canary.require_ready_publication(home, "a" * 64, expected)
                transaction_path.write_text(json.dumps(transaction), encoding="utf-8")
            index_path = home / "channel_relinks.json"; index = json.loads(index_path.read_text())
            index["pending"][0]["bound_material_sha256"] = "0" * 64
            index_path.write_text(json.dumps(index), encoding="utf-8")
            with self.assertRaisesRegex(canary.Failure, "relink_ready_invalid"):
                canary.require_ready_publication(home, "a" * 64, expected)
            index_path.write_bytes(raw["channel_relinks.json"])
            (home / "credentials.yaml").write_bytes(b"plain-text-credentials")
            with self.assertRaisesRegex(canary.Failure, "credentials_not_encrypted"):
                canary.require_ready_publication(home, "a" * 64, expected)
            (home / "credentials.yaml").write_bytes(raw["credentials.yaml"])
            (home / "channel_routing.json").write_text('{"destinations":{"imessage_chat_guid":"wrong"}}', encoding="utf-8")
            with self.assertRaisesRegex(canary.Failure, "routing_target_invalid"):
                canary.require_ready_publication(home, "a" * 64, expected)

    def test_wrong_target_allows_only_the_pending_index_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "channel_relinks.json").write_text('{"pending":[{"state":"pending"}]}', encoding="utf-8")
            result = canary.require_wrong_target_pending(home)
            self.assertTrue(all(result.values()))
            (home / "credentials.yaml").write_text("private", encoding="utf-8")
            with self.assertRaisesRegex(canary.Failure, "wrong_target_publication_invalid"):
                canary.require_wrong_target_pending(home)

    def test_envelope_does_not_publish_the_secret_outside_the_private_input(self) -> None:
        value = json.loads(canary.envelope(1234))
        self.assertEqual(value["fields"]["password"], canary.PASSWORD)
        self.assertEqual(value["fields"]["url"], "http://127.0.0.1:1234")
        self.assertEqual(value["channel"], "imessage_bluebubbles")
        self.assertNotIn(canary.PASSWORD, json.dumps({"request_classes": ["ping", "target"]}))

    def test_cleanup_refuses_outside_or_symlink_paths_and_keeps_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"; root.mkdir(); home = root / "neoth-home"; home.mkdir()
            source = root / "openclaw.yaml"; source.write_text("fixture", encoding="utf-8")
            evidence = root / "evidence"; evidence.mkdir(); (evidence / "receipt-summary.json").write_text("{}", encoding="utf-8")
            flags = canary.cleanup_owned(root, home, source, evidence)
            self.assertTrue(all(flags.values()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"; root.mkdir(); evidence = root / "evidence"; evidence.mkdir()
            outside = Path(directory) / "outside"; outside.mkdir(); source = root / "openclaw.yaml"; source.symlink_to(outside, target_is_directory=True)
            flags = canary.cleanup_owned(root, root / "neoth-home", source, evidence)
            self.assertFalse(flags["source_removed"]); self.assertTrue(outside.exists())

    def test_hosted_guard_rejects_non_main_and_nonempty_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "product"; root.mkdir()
            original = dict(os.environ)
            try:
                os.environ.update({"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/feature", "GITHUB_SHA": "a" * 40, "RUNNER_TEMP": directory})
                with self.assertRaises(canary.Failure):
                    canary.require_hosted(root, root / "neoth-home", root / "openclaw.yaml", root / "evidence", root / "receipt" / "receipt.json")
                os.environ["GITHUB_REF"] = "refs/heads/main"; (root / "residue").write_text("x", encoding="utf-8")
                with self.assertRaisesRegex(canary.Failure, "isolated_root_invalid"):
                    canary.require_hosted(root, root / "neoth-home", root / "openclaw.yaml", root / "evidence", root / "receipt" / "receipt.json")
            finally:
                os.environ.clear(); os.environ.update(original)

    def test_loopback_rejects_unexpected_requests_without_recording_secret_values(self) -> None:
        server = canary.LoopbackBlueBubbles(); port = server.start()
        try:
            with self.assertRaises(Exception):
                # A malformed request must not be accepted as a product probe.
                import urllib.request
                urllib.request.urlopen(f"http://127.0.0.1:{port}/unexpected?password=not-the-secret", timeout=5)
            counts = server.counts()
            self.assertEqual(counts["unexpected_get"], 1)
            self.assertEqual(counts["post"], 0)
            self.assertNotIn("not-the-secret", json.dumps(counts))
        finally:
            self.assertTrue(server.stop())


if __name__ == "__main__":
    unittest.main()
