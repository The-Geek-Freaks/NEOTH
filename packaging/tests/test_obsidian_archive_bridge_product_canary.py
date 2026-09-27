from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import obsidian_archive_bridge_product_canary as canary

class ArchiveBridgeCanaryContractTests(unittest.TestCase):
    def test_minimal_config_admits_only_accountless_active_obsidian(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, vault = Path(directory) / "home", Path(directory) / "vault"; home.mkdir(); vault.mkdir()
            canary.write_bridge_config(home, vault)
            value = __import__("json").loads((home / "freedom.yaml").read_text())
        account = value["context_connectors"]["registered_accounts"]
        self.assertEqual(len(account), 1)
        self.assertEqual(account[0]["configuration"]["connector_id"], "obsidian")
        self.assertIsNone(account[0]["configuration"]["account_id"])
        self.assertEqual(account[0]["lifecycle"], "active")
        self.assertTrue(value["obsidian_vault_reader_enabled"])
        self.assertTrue(value["obsidian_archive_bridge_enabled"])
        self.assertTrue(value["onboarding_complete"])

    def test_hosted_guard_rejects_non_isolated_or_non_main_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"; root.mkdir(); receipt = root / "receipt" / "receipt.json"; receipt.parent.mkdir()
            original = dict(os.environ)
            try:
                os.environ.update({"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/feature", "GITHUB_SHA": "a" * 40, "RUNNER_TEMP": directory})
                with self.assertRaises(canary.Failure): canary.require_hosted(root, root / "neoth-home", root / "vault", receipt)
            finally:
                os.environ.clear(); os.environ.update(original)

    def test_ownership_marker_is_exactly_bound_to_bundle_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); asset, slot = root / "asset", root / "slot"; asset.mkdir(); slot.mkdir()
            (asset / "main.js").write_bytes(b"main")
            (asset / "manifest.json").write_bytes(b'{"version":"0.2.0"}\n')
            for name in ("main.js", "manifest.json"):
                (slot / name).write_bytes((asset / name).read_bytes())
            (slot / "ownership.json").write_bytes(canary.ownership_bytes(asset))
            canary.assert_current_payload(slot, asset)
            for malformed in (b"{}\n", canary.ownership_bytes(asset).replace(b"a", b"b", 1)):
                (slot / "ownership.json").write_bytes(malformed)
                with self.subTest(marker=malformed), self.assertRaises(canary.Failure):
                    canary.assert_current_payload(slot, asset)

    def test_import_effect_requires_one_bound_groundtruth_and_dedup_row(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); database = home / "views.db"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE obsidian_archive_bridge_dedup_v1 (source_id TEXT NOT NULL, source_revision TEXT NOT NULL, PRIMARY KEY(source_id, source_revision)) WITHOUT ROWID")
            connection.execute("CREATE TABLE idx_groundtruth (statement TEXT, source TEXT, scope TEXT, revoked_at INTEGER)")
            connection.execute("INSERT INTO obsidian_archive_bridge_dedup_v1 VALUES ('opaque-source', 'opaque-revision')")
            connection.execute("INSERT INTO idx_groundtruth VALUES ('fixture', 'import:obsidian', 'obsidian-archive-bridge', NULL)")
            connection.commit(); connection.close()
            (home / "obsidian_archive_bridge_state.v1.json").write_text('{"opaque-source":"opaque-revision"}', encoding="utf-8")
            canary.observe_import_effect(home, b"fixture")
            with self.assertRaises(canary.Failure): canary.observe_import_effect(home, b"different")

    def test_daemon_diagnostic_never_echoes_secret_bearing_stderr(self) -> None:
        raw = b"startup failed token=do-not-emit\n"
        value = canary.redacted_daemon_diagnostic("daemon_exited_early", 17, raw)
        encoded = __import__("json").dumps(value)
        self.assertEqual(value["reason"], "daemon_exited_early")
        self.assertEqual(value["returncode"], 17)
        self.assertNotIn("do-not-emit", encoded)
        self.assertNotIn("token=", encoded)
        self.assertIn("log_sha256", value)
        self.assertEqual(value["classification"], "unclassified")
        classified = canary.redacted_daemon_diagnostic("daemon_exited_early", 1, b"GOLD-ADAPT-OH-03: onboarding incomplete secret=never-output")
        self.assertEqual(classified["classification"], "onboarding_incomplete")
        self.assertNotIn("never-output", __import__("json").dumps(classified))

if __name__ == "__main__": unittest.main()
