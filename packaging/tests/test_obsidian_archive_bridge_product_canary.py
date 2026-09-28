from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
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

    def test_hosted_guard_rejects_a_root_that_would_exceed_bridge_socket_cap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ("x" * 55); root.mkdir()
            original = dict(os.environ)
            try:
                os.environ.update({"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40, "RUNNER_TEMP": directory})
                with self.assertRaisesRegex(canary.Failure, "bridge_socket_path_too_long"):
                    canary.require_hosted(root, root / "neoth-home", root / "vault", root / "receipt" / "receipt.json")
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
        self.assertEqual(value["last_milestone"], "not_observed")
        self.assertNotIn("do-not-emit", encoded)
        self.assertNotIn("token=", encoded)
        self.assertIn("log_sha256", value)
        self.assertEqual(value["classification"], "unclassified")
        classified = canary.redacted_daemon_diagnostic("daemon_exited_early", 1, b"GOLD-ADAPT-OH-03: onboarding incomplete secret=never-output")
        self.assertEqual(classified["classification"], "onboarding_incomplete")
        self.assertNotIn("never-output", __import__("json").dumps(classified))

    def test_daemon_diagnostic_uses_closed_source_categories_and_observed_milestones(self) -> None:
        cases = (
            (b"operator hooks at /private/hook rejected token=hidden", "startup_hooks_rejected"),
            (b"establish instance WAL HMAC authority before recovery scan at /private/key", "wal_authority_rejected"),
            (b"select active Obsidian connector authority for Archive Bridge: hidden", "bridge_authority_rejected"),
            (b"existing WAL master key is absent at /private/key hidden", "wal_master_key_missing"),
            (b"parse bridge pairing record: hidden", "bridge_pairing_record_invalid"),
            (b"bind existing private Obsidian Archive Bridge IPC: hidden", "bridge_ipc_bind_failed"),
            (b"start daemon membership/audit RPC: hidden", "membership_audit_rpc_start_failed"),
            (b"connector-control operator_id is incompatible with SubjectId: hidden", "connector_control_subject_invalid"),
            (b"consent gate (V03-08 + A-2): hidden", "provider_consent_rejected"),
            (b"load skill registry for daemon instance at /private/skills", "skill_registry_load_failed"),
        )
        for raw, expected in cases:
            with self.subTest(expected=expected):
                value = canary.redacted_daemon_diagnostic("daemon_exited_early", 1, raw)
                self.assertEqual(value["classification"], expected)
                self.assertNotIn("hidden", __import__("json").dumps(value))
                self.assertNotIn("/private", __import__("json").dumps(value))
        milestone = canary.redacted_daemon_diagnostic(
            "daemon_exited_early", 1,
            b"loaded freedom.yaml\nBOOT event written and fsynced\nobsidian vault reader cron enabled\nskill registry primed for daemon\nTRAIL-04: ViewsExecutor ready (writer:1 + readers:4)",
        )
        self.assertEqual(milestone["last_milestone"], "views_executor_ready")
        full_start = canary.redacted_daemon_diagnostic(
            "daemon_exited_early", 1,
            b"loaded freedom.yaml\nBOOT event written and fsynced\nskill registry primed for daemon\n"
            b"TRAIL-04: ViewsExecutor ready (writer:1 + readers:4)\nobsidian vault reader cron enabled",
        )
        self.assertEqual(full_start["last_milestone"], "obsidian_reader_started")

    def test_daemon_diagnostic_prefers_inner_rpc_failures_without_retaining_error_text(self) -> None:
        cases = (
            (b"mint mandatory daemon internal-RPC token: write audit-RPC token /private/token: File exists", "audit_rpc_token_write_failed"),
            (b"mint mandatory daemon internal-RPC token: atomically replace audit-RPC token /private/token: denied", "audit_rpc_token_write_failed"),
            (b"mint mandatory daemon internal-RPC token: OS RNG unavailable", "audit_rpc_token_mint_failed"),
            (b"bind mandatory daemon internal-RPC listener: create exclusive audit-RPC runtime directory /private/socket", "audit_rpc_runtime_create_failed"),
            (b"bind mandatory daemon internal-RPC listener: create private audit-RPC runtime root /private/root", "audit_rpc_root_create_failed"),
            (b"bind mandatory daemon internal-RPC listener: create private audit-RPC home namespace /private/home", "audit_rpc_namespace_create_failed"),
            (b"bind mandatory daemon internal-RPC listener: scan private audit-RPC home namespace /private/home", "audit_rpc_stale_scan_failed"),
            (b"bind mandatory daemon internal-RPC listener: verify audit-RPC runtime directory /private/runtime", "audit_rpc_runtime_verify_failed"),
            (b"bind mandatory daemon internal-RPC listener: bind audit-RPC Unix socket /private/socket", "audit_rpc_socket_bind_failed"),
            (b"bind mandatory daemon internal-RPC listener: set audit-RPC socket mode 0600 on /private/socket", "audit_rpc_socket_mode_failed"),
            (b"bind mandatory daemon internal-RPC listener: verify audit-RPC socket /private/socket", "audit_rpc_socket_verify_failed"),
            (b"bind mandatory daemon internal-RPC listener: unknown reason", "audit_rpc_listener_bind_failed"),
            (b"write mandatory daemon internal-RPC discovery sidecar: unknown reason", "audit_rpc_sidecar_write_failed"),
            (b"commit daemon internal-RPC endpoint to PID lock: unknown reason", "audit_rpc_pid_commit_failed"),
        )
        for outer in (b"start daemon membership/audit RPC", b"start mandatory daemon audit RPC"):
            for inner, expected in cases:
                with self.subTest(outer=outer, expected=expected):
                    raw = outer + b": " + inner + b" password=never-persist\n"
                    value = canary.redacted_daemon_diagnostic("daemon_exited_early", 1, raw)
                    self.assertEqual(value["classification"], expected)
                    encoded = __import__("json").dumps(value)
                    self.assertNotIn("/private", encoded)
                    self.assertNotIn("never-persist", encoded)
                    self.assertNotIn("File exists", encoded)

    def test_first_setup_requires_init_to_create_private_identity_without_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            calls: list[list[str]] = []
            state: dict = {"init_diagnostics": []}
            def fake_run(argv: list[str], **_: object) -> object:
                calls.append(argv)
                (home / "wal").mkdir()
                key = home / "wal" / "master.key"
                key.write_bytes(b"k" * 32); key.chmod(0o600)
                return canary.subprocess.CompletedProcess(argv, 0, b"initialized", b"")
            with mock.patch.object(canary.subprocess, "run", side_effect=fake_run):
                identity = canary.initialize_fresh_home(Path("/product/neoth"), home, {}, state)
            self.assertEqual(identity, b"k" * 32)
            self.assertEqual(calls, [["/product/neoth", "init", "--non-interactive", "--cli", "--accept-license", "--operator-id", "archive-bridge-canary", "--provider", "skip"]])
            self.assertEqual(state["init_diagnostics"], [])

    def test_first_setup_rejects_preexisting_state_and_missing_init_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            state: dict = {"init_diagnostics": []}
            (home / "freedom.yaml").write_bytes(b"prior")
            with mock.patch.object(canary.subprocess, "run") as command:
                with self.assertRaisesRegex(canary.Failure, "init_home_not_fresh"):
                    canary.initialize_fresh_home(Path("/product/neoth"), home, {}, state)
                command.assert_not_called()
            (home / "freedom.yaml").unlink()
            completed = canary.subprocess.CompletedProcess([], 0, b"success without key", b"")
            with mock.patch.object(canary.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(canary.Failure, "init_identity_invalid"):
                    canary.initialize_fresh_home(Path("/product/neoth"), home, {}, state)

    def test_initialization_records_redacted_nonzero_and_timeout_subprocess_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            state: dict = {"init_diagnostics": []}
            failed = canary.subprocess.CompletedProcess([], 23, b"first-install home changed after final fresh-state inspection: /private/interface.lock", b"token=never-persist")
            with mock.patch.object(canary.subprocess, "run", return_value=failed):
                with self.assertRaisesRegex(canary.Failure, "command_failed"):
                    canary.initialize_fresh_home(Path("/product/neoth"), home, {}, state)
            diagnostic = state["init_diagnostics"].pop()
            self.assertEqual(diagnostic["reason"], "exited_nonzero")
            self.assertEqual(diagnostic["classification"], "interface_lock_residue")
            self.assertEqual(diagnostic["returncode"], 23)
            encoded = __import__("json").dumps(diagnostic)
            self.assertNotIn("/private", encoded); self.assertNotIn("never-persist", encoded)
            similarly_named = canary.redacted_init_diagnostic(
                "exited_nonzero", 23,
                b"first-install home changed after final fresh-state inspection: /private/interface.lock.extra",
            )
            self.assertEqual(similarly_named["classification"], "home_changed_after_inspection")
            early_residue = canary.redacted_init_diagnostic(
                "exited_nonzero", 23,
                b"unrecognised NEOTH home residue blocks first-install identity provisioning: /private/interface.lock",
            )
            self.assertEqual(early_residue["classification"], "interface_lock_residue")
            timeout = canary.subprocess.TimeoutExpired([], 45, output=b"first-install WAL identity changed after initial inspection /private/home", stderr=b"key=never-persist")
            with mock.patch.object(canary.subprocess, "run", side_effect=timeout):
                with self.assertRaisesRegex(canary.Failure, "command_failed"):
                    canary.initialize_fresh_home(Path("/product/neoth"), home, {}, state)
            diagnostic = state["init_diagnostics"].pop()
            self.assertEqual(diagnostic["reason"], "timed_out")
            self.assertEqual(diagnostic["classification"], "identity_changed_before_provision")
            self.assertIsNone(diagnostic["returncode"])
            encoded = __import__("json").dumps(diagnostic)
            self.assertNotIn("/private", encoded); self.assertNotIn("never-persist", encoded)

    def test_first_setup_rejects_malformed_or_public_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); (home / "wal").mkdir()
            key = home / "wal" / "master.key"
            key.write_bytes(b"malformed"); key.chmod(0o600)
            with self.assertRaisesRegex(canary.Failure, "init_identity_invalid"):
                canary.observe_init_identity(home)
            key.write_bytes(b"k" * 32); key.chmod(0o644)
            with self.assertRaisesRegex(canary.Failure, "init_identity_invalid"):
                canary.observe_init_identity(home)

if __name__ == "__main__": unittest.main()
