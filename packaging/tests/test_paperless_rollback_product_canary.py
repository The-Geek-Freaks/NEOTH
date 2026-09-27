from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import paperless_rollback_product_canary as canary


class RollbackReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.restore_job = "paperless-restore-abcdef12-1234-4234-8234-123456789abc"
        self.current = b'{"schema_version":3}'
        self.restore_custody = b'{"schema_version":2,"operation":"paperless.restore"}'
        self.pointer = b'{"schema_version":1,"operation":"paperless.restore"}'
        self.preview = {"operation": "paperless.rollback", "restore_job_id": self.restore_job, "current_project": "restore-project", "rollback_project": "base-project", "current_install_receipt_sha256": hashlib.sha256(self.current).hexdigest(), "confirmation": "rollback:fixture"}
        self.receipt = {"operation": "paperless.rollback", "restore_job_id": self.restore_job, "current_project": "restore-project", "rollback_project": "base-project", "old_source_was_running": True, "authenticated_api_ready": True, "rollback_custody_ref": f".neoth-paperless-rollback-{self.restore_job}.v1.json", "rollback_custody_sha256": "a" * 64}

    def test_preview_requires_exact_generation_and_digest(self) -> None:
        self.assertEqual(canary.rollback_preview(self.preview, self.restore_job, "restore-project", "base-project", self.current), "rollback:fixture")
        for mutate in (
            lambda value: value.__setitem__("current_project", "foreign"),
            lambda value: value.__setitem__("current_install_receipt_sha256", "b" * 64),
            lambda value: value.pop("confirmation"),
        ):
            changed = json.loads(json.dumps(self.preview)); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(canary.Failure):
                canary.rollback_preview(changed, self.restore_job, "restore-project", "base-project", self.current)

    def test_receipt_requires_exact_custody_reference_and_ready_proof(self) -> None:
        self.assertEqual(canary.rollback_receipt(self.receipt, self.restore_job, "restore-project", "base-project"), (self.receipt["rollback_custody_ref"], "a" * 64))
        for mutate in (
            lambda value: value.__setitem__("authenticated_api_ready", False),
            lambda value: value.__setitem__("rollback_custody_ref", ".neoth-paperless-rollback-foreign.v1.json"),
            lambda value: value.__setitem__("rollback_custody_sha256", "G" * 64),
        ):
            changed = json.loads(json.dumps(self.receipt)); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(canary.Failure):
                canary.rollback_receipt(changed, self.restore_job, "restore-project", "base-project")

    def test_terminal_custody_rejects_raw_producer_or_pointer_changes(self) -> None:
        value = {"schema_version": 1, "operation": "paperless.rollback", "phase": "committed", "restore_job_id": self.restore_job, "restore_custody_sha256": hashlib.sha256(self.restore_custody).hexdigest(), "current_install_receipt_bytes": list(self.current), "current_snapshot_bytes": list(b'{"volume_set_id":"current"}'), "current_active_pointer": {"state": "present", "bytes": list(self.pointer), "sha256": hashlib.sha256(self.pointer).hexdigest()}, "current_project": "restore-project", "rollback_project": "base-project", "current": self._containers("current"), "old": self._containers("old"), "current_stop_attempted": True, "old_start_attempted": True, "readiness_attempted": True, "authenticated_api_ready": True, "pending_command": None}
        self._validate(value)
        for mutate in (
            lambda item: item.__setitem__("phase", "held"),
            lambda item: item["current_install_receipt_bytes"].__setitem__(0, 0),
            lambda item: item["current_active_pointer"].__setitem__("sha256", "b" * 64),
            lambda item: item.__setitem__("rollback_project", "foreign"),
            lambda item: item["current"].__setitem__(0, {"service": "webserver", "id": "f" * 64, "image_id": "sha256:foreign", "running": True}),
            lambda item: item["old"].__setitem__(1, {"service": "broker", "id": "e" * 64, "image_id": "sha256:foreign", "running": True}),
            lambda item: item.__setitem__("pending_command", {"action": "start", "id": "f" * 64}),
        ):
            changed = json.loads(json.dumps(value)); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(canary.Failure):
                self._validate(changed)
        with self.assertRaises(canary.Failure):
            self._validate(value, terminal_digest="b" * 64)
        changed = json.loads(json.dumps(value)); changed["restore_custody_sha256"] = "c" * 64
        with self.assertRaises(canary.Failure):
            self._validate(changed)

    def test_recovery_authority_accepts_only_derived_restore_or_exact_base(self) -> None:
        base_project = "neoth-paperless-abcdef123456"
        backup_job = "paperless-backup-" + "a" * 64
        generation = "abcdef12-1234-4234-8234-123456789abc"
        restore_project = canary.base.restore_project_name(base_project, backup_job, generation)
        observed = (restore_project, {}, (), generation)
        self.assertTrue(canary.trusted_restore_recovery(base_project, backup_job, observed))
        self.assertFalse(canary.trusted_restore_recovery(base_project, backup_job, (base_project, {}, (), generation)))
        self.assertFalse(canary.trusted_restore_recovery(base_project, backup_job, ("foreign", {}, (), generation)))
        self.assertTrue(canary.trusted_rollback_recovery(base_project, generation, (base_project, {}, (), generation)))
        self.assertFalse(canary.trusted_rollback_recovery(base_project, generation, (restore_project, {}, (), generation)))
        self.assertFalse(canary.trusted_rollback_recovery(base_project, generation, (base_project, {}, (), "12345678-1234-4234-8234-123456789abc")))

    def _validate(self, value: dict, terminal_digest: str | None = None) -> None:
        # Validator reads the persistent terminal receipt; isolate bytes without claiming a runtime lifecycle.
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); state = home / "paperless" / "state"; state.mkdir(parents=True)
            name = self.receipt["rollback_custody_ref"]
            (state / name).write_text(json.dumps(value), encoding="utf-8")
            os.chmod(state / name, 0o600)
            raw = (state / name).read_bytes()
            canary.validate_terminal_custody(home, name, terminal_digest or hashlib.sha256(raw).hexdigest(), hashlib.sha256(self.restore_custody).hexdigest(), self.restore_job, self.current, b'{"volume_set_id":"current"}', self.pointer, "restore-project", "base-project", self._containers("current"), self._containers("old"))

    def _containers(self, prefix: str) -> list[dict]:
        return [{"service": service, "id": f"{index:064x}", "image_id": f"sha256:{prefix}-{service}", "running": True} for index, service in enumerate(("webserver", "broker", "db"), start=1)]


if __name__ == "__main__":
    unittest.main()
