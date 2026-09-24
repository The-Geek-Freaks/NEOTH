"""Pure helper checks for the hosted compiled-product bootstrap canary."""
from __future__ import annotations

import sys
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import n8n_product_bootstrap_canary as canary


class ProductReceiptTests(unittest.TestCase):
    def test_product_output_requires_ready_and_nonempty_job(self) -> None:
        job = "12345678-1234-7234-8234-123456789abc"
        self.assertEqual(canary.validate_product({"job_id": job, "state": "ready", "failure_code": None}), job)
        for row in ({"job_id": "", "state": "ready", "failure_code": None}, {"job_id": job, "state": "failed", "failure_code": None}, {"job_id": job, "state": "ready", "failure_code": "x"}):
            with self.subTest(row=row):
                with self.assertRaises(canary.Failure): canary.validate_product(row)

    def test_status_rejects_wrong_endpoint_or_incomplete_progress(self) -> None:
        job = "12345678-1234-7234-8234-123456789abc"
        status = {"job": {"id": job, "state": "ready", "completed_steps": 4, "total_steps": 4, "failure_code": None}, "configured_endpoint": "http://127.0.0.1:5681", "api_key_present": True}
        canary.validate_status(status, job, 5681)
        status["job"]["completed_steps"] = 3
        with self.assertRaisesRegex(canary.Failure, "status_progress_invalid"): canary.validate_status(status, job, 5681)

    def test_custody_rejects_foreign_runtime_or_noncanonical_volume(self) -> None:
        job, digest, identifier, volume = "12345678-1234-7234-8234-123456789abc", "a" * 64, "b" * 64, "neoth_n8n_" + "c" * 32
        boot = {"schema_version": 2, "phase": "Ready", "job_id": job, "manifest_sha256": digest, "volume_name": volume, "bootstrap_container_id": identifier, "runtime_container_id": identifier, "host_port": 5681, "pinned_image": canary.IMAGE}
        runtime = {"schema_version": 2, "phase": "Ready", "job_id": job, "manifest_sha256": digest, "container_id": identifier, "container_name": "neoth-n8n", "host_port": 5681, "volume": volume, "image": canary.IMAGE}
        self.assertEqual(canary.validate_custody(boot, runtime, job, 5681), (volume, identifier, identifier))
        runtime["manifest_sha256"] = "f" * 64
        with self.assertRaisesRegex(canary.Failure, "custody_manifest_mismatch"):
            canary.validate_custody(boot, runtime, job, 5681)
        runtime["manifest_sha256"] = digest
        runtime["container_name"] = "foreign"
        with self.assertRaises(canary.Failure): canary.validate_custody(boot, runtime, job, 5681)


class CustodyBoundaryTests(unittest.TestCase):
    def test_absence_rejects_identifier_prefix_collision(self) -> None:
        result = canary.bounded.Result(1, b"", b"Error response from daemon: No such container: expected-extra", False, False)
        with patch.object(canary.bounded, "daemon_healthy", return_value=True), patch.object(canary.bounded, "run", return_value=result):
            self.assertFalse(canary.exact_absent("container", "expected"))

    def test_bounded_command_does_not_accept_truncated_success(self) -> None:
        result = canary.bounded.Result(0, b"partial", b"", False, True)
        with patch.object(canary.bounded, "run", return_value=result):
            with self.assertRaisesRegex(canary.Failure, "command_failed"):
                canary.run(["fixture"])

    def test_event_command_suffix_cannot_hide_rebootstrap(self) -> None:
        event = {"Action": "exec_create: node -e fixture", "Actor": {"Attributes": {"io.neoth.n8n-job": "fixture"}}}
        with self.assertRaisesRegex(canary.Failure, "second_call_rebootstrap_event"):
            canary.assert_no_rebootstrap_events(json.dumps(event), "fixture")
        event["Action"] = "die"
        with self.assertRaisesRegex(canary.Failure, "event_owner_mismatch"):
            canary.assert_no_rebootstrap_events(json.dumps(event), "different")

    def test_invalid_hosted_guard_cannot_write_receipt_or_delete_home(self) -> None:
        with patch.object(sys, "argv", ["canary", "--binary", "unused", "--home", "/outside", "--port", "5681", "--receipt", "/outside.json"]), patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), patch.object(Path, "write_text") as write, patch.object(canary.shutil, "rmtree") as remove, patch.object(canary, "read_json_from_command") as command:
            self.assertEqual(canary.main(), 2)
        write.assert_not_called()
        remove.assert_not_called()
        command.assert_not_called()

    def test_hosted_home_requires_exact_empty_owned_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "w1018-n8n-123-1" / "neoth-home"
            home.mkdir(parents=True)
            receipt = home.parent / "receipt" / "receipt.json"
            env = {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_TEMP": str(root), "NEOTH_HOME": str(home)}
            with patch.dict(os.environ, env):
                self.assertEqual(canary.hosted_paths(home, receipt), home.parent)
                (home / "existing-custody").write_text("preserve")
                with self.assertRaisesRegex(canary.Failure, "isolated_path_invalid"):
                    canary.hosted_paths(home, receipt)

    def test_secret_cleanup_rejects_still_present_value(self) -> None:
        result = canary.bounded.Result(0, b"still-present", b"", False, False)
        with patch.object(canary, "run"), patch.object(canary.bounded, "run", return_value=result):
            with self.assertRaisesRegex(canary.Failure, "secret_removal_unproven"):
                canary.clear_bootstrap_secrets("fixture")


if __name__ == "__main__": unittest.main()
