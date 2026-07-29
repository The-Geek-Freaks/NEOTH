#!/usr/bin/env python3
from __future__ import annotations

import copy
import pathlib
import sys
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "packaging"))

import openclaw_provider_parity as parity  # noqa: E402


class OpenClawProviderParityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = parity.load_json(parity.DEFAULT_SNAPSHOT_PATH)
        cls.matrix = parity.load_json(parity.DEFAULT_MATRIX_PATH)

    def test_checked_in_snapshot_and_matrix_are_complete(self) -> None:
        counts = parity.validate_contract(self.snapshot, self.matrix)
        self.assertEqual(counts["manifest_count"], 57)
        self.assertEqual(counts["llm_provider_count"], 73)
        self.assertEqual(counts["non_llm_provider_count"], 3)
        self.assertEqual(counts["matrix_provider_count"], 74)
        self.assertEqual(counts["disposition_native"], 0)
        self.assertEqual(counts["disposition_typed_compatible"], 0)
        self.assertEqual(counts["disposition_missing"], 74)

    def test_missing_provider_entry_fails_closed(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        removed = matrix["providers"].pop()
        with self.assertRaisesRegex(
            parity.ContractError, "provider matrix is missing provider entries"
        ):
            parity.validate_contract(self.snapshot, matrix)
        self.assertTrue(removed["id"])

    def test_duplicate_provider_entry_fails_closed(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        matrix["providers"].append(copy.deepcopy(matrix["providers"][-1]))
        with self.assertRaisesRegex(
            parity.ContractError, "duplicate provider ids"
        ):
            parity.validate_contract(self.snapshot, matrix)

    def test_unclassified_provider_entry_fails_closed(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        matrix["providers"][0]["disposition"] = "unclassified"
        with self.assertRaisesRegex(
            parity.ContractError, "disposition is unclassified"
        ):
            parity.validate_contract(self.snapshot, matrix)

    def test_fake_complete_parity_claim_fails_closed(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        row = next(row for row in matrix["providers"] if row["id"] == "openai")
        row["disposition"] = "native"
        row["implementation_status"] = "native_complete"
        row["neoth_bindings"] = ["not-a-real-factory"]
        row["tests"] = ["not-a-real-test"]
        with self.assertRaisesRegex(
            parity.ContractError, "schema v1 cannot assert complete parity"
        ):
            parity.validate_contract(self.snapshot, matrix)

    def test_snapshot_scope_cannot_hide_an_llm_provider(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        manifest = next(
            manifest
            for manifest in snapshot["upstream"]["registry"]["manifests"]
            if manifest["path"] == "extensions/anthropic/openclaw.plugin.json"
        )
        manifest["scope"] = "non_llm"
        with self.assertRaisesRegex(
            parity.ContractError, "not in the reviewed non-LLM provider allowlist"
        ):
            parity.validate_contract(snapshot, self.matrix)

    def test_reviewed_non_llm_scope_cannot_be_reclassified(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        manifest = next(
            manifest
            for manifest in snapshot["upstream"]["registry"]["manifests"]
            if manifest["path"] == "extensions/comfy/openclaw.plugin.json"
        )
        manifest["scope"] = "llm_inference"
        with self.assertRaisesRegex(
            parity.ContractError, "must retain its reviewed non-LLM classification"
        ):
            parity.validate_contract(snapshot, self.matrix)

    def test_windows_evidence_paths_cannot_escape_repository(self) -> None:
        for path in (r"C:\Windows\System32\cmd.exe", r"\Windows\System32\cmd.exe"):
            with self.subTest(path=path):
                matrix = copy.deepcopy(self.matrix)
                row = next(
                    row for row in matrix["providers"] if row["id"] == "openai"
                )
                row["evidence"] = [path]
                with self.assertRaisesRegex(
                    parity.ContractError,
                    "canonical repository-relative POSIX path",
                ):
                    parity.validate_contract(self.snapshot, matrix)

    def test_release_source_drift_fails_closed(self) -> None:
        observed = parity.observed_from_snapshot(self.snapshot)
        observed["provider_manifests"][0]["blob_sha"] = "0" * 40
        with self.assertRaisesRegex(
            parity.ContractError, "OpenClaw provider release drift detected"
        ):
            parity.compare_upstream(self.snapshot, observed)

    def test_release_provider_id_drift_fails_closed(self) -> None:
        observed = parity.observed_from_snapshot(self.snapshot)
        observed["provider_manifests"][0]["provider_ids"].append("new-provider")
        with self.assertRaisesRegex(
            parity.ContractError, "OpenClaw provider release drift detected"
        ):
            parity.compare_upstream(self.snapshot, observed)

    def test_release_workflow_runs_live_freshness_gate(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        command = (
            "python packaging/openclaw_provider_parity.py --check-upstream"
        )
        self.assertEqual(workflow.count(command), 1)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", workflow)

    def test_ci_runs_offline_contract_tests(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        command = "python3 packaging/tests/test_openclaw_provider_parity.py"
        self.assertEqual(workflow.count(command), 1)
        self.assertNotIn(
            "openclaw_provider_parity.py --check-upstream",
            workflow,
            "normal CI must remain deterministic and network-independent",
        )


if __name__ == "__main__":
    unittest.main()
