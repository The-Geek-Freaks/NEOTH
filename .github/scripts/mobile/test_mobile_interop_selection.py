"""Focused contract regressions for the hosted mobile-interop selection."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
VALIDATOR_PATH = HERE / "validate-mobile-interop-selection.py"
SPEC = importlib.util.spec_from_file_location("mobile_interop_selection_validator", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
MANIFEST_PATH = HERE / "mobile-companion-interop-selection.json"
REPO_ROOT = HERE.parents[2]


class SelectionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        for relative in self.data["sourcePaths"]:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = REPO_ROOT / relative
            if not source.is_file():
                self.fail(f"bound fixture source missing from candidate checkout: {relative}")
            shutil.copyfile(source, destination)
        self.manifest = self.root / ".github/scripts/mobile/mobile-companion-interop-selection.json"
        self._write_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(self) -> None:
        self.manifest.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")

    def _validate(self) -> dict[str, object]:
        return VALIDATOR.validate(self.manifest, self.root)

    def test_preserves_exact_selection_and_custody_inputs(self) -> None:
        custody = self._validate()
        self.assertEqual(custody["counts"], {
            "rust": 36,
            "collector": 4,
            "sources": 38,
            "groups": {"libudx": 5, "peeroxide": 3, "dht": 11, "core": 15, "no_cluster": 1, "bridge": 1},
        })
        self.assertEqual(custody["groups"]["libudx"]["identities"][-2], (
            "native::stream::bounded_transport_tests::bounded_read_queue_backpressures_then_roundtrips_after_drain"
        ))
        self.assertEqual(custody["collector"]["identities"], [
            "test_chunk_boundaries_do_not_duplicate_or_merge_pair_and_active_markers",
            "test_reply_boundary_markers_preserve_exact_scope_and_chunk_custody",
            "test_os_send_completion_markers_keep_pair_active_scope_and_drop_boundaries",
            "test_cursor_retains_prior_pair_evidence_without_counting_it_as_active",
        ])
        self.assertIn("SRC/vendor/libudx/src/native/header.rs", custody["sourceSha256"])
        self.assertEqual(custody["dispatchHashSources"]["bridge_header_sha256"], (
            "bridges/companion-native/include/neoth_companion_bridge.h"
        ))

    def test_rejects_missing_source_path_before_any_output(self) -> None:
        missing = self.root / "SRC/vendor/libudx/src/native/header.rs"
        missing.unlink()
        with self.assertRaisesRegex(VALIDATOR.ContractError, "missing or outside"):
            self._validate()

    def test_rejects_duplicate_rust_identity(self) -> None:
        self.data["groups"]["peeroxide"]["identities"][0] = self.data["groups"]["libudx"]["identities"][0]
        self._write_manifest()
        with self.assertRaisesRegex(VALIDATOR.ContractError, "duplicated"):
            self._validate()

    def test_rejects_wrong_collector_set(self) -> None:
        collector = self.root / ".github/scripts/mobile/test_hosted_mobile_interop_diagnostics.py"
        text = collector.read_text(encoding="utf-8")
        collector.write_text(text.replace(
            "def test_cursor_retains_prior_pair_evidence_without_counting_it_as_active(",
            "def no_longer_a_collector_test(",
        ), encoding="utf-8")
        with self.assertRaisesRegex(VALIDATOR.ContractError, "collector unittest loader IDs"):
            self._validate()

    def test_loader_discovers_typed_and_inherited_methods_before_rejecting_drift(self) -> None:
        collector = self.root / ".github/scripts/mobile/test_hosted_mobile_interop_diagnostics.py"
        text = collector.read_text(encoding="utf-8")
        text = text.replace(
            "class ScopedCollectorTests(unittest.TestCase):",
            "class _InheritedCollectorTests(unittest.TestCase):\n"
            "    def test_inherited_loader_coverage(self) -> None:\n"
            "        pass\n\n\n"
            "class ScopedCollectorTests(_InheritedCollectorTests):",
            1,
        )
        collector.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(VALIDATOR.ContractError, "collector unittest loader IDs"):
            self._validate()

    def test_rejects_unsafe_source_path(self) -> None:
        self.data["sourcePaths"][0] = "../outside.yml"
        self._write_manifest()
        with self.assertRaisesRegex(VALIDATOR.ContractError, "unsafe source path"):
            self._validate()

    def test_rejects_duplicate_json_key(self) -> None:
        source = self.manifest.read_text(encoding="utf-8")
        self.manifest.write_text(source.replace(
            '  "schema": "neoth.mobile-interop-selection.v1",',
            '  "schema": "neoth.mobile-interop-selection.v1",\n  "schema": "duplicate",',
            1,
        ), encoding="utf-8")
        with self.assertRaisesRegex(VALIDATOR.ContractError, "duplicate JSON key"):
            self._validate()

    def test_rejects_workflow_dispatch_input_drift(self) -> None:
        workflow = self.root / ".github/workflows/mobile-companion-interop.yml"
        text = workflow.read_text(encoding="utf-8")
        workflow.write_text(text.replace("bridge_header_sha256:", "bridge_header_sha256_old:", 1), encoding="utf-8")
        with self.assertRaisesRegex(VALIDATOR.ContractError, "workflow dispatch input mismatch"):
            self._validate()

    def test_emits_atomic_custody_and_ordered_group_files(self) -> None:
        custody = self._validate()
        output = self.root / "out"
        with mock.patch.object(VALIDATOR, "_producer_head", return_value="a" * 40):
            VALIDATOR.emit(custody, output, self.root)
        self.assertEqual((output / "libudx.txt").read_text(encoding="utf-8").splitlines(), custody["groups"]["libudx"]["identities"])
        emitted = json.loads((output / "selection-custody.json").read_text(encoding="utf-8"))
        self.assertEqual(emitted["producer"]["head"], "a" * 40)
        self.assertEqual(emitted["manifest"]["path"], ".github/scripts/mobile/mobile-companion-interop-selection.json")


if __name__ == "__main__":
    unittest.main()
