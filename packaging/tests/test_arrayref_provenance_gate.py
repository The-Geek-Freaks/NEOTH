from __future__ import annotations

import shutil
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

import arrayref_provenance_gate as gate  # noqa: E402


class ArrayrefProvenanceGateTests(unittest.TestCase):
    def fixture_root(self) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name)
        (destination / "SRC").mkdir()
        shutil.copy2(ROOT / "SRC" / "Cargo.toml", destination / "SRC" / "Cargo.toml")
        shutil.copy2(ROOT / "SRC" / "Cargo.lock", destination / "SRC" / "Cargo.lock")
        shutil.copytree(
            ROOT / "SRC" / "vendor" / "arrayref",
            destination / "SRC" / "vendor" / "arrayref",
        )
        return temporary

    def assert_gate_rejects(self, mutate: object, fragment: str) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            assert callable(mutate)
            mutate(root)
            with self.assertRaisesRegex(gate.ArrayrefProvenanceError, fragment):
                gate.validate(root)

    def test_checked_in_containment_passes(self) -> None:
        gate.validate(ROOT)

    def test_vendor_tamper_and_unexpected_file_fail_closed(self) -> None:
        def tamper(root: Path) -> None:
            path = root / gate.VENDOR_RELATIVE / "src" / "lib.rs"
            path.write_text(
                path.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8"
            )

        self.assert_gate_rejects(tamper, "hash mismatch")

        def extra(root: Path) -> None:
            (root / gate.VENDOR_RELATIVE / "surprise.rs").write_text(
                "not reviewed\n", encoding="utf-8"
            )

        self.assert_gate_rejects(extra, "file allowlist mismatch")

    def test_manifest_build_and_dependency_declarations_fail_closed(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            manifest = root / gate.VENDOR_RELATIVE / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8")
                + '\n[dependencies]\nserde = "1"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                gate.ArrayrefProvenanceError, "forbidden runtime/build dependency"
            ):
                gate.require_vendor_manifest(root)

        with self.fixture_root() as temporary:
            root = Path(temporary)
            manifest = root / gate.VENDOR_RELATIVE / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    'repository = "https://github.com/droundy/arrayref"',
                    'repository = "https://github.com/droundy/arrayref"\nbuild = "build.rs"',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(gate.ArrayrefProvenanceError, "build script"):
                gate.require_vendor_manifest(root)

    def test_wrong_vcs_patch_and_lock_identity_fail_closed(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            path = root / gate.VENDOR_RELATIVE / ".cargo_vcs_info.json"
            path.write_text(
                '{"git":{"sha1":"0000000000000000000000000000000000000000"},"path_in_vcs":""}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                gate.ArrayrefProvenanceError, "must pin upstream commit"
            ):
                gate.require_vcs_provenance(root)

        def wrong_patch(root: Path) -> None:
            path = root / gate.MANIFEST_RELATIVE
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'path = "vendor/arrayref"', 'path = "vendor/arrayref-unreviewed"'
                ),
                encoding="utf-8",
            )

        self.assert_gate_rejects(wrong_patch, "must patch arrayref only")

        def registry_lock(root: Path) -> None:
            path = root / gate.LOCK_RELATIVE
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'name = "arrayref"\nversion = "0.3.9"\n',
                    'name = "arrayref"\nversion = "0.3.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
                    1,
                ),
                encoding="utf-8",
            )

        self.assert_gate_rejects(registry_lock, "dependency-free path patch")

    def test_known_compromise_versions_fail_closed(self) -> None:
        def newer_arrayref(root: Path) -> None:
            path = root / gate.LOCK_RELATIVE
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'name = "arrayref"\nversion = "0.3.9"',
                    'name = "arrayref"\nversion = "0.3.10"',
                    1,
                ),
                encoding="utf-8",
            )

        self.assert_gate_rejects(newer_arrayref, "must pin arrayref@0.3.9")

        def proc_macro1(root: Path) -> None:
            path = root / gate.LOCK_RELATIVE
            path.write_text(
                path.read_text(encoding="utf-8")
                + '\n[[package]]\nname = "proc-macro1"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )

        self.assert_gate_rejects(proc_macro1, "compromised proc-macro1")

    def test_ci_runs_fixture_and_actual_gate_before_cargo_metadata(self) -> None:
        cargo_metadata_marker = {
            "preflight.yml": "Validate locked workspace metadata without dependencies",
            "security.yml": "cargo metadata --manifest-path SRC/Cargo.toml",
        }
        for workflow_name, marker in cargo_metadata_marker.items():
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(
                encoding="utf-8"
            )
            positions = [
                workflow.index(
                    "python3 packaging/tests/test_arrayref_provenance_gate.py"
                ),
                workflow.index("python3 packaging/arrayref_provenance_gate.py"),
                workflow.index(marker),
            ]
            self.assertEqual(
                positions,
                sorted(positions),
                f"{workflow_name} must prove the vendored archive before Cargo metadata",
            )


if __name__ == "__main__":
    unittest.main()
