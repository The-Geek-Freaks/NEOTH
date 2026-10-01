from __future__ import annotations

import shutil
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

import imbl_provenance_gate as gate  # noqa: E402


class ImblProvenanceGateTests(unittest.TestCase):
    def fixture_root(self) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name)
        (destination / "SRC").mkdir()
        (destination / "packaging" / "vendor-provenance").mkdir(parents=True)
        shutil.copy2(ROOT / "SRC" / "Cargo.toml", destination / "SRC" / "Cargo.toml")
        # The checked-in lock is intentionally pre-resolution when this suite
        # runs before Cargo. Full-lock fixtures use a tiny known-valid graph so
        # each negative assertion reaches the intended lock condition.
        (destination / "SRC" / "Cargo.lock").write_text(
            '''version = 4

[[package]]
name = "imbl"
version = "6.1.0"
dependencies = ["imbl-sized-chunks"]

[[package]]
name = "imbl-sized-chunks"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2a0813be332553f857953298749fa19549e8b61b80589757c29b4e2a804fa9c6"
''',
            encoding="utf-8",
        )
        shutil.copytree(ROOT / "SRC" / "vendor" / "imbl", destination / "SRC" / "vendor" / "imbl")
        shutil.copy2(
            ROOT / gate.ARCHIVE_RELATIVE,
            destination / gate.ARCHIVE_RELATIVE,
        )
        return temporary

    def assert_rejects(self, mutate: object, fragment: str) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            assert callable(mutate)
            mutate(root)
            with self.assertRaisesRegex(gate.ImblProvenanceError, fragment):
                gate.validate(root)

    def test_checked_in_containment_passes(self) -> None:
        gate.validate(ROOT)

    def test_source_only_mode_does_not_consume_lock(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            lock = root / gate.LOCK_RELATIVE
            lock.unlink()
            gate.validate(root, check_lock=False)
            with self.assertRaisesRegex(gate.ImblProvenanceError, "cannot read TOML"):
                gate.validate(root)

    def test_valid_full_lock_fixture_passes(self) -> None:
        with self.fixture_root() as temporary:
            gate.validate(Path(temporary))

    def test_full_vendor_inventory_rejects_tamper_and_extra_file(self) -> None:
        def tamper(root: Path) -> None:
            path = root / gate.VENDOR_RELATIVE / "src" / "lib.rs"
            path.write_text(path.read_text(encoding="utf-8") + "\n// changed\n", encoding="utf-8")

        self.assert_rejects(tamper, "hash mismatch")

        def extra(root: Path) -> None:
            (root / gate.VENDOR_RELATIVE / "unexpected.rs").write_text("extra\n", encoding="utf-8")

        self.assert_rejects(extra, "file allowlist mismatch")

    def test_vendor_symlink_fails_closed(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            link = root / gate.VENDOR_RELATIVE / "linked-lib.rs"
            try:
                link.symlink_to("src/lib.rs")
            except OSError as error:
                self.skipTest(f"symlinks unavailable in this test environment: {error}")
            with self.assertRaisesRegex(gate.ImblProvenanceError, "non-regular file"):
                gate.require_exact_vendor_tree(root)

    def test_archive_manifest_and_vcs_tamper_fail_closed(self) -> None:
        def archive(root: Path) -> None:
            path = root / gate.ARCHIVE_RELATIVE
            path.write_bytes(path.read_bytes() + b"x")

        self.assert_rejects(archive, "archive checksum mismatch")

        with self.fixture_root() as temporary:
            root = Path(temporary)
            path = root / gate.VENDOR_RELATIVE / "Cargo.toml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    '[dependencies.imbl-sized-chunks]\nversion = "=0.2.0"',
                    '[dependencies.bitmaps]\nversion = "3"\n\n[dependencies.imbl-sized-chunks]\nversion = "=0.2.0"',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(gate.ImblProvenanceError, "must not declare bitmaps"):
                gate.require_vendor_manifest_and_vcs(root)

        with self.fixture_root() as temporary:
            root = Path(temporary)
            path = root / gate.VENDOR_RELATIVE / ".cargo_vcs_info.json"
            path.write_text('{"git":{"sha1":"0"},"path_in_vcs":""}', encoding="utf-8")
            with self.assertRaisesRegex(gate.ImblProvenanceError, "VCS metadata"):
                gate.require_vendor_manifest_and_vcs(root)

    def test_patch_lock_and_chunks_identity_fail_closed(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            manifest = root / gate.MANIFEST_RELATIVE
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    'path = "vendor/imbl"', 'path = "vendor/imbl-unreviewed"'
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(gate.ImblProvenanceError, "path/version"):
                gate.require_patch_and_lock_identity(root)

        with self.fixture_root() as temporary:
            root = Path(temporary)
            manifest = root / gate.MANIFEST_RELATIVE
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    'version = "=6.1.0"', 'version = "=6.1.1"', 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(gate.ImblProvenanceError, "path/version"):
                gate.require_patch_and_lock_identity(root)

        with self.fixture_root() as temporary:
            root = Path(temporary)
            lock = root / gate.LOCK_RELATIVE
            lock.write_text(
                lock.read_text(encoding="utf-8").replace(
                    'name = "imbl-sized-chunks"\nversion = "0.2.0"',
                    'name = "imbl-sized-chunks"\nversion = "0.2.1"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(gate.ImblProvenanceError, "imbl-sized-chunks@0.2.0"):
                gate.require_patch_and_lock_identity(root)

        with self.fixture_root() as temporary:
            root = Path(temporary)
            lock = root / gate.LOCK_RELATIVE
            lock.write_text(
                lock.read_text(encoding="utf-8")
                + '\n[[package]]\nname = "bitmaps"\nversion = "3.2.1"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(gate.ImblProvenanceError, "must not resolve bitmaps"):
                gate.require_patch_and_lock_identity(root)

    def test_provenance_precedes_cargo_in_preflight_and_security(self) -> None:
        commands = (
            "python3 packaging/tests/test_arrayref_provenance_gate.py",
            "python3 packaging/arrayref_provenance_gate.py",
            "python3 packaging/tests/test_imbl_provenance_gate.py",
            "python3 packaging/imbl_provenance_gate.py",
            "cargo metadata --",
        )
        for name in ("preflight.yml", "security.yml"):
            with self.subTest(workflow=name):
                source = (ROOT / ".github" / "workflows" / name).read_text(
                    encoding="utf-8"
                )
                offsets = [source.index(command) for command in commands]
                self.assertEqual(offsets, sorted(offsets))
                self.assertNotIn("imbl_provenance_gate.py --source-only", source)

if __name__ == "__main__":
    unittest.main()
