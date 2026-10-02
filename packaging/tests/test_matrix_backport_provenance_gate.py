from __future__ import annotations

from datetime import date
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging"))
import matrix_backport_provenance_gate as gate  # noqa: E402


class MatrixBackportProvenanceGateTests(unittest.TestCase):
    def fixture_root(self) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        (root / "SRC" / "vendor").mkdir(parents=True)
        (root / "SRC" / ".cargo").mkdir(parents=True)
        (root / "packaging" / "vendor-provenance").mkdir(parents=True)
        for name, spec in gate.PACKAGES.items():
            shutil.copytree(ROOT / spec["vendor"], root / spec["vendor"])
            shutil.copy2(ROOT / spec["archive"], root / spec["archive"])
        (root / gate.MANIFEST_RELATIVE).write_text(
            "[patch.crates-io]\n"
            'matrix-sdk = { path = "vendor/matrix-sdk", version = "=0.18.0" }\n'
            'matrix-sdk-crypto = { path = "vendor/matrix-sdk-crypto", version = "=0.18.0" }\n',
            encoding="utf-8",
        )
        (root / gate.LOCK_RELATIVE).write_text(
            "version = 4\n\n"
            '[[package]]\nname = "matrix-sdk"\nversion = "0.18.0"\n\n'
            '[[package]]\nname = "matrix-sdk-crypto"\nversion = "0.18.0"\n\n'
            '[[package]]\nname = "anymap3"\nversion = "1.1.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{gate.ANYMAP3_CHECKSUM}"\n', encoding="utf-8")
        (root / gate.AUDIT_RELATIVE).write_text(
            f'[advisories]\nignore = ["{gate.ADVISORY}"]\n', encoding="utf-8")
        (root / gate.DENY_RELATIVE).write_text(
            f'[advisories]\nignore = [{{ id = "{gate.ADVISORY}", reason = "fixed vendor backport; re-evaluate 2026-11-01" }}]\n', encoding="utf-8")
        return temporary

    def test_reviewed_postimages_and_final_graph_pass(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            gate.validate_sources(root)
            gate.validate(root, today=date(2026, 10, 31))

    def test_source_mode_requires_neither_lock_nor_exceptions(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary)
            (root / gate.LOCK_RELATIVE).unlink(); (root / gate.AUDIT_RELATIVE).unlink()
            gate.validate_sources(root)
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "cannot read TOML"):
                gate.validate(root, today=date(2026, 10, 31))

    def test_tampered_extra_and_symlink_vendor_members_fail(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary); target = root / gate.PACKAGES[gate.SDK]["vendor"] / "src" / "lib.rs"
            target.write_bytes(target.read_bytes() + b"x")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "postimage mismatch"):
                gate.validate_sources(root)
        with self.fixture_root() as temporary:
            root = Path(temporary); (root / gate.PACKAGES[gate.CRYPTO]["vendor"] / "extra.rs").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "allowlist mismatch"):
                gate.validate_sources(root)
        with self.fixture_root() as temporary:
            root = Path(temporary); link = root / gate.PACKAGES[gate.SDK]["vendor"] / "linked.rs"
            try: link.symlink_to("src/lib.rs")
            except OSError as error: self.skipTest(f"symlinks unavailable: {error}")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "non-regular file"):
                gate.validate_sources(root)

    def test_tampered_archive_and_unpatched_postimage_fail(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary); archive = root / gate.PACKAGES[gate.SDK]["archive"]
            archive.write_bytes(archive.read_bytes() + b"x")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "checksum mismatch"):
                gate.validate_sources(root)
        with self.fixture_root() as temporary:
            root = Path(temporary); path = root / gate.PACKAGES[gate.CRYPTO]["vendor"] / "src/session_manager/group_sessions/share_strategy.rs"
            path.write_bytes(b"unpatched archive preimage substitution")
            # The checked-in integration must use the reviewed postimage, never the archive preimage.
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "postimage mismatch"):
                gate.validate_sources(root)

    def test_missing_duplicate_and_registry_backed_crypto_fail(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary); lock = root / gate.LOCK_RELATIVE
            lock.write_text(lock.read_text(encoding="utf-8").replace('name = "matrix-sdk-crypto"', 'name = "wrong"', 1), encoding="utf-8")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "one source-less matrix-sdk-crypto"):
                gate.validate(root, today=date(2026, 10, 31))
        with self.fixture_root() as temporary:
            root = Path(temporary); lock = root / gate.LOCK_RELATIVE
            lock.write_text(lock.read_text(encoding="utf-8").replace('name = "matrix-sdk-crypto"\nversion = "0.18.0"', 'name = "matrix-sdk-crypto"\nversion = "0.18.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"', 1), encoding="utf-8")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "one source-less matrix-sdk-crypto"):
                gate.validate(root, today=date(2026, 10, 31))
        with self.fixture_root() as temporary:
            root = Path(temporary); lock = root / gate.LOCK_RELATIVE
            lock.write_text(lock.read_text(encoding="utf-8") + '\n[[package]]\nname = "matrix-sdk-crypto"\nversion = "0.18.0"\n', encoding="utf-8")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "one source-less matrix-sdk-crypto"):
                gate.validate(root, today=date(2026, 10, 31))

    def test_anymap_exception_count_and_expiry_fail_closed(self) -> None:
        with self.fixture_root() as temporary:
            root = Path(temporary); lock = root / gate.LOCK_RELATIVE
            lock.write_text(lock.read_text(encoding="utf-8") + '\n[[package]]\nname = "anymap2"\nversion = "0.13.0"\n', encoding="utf-8")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "must not resolve anymap2"):
                gate.validate(root, today=date(2026, 10, 31))
        with self.fixture_root() as temporary:
            root = Path(temporary); audit = root / gate.AUDIT_RELATIVE
            audit.write_text(f'[advisories]\nignore = ["{gate.ADVISORY}", "{gate.ADVISORY}"]\n', encoding="utf-8")
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "exactly once in audit"):
                gate.validate(root, today=date(2026, 10, 31))
        with self.fixture_root() as temporary:
            with self.assertRaisesRegex(gate.MatrixBackportProvenanceError, "expired"):
                gate.validate(Path(temporary), today=gate.EXPIRY_DATE)


if __name__ == "__main__":
    unittest.main()
