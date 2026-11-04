#!/usr/bin/env python3
"""Hosted regression coverage for the fixed SSH pin custody successor."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import candle_pin_revision as pins
import candle_zip_migration as gate

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "SRC/neothd/Cargo.toml"
ASSETS = "packaging/vendor-provenance"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SshPinSuccessorTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        paths = [
            pins._SPEC, pins._REVISION, pins._PATCH, pins._SSH_REVISION,
            f"{ASSETS}/candle-core-0.8.4.crate",
            f"{ASSETS}/candle-core-0.8.4-zip9.patch",
            MANIFEST, "SRC/vendor/candle-core/Cargo.toml",
            "SRC/vendor/candle-core/Cargo.toml.orig", "SRC/Cargo.lock",
        ]
        with tempfile.TemporaryDirectory(prefix="neoth-ssh-pin-test-") as directory:
            root = Path(directory) / "repo"
            for relative in paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            yield root

    def verify(self, root):
        spec = json.loads((root / pins._SPEC).read_bytes())
        return pins.revision_sources(root, spec)

    def rebind(self, root, mutation):
        path = root / pins._SSH_REVISION
        receipt = json.loads(path.read_bytes())
        mutation(receipt)
        path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

    def test_exact_successor_reconstructs_original_postimages(self):
        with self.fixture() as root:
            actual = self.verify(root)
            spec = json.loads((root / pins._SPEC).read_bytes())
            expected = {item["path"]: item["after"] for item in spec["changes"]}
            self.assertEqual(set(actual), set(pins._ALLOWED))
            for name, data in actual.items():
                self.assertEqual(sha(data), expected[name])
            self.assertIn(b'"=0.63.2"', actual[MANIFEST])

    def test_current_pin_without_successor_is_rejected(self):
        with self.fixture() as root:
            (root / pins._SSH_REVISION).unlink()
            with self.assertRaisesRegex(ValueError, "effective source digest"):
                self.verify(root)

    def test_old_pin_without_successor_remains_verifiable(self):
        with self.fixture() as root:
            path = root / MANIFEST
            path.write_bytes(path.read_bytes().replace(b'"=0.65.0"', b'"=0.64.1"'))
            (root / pins._SSH_REVISION).unlink()
            self.assertIn(MANIFEST, self.verify(root))

    def test_stale_pin_with_successor_is_rejected(self):
        with self.fixture() as root:
            path = root / MANIFEST
            path.write_bytes(path.read_bytes().replace(b'"=0.65.0"', b'"=0.64.1"'))
            with self.assertRaisesRegex(ValueError, "SSH successor effective digest"):
                self.verify(root)

    def test_rehashed_non_pin_change_cannot_extend_custody(self):
        with self.fixture() as root:
            path = root / MANIFEST
            path.write_bytes(path.read_bytes() + b"\n# unrelated change\n")
            self.rebind(root, lambda data: data.update(after=sha(path.read_bytes())))
            with self.assertRaisesRegex(ValueError, "SSH successor reconstructed digest"):
                self.verify(root)

    def test_successor_schema_and_binding_mutations_reject(self):
        mutations = (
            lambda data: data.update(unexpected=True),
            lambda data: data.update(path="SRC/vendor/candle-core/Cargo.toml"),
            lambda data: data.update(predecessorRevisionSha256="0" * 64),
            lambda data: data.update(before="0" * 64),
            lambda data: data.update(edit={"before": '"=0.64.1"', "after": '"=0.66.0"'}),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.fixture() as root:
                self.rebind(root, mutation)
                with self.assertRaises(ValueError):
                    self.verify(root)
        with self.fixture() as root:
            path = root / pins._SSH_REVISION
            path.write_text('{"schema":"duplicate",' + path.read_text().lstrip()[1:])
            with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
                self.verify(root)

    def test_rehashed_unsupported_pin_does_not_extend_allowlist(self):
        with self.fixture() as root:
            path = root / MANIFEST
            path.write_bytes(path.read_bytes().replace(b'"=0.65.0"', b'"=0.66.0"'))
            self.rebind(root, lambda data: data.update(after=sha(path.read_bytes())))
            with self.assertRaisesRegex(ValueError, "ambiguous SSH successor substitution"):
                self.verify(root)

    def test_duplicate_new_pin_is_rejected(self):
        with self.fixture() as root:
            path = root / MANIFEST
            path.write_bytes(path.read_bytes() + b'\n# duplicate "=0.65.0"\n')
            self.rebind(root, lambda data: data.update(after=sha(path.read_bytes())))
            with self.assertRaisesRegex(ValueError, "ambiguous SSH successor substitution"):
                self.verify(root)

    def test_successor_link_is_rejected(self):
        with self.fixture() as root:
            original = root / pins._SSH_REVISION
            external = root.parent / "external-receipt.json"
            original.rename(external)
            original.symlink_to(external)
            with self.assertRaisesRegex(ValueError, "linked custody input"):
                self.verify(root)

    def test_mixed_resolved_ssh_versions_are_rejected(self):
        for package, old, new, message in (
            ("russh", "0.65.0", "0.64.1", "Russh revision resolution/checksum mismatch"),
            ("pageant", "0.2.5", "0.2.3", "Pageant successor resolution/checksum mismatch"),
        ):
            with self.subTest(package=package), self.fixture() as root:
                lock = root / "SRC/Cargo.lock"
                baseline = lock.read_bytes()
                before = f'name = "{package}"\nversion = "{old}"'.encode()
                after = f'name = "{package}"\nversion = "{new}"'.encode()
                self.assertEqual(baseline.count(before), 1)
                lock.write_bytes(baseline.replace(before, after, 1))
                with patch.multiple(gate, ROOT=root, ASSETS=root / ASSETS):
                    with patch.object(gate, "run", return_value=baseline):
                        with self.assertRaisesRegex(ValueError, message):
                            gate.verify_resolution(root.parent / "unused-proof")


if __name__ == "__main__":
    unittest.main()
