#!/usr/bin/env python3
"""Hosted-only regression coverage of the original and revised custody gates."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import candle_zip_migration as gate

SOURCE_ROOT = Path(__file__).resolve().parents[1]
ASSET_PATH = Path("packaging/vendor-provenance")
REVISION_NAME = "candle-core-0.8.4-pin-revision.json"
PATCH_NAME = "zip9.0.5-russh0.64.1.patch"
CANDIDATE_NAMES = {
    "SRC/neothd/Cargo.toml": "neothd-Cargo.toml",
    "SRC/vendor/candle-core/Cargo.toml": "candle-Cargo.toml",
    "SRC/vendor/candle-core/Cargo.toml.orig": "candle-Cargo.toml.orig",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PinRevisionCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # The candidate workflow must run before importing pins, on its exact
        # producer, and provide the separately retained candidate bundle.
        cls.candidate = Path(os.environ["NEOTH_PIN_REVISION_INPUT"]).resolve()
        cls.spec = json.loads(
            (SOURCE_ROOT / ASSET_PATH / "candle-core-0.8.4-zip9.json").read_bytes()
        )
        for change in cls.spec["changes"]:
            if sha((SOURCE_ROOT / change["path"]).read_bytes()) != change["after"]:
                raise AssertionError("source baseline is not the original admitted postimage")

    @contextmanager
    def fixture(self, *, revised: bool = True):
        with tempfile.TemporaryDirectory(prefix="neoth-pin-gate-test-") as directory:
            root = Path(directory) / "repo"
            assets = root / ASSET_PATH
            vendor = root / "SRC/vendor/candle-core"
            assets.mkdir(parents=True)
            shutil.copytree(SOURCE_ROOT / "SRC/vendor/candle-core", vendor)
            for change in self.spec["changes"]:
                if change["path"].startswith("SRC/vendor/candle-core/"):
                    continue
                destination = root / change["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE_ROOT / change["path"], destination)
            for name in (
                "candle-core-0.8.4-zip9.json", "candle-core-0.8.4.crate",
                "candle-core-0.8.4-zip9.patch", "candle_zip_compat.rs",
            ):
                shutil.copyfile(SOURCE_ROOT / ASSET_PATH / name, assets / name)
            test = root / gate.TEST
            test.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE_ROOT / gate.TEST, test)
            if revised:
                for relative, name in CANDIDATE_NAMES.items():
                    shutil.copyfile(self.candidate / name, root / relative)
                shutil.copyfile(
                    self.candidate / "candle-core-0.8.4-pin-revision.candidate.json",
                    assets / REVISION_NAME,
                )
                shutil.copyfile(self.candidate / PATCH_NAME, assets / PATCH_NAME)
            with patch.multiple(
                gate, ROOT=root, ASSETS=assets, VENDOR=vendor,
                ARCHIVE=assets / "candle-core-0.8.4.crate",
                PATCH=assets / "candle-core-0.8.4-zip9.patch",
            ):
                yield root

    def verify(self, *, required: bool = True) -> None:
        spec = gate.bindings()
        gate.verify_source(spec, gate.upstream_files(), require_revision=required)

    def update_revision(self, root: Path, change) -> None:
        path = root / ASSET_PATH / REVISION_NAME
        data = json.loads(path.read_bytes())
        change(data)
        path.write_text(json.dumps(data) + "\n", encoding="utf-8")

    def assert_rejected(self) -> None:
        with self.assertRaises((ValueError, OSError, subprocess.CalledProcessError)):
            self.verify()

    def test_original_source_custody_remains_valid(self) -> None:
        with self.fixture(revised=False):
            self.verify(required=False)
            self.assert_rejected()  # Required revision cannot fall back.

    def test_exact_pin_revision_passes_full_vendor_custody(self) -> None:
        with self.fixture():
            self.verify()

    def test_rehashed_non_pin_edit_and_other_vendor_edit_are_rejected(self) -> None:
        with self.fixture() as root:
            path = root / "SRC/neothd/Cargo.toml"
            path.write_bytes(path.read_bytes() + b"\n# unreviewed source change\n")
            def rebind(data):
                next(item for item in data["changes"] if item["path"] == "SRC/neothd/Cargo.toml")["after"] = sha(path.read_bytes())
            self.update_revision(root, rebind)
            self.assert_rejected()
        with self.fixture() as root:
            path = root / "SRC/vendor/candle-core/src/npy.rs"
            path.write_bytes(path.read_bytes() + b"\n// unreviewed source change\n")
            self.assert_rejected()

    def test_patch_mode_and_extra_path_reject_after_digest_rebinding(self) -> None:
        for mutation in ("mode", "extra"):
            with self.subTest(mutation=mutation), self.fixture() as root:
                path = root / ASSET_PATH / PATCH_NAME
                content = path.read_text(encoding="utf-8")
                if mutation == "mode":
                    content = content.replace("\nindex ", "\nold mode 100644\nnew mode 100755\nindex ", 1)
                else:
                    content += (
                        "\ndiff --git a/SRC/neothd/src/media/document.rs b/SRC/neothd/src/media/document.rs\n"
                        "index 1111111111111111111111111111111111111111.."
                        "2222222222222222222222222222222222222222 100644\n"
                        "--- a/SRC/neothd/src/media/document.rs\n"
                        "+++ b/SRC/neothd/src/media/document.rs\n@@ -0,0 +1 @@\n+// extra\n"
                    )
                path.write_text(content, encoding="utf-8", newline="\n")
                if mutation == "extra":
                    stat = subprocess.check_output(
                        ["git", "apply", "--numstat", "-"],
                        input=content.encode("utf-8"), cwd=root, timeout=15,
                    )
                    self.assertIn(b"\tSRC/neothd/src/media/document.rs\n", stat)
                self.update_revision(root, lambda data: data.update(patchSha256=sha(path.read_bytes())))
                self.assert_rejected()

    def test_revision_closed_schema_duplicates_and_missing_path_reject(self) -> None:
        for mutation in ("extra", "duplicate_field", "missing_path", "duplicate_path"):
            with self.subTest(mutation=mutation), self.fixture() as root:
                path = root / ASSET_PATH / REVISION_NAME
                if mutation == "duplicate_field":
                    text = path.read_text(encoding="utf-8")
                    path.write_text('{"schema": "duplicate", ' + text.lstrip()[1:], encoding="utf-8")
                else:
                    def mutate(data):
                        if mutation == "extra":
                            data["unexpected"] = True
                        elif mutation == "missing_path":
                            data["changes"].pop()
                        else:
                            data["changes"][1] = data["changes"][0]
                    self.update_revision(root, mutate)
                self.assert_rejected()

    def test_original_assets_and_required_revision_cannot_disappear(self) -> None:
        for name in ("candle-core-0.8.4.crate", "candle-core-0.8.4-zip9.patch",
                     "candle-core-0.8.4-zip9.json", REVISION_NAME, PATCH_NAME):
            with self.subTest(name=name), self.fixture() as root:
                (root / ASSET_PATH / name).unlink()
                self.assert_rejected()

    def test_vendor_inventory_and_byte_identical_links_are_rejected(self) -> None:
        for mutation in ("extra", "missing", "manifest_link", "vendor_link", "parent_link"):
            with self.subTest(mutation=mutation), self.fixture() as root:
                if mutation == "extra":
                    (root / "SRC/vendor/candle-core/unreviewed.rs").write_text("// extra\n")
                elif mutation == "missing":
                    (root / "SRC/vendor/candle-core/src/npy.rs").unlink()
                elif mutation == "parent_link":
                    original = root / "SRC/neothd"
                    moved = root.parent / "external-neothd"
                    original.rename(moved)
                    original.symlink_to(moved, target_is_directory=True)
                else:
                    relative = "SRC/neothd/Cargo.toml" if mutation == "manifest_link" else "SRC/vendor/candle-core/src/npy.rs"
                    original = root / relative
                    moved = root.parent / "byte-identical-source"
                    original.rename(moved)
                    original.symlink_to(moved)
                self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
