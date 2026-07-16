from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "generate_release_manifests.py"
REPOSITORY_ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("generate_release_manifests", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class GenerateReleaseManifestsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.output = self.root / "output"
        self.dist.mkdir()
        self.version = "1.0.0"
        names = list(MODULE.required_native_names(self.version))
        names.extend(
            (
                "neoth-v1.0.0-x86_64-unknown-linux-gnu.tar.gz",
                "neoth-v1.0.0-x86_64-pc-windows-msvc.zip",
            )
        )
        for index, name in enumerate(names):
            payload = f"asset-{index}-{name}".encode()
            (self.dist / name).write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            (self.dist / f"{name}.sha256").write_text(
                f"{digest}  {name}\n", encoding="utf-8"
            )
            if name.endswith(MODULE.NATIVE_METADATA_SUFFIXES):
                (self.dist / f"{name}.json").write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "product": "NEOTH",
                            "name": name,
                            "version": self.version,
                            "target": "fixture-target",
                            "architecture": "fixture-arch",
                            "format": "fixture",
                            "sha256": digest,
                            "trust": {"fixture": True},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_generates_hash_bound_winget_homebrew_and_index(self) -> None:
        archive = MODULE.generate(
            self.dist,
            self.output,
            "The-Geek-Freaks/NEOTH",
            self.version,
        )
        self.assertTrue(archive.is_file())
        with zipfile.ZipFile(archive) as generated:
            names = set(generated.namelist())
            self.assertIn("homebrew/neoth.rb", names)
            self.assertIn("winget/TheGeekFreaks.NEOTH.installer.yaml", names)
            cask = generated.read("homebrew/neoth.rb").decode()
            self.assertIn("NEOTH.app/Contents/MacOS/neoth-keet-bridge", cask)
            self.assertIn("NEOTH.app/Contents/MacOS/neothd-gui", cask)
            winget = generated.read(
                "winget/TheGeekFreaks.NEOTH.installer.yaml"
            ).decode()
            self.assertIn("InstallerType: inno", winget)
            self.assertNotIn("00000000000000000000000000000000", winget)
            index = json.loads(generated.read("release-index.json"))
            self.assertEqual(index["tag"], "v1.0.0")
            self.assertEqual(len(index["assets"]), 12)
            native = next(
                asset for asset in index["assets"] if asset["name"].endswith(".deb")
            )
            self.assertEqual(native["metadata"], f'{native["name"]}.json')
            raw = next(
                asset
                for asset in index["assets"]
                if asset["name"].endswith(".tar.gz")
            )
            self.assertIsNone(raw["metadata"])

    def test_repository_has_no_versioned_winget_stubs(self) -> None:
        legacy_root = (
            REPOSITORY_ROOT / "SRC" / "dist" / "winget" / "manifests"
        )
        tracked_stubs = (
            sorted(legacy_root.rglob("*.yaml")) if legacy_root.exists() else []
        )
        self.assertEqual(
            tracked_stubs,
            [],
            "WinGet manifests must be generated from final release hashes, not checked in",
        )

    def test_rejects_tampered_payload(self) -> None:
        name = f"NEOTH-{self.version}-x64-Setup.exe"
        (self.dist / name).write_bytes(b"tampered")
        with self.assertRaisesRegex(MODULE.ManifestError, "SHA-256 mismatch"):
            MODULE.generate(
                self.dist,
                self.output,
                "The-Geek-Freaks/NEOTH",
                self.version,
            )

    def test_rejects_sidecar_bound_to_another_name(self) -> None:
        name = f"NEOTH-{self.version}-arm64-Setup.exe"
        sidecar = self.dist / f"{name}.sha256"
        digest = hashlib.sha256((self.dist / name).read_bytes()).hexdigest()
        sidecar.write_text(f"{digest}  wrong.exe\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.ManifestError, "is bound to"):
            MODULE.generate(
                self.dist,
                self.output,
                "The-Geek-Freaks/NEOTH",
                self.version,
            )

    def test_rejects_non_strict_prerelease(self) -> None:
        with self.assertRaisesRegex(MODULE.ManifestError, "leading zero"):
            MODULE.strict_version("1.0.0-rc.01")

    def test_rejects_manifest_injection_repository(self) -> None:
        with self.assertRaisesRegex(MODULE.ManifestError, "repository identifier"):
            MODULE.generate(
                self.dist,
                self.output,
                "The-Geek-Freaks/NEOTH\nInstallerSha256: forged",
                self.version,
            )

    def test_rejects_native_metadata_hash_drift(self) -> None:
        name = f"NEOTH-{self.version}-x64-Setup.exe"
        metadata_path = self.dist / f"{name}.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["sha256"] = "0" * 64
        metadata_path.write_text(json.dumps(metadata) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.ManifestError, "metadata SHA-256"):
            MODULE.generate(
                self.dist,
                self.output,
                "The-Geek-Freaks/NEOTH",
                self.version,
            )


if __name__ == "__main__":
    unittest.main()
