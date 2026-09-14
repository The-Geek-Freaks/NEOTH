from __future__ import annotations

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).parents[2]
WORKFLOW = (ROOT / ".github" / "workflows" / "publish-crates.yml").read_text(
    encoding="utf-8"
)
RELEASE_WORKFLOW = (ROOT / ".github" / "workflows" / "release.yml").read_text(
    encoding="utf-8"
)


class PublishCratesContractTests(unittest.TestCase):
    def test_custody_manifest_and_consumers_use_the_exact_public_identity(self) -> None:
        custody = tomllib.loads(
            (ROOT / "SRC" / "neoth-openclaw-custody" / "Cargo.toml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(custody["package"]["name"], "neoth-openclaw-custody")
        self.assertEqual(custody["package"]["version"], "1.0.0")

        for package in ("neothd", "neoth-migrate"):
            manifest = tomllib.loads(
                (ROOT / "SRC" / package / "Cargo.toml").read_text(encoding="utf-8")
            )
            self.assertEqual(
                manifest["dependencies"]["neoth-openclaw-custody"],
                {"path": "../neoth-openclaw-custody", "version": "1.0.0"},
            )

    def test_custody_is_verified_published_and_propagated_before_core_packaging(self) -> None:
        required = [
            "custody_version: ${{ steps.contract.outputs.custody_version }}",
            'Path("SRC/neoth-openclaw-custody/Cargo.toml")',
            'custody_package["name"] != "neoth-openclaw-custody"',
            'custody_package["version"] != "1.0.0"',
            "cargo package -p neoth-openclaw-custody --locked --no-verify",
            "https://crates.io/api/v1/crates/neoth-openclaw-custody/$CUSTODY_VERSION",
            "target/package/neoth-openclaw-custody-$CUSTODY_VERSION.crate",
            "existing neoth-openclaw-custody version does not match this release tag",
            "cargo publish -p neoth-openclaw-custody --locked --no-verify",
            "Wait for custody and SDK index propagation, then package neoth",
            "cargo package -p neoth --locked --no-verify",
        ]
        for text in required:
            self.assertIn(text, WORKFLOW)

        self.assertLess(
            WORKFLOW.index("Package custody for immutable-content verification"),
            WORKFLOW.index("Package SDK for immutable-content verification"),
        )
        self.assertLess(
            WORKFLOW.index("- name: Publish custody\n"),
            WORKFLOW.index("- name: Publish SDK\n"),
        )
        self.assertLess(
            WORKFLOW.index("- name: Publish SDK\n"),
            WORKFLOW.index("- name: Wait for custody and SDK index propagation, then package neoth\n"),
        )
        self.assertLess(
            WORKFLOW.index("- name: Wait for custody and SDK index propagation, then package neoth\n"),
            WORKFLOW.index("- name: Check neoth registry state\n"),
        )

    def test_release_contract_requires_the_same_custody_identity_and_consumers(self) -> None:
        required = [
            'Path("SRC/neoth-openclaw-custody/Cargo.toml")',
            'custody["package"]["name"] != "neoth-openclaw-custody"',
            'custody["package"]["version"] != "1.0.0"',
            '(("neoth", core), ("neoth-migrate", migrate))',
            'manifest["dependencies"].get("neoth-openclaw-custody")',
            'custody_dependency.get("version") != "1.0.0"',
            'custody_dependency.get("path") != "../neoth-openclaw-custody"',
        ]
        for text in required:
            self.assertIn(text, RELEASE_WORKFLOW)


if __name__ == "__main__":
    unittest.main()
