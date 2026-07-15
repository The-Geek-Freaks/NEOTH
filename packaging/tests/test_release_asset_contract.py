from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "release_asset_contract.py"
GOLDEN_NAMES = Path(__file__).parent / "fixtures" / "release_asset_names.golden.txt"
SPEC = importlib.util.spec_from_file_location("release_asset_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


def golden_canonical_names(version: str) -> set[str]:
    templates = GOLDEN_NAMES.read_text(encoding="utf-8").splitlines()
    return {template.format(version=version) for template in templates if template}


def golden_contract_sets(version: str) -> dict[str, set[str]]:
    canonical = golden_canonical_names(version)
    policy_name = "NEOTH_INTERNAL_RELEASE_ASSET_POLICY"
    signing_inputs_manifest = "NEOTH_INTERNAL_SIGNING_INPUTS.SHA256"
    minisign_manifest = "NEOTH_INTERNAL_MINISIGN_SIGNATURES.SHA256"
    cosign_manifest = "NEOTH_INTERNAL_COSIGN_BUNDLES.SHA256"
    public_key = "NEOTH_RELEASE_MINISIGN_PUBKEY.txt"
    signable = canonical | {"SHA256SUMS"}
    signing_inputs = signable | {public_key}
    publication = (
        signing_inputs
        | {f"{name}.minisig" for name in signable}
        | {f"{name}.cosign.bundle" for name in signing_inputs}
    )
    return {
        "canonical": canonical,
        "canonical-policy": canonical | {policy_name},
        "signing": signing_inputs | {policy_name},
        "signing-transfer": signing_inputs
        | {policy_name, signing_inputs_manifest},
        "minisign-transfer": {f"{name}.minisig" for name in signable}
        | {minisign_manifest},
        "cosign-transfer": {
            f"{name}.cosign.bundle" for name in signing_inputs
        }
        | {cosign_manifest},
        "publication": publication,
        "release-transfer": publication
        | {
            policy_name,
            signing_inputs_manifest,
            minisign_manifest,
            cosign_manifest,
        },
    }


class ReleaseAssetContractTests(unittest.TestCase):
    def test_golden_fixture_is_exact_unique_and_sorted(self) -> None:
        templates = GOLDEN_NAMES.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(templates), 52)
        self.assertEqual(len(set(templates)), 52)
        self.assertListEqual(templates, sorted(templates))

    def test_every_public_asset_set_matches_the_independent_golden_contract(self) -> None:
        for version in ("1.0.0", "1.0.0-rc.2"):
            for contract_set, expected in golden_contract_sets(version).items():
                with self.subTest(version=version, contract_set=contract_set):
                    self.assertSetEqual(
                        contract.expected_names(version, contract_set), expected
                    )

    def test_supported_prerelease_boundaries_are_accepted(self) -> None:
        for version in (
            "0.1.0",
            "1.0.0-alpha.0",
            "1.0.0-alpha.31",
            "1.0.0-beta.0",
            "1.0.0-beta.31",
            "1.0.0-rc.0",
            "1.0.0-rc.31",
            "99.99.99",
            "99.99.99-rc.31",
        ):
            with self.subTest(version=version):
                self.assertEqual(contract.validate_version(version), version)

    def test_prerelease_version_is_preserved_in_every_name(self) -> None:
        names = contract.expected_names("1.0.0-rc.2", "canonical")
        self.assertTrue(all("1.0.0-rc.2" in name for name in names))

    def test_invalid_or_ambiguous_versions_are_rejected(self) -> None:
        for version in (
            "v1.0.0",
            "1.0",
            "01.0.0",
            "1.0.0-01",
            "1.0.0-alpha.32",
            "1.0.0-rc.01",
            "1.0.0-rc1",
            "1.0.0-gold-rc1",
            "1.0.0+build.1",
            "0.0.0",
            "0.0.1",
            "100.0.0",
            "1.100.0",
            "1.0.100",
            "../1.0.0",
        ):
            with self.subTest(version=version), self.assertRaises(
                contract.AssetContractError
            ):
                contract.canonical_payload_names(version)

    def test_exact_directory_verifier_rejects_missing_and_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            names = contract.expected_names("1.0.0", "canonical")
            for name in names:
                directory.joinpath(name).write_bytes(b"x")
            contract.verify(directory, "1.0.0", "canonical")
            directory.joinpath("surprise.zip").write_bytes(b"x")
            with self.assertRaisesRegex(contract.AssetContractError, "extra=surprise.zip"):
                contract.verify(directory, "1.0.0", "canonical")
            directory.joinpath("surprise.zip").unlink()
            missing = next(iter(names))
            directory.joinpath(missing).unlink()
            with self.assertRaisesRegex(contract.AssetContractError, "missing="):
                contract.verify(directory, "1.0.0", "canonical")

    def test_policy_is_deterministic_and_names_every_phase(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / contract.POLICY_NAME
            contract.write_policy(path, "1.0.0")
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value, contract.policy("1.0.0"))
            self.assertEqual(value["schema_version"], 1)
            self.assertEqual(len(value["canonical_payloads"]), 52)
            self.assertEqual(len(value["publication"]), 161)
            self.assertIn(
                contract.POLICY_NAME,
                contract.expected_names("1.0.0", "release-transfer"),
            )


if __name__ == "__main__":
    unittest.main()
