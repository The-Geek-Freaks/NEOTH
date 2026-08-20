from __future__ import annotations

from pathlib import Path
import sys
from typing import Any
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

from generate_rust_notices import (  # noqa: E402
    canonical_public_https_repository,
    generate,
    local_vendor_provenance,
    upstream_vcs_path,
)


class LocalVendorRepositoryProvenanceTests(unittest.TestCase):
    def test_embedded_ascii_controls_are_rejected_before_url_parsing(self) -> None:
        for control in ("\n", "\r", "\t"):
            with self.subTest(control=repr(control)):
                with patch("generate_rust_notices.urlsplit") as urlsplit:
                    self.assertIsNone(
                        canonical_public_https_repository(
                            f"https://github.com/rightbracket/peer{control}oxide"
                        )
                    )
                    urlsplit.assert_not_called()

    def test_canonical_public_repository_is_accepted(self) -> None:
        self.assertEqual(
            canonical_public_https_repository(
                "https://github.com/Rightbracket/peeroxide.git"
            ),
            "https://github.com/rightbracket/peeroxide",
        )


class LocalVendorVcsPathTests(unittest.TestCase):
    ARRAYREF_SHA = "f8d0299d863922db6c409d08098941e833b70d69"
    ARRAYREF_MANIFEST = ROOT / "SRC" / "vendor" / "arrayref" / "Cargo.toml"

    def test_repository_root_marker_is_accepted_without_normalization(self) -> None:
        self.assertEqual(upstream_vcs_path(""), "")

    def test_non_root_vcs_paths_must_be_strict_posix_relative_paths(self) -> None:
        self.assertEqual(upstream_vcs_path("crates/arrayref"), "crates/arrayref")
        for value in (
            ".",
            "..",
            "./arrayref",
            "arrayref/../other",
            "/arrayref",
            "C:/arrayref",
            "arrayref\\other",
            "arrayref\nother",
            "arrayref`breakout",
            "[arrayref](https://example.invalid)",
            None,
        ):
            with self.subTest(value=repr(value)):
                self.assertIsNone(upstream_vcs_path(value))

    def test_arrayref_repository_root_provenance_is_rendered(self) -> None:
        package: dict[str, Any] = {
            "name": "arrayref",
            "version": "0.3.9",
            "license": "BSD-2-Clause",
            "repository": "https://github.com/droundy/arrayref",
            "manifest_path": str(self.ARRAYREF_MANIFEST),
            "source": None,
            "_targets": {"x86_64-unknown-linux-gnu"},
        }
        provenance = local_vendor_provenance(package)
        self.assertIsNotNone(provenance)
        assert provenance is not None
        self.assertEqual(provenance["revision"], self.ARRAYREF_SHA)
        self.assertEqual(provenance["path_in_vcs"], "")
        self.assertEqual(
            provenance["identity"],
            f"vendor+https://github.com/droundy/arrayref@{self.ARRAYREF_SHA}#",
        )

        package["_local_vendor_provenance"] = provenance
        generated = generate([package])
        self.assertIn(f"source `{provenance['identity']}`", generated)


if __name__ == "__main__":
    unittest.main()
