from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

from generate_rust_notices import (  # noqa: E402
    canonical_public_https_repository,
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


if __name__ == "__main__":
    unittest.main()
