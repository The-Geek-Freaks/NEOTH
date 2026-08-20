#!/usr/bin/env python3
"""Fail closed on NEOTH's quarantined, vendored arrayref 0.3.9 package.

arrayref 0.3.9 is yanked upstream.  It remains only as a byte-for-byte copy
of the reviewed crates.io archive while the dependency is removed upstream.
This gate runs before Cargo reads the workspace graph, so a changed vendor
tree cannot make a security job resolve an unreviewed replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tomllib
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
VENDOR_RELATIVE = Path("SRC/vendor/arrayref")
MANIFEST_RELATIVE = Path("SRC/Cargo.toml")
LOCK_RELATIVE = Path("SRC/Cargo.lock")
CRATE_NAME = "arrayref"
CRATE_VERSION = "0.3.9"
CRATE_CHECKSUM = "76a2e8124351fda1ef8aaaa3bbd7ebbcb486bbcd4225aca0aa0d84bb2db8fecb"
UPSTREAM_VCS_SHA = "f8d0299d863922db6c409d08098941e833b70d69"

# Full upstream crate archive inventory, excluding Cargo's local extraction
# marker (.cargo-ok).  Keeping all archive members gives us a reproducible
# provenance claim instead of a hand-curated subset that could conceal drift.
EXPECTED_FILE_HASHES = {
    ".cargo_vcs_info.json": (
        "38cf63576b82b1cbd13a45debc16b4a8db667de12fc7e8f4262c828211734a60"
    ),
    ".github/workflows/rust.yml": (
        "731b95305723b149de1fdc4369671e8f5da196d4d0fc27abcb0984186fef0632"
    ),
    ".gitignore": "7150ee9391a955b2ef7e0762fc61c0c1aab167620ca36d88d78062d93b8334ba",
    ".travis.yml": "19382d5f7c535638c53c19821fdfc3d8e3b2acb521a20339ce710ac6155c3c4e",
    "Cargo.lock": "a662fab7d33586364087c438737169ac88fbdc810973374a2196f6b0d45484b5",
    "Cargo.toml": "517b570f4136de5b5a07e1c41a84d6876227b09aab84e69e578bfa8be2e67546",
    "Cargo.toml.orig": (
        "122da2bce2d1aea793e4dc4d38a98966c67f3339a4db2f8fc740bd74ce97e668"
    ),
    "examples/array_refs_with_const.rs": (
        "d04c8f8db0989ed0c3adee472923d673d25155fad8297f9860dde9a79d8df679"
    ),
    "examples/array_refs.rs": (
        "f0cda2c12723da36d722fc820c027c64f4f48fe0a62e6dec7bb4f62cf5197148"
    ),
    "examples/simple-case.rs": (
        "bfd9bd711e18fe23d0016e9856467d00717dd611522e01d227f7ba525e635280"
    ),
    "LICENSE": "1bc7e6f475b3ec99b7e2643411950ae2368c250dd4c5c325f80f9811362a94a1",
    "README.md": "039b4028d39ba4ec049041dbbf949555bcc42aa7bced920725c5573d2b6cad24",
    "src/lib.rs": "b74872c9bb2b836132817e024a3f9205f83a6864de1a9bfb46acc1bfbbc1873a",
}
EXPECTED_DIRECTORIES = {
    ".github",
    ".github/workflows",
    "examples",
    "src",
}


class ArrayrefProvenanceError(ValueError):
    """The vendored yanked dependency no longer has complete evidence."""


def _load_toml(path: Path) -> dict[str, object]:
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ArrayrefProvenanceError(f"cannot read TOML {path}: {error}") from error
    if not isinstance(loaded, dict):
        raise ArrayrefProvenanceError(f"TOML {path} is not an object")
    return loaded


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ArrayrefProvenanceError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _relative_posix(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def require_exact_vendor_archive(root: Path) -> None:
    """Require only the reviewed archive files, with their exact bytes."""

    vendor = root / VENDOR_RELATIVE
    if not vendor.is_dir() or vendor.is_symlink():
        raise ArrayrefProvenanceError("arrayref vendor root must be a real directory")

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for current_root, directory_names, file_names in os.walk(vendor, followlinks=False):
        current = Path(current_root)
        for directory_name in directory_names:
            directory = current / directory_name
            relative = _relative_posix(vendor, directory)
            if directory.is_symlink():
                raise ArrayrefProvenanceError(
                    f"arrayref vendor archive contains symlink directory {relative!r}"
                )
            actual_directories.add(relative)
        for file_name in file_names:
            file_path = current / file_name
            relative = _relative_posix(vendor, file_path)
            if file_path.is_symlink() or not file_path.is_file():
                raise ArrayrefProvenanceError(
                    f"arrayref vendor archive contains non-regular file {relative!r}"
                )
            actual_files.add(relative)

    if actual_directories != EXPECTED_DIRECTORIES:
        raise ArrayrefProvenanceError(
            "arrayref vendor directory allowlist mismatch: "
            f"expected={sorted(EXPECTED_DIRECTORIES)!r}, actual={sorted(actual_directories)!r}"
        )
    expected_files = set(EXPECTED_FILE_HASHES)
    if actual_files != expected_files:
        raise ArrayrefProvenanceError(
            "arrayref vendor file allowlist mismatch: "
            f"expected={sorted(expected_files)!r}, actual={sorted(actual_files)!r}"
        )
    for relative, expected_hash in EXPECTED_FILE_HASHES.items():
        actual_hash = _sha256(vendor / relative)
        if actual_hash != expected_hash:
            raise ArrayrefProvenanceError(
                f"arrayref vendor hash mismatch for {relative}: "
                f"expected {expected_hash}, got {actual_hash}"
            )


def require_vendor_manifest(root: Path) -> None:
    """Confirm the archive is still the reviewed package, not a build script shim."""

    manifest = _load_toml(root / VENDOR_RELATIVE / "Cargo.toml")
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise ArrayrefProvenanceError("arrayref vendor manifest has no [package]")
    if (
        package.get("name") != CRATE_NAME
        or package.get("version") != CRATE_VERSION
        or package.get("license") != "BSD-2-Clause"
    ):
        raise ArrayrefProvenanceError(
            "arrayref vendor manifest must retain reviewed name/version/license"
        )
    if "build" in package or "build" in manifest:
        raise ArrayrefProvenanceError(
            "arrayref vendor manifest must not declare a build script"
        )
    forbidden_dependency_sections = (
        "dependencies",
        "build-dependencies",
        "workspace",
        "target",
    )
    present = [key for key in forbidden_dependency_sections if key in manifest]
    if present:
        raise ArrayrefProvenanceError(
            "arrayref vendor manifest has forbidden runtime/build dependency "
            f"sections: {present!r}"
        )


def require_vcs_provenance(root: Path) -> None:
    """Require the upstream commit recorded by Cargo in the official archive."""

    path = root / VENDOR_RELATIVE / ".cargo_vcs_info.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ArrayrefProvenanceError(
            f"cannot read arrayref VCS metadata: {error}"
        ) from error
    if not isinstance(value, dict):
        raise ArrayrefProvenanceError("arrayref VCS metadata is not an object")
    git = value.get("git")
    if not isinstance(git, dict) or git.get("sha1") != UPSTREAM_VCS_SHA:
        raise ArrayrefProvenanceError(
            f"arrayref VCS metadata must pin upstream commit {UPSTREAM_VCS_SHA}"
        )
    if value.get("path_in_vcs") != "":
        raise ArrayrefProvenanceError("arrayref VCS metadata must be repository-rooted")


def require_patch_and_lock_identity(root: Path) -> None:
    """Prove Cargo can only consume this local vendor package at 0.3.9."""

    workspace_manifest = _load_toml(root / MANIFEST_RELATIVE)
    patch = workspace_manifest.get("patch")
    crates_io = patch.get("crates-io") if isinstance(patch, dict) else None
    entry = crates_io.get(CRATE_NAME) if isinstance(crates_io, dict) else None
    expected_entry = {"path": "vendor/arrayref", "version": f"={CRATE_VERSION}"}
    if entry != expected_entry:
        raise ArrayrefProvenanceError(
            "SRC/Cargo.toml must patch arrayref only to "
            f"{expected_entry!r}, got {entry!r}"
        )

    lock = _load_toml(root / LOCK_RELATIVE)
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ArrayrefProvenanceError("SRC/Cargo.lock has no package list")
    arrayrefs = [
        package
        for package in packages
        if isinstance(package, dict) and package.get("name") == CRATE_NAME
    ]
    if len(arrayrefs) != 1:
        raise ArrayrefProvenanceError(
            f"SRC/Cargo.lock must contain exactly one {CRATE_NAME} package"
        )
    arrayref = arrayrefs[0]
    if arrayref.get("version") != CRATE_VERSION:
        raise ArrayrefProvenanceError(
            f"SRC/Cargo.lock must pin {CRATE_NAME}@{CRATE_VERSION}"
        )
    if "source" in arrayref or "checksum" in arrayref or "dependencies" in arrayref:
        raise ArrayrefProvenanceError(
            "SRC/Cargo.lock arrayref entry must be the dependency-free path patch"
        )
    versions = [
        package.get("version")
        for package in arrayrefs
        if isinstance(package.get("version"), str)
    ]
    if versions != [CRATE_VERSION]:
        raise ArrayrefProvenanceError(
            f"SRC/Cargo.lock must not resolve another {CRATE_NAME} version: {versions!r}"
        )
    if any(
        isinstance(package, dict) and package.get("name") == "proc-macro1"
        for package in packages
    ):
        raise ArrayrefProvenanceError(
            "SRC/Cargo.lock must not resolve compromised proc-macro1"
        )


def validate(root: Path = ROOT) -> None:
    """Run every independent provenance assertion before invoking Cargo."""

    require_exact_vendor_archive(root)
    require_vendor_manifest(root)
    require_vcs_provenance(root)
    require_patch_and_lock_identity(root)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root (defaults to this script's repository)",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate(args.root.resolve())
    except ArrayrefProvenanceError as error:
        print(f"::error::arrayref provenance gate failed: {error}", file=sys.stderr)
        return 1
    print(
        "arrayref provenance gate passed: full official 0.3.9 archive is "
        f"byte-for-byte pinned to crate checksum {CRATE_CHECKSUM} and "
        f"upstream commit {UPSTREAM_VCS_SHA}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
