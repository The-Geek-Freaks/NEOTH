#!/usr/bin/env python3
"""Fail closed on the reviewed, locally patched imbl 6.1.0 archive.

The archive checksum is the external trust anchor.  This gate pins every
archive member, permits only the reviewed three-file backport delta, and
proves Cargo consumes only the exact path-patched package before metadata.
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
VENDOR_RELATIVE = Path("SRC/vendor/imbl")
MANIFEST_RELATIVE = Path("SRC/Cargo.toml")
LOCK_RELATIVE = Path("SRC/Cargo.lock")
ARCHIVE_RELATIVE = Path("packaging/vendor-provenance/imbl-6.1.0.crate")
CRATE_NAME = "imbl"
CRATE_VERSION = "6.1.0"
CRATE_CHECKSUM = "0fade8ae6828627ad1fa094a891eccfb25150b383047190a3648d66d06186501"
UPSTREAM_VCS_SHA = "70ea30037b159c2110bcfc580e0929a1d65acbe1"
CHUNKS_NAME = "imbl-sized-chunks"
CHUNKS_VERSION = "0.2.0"
CHUNKS_CHECKSUM = "2a0813be332553f857953298749fa19549e8b61b80589757c29b4e2a804fa9c6"
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"


EXPECTED_FILE_HASHES = {
    ".cargo_vcs_info.json": "ef71a652c3dd17771e25ddea0aaf1c907a4284553ac396072e2e27629921994e",
    ".github/dependabot.yml": "9cfec6a922efe988528a211f58ebd1d3fc3567c59e731b259d9273c7348aa2a0",
    ".github/workflows/ci.yml": "6368b237e7c7aaf85bc6027972d19d60d0a293f3ee4145b24f4c3003518728fb",
    ".gitignore": "ae0226639cb642c8527aa4b9a70a753ca2d1487a70ba974a8b55378d6d3c5604",
    ".rustfmt.toml": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ".travis.yml": "148c8340bf637260ec16fb05dea8de07db994662cda966cda46e34ac787423cb",
    ".vscode/settings.json": "9e46f2ef232dcc5289aee3115090d2c0754d74a8466ae54a964d0a3126e498a8",
    "benches/hashmap.rs": "425451910d477fe51ea747476f7c7fc24ad904d50df0108d50f474df7025c181",
    "benches/ordmap.rs": "2d7010fee23ff04d05613a0a546a668a0d196bd42c2d10f53522e2ac283b2820",
    "benches/utils/mod.rs": "53b3c80e081ecfbfde1183c0a2f6b4e19b521c6db9c0b73e73228f0d77cabf4a",
    "benches/vector.rs": "8310844d33ef56d03c19b5f0cd1dd5215cebf39fd20562ade110b6749792a472",
    "Cargo.lock": "85f06207220f53c8e45405685d82a55a83960353cea94efc2ccb251b251a437a",
    "Cargo.toml": "cac4c1a1d8f98467782713e32941cecf0b997f52bb4448ce6e7341f0f5fea514",
    "Cargo.toml.orig": "2f7f17962743e0b09c851d918ed4b78b2f11e64787066d68693feeda816792d4",
    "CHANGELOG.md": "851edca6df0e32a924b0a87e8a5541eaf065924d2938973377868c89c38220df",
    "clippy.toml": "6c881ed685df35c82b4a847a9a63612456a34266eb32234ab3f5c659590dace1",
    "CODE_OF_CONDUCT.md": "3db9f112c815ffef9a6f51eef2f5f6a3f3c2900510c243f26ad890321b888473",
    "LICENCE.md": "e6b6566f085df5746515c6d7e2edcaec0d2b77d527ac40d91409d783fb6c8508",
    "README.md": "13a5e22ae62c9969272ad79bd0213a300cfb2150e42825d178b398225d7fb264",
    "src/arbitrary.rs": "62846714afcb0b59feb89609ae2f129200b4ef595af2bfa594b733d62dd5b956",
    "src/bincode.rs": "3e6f57ec8f7d49b0834f49a5b0655b6f089b1050d09d7838183d61d9718a9fde",
    "src/config.rs": "a6c0112756b2a94d587ae3583dbf3550cb41c66c4b17c466748573277ee81929",
    "src/fakepool.rs": "bb41052c234bed8cc1afd31a2578f2383afc3981c2562603fa35cd6e66379a9e",
    "src/hash/map.rs": "dabe039cb6f67dd97517dd231812378ed81585a21d49eacbfd1b0a7e671e85d4",
    "src/hash/mod.rs": "96e9b19b81c59b248c252b9dd085af45a7a45b1f50087aaa2bd94894f2df5706",
    "src/hash/set.rs": "1c819899a6f029dde3e8c4fb7a0969f8f534b280154be9a97ac14db0c9b90e20",
    "src/iter.rs": "a78eeb5fb7dd2241eac78288478c8b2239c04775f7144ad1ad2d93a30994c3b5",
    "src/lib.rs": "0b3e01dd98638dccd68119d0490747e4d0bfdf907f222e9366fcb458b53ef61e",
    "src/nodes/btree.rs": "bf8496b3b3d65f7300f53dbc7f4f2f603ff1732e5977ea00f5f745d30a9e57fd",
    "src/nodes/hamt.rs": "adaefadf01df70a09f3251dd7ec68dd229e1a33fab31061cb9dcbba7ecb5ef25",
    "src/nodes/mod.rs": "e207aa15e2179ba0b4ddba1fb67f89390146af1c08e94c174f3e7f2d75656b28",
    "src/nodes/rrb.rs": "5de89d2d705d5aaacef8887e7ce7c7b005322d11b6e7a14baabe79eee38e7271",
    "src/ord/map.rs": "21c10e0c3cff232e7f951b93b452831440f868e9721a95f1ae24c8045abcdd86",
    "src/ord/mod.rs": "96e9b19b81c59b248c252b9dd085af45a7a45b1f50087aaa2bd94894f2df5706",
    "src/ord/set.rs": "8fdaf60f3df641fffe3956da8b31ed3c83df10ca909b2c6b5dac3772609337b7",
    "src/ord/test-fixtures/issue_124.txt": "b47660b232309abefe3965f168474db05a65bf6d36b0289454aaba6318ffd017",
    "src/proptest.rs": "aad97bb11b48aa4128f75d20481ed1d01080790977039ece218a2d2301a25a39",
    "src/quickcheck.rs": "732c2d150d9f1921dcd06e4b542b67d3b85aa3dc29b635fc48b05595b6abd47b",
    "src/ser.rs": "c1573e0048c86c44a07cb6959c080c2673ed87ae4dc28ec90dcb1de7a439d9bc",
    "src/shared_ptr.rs": "b3be8466ea25f2e137662890acf65cb2de1d8027a8e62950252422c90da58d22",
    "src/sort.rs": "caa9797dfed220463b0114946755b00c9dbc35888143c60fb10c1b0777acd751",
    "src/sync.rs": "da2d5b2846083e512b2008bf61d847bd5ff54ae07d36ce2c5e5409fc6d585442",
    "src/test.rs": "a9676593280e29049789e040b42c6732877ff41696be5a5dcbe97c8b5e894441",
    "src/tests/hashset.rs": "dbb867a786f09872c3815baa6a106f44d69d01c4e334ddad237ade0ebb674784",
    "src/tests/mod.rs": "4e195032b38a3296d91b0dfdd32c16eb0e8d880af775c5965826c6402d63eb5f",
    "src/tests/ordset.rs": "f18b67e47286edeeac13aecafda38d8d5c8ee173f16561bbac1acaf67e0acc11",
    "src/tests/vector.rs": "e1272666871e6d5a41ce889bc7e41019e283e8db0ae674e485d456417decc2f6",
    "src/util.rs": "a945475cf9f2f6a9ec1994a801e21bb46fc991a281545f057b90e171aa55a98e",
    "src/vector/focus.rs": "7bbcc9a87ed33fca73dc6abc3c7ccbb325348e5bcfdb6cb1b38c2e530c362575",
    "src/vector/mod.rs": "515fe7b698df2aea3dcfc22902982563dad31cd35db4ffa1e61db76e7a0ca6e8",
    "src/vector/pool.rs": "881212c56711e62fd7f9538b8b7905de0687fd766e6c4d18a2481c10f5063cb0",
    "src/vector/rayon.rs": "a739de42ada6407358d1faeaef59a2f5d22689f86019e7b59498013b77d036b2",
}
EXPECTED_DIRECTORIES = {".github", ".github/workflows", ".vscode", "benches", "benches/utils", "src", "src/hash", "src/nodes", "src/ord", "src/ord/test-fixtures", "src/tests", "src/vector"}
BACKPORT_DELTA = {
    "Cargo.toml": (
        "8cb7063de1d4d2ab80852ca3c4e71820c642784c055cffba49e566faa60179b3",
        "cac4c1a1d8f98467782713e32941cecf0b997f52bb4448ce6e7341f0f5fea514",
    ),
    "Cargo.toml.orig": (
        "e9c2b26c12242ef501dfde29c31e104fafc07e0713d44747671ece20e36a69d6",
        "2f7f17962743e0b09c851d918ed4b78b2f11e64787066d68693feeda816792d4",
    ),
    "src/nodes/hamt.rs": (
        "5302a5ad51c4b466dc5b328f71bbdbe1a16893ba0c4fe0292d0571b4082cecb2",
        "adaefadf01df70a09f3251dd7ec68dd229e1a33fab31061cb9dcbba7ecb5ef25",
    ),
}


class ImblProvenanceError(ValueError):
    """The path-patched imbl package no longer has its review evidence."""


def _load_toml(path: Path) -> dict[str, object]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ImblProvenanceError(f"cannot read TOML {path}: {error}") from error
    if not isinstance(value, dict):
        raise ImblProvenanceError(f"TOML {path} is not an object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ImblProvenanceError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def require_archive_anchor(root: Path) -> None:
    archive = root / ARCHIVE_RELATIVE
    if not archive.is_file() or archive.is_symlink():
        raise ImblProvenanceError("imbl official archive is missing or not regular")
    actual = _sha256(archive)
    if actual != CRATE_CHECKSUM:
        raise ImblProvenanceError(
            f"imbl archive checksum mismatch: expected {CRATE_CHECKSUM}, got {actual}"
        )


def require_exact_vendor_tree(root: Path) -> None:
    vendor = root / VENDOR_RELATIVE
    if not vendor.is_dir() or vendor.is_symlink():
        raise ImblProvenanceError("imbl vendor root must be a real directory")
    files: set[str] = set()
    directories: set[str] = set()
    for current_root, directory_names, file_names in os.walk(vendor, followlinks=False):
        current = Path(current_root)
        for name in directory_names:
            path = current / name
            relative = _relative(vendor, path)
            if path.is_symlink():
                raise ImblProvenanceError(f"imbl vendor contains symlink directory {relative!r}")
            directories.add(relative)
        for name in file_names:
            path = current / name
            relative = _relative(vendor, path)
            if path.is_symlink() or not path.is_file():
                raise ImblProvenanceError(f"imbl vendor contains non-regular file {relative!r}")
            files.add(relative)
    if directories != EXPECTED_DIRECTORIES:
        raise ImblProvenanceError("imbl vendor directory allowlist mismatch")
    if files != set(EXPECTED_FILE_HASHES):
        raise ImblProvenanceError("imbl vendor file allowlist mismatch")
    for relative, expected in EXPECTED_FILE_HASHES.items():
        actual = _sha256(vendor / relative)
        if actual != expected:
            raise ImblProvenanceError(
                f"imbl vendor hash mismatch for {relative}: expected {expected}, got {actual}"
            )
    if set(BACKPORT_DELTA) != {
        "Cargo.toml", "Cargo.toml.orig", "src/nodes/hamt.rs"
    } or any(
        EXPECTED_FILE_HASHES[relative] != candidate
        for relative, (_, candidate) in BACKPORT_DELTA.items()
    ):
        raise ImblProvenanceError("imbl backport delta declaration is incomplete")


def require_vendor_manifest_and_vcs(root: Path) -> None:
    manifest = _load_toml(root / VENDOR_RELATIVE / "Cargo.toml")
    package = manifest.get("package")
    if not isinstance(package, dict) or (
        package.get("name"), package.get("version"), package.get("license"), package.get("rust-version")
    ) != (CRATE_NAME, CRATE_VERSION, "MPL-2.0+", "1.85"):
        raise ImblProvenanceError("imbl manifest must retain reviewed package identity")
    if package.get("build") is not False or "build-dependencies" not in manifest:
        raise ImblProvenanceError("imbl manifest build-script containment changed")
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict) or "bitmaps" in dependencies:
        raise ImblProvenanceError("imbl manifest must not declare bitmaps")
    chunks = dependencies.get(CHUNKS_NAME)
    if not isinstance(chunks, dict) or chunks.get("version") != f"={CHUNKS_VERSION}":
        raise ImblProvenanceError("imbl manifest must pin imbl-sized-chunks to 0.2.0")
    original = _load_toml(root / VENDOR_RELATIVE / "Cargo.toml.orig")
    original_dependencies = original.get("dependencies")
    if not isinstance(original_dependencies, dict) or "bitmaps" in original_dependencies or original_dependencies.get(CHUNKS_NAME) != f"={CHUNKS_VERSION}":
        raise ImblProvenanceError("imbl original manifest backport declarations changed")
    try:
        vcs = json.loads((root / VENDOR_RELATIVE / ".cargo_vcs_info.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ImblProvenanceError(f"cannot read imbl VCS metadata: {error}") from error
    git = vcs.get("git") if isinstance(vcs, dict) else None
    if not isinstance(git, dict) or git.get("sha1") != UPSTREAM_VCS_SHA or vcs.get("path_in_vcs") != "":
        raise ImblProvenanceError("imbl VCS metadata must retain the reviewed upstream commit")


def require_patch_identity(root: Path) -> None:
    workspace = _load_toml(root / MANIFEST_RELATIVE)
    patch = workspace.get("patch")
    crates_io = patch.get("crates-io") if isinstance(patch, dict) else None
    expected_patch = {"path": "vendor/imbl", "version": f"={CRATE_VERSION}"}
    if not isinstance(crates_io, dict) or crates_io.get(CRATE_NAME) != expected_patch:
        raise ImblProvenanceError("SRC/Cargo.toml must patch imbl only to the reviewed path/version")


def require_lock_identity(root: Path) -> None:
    lock = _load_toml(root / LOCK_RELATIVE)
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ImblProvenanceError("SRC/Cargo.lock has no package list")
    imbl = [p for p in packages if isinstance(p, dict) and p.get("name") == CRATE_NAME]
    if len(imbl) != 1 or imbl[0].get("version") != CRATE_VERSION or "source" in imbl[0] or "checksum" in imbl[0]:
        raise ImblProvenanceError("SRC/Cargo.lock must contain one source-less imbl@6.1.0 path patch")
    chunks = [p for p in packages if isinstance(p, dict) and p.get("name") == CHUNKS_NAME]
    if len(chunks) != 1 or (chunks[0].get("version"), chunks[0].get("source"), chunks[0].get("checksum")) != (CHUNKS_VERSION, REGISTRY_SOURCE, CHUNKS_CHECKSUM):
        raise ImblProvenanceError("SRC/Cargo.lock must pin the reviewed registry imbl-sized-chunks@0.2.0")
    if any(isinstance(p, dict) and p.get("name") == "bitmaps" for p in packages):
        raise ImblProvenanceError("SRC/Cargo.lock must not resolve bitmaps")


def require_patch_and_lock_identity(root: Path) -> None:
    """Compatibility helper for fixtures that exercise the full state."""

    require_patch_identity(root)
    require_lock_identity(root)


def validate(root: Path = ROOT, *, check_lock: bool = True) -> None:
    """Validate source custody; require resolved lock identity unless disabled."""

    require_archive_anchor(root)
    require_exact_vendor_tree(root)
    require_vendor_manifest_and_vcs(root)
    require_patch_identity(root)
    if check_lock:
        require_lock_identity(root)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", type=Path, default=ROOT)
    result.add_argument(
        "--source-only",
        action="store_true",
        help="verify archive/vendor/manifest/VCS/root patch custody before Cargo updates Cargo.lock",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate(args.root.resolve(), check_lock=not args.source_only)
    except ImblProvenanceError as error:
        print(f"::error::imbl provenance gate failed: {error}", file=sys.stderr)
        return 1
    mode = "source-only" if args.source_only else "full"
    print(f"imbl provenance gate passed ({mode}): reviewed {CRATE_NAME}@{CRATE_VERSION} backport")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
