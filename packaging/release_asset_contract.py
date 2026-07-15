#!/usr/bin/env python3
"""Closed public-asset policy for one NEOTH release version.

The release workflow must not infer its public API from whatever files happen
to be produced.  This module owns the exact v1 asset names and emits a small
internal policy that is hash-bound across the keyless/signing jobs.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Iterable


SCHEMA_VERSION = 1
POLICY_NAME = "NEOTH_INTERNAL_RELEASE_ASSET_POLICY"
SIGNING_INPUTS_MANIFEST = "NEOTH_INTERNAL_SIGNING_INPUTS.SHA256"
MINISIGN_MANIFEST = "NEOTH_INTERNAL_MINISIGN_SIGNATURES.SHA256"
COSIGN_MANIFEST = "NEOTH_INTERNAL_COSIGN_BUNDLES.SHA256"
PUBLIC_KEY = "NEOTH_RELEASE_MINISIGN_PUBKEY.txt"
SHA256SUMS = "SHA256SUMS"

VERSION_RE = re.compile(
    r"(?P<major>0|[1-9]|[1-9][0-9])\."
    r"(?P<minor>0|[1-9]|[1-9][0-9])\."
    r"(?P<patch>0|[1-9]|[1-9][0-9])"
    r"(?:-(?:alpha|beta|rc)\.(?:0|[1-9]|[12][0-9]|3[01]))?"
)


class AssetContractError(ValueError):
    pass


def validate_version(version: str) -> str:
    match = VERSION_RE.fullmatch(version)
    if match is None:
        raise AssetContractError(
            "invalid release version "
            f"{version!r}; expected MAJOR.MINOR.PATCH or "
            "MAJOR.MINOR.PATCH-{alpha,beta,rc}.N with N in 0..31; "
            "core components must be in 0..99 and build metadata is not supported"
        )
    if match.group("major") == "0" and match.group("minor") == "0":
        raise AssetContractError(
            "macOS native releases require major or minor to be nonzero: "
            f"{version!r}"
        )
    return version


def _with_sidecars(name: str, *, metadata: bool) -> set[str]:
    result = {name, f"{name}.sha256"}
    if metadata:
        result.add(f"{name}.json")
    return result


def canonical_payload_names(version: str) -> set[str]:
    version = validate_version(version)
    names: set[str] = set()

    for target in (
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-gnu",
    ):
        names |= _with_sidecars(
            f"neoth-v{version}-{target}.tar.gz", metadata=False
        )

    for architecture, target in (
        ("x64", "x86_64-pc-windows-msvc"),
        ("arm64", "aarch64-pc-windows-msvc"),
    ):
        names |= _with_sidecars(f"neoth-v{version}-{target}.zip", metadata=True)
        names |= _with_sidecars(
            f"NEOTH-{version}-{architecture}-Setup.exe", metadata=True
        )

    for target in (
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
    ):
        for extension in ("deb", "rpm"):
            names |= _with_sidecars(
                f"NEOTH-{version}-{target}.{extension}", metadata=True
            )

    for target in ("x86_64-apple-darwin", "aarch64-apple-darwin"):
        names |= _with_sidecars(
            f"neoth-v{version}-{target}.tar.gz", metadata=True
        )
        for extension in ("pkg", "dmg"):
            names |= _with_sidecars(
                f"NEOTH-{version}-{target}.{extension}", metadata=True
            )

    names |= _with_sidecars(
        f"neoth-whatsapp-baileys-v{version}.tar.gz", metadata=False
    )
    names |= _with_sidecars(
        f"neoth-package-manifests-v{version}.zip", metadata=False
    )
    if len(names) != 52:
        raise AssetContractError(
            f"internal canonical release-asset count drifted: {len(names)} != 52"
        )
    return names


def policy(version: str) -> dict[str, object]:
    canonical = canonical_payload_names(version)
    signable = canonical | {SHA256SUMS}
    signing_inputs = signable | {PUBLIC_KEY}
    publication = (
        signing_inputs
        | {f"{name}.minisig" for name in signable}
        | {f"{name}.cosign.bundle" for name in signing_inputs}
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "canonical_payloads": sorted(canonical),
        "signable_payloads": sorted(signable),
        "signing_inputs": sorted(signing_inputs),
        "publication": sorted(publication),
    }


def expected_names(version: str, contract_set: str) -> set[str]:
    value = policy(version)
    canonical = set(value["canonical_payloads"])
    signable = set(value["signable_payloads"])
    signing_inputs = set(value["signing_inputs"])
    publication = set(value["publication"])
    sets = {
        "canonical": canonical,
        "canonical-policy": canonical | {POLICY_NAME},
        "signing": signing_inputs | {POLICY_NAME},
        "signing-transfer": signing_inputs
        | {POLICY_NAME, SIGNING_INPUTS_MANIFEST},
        "minisign-transfer": {f"{name}.minisig" for name in signable}
        | {MINISIGN_MANIFEST},
        "cosign-transfer": {
            f"{name}.cosign.bundle" for name in signing_inputs
        }
        | {COSIGN_MANIFEST},
        "publication": publication,
        "release-transfer": publication
        | {
            POLICY_NAME,
            SIGNING_INPUTS_MANIFEST,
            MINISIGN_MANIFEST,
            COSIGN_MANIFEST,
        },
    }
    try:
        return sets[contract_set]
    except KeyError as error:
        raise AssetContractError(f"unknown release asset set: {contract_set}") from error


def actual_regular_names(directory: Path) -> set[str]:
    if not directory.is_dir() or directory.is_symlink():
        raise AssetContractError(f"asset directory is missing or unsafe: {directory}")
    names: set[str] = set()
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise AssetContractError(f"release asset is not a regular file: {path.name}")
        if path.name in names:
            raise AssetContractError(f"duplicate release asset name: {path.name}")
        if path.stat().st_size == 0:
            raise AssetContractError(f"release asset is empty: {path.name}")
        names.add(path.name)
    return names


def verify(directory: Path, version: str, contract_set: str) -> None:
    expected = expected_names(version, contract_set)
    actual = actual_regular_names(directory)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise AssetContractError(
            f"release asset set {contract_set!r} is not exact: " + "; ".join(details)
        )


def write_policy(path: Path, version: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.name != POLICY_NAME:
        raise AssetContractError(f"policy filename must be exactly {POLICY_NAME}")
    if path.exists():
        raise AssetContractError(f"refusing to replace existing policy: {path}")
    path.write_text(
        json.dumps(policy(version), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)
    expected = subcommands.add_parser("expected")
    expected.add_argument("--version", required=True)
    expected.add_argument("--set", required=True, dest="contract_set")
    verify_parser = subcommands.add_parser("verify")
    verify_parser.add_argument("--version", required=True)
    verify_parser.add_argument("--set", required=True, dest="contract_set")
    verify_parser.add_argument("--directory", required=True, type=Path)
    write = subcommands.add_parser("write-policy")
    write.add_argument("--version", required=True)
    write.add_argument("--output", required=True, type=Path)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "expected":
            print("\n".join(sorted(expected_names(args.version, args.contract_set))))
        elif args.command == "verify":
            verify(args.directory, args.version, args.contract_set)
            print(
                f"release asset contract {args.contract_set}: "
                f"{len(expected_names(args.version, args.contract_set))} exact files"
            )
        elif args.command == "write-policy":
            write_policy(args.output, args.version)
        else:  # pragma: no cover - argparse owns the command space
            raise AssetContractError(f"unsupported command: {args.command}")
    except (AssetContractError, OSError) as error:
        print(f"release asset contract failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
