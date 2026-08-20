#!/usr/bin/env python3
"""Fail closed on the temporary Matrix-only ``bitmaps`` advisory exception.

The two ignored advisories have no upstream-compatible remediation yet.  This
gate makes that narrow exception self-expiring and rejects graph/configuration
drift before cargo-audit and cargo-deny are allowed to rely on it.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
import json
from pathlib import Path
import sys
import tomllib
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_CONFIG = ROOT / "SRC" / ".cargo" / "audit.toml"
DEFAULT_DENY_CONFIG = ROOT / "SRC" / "deny.toml"
EXPIRY_DATE = date(2026, 11, 13)
TEMPORARY_ADVISORIES = (
    "RUSTSEC-2026-0247",
    "RUSTSEC-2025-0167",
)
BITMAPS_NAME = "bitmaps"
BITMAPS_VERSION = "3.2.1"
CRATES_IO_REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
# These exact package versions form the reviewed immutable-collections and
# Matrix SDK reverse chain. A version or path change fails until it is reviewed
# and explicitly added here; a crate-name prefix is intentionally insufficient.
IMMUTABLE_COLLECTIONS_PACKAGES = {
    "imbl": "6.1.0",
    "imbl-sized-chunks": "0.1.3",
    "eyeball-im": "0.8.0",
}
MATRIX_CHAIN_PACKAGES = {
    "matrix-sdk": "0.18.0",
    "matrix-sdk-base": "0.18.0",
    "matrix-sdk-common": "0.18.0",
    "matrix-sdk-crypto": "0.18.0",
    "matrix-sdk-indexeddb": "0.18.0",
    "matrix-sdk-sqlite": "0.18.0",
}
REVIEWED_PACKAGE_VERSIONS = {
    BITMAPS_NAME: BITMAPS_VERSION,
    **IMMUTABLE_COLLECTIONS_PACKAGES,
    **MATRIX_CHAIN_PACKAGES,
}


class AdvisoryExceptionGateError(ValueError):
    """The temporary advisory exception no longer has its required evidence."""


def current_utc_date() -> date:
    """Return the date used for an unattended CI evaluation."""

    return datetime.now(timezone.utc).date()


def require_unexpired(*, today: date) -> None:
    """Reject the exception on and after its published re-evaluation date."""

    if today >= EXPIRY_DATE:
        raise AdvisoryExceptionGateError(
            "temporary bitmaps advisory exceptions expired on "
            f"{EXPIRY_DATE.isoformat()}; remove or explicitly re-review them"
        )


def _load_toml(path: Path) -> dict[str, object]:
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise AdvisoryExceptionGateError(
            f"cannot read TOML configuration {path}: {error}"
        ) from error
    if not isinstance(loaded, dict):  # Defensive: tomllib currently guarantees it.
        raise AdvisoryExceptionGateError(f"TOML configuration {path} is not an object")
    return loaded


def _temporary_counts(values: object, *, location: str) -> Counter[str]:
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise AdvisoryExceptionGateError(
            f"{location} must be a list of advisory identifier strings"
        )
    return Counter(value for value in values if value in TEMPORARY_ADVISORIES)


def _deny_temporary_counts(values: object) -> Counter[str]:
    if not isinstance(values, list):
        raise AdvisoryExceptionGateError("deny.toml [advisories].ignore must be a list")
    identifiers: list[str] = []
    for index, entry in enumerate(values):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise AdvisoryExceptionGateError(
                "deny.toml [advisories].ignore entry "
                f"{index} must be an object with a string id"
            )
        identifier = entry["id"]
        if identifier in TEMPORARY_ADVISORIES:
            identifiers.append(identifier)
    return Counter(identifiers)


def require_synchronized_configurations(
    audit_config: dict[str, object],
    deny_config: dict[str, object],
) -> None:
    """Require one copy of both exception IDs in each independently used tool."""

    audit_advisories = audit_config.get("advisories")
    deny_advisories = deny_config.get("advisories")
    if not isinstance(audit_advisories, dict):
        raise AdvisoryExceptionGateError("audit.toml has no [advisories] table")
    if not isinstance(deny_advisories, dict):
        raise AdvisoryExceptionGateError("deny.toml has no [advisories] table")
    audit_counts = _temporary_counts(
        audit_advisories.get("ignore"), location="audit.toml [advisories].ignore"
    )
    deny_counts = _deny_temporary_counts(deny_advisories.get("ignore"))
    expected = Counter({identifier: 1 for identifier in TEMPORARY_ADVISORIES})
    if audit_counts != expected or deny_counts != expected:
        raise AdvisoryExceptionGateError(
            "temporary bitmaps advisory exceptions must occur exactly once in "
            "both SRC/.cargo/audit.toml and SRC/deny.toml; "
            f"audit={dict(audit_counts)!r}, deny={dict(deny_counts)!r}"
        )


def _metadata_packages(
    metadata: object,
) -> tuple[dict[str, dict[str, object]], set[str], list[tuple[str, list[str]]]]:
    if not isinstance(metadata, dict):
        raise AdvisoryExceptionGateError("cargo metadata root must be an object")
    raw_packages = metadata.get("packages")
    raw_workspace = metadata.get("workspace_members")
    resolve = metadata.get("resolve")
    if not isinstance(raw_packages, list) or not isinstance(raw_workspace, list):
        raise AdvisoryExceptionGateError(
            "cargo metadata must contain packages and workspace_members lists"
        )
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise AdvisoryExceptionGateError(
            "cargo metadata has no resolved dependency nodes"
        )
    packages: dict[str, dict[str, object]] = {}
    for index, package in enumerate(raw_packages):
        if not isinstance(package, dict):
            raise AdvisoryExceptionGateError(
                f"cargo metadata package {index} is not an object"
            )
        identifier = package.get("id")
        name = package.get("name")
        version = package.get("version")
        if (
            not isinstance(identifier, str)
            or not identifier
            or not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
        ):
            raise AdvisoryExceptionGateError(
                f"cargo metadata package {index} has no valid id, name, or version"
            )
        if identifier in packages:
            raise AdvisoryExceptionGateError(
                f"cargo metadata repeats package id {identifier!r}"
            )
        packages[identifier] = package
    workspace_members: set[str] = set()
    for identifier in raw_workspace:
        if not isinstance(identifier, str) or identifier not in packages:
            raise AdvisoryExceptionGateError(
                "cargo metadata workspace_members contains an unknown package id"
            )
        workspace_members.add(identifier)
    if len(workspace_members) != len(raw_workspace):
        raise AdvisoryExceptionGateError("cargo metadata repeats a workspace member")
    nodes: list[tuple[str, list[str]]] = []
    for index, node in enumerate(resolve["nodes"]):
        if not isinstance(node, dict):
            raise AdvisoryExceptionGateError(
                f"cargo metadata resolve node {index} is not an object"
            )
        identifier = node.get("id")
        dependencies = node.get("dependencies")
        if not isinstance(identifier, str) or identifier not in packages:
            raise AdvisoryExceptionGateError(
                f"cargo metadata resolve node {index} has an unknown package id"
            )
        if not isinstance(dependencies, list):
            raise AdvisoryExceptionGateError(
                f"cargo metadata resolve node {index} has invalid dependencies"
            )
        typed_dependencies: list[str] = []
        for dependency in dependencies:
            if not isinstance(dependency, str) or dependency not in packages:
                raise AdvisoryExceptionGateError(
                    f"cargo metadata resolve node {index} has invalid dependencies"
                )
            typed_dependencies.append(dependency)
        if len(typed_dependencies) != len(set(typed_dependencies)):
            raise AdvisoryExceptionGateError(
                f"cargo metadata resolve node {index} repeats a dependency"
            )
        nodes.append((identifier, typed_dependencies))
    node_ids = [identifier for identifier, _ in nodes]
    if len(node_ids) != len(set(node_ids)) or set(node_ids) != set(packages):
        raise AdvisoryExceptionGateError(
            "cargo metadata resolve nodes must contain every package exactly once"
        )
    return packages, workspace_members, nodes


def require_matrix_only_bitmaps_chain(metadata: object) -> None:
    """Prove every resolved reverse path is the reviewed Matrix-only chain."""

    packages, workspace_members, nodes = _metadata_packages(metadata)
    for reviewed_name, reviewed_version in REVIEWED_PACKAGE_VERSIONS.items():
        candidates = [
            package for package in packages.values() if package["name"] == reviewed_name
        ]
        if len(candidates) > 1:
            raise AdvisoryExceptionGateError(
                "cargo metadata must resolve at most one canonical reviewed "
                f"package {reviewed_name}@{reviewed_version}; found {len(candidates)}"
            )
        if not candidates:
            continue
        candidate = candidates[0]
        if (
            candidate["version"] != reviewed_version
            or candidate.get("source") != CRATES_IO_REGISTRY_SOURCE
        ):
            raise AdvisoryExceptionGateError(
                "cargo metadata reviewed package must use its exact canonical "
                f"crates.io source and version: {reviewed_name}@{reviewed_version}"
            )
    bitmaps = [
        package for package in packages.values() if package["name"] == BITMAPS_NAME
    ]
    if len(bitmaps) != 1:
        raise AdvisoryExceptionGateError(
            "cargo metadata must resolve exactly one bitmaps package; "
            f"found {len(bitmaps)}"
        )
    target = bitmaps[0]
    if target["version"] != BITMAPS_VERSION:
        raise AdvisoryExceptionGateError(
            f"cargo metadata resolved {BITMAPS_NAME}@{target['version']}; "
            f"expected exactly {BITMAPS_NAME}@{BITMAPS_VERSION}"
        )

    reverse: dict[str, list[str]] = defaultdict(list)
    for node_id, dependencies in nodes:
        for dependency in dependencies:
            reverse[dependency].append(node_id)
    for parents in reverse.values():
        parents.sort()

    # The graph is walked reverse (dependency -> dependent) with a fixed state
    # machine. This checks every possible workspace path, not merely one tree
    # cargo happens to print. State 3 requires the first reviewed Matrix SDK
    # package; only state 4 may terminate at a workspace member.
    # `imbl` uses bitmaps both directly and through imbl-sized-chunks. Both
    # routes converge at imbl before the reviewed Matrix SDK segment.
    states = {
        1: ("imbl", 2),
    }
    visited: set[tuple[str, int]] = set()
    active: set[tuple[str, int]] = set()
    terminal_paths = 0

    def require_reviewed_version(
        package: dict[str, object],
        expected_versions: dict[str, str],
        rendered: tuple[str, ...],
    ) -> None:
        name = package["name"]
        version = package["version"]
        if not isinstance(name, str) or not isinstance(version, str):
            raise AdvisoryExceptionGateError(
                "cargo metadata package has a non-string name or version"
            )
        if expected_versions.get(name) != version:
            raise AdvisoryExceptionGateError(
                "bitmaps reverse path uses an unreviewed immutable-collections "
                "or Matrix package version: " + " -> ".join(rendered)
            )

    def visit(identifier: str, state: int, path: tuple[str, ...]) -> None:
        nonlocal terminal_paths
        marker = (identifier, state)
        if marker in active:
            raise AdvisoryExceptionGateError(
                "bitmaps reverse path contains a cycle through the Matrix "
                "SDK chain: " + " -> ".join(path)
            )
        if marker in visited:
            return
        active.add(marker)
        try:
            parents = reverse.get(identifier, [])
            if not parents:
                package = packages[identifier]
                raise AdvisoryExceptionGateError(
                    "bitmaps reverse path does not reach a workspace package: "
                    + " -> ".join(path + (str(package["name"]),))
                )
            for parent_id in parents:
                parent = packages[parent_id]
                parent_name = parent["name"]
                rendered = path + (str(parent_name),)
                if state == 0:
                    if parent_name == "imbl":
                        require_reviewed_version(
                            parent, IMMUTABLE_COLLECTIONS_PACKAGES, rendered
                        )
                        visit(parent_id, 2, rendered)
                        continue
                    if parent_name == "imbl-sized-chunks":
                        require_reviewed_version(
                            parent, IMMUTABLE_COLLECTIONS_PACKAGES, rendered
                        )
                        visit(parent_id, 1, rendered)
                        continue
                    raise AdvisoryExceptionGateError(
                        "bitmaps has a non-Matrix immutable-collections reverse "
                        "path; expected 'imbl' or 'imbl-sized-chunks', found "
                        f"{parent_name!r}: " + " -> ".join(rendered)
                    )
                if state == 2:
                    if parent_name == "eyeball-im":
                        require_reviewed_version(
                            parent, IMMUTABLE_COLLECTIONS_PACKAGES, rendered
                        )
                        visit(parent_id, 3, rendered)
                        continue
                    if parent_name in MATRIX_CHAIN_PACKAGES:
                        require_reviewed_version(
                            parent, MATRIX_CHAIN_PACKAGES, rendered
                        )
                        visit(parent_id, 4, rendered)
                        continue
                    raise AdvisoryExceptionGateError(
                        "bitmaps reverse path leaves the reviewed Matrix SDK "
                        "immutable-collections chain: " + " -> ".join(rendered)
                    )
                if state in states:
                    expected_name, next_state = states[state]
                    if parent_name != expected_name:
                        raise AdvisoryExceptionGateError(
                            "bitmaps has a non-Matrix immutable-collections reverse "
                            "path; expected "
                            f"{expected_name!r}, found {parent_name!r}: "
                            + " -> ".join(rendered)
                        )
                    require_reviewed_version(
                        parent, IMMUTABLE_COLLECTIONS_PACKAGES, rendered
                    )
                    visit(parent_id, next_state, rendered)
                    continue
                if state == 3:
                    if parent_id in workspace_members:
                        raise AdvisoryExceptionGateError(
                            "bitmaps reverse path reaches a workspace package before "
                            "a reviewed Matrix SDK package: " + " -> ".join(rendered)
                        )
                    if parent_name not in MATRIX_CHAIN_PACKAGES:
                        raise AdvisoryExceptionGateError(
                            "bitmaps reverse path leaves the reviewed Matrix SDK chain: "
                            + " -> ".join(rendered)
                        )
                    require_reviewed_version(parent, MATRIX_CHAIN_PACKAGES, rendered)
                    visit(parent_id, 4, rendered)
                    continue
                if parent_id in workspace_members:
                    terminal_paths += 1
                    continue
                if parent_name not in MATRIX_CHAIN_PACKAGES:
                    raise AdvisoryExceptionGateError(
                        "bitmaps reverse path leaves the reviewed Matrix SDK chain: "
                        + " -> ".join(rendered)
                    )
                require_reviewed_version(parent, MATRIX_CHAIN_PACKAGES, rendered)
                visit(parent_id, state, rendered)
            visited.add(marker)
        finally:
            active.remove(marker)

    visit(str(target["id"]), 0, (f"{BITMAPS_NAME}@{BITMAPS_VERSION}",))
    if terminal_paths == 0:
        raise AdvisoryExceptionGateError(
            "bitmaps has no reverse path to a workspace package"
        )


def validate(
    *,
    audit_config: dict[str, object],
    deny_config: dict[str, object],
    metadata: object,
    today: date,
) -> None:
    """Run the complete self-expiring, synchronized Matrix-only exception gate."""

    require_unexpired(today=today)
    require_synchronized_configurations(audit_config, deny_config)
    require_matrix_only_bitmaps_chain(metadata)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--metadata", type=Path, required=True)
    result.add_argument("--audit-config", type=Path, default=DEFAULT_AUDIT_CONFIG)
    result.add_argument("--deny-config", type=Path, default=DEFAULT_DENY_CONFIG)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate(
            audit_config=_load_toml(args.audit_config),
            deny_config=_load_toml(args.deny_config),
            metadata=json.loads(args.metadata.read_text(encoding="utf-8")),
            today=current_utc_date(),
        )
    except (
        AdvisoryExceptionGateError,
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(
            f"::error::temporary bitmaps advisory exception gate failed: {error}",
            file=sys.stderr,
        )
        return 1
    print(
        "temporary bitmaps advisory exception gate passed: synchronized Matrix-only "
        f"exception remains valid before {EXPIRY_DATE.isoformat()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
