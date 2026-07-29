#!/usr/bin/env python3
"""Validate the pinned OpenClaw provider snapshot and NEOTH parity matrix.

The default check is offline and deterministic. ``--check-upstream`` is the
release-only freshness gate: it resolves one OpenClaw main commit, then reads
the provider documentation and extension manifests from that immutable commit.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_SNAPSHOT_PATH = (
    REPOSITORY_ROOT
    / "packaging"
    / "provider-parity"
    / "openclaw-provider-snapshot.json"
)
DEFAULT_MATRIX_PATH = (
    REPOSITORY_ROOT
    / "packaging"
    / "provider-parity"
    / "neoth-openclaw-provider-matrix.json"
)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
MANIFEST_PATH = re.compile(r"^extensions/[^/]+/openclaw\.plugin\.json$")
DISPOSITIONS = {"native", "typed_compatible", "missing"}
IMPLEMENTATION_STATUSES = {
    "native_complete",
    "typed_compatible_complete",
    "partial_native",
    "openai_compat_preset",
    "partial_generic_endpoint",
    "absent",
}
SOURCE_SCOPES = {"llm_inference", "non_llm"}
# Reviewed against the pinned manifests: these provider registrations expose
# media generation/speech contracts only, not LLM inference. Keep this list in
# executable code so editing snapshot metadata cannot hide an LLM provider.
NON_LLM_PROVIDER_MANIFESTS = {
    "extensions/comfy/openclaw.plugin.json": ("comfy",),
    "extensions/fal/openclaw.plugin.json": ("fal",),
    "extensions/vydra/openclaw.plugin.json": ("vydra",),
}


class ContractError(ValueError):
    """A checked-in or upstream provider-parity contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot load {path}: {error}") from error
    require(isinstance(value, dict), f"{path} root must be an object")
    return value


def _require_timestamp(value: object, field: str) -> None:
    require(isinstance(value, str) and value.endswith("Z"), f"{field} must be UTC")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError(f"{field} is not an ISO-8601 timestamp") from error
    require(parsed.tzinfo is not None, f"{field} must include a timezone")


def _require_string_list(value: object, field: str) -> list[str]:
    require(isinstance(value, list), f"{field} must be an array")
    require(
        all(isinstance(item, str) and item for item in value),
        f"{field} must contain non-empty strings",
    )
    result = list(value)
    require(len(result) == len(set(result)), f"{field} contains duplicate entries")
    return result


def _require_evidence_paths(value: object, field: str) -> list[str]:
    paths = _require_string_list(value, field)
    repository_root = REPOSITORY_ROOT.resolve(strict=True)
    for path_string in paths:
        require(
            "\\" not in path_string and ":" not in path_string,
            f"{field} must use a canonical repository-relative POSIX path",
        )
        path = pathlib.PurePosixPath(path_string)
        require(
            not path.is_absolute() and ".." not in path.parts,
            f"{field} contains a path outside the repository",
        )
        try:
            local_path = repository_root.joinpath(*path.parts).resolve(strict=True)
        except OSError as error:
            raise ContractError(f"{field} path does not exist: {path_string}") from error
        try:
            local_path.relative_to(repository_root)
        except ValueError as error:
            raise ContractError(
                f"{field} resolves outside the repository: {path_string}"
            ) from error
        require(local_path.is_file(), f"{field} path is not a file: {path_string}")
    return paths


def validate_contract(
    snapshot: dict[str, Any], matrix: dict[str, Any]
) -> dict[str, int]:
    """Validate both checked-in files and return stable inventory counts."""

    require(snapshot.get("schema_version") == 1, "snapshot schema_version must be 1")
    require(snapshot.get("contract") == "GOLD-R4-14", "snapshot contract drifted")
    _require_timestamp(snapshot.get("retrieved_at"), "snapshot.retrieved_at")

    upstream = snapshot.get("upstream")
    require(isinstance(upstream, dict), "snapshot.upstream must be an object")
    require(
        upstream.get("repository") == "openclaw/openclaw",
        "snapshot upstream repository drifted",
    )
    require(upstream.get("branch") == "main", "snapshot upstream branch drifted")
    require(
        isinstance(upstream.get("head_commit"), str)
        and HEX40.fullmatch(upstream["head_commit"]) is not None,
        "snapshot upstream head_commit must be a lowercase Git SHA",
    )
    _require_timestamp(
        upstream.get("head_committed_at"), "snapshot.upstream.head_committed_at"
    )

    documentation = upstream.get("documentation")
    require(
        isinstance(documentation, dict),
        "snapshot upstream documentation must be an object",
    )
    require(
        documentation.get("path") == "docs/concepts/model-providers.md",
        "OpenClaw provider documentation path drifted",
    )
    for field in ("last_commit", "blob_sha"):
        require(
            isinstance(documentation.get(field), str)
            and HEX40.fullmatch(documentation[field]) is not None,
            f"snapshot documentation {field} must be a lowercase Git SHA",
        )
    require(
        isinstance(documentation.get("sha256"), str)
        and HEX64.fullmatch(documentation["sha256"]) is not None,
        "snapshot documentation sha256 is invalid",
    )
    require(
        isinstance(documentation.get("bytes"), int)
        and documentation["bytes"] > 0,
        "snapshot documentation byte count is invalid",
    )
    _require_timestamp(
        documentation.get("last_committed_at"),
        "snapshot.upstream.documentation.last_committed_at",
    )
    expected_source_url = (
        "https://github.com/openclaw/openclaw/blob/"
        f"{documentation['last_commit']}/{documentation['path']}"
    )
    require(
        documentation.get("source_url") == expected_source_url,
        "snapshot documentation source_url is not commit-pinned",
    )

    registry = upstream.get("registry")
    require(isinstance(registry, dict), "snapshot upstream registry must be an object")
    require(
        registry.get("source_rule")
        == "top-level providers arrays in extensions/*/openclaw.plugin.json",
        "snapshot registry source rule drifted",
    )
    manifests = registry.get("manifests")
    require(isinstance(manifests, list) and manifests, "registry manifests are empty")

    manifest_paths: list[str] = []
    all_upstream_ids: list[str] = []
    llm_provider_ids: list[str] = []
    non_llm_provider_ids: list[str] = []
    for index, manifest in enumerate(manifests):
        field = f"snapshot.upstream.registry.manifests[{index}]"
        require(isinstance(manifest, dict), f"{field} must be an object")
        path = manifest.get("path")
        require(
            isinstance(path, str) and MANIFEST_PATH.fullmatch(path) is not None,
            f"{field}.path is not an extension manifest path",
        )
        manifest_paths.append(path)
        require(
            isinstance(manifest.get("blob_sha"), str)
            and HEX40.fullmatch(manifest["blob_sha"]) is not None,
            f"{field}.blob_sha must be a lowercase Git SHA",
        )
        scope = manifest.get("scope")
        require(scope in SOURCE_SCOPES, f"{field}.scope is unclassified")
        provider_ids = _require_string_list(
            manifest.get("provider_ids"), f"{field}.provider_ids"
        )
        require(
            all(PROVIDER_ID.fullmatch(provider_id) for provider_id in provider_ids),
            f"{field}.provider_ids contains an invalid provider id",
        )
        expected_non_llm_ids = NON_LLM_PROVIDER_MANIFESTS.get(path)
        if expected_non_llm_ids is None:
            require(
                scope == "llm_inference",
                f"{field} is not in the reviewed non-LLM provider allowlist",
            )
        else:
            require(
                scope == "non_llm",
                f"{field} must retain its reviewed non-LLM classification",
            )
            require(
                tuple(provider_ids) == expected_non_llm_ids,
                f"{field}.provider_ids drifted from the reviewed non-LLM allowlist",
            )
        all_upstream_ids.extend(provider_ids)
        if scope == "llm_inference":
            llm_provider_ids.extend(provider_ids)
        else:
            non_llm_provider_ids.extend(provider_ids)

    require(
        manifest_paths == sorted(manifest_paths),
        "registry manifests must be sorted by path",
    )
    require(
        len(manifest_paths) == len(set(manifest_paths)),
        "registry contains duplicate manifest paths",
    )
    require(
        len(all_upstream_ids) == len(set(all_upstream_ids)),
        "registry contains duplicate provider ids",
    )
    require(
        set(NON_LLM_PROVIDER_MANIFESTS) <= set(manifest_paths),
        "reviewed non-LLM provider manifest is missing from the snapshot",
    )

    operator_defined_id = upstream.get("operator_defined_provider_id")
    require(
        operator_defined_id == "operator-defined",
        "operator-defined provider sentinel drifted",
    )
    require(
        operator_defined_id not in all_upstream_ids,
        "operator-defined sentinel collides with an upstream provider id",
    )

    require(matrix.get("schema_version") == 1, "matrix schema_version must be 1")
    require(matrix.get("contract") == "GOLD-R4-14", "matrix contract drifted")
    require(
        matrix.get("snapshot_head") == upstream["head_commit"],
        "matrix is not bound to the snapshot head",
    )
    rows = matrix.get("providers")
    require(isinstance(rows, list) and rows, "provider matrix is empty")

    matrix_ids: list[str] = []
    disposition_counts = {disposition: 0 for disposition in sorted(DISPOSITIONS)}
    status_counts = {status: 0 for status in sorted(IMPLEMENTATION_STATUSES)}
    for index, row in enumerate(rows):
        field = f"matrix.providers[{index}]"
        require(isinstance(row, dict), f"{field} must be an object")
        provider_id = row.get("id")
        require(
            isinstance(provider_id, str)
            and PROVIDER_ID.fullmatch(provider_id) is not None,
            f"{field}.id is invalid",
        )
        require("alias_of" not in row, f"{field} silently aliases another provider")
        matrix_ids.append(provider_id)

        disposition = row.get("disposition")
        require(disposition in DISPOSITIONS, f"{field}.disposition is unclassified")
        disposition_counts[disposition] += 1

        implementation_status = row.get("implementation_status")
        require(
            implementation_status in IMPLEMENTATION_STATUSES,
            f"{field}.implementation_status is unclassified",
        )
        status_counts[implementation_status] += 1
        bindings = _require_string_list(row.get("neoth_bindings"), f"{field}.neoth_bindings")
        evidence = _require_evidence_paths(row.get("evidence"), f"{field}.evidence")
        tests = _require_string_list(row.get("tests"), f"{field}.tests")

        # This bounded slice establishes the source baseline, not runtime
        # completeness. Schema v1 therefore cannot promote a row based on
        # unchecked strings. A later schema must add and execute a typed
        # registry-to-factory-to-surface proof before enabling either complete
        # disposition.
        require(
            disposition == "missing",
            f"{field} schema v1 cannot assert complete parity; "
            "add an executable registry-to-factory-to-surface proof and bump the schema",
        )
        require(
            implementation_status
            not in {"native_complete", "typed_compatible_complete"},
            f"{field} is marked missing but claims a complete implementation",
        )
        require(not tests, f"{field} schema v1 does not accept parity test claims")

        if implementation_status == "absent":
            require(
                not bindings,
                f"{field} is absent but still names a NEOTH provider binding",
            )
        else:
            require(bindings, f"{field} implementation status lacks a NEOTH binding")
            require(evidence, f"{field} implementation status lacks source evidence")

    require(matrix_ids == sorted(matrix_ids), "provider matrix must be sorted by id")
    require(
        len(matrix_ids) == len(set(matrix_ids)),
        "provider matrix contains duplicate provider ids",
    )
    expected_matrix_ids = set(llm_provider_ids)
    expected_matrix_ids.add(operator_defined_id)
    actual_matrix_ids = set(matrix_ids)
    missing = sorted(expected_matrix_ids - actual_matrix_ids)
    extra = sorted(actual_matrix_ids - expected_matrix_ids)
    require(not missing, f"provider matrix is missing provider entries: {missing}")
    require(not extra, f"provider matrix contains stale provider entries: {extra}")
    require(
        not (actual_matrix_ids & set(non_llm_provider_ids)),
        "non-LLM media providers leaked into the LLM parity matrix",
    )

    return {
        "manifest_count": len(manifests),
        "llm_provider_count": len(llm_provider_ids),
        "non_llm_provider_count": len(non_llm_provider_ids),
        "matrix_provider_count": len(rows),
        **{f"disposition_{key}": value for key, value in disposition_counts.items()},
        **{f"status_{key}": value for key, value in status_counts.items()},
    }


def observed_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Build a no-network observed fixture from a validated snapshot."""

    upstream = snapshot["upstream"]
    documentation = upstream["documentation"]
    return {
        "repository_head": upstream["head_commit"],
        "documentation": {
            "path": documentation["path"],
            "blob_sha": documentation["blob_sha"],
            "sha256": documentation["sha256"],
            "bytes": documentation["bytes"],
        },
        "provider_manifests": [
            {
                "path": manifest["path"],
                "blob_sha": manifest["blob_sha"],
                "provider_ids": copy.deepcopy(manifest["provider_ids"]),
            }
            for manifest in upstream["registry"]["manifests"]
        ],
    }


def compare_upstream(
    snapshot: dict[str, Any], observed: dict[str, Any]
) -> list[str]:
    """Fail if current upstream provider-bearing inputs differ from the pin."""

    expected_docs = snapshot["upstream"]["documentation"]
    observed_docs = observed.get("documentation")
    require(
        isinstance(observed_docs, dict),
        "upstream observation lacks provider documentation",
    )
    drift: list[str] = []
    for field in ("path", "blob_sha", "sha256", "bytes"):
        if observed_docs.get(field) != expected_docs.get(field):
            drift.append(
                "provider documentation "
                f"{field}: pinned={expected_docs.get(field)!r} "
                f"current={observed_docs.get(field)!r}"
            )

    expected_manifests = {
        manifest["path"]: manifest
        for manifest in snapshot["upstream"]["registry"]["manifests"]
    }
    observed_rows = observed.get("provider_manifests")
    require(
        isinstance(observed_rows, list),
        "upstream observation lacks provider manifests",
    )
    observed_manifests: dict[str, dict[str, Any]] = {}
    for row in observed_rows:
        require(isinstance(row, dict), "observed provider manifest must be an object")
        path = row.get("path")
        require(isinstance(path, str), "observed provider manifest path is invalid")
        require(
            path not in observed_manifests,
            f"observed provider manifest is duplicated: {path}",
        )
        observed_manifests[path] = row

    missing_paths = sorted(expected_manifests.keys() - observed_manifests.keys())
    new_paths = sorted(observed_manifests.keys() - expected_manifests.keys())
    if missing_paths:
        drift.append(f"provider manifests removed: {missing_paths}")
    if new_paths:
        drift.append(f"provider manifests added: {new_paths}")
    for path in sorted(expected_manifests.keys() & observed_manifests.keys()):
        expected = expected_manifests[path]
        current = observed_manifests[path]
        for field in ("blob_sha", "provider_ids"):
            if current.get(field) != expected.get(field):
                drift.append(
                    f"{path} {field}: pinned={expected.get(field)!r} "
                    f"current={current.get(field)!r}"
                )

    require(
        not drift,
        "OpenClaw provider release drift detected; re-snapshot and review:\n- "
        + "\n- ".join(drift),
    )
    return drift


def _request_bytes(url: str, token: str | None) -> bytes:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "NEOTH-GOLD-R4-14-provider-parity",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as error:
        raise ContractError(f"upstream request failed for {url}: {error}") from error


def _request_json(url: str, token: str | None) -> dict[str, Any]:
    raw = _request_bytes(url, token)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"upstream returned invalid JSON for {url}: {error}") from error
    require(isinstance(value, dict), f"upstream JSON root is not an object: {url}")
    return value


def fetch_upstream(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Fetch current provider-bearing inputs from one immutable upstream HEAD."""

    upstream = snapshot["upstream"]
    repository = upstream["repository"]
    branch = upstream["branch"]
    token = os.environ.get("GITHUB_TOKEN") or None
    api_base = f"https://api.github.com/repos/{repository}"
    commit = _request_json(
        f"{api_base}/commits/{urllib.parse.quote(branch, safe='')}", token
    )
    head = commit.get("sha")
    require(
        isinstance(head, str) and HEX40.fullmatch(head) is not None,
        "upstream main did not resolve to a Git SHA",
    )

    tree = _request_json(f"{api_base}/git/trees/{head}?recursive=1", token)
    require(tree.get("truncated") is False, "upstream Git tree response was truncated")
    tree_rows = tree.get("tree")
    require(isinstance(tree_rows, list), "upstream Git tree is missing")
    blobs = {
        row["path"]: row["sha"]
        for row in tree_rows
        if isinstance(row, dict)
        and row.get("type") == "blob"
        and isinstance(row.get("path"), str)
        and isinstance(row.get("sha"), str)
    }

    docs_path = upstream["documentation"]["path"]
    docs_blob = blobs.get(docs_path)
    require(
        isinstance(docs_blob, str) and HEX40.fullmatch(docs_blob) is not None,
        f"upstream provider documentation is missing: {docs_path}",
    )
    raw_base = f"https://raw.githubusercontent.com/{repository}/{head}"
    docs_raw = _request_bytes(
        f"{raw_base}/{urllib.parse.quote(docs_path, safe='/')}", token
    )

    candidate_manifests = sorted(
        path for path in blobs if MANIFEST_PATH.fullmatch(path) is not None
    )

    def fetch_manifest(path: str) -> dict[str, Any] | None:
        raw = _request_bytes(
            f"{raw_base}/{urllib.parse.quote(path, safe='/')}", token
        )
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ContractError(f"upstream manifest is invalid JSON: {path}: {error}") from error
        require(isinstance(manifest, dict), f"upstream manifest root is invalid: {path}")
        provider_ids = manifest.get("providers")
        if provider_ids is None:
            return None
        provider_ids = _require_string_list(provider_ids, f"upstream {path}.providers")
        if not provider_ids:
            return None
        require(
            all(PROVIDER_ID.fullmatch(provider_id) for provider_id in provider_ids),
            f"upstream {path}.providers contains an invalid provider id",
        )
        return {
            "path": path,
            "blob_sha": blobs[path],
            "provider_ids": provider_ids,
        }

    provider_manifests: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = {
            executor.submit(fetch_manifest, path): path for path in candidate_manifests
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                manifest = future.result()
            except Exception as error:
                if isinstance(error, ContractError):
                    raise
                raise ContractError(
                    f"cannot inspect upstream manifest {futures[future]}: {error}"
                ) from error
            if manifest is not None:
                provider_manifests.append(manifest)
    provider_manifests.sort(key=lambda item: item["path"])

    return {
        "repository_head": head,
        "documentation": {
            "path": docs_path,
            "blob_sha": docs_blob,
            "sha256": hashlib.sha256(docs_raw).hexdigest(),
            "bytes": len(docs_raw),
        },
        "provider_manifests": provider_manifests,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot",
        type=pathlib.Path,
        default=DEFAULT_SNAPSHOT_PATH,
        help="checked-in OpenClaw source snapshot",
    )
    parser.add_argument(
        "--matrix",
        type=pathlib.Path,
        default=DEFAULT_MATRIX_PATH,
        help="checked-in NEOTH provider disposition matrix",
    )
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="release gate: fail if current OpenClaw provider inputs changed",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        snapshot = load_json(args.snapshot)
        matrix = load_json(args.matrix)
        counts = validate_contract(snapshot, matrix)
        if args.check_upstream:
            observed = fetch_upstream(snapshot)
            compare_upstream(snapshot, observed)
            freshness = f"; upstream_head={observed['repository_head']}"
        else:
            freshness = ""
    except ContractError as error:
        print(f"OpenClaw provider parity contract failed: {error}", file=sys.stderr)
        return 1

    print(
        "OpenClaw provider parity contract OK: "
        f"manifests={counts['manifest_count']} "
        f"upstream_llm_ids={counts['llm_provider_count']} "
        f"matrix_rows={counts['matrix_provider_count']} "
        f"native={counts['disposition_native']} "
        f"typed_compatible={counts['disposition_typed_compatible']} "
        f"missing={counts['disposition_missing']}"
        f"{freshness}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
