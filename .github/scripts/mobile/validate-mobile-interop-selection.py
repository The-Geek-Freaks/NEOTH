#!/usr/bin/env python3
"""Validate and emit the canonical hosted mobile-interop selection contract."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
from typing import Any
import unittest


SCHEMA = "neoth.mobile-interop-selection.v1"
CUSTODY_SCHEMA = "neoth.mobile-interop-selection-custody.v1"
GROUPS = ("libudx", "peeroxide", "dht", "core", "no_cluster", "bridge")
IDENTITY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*){1,}$")
METHOD_RE = re.compile(r"^test_[A-Za-z0-9_]+$")
SHA256_RE = re.compile(r"^[0-9A-F]{64}$")


class ContractError(ValueError):
    """A canonical selection cannot safely drive hosted verification."""


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid selection JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("selection root must be an object")
    return value


def _require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ContractError(f"{label} keys must be exactly {sorted(expected)}; got {sorted(actual)}")


def _safe_repo_file(repo_root: pathlib.Path, raw_path: object) -> pathlib.Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ContractError("source path must be a non-empty string")
    pure = pathlib.PurePosixPath(raw_path)
    if (
        "\\" in raw_path
        or ":" in raw_path
        or pure.as_posix() != raw_path
        or pure.is_absolute()
        or any(part in ("", ".", "..") for part in pure.parts)
    ):
        raise ContractError(f"unsafe source path: {raw_path!r}")
    candidate = repo_root.joinpath(*pure.parts)
    try:
        relative = candidate.resolve(strict=True).relative_to(repo_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ContractError(f"source path missing or outside repository: {raw_path}") from exc
    current = repo_root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ContractError(f"symlink source path is not allowed: {raw_path}")
    if not candidate.is_file():
        raise ContractError(f"source path is not a regular file: {raw_path}")
    return candidate


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def _workflow_name_counts(path: pathlib.Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in re.findall(r"^\s*-\s+name:\s+(.+?)\s*$", path.read_text(encoding="utf-8"), re.MULTILINE):
        counts[name] = counts.get(name, 0) + 1
    return counts


def _flatten_test_ids(suite: unittest.TestSuite) -> list[str]:
    test_ids: list[str] = []
    for member in suite:
        if isinstance(member, unittest.TestSuite):
            test_ids.extend(_flatten_test_ids(member))
        else:
            test_ids.append(member.id())
    return test_ids


def _collector_test_ids(path: pathlib.Path, module_name: str) -> list[str]:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ContractError(f"collector module cannot be loaded: {module_name}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        return _flatten_test_ids(unittest.defaultTestLoader.loadTestsFromModule(module))
    except Exception as exc:
        raise ContractError(f"collector module discovery failed: {exc}") from exc
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous


def _validate_builder(builder: pathlib.Path, dispatch_sources: dict[str, str]) -> None:
    text = builder.read_text(encoding="utf-8")
    expected = {
        "bridge_cargo_sha256": '$bridge/Cargo.toml',
        "bridge_lib_sha256": '$bridge/src/lib.rs',
        "bridge_header_sha256": '$bridge/include/neoth_companion_bridge.h',
        "canonical_protocol_sha256": '$protocol',
    }
    for input_name, source in dispatch_sources.items():
        if input_name not in expected:
            raise ContractError(f"unsupported dispatch hash input: {input_name}")
        if source != {
            "bridge_cargo_sha256": "bridges/companion-native/Cargo.toml",
            "bridge_lib_sha256": "bridges/companion-native/src/lib.rs",
            "bridge_header_sha256": "bridges/companion-native/include/neoth_companion_bridge.h",
            "canonical_protocol_sha256": "SRC/neothd/src/daemon/companion_protocol.rs",
        }[input_name]:
            raise ContractError(f"dispatch hash source mismatch for {input_name}")
        variable = input_name.upper()
        if text.count(variable) < 2 or expected[input_name] not in text:
            raise ContractError(f"builder no longer protects {input_name}")


def validate(manifest_path: pathlib.Path, repo_root: pathlib.Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve(strict=True)
    repo_root = repo_root.resolve(strict=True)
    try:
        manifest_relative = manifest_path.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise ContractError("manifest must be inside repository") from exc
    if manifest_relative != ".github/scripts/mobile/mobile-companion-interop-selection.json":
        raise ContractError("manifest path is fixed to the tracked canonical location")

    data = _load_json(manifest_path)
    _require_keys(data, {"schema", "groups", "collector", "sourcePaths", "dispatchHashSources"}, "selection")
    if data["schema"] != SCHEMA:
        raise ContractError(f"unsupported schema: {data['schema']!r}")
    if not isinstance(data["groups"], dict):
        raise ContractError("groups must be an object")
    if tuple(data["groups"].keys()) != GROUPS:
        raise ContractError(f"groups must be ordered exactly as {list(GROUPS)}")

    groups: dict[str, dict[str, Any]] = {}
    all_identities: set[str] = set()
    for group_name in GROUPS:
        group = data["groups"][group_name]
        if not isinstance(group, dict):
            raise ContractError(f"group {group_name} must be an object")
        _require_keys(group, {"step", "identities"}, f"group {group_name}")
        step, identities = group["step"], group["identities"]
        if not isinstance(step, str) or not step or not isinstance(identities, list) or not identities:
            raise ContractError(f"group {group_name} needs a step and identities")
        if any(not isinstance(item, str) or not IDENTITY_RE.fullmatch(item) for item in identities):
            raise ContractError(f"group {group_name} contains an unsafe Rust identity")
        if len(set(identities)) != len(identities) or all_identities.intersection(identities):
            raise ContractError(f"Rust identity duplicated in group {group_name}")
        all_identities.update(identities)
        groups[group_name] = {"step": step, "identities": identities}

    collector = data["collector"]
    if not isinstance(collector, dict):
        raise ContractError("collector must be an object")
    _require_keys(collector, {"module", "class", "identities"}, "collector")
    module, class_name, collector_identities = collector["module"], collector["class"], collector["identities"]
    if module != "test_hosted_mobile_interop_diagnostics" or not isinstance(class_name, str) or not class_name:
        raise ContractError("collector module or class is unsafe")
    if not isinstance(collector_identities, list) or not collector_identities or any(
        not isinstance(item, str) or not METHOD_RE.fullmatch(item) for item in collector_identities
    ) or len(set(collector_identities)) != len(collector_identities):
        raise ContractError("collector identities must be unique test methods")

    source_paths = data["sourcePaths"]
    if (
        not isinstance(source_paths, list)
        or not source_paths
        or any(not isinstance(path, str) for path in source_paths)
        or len(set(source_paths)) != len(source_paths)
    ):
        raise ContractError("sourcePaths must be a non-empty unique list")
    source_files = {path: _safe_repo_file(repo_root, path) for path in source_paths}
    required_new = {
        ".github/scripts/mobile/mobile-companion-interop-selection.json",
        ".github/scripts/mobile/validate-mobile-interop-selection.py",
        ".github/scripts/mobile/test_mobile_interop_selection.py",
    }
    if not required_new.issubset(source_files):
        raise ContractError("sourcePaths must retain all three canonical-contract files")

    workflow = source_files.get(".github/workflows/mobile-companion-interop.yml")
    collector_path = source_files.get(".github/scripts/mobile/test_hosted_mobile_interop_diagnostics.py")
    builder = source_files.get(".github/scripts/mobile/build-host-interop-bridge.sh")
    if workflow is None or collector_path is None or builder is None:
        raise ContractError("workflow, collector, and builder paths are mandatory")
    names = _workflow_name_counts(workflow)
    for group in groups.values():
        if names.get(group["step"], 0) != 1:
            raise ContractError(f"workflow step must occur exactly once: {group['step']}")

    expected_collector_ids = {f"{module}.{class_name}.{method}" for method in collector_identities}
    discovered_collector_ids = _collector_test_ids(collector_path, module)
    if len(discovered_collector_ids) != len(set(discovered_collector_ids)) or set(discovered_collector_ids) != expected_collector_ids:
        raise ContractError("collector unittest loader IDs do not exactly match the canonical class and set")

    dispatch_sources = data["dispatchHashSources"]
    if not isinstance(dispatch_sources, dict) or set(dispatch_sources) != {
        "bridge_cargo_sha256", "bridge_lib_sha256", "bridge_header_sha256", "canonical_protocol_sha256"
    }:
        raise ContractError("dispatchHashSources must contain exactly the four protected inputs")
    for input_name, source_path in dispatch_sources.items():
        if not isinstance(source_path, str):
            raise ContractError(f"dispatch hash source is unsafe: {input_name}")
        if source_path not in source_files:
            raise ContractError(f"dispatch hash source is not a tracked source path: {input_name}")
        if len(re.findall(rf"^\s+{re.escape(input_name)}:\s*", workflow.read_text(encoding="utf-8"), re.MULTILINE)) != 1:
            raise ContractError(f"workflow dispatch input mismatch: {input_name}")
    _validate_builder(builder, dispatch_sources)

    source_sha256 = {path: _sha256(source_files[path]) for path in source_paths}
    if any(not SHA256_RE.fullmatch(value) for value in source_sha256.values()):
        raise ContractError("internal SHA-256 encoding failure")
    return {
        "schema": CUSTODY_SCHEMA,
        "manifest": {"path": manifest_relative, "sha256": _sha256(manifest_path)},
        "groups": groups,
        "collector": {"module": module, "class": class_name, "identities": collector_identities},
        "sourcePaths": source_paths,
        "sourceSha256": source_sha256,
        "dispatchHashSources": dispatch_sources,
        "counts": {
            "rust": len(all_identities),
            "collector": len(collector_identities),
            "sources": len(source_paths),
            "groups": {name: len(groups[name]["identities"]) for name in GROUPS},
        },
    }


def _producer_head(repo_root: pathlib.Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=False, capture_output=True, text=True,
    )
    head = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ContractError("cannot determine exact producer head")
    return head


def emit(custody: dict[str, Any], output_dir: pathlib.Path, repo_root: pathlib.Path) -> None:
    if output_dir.exists():
        raise ContractError("output directory must not already exist")
    if output_dir.is_symlink():
        raise ContractError("output directory cannot be a symlink")
    custody = dict(custody)
    custody["producer"] = {"head": _producer_head(repo_root)}
    output_dir.mkdir(parents=True, exist_ok=False)
    try:
        for group_name, group in custody["groups"].items():
            (output_dir / f"{group_name}.txt").write_text("\n".join(group["identities"]) + "\n", encoding="utf-8")
        (output_dir / "collector.txt").write_text(
            "\n".join(custody["collector"]["identities"]) + "\n", encoding="utf-8"
        )
        (output_dir / "selection-custody.json").write_text(
            json.dumps(custody, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except Exception:
        for child in output_dir.iterdir():
            child.unlink()
        output_dir.rmdir()
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    script = pathlib.Path(__file__).resolve()
    parser.add_argument("--repo-root", type=pathlib.Path, default=script.parents[3])
    parser.add_argument(
        "--manifest", type=pathlib.Path,
        default=pathlib.PurePosixPath(".github/scripts/mobile/mobile-companion-interop-selection.json"),
    )
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve(strict=True)
    manifest = args.manifest if args.manifest.is_absolute() else repo_root / args.manifest
    output_dir = args.output_dir if args.output_dir.is_absolute() else repo_root / args.output_dir
    try:
        custody = validate(manifest, repo_root)
        emit(custody, output_dir, repo_root)
    except (ContractError, OSError) as exc:
        print(f"mobile interop selection contract rejected: {exc}", file=sys.stderr)
        return 64
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
