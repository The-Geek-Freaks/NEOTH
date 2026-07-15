#!/usr/bin/env python3
"""Add locally extracted AST data for tracked code Graphify's detector skips.

Graphify intentionally excludes sensitive-looking filenames before deciding
whether a file is code or prose. That is correct for semantic/cloud extraction,
but names such as ``credentials.rs`` are public, tracked source and essential to
NEOTH's architecture map. This release-only phase recovers those files through
Graphify's local AST extractor; it never submits their bytes to an LLM backend.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from graphify.build import dedupe_edges, dedupe_nodes
from graphify.detect import FileType, classify_file, detect, save_manifest
from graphify.extract import _get_extractor, extract


def git_tracked_code(repo: Path) -> list[Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=repo)
    paths = []
    for relative in raw.decode("utf-8").split("\0"):
        if not relative:
            continue
        path = repo / relative
        if classify_file(path) != FileType.CODE:
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"tracked code is not a regular file: {relative}")
        if _get_extractor(path) is None:
            raise RuntimeError(
                f"Graphify 0.8.41 has no AST extractor for tracked code: {relative}"
            )
        paths.append(path.resolve())
    if not paths:
        raise RuntimeError("release source contains no tracked Graphify code inputs")
    return sorted(set(paths))


def resolved_source_file(raw: Any, repo: Path) -> Path | None:
    if not isinstance(raw, str) or not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = repo / path
    try:
        resolved = path.resolve()
        resolved.relative_to(repo)
    except (OSError, ValueError):
        return None
    return resolved


def write_json_atomic(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.neoth-ast.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def augment(repo: Path, graph_path: Path) -> int:
    repo = repo.resolve()
    graph_path = graph_path.resolve()
    expected_graph = repo / "graphify-out" / "graph.json"
    if graph_path != expected_graph:
        raise RuntimeError(f"graph path must be exactly {expected_graph}")
    if not graph_path.is_file() or graph_path.is_symlink():
        raise RuntimeError("Graphify raw graph is missing or unsafe")

    tracked = set(git_tracked_code(repo))
    detection = detect(repo, follow_symlinks=False, google_workspace=False)
    detected = {
        resolved
        for raw in detection.get("files", {}).get("code", [])
        if (resolved := resolved_source_file(raw, repo)) is not None
    }
    if not detected.issubset(tracked):
        raise RuntimeError("Graphify detector selected untracked code")
    missing = sorted(tracked - detected)
    if not missing:
        print("tracked-code AST augmentation: no detector omissions")
        return 0

    extracted = extract(missing, cache_root=repo)
    nodes = extracted.get("nodes")
    edges = extracted.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise RuntimeError("Graphify AST augmentation returned an invalid graph fragment")
    covered = {
        resolved
        for item in [*nodes, *edges]
        if isinstance(item, dict)
        and (resolved := resolved_source_file(item.get("source_file"), repo)) is not None
    }
    uncovered = sorted(tracked_path for tracked_path in missing if tracked_path not in covered)
    if uncovered:
        names = ", ".join(path.relative_to(repo).as_posix() for path in uncovered[:8])
        raise RuntimeError(f"Graphify AST augmentation omitted tracked code: {names}")

    raw = json.loads(graph_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("nodes"), list) or not isinstance(raw.get("edges"), list):
        raise RuntimeError("Graphify raw graph has an invalid extraction schema")
    raw["nodes"] = dedupe_nodes([*nodes, *raw["nodes"]])
    raw["edges"] = dedupe_edges([*edges, *raw["edges"]])
    raw["input_tokens"] = int(raw.get("input_tokens", 0)) + int(
        extracted.get("input_tokens", 0)
    )
    raw["output_tokens"] = int(raw.get("output_tokens", 0)) + int(
        extracted.get("output_tokens", 0)
    )
    write_json_atomic(graph_path, raw)

    manifest_path = repo / "graphify-out" / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RuntimeError("Graphify manifest is missing before AST augmentation")
    save_manifest(
        {"code": [str(path) for path in missing]},
        manifest_path=str(manifest_path),
        kind="ast",
        root=repo,
    )
    print(
        "tracked-code AST augmentation: "
        f"{len(missing)} locally recovered file(s), {len(nodes)} nodes, {len(edges)} edges"
    )
    return len(missing)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repo", required=True)
    result.add_argument("--graph", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        augment(Path(args.repo), Path(args.graph))
    except Exception as error:
        print(f"tracked-code AST augmentation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
