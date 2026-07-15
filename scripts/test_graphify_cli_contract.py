#!/usr/bin/env python3
"""Exercise the real pinned Graphify CLI before spending release LLM budget."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from build_release_self_knowledge import (
    mark_raw_extraction_directed,
)
from graphify.detect import FileType, classify_file, detect
from graphify.extract import _get_extractor


def run(argv: list[str], *, cwd: Path) -> None:
    subprocess.run(argv, cwd=cwd, check=True)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def real_detector_selection(repo: Path) -> tuple[dict[str, str], list[str]]:
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=repo).decode(
        "utf-8"
    )
    tracked_code = {
        relative
        for relative in tracked.split("\0")
        if relative
        and classify_file(repo / relative) == FileType.CODE
        and _get_extractor(repo / relative) is not None
    }
    detection = detect(repo, follow_symlinks=False, google_workspace=False)
    detected_code = {
        Path(raw).resolve().relative_to(repo).as_posix()
        for raw in detection.get("files", {}).get("code", [])
    }
    unexpected = detected_code - tracked_code
    if unexpected:
        raise RuntimeError(f"real Graphify detector selected untracked code: {unexpected}")
    return (
        {relative: "code" for relative in sorted(tracked_code)},
        sorted(tracked_code - detected_code),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphify-bin", required=True)
    parser.add_argument("--graphify-python", required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()
    augmentation = Path(__file__).with_name("augment_graphify_tracked_code.py").resolve()

    with tempfile.TemporaryDirectory(prefix="neoth-graphify-contract-") as raw:
        repo = Path(raw).resolve()
        write(repo / "src" / "lib.rs", "mod credentials;\npub fn run() -> bool { true }\n")
        write(
            repo / "src" / "credentials.rs",
            "pub struct CredentialStore;\nimpl CredentialStore { pub fn load(&self) {} }\n",
        )
        write(repo / "src" / "data.json", "[1, 2, 3]\n")
        write(
            repo / "Cargo.toml",
            '[package]\nname = "graphify-contract"\nversion = "0.0.0"\n'
            'edition = "2021"\npublish = false\n',
        )
        run(["git", "init", "-q"], cwd=repo)
        run(["git", "config", "user.email", "graphify-contract@example.invalid"], cwd=repo)
        run(["git", "config", "user.name", "NEOTH Graphify Contract"], cwd=repo)
        run(
            [
                "git",
                "add",
                "Cargo.toml",
                "src/lib.rs",
                "src/credentials.rs",
                "src/data.json",
            ],
            cwd=repo,
        )
        run(["git", "commit", "-qm", "fixture"], cwd=repo)

        run(
            [
                args.graphify_bin,
                "extract",
                ".",
                "--mode",
                "deep",
                "--cargo",
                "--no-cluster",
                "--backend",
                args.backend,
                "--model",
                args.model,
            ],
            cwd=repo,
        )
        graph_path = repo / "graphify-out" / "graph.json"
        selected, missing = real_detector_selection(repo)
        if missing != ["src/credentials.rs"]:
            raise RuntimeError(
                "real Graphify detector did not reproduce the expected sensitive-file "
                f"omission: {missing!r}"
            )
        raw_manifest = json.loads(
            (repo / "graphify-out" / "manifest.json").read_text(encoding="utf-8")
        )
        if "src/credentials.rs" in raw_manifest:
            raise RuntimeError(
                "real Graphify unexpectedly included the sensitive-file fixture before "
                "the local AST recovery phase"
            )
        raw_graph_text = graph_path.read_text(encoding="utf-8")
        if "credentials.rs" in raw_graph_text:
            raise RuntimeError(
                "real Graphify unexpectedly graphed the sensitive-file fixture before "
                "the local AST recovery phase"
            )
        run(
            [
                args.graphify_python,
                str(augmentation),
                "--repo",
                ".",
                "--graph",
                "graphify-out/graph.json",
            ],
            cwd=repo,
        )
        mark_raw_extraction_directed(graph_path, repo, selected)

        graph_arg = "graphify-out/graph.json"
        run(
            [
                args.graphify_bin,
                "cluster-only",
                ".",
                "--graph",
                graph_arg,
                "--no-label",
            ],
            cwd=repo,
        )
        for export in ("html", "wiki", "svg", "graphml"):
            run(
                [args.graphify_bin, "export", export, "--graph", graph_arg],
                cwd=repo,
            )
        run(
            [
                args.graphify_bin,
                "export",
                "obsidian",
                "--graph",
                graph_arg,
                "--dir",
                "graphify-out/obsidian",
            ],
            cwd=repo,
        )

        manifest = json.loads(
            (repo / "graphify-out" / "manifest.json").read_text(encoding="utf-8")
        )
        for path in ("src/lib.rs", "src/credentials.rs", "src/data.json"):
            ast_hash = manifest.get(path, {}).get("ast_hash", "")
            if not isinstance(ast_hash, str) or len(ast_hash) < 32:
                raise RuntimeError(f"real Graphify manifest lacks AST proof for {path}")
        graph_text = graph_path.read_text(encoding="utf-8")
        graph = json.loads(graph_text)
        if str(repo).casefold() in graph_text.casefold():
            raise RuntimeError("canonical graph leaked its temporary checkout path")
        source_files = {
            item.get("source_file")
            for item in [*graph.get("nodes", []), *graph.get("links", [])]
            if isinstance(item, dict) and item.get("source_file")
        }
        if "src/credentials.rs" not in source_files:
            raise RuntimeError("sensitive-looking tracked code is absent from the final graph")
        if "src/data.json" not in source_files:
            raise RuntimeError("entity-free tracked input lacks its final graph file anchor")
        for required in (
            "GRAPH_REPORT.md",
            "graph.html",
            "graph.svg",
            "graph.graphml",
            "wiki/index.md",
            "obsidian/graph.canvas",
        ):
            path = repo / "graphify-out" / required
            if not path.is_file() or path.stat().st_size == 0:
                raise RuntimeError(f"real Graphify CLI omitted {required}")

    print("real Graphify CLI contract: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
