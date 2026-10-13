#!/usr/bin/env python3
"""Produce a source-bound developer navigation map; never release acceptance."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from importlib.metadata import version
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys

SCOPES = ("SRC", "apps/neoth_companion", "bridges", "scripts", "packaging", ".github")
EXTENSIONS = {
    ".rs", ".dart", ".kt", ".kts", ".swift", ".slint", ".js", ".ts", ".tsx",
    ".jsx", ".h", ".hpp", ".c", ".cpp", ".toml", ".yaml", ".yml", ".py", ".sh", ".ps1",
}
EXCLUDED = {"target", "node_modules", "graphify-out", "vendor", "third_party", "build", ".dart_tool"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo)


def source_inputs(repo, producer):
    require(git(repo, "rev-parse", "HEAD").decode().strip() == producer, "producer differs")
    records = []
    for record in git(repo, "ls-tree", "-rz", "--full-tree", producer, "--", *SCOPES).split(b"\0"):
        if not record:
            continue
        meta, raw_path = record.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        relative = raw_path.decode("utf-8")
        path = Path(relative)
        if path.suffix not in EXTENSIONS or EXCLUDED.intersection(path.parts):
            continue
        require(mode in {"100644", "100755"} and kind == "blob", f"nonregular input: {relative}")
        full = repo / path
        require(full.is_file() and not full.is_symlink(), f"missing/symlink input: {relative}")
        require(full.resolve().is_relative_to(repo), f"input escapes checkout: {relative}")
        data = full.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(actual == blob, f"input differs from Git blob: {relative}")
        records.append({"path": relative, "blob": blob, "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()})
    require(records, "no tracked navigation inputs")
    return sorted(records, key=lambda item: item["path"])


class WarningCapture(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(self.format(record))


def build(repo, producer, output):
    require(version("graphifyy") == "0.8.41", "requires exact locked graphifyy 0.8.41")
    require(re.fullmatch(r"[0-9a-f]{40}", producer), "expected full source commit")
    require(not output.is_relative_to(repo), "output must be outside checkout")
    require(not output.exists(), "refusing to reuse navigation output or cached results")
    output.mkdir(parents=True)
    os.environ["GRAPHIFY_OUT"] = str(output / "cache")
    # Set before importing: Graphify captures this variable at module import.
    import graphify.extract as extractor

    records = source_inputs(repo, producer)
    save(output / "inputs.json", {"producer": producer, "files": records})
    supported, unsupported = [], []
    for record in records:
        selected = extractor._get_extractor(repo / record["path"])
        if selected is None:
            unsupported.append({**record, "reason": "unsupported_extension"})
        else:
            supported.append({**record, "extractor": selected.__name__,
                              "heuristic_dart": Path(record["path"]).suffix == ".dart"})
    save(output / "unsupported.json", unsupported)
    require(supported, "no supported structural inputs")
    outcomes = {}
    warnings = WarningCapture()
    logging.getLogger("graphify").addHandler(warnings)
    original = extractor._safe_extract
    failure = None
    graph = None

    def observed_extract(selected, path):
        relative = path.resolve().relative_to(repo).as_posix()
        require(relative not in outcomes, f"duplicate extraction: {relative}")
        result = original(selected, path)
        require(isinstance(result, dict), f"invalid extraction result: {relative}")
        error = result.get("error")
        outcomes[relative] = {
            "path": relative, "error": error,
            "nodes": len(result.get("nodes", [])), "edges": len(result.get("edges", [])),
        }
        require(not error, f"parser error in {relative}: {error}")
        return result

    # Pinned private API instrumentation exposes errors discarded by extract().
    # A fresh cache and parallel=False ensure every supported file is observed.
    extractor._safe_extract = observed_extract
    try:
        graph = extractor.extract([repo / item["path"] for item in supported],
                                  cache_root=repo, parallel=False)
        require(set(outcomes) == {item["path"] for item in supported},
                "not all supported files were observed; cache/dispatch mismatch")
        require(isinstance(graph.get("nodes"), list) and graph["nodes"], "empty/invalid graph")
        require(isinstance(graph.get("edges"), list), "invalid graph edges")
        require(source_inputs(repo, producer) == records, "source changed during extraction")
        graph.update({"directed": True, "source_head": producer, "purpose": "developer_navigation"})
        save(output / "graph.json", graph)
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        extractor._safe_extract = original
        logging.getLogger("graphify").removeHandler(warnings)

    save(output / "parser-outcomes.json", sorted(outcomes.values(), key=lambda item: item["path"]))
    save(output / "warnings.json", warnings.messages)
    save(output / "supported.json", supported)
    status = "failed" if failure else (
        "partial_unsupported_or_warnings" if unsupported or warnings.messages else "structural_only"
    )
    receipt = {
        "schema": "neoth.graphify.navigation.v1", "producer": producer,
        "run": os.environ.get("GITHUB_RUN_ID"), "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workflowCommit": os.environ.get("GITHUB_SHA"), "graphify": "0.8.41",
        "python": sys.version, "status": status, "failure": failure,
        "inputs": len(records), "supported": len(supported), "observed": len(outcomes),
        "unsupported": len(unsupported), "warnings": len(warnings.messages),
        "nodes": len(graph["nodes"]) if graph else 0, "edges": len(graph["edges"]) if graph else 0,
        "completeSemanticMap": False, "testOrGoldAcceptance": False,
        "parallel": False, "modelCalls": 0, "privateApiPinned": True,
    }
    save(output / "receipt.json", receipt)
    counts = Counter(Path(item["path"]).suffix for item in unsupported)
    (output / "GRAPH_REPORT.md").write_text(
        "# NEOTH structural navigation map\n\n"
        f"Producer: {producer}\n\nStatus: {status}\n\n"
        f"Inputs: {len(records)}; supported: {len(supported)}; observed: {len(outcomes)}; "
        f"unsupported: {len(unsupported)}.\n\n"
        f"Unsupported extensions: {dict(sorted(counts.items()))}.\n\n"
        "Dart extraction uses regex. Other structural links may also be inferred; retain "
        "Graphify evidence labels and verify important links in source. This is neither a "
        "compiler-complete call graph nor proof of working product flows or Gold completion. "
        "Consult inputs.json for exact scope, unsupported.json and warnings.json for omissions. "
        "A later producer requires a refreshed map or an explicit source-diff overlay.\n",
        encoding="utf-8",
    )
    members = sorted(path for path in output.iterdir() if path.is_file())
    (output / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in members
    ), encoding="utf-8")
    require(failure is None, failure)
    print(json.dumps(receipt, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(Path.cwd().resolve(), args.source_head, args.output.resolve())


if __name__ == "__main__":
    main()
