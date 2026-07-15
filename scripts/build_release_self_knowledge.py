#!/usr/bin/env python3
"""Build and verify NEOTH's release-bound Graphify self-knowledge snapshot.

The release pipeline must call ``build`` from a clean, tagged checkout.  The
command removes any prior graphify output, runs a fresh deep Graphify pass, and
packages the result with two independent integrity views:

* ``SOURCE_MANIFEST.json`` binds every tracked source byte to the exact HEAD.
* ``manifest.json`` binds every shipped self-knowledge byte and its role.

``verify`` is intentionally dependency-free so release, package, and installer
jobs can fail closed without installing Graphify or Python packages.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable, Sequence
import unicodedata


SCHEMA_VERSION = 1
PRODUCT = "NEOTH"
REQUIRED_FILES = {
    "graph.json": "graph",
    "GRAPH_REPORT.md": "report",
    "graph.html": "html",
    "graph.svg": "visualization",
    "graph.graphml": "visualization",
    "graphify-manifest.json": "graphify_manifest",
    "SOURCE_MANIFEST.json": "source_manifest",
    "GENERATION_RECEIPT.json": "generation_receipt",
    "BASELINE_READ_ONLY.md": "operator_guide",
}
MAX_MANIFEST_FILES = 100_000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
# These limits are part of the native runtime contract, not merely build-time
# resource guards.  A release snapshot that verifies cryptographically but
# cannot be queried or ingested by the shipped binary is not a valid release.
MAX_NATIVE_GRAPH_BYTES = 256 * 1024 * 1024
MAX_NATIVE_GRAPH_NODES = 500_000
MAX_NATIVE_GRAPH_EDGES = 2_000_000
MAX_NATIVE_INGEST_MARKDOWN_BYTES = 64 * 1024 * 1024
HEAD_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTENT_HASH_RE = re.compile(r"^[0-9a-f]{32,128}$")
VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?"
    r"(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
RUSTC_VERSION_LINE_RE = re.compile(
    r"^rustc (?P<version>[^ ]+) \((?P<commit>[0-9a-f]{7,64}) "
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})\)$"
)
CARGO_VERSION_LINE_RE = re.compile(
    r"^cargo (?P<version>[^ ]+) \((?P<commit>[0-9a-f]{7,64}) "
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})\)$"
)
SEMANTIC_EXTENSIONS = {
    ".md",
    ".mdx",
    ".qmd",
    ".txt",
    ".rst",
    ".html",
    ".yaml",
    ".yml",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".docx",
    ".xlsx",
}
WINDOWS_RESERVED_STEMS = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


class ContractError(RuntimeError):
    """A release self-knowledge contract was not satisfied."""


def run(
    argv: Sequence[str],
    *,
    cwd: Path,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def git(repo: Path, *args: str) -> str:
    try:
        return run(("git", *args), cwd=repo).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise ContractError(f"git {' '.join(args)} failed: {detail.strip()}") from error


def git_head(repo: Path) -> str:
    head = git(repo, "rev-parse", "HEAD").lower()
    if not HEAD_RE.fullmatch(head):
        raise ContractError(f"git returned an invalid HEAD: {head!r}")
    return head


def require_clean_tracked_tree(repo: Path) -> None:
    dirty = git(repo, "status", "--porcelain=v1", "--untracked-files=no")
    if dirty:
        raise ContractError(
            "tracked worktree/index is dirty; refusing to bind a release graph "
            "to bytes that are not the exact HEAD"
        )


def require_pristine_generation_input(repo: Path) -> None:
    """Require Graphify to see only bytes bound to the release HEAD."""
    dirty = run(
        (
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        ),
        cwd=repo,
    ).stdout
    if dirty:
        raise ContractError(
            "worktree/index contains tracked, untracked, or ignored inputs; refusing "
            "to generate release self-knowledge from bytes outside the exact HEAD"
        )


def require_only_graphify_outputs(repo: Path) -> None:
    """After generation, only graphify-out may be untracked or changed."""
    raw = run(
        (
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        ),
        cwd=repo,
    ).stdout
    invalid: list[str] = []
    for record in (item for item in raw.split("\0") if item):
        if not (record.startswith("?? ") or record.startswith("!! ")):
            invalid.append(record[:2])
            continue
        relative = record[3:]
        if relative != "graphify-out" and not relative.startswith("graphify-out/"):
            invalid.append(relative)
    if invalid:
        raise ContractError(
            "Graphify changed or created source-tree bytes outside graphify-out: "
            + ", ".join(invalid[:8])
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_payload_hash(entries: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item["path"]):
        line = (
            f"{entry['path']}\0{entry['sha256']}\0"
            f"{entry['bytes']}\0{entry['role']}\n"
        )
        digest.update(line.encode("utf-8"))
    return digest.hexdigest()


def canonical_source_tree_hash(entries: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item["path"]):
        line = f"{entry['path']}\0{entry['sha256']}\0{entry['bytes']}\n"
        digest.update(line.encode("utf-8"))
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def load_json(path: Path, *, max_bytes: int = MAX_MANIFEST_BYTES) -> Any:
    if not path.is_file() or is_link_like(path):
        raise ContractError(f"required regular file is missing: {path}")
    if path.stat().st_size > max_bytes:
        raise ContractError(f"JSON file exceeds {max_bytes} bytes: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"invalid JSON in {path}: {error}") from error


def relative_posix(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError as error:
        raise ContractError(f"path escapes root {root}: {path}") from error
    validate_relative_path(rel)
    return rel


def validate_relative_path(raw: str) -> None:
    if not raw or "\\" in raw or "\0" in raw or unicodedata.normalize("NFC", raw) != raw:
        raise ContractError(f"invalid manifest path: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ContractError(f"unsafe manifest path: {raw!r}")
    if path.as_posix() != raw:
        raise ContractError(f"non-canonical manifest path: {raw!r}")
    for part in path.parts:
        if part.endswith((" ", ".")):
            raise ContractError(f"non-portable manifest path component: {raw!r}")
        if any(ord(character) < 32 or character in '<>:"|?*' for character in part):
            raise ContractError(f"Windows-unsafe manifest path component: {raw!r}")
        if part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_STEMS:
            raise ContractError(f"Windows-reserved manifest path component: {raw!r}")


def portable_path_key(raw: str) -> str:
    validate_relative_path(raw)
    return unicodedata.normalize("NFC", raw).casefold()


def is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def tracked_source_entries(repo: Path) -> list[dict[str, Any]]:
    raw = run(("git", "ls-files", "-z"), cwd=repo).stdout
    paths = [item for item in raw.split("\0") if item]
    if not paths:
        raise ContractError("git ls-files returned an empty source tree")
    entries: list[dict[str, Any]] = []
    for rel in sorted(paths):
        validate_relative_path(rel)
        path = repo.joinpath(*PurePosixPath(rel).parts)
        if not path.is_file() or is_link_like(path):
            raise ContractError(f"tracked source is not a regular non-symlink file: {rel}")
        entries.append(
            {"path": rel, "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        )
    return entries


def source_manifest(repo: Path, head: str) -> dict[str, Any]:
    entries = tracked_source_entries(repo)
    return {
        "schema_version": SCHEMA_VERSION,
        "source_head": head,
        "source_tree_sha256": canonical_source_tree_hash(entries),
        "files": entries,
    }


def ensure_output_is_safe(repo: Path, graphify_out: Path, output: Path) -> None:
    repo = repo.resolve()
    graphify_out = graphify_out.resolve()
    output = output.resolve()
    if graphify_out != repo / "graphify-out":
        raise ContractError(
            f"graphify output must be exactly {repo / 'graphify-out'}, got {graphify_out}"
        )
    if output == repo or output == graphify_out or graphify_out in output.parents:
        raise ContractError(f"unsafe snapshot output path: {output}")
    if repo == output or repo in output.parents:
        relative = output.relative_to(repo)
        if any(part.casefold() == ".git" for part in relative.parts):
            raise ContractError(f"snapshot output may not be placed below .git: {output}")
    git_dir_raw = git(repo, "rev-parse", "--git-dir")
    git_dir = Path(git_dir_raw)
    if not git_dir.is_absolute():
        git_dir = repo / git_dir
    git_dir = git_dir.resolve()
    if output == git_dir or git_dir in output.parents:
        raise ContractError(f"snapshot output may not be placed in Git metadata: {output}")


def graphify_id(raw: str) -> str:
    """Mirror Graphify 0.8.41's path-ID normalisation."""
    combined = unicodedata.normalize("NFKC", raw.strip("_."))
    cleaned = re.sub(r"[^\w]+", "_", combined, flags=re.UNICODE)
    return re.sub(r"_+", "_", cleaned).strip("_").casefold()


def canonical_source_file(raw: str, repo: Path) -> str:
    if not raw:
        raise ContractError("Graphify emitted an empty source_file")
    path = Path(raw)
    if path.is_absolute():
        try:
            relative = path.resolve().relative_to(repo.resolve()).as_posix()
        except ValueError as error:
            raise ContractError(
                f"Graphify source_file escapes the release checkout: {raw}"
            ) from error
    else:
        relative = PurePosixPath(raw.replace("\\", "/")).as_posix()
    validate_relative_path(relative)
    source = repo.joinpath(*PurePosixPath(relative).parts)
    if not source.is_file() or is_link_like(source):
        raise ContractError(
            f"Graphify source_file is not a tracked regular input: {relative}"
        )
    return relative


def mark_raw_extraction_directed(
    graph_path: Path,
    repo: Path,
    selected_inputs: dict[str, str],
) -> None:
    """Canonicalise the raw graph and preserve source->target direction.

    Graphify 0.8.41's headless extractor has no directed switch. Its
    ``--no-cluster`` output is still the lossless extraction shape, so adding
    this build-mode bit before cluster-only is the only public-CLI path that
    avoids collapsing reverse-direction relations. The headless CLI also emits
    absolute ``source_file`` values and derives file-anchor IDs from those
    machine-local paths. Rewrite both before clustering so release snapshots do
    not leak a runner path or change identity merely because the checkout moved.
    """
    raw = load_json(graph_path, max_bytes=1024 * 1024 * 1024)
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("nodes"), list)
        or not raw["nodes"]
        or not isinstance(raw.get("edges"), list)
        or not raw["edges"]
        or "links" in raw
    ):
        raise ContractError(
            "Graphify extract --no-cluster did not produce a non-empty raw extraction"
        )
    id_rewrites: dict[str, str] = {}
    for node in raw["nodes"]:
        if not isinstance(node, dict):
            raise ContractError("Graphify emitted a non-object node")
        source_file = node.get("source_file")
        if source_file is None:
            continue
        if not isinstance(source_file, str):
            raise ContractError("Graphify emitted a non-string source_file")
        relative = canonical_source_file(source_file, repo)
        node_id = node.get("id")
        if isinstance(node_id, str) and node_id == graphify_id(source_file):
            canonical_id = graphify_id(relative)
            if not canonical_id:
                raise ContractError(f"Graphify file anchor has no canonical ID: {relative}")
            id_rewrites[node_id] = canonical_id
        node["source_file"] = relative

    # Graphify legitimately returns no AST/semantic entities for some inputs
    # (for example data-shaped JSON or a prose file with no extractable
    # relation). Its manifest still proves that the exact bytes were processed,
    # but without a node the shipped graph cannot even tell the operator that
    # the file exists. Add a deterministic metadata-only anchor for every such
    # selected input before clustering. This never invents source contents or
    # relations; it makes extraction coverage explicit and queryable.
    node_sources = {
        node.get("source_file")
        for node in raw["nodes"]
        if isinstance(node.get("source_file"), str) and node.get("source_file")
    }
    for relative, kind in sorted(selected_inputs.items()):
        validate_relative_path(relative)
        if kind not in {"code", "document", "paper", "image"}:
            raise ContractError(f"unsupported Graphify input kind for {relative}: {kind}")
        if relative in node_sources:
            continue
        raw["nodes"].append(
            {
                "id": "neoth_release_input_"
                + hashlib.sha256(relative.encode("utf-8")).hexdigest(),
                "label": PurePosixPath(relative).name,
                "file_type": kind,
                "source_file": relative,
                "source_location": "",
                "_origin": "neoth-release-input-anchor",
            }
        )

    for collection in (raw.get("edges", []), raw.get("hyperedges", [])):
        if not isinstance(collection, list):
            raise ContractError("Graphify emitted an invalid edge collection")
        for item in collection:
            if not isinstance(item, dict):
                raise ContractError("Graphify emitted a non-object edge")
            source_file = item.get("source_file")
            if source_file is not None:
                if not isinstance(source_file, str):
                    raise ContractError("Graphify emitted a non-string edge source_file")
                item["source_file"] = canonical_source_file(source_file, repo)

    for node in raw["nodes"]:
        node_id = node.get("id")
        if isinstance(node_id, str) and node_id in id_rewrites:
            node["id"] = id_rewrites[node_id]
    for collection in (raw.get("edges", []), raw.get("hyperedges", [])):
        for item in collection:
            for field in ("source", "target"):
                value = item.get(field)
                if isinstance(value, str) and value in id_rewrites:
                    item[field] = id_rewrites[value]
            members = item.get("members")
            if isinstance(members, list):
                item["members"] = [id_rewrites.get(value, value) for value in members]

    node_ids = [node.get("id") for node in raw["nodes"]]
    if any(not isinstance(node_id, str) or not node_id for node_id in node_ids):
        raise ContractError("Graphify emitted a node without an ID")
    if len(node_ids) != len(set(node_ids)):
        raise ContractError("canonical Graphify file-anchor IDs collide")

    raw["directed"] = True
    encoded = json.dumps(raw, sort_keys=True, ensure_ascii=False)
    repo_text = str(repo.resolve())
    if repo_text.casefold() in encoded.casefold() or repo_text.replace("\\", "/").casefold() in encoded.casefold():
        raise ContractError("Graphify graph still contains the machine-local checkout path")
    temporary = graph_path.with_name(f".{graph_path.name}.directed.tmp")
    write_json(temporary, raw)
    temporary.replace(graph_path)


def probe_graphify_toolchain(
    python_bin: str,
    distribution_name: str,
    graphify_version_output: str,
    *,
    cwd: Path,
) -> dict[str, Any]:
    if not distribution_name.strip():
        raise ContractError("Graphify distribution name must be explicit")
    probe = r"""
import importlib.metadata as metadata
import json
import platform

packages = sorted(
    {
        (dist.metadata.get("Name", "").strip(), dist.version.strip())
        for dist in metadata.distributions()
        if dist.metadata.get("Name", "").strip() and dist.version.strip()
    },
    key=lambda item: (item[0].casefold(), item[1]),
)
print(json.dumps({
    "schema_version": 1,
    "python_implementation": platform.python_implementation(),
    "python_version": platform.python_version(),
    "packages": [{"name": name, "version": version} for name, version in packages],
}, sort_keys=True, separators=(",", ":")))
"""
    try:
        result = run((python_bin, "-c", probe), cwd=cwd)
        inventory = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise ContractError(f"Graphify Python toolchain probe failed: {error}") from error
    if not isinstance(inventory, dict):
        raise ContractError("Graphify Python toolchain probe returned no object")
    require_exact_keys(
        inventory,
        {"schema_version", "python_implementation", "python_version", "packages"},
        "Graphify Python toolchain",
    )
    if inventory.get("schema_version") != SCHEMA_VERSION:
        raise ContractError("Graphify Python toolchain schema is unsupported")
    for field in ("python_implementation", "python_version"):
        value = inventory.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ContractError(f"Graphify Python toolchain {field} is empty")
    packages = inventory.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ContractError("Graphify Python toolchain package inventory is empty")
    previous: tuple[str, str] | None = None
    distribution_version = None
    for package in packages:
        if not isinstance(package, dict):
            raise ContractError("Graphify Python toolchain package is not an object")
        require_exact_keys(package, {"name", "version"}, "Graphify package inventory entry")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name.strip() or not isinstance(version, str) or not version.strip():
            raise ContractError("Graphify Python toolchain package identity is invalid")
        key = (name.casefold(), version)
        if previous is not None and key <= previous:
            raise ContractError("Graphify Python package inventory is not sorted and unique")
        previous = key
        if name.casefold().replace("_", "-") == distribution_name.casefold().replace("_", "-"):
            distribution_version = version
    if distribution_version is None:
        raise ContractError(
            f"Graphify distribution {distribution_name!r} is absent from its Python environment"
        )
    if graphify_version_output != f"graphify {distribution_version}":
        raise ContractError(
            "Graphify executable version does not match its installed distribution: "
            f"{graphify_version_output!r} != graphify {distribution_version}"
        )
    rustc_verbose_version = probe_tool_version(("rustc", "-Vv"), "rustc", cwd=cwd)
    cargo_version = probe_tool_version(("cargo", "-V"), "Cargo", cwd=cwd)
    validate_rust_toolchain_versions(rustc_verbose_version, cargo_version)
    inventory["rustc_verbose_version"] = rustc_verbose_version
    inventory["cargo_version"] = cargo_version
    canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    inventory["inventory_sha256"] = hashlib.sha256(canonical).hexdigest()
    inventory["graphify_distribution"] = distribution_name
    inventory["graphify_distribution_version"] = distribution_version
    return inventory


def probe_tool_version(argv: Sequence[str], label: str, *, cwd: Path) -> str:
    try:
        output = run(argv, cwd=cwd).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError(f"{label} toolchain probe failed: {error}") from error
    normalized = output.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    if (
        not normalized
        or "\0" in normalized
        or len(normalized.encode("utf-8")) > 16 * 1024
        or any(not line or line != line.strip() for line in normalized.split("\n"))
    ):
        raise ContractError(f"{label} toolchain probe returned malformed output")
    return normalized


def validate_rust_toolchain_versions(
    rustc_verbose_version: Any,
    cargo_version: Any,
) -> None:
    if not isinstance(rustc_verbose_version, str) or not isinstance(cargo_version, str):
        raise ContractError("Rust/Cargo toolchain receipt is not textual")
    rustc_lines = rustc_verbose_version.split("\n")
    if len(rustc_lines) != 7:
        raise ContractError("rustc -Vv receipt does not contain the closed stable schema")
    first = RUSTC_VERSION_LINE_RE.fullmatch(rustc_lines[0])
    if first is None or VERSION_RE.fullmatch(first.group("version")) is None:
        raise ContractError("rustc -Vv receipt has an invalid release identity")
    fields: dict[str, str] = {}
    for line in rustc_lines[1:]:
        key, separator, value = line.partition(": ")
        if not separator or not key or not value or key in fields:
            raise ContractError("rustc -Vv receipt contains an invalid identity field")
        fields[key] = value
    if set(fields) != {
        "binary",
        "commit-hash",
        "commit-date",
        "host",
        "release",
        "LLVM version",
    }:
        raise ContractError("rustc -Vv receipt does not contain the closed stable schema")
    try:
        dt.date.fromisoformat(first.group("date"))
        dt.date.fromisoformat(fields["commit-date"])
    except ValueError as error:
        raise ContractError("rustc -Vv receipt contains an invalid commit date") from error
    if (
        fields["binary"] != "rustc"
        or re.fullmatch(r"[0-9a-f]{40,64}", fields["commit-hash"]) is None
        or not fields["commit-hash"].startswith(first.group("commit"))
        or fields["commit-date"] != first.group("date")
        or fields["release"] != first.group("version")
        or re.fullmatch(r"[^\s]+", fields["host"]) is None
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", fields["LLVM version"]) is None
    ):
        raise ContractError("rustc -Vv receipt is internally inconsistent")

    cargo = CARGO_VERSION_LINE_RE.fullmatch(cargo_version)
    if cargo is None or VERSION_RE.fullmatch(cargo.group("version")) is None:
        raise ContractError("cargo -V receipt has an invalid release identity")
    try:
        dt.date.fromisoformat(cargo.group("date"))
    except ValueError as error:
        raise ContractError("cargo -V receipt contains an invalid commit date") from error
    if cargo.group("version") != fields["release"]:
        raise ContractError("Cargo and rustc release versions disagree")


def probe_graphify_selection(
    python_bin: str,
    repo: Path,
) -> tuple[dict[str, str], list[str]]:
    """Return the exact pinned-Graphify input set plus locally recoverable code."""
    probe = r"""
import json
from pathlib import Path
import subprocess
import sys

from graphify.detect import FileType, classify_file, detect
from graphify.extract import _get_extractor

root = Path(sys.argv[1]).resolve()
detection = detect(root, follow_symlinks=False, google_workspace=False)
tracked = subprocess.check_output(
    ["git", "ls-files", "-z"], cwd=root
).decode("utf-8").split("\0")
tracked_code = []
unsupported_code = []
for rel in tracked:
    if not rel:
        continue
    path = root / rel
    if classify_file(path) != FileType.CODE:
        continue
    tracked_code.append(str(path.resolve()))
    if _get_extractor(path) is None:
        unsupported_code.append(str(path.resolve()))
payload = {
    "schema_version": 1,
    "scan_root": str(root),
    "files": detection["files"],
    "tracked_code": tracked_code,
    "unsupported_code": unsupported_code,
    "skipped_sensitive": detection.get("skipped_sensitive", []),
}
print("NEOTH_GRAPHIFY_SELECTION=" + json.dumps(payload, sort_keys=True))
"""
    try:
        result = run((python_bin, "-c", probe, str(repo)), cwd=repo)
        marker = next(
            line.removeprefix("NEOTH_GRAPHIFY_SELECTION=")
            for line in reversed(result.stdout.splitlines())
            if line.startswith("NEOTH_GRAPHIFY_SELECTION=")
        )
        selection = json.loads(marker)
    except (OSError, subprocess.CalledProcessError, StopIteration, json.JSONDecodeError) as error:
        raise ContractError(f"Graphify input-selection probe failed: {error}") from error
    if not isinstance(selection, dict):
        raise ContractError("Graphify input-selection probe returned no object")
    require_exact_keys(
        selection,
        {
            "schema_version",
            "scan_root",
            "files",
            "tracked_code",
            "unsupported_code",
            "skipped_sensitive",
        },
        "Graphify input selection",
    )
    if selection.get("schema_version") != SCHEMA_VERSION:
        raise ContractError("Graphify input-selection schema is unsupported")
    try:
        scan_root = Path(selection["scan_root"]).resolve()
    except TypeError as error:
        raise ContractError("Graphify input-selection root is invalid") from error
    if scan_root != repo.resolve():
        raise ContractError("Graphify input-selection root changed")
    files = selection.get("files")
    if not isinstance(files, dict) or set(files) != {
        "code",
        "document",
        "paper",
        "image",
        "video",
    }:
        raise ContractError("Graphify detector returned an unknown input-kind schema")

    selected: dict[str, str] = {}

    def add_paths(kind: str, values: Any) -> None:
        if not isinstance(values, list):
            raise ContractError(f"Graphify detector {kind} inputs are not a list")
        for raw in values:
            if not isinstance(raw, str):
                raise ContractError(f"Graphify detector emitted a non-string {kind} path")
            relative = canonical_source_file(raw, repo)
            previous = selected.setdefault(relative, kind)
            if previous != kind:
                raise ContractError(
                    f"Graphify classified one input as both {previous} and {kind}: {relative}"
                )

    for kind in ("document", "paper", "image"):
        add_paths(kind, files[kind])

    video_values = files["video"]
    if not isinstance(video_values, list):
        raise ContractError("Graphify detector video inputs are not a list")
    videos = []
    for raw in video_values:
        if not isinstance(raw, str):
            raise ContractError("Graphify detector emitted a non-string video path")
        videos.append(canonical_source_file(raw, repo))
    if videos:
        raise ContractError(
            "Graphify detected audio/video inputs but the pinned release pipeline "
            "has no transcript phase: " + ", ".join(sorted(videos)[:8])
        )

    detected_code: set[str] = set()
    code_values = files["code"]
    if not isinstance(code_values, list):
        raise ContractError("Graphify detector code inputs are not a list")
    for raw in code_values:
        if not isinstance(raw, str):
            raise ContractError("Graphify detector emitted a non-string code path")
        detected_code.add(canonical_source_file(raw, repo))

    tracked_code = selection.get("tracked_code")
    if not isinstance(tracked_code, list) or not tracked_code:
        raise ContractError("Graphify found no tracked code inputs")
    canonical_tracked_code: set[str] = set()
    for raw in tracked_code:
        if not isinstance(raw, str):
            raise ContractError("Graphify tracked-code selection contains a non-string path")
        canonical_tracked_code.add(canonical_source_file(raw, repo))
    unsupported_code = selection.get("unsupported_code")
    if not isinstance(unsupported_code, list):
        raise ContractError("Graphify unsupported-code selection is not a list")
    canonical_unsupported = []
    for raw in unsupported_code:
        if not isinstance(raw, str):
            raise ContractError("Graphify unsupported-code selection contains a non-string path")
        canonical_unsupported.append(canonical_source_file(raw, repo))
    if canonical_unsupported:
        raise ContractError(
            "Graphify classified tracked code for which 0.8.41 has no pinned AST extractor: "
            + ", ".join(sorted(canonical_unsupported)[:8])
        )

    skipped_sensitive = selection.get("skipped_sensitive")
    if not isinstance(skipped_sensitive, list):
        raise ContractError("Graphify skipped-sensitive selection is not a list")
    canonical_skipped_sensitive: set[str] = set()
    for raw in skipped_sensitive:
        if not isinstance(raw, str):
            raise ContractError(
                "Graphify skipped-sensitive selection contains a non-string path"
            )
        try:
            canonical_skipped_sensitive.add(canonical_source_file(raw, repo))
        except ContractError as error:
            raise ContractError(
                "Graphify skipped an input that cannot be bound to an exact tracked path"
            ) from error
    unrecoverable_sensitive = canonical_skipped_sensitive - canonical_tracked_code
    if unrecoverable_sensitive:
        raise ContractError(
            "Graphify skipped sensitive-looking tracked inputs that the local AST "
            "recovery cannot represent: "
            + ", ".join(sorted(unrecoverable_sensitive)[:8])
        )
    unexpected_code = detected_code - canonical_tracked_code
    if unexpected_code:
        raise ContractError(
            "Graphify selected code outside the tracked release source: "
            + ", ".join(sorted(unexpected_code)[:8])
        )
    for relative in sorted(canonical_tracked_code):
        selected[relative] = "code"

    if not any(kind != "code" for kind in selected.values()):
        raise ContractError("Graphify found no semantic release inputs")
    missing_code = sorted(canonical_tracked_code - detected_code)
    skipped_but_not_missing = canonical_skipped_sensitive - set(missing_code)
    if skipped_but_not_missing:
        raise ContractError(
            "Graphify reported sensitive omissions that were also selected for extraction: "
            + ", ".join(sorted(skipped_but_not_missing)[:8])
        )
    return selected, missing_code


def run_graphify(
    repo: Path,
    graphify_out: Path,
    executable: str,
    launcher_args: Sequence[str],
    backend: str,
    model: str,
    python_bin: str,
    distribution_name: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    ensure_output_is_safe(repo, graphify_out, repo / "dist-self-knowledge-safety-check")
    if graphify_out.exists():
        if is_link_like(graphify_out) or not graphify_out.is_dir():
            raise ContractError(f"refusing to replace unsafe graphify output: {graphify_out}")
        shutil.rmtree(graphify_out)

    if not backend.strip() or not model.strip():
        raise ContractError("Graphify backend and model must be explicit and non-empty")
    start_head = git_head(repo)
    require_pristine_generation_input(repo)
    version_command = [executable, *launcher_args, "--version"]
    try:
        version_before = run(version_command, cwd=repo).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError(f"Graphify version probe failed: {error}") from error
    if not version_before or len(version_before) > 256 or "unknown" in version_before.casefold():
        raise ContractError(f"Graphify returned an unusable version: {version_before!r}")
    toolchain = probe_graphify_toolchain(
        python_bin,
        distribution_name,
        version_before,
        cwd=repo,
    )

    started_ns = time.time_ns()
    graph_path = "graphify-out/graph.json"
    extract_command = [
        executable,
        *launcher_args,
        "extract",
        ".",
        "--mode",
        "deep",
        "--cargo",
        "--no-cluster",
        "--backend",
        backend,
        "--model",
        model,
    ]
    pipeline = [extract_command]
    try:
        run(extract_command, cwd=repo, capture=False)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError(f"Graphify phase 'extract .' failed: {error}") from error

    selected_inputs, missing_code = probe_graphify_selection(python_bin, repo)
    if missing_code:
        augmentation_command = [
            python_bin,
            "scripts/augment_graphify_tracked_code.py",
            "--repo",
            ".",
            "--graph",
            graph_path,
        ]
        try:
            run(augmentation_command, cwd=repo, capture=False)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ContractError(
                "Graphify tracked-code AST augmentation failed: "
                + ", ".join(missing_code[:8])
            ) from error
        pipeline.append(augmentation_command)

    mark_raw_extraction_directed(graphify_out / "graph.json", repo, selected_inputs)
    remaining_pipeline = [
        [
            executable,
            *launcher_args,
            "cluster-only",
            ".",
            "--graph",
            graph_path,
            "--backend",
            backend,
            "--model",
            model,
        ],
        [executable, *launcher_args, "export", "html", "--graph", graph_path],
        [executable, *launcher_args, "export", "wiki", "--graph", graph_path],
        [
            executable,
            *launcher_args,
            "export",
            "obsidian",
            "--graph",
            graph_path,
            "--dir",
            "graphify-out/obsidian",
        ],
        [executable, *launcher_args, "export", "svg", "--graph", graph_path],
        [executable, *launcher_args, "export", "graphml", "--graph", graph_path],
    ]
    for command in remaining_pipeline:
        try:
            run(command, cwd=repo, capture=False)
        except (OSError, subprocess.CalledProcessError) as error:
            phase = " ".join(command[len([executable, *launcher_args]) :][:2])
            raise ContractError(f"Graphify phase {phase!r} failed: {error}") from error
    pipeline.extend(remaining_pipeline)

    end_head = git_head(repo)
    require_only_graphify_outputs(repo)
    if end_head != start_head:
        raise ContractError(
            f"HEAD changed during Graphify generation: {start_head} -> {end_head}"
        )

    try:
        version_after = run(version_command, cwd=repo).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError(f"Graphify final version probe failed: {error}") from error
    if version_after != version_before:
        raise ContractError(
            f"Graphify version changed during generation: {version_before!r} -> {version_after!r}"
        )
    final_toolchain = probe_graphify_toolchain(
        python_bin,
        distribution_name,
        version_after,
        cwd=repo,
    )
    if final_toolchain != toolchain:
        raise ContractError("Graphify, Python, Rust, or Cargo toolchain changed during generation")

    return (
        {
            "schema_version": SCHEMA_VERSION,
            "source_head_before": start_head,
            "source_head_after": end_head,
            "started_unix_ns": started_ns,
            "finished_unix_ns": time.time_ns(),
            "graphify_version": version_after,
            "graphify_backend": backend,
            "graphify_model": model,
            "toolchain": toolchain,
            "pipeline": pipeline,
        },
        selected_inputs,
    )


def validate_graphify_manifest(
    value: Any,
    source_entries: Sequence[dict[str, Any]],
    selected_inputs: dict[str, str] | None = None,
) -> tuple[int, int]:
    if not isinstance(value, dict) or not value:
        raise ContractError("Graphify manifest is empty or not an object")
    manifest_paths: set[str] = set()
    portable_paths: set[str] = set()
    semantic_complete = 0
    for rel, entry in value.items():
        if not isinstance(rel, str) or not isinstance(entry, dict):
            raise ContractError("Graphify manifest contains an invalid file entry")
        validate_relative_path(rel)
        portable = portable_path_key(rel)
        if rel in manifest_paths or portable in portable_paths:
            raise ContractError(f"Graphify manifest contains a portable path collision: {rel}")
        manifest_paths.add(rel)
        portable_paths.add(portable)
        ast_hash = entry.get("ast_hash")
        semantic_hash = entry.get("semantic_hash")
        if not isinstance(ast_hash, str) or not isinstance(semantic_hash, str):
            raise ContractError(f"Graphify manifest hashes are invalid for {rel}")
        if ast_hash and not CONTENT_HASH_RE.fullmatch(ast_hash):
            raise ContractError(f"Graphify AST hash is invalid for {rel}")
        if semantic_hash and not CONTENT_HASH_RE.fullmatch(semantic_hash):
            raise ContractError(f"Graphify semantic hash is invalid for {rel}")
        if not ast_hash and not semantic_hash:
            if selected_inputs is not None and rel in selected_inputs:
                mode = "AST" if selected_inputs[rel] == "code" else "semantic"
                raise ContractError(
                    f"Graphify did not complete {mode} extraction for {rel}"
                )
            raise ContractError(f"Graphify recorded no extraction for {rel}")
        if semantic_hash:
            semantic_complete += 1

    tracked_inputs = {entry["path"] for entry in source_entries}
    extra = sorted(manifest_paths - tracked_inputs)
    if extra:
        raise ContractError(
            "Graphify consumed inputs outside the tracked release source tree: "
            + ", ".join(extra[:8])
        )

    if selected_inputs is not None:
        if not selected_inputs:
            raise ContractError("Graphify selected no release inputs")
        unknown_kinds = set(selected_inputs.values()) - {
            "code",
            "document",
            "paper",
            "image",
        }
        if unknown_kinds:
            raise ContractError(
                "Graphify selected unknown input kinds: " + ", ".join(sorted(unknown_kinds))
            )
        selected_paths = set(selected_inputs)
        untracked_selected = sorted(selected_paths - tracked_inputs)
        if untracked_selected:
            raise ContractError(
                "Graphify selected inputs outside the tracked release source tree: "
                + ", ".join(untracked_selected[:8])
            )
        missing = sorted(selected_paths - manifest_paths)
        unexpected = sorted(manifest_paths - selected_paths)
        if missing or unexpected:
            raise ContractError(
                "Graphify manifest differs from the pinned detector selection: "
                f"missing={missing[:8]}, unexpected={unexpected[:8]}"
            )
        code_complete = 0
        semantic_complete = 0
        for rel, kind in selected_inputs.items():
            field = "ast_hash" if kind == "code" else "semantic_hash"
            digest = value[rel].get(field)
            if not isinstance(digest, str) or not CONTENT_HASH_RE.fullmatch(digest):
                mode = "AST" if kind == "code" else "semantic"
                raise ContractError(f"Graphify did not complete {mode} extraction for {rel}")
            if kind == "code":
                code_complete += 1
            else:
                semantic_complete += 1
        if code_complete == 0 or semantic_complete == 0:
            raise ContractError("release graph requires both code and semantic Graphify inputs")
    elif semantic_complete == 0:
        raise ContractError("Graphify manifest proves no completed semantic extraction")
    return len(value), semantic_complete


def locate_graphify_outputs(
    graphify_out: Path,
    started_ns: int,
    source_entries: Sequence[dict[str, Any]],
    selected_inputs: dict[str, str],
) -> dict[str, Any]:
    required = {
        "graph": graphify_out / "graph.json",
        "report": graphify_out / "GRAPH_REPORT.md",
        "graphify_manifest": graphify_out / "manifest.json",
        "svg": graphify_out / "graph.svg",
        "graphml": graphify_out / "graph.graphml",
    }
    html_candidates = [graphify_out / "graph.html", graphify_out / "GRAPH_TREE.html"]
    html = next(
        (path for path in html_candidates if path.is_file() and not is_link_like(path)),
        None,
    )
    if html is None:
        raise ContractError("Graphify did not produce graph.html or GRAPH_TREE.html")
    required["html"] = html

    for role, path in required.items():
        if not path.is_file() or is_link_like(path) or path.stat().st_size == 0:
            raise ContractError(f"Graphify output {role} is missing/empty/unsafe: {path}")
        if path.stat().st_mtime_ns + 2_000_000_000 < started_ns:
            raise ContractError(f"Graphify output predates this generation run: {path}")

    wiki = graphify_out / "wiki"
    obsidian = graphify_out / "obsidian"
    for role, directory in (("wiki", wiki), ("obsidian", obsidian)):
        if not directory.is_dir() or is_link_like(directory):
            raise ContractError(f"Graphify {role} export is missing: {directory}")
        pages = [
            path
            for path in directory.rglob("*.md")
            if path.is_file() and not is_link_like(path) and path.stat().st_size > 0
        ]
        if not pages:
            raise ContractError(f"Graphify {role} export contains no Markdown pages")

    graph = load_json(required["graph"], max_bytes=MAX_NATIVE_GRAPH_BYTES)
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list):
        raise ContractError("graph.json has no nodes array")
    if not graph["nodes"]:
        raise ContractError("graph.json is empty")
    links = graph.get("links", graph.get("edges"))
    if not isinstance(links, list) or not links:
        raise ContractError("graph.json has no links/edges")
    if len(graph["nodes"]) > MAX_NATIVE_GRAPH_NODES:
        raise ContractError(
            "graph.json exceeds the native query node ceiling: "
            f"{len(graph['nodes'])} > {MAX_NATIVE_GRAPH_NODES}"
        )
    if len(links) > MAX_NATIVE_GRAPH_EDGES:
        raise ContractError(
            "graph.json exceeds the native query edge ceiling: "
            f"{len(links)} > {MAX_NATIVE_GRAPH_EDGES}"
        )
    if graph.get("directed") is not True:
        raise ContractError("release graph.json must preserve directed source-to-target edges")

    ingest_markdown = [required["report"]]
    for directory in (wiki, obsidian):
        ingest_markdown.extend(
            path
            for path in directory.rglob("*.md")
            if path.is_file() and not is_link_like(path)
        )
    ingest_markdown_bytes = sum(path.stat().st_size for path in ingest_markdown)
    if ingest_markdown_bytes > MAX_NATIVE_INGEST_MARKDOWN_BYTES:
        raise ContractError(
            "release report/wiki/Obsidian Markdown exceeds the native recall "
            f"ceiling: {ingest_markdown_bytes} > {MAX_NATIVE_INGEST_MARKDOWN_BYTES}"
        )

    graphify_manifest = load_json(required["graphify_manifest"], max_bytes=512 * 1024 * 1024)
    graphify_files, semantic_files = validate_graphify_manifest(
        graphify_manifest,
        source_entries,
        selected_inputs,
    )
    selected_paths = set(selected_inputs)
    node_sources: set[str] = set()
    for node in graph["nodes"]:
        if not isinstance(node, dict):
            raise ContractError("graph.json contains a non-object node")
        source_file = node.get("source_file")
        if source_file in (None, ""):
            continue
        if not isinstance(source_file, str):
            raise ContractError("graph.json contains a non-string node source_file")
        validate_relative_path(source_file)
        if source_file not in selected_paths:
            raise ContractError(
                f"graph.json references a source outside the Graphify manifest: {source_file}"
            )
        node_sources.add(source_file)
    for edge in links:
        if not isinstance(edge, dict):
            raise ContractError("graph.json contains a non-object edge")
        source_file = edge.get("source_file")
        if source_file in (None, ""):
            continue
        if not isinstance(source_file, str):
            raise ContractError("graph.json contains a non-string edge source_file")
        validate_relative_path(source_file)
        if source_file not in selected_paths:
            raise ContractError(
                f"graph.json edge references a source outside the Graphify manifest: {source_file}"
            )
    missing_graph_sources = sorted(selected_paths - node_sources)
    if missing_graph_sources:
        raise ContractError(
            "graph.json has no node/file anchor for Graphify inputs: "
            + ", ".join(missing_graph_sources[:8])
        )

    return {
        **required,
        "wiki": wiki,
        "obsidian": obsidian,
        "node_count": len(graph["nodes"]),
        "edge_count": len(links),
        "graphify_file_count": graphify_files,
        "semantic_file_count": semantic_files,
    }


def copy_regular_file(source: Path, destination: Path) -> None:
    if not source.is_file() or is_link_like(source):
        raise ContractError(f"source is not a regular non-symlink file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination, follow_symlinks=False)


def copy_tree(source: Path, destination: Path) -> None:
    if is_link_like(source) or not source.is_dir():
        raise ContractError(f"source tree is missing or unsafe: {source}")
    for path in sorted(source.rglob("*")):
        if is_link_like(path):
            raise ContractError(f"symlink is forbidden in release self-knowledge: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ContractError(f"non-regular entry in release self-knowledge: {path}")
        rel = path.relative_to(source)
        copy_regular_file(path, destination / rel)


def classify_role(rel: str) -> str:
    singleton = REQUIRED_FILES.get(rel)
    if singleton:
        return singleton
    if rel.startswith("wiki/"):
        return "wiki"
    if rel.startswith("obsidian/"):
        return "obsidian"
    if rel in ("graph.svg", "graph.graphml"):
        return "visualization"
    if rel == "BASELINE_READ_ONLY.md":
        return "operator_guide"
    raise ContractError(f"unclassified release self-knowledge file: {rel}")


def payload_entries(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    portable_paths: set[str] = set()
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if path.name == "manifest.json" and path.parent == root:
            continue
        if is_link_like(path):
            raise ContractError(f"symlink is forbidden in snapshot: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ContractError(f"non-regular snapshot entry: {path}")
        rel = relative_posix(path, root)
        portable = portable_path_key(rel)
        if portable in portable_paths:
            raise ContractError(f"portable snapshot path collision: {rel}")
        portable_paths.add(portable)
        size = path.stat().st_size
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise ContractError("snapshot exceeds the 2 GiB safety ceiling")
        entries.append(
            {
                "path": rel,
                "bytes": size,
                "sha256": sha256_file(path),
                "role": classify_role(rel),
            }
        )
    if not entries or len(entries) > MAX_MANIFEST_FILES:
        raise ContractError(f"invalid snapshot file count: {len(entries)}")
    entries.sort(key=lambda entry: entry["path"])
    return entries


def build_snapshot(args: argparse.Namespace) -> None:
    repo = Path(args.repo).resolve()
    graphify_out = (repo / "graphify-out").resolve()
    output = Path(args.output).resolve()
    ensure_output_is_safe(repo, graphify_out, output)
    if output.exists():
        raise ContractError(f"snapshot output already exists: {output}")

    if not VERSION_RE.fullmatch(args.version):
        raise ContractError(f"release version is not valid SemVer: {args.version!r}")
    receipt, selected_inputs = run_graphify(
        repo,
        graphify_out,
        args.graphify_bin,
        args.graphify_launcher_arg,
        args.graphify_backend,
        args.graphify_model,
        args.graphify_python_bin,
        args.graphify_distribution,
    )
    source = source_manifest(repo, receipt["source_head_after"])
    outputs = locate_graphify_outputs(
        graphify_out,
        receipt["started_unix_ns"],
        source["files"],
        selected_inputs,
    )
    receipt["node_count"] = outputs["node_count"]
    receipt["edge_count"] = outputs["edge_count"]
    receipt["graphify_file_count"] = outputs["graphify_file_count"]
    receipt["semantic_file_count"] = outputs["semantic_file_count"]
    receipt["graphify_distribution"] = receipt["toolchain"]["graphify_distribution"]
    receipt["graphify_toolchain_sha256"] = receipt["toolchain"]["inventory_sha256"]

    source_tree_sha256 = source["source_tree_sha256"]
    source_date_raw = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        source_date_epoch = (
            int(source_date_raw)
            if source_date_raw is not None
            else int(git(repo, "show", "-s", "--format=%ct", receipt["source_head_after"]))
        )
    except ValueError as error:
        raise ContractError("SOURCE_DATE_EPOCH/commit timestamp is invalid") from error
    if source_date_epoch < 0:
        raise ContractError("SOURCE_DATE_EPOCH/commit timestamp must not be negative")
    generated_at = dt.datetime.fromtimestamp(source_date_epoch, dt.timezone.utc).isoformat()

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        copy_regular_file(outputs["graph"], stage / "graph.json")
        copy_regular_file(outputs["report"], stage / "GRAPH_REPORT.md")
        copy_regular_file(outputs["html"], stage / "graph.html")
        copy_regular_file(outputs["graphify_manifest"], stage / "graphify-manifest.json")
        copy_regular_file(outputs["svg"], stage / "graph.svg")
        copy_regular_file(outputs["graphml"], stage / "graph.graphml")
        copy_tree(outputs["wiki"], stage / "wiki")
        copy_tree(outputs["obsidian"], stage / "obsidian")
        write_json(stage / "SOURCE_MANIFEST.json", source)
        write_json(stage / "GENERATION_RECEIPT.json", receipt)
        (stage / "BASELINE_READ_ONLY.md").write_text(
            "# NEOTH release self-knowledge baseline\n\n"
            "This directory is the immutable, release-signed description of the "
            "running NEOTH build. Do not edit it. Put operator or Self-Improve "
            "changes in the sibling `User Overlays` directory; upgrades create a "
            "new baseline and preserve those overlays.\n",
            encoding="utf-8",
            newline="\n",
        )
        entries = payload_entries(stage)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "product": PRODUCT,
            "release_version": args.version,
            "source_head": receipt["source_head_after"],
            "source_tree_sha256": source_tree_sha256,
            "generated_at": generated_at,
            "graphify_version": receipt["graphify_version"],
            "graphify_backend": receipt["graphify_backend"],
            "graphify_model": receipt["graphify_model"],
            "graphify_distribution": receipt["toolchain"]["graphify_distribution"],
            "graphify_toolchain_sha256": receipt["toolchain"]["inventory_sha256"],
            "node_count": outputs["node_count"],
            "edge_count": outputs["edge_count"],
            "payload_sha256": canonical_payload_hash(entries),
            "files": entries,
        }
        write_json(stage / "manifest.json", manifest)
        verify_snapshot(stage, expected_head=manifest["source_head"], expected_version=args.version)
        stage.replace(output)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise

    if args.verify_repo:
        verify_snapshot(output, repo=repo, expected_head=receipt["source_head_after"], expected_version=args.version)
    print(
        f"release self-knowledge ready: {output} "
        f"({outputs['node_count']} nodes, {outputs['edge_count']} edges, "
        f"HEAD {receipt['source_head_after']})"
    )


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ContractError(
            f"{label} fields differ from the closed schema: "
            f"extra={sorted(actual - expected)}, missing={sorted(expected - actual)}"
        )


def validate_source_manifest(
    snapshot: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    source = load_json(snapshot / "SOURCE_MANIFEST.json")
    if not isinstance(source, dict):
        raise ContractError("SOURCE_MANIFEST.json must contain an object")
    require_exact_keys(
        source,
        {"schema_version", "source_head", "source_tree_sha256", "files"},
        "SOURCE_MANIFEST.json",
    )
    if source.get("schema_version") != SCHEMA_VERSION:
        raise ContractError("SOURCE_MANIFEST.json has an unsupported schema")
    if source.get("source_head") != manifest["source_head"]:
        raise ContractError("SOURCE_MANIFEST.json source_head disagrees with manifest.json")
    entries = source.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_MANIFEST_FILES:
        raise ContractError("SOURCE_MANIFEST.json files must be a bounded non-empty array")
    previous = ""
    portable_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ContractError("SOURCE_MANIFEST.json contains a non-object file entry")
        require_exact_keys(entry, {"path", "bytes", "sha256"}, "source file entry")
        rel = entry.get("path")
        size = entry.get("bytes")
        digest = entry.get("sha256")
        if not isinstance(rel, str):
            raise ContractError("source manifest path is not a string")
        validate_relative_path(rel)
        portable = portable_path_key(rel)
        if rel <= previous or portable in portable_paths:
            raise ContractError("source manifest paths are not portable, sorted, and unique")
        previous = rel
        portable_paths.add(portable)
        if type(size) is not int or size < 0:
            raise ContractError(f"source manifest byte size is invalid for {rel}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ContractError(f"source manifest SHA-256 is invalid for {rel}")
    if canonical_source_tree_hash(entries) != source.get("source_tree_sha256"):
        raise ContractError("SOURCE_MANIFEST.json source_tree_sha256 is invalid")
    if source.get("source_tree_sha256") != manifest["source_tree_sha256"]:
        raise ContractError("source tree hash disagrees between manifests")
    return source


def verify_source_manifest(
    manifest: dict[str, Any],
    source: dict[str, Any],
    repo: Path,
) -> None:
    if git_head(repo) != manifest["source_head"]:
        raise ContractError("snapshot source_head does not equal the checkout HEAD")
    require_clean_tracked_tree(repo)
    current = source_manifest(repo, manifest["source_head"])
    if current != source:
        raise ContractError("tracked source bytes do not equal SOURCE_MANIFEST.json")


def validate_pipeline_receipt(snapshot: Path, manifest: dict[str, Any]) -> None:
    receipt = load_json(snapshot / "GENERATION_RECEIPT.json")
    if not isinstance(receipt, dict):
        raise ContractError("GENERATION_RECEIPT.json must contain an object")
    require_exact_keys(
        receipt,
        {
            "schema_version",
            "source_head_before",
            "source_head_after",
            "started_unix_ns",
            "finished_unix_ns",
            "graphify_version",
            "graphify_backend",
            "graphify_model",
            "graphify_distribution",
            "graphify_toolchain_sha256",
            "toolchain",
            "pipeline",
            "node_count",
            "edge_count",
            "graphify_file_count",
            "semantic_file_count",
        },
        "GENERATION_RECEIPT.json",
    )
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("source_head_before") != manifest["source_head"]
        or receipt.get("source_head_after") != manifest["source_head"]
        or receipt.get("graphify_version") != manifest["graphify_version"]
        or receipt.get("graphify_backend") != manifest["graphify_backend"]
        or receipt.get("graphify_model") != manifest["graphify_model"]
        or receipt.get("graphify_distribution") != manifest["graphify_distribution"]
        or receipt.get("graphify_toolchain_sha256")
        != manifest["graphify_toolchain_sha256"]
        or receipt.get("node_count") != manifest["node_count"]
        or receipt.get("edge_count") != manifest["edge_count"]
    ):
        raise ContractError("Graphify generation receipt identity disagrees with manifest.json")
    toolchain = receipt.get("toolchain")
    if not isinstance(toolchain, dict):
        raise ContractError("Graphify generation receipt has no toolchain inventory")
    require_exact_keys(
        toolchain,
        {
            "schema_version",
            "python_implementation",
            "python_version",
            "rustc_verbose_version",
            "cargo_version",
            "packages",
            "inventory_sha256",
            "graphify_distribution",
            "graphify_distribution_version",
        },
        "Graphify toolchain receipt",
    )
    if (
        toolchain.get("schema_version") != SCHEMA_VERSION
        or toolchain.get("graphify_distribution") != manifest["graphify_distribution"]
        or toolchain.get("inventory_sha256") != manifest["graphify_toolchain_sha256"]
    ):
        raise ContractError("Graphify toolchain identity disagrees with manifest.json")
    validate_rust_toolchain_versions(
        toolchain.get("rustc_verbose_version"),
        toolchain.get("cargo_version"),
    )
    packages = toolchain.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ContractError("Graphify toolchain package inventory is empty")
    canonical_packages: list[dict[str, str]] = []
    previous: tuple[str, str] | None = None
    distribution_version = None
    for package in packages:
        if not isinstance(package, dict):
            raise ContractError("Graphify toolchain package entry is invalid")
        require_exact_keys(package, {"name", "version"}, "Graphify package inventory entry")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name.strip() or not isinstance(version, str) or not version.strip():
            raise ContractError("Graphify toolchain package identity is invalid")
        key = (name.casefold(), version)
        if previous is not None and key <= previous:
            raise ContractError("Graphify toolchain package inventory is not sorted and unique")
        previous = key
        canonical_packages.append({"name": name, "version": version})
        if name.casefold().replace("_", "-") == manifest["graphify_distribution"].casefold().replace("_", "-"):
            distribution_version = version
    inventory_core = {
        "schema_version": toolchain["schema_version"],
        "python_implementation": toolchain["python_implementation"],
        "python_version": toolchain["python_version"],
        "rustc_verbose_version": toolchain["rustc_verbose_version"],
        "cargo_version": toolchain["cargo_version"],
        "packages": canonical_packages,
    }
    inventory_hash = hashlib.sha256(
        json.dumps(inventory_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if inventory_hash != toolchain["inventory_sha256"]:
        raise ContractError("Graphify toolchain package inventory hash is invalid")
    if (
        distribution_version != toolchain.get("graphify_distribution_version")
        or manifest["graphify_version"] != f"graphify {distribution_version}"
    ):
        raise ContractError("Graphify distribution/version provenance is inconsistent")
    started = receipt.get("started_unix_ns")
    finished = receipt.get("finished_unix_ns")
    if type(started) is not int or type(finished) is not int or started <= 0 or finished < started:
        raise ContractError("Graphify generation receipt timestamps are invalid")
    graphify_files = receipt.get("graphify_file_count")
    semantic_files = receipt.get("semantic_file_count")
    if (
        type(graphify_files) is not int
        or graphify_files <= 0
        or type(semantic_files) is not int
        or semantic_files <= 0
    ):
        raise ContractError("Graphify generation receipt extraction counts are invalid")

    pipeline = receipt.get("pipeline")
    if not isinstance(pipeline, list) or len(pipeline) not in (7, 8):
        raise ContractError(
            "Graphify generation receipt must contain the seven-phase pipeline "
            "and at most one tracked-code AST augmentation"
        )
    commands: list[list[str]] = []
    for command in pipeline:
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(part, str) or not part for part in command)
        ):
            raise ContractError("Graphify pipeline contains an invalid command")
        commands.append(command)

    extract_index = commands[0].index("extract") if "extract" in commands[0] else -1
    if extract_index <= 0:
        raise ContractError("Graphify pipeline does not begin with extract")
    launcher = commands[0][:extract_index]
    expected_graph = "graphify-out/graph.json"
    required_extract = {
        ("--mode", "deep"),
        ("--backend", manifest["graphify_backend"]),
        ("--model", manifest["graphify_model"]),
    }
    extract_tail = commands[0][extract_index + 1 :]
    if not extract_tail or extract_tail[0] != "." or "--cargo" not in extract_tail or "--no-cluster" not in extract_tail:
        raise ContractError("Graphify extract phase is not deep/Cargo/raw")
    for flag, value in required_extract:
        if not any(
            extract_tail[index : index + 2] == [flag, value]
            for index in range(len(extract_tail) - 1)
        ):
            raise ContractError(f"Graphify extract phase is missing {flag} {value}")

    command_index = 1
    if len(commands) == 8:
        augmentation = commands[1]
        script = PurePosixPath(augmentation[1].replace("\\", "/")).as_posix() if len(augmentation) > 1 else ""
        if (
            not script.endswith("scripts/augment_graphify_tracked_code.py")
            or augmentation[2:]
            != ["--repo", ".", "--graph", "graphify-out/graph.json"]
        ):
            raise ContractError("Graphify tracked-code AST augmentation phase is invalid")
        command_index += 1

    expected_exports = ["html", "wiki", "obsidian", "svg", "graphml"]
    cluster = commands[command_index]
    if cluster[: len(launcher)] != launcher or cluster[len(launcher) : len(launcher) + 2] != ["cluster-only", "."]:
        raise ContractError("Graphify cluster-only phase does not share the launcher/path")
    for required_pair in (
        ["--graph", expected_graph],
        ["--backend", manifest["graphify_backend"]],
        ["--model", manifest["graphify_model"]],
    ):
        if not any(
            cluster[index : index + 2] == required_pair
            for index in range(len(cluster) - 1)
        ):
            raise ContractError("Graphify cluster-only phase is not release-bound")
    export_commands = commands[command_index + 1 :]
    for command, export in zip(export_commands, expected_exports, strict=True):
        if command[: len(launcher)] != launcher or command[len(launcher) : len(launcher) + 2] != ["export", export]:
            raise ContractError(f"Graphify {export} export phase is missing")
        if not any(
            command[index : index + 2] == ["--graph", expected_graph]
            for index in range(len(command) - 1)
        ):
            raise ContractError(f"Graphify {export} export is not bound to graph.json")
    obsidian = export_commands[2]
    if not any(
        obsidian[index : index + 2] == ["--dir", "graphify-out/obsidian"]
        for index in range(len(obsidian) - 1)
    ):
        raise ContractError("Graphify Obsidian export has the wrong destination")


def verify_snapshot(
    snapshot: Path,
    *,
    repo: Path | None = None,
    expected_head: str | None = None,
    expected_version: str | None = None,
) -> dict[str, Any]:
    if is_link_like(snapshot):
        raise ContractError(f"snapshot root may not be a symlink/junction: {snapshot}")
    snapshot = snapshot.resolve()
    if not snapshot.is_dir() or is_link_like(snapshot):
        raise ContractError(f"snapshot is not a regular directory: {snapshot}")
    manifest = load_json(snapshot / "manifest.json")
    if not isinstance(manifest, dict):
        raise ContractError("manifest.json must contain an object")
    require_exact_keys(
        manifest,
        {
            "schema_version",
            "product",
            "release_version",
            "source_head",
            "source_tree_sha256",
            "generated_at",
            "graphify_version",
            "graphify_backend",
            "graphify_model",
            "graphify_distribution",
            "graphify_toolchain_sha256",
            "node_count",
            "edge_count",
            "payload_sha256",
            "files",
        },
        "manifest.json",
    )
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("product") != PRODUCT:
        raise ContractError("unsupported self-knowledge manifest schema/product")
    head = manifest.get("source_head")
    if not isinstance(head, str) or not HEAD_RE.fullmatch(head):
        raise ContractError(f"invalid manifest source_head: {head!r}")
    if expected_head and head != expected_head.lower():
        raise ContractError(f"snapshot HEAD {head} != expected {expected_head.lower()}")
    version = manifest.get("release_version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ContractError("manifest release_version is invalid")
    if expected_version and version != expected_version:
        raise ContractError(f"snapshot version {version} != expected {expected_version}")
    if not isinstance(manifest.get("source_tree_sha256"), str) or not SHA256_RE.fullmatch(
        manifest["source_tree_sha256"]
    ):
        raise ContractError("manifest source_tree_sha256 is invalid")
    generated_at = manifest.get("generated_at")
    try:
        parsed_generated_at = dt.datetime.fromisoformat(generated_at)
    except (TypeError, ValueError) as error:
        raise ContractError("manifest generated_at is not an ISO-8601 timestamp") from error
    if parsed_generated_at.tzinfo is None:
        raise ContractError("manifest generated_at must include a timezone")
    for field in (
        "graphify_version",
        "graphify_backend",
        "graphify_model",
        "graphify_distribution",
    ):
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip() or "unknown" in value.casefold():
            raise ContractError(f"manifest {field} is not explicit")
    toolchain_sha = manifest.get("graphify_toolchain_sha256")
    if not isinstance(toolchain_sha, str) or not SHA256_RE.fullmatch(toolchain_sha):
        raise ContractError("manifest graphify_toolchain_sha256 is invalid")
    for field in ("node_count", "edge_count"):
        value = manifest.get(field)
        if type(value) is not int or value <= 0:
            raise ContractError(f"manifest {field} must be a positive integer")
    payload_sha = manifest.get("payload_sha256")
    if not isinstance(payload_sha, str) or not SHA256_RE.fullmatch(payload_sha):
        raise ContractError("manifest payload_sha256 is invalid")

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_MANIFEST_FILES:
        raise ContractError("manifest files must be a bounded non-empty array")
    seen: set[str] = set()
    roles: dict[str, int] = {}
    prior = ""
    listed: set[str] = set()
    portable_paths: set[str] = set()
    total_bytes = 0
    wiki_markdown = 0
    obsidian_markdown = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ContractError("manifest file entry is not an object")
        require_exact_keys(entry, {"path", "bytes", "sha256", "role"}, "manifest file entry")
        rel = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("bytes")
        role = entry.get("role")
        if not isinstance(rel, str):
            raise ContractError("manifest path is not a string")
        validate_relative_path(rel)
        portable = portable_path_key(rel)
        if rel <= prior or rel in seen or portable in portable_paths:
            raise ContractError("manifest files are not portable, strictly sorted, and unique")
        prior = rel
        seen.add(rel)
        listed.add(rel)
        portable_paths.add(portable)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ContractError(f"invalid SHA-256 for {rel}")
        if type(size) is not int or size < 0:
            raise ContractError(f"invalid byte size for {rel}")
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise ContractError("snapshot exceeds the 2 GiB safety ceiling")
        if not isinstance(role, str) or classify_role(rel) != role:
            raise ContractError(f"invalid role for {rel}: {role!r}")
        path = snapshot.joinpath(*PurePosixPath(rel).parts)
        if not path.is_file() or is_link_like(path):
            raise ContractError(f"listed snapshot file is missing/unsafe: {rel}")
        if path.stat().st_size != size or sha256_file(path) != digest:
            raise ContractError(f"listed snapshot file failed integrity: {rel}")
        roles[role] = roles.get(role, 0) + 1
        if role == "wiki" and rel.casefold().endswith(".md") and size > 0:
            wiki_markdown += 1
        if role == "obsidian" and rel.casefold().endswith(".md") and size > 0:
            obsidian_markdown += 1

    actual: set[str] = set()
    for path in snapshot.rglob("*"):
        if is_link_like(path):
            raise ContractError(f"symlink is forbidden in snapshot: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ContractError(f"non-regular entry is forbidden in snapshot: {path}")
        if path.name != "manifest.json" or path.parent != snapshot:
            actual.add(relative_posix(path, snapshot))
    if actual != listed:
        raise ContractError(
            f"snapshot has unlisted/missing payload files: "
            f"extra={sorted(actual - listed)}, missing={sorted(listed - actual)}"
        )
    for rel, role in REQUIRED_FILES.items():
        if rel not in listed:
            raise ContractError(f"required release self-knowledge file is missing: {rel}/{role}")
        entry = next(item for item in entries if item["path"] == rel)
        if entry["role"] != role or entry["bytes"] == 0:
            raise ContractError(f"required release self-knowledge file is empty/misclassified: {rel}")
    if wiki_markdown == 0 or obsidian_markdown == 0:
        raise ContractError("snapshot must contain non-empty Wiki and Obsidian Markdown")
    if canonical_payload_hash(entries) != payload_sha:
        raise ContractError("manifest payload_sha256 is invalid")

    graph = load_json(snapshot / "graph.json", max_bytes=1024 * 1024 * 1024)
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    links = graph.get("links", graph.get("edges")) if isinstance(graph, dict) else None
    if not isinstance(nodes, list) or not nodes or not isinstance(links, list) or not links:
        raise ContractError("graph.json is empty or malformed")
    if graph.get("directed") is not True:
        raise ContractError("graph.json does not preserve directed edges")
    if manifest.get("node_count") != len(nodes) or manifest.get("edge_count") != len(links):
        raise ContractError("manifest graph counters disagree with graph.json")

    source = validate_source_manifest(snapshot, manifest)
    graphify_manifest = load_json(
        snapshot / "graphify-manifest.json", max_bytes=512 * 1024 * 1024
    )
    graphify_files, semantic_files = validate_graphify_manifest(
        graphify_manifest, source["files"]
    )
    validate_pipeline_receipt(snapshot, manifest)
    receipt = load_json(snapshot / "GENERATION_RECEIPT.json")
    if (
        receipt.get("graphify_file_count") != graphify_files
        or receipt.get("semantic_file_count") != semantic_files
    ):
        raise ContractError("Graphify receipt extraction counts disagree with its manifest")
    if repo is not None:
        verify_source_manifest(manifest, source, repo.resolve())
    return manifest


def verify_command(args: argparse.Namespace) -> None:
    manifest = verify_snapshot(
        Path(args.snapshot),
        repo=Path(args.repo) if args.repo else None,
        expected_head=args.expected_head,
        expected_version=args.expected_version,
    )
    print(
        f"release self-knowledge verified: version {manifest['release_version']}, "
        f"HEAD {manifest['source_head']}, payload {manifest['payload_sha256']}"
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="run Graphify and build a release snapshot")
    build.add_argument("--repo", default=".")
    build.add_argument("--output", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--graphify-bin", default="graphify")
    build.add_argument(
        "--graphify-launcher-arg",
        action="append",
        default=[],
        help="launcher argument before the Graphify subcommand (tests/wrappers only)",
    )
    build.add_argument(
        "--graphify-backend",
        required=True,
        help="explicit semantic backend; auto-detection is forbidden for releases",
    )
    build.add_argument(
        "--graphify-model",
        required=True,
        help="explicit semantic model recorded in the release receipt",
    )
    build.add_argument(
        "--graphify-python-bin",
        required=True,
        help="Python executable from the locked Graphify environment",
    )
    build.add_argument(
        "--graphify-distribution",
        default="graphifyy",
        help="installed distribution that owns the Graphify executable",
    )
    build.add_argument("--verify-repo", action=argparse.BooleanOptionalAction, default=True)
    build.set_defaults(handler=build_snapshot)

    verify = commands.add_parser("verify", help="verify a packaged release snapshot")
    verify.add_argument("--snapshot", required=True)
    verify.add_argument("--repo")
    verify.add_argument("--expected-head")
    verify.add_argument("--expected-version")
    verify.set_defaults(handler=verify_command)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        args.handler(args)
        return 0
    except ContractError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
