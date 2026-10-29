#!/usr/bin/env python3
"""Prepare/check the bounded Candle 0.8.4 + ZIP 9 candidate on hosted runners.

This does not publish or accept a candidate. Root reviews the original archive,
source delta, solver delta, audit, and behavior receipts before importing it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tomllib

from candle_pin_revision import revision_sources

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "packaging/vendor-provenance"
VENDOR = ROOT / "SRC/vendor/candle-core"
ARCHIVE = ASSETS / "candle-core-0.8.4.crate"
PATCH = ASSETS / "candle-core-0.8.4-zip9.patch"
TEST = "SRC/neothd/tests/candle_zip_compat.rs"
ZIP_CHECKSUM = "711e8c9646791c49b7eb799a19c4ae70a9b8372ddc6a1fa4778defd1e2aa5d5e"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(*args: str) -> bytes:
    return subprocess.check_output(args, cwd=ROOT)


def bindings() -> dict:
    spec = json.loads((ASSETS / "candle-core-0.8.4-zip9.json").read_text(encoding="utf-8-sig"))
    require(digest(ARCHIVE.read_bytes()) == spec["archiveSha256"], "official archive digest mismatch")
    require(digest(PATCH.read_bytes()) == spec["patchSha256"], "reviewed patch digest mismatch")
    require(len(spec["changes"]) == 7, "source delta must contain exactly seven paths")
    require(len({item["path"] for item in spec["changes"]}) == 7, "duplicate delta path")
    return spec


def upstream_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.isfile(), f"nonregular upstream member: {member.name}")
            require(path.parts[0] == "candle-core-0.8.4", "upstream prefix mismatch")
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            require(relative not in files and relative != ".", "duplicate/empty upstream member")
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in relative,
                    "unsafe upstream member")
            require(0 <= member.size <= 8 * 1024 * 1024, "oversized upstream member")
            handle = archive.extractfile(member)
            require(handle is not None, "missing upstream member body")
            files[relative] = handle.read()
            require(len(files[relative]) == member.size, "truncated upstream member")
    require(len(files) == 97 and sum(map(len, files.values())) < 16 * 1024 * 1024,
            "unexpected upstream inventory")
    return files


def prepare(spec: dict, files: dict[str, bytes]) -> None:
    require(not VENDOR.exists() and not (ROOT / TEST).exists(), "candidate paths already exist")
    for change in spec["changes"]:
        relative = change["path"]
        if relative.startswith("SRC/vendor/candle-core/"):
            body = files[relative.removeprefix("SRC/vendor/candle-core/")]
        else:
            body = (ROOT / relative).read_bytes()
        require(digest(body) == change["before"], f"preimage changed: {relative}")
    for relative, body in files.items():
        path = VENDOR / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    run("git", "apply", "--check", str(PATCH))
    run("git", "apply", str(PATCH))
    shutil.copyfile(ASSETS / "candle_zip_compat.rs", ROOT / TEST)


def verify_source(spec: dict, files: dict[str, bytes], *, require_revision: bool = False) -> None:
    require(VENDOR.is_dir() and not VENDOR.is_symlink(), "missing/linked vendor directory")
    revision = ASSETS / "candle-core-0.8.4-pin-revision.json"
    require(not require_revision or revision.is_file(), "required pin revision is missing")
    restored = revision_sources(ROOT, spec) if revision.exists() else {}

    def original_source(path: str) -> bytes:
        return restored[path] if path in restored else (ROOT / path).read_bytes()

    actual = set()
    for directory, directories, names in os.walk(VENDOR, followlinks=False):
        for name in directories + names:
            require(not (Path(directory) / name).is_symlink(), "vendor contains link")
        for name in names:
            path = Path(directory) / name
            require(path.is_file(), "nonregular vendor member")
            actual.add(path.relative_to(VENDOR).as_posix())
    require(actual == set(files), "vendor file inventory changed")
    changes = {item["path"]: item for item in spec["changes"]}
    for relative, body in files.items():
        path = "SRC/vendor/candle-core/" + relative
        expected = changes[path]["after"] if path in changes else digest(body)
        require(digest(original_source(path)) == expected, f"vendor delta changed: {path}")
    for path, change in changes.items():
        require(digest(original_source(path)) == change["after"], f"postimage mismatch: {path}")
    require((ROOT / TEST).read_bytes() == (ASSETS / "candle_zip_compat.rs").read_bytes(),
            "integration test differs from reviewed template")
    vcs = json.loads((VENDOR / ".cargo_vcs_info.json").read_bytes())
    require(vcs["git"]["sha1"] == spec["upstreamCommit"] and vcs["path_in_vcs"] == "candle-core",
            "upstream VCS identity changed")


def verify_resolution(proof: Path) -> None:
    baseline = tomllib.loads(run("git", "show", "HEAD:SRC/Cargo.lock").decode())["package"]
    current = tomllib.loads((ROOT / "SRC/Cargo.lock").read_text())["package"]
    revision_active = (ASSETS / "candle-core-0.8.4-pin-revision.json").exists()
    zip_version = "9.0.5" if revision_active else "9.0.0"
    zip_checksum = (
        "6e04976da629d3b04204ba8105b396a193af8ad2583b2c79bfb3ab8af580a11e"
        if revision_active else ZIP_CHECKSUM
    )
    if revision_active:
        russh = [p for p in current if p["name"] == "russh"]
        require(len(russh) == 1 and russh[0]["version"] == "0.64.1"
                and russh[0].get("source") == REGISTRY
                and russh[0].get("checksum")
                == "ba61e87b9ec9a39a59a6bbed4c0b8ff7fb07073405b24a767a1f2c8560ac8f58",
                "Russh revision resolution/checksum mismatch")
        require([p for p in baseline if p["name"] == "pageant"]
                == [p for p in current if p["name"] == "pageant"],
                "unreviewed Pageant change")
    zip_packages = [p for p in current if p["name"] == "zip"]
    require(len(zip_packages) == 1 and zip_packages[0]["version"] == zip_version
            and zip_packages[0].get("source") == REGISTRY
            and zip_packages[0].get("checksum") == zip_checksum, "ZIP resolution/checksum mismatch")
    core = [p for p in current if p["name"] == "candle-core"]
    require(len(core) == 1 and core[0]["version"] == "0.8.4"
            and "source" not in core[0] and "checksum" not in core[0], "Candle source not vendored")
    for name in {p["name"] for p in baseline if p["name"].startswith("candle-")} - {"candle-core"}:
        require([p for p in baseline if p["name"] == name] == [p for p in current if p["name"] == name],
                f"unreviewed Candle family change: {name}")
    first = json.loads((proof / "metadata-1.json").read_bytes())
    second = json.loads((proof / "metadata-2.json").read_bytes())
    require(first == second, "locked metadata is unstable")
    packages = first["packages"]
    selected = [p for p in packages if p["name"] == "candle-core"]
    require(len(selected) == 1 and selected[0]["source"] is None
            and Path(selected[0]["manifest_path"]).resolve() == (VENDOR / "Cargo.toml").resolve(),
            "metadata does not select exact vendor")
    zips = [p for p in packages if p["name"] == "zip"]
    require(len(zips) == 1 and zips[0]["version"] == zip_version, "metadata retains another ZIP")
    for name in ("neoth", "candle-core"):
        package = next(p for p in packages if p["name"] == name)
        node = next(n for n in first["resolve"]["nodes"] if n["id"] == package["id"])
        require(zips[0]["id"] in node["dependencies"], f"{name} does not consume reviewed ZIP")
    identity = lambda p: (p["name"], p["version"], p.get("source", ""))
    before = {identity(p): p for p in baseline}
    after = {identity(p): p for p in current}
    delta = {"added": [after[k] for k in sorted(after.keys() - before.keys())],
             "removed": [before[k] for k in sorted(before.keys() - after.keys())],
             "changed": [{"before": before[k], "after": after[k]}
                         for k in sorted(before.keys() & after.keys()) if before[k] != after[k]]}
    for package in delta["added"]:
        require(package["name"] == "candle-core" or
                (package.get("source") == REGISTRY and len(package.get("checksum", "")) == 64),
                "new dependency has unreviewed provenance")
    (proof / "solver-delta.json").write_text(json.dumps(delta, indent=2) + "\n")


def export(spec: dict, files: dict[str, bytes], proof: Path) -> None:
    verify_source(spec, files)
    # Upstream model fixtures may match repository ignore patterns. The complete
    # authenticated archive must appear in the patch, including those fixtures.
    run("git", "add", "-N", "--force", "--", "SRC/vendor/candle-core", TEST)
    paths = set(run("git", "diff", "HEAD", "--name-only").decode().splitlines())
    allowed = {item["path"] for item in spec["changes"]} | {"SRC/Cargo.lock", "THIRD_PARTY_LICENSES", TEST}
    allowed |= {"SRC/vendor/candle-core/" + relative for relative in files}
    required = allowed - {"THIRD_PARTY_LICENSES"}
    require(required <= paths <= allowed, "candidate path escape/incomplete")
    (proof / "candidate.patch").write_bytes(run("git", "diff", "HEAD", "--binary", "--full-index"))
    shutil.copyfile(ROOT / "SRC/Cargo.lock", proof / "Cargo.lock")
    receipt = {"producer": os.environ["GITHUB_SHA"], "run": os.environ["GITHUB_RUN_ID"],
               "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "status": "ROOT_REVIEW_REQUIRED",
               "paths": sorted(paths), "vendorFiles": len(files), "goldAccepted": False,
               "nativeAccepted": False, "fullSecurityAccepted": False}
    (proof / "candidate.json").write_text(json.dumps(receipt, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "source", "resolved", "export"))
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    spec = bindings()
    files = upstream_files()
    args.proof.mkdir(parents=True, exist_ok=True)
    if args.mode == "prepare":
        prepare(spec, files)
    verify_source(spec, files)
    if args.mode == "resolved":
        verify_resolution(args.proof)
    if args.mode == "export":
        export(spec, files, args.proof)
    (args.proof / (args.mode + "-verified.json")).write_text(json.dumps({
        "mode": args.mode, "vendorFiles": len(files), "patchSha256": spec["patchSha256"],
        "producer": os.environ["GITHUB_SHA"], "run": os.environ["GITHUB_RUN_ID"],
        "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "accepted": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
