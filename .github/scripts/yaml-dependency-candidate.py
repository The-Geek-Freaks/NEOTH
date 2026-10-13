#!/usr/bin/env python3
"""Generate and retain a hosted YAML candidate. Never accept or commit it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path.cwd()
MANIFESTS = [
    "SRC/neothd/Cargo.toml",
    "SRC/neoth-migrate/Cargo.toml",
    "SRC/neoth-relay/Cargo.toml",
    "SRC/neothd-gui/Cargo.toml",
]
PRODUCT = [*MANIFESTS, "SRC/Cargo.lock"]
OWNERS = {"neoth", "neoth-migrate", "neoth-relay", "neothd-gui"}
BOUND = [
    ".github/workflows/yaml-dependency-candidate.yml",
    ".github/scripts/yaml-dependency-candidate.py",
    ".github/scripts/test_yaml_dependency_candidate.py",
    "packaging/fixtures/yaml-compatibility/Cargo.toml",
    "packaging/fixtures/yaml-compatibility/src/lib.rs",
    "SRC/Cargo.toml",
    "SRC/deny.toml",
    *PRODUCT,
]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = "33b729a08a9a6be689bbad3e2bf8015926db54b6622cc89c3a5f7dc174b9e918"
REQUEST = '{ package = "yaml_serde", version = "=0.10.7" }'
OLD_SERDE = ("serde_yaml", "0.9.34+deprecated", REGISTRY)
OLD_UNSAFE = ("unsafe-libyaml", "0.2.11", REGISTRY)
NEW_YAML = ("yaml_serde", "0.10.7", REGISTRY)
NEW_LIBYAML = ("libyaml-rs", "0.3.0", REGISTRY)
OLD_SERDE_CHECKSUM = "6a8b1a1a2ebf674015cc02edccce75287f1a0130d394307b36743c2f5d504b47"
OLD_UNSAFE_CHECKSUM = "673aac59facbab8a9007c7f6108d11f63b603f7cabff99fabf650fea5c32b861"
LIBYAML_CHECKSUM = "2e126dda6f34391ab7b444f9922055facc83c07a910da3eb16f1e4d9c45dc777"
OLD_SERDE_DEPS = ["indexmap 2.14.0", "itoa", "ryu", "serde", "unsafe-libyaml"]
NEW_YAML_DEPS = ["indexmap 2.14.0", "itoa", "libyaml-rs", "ryu", "serde"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def raw(path: str) -> bytes:
    file = ROOT / path
    require(not file.is_symlink() and file.is_file(), f"nonregular source: {path}")
    return file.read_bytes()


def save_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def copy_into(root: Path, path: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw(path))


def assert_changed(expected: set[str]) -> None:
    changed = set(filter(None, git("diff", "--name-only", "HEAD").splitlines()))
    require(changed == expected, f"changed paths {sorted(changed)} != {sorted(expected)}")
    require(not git("diff", "--cached", "--name-only"), "candidate must never stage files")


def candidate_manifest(data: bytes) -> bytes:
    # Preserve every byte except the single reviewed dependency request.
    text = data.decode("utf-8")
    changed, count = re.subn(
        r'(?m)^(serde_yaml\s*=\s*)"0\.9"([ \t]*)(\r?)$',
        lambda match: match[1] + REQUEST + match[2] + match[3], text,
    )
    require(count == 1, f"expected one serde_yaml=0.9 request; found {count}")
    return changed.encode("utf-8")


def package_index(path: Path) -> dict:
    return package_index_data(path.read_bytes())


def package_index_data(data: bytes) -> dict:
    result = {}
    for package in tomllib.loads(data.decode("utf-8"))["package"]:
        key = (package["name"], package["version"], package.get("source", ""))
        require(key not in result, f"duplicate package identity: {key}")
        result[key] = package
    return result


def candidate_lock(data: bytes) -> bytes:
    """Replace six reviewed blocks/edges; preserve every unrelated lock byte."""
    before = package_index_data(data)
    require(before.get(OLD_SERDE, {}).get("checksum") == OLD_SERDE_CHECKSUM,
            "unexpected base serde_yaml checksum")
    require(before[OLD_SERDE].get("dependencies") == OLD_SERDE_DEPS,
            "unexpected base serde_yaml dependencies")
    require(before.get(OLD_UNSAFE, {}).get("checksum") == OLD_UNSAFE_CHECKSUM
            and not before[OLD_UNSAFE].get("dependencies"),
            "unexpected base unsafe-libyaml package")
    require(not ({"yaml_serde", "libyaml-rs"} & {key[0] for key in before}),
            "candidate packages already present")
    nl = b"\r\n" if b"\r\n" in data else b"\n"
    parts = re.split(rb"(?m)(?=^\[\[package\]\]\r?$)", data)
    require(len(parts) > 1, "lock has no package blocks")
    edited = set()
    for index in range(1, len(parts)):
        block = parts[index]
        parsed = package_index_data(block)
        require(len(parsed) == 1, "ambiguous raw package block")
        key, package = next(iter(parsed.items()))
        if key in {OLD_SERDE, OLD_UNSAFE}:
            name, release, checksum, deps = (
                ("yaml_serde", "0.10.7", CHECKSUM, NEW_YAML_DEPS) if key == OLD_SERDE else
                ("libyaml-rs", "0.3.0", LIBYAML_CHECKSUM, [])
            )
            lines = ["[[package]]", f'name = "{name}"', f'version = "{release}"',
                     f'source = "{REGISTRY}"', f'checksum = "{checksum}"']
            if deps:
                lines += ["dependencies = [", *[f' "{edge}",' for edge in deps], "]"]
            parts[index] = nl.join(line.encode() for line in lines) + nl + nl
            edited.add(key)
        elif key[0] in OWNERS and key[2] == "":
            require(package.get("dependencies", []).count("serde_yaml") == 1,
                    f"unexpected base owner edge: {key}")
            changed, count = re.subn(
                rb'(?m)^([ \t]*)"serde_yaml",([ \t]*\r?)$',
                lambda match: match[1] + b'"yaml_serde",' + match[2], block,
            )
            require(count == 1, f"unexpected raw owner edge: {key}")
            parts[index] = changed
            edited.add(key)
    require(len(edited) == 6 and {OLD_SERDE, OLD_UNSAFE}.issubset(edited),
            "expected two package blocks and four owner edges")
    candidate = b"".join(parts)
    validate_packages(before, package_index_data(candidate))
    return candidate

def validate_packages(before: dict, after: dict) -> dict:
    added, removed = set(after) - set(before), set(before) - set(after)
    require(added == {NEW_YAML, NEW_LIBYAML},
            f"unexpected added identities: {sorted(added)}")
    require(removed == {OLD_SERDE, OLD_UNSAFE},
            f"unexpected removed identities: {sorted(removed)}")
    require(not ({"serde_yaml", "unsafe-libyaml"} & {k[0] for k in after}),
            "deprecated YAML packages remain")
    yaml_key = ("yaml_serde", "0.10.7", REGISTRY)
    require(yaml_key in after and after[yaml_key].get("checksum") == CHECKSUM,
            "yaml_serde registry pin or checksum differs")
    yaml = after[yaml_key]
    require(sum(k[0] == "yaml_serde" for k in after) == 1, "multiple YAML candidates")
    libyaml = [k for k in added if k[0] == "libyaml-rs"]
    require(len(libyaml) == 1 and libyaml[0][1].startswith("0.3.") and libyaml[0][2] == REGISTRY,
            "unexpected libyaml-rs identity")
    require(after[NEW_LIBYAML].get("checksum") == LIBYAML_CHECKSUM
            and not after[NEW_LIBYAML].get("dependencies"),
            "libyaml-rs checksum or dependencies differ")
    require(yaml.get("dependencies") == NEW_YAML_DEPS, "candidate YAML dependencies differ")
    changed_owners = set()
    for key in set(before) & set(after):
        old, new = before[key], after[key]
        require({k: v for k, v in old.items() if k != "dependencies"}
                == {k: v for k, v in new.items() if k != "dependencies"},
                f"retained package metadata/checksum changed: {key}")
        old_edges, new_edges = old.get("dependencies", []), new.get("dependencies", [])
        if old_edges == new_edges:
            continue
        require(key[0] in OWNERS and key[2] == "", f"unrelated dependency edges changed: {key}")
        require(old_edges.count("serde_yaml") == 1, f"unexpected old YAML edge: {key}")
        expected_edges = ["yaml_serde" if edge == "serde_yaml" else edge for edge in old_edges]
        require(sorted(new_edges) == sorted(expected_edges), f"non-YAML consumer edge changed: {key}")
        changed_owners.add(key[0])
    require(changed_owners == OWNERS, "not all four direct consumers changed only their YAML edge")
    require(any(edge.split()[0] == "libyaml-rs" for edge in yaml.get("dependencies", [])),
            "candidate YAML implementation dependency absent")
    return {"added": sorted(added), "removed": sorted(removed), "consumers": sorted(changed_owners)}


def custody(proof: Path) -> None:
    proof.mkdir(parents=True, exist_ok=True)
    entries = []
    for path in BOUND:
        data = raw(path)
        blob = git("rev-parse", "HEAD:" + path)
        require(git("hash-object", "--no-filters", "--", path) == blob,
                f"checkout differs from producer: {path}")
        entries.append({"path": path, "blob": blob, "sha256": sha(data)})
    save_json(proof / "source-custody.json", {
        "producer": git("rev-parse", "HEAD"), "run": os.environ["GITHUB_RUN_ID"],
        "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "sources": entries,
    })


def prepare(proof: Path) -> None:
    assert_changed(set())
    base = {path: raw(path) for path in PRODUCT}
    candidate = {path: candidate_manifest(base[path]) for path in MANIFESTS}
    candidate["SRC/Cargo.lock"] = candidate_lock(base["SRC/Cargo.lock"])
    # All transformations are validated before any product byte is changed.
    for path, data in base.items():
        target = proof / "base" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for path, data in candidate.items():
        (ROOT / path).write_bytes(data)
    assert_changed(set(PRODUCT))


def validate(proof: Path, metadata: Path) -> None:
    assert_changed(set(PRODUCT))
    for path in PRODUCT:
        copy_into(proof / "candidate", path)
    for path in MANIFESTS:
        require(raw(path) == candidate_manifest((proof / "base" / path).read_bytes()),
                f"manifest has unrelated changes: {path}")
    delta = validate_packages(package_index(proof / "base/SRC/Cargo.lock"),
                              package_index(ROOT / "SRC/Cargo.lock"))
    graph = json.loads(metadata.read_text(encoding="utf-8"))
    packages = graph.get("packages", [])
    require(packages and not ({"serde_yaml", "unsafe-libyaml"} & {p["name"] for p in packages}),
            "resolved product graph contains legacy YAML or is empty")
    selected = [p for p in packages if p["name"] == "yaml_serde"]
    require(len(selected) == 1 and selected[0]["version"] == "0.10.7"
            and selected[0]["source"] == REGISTRY, "resolved YAML candidate differs")
    save_json(proof / "lock-validation.json", {
        "producer": git("rev-parse", "HEAD"), **delta, "yamlSerdeChecksum": CHECKSUM,
        "changedFiles": PRODUCT, "candidateOnly": True, "requiresRootReview": True,
    })
    save_json(proof / "manifest-validation.json", {"directConsumers": MANIFESTS, "exactRequest": REQUEST})
    (proof / "candidate.patch").write_bytes(subprocess.check_output(
        ["git", "diff", "--binary", "--full-index", "--", *PRODUCT], cwd=ROOT,
    ))


def finalize(proof: Path) -> None:
    proof.mkdir(parents=True, exist_ok=True)
    scope_error = None
    try:
        assert_changed(set(PRODUCT))
        for path in PRODUCT:
            require(raw(path) == (proof / "candidate" / path).read_bytes(),
                    f"validated candidate changed during execution: {path}")
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        scope_error = str(exc)
    save_json(proof / "execution.json", {
        "producer": git("rev-parse", "HEAD"), "run": os.environ.get("GITHUB_RUN_ID"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "outcomes": {k: os.environ.get(k) for k in ("RESOLVE", "DIFFERENTIAL", "CONTRACTS", "CONSUMERS", "DENY")},
        "candidateOnly": True, "automaticProductAcceptance": False,
        "releaseGoldAccepted": False, "scopeValidationError": scope_error,
    })
    files = sorted(p for p in proof.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (proof / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(proof).as_posix()}\n" for p in files
    ), encoding="utf-8")
    require(scope_error is None, f"final candidate scope invalid: {scope_error}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("custody", "prepare", "validate", "finalize"))
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args()
    if args.command == "validate":
        require(args.metadata is not None, "validate needs metadata")
        validate(args.proof, args.metadata)
    else:
        {"custody": custody, "prepare": prepare, "finalize": finalize}[args.command](args.proof)


if __name__ == "__main__":
    main()
