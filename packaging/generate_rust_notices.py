#!/usr/bin/env python3
"""Generate deterministic notices for every Rust crate shipped by NEOTH.

The release workflow builds two exact feature profiles across seven targets.
This script resolves those profiles from Cargo.lock, walks every non-dev
dependency (including build dependencies conservatively), and records the
license/notice files that crates actually publish. It never guesses a missing
copyright holder or silently drops a package with metadata-only licensing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any
from urllib.parse import urlsplit, urlunsplit


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = REPOSITORY_ROOT / "SRC"
TARGET_FILE = REPOSITORY_ROOT / "THIRD_PARTY_LICENSES"
SNAPSHOT_FILE = REPOSITORY_ROOT / "packaging" / "rust-license-snapshots.json"
MARKER_START = "<!-- BEGIN GENERATED: RUST DISTRIBUTION LICENSES -->"
MARKER_END = "<!-- END GENERATED: RUST DISTRIBUTION LICENSES -->"

# Mirrors the exact release.yml build contract. The bool controls whether the
# separately shipped Slint GUI is a root of the resolved distribution graph.
RELEASE_PROFILES = (
    ("x86_64-unknown-linux-gnu", "release-desktop", True),
    ("aarch64-unknown-linux-gnu", "release-desktop", True),
    ("x86_64-apple-darwin", "release-desktop", True),
    ("aarch64-apple-darwin", "release-desktop", True),
    ("x86_64-pc-windows-msvc", "release-desktop", True),
    ("aarch64-pc-windows-msvc", "release-desktop", True),
    ("x86_64-unknown-linux-musl", "release-server", False),
)
ROOT_PACKAGES = {"neoth", "neoth-migrate", "neoth-relay"}
VENDOR_ROOT = WORKSPACE_ROOT / "vendor"
NOTICE_NAME = re.compile(
    r"^(?:licen[cs]e|copying|copyright|notice|unlicense|authors?)(?:[._-].*)?$",
    re.IGNORECASE,
)
NOTICE_DIRECTORIES = {"license", "licenses", "licence", "licences"}
MAX_NOTICE_BYTES = 2 * 1024 * 1024
PUBLIC_REPOSITORY_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
POSIX_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def cargo_metadata(target: str, feature: str) -> dict[str, Any]:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        target,
        "--features",
        f"neoth/{feature}",
    ]
    try:
        output = subprocess.run(
            command,
            cwd=WORKSPACE_ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except FileNotFoundError as error:
        raise SystemExit(
            "cargo is required to verify Rust distribution notices"
        ) from error
    except subprocess.CalledProcessError as error:
        sys.stderr.buffer.write(error.stderr)
        raise SystemExit(
            f"cargo metadata failed for {target} / {feature} with exit {error.returncode}"
        ) from error
    return json.loads(output.decode("utf-8"))


def distribution_packages(
    metadata: dict[str, Any], target: str, include_gui: bool
) -> dict[tuple[str, str, str], dict[str, Any]]:
    packages_by_id = {package["id"]: package for package in metadata["packages"]}
    nodes_by_id = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root_names = ROOT_PACKAGES | ({"neothd-gui"} if include_gui else set())
    roots = {
        package["id"]
        for package in metadata["packages"]
        if package["source"] is None and package["name"] in root_names
    }
    found_root_names = {packages_by_id[package_id]["name"] for package_id in roots}
    if found_root_names != root_names:
        missing = ", ".join(sorted(root_names - found_root_names))
        raise SystemExit(
            f"Cargo metadata is missing release root package(s): {missing}"
        )

    reachable = set(roots)
    queue = list(roots)
    while queue:
        package_id = queue.pop()
        node = nodes_by_id.get(package_id)
        if node is None:
            raise SystemExit(f"Cargo metadata has no resolve node for {package_id}")
        for dependency in node["deps"]:
            dependency_kinds = dependency.get("dep_kinds", [])
            if dependency_kinds and all(
                dependency_kind.get("kind") == "dev"
                for dependency_kind in dependency_kinds
            ):
                continue
            dependency_id = dependency["pkg"]
            if dependency_id not in reachable:
                reachable.add(dependency_id)
                queue.append(dependency_id)

    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for package_id in reachable:
        package = packages_by_id[package_id]
        source = package.get("source")
        package = dict(package)
        if source is None:
            # Cargo represents both workspace members and `[patch]` path
            # dependencies with `source = null`.  NEOTH's release roots are
            # first-party and intentionally excluded, but a dependency rooted
            # below `SRC/vendor` is a shipped third-party fork.  Its source
            # identity must not depend on this checkout's absolute path.
            provenance = local_vendor_provenance(package)
            if provenance is None:
                continue
            package["_local_vendor_provenance"] = provenance
        identity = (package["name"], package["version"], package_source(package))
        package["_targets"] = {target}
        result[identity] = package
    return result


def canonical_public_https_repository(repository: object) -> str | None:
    """Return a canonical public HTTPS owner/repository URL or reject it.

    This is intentionally narrower than `repository_key()`: local vendor
    provenance becomes part of a generated Markdown artifact and needs a
    single, public, checkout-independent representation.  Credentials,
    ports, query strings, fragments, and nested/non-repository paths are not
    provenance identities.
    """

    if (
        not isinstance(repository, str)
        or repository != repository.strip()
        or contains_ascii_control(repository)
    ):
        return None
    try:
        parsed = urlsplit(repository)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    path_parts = parsed.path.split("/")
    if len(path_parts) != 3 or path_parts[0] or not all(path_parts[1:]):
        return None
    owner, repository_name = path_parts[1:]
    if repository_name.endswith(".git"):
        repository_name = repository_name[:-4]
    if not all(
        PUBLIC_REPOSITORY_SEGMENT.fullmatch(segment)
        for segment in (owner, repository_name)
    ):
        return None
    return (
        f"https://{parsed.hostname.lower()}/{owner.lower()}/{repository_name.lower()}"
    )


def unchanged_posix_relative_path(value: object) -> str | None:
    """Accept only a safe, unmodified POSIX relative path for Markdown output."""

    if not isinstance(value, str) or not value or "\\" in value:
        return None
    if contains_ascii_control(value):
        return None
    parts = value.split("/")
    if not all(POSIX_PATH_SEGMENT.fullmatch(part) for part in parts):
        return None
    return value


def upstream_vcs_path(value: object) -> str | None:
    """Accept Cargo's repository-root marker or a strict POSIX crate path.

    Cargo writes ``path_in_vcs: ""`` for a crate published from its upstream
    repository root.  That exact empty marker is safe to retain as a stable
    identity component.  Every non-root path must still pass the ordinary
    Markdown-safe relative-path validation; in particular, no normalization is
    performed for traversal, platform, or presentation syntax.
    """

    if value == "":
        return ""
    return unchanged_posix_relative_path(value)


def contains_ascii_control(value: str) -> bool:
    """Return whether a value contains a C0 control or DEL character."""

    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def local_vendor_provenance(package: dict[str, Any]) -> dict[str, str] | None:
    """Return checked, stable provenance for a locally vended third-party crate.

    A local `path+file://...` Cargo identity is host-specific, so it cannot be
    used for a reproducible distribution notice.  The vendored crate instead
    carries the exact upstream revision and its path in the upstream VCS in
    `.cargo_vcs_info.json`.  Both values, plus the repository URL from the
    manifest, form the stable identity recorded in the generated notices.
    """

    manifest = Path(package["manifest_path"])
    package_root = manifest.parent.resolve()
    try:
        local_path = unchanged_posix_relative_path(
            package_root.relative_to(VENDOR_ROOT.resolve()).as_posix()
        )
    except ValueError:
        return None
    if local_path is None:
        raise SystemExit(
            f"locally vended {package_label(package)} has an unsafe local vendor path"
        )

    repository = package.get("repository")
    normalized_repository = canonical_public_https_repository(repository)
    if normalized_repository is None:
        raise SystemExit(
            f"locally vended {package_label(package)} has no canonical upstream repository"
        )

    provenance_path = package_root / ".cargo_vcs_info.json"
    if not provenance_path.is_file():
        raise SystemExit(
            f"locally vended {package_label(package)} has no .cargo_vcs_info.json"
        )
    try:
        data = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(
            f"cannot read local vendor provenance for {package_label(package)}: {error}"
        ) from error

    revision = data.get("git", {}).get("sha1")
    path_in_vcs = upstream_vcs_path(data.get("path_in_vcs"))
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SystemExit(
            f"locally vended {package_label(package)} has no exact upstream Git revision"
        )
    if path_in_vcs is None:
        raise SystemExit(
            f"locally vended {package_label(package)} has invalid upstream VCS path"
        )

    return {
        "identity": f"vendor+{normalized_repository}@{revision}#{path_in_vcs}",
        "local_path": f"SRC/vendor/{local_path}",
        "repository": normalized_repository,
        "revision": revision,
        "path_in_vcs": path_in_vcs,
    }


def package_source(package: dict[str, Any]) -> str:
    """Return a stable source identity for registry and local-vendor crates."""

    provenance = package.get("_local_vendor_provenance")
    if provenance is not None:
        return provenance["identity"]
    source = package.get("source")
    if not isinstance(source, str):
        raise SystemExit(f"{package_label(package)} has no stable package source")
    return source


def notice_paths(package: dict[str, Any]) -> list[Path]:
    manifest = Path(package["manifest_path"])
    package_root = manifest.parent
    candidates: set[Path] = set()

    declared_license_file = package.get("license_file")
    if declared_license_file:
        path = Path(declared_license_file)
        if not path.is_absolute():
            path = package_root / path
        candidates.add(path)

    try:
        children = list(package_root.iterdir())
    except OSError as error:
        raise SystemExit(
            f"cannot inspect crate directory {package_root}: {error}"
        ) from error

    for child in children:
        if child.is_file() and NOTICE_NAME.match(child.name):
            candidates.add(child)
        elif child.is_dir() and child.name.lower() in NOTICE_DIRECTORIES:
            candidates.update(path for path in child.rglob("*") if path.is_file())

    safe_paths: list[Path] = []
    package_root_resolved = package_root.resolve()
    for path in candidates:
        if not path.is_file():
            raise SystemExit(
                f"{package['name']} {package['version']} declares missing license file {path}"
            )
        resolved = path.resolve()
        try:
            resolved.relative_to(package_root_resolved)
        except ValueError as error:
            raise SystemExit(
                f"{package['name']} {package['version']} license file escapes its crate: {path}"
            ) from error
        if resolved.stat().st_size > MAX_NOTICE_BYTES:
            raise SystemExit(f"crate notice is unexpectedly large: {resolved}")
        safe_paths.append(resolved)
    return sorted(set(safe_paths), key=lambda path: str(path).lower())


def read_notice(path: Path) -> str:
    raw = path.read_bytes()
    if b"\0" in raw:
        raise SystemExit(f"crate notice is not text: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return normalize_notice_text(text)


def normalize_notice_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.splitlines()).strip() + "\n"


def package_label(package: dict[str, Any]) -> str:
    return f"{package['name']} {package['version']}"


def package_identity_key(package: dict[str, Any]) -> str:
    return "\0".join((package["name"], package["version"], package_source(package)))


def package_url(package: dict[str, Any]) -> str:
    provenance = package.get("_local_vendor_provenance")
    if provenance is not None:
        return provenance["identity"]
    repository = package.get("repository")
    if repository:
        return repository
    source = package_source(package)
    if source.startswith("registry+"):
        return f"https://crates.io/crates/{package['name']}/{package['version']}"
    return source


def repository_key(package: dict[str, Any]) -> str | None:
    repository = package.get("repository")
    if not repository:
        return None
    parsed = urlsplit(repository.strip())
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    lowered_path = path.lower()
    for marker in ("/tree/", "/blob/", "/src/branch/", "/src/tag/"):
        position = lowered_path.find(marker)
        if position != -1:
            path = path[:position]
            break
    return urlunsplit(("https", host, path, "", "")).lower()


def resolved_release_packages() -> list[dict[str, Any]]:
    packages: dict[tuple[str, str, str], dict[str, Any]] = {}
    for target, feature, include_gui in RELEASE_PROFILES:
        resolved = distribution_packages(
            cargo_metadata(target, feature), target, include_gui
        )
        for identity, package in resolved.items():
            existing = packages.get(identity)
            if existing is None:
                packages[identity] = package
            else:
                existing["_targets"].update(package["_targets"])
    return sorted(
        packages.values(),
        key=lambda package: (
            package["name"].lower(),
            package["version"],
            package_source(package),
        ),
    )


def load_license_snapshots() -> dict[str, Any]:
    if not SNAPSHOT_FILE.is_file():
        return {}
    data = json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("packages"), dict):
        raise SystemExit(f"unsupported Rust license snapshot schema in {SNAPSHOT_FILE}")
    return data["packages"]


def generate(ordered_packages: list[dict[str, Any]] | None = None) -> str:
    if ordered_packages is None:
        ordered_packages = resolved_release_packages()
    snapshots = load_license_snapshots()
    texts: dict[str, dict[str, Any]] = {}
    repository_texts: dict[str, set[str]] = {}
    pending_metadata_only: list[dict[str, Any]] = []
    vcs_snapshot_packages: list[dict[str, Any]] = []
    manifest_grant_packages: list[dict[str, Any]] = []
    for package in ordered_packages:
        license_expression = package.get("license")
        if not license_expression:
            raise SystemExit(
                f"{package_label(package)} has no SPDX license expression in Cargo metadata"
            )
        paths = notice_paths(package)
        if not paths:
            snapshot = snapshots.get(package_identity_key(package))
            if snapshot is None:
                pending_metadata_only.append(package)
                continue
            if snapshot.get("kind", "vcs") == "manifest-grant":
                manifest_grant_packages.append(package)
            else:
                vcs_snapshot_packages.append(package)
            notices = []
            for snapshot_notice in snapshot.get("files", []):
                notice = snapshot_notice["text"]
                digest = hashlib.sha256(notice.encode("utf-8")).hexdigest()
                if digest != snapshot_notice.get("sha256"):
                    raise SystemExit(
                        f"corrupt license snapshot for {package_label(package)}: "
                        f"{snapshot_notice.get('path', '<unknown>')}"
                    )
                notices.append((digest, notice))
            if not notices:
                raise SystemExit(f"empty license snapshot for {package_label(package)}")
        else:
            notices = []
            for path in paths:
                notice = read_notice(path)
                digest = hashlib.sha256(notice.encode("utf-8")).hexdigest()
                notices.append((digest, notice))
        for digest, notice in notices:
            entry = texts.setdefault(digest, {"text": notice, "packages": set()})
            entry["packages"].add(package_label(package))
            key = repository_key(package)
            if key:
                repository_texts.setdefault(key, set()).add(digest)

    inherited_repository_texts: list[dict[str, Any]] = []
    metadata_only: list[dict[str, Any]] = []
    for package in pending_metadata_only:
        key = repository_key(package)
        inherited = repository_texts.get(key or "", set())
        if not inherited:
            metadata_only.append(package)
            continue
        for digest in inherited:
            texts[digest]["packages"].add(package_label(package))
        inherited_repository_texts.append(package)

    lines = [
        MARKER_START,
        "",
        "## Rust distribution dependencies",
        "",
        (
            "Generated from `SRC/Cargo.lock` and the exact `release-desktop` / "
            "`release-server` target profiles used by the release workflow. "
            f"The inventory covers {len(ordered_packages)} external crates reachable "
            "through runtime or build dependencies; dev-only edges are excluded. "
            "Regenerate with `python packaging/generate_rust_notices.py --write`."
        ),
        "",
        "### Exact package inventory",
        "",
    ]
    for package in ordered_packages:
        targets = ", ".join(sorted(package["_targets"]))
        lines.append(
            f"- `{package_label(package)}` - `{package['license']}` - "
            f"{package_url(package)} - targets: {targets}"
        )

    local_vendor_packages = [
        package for package in ordered_packages if "_local_vendor_provenance" in package
    ]
    if local_vendor_packages:
        lines.extend(
            [
                "",
                "### Locally vended third-party forks",
                "",
                (
                    "Cargo marks both workspace members and local patches as `source = null`. "
                    "The packages below are deliberately included because their manifests live "
                    "under `SRC/vendor/`, not as NEOTH workspace crates. Their stable source "
                    "identities bind the local fork to the upstream repository, exact Git revision, "
                    "and upstream crate path recorded in `.cargo_vcs_info.json`. Their license texts "
                    "are read directly from the corresponding local vendor directories."
                ),
                "",
            ]
        )
        for package in local_vendor_packages:
            provenance = package["_local_vendor_provenance"]
            lines.append(
                f"- `{package_label(package)}` - local `{provenance['local_path']}` - "
                f"source `{provenance['identity']}` - upstream {provenance['repository']}"
            )

    if vcs_snapshot_packages:
        lines.extend(
            [
                "",
                "### Exact upstream VCS license snapshots",
                "",
                (
                    "These crate archives omit a standalone notice file. Their published "
                    "`.cargo_vcs_info.json` revision is bound to a committed repository-license "
                    "snapshot in `packaging/rust-license-snapshots.json`; every embedded text "
                    "is SHA-256 checked during regeneration."
                ),
                "",
            ]
        )
        for package in vcs_snapshot_packages:
            snapshot = snapshots[package_identity_key(package)]
            lines.append(
                f"- `{package_label(package)}` - `{package['license']}` - "
                f"revision `{snapshot['revision']}` - {snapshot['repository']}"
            )

    if manifest_grant_packages:
        lines.extend(
            [
                "",
                "### Published manifest grants with pinned SPDX texts",
                "",
                (
                    "These upstreams publish a license expression but no standalone notice in "
                    "the locked crate archive or its exact VCS revision. NEOTH binds the record "
                    "to the Cargo.lock crate checksum (and VCS revision when present), preserves "
                    "the published author metadata, and reproduces the selected compatible full "
                    "license text from pinned SPDX License List v3.27.0. No absent upstream "
                    "copyright assertion is invented."
                ),
                "",
            ]
        )
        for package in manifest_grant_packages:
            snapshot = snapshots[package_identity_key(package)]
            lines.append(
                f"- `{package_label(package)}` - `{package['license']}` - selected "
                f"`{snapshot['spdx_license']}` - binding `{snapshot['revision']}` - "
                f"crate SHA-256 `{snapshot['crate_sha256']}` - {snapshot['repository']}"
            )

    if inherited_repository_texts:
        lines.extend(
            [
                "",
                "### Repository-level texts used for split upstream crates",
                "",
                (
                    "These crate archives contain no standalone notice file, but another "
                    "locked crate from the same canonical upstream repository publishes the "
                    "repository-level text reproduced below. The crate's exact SPDX expression "
                    "in the inventory remains authoritative; carrying a repository's additional "
                    "text does not change that expression."
                ),
                "",
            ]
        )
        for package in inherited_repository_texts:
            lines.append(
                f"- `{package_label(package)}` - `{package['license']}` - {package_url(package)}"
            )

    if metadata_only:
        missing = "\n- ".join(package_label(package) for package in metadata_only)
        raise SystemExit(
            "Rust notice generation is incomplete; refresh exact upstream snapshots for:\n- "
            + missing
        )

    lines.extend(["", "### Published license and notice texts", ""])
    for digest, entry in sorted(texts.items()):
        lines.extend(
            [
                f"#### SHA-256 `{digest}`",
                "",
                "Applies to: "
                + ", ".join(f"`{label}`" for label in sorted(entry["packages"])),
                "",
                "----- BEGIN UPSTREAM LICENSE OR NOTICE -----",
                entry["text"].rstrip("\n"),
                "----- END UPSTREAM LICENSE OR NOTICE -----",
                "",
            ]
        )
    lines.extend([MARKER_END, ""])
    return "\n".join(lines)


def replace_generated_section(current: str, generated: str) -> str:
    start = current.find(MARKER_START)
    end = current.find(MARKER_END)
    if (start == -1) != (end == -1) or (start != -1 and end < start):
        raise SystemExit("THIRD_PARTY_LICENSES has malformed Rust notice markers")
    if start == -1:
        keet_marker = "<!-- BEGIN GENERATED: KEET DESKTOP RUNTIME LICENSES -->"
        insertion = current.find(keet_marker)
        if insertion == -1:
            return current.rstrip() + "\n\n" + generated
        return (
            current[:insertion].rstrip()
            + "\n\n"
            + generated
            + "\n"
            + current[insertion:]
        )
    end += len(MARKER_END)
    return current[:start] + generated.rstrip() + current[end:]


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    generated = generate()
    current = TARGET_FILE.read_text(encoding="utf-8")
    next_content = replace_generated_section(current, generated)
    if not next_content.endswith("\n"):
        next_content += "\n"

    if args.check:
        if next_content != current:
            raise SystemExit(
                "THIRD_PARTY_LICENSES has stale Rust distribution notices; run "
                "`python packaging/generate_rust_notices.py --write`"
            )
        print("Rust distribution notices are current in THIRD_PARTY_LICENSES")
        return

    TARGET_FILE.write_text(next_content, encoding="utf-8", newline="\n")
    print("Updated Rust distribution notices in THIRD_PARTY_LICENSES")


if __name__ == "__main__":
    main()
