#!/usr/bin/env python3
"""Refresh exact VCS-bound license snapshots for split Rust crates."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib
from typing import Any
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from generate_rust_notices import (
    MAX_NOTICE_BYTES,
    NOTICE_DIRECTORIES,
    NOTICE_NAME,
    SNAPSHOT_FILE,
    WORKSPACE_ROOT,
    notice_paths,
    package_identity_key,
    package_label,
    read_notice,
    repository_key,
    resolved_release_packages,
    normalize_notice_text,
)


USER_AGENT = "NEOTH-license-snapshot/1.0 (+https://github.com/The-Geek-Freaks/NEOTH)"
REPOSITORY_OVERRIDES = {
    "cranelift-assembler-x64": "https://github.com/bytecodealliance/wasmtime",
    "cranelift-assembler-x64-meta": "https://github.com/bytecodealliance/wasmtime",
}
SPDX_REVISION = "d46e94e2c78ceede1cfc63cfa0396472d2798d4c"  # license-list-data v3.27.0
MANIFEST_GRANT_FALLBACKS = {
    ("adobe-cmap-parser", "0.4.1"): "MIT",
    ("anndists", "0.1.5"): "Apache-2.0",
    ("bitcoin-io", "0.1.100"): "CC0-1.0",
    ("bitcoin_hashes", "0.14.100"): "CC0-1.0",
    ("crc32c", "0.6.8"): "Apache-2.0",
    ("dispatch", "0.2.0"): "MIT",
    ("drm-fourcc", "2.2.0"): "MIT",
    ("enum-assoc", "1.3.0"): "MIT",
    ("pdf-extract", "0.12.0"): "MIT",
    ("realfft", "3.5.0"): "MIT",
    ("simd_helpers", "0.1.0"): "MIT",
    ("type1-encoding-parser", "0.1.1"): "MIT",
}
# `selectors` is covered by an exact same-repository license text published by
# another locked Servo crate. generate_rust_notices.py proves that inheritance.
REPOSITORY_INHERIT_ONLY = {("selectors", "0.38.0")}


def fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urlopen(request, timeout=90) as response:
        return response.read()


def crates_io_repository(package: dict[str, Any]) -> str | None:
    name = quote(package["name"], safe="")
    version = quote(package["version"], safe="")
    data = json.loads(fetch(f"https://crates.io/api/v1/crates/{name}/{version}"))
    crate = data.get("crate") or {}
    version_data = data.get("version") or {}
    return version_data.get("repository") or crate.get("repository")


def vcs_info(package: dict[str, Any]) -> tuple[str, str]:
    path = Path(package["manifest_path"]).parent / ".cargo_vcs_info.json"
    if not path.is_file():
        raise RuntimeError(f"{package_label(package)} has no .cargo_vcs_info.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    revision = data.get("git", {}).get("sha1")
    if not revision or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError(f"{package_label(package)} has no exact published Git revision")
    return revision, data.get("path_in_vcs", "").strip("/")


def archive_url(repository: str, revision: str) -> str:
    parsed = urlsplit(repository)
    path = parsed.path.strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    path = re.split(r"/(?:tree|blob)/", path, maxsplit=1, flags=re.IGNORECASE)[0]
    path = re.split(r"/src/(?:branch|tag)/", path, maxsplit=1, flags=re.IGNORECASE)[0]
    parts = path.split("/")
    if len(parts) < 2:
        raise RuntimeError(f"unsupported repository URL: {repository}")
    owner, repo = parts[0], parts[1]
    host = parsed.netloc.lower()
    if host in {"github.com", "www.github.com"}:
        return f"https://codeload.github.com/{owner}/{repo}/tar.gz/{revision}"
    if host == "codeberg.org":
        return f"https://codeberg.org/{owner}/{repo}/archive/{revision}.tar.gz"
    raise RuntimeError(f"unsupported repository host for exact snapshot: {host}")


def candidate_prefixes(path_in_vcs: str) -> set[PurePosixPath]:
    prefixes = {PurePosixPath(".")}
    current = PurePosixPath(path_in_vcs)
    if str(current) not in {"", "."}:
        parts = current.parts
        for count in range(1, len(parts) + 1):
            prefixes.add(PurePosixPath(*parts[:count]))
    return prefixes


def extract_notices(archive: bytes, path_in_vcs: str) -> list[dict[str, str]]:
    prefixes = candidate_prefixes(path_in_vcs)
    notices: dict[str, dict[str, str]] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.size > MAX_NOTICE_BYTES:
                continue
            path = PurePosixPath(member.name)
            if len(path.parts) < 2:
                continue
            relative = PurePosixPath(*path.parts[1:])
            selected = False
            for prefix in prefixes:
                try:
                    nested = relative.relative_to(prefix)
                except ValueError:
                    continue
                if len(nested.parts) == 1 and NOTICE_NAME.match(nested.name):
                    selected = True
                elif nested.parts and nested.parts[0].lower() in NOTICE_DIRECTORIES:
                    selected = True
                if selected:
                    break
            if not selected:
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            raw = extracted.read()
            if b"\0" in raw:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
            text = normalize_notice_text(text)
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            notices.setdefault(
                digest,
                {"path": str(relative), "sha256": digest, "text": text},
            )
    return sorted(notices.values(), key=lambda notice: (notice["path"].lower(), notice["sha256"]))


def lock_checksums() -> dict[tuple[str, str, str], str]:
    lock = tomllib.loads((WORKSPACE_ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    return {
        (package["name"], package["version"], package.get("source", "")): package["checksum"]
        for package in lock["package"]
        if package.get("checksum")
    }


def snapshot_file(path: str, text: str) -> dict[str, str]:
    normalized = normalize_notice_text(text)
    return {
        "path": path,
        "sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "text": normalized,
    }


def manifest_grant_snapshot(
    package: dict[str, Any], repository: str, selected_license: str, checksum: str
) -> dict[str, Any]:
    try:
        revision, path_in_vcs = vcs_info(package)
    except RuntimeError:
        revision, path_in_vcs = f"crate-sha256:{checksum}", ""

    spdx_url = (
        "https://raw.githubusercontent.com/spdx/license-list-data/"
        f"{SPDX_REVISION}/text/{selected_license}.txt"
    )
    canonical_text = fetch(spdx_url).decode("utf-8")
    authors = package.get("authors") or []
    if selected_license == "MIT":
        if not authors:
            raise RuntimeError("MIT metadata fallback has no published author attribution")
        canonical_text = canonical_text.replace(
            "Copyright (c) <year> <copyright holders>",
            "Published upstream author attribution: " + "; ".join(authors),
        )

    grant_lines = [
        "UPSTREAM PUBLISHED LICENSE GRANT RECORD",
        "",
        f"Package: {package_label(package)}",
        f"Locked registry source: {package['source']}",
        f"Published crate SHA-256: {checksum}",
        f"Published license expression: {package['license']}",
        f"Selected compatible license text: {selected_license}",
        f"Repository: {repository}",
        f"Revision binding: {revision}",
        "Published authors:",
    ]
    grant_lines.extend(f"- {author}" for author in authors)
    grant_lines.extend(
        [
            "",
            "The exact published crate archive and, where available, its bound VCS revision",
            "contain no standalone license/notice file. This record preserves every license",
            "and author field the upstream publisher supplied. The full selected license text",
            "is reproduced from the pinned SPDX License List revision named in this snapshot.",
            "For MIT-only packages, the published author entries are retained as attribution;",
            "they are not recharacterized as an upstream copyright assertion.",
        ]
    )
    return {
        "kind": "manifest-grant",
        "repository": repository,
        "revision": revision,
        "path_in_vcs": path_in_vcs,
        "crate_sha256": checksum,
        "spdx_license": selected_license,
        "spdx_revision": SPDX_REVISION,
        "files": [
            snapshot_file("UPSTREAM-MANIFEST-GRANT.txt", "\n".join(grant_lines)),
            snapshot_file(f"SPDX-v3.27.0/{selected_license}.txt", canonical_text),
        ],
    }


def main() -> None:
    packages = [package for package in resolved_release_packages() if not notice_paths(package)]
    snapshots: dict[str, Any] = {}
    archive_cache: dict[tuple[str, str], bytes] = {}
    failures: list[str] = []
    checksums = lock_checksums()

    for index, package in enumerate(packages, 1):
        package_version = (package["name"], package["version"])
        if package_version in REPOSITORY_INHERIT_ONLY:
            print(
                f"{index}/{len(packages)} same-repository inheritance {package_label(package)}",
                flush=True,
            )
            continue
        try:
            repository = (
                package.get("repository")
                or package.get("homepage")
                or REPOSITORY_OVERRIDES.get(package["name"])
                or crates_io_repository(package)
            )
            if not repository:
                raise RuntimeError("no upstream repository URL")
            normalized_repository = repository_key({"repository": repository})
            if normalized_repository is None:
                raise RuntimeError("cannot normalize upstream repository URL")
            checksum = checksums.get(
                (package["name"], package["version"], package["source"])
            )
            if not checksum:
                raise RuntimeError("Cargo.lock has no registry checksum")
            selected_license = MANIFEST_GRANT_FALLBACKS.get(package_version)
            if selected_license:
                try:
                    revision, path_in_vcs = vcs_info(package)
                    cache_key = (normalized_repository, revision)
                    archive = archive_cache.get(cache_key)
                    if archive is None:
                        archive = fetch(archive_url(repository, revision))
                        archive_cache[cache_key] = archive
                    files = extract_notices(archive, path_in_vcs)
                except RuntimeError:
                    files = []
                if not files:
                    snapshots[package_identity_key(package)] = manifest_grant_snapshot(
                        package, normalized_repository, selected_license, checksum
                    )
                    print(
                        f"{index}/{len(packages)} manifest grant {package_label(package)}",
                        flush=True,
                    )
                    continue
            revision, path_in_vcs = vcs_info(package)
            cache_key = (normalized_repository, revision)
            archive = archive_cache.get(cache_key)
            if archive is None:
                archive = fetch(archive_url(repository, revision))
                archive_cache[cache_key] = archive
            files = extract_notices(archive, path_in_vcs)
            if not files:
                raise RuntimeError("exact upstream revision contains no applicable notice file")
            snapshots[package_identity_key(package)] = {
                "repository": normalized_repository,
                "revision": revision,
                "path_in_vcs": path_in_vcs,
                "files": files,
            }
            print(f"{index}/{len(packages)} snapshotted {package_label(package)}", flush=True)
        except Exception as error:  # each failure is reported together for one review pass
            failures.append(f"{package_label(package)}: {error}")

    output = {"schema": 1, "packages": dict(sorted(snapshots.items()))}
    SNAPSHOT_FILE.write_text(
        json.dumps(output, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"Wrote {len(snapshots)} exact package snapshots from "
        f"{len(archive_cache)} upstream revisions to {SNAPSHOT_FILE}"
    )
    if failures:
        raise SystemExit("unresolved Rust license snapshots:\n- " + "\n- ".join(failures))


if __name__ == "__main__":
    main()
