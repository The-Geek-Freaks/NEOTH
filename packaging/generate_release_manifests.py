#!/usr/bin/env python3
"""Generate package-manager manifests from verified release payloads.

The release workflow invokes this only after every native package job. Inputs
are the actual payload bytes and their exact-name SHA-256 sidecars; placeholder
hashes and hand-edited URLs are therefore impossible in generated output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path


SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
SIDECAR = re.compile(r"^([0-9a-fA-F]{64})  ([^/\\\r\n]+)\n?$", re.ASCII)
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", re.ASCII)
PAYLOAD_SUFFIXES = (".tar.gz", ".zip", ".exe", ".deb", ".rpm", ".pkg", ".dmg")
NATIVE_METADATA_SUFFIXES = (".exe", ".deb", ".rpm", ".pkg", ".dmg")


class ManifestError(RuntimeError):
    pass


@dataclass(frozen=True)
class Asset:
    name: str
    sha256: str
    size: int
    metadata: str | None


def strict_version(value: str) -> str:
    match = SEMVER.fullmatch(value)
    if not match:
        raise ManifestError(f"invalid strict SemVer: {value}")
    prerelease = match.group(4)
    if prerelease and any(
        part.isdigit() and len(part) > 1 and part.startswith("0")
        for part in prerelease.split(".")
    ):
        raise ManifestError(f"numeric prerelease identifier has a leading zero: {value}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified_asset(dist: Path, name: str, version: str) -> Asset:
    payload = dist / name
    sidecar = dist / f"{name}.sha256"
    if payload.is_symlink() or not payload.is_file() or payload.stat().st_size == 0:
        raise ManifestError(f"missing non-empty release payload: {name}")
    if sidecar.is_symlink() or not sidecar.is_file():
        raise ManifestError(f"missing SHA-256 sidecar: {sidecar.name}")
    text = sidecar.read_text(encoding="utf-8")
    match = SIDECAR.fullmatch(text)
    if not match:
        raise ManifestError(f"malformed SHA-256 sidecar: {sidecar.name}")
    expected, bound_name = match.groups()
    if bound_name != name:
        raise ManifestError(
            f"{sidecar.name} is bound to {bound_name!r}, expected {name!r}"
        )
    actual = sha256(payload)
    if actual != expected.lower():
        raise ManifestError(f"SHA-256 mismatch for {name}")
    metadata_name = None
    metadata_path = dist / f"{name}.json"
    metadata_required = name.endswith(NATIVE_METADATA_SUFFIXES)
    if metadata_path.is_symlink():
        raise ManifestError(f"native package metadata is a symlink: {metadata_path.name}")
    if metadata_required and not metadata_path.is_file():
        raise ManifestError(f"missing native package metadata: {metadata_path.name}")
    if metadata_path.is_file():
        if metadata_path.stat().st_size == 0:
            raise ManifestError(f"missing native package metadata: {metadata_path.name}")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ManifestError(
                f"malformed native package metadata: {metadata_path.name}"
            ) from error
        if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
            raise ManifestError(f"invalid metadata schema: {metadata_path.name}")
        if metadata.get("product") != "NEOTH" or metadata.get("name") != name:
            raise ManifestError(f"metadata is not bound to {name}: {metadata_path.name}")
        if metadata.get("version") != version:
            raise ManifestError(f"metadata version mismatch for {name}")
        if metadata.get("sha256") != actual:
            raise ManifestError(f"metadata SHA-256 mismatch for {name}")
        for field in ("target", "architecture", "format"):
            if not isinstance(metadata.get(field), str) or not metadata[field]:
                raise ManifestError(f"metadata field {field} is invalid for {name}")
        if not isinstance(metadata.get("trust"), dict):
            raise ManifestError(f"metadata trust contract is invalid for {name}")
        metadata_name = metadata_path.name
    return Asset(
        name=name,
        sha256=actual,
        size=payload.stat().st_size,
        metadata=metadata_name,
    )


def discover_assets(dist: Path, version: str) -> dict[str, Asset]:
    names = sorted(
        path.name
        for path in dist.iterdir()
        if path.is_file() and path.name.endswith(PAYLOAD_SUFFIXES)
    )
    if not names:
        raise ManifestError("no release payloads found")
    return {name: verified_asset(dist, name, version) for name in names}


def required_native_names(version: str) -> tuple[str, ...]:
    return (
        f"NEOTH-{version}-x64-Setup.exe",
        f"NEOTH-{version}-arm64-Setup.exe",
        f"NEOTH-{version}-x86_64-unknown-linux-gnu.deb",
        f"NEOTH-{version}-aarch64-unknown-linux-gnu.deb",
        f"NEOTH-{version}-x86_64-unknown-linux-gnu.rpm",
        f"NEOTH-{version}-aarch64-unknown-linux-gnu.rpm",
        f"NEOTH-{version}-x86_64-apple-darwin.pkg",
        f"NEOTH-{version}-aarch64-apple-darwin.pkg",
        f"NEOTH-{version}-x86_64-apple-darwin.dmg",
        f"NEOTH-{version}-aarch64-apple-darwin.dmg",
    )


def release_url(repository: str, version: str, name: str) -> str:
    return f"https://github.com/{repository}/releases/download/v{version}/{name}"


def render_winget_installer(
    repository: str, version: str, assets: dict[str, Asset]
) -> str:
    rows = []
    for architecture in ("x64", "arm64"):
        name = f"NEOTH-{version}-{architecture}-Setup.exe"
        asset = assets[name]
        rows.append(
            f"""  - Architecture: {architecture}
    Scope: user
    InstallerUrl: {release_url(repository, version, name)}
    InstallerSha256: {asset.sha256.upper()}
    ProductCode: TheGeekFreaks.NEOTH.BF6060F4-B75D-4E9A-BEB6-7EC8CB94A3C1_is1
    AppsAndFeaturesEntries:
      - DisplayName: NEOTH {version}
        ProductCode: TheGeekFreaks.NEOTH.BF6060F4-B75D-4E9A-BEB6-7EC8CB94A3C1_is1"""
        )
    return f"""PackageIdentifier: TheGeekFreaks.NEOTH
PackageVersion: {version}
InstallerType: inno
InstallerLocale: en-US
InstallModes:
  - interactive
  - silent
  - silentWithProgress
InstallerSwitches:
  Custom: /CURRENTUSER
  Upgrade: /CURRENTUSER
UpgradeBehavior: install
Commands:
  - neoth
  - neothd
  - neothd-gui
  - neoth-migrate
  - neoth-relay
  - neoth-keet-bridge
Installers:
{chr(10).join(rows)}
ManifestType: installer
ManifestVersion: 1.6.0
"""


def render_winget_version(version: str) -> str:
    return f"""PackageIdentifier: TheGeekFreaks.NEOTH
PackageVersion: {version}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"""


def render_winget_locale(repository: str, version: str) -> str:
    return f"""PackageIdentifier: TheGeekFreaks.NEOTH
PackageVersion: {version}
PackageLocale: en-US
Publisher: The Geek Freaks
PublisherUrl: https://github.com/The-Geek-Freaks
PublisherSupportUrl: https://github.com/{repository}/issues
PackageName: NEOTH
PackageUrl: https://github.com/{repository}
License: MIT OR Apache-2.0
LicenseUrl: https://github.com/{repository}/blob/main/LICENSE-MIT
ShortDescription: Local-first personal AI agent with operator-controlled automation.
Description: |-
  NEOTH is a local-first personal AI agent with durable tiered memory,
  multi-provider deliberation, a graphical desktop interface, a complete CLI,
  audited cost and permission gates, scheduled automation, migration tooling,
  and first-class messaging channels including its authenticated Keet companion.
Moniker: neoth
Tags:
  - agent
  - ai
  - assistant
  - cli
  - gui
  - llm
  - local-first
  - memory
  - privacy
  - rust
ReleaseNotesUrl: https://github.com/{repository}/releases/tag/v{version}
ManifestType: defaultLocale
ManifestVersion: 1.6.0
"""


def render_homebrew_cask(
    repository: str, version: str, assets: dict[str, Asset]
) -> str:
    arm = assets[f"NEOTH-{version}-aarch64-apple-darwin.dmg"]
    intel = assets[f"NEOTH-{version}-x86_64-apple-darwin.dmg"]
    return f'''cask "neoth" do
  version "{version}"
  arch arm: "aarch64", intel: "x86_64"

  sha256 arm:   "{arm.sha256}",
         intel: "{intel.sha256}"

  url "https://github.com/{repository}/releases/download/v#{{version}}/NEOTH-#{{version}}-#{{arch}}-apple-darwin.dmg"
  name "NEOTH"
  desc "Local-first personal AI agent with operator-controlled automation"
  homepage "https://github.com/{repository}"
  depends_on macos: ">= :ventura"

  app "NEOTH.app"
  binary "#{{appdir}}/NEOTH.app/Contents/MacOS/neoth", target: "neoth"
  binary "#{{appdir}}/NEOTH.app/Contents/MacOS/neothd", target: "neothd"
  binary "#{{appdir}}/NEOTH.app/Contents/MacOS/neothd-gui", target: "neothd-gui"
  binary "#{{appdir}}/NEOTH.app/Contents/MacOS/neoth-migrate", target: "neoth-migrate"
  binary "#{{appdir}}/NEOTH.app/Contents/MacOS/neoth-relay", target: "neoth-relay"
  binary "#{{appdir}}/NEOTH.app/Contents/MacOS/neoth-keet-bridge", target: "neoth-keet-bridge"

  caveats <<~EOS
    Run `neoth` once to choose the graphical or command-line interface.
    Uninstalling the app deliberately preserves your ~/.neoth operator data.
  EOS
end
'''


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def deterministic_zip(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, path.read_bytes())


def generate(dist: Path, output: Path, repository: str, version: str) -> Path:
    version = strict_version(version)
    if not REPOSITORY.fullmatch(repository):
        raise ManifestError(f"invalid GitHub repository identifier: {repository}")
    dist = dist.resolve(strict=True)
    if not dist.is_dir():
        raise ManifestError(f"dist is not a directory: {dist}")
    output.mkdir(parents=True, exist_ok=True)
    assets = discover_assets(dist, version)
    missing = sorted(set(required_native_names(version)) - set(assets))
    if missing:
        raise ManifestError("missing native release assets: " + ", ".join(missing))

    bundle = output / f"neoth-package-manifests-v{version}"
    archive = output / f"neoth-package-manifests-v{version}.zip"
    sidecar = archive.with_suffix(".zip.sha256")
    for destination in (bundle, archive, sidecar):
        if destination.exists() or destination.is_symlink():
            raise ManifestError(f"output already exists: {destination}")
    write_text(
        bundle / "winget" / "TheGeekFreaks.NEOTH.installer.yaml",
        render_winget_installer(repository, version, assets),
    )
    write_text(
        bundle / "winget" / "TheGeekFreaks.NEOTH.yaml",
        render_winget_version(version),
    )
    write_text(
        bundle / "winget" / "TheGeekFreaks.NEOTH.locale.en-US.yaml",
        render_winget_locale(repository, version),
    )
    write_text(
        bundle / "homebrew" / "neoth.rb",
        render_homebrew_cask(repository, version, assets),
    )
    index = {
        "schema_version": 1,
        "repository": repository,
        "tag": f"v{version}",
        "version": version,
        "assets": [asdict(assets[name]) for name in sorted(assets)],
    }
    write_text(
        bundle / "release-index.json",
        json.dumps(index, indent=2, sort_keys=True) + "\n",
    )

    deterministic_zip(bundle, archive)
    digest = sha256(archive)
    write_text(sidecar, f"{digest}  {archive.name}\n")
    return archive


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", default="The-Geek-Freaks/NEOTH")
    args = parser.parse_args()
    archive = generate(args.dist, args.output, args.repository, args.version)
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
