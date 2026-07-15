#!/usr/bin/env python3
"""Pin the clean-machine installer verifier to one reviewed Sigstore source."""

from __future__ import annotations

import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = json.loads(
    (ROOT / "packaging/cosign-bootstrap.json").read_text(encoding="utf-8")
)
UNIX = (ROOT / "SRC/install.sh").read_text(encoding="utf-8")
WINDOWS = (ROOT / "SRC/install.ps1").read_text(encoding="utf-8")
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"bootstrap verifier contract failed: {message}")


def capture(text: str, pattern: str, label: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    require(match is not None, f"missing {label}")
    return match.group(1)


require(MANIFEST.get("schema_version") == 1, "unknown manifest schema")
source = MANIFEST.get("source", {})
require(source.get("repository") == "sigstore/cosign-installer", "wrong source repo")
require(re.fullmatch(r"[0-9a-f]{40}", source.get("commit", "")) is not None, "source commit is not immutable")
require(source.get("path") == "action.yml", "wrong digest source path")

version = MANIFEST["cosign_version"]
assets = MANIFEST["assets"]
for platform, asset in assets.items():
    require(re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]) is not None, f"bad {platform} digest")
    require("/" not in asset["name"] and "\\" not in asset["name"], f"unsafe {platform} asset name")

unix_pins = {
    "version": capture(UNIX, r'^COSIGN_BOOTSTRAP_VERSION="([^"]+)"$', "Unix version pin"),
    "linux_amd64": capture(UNIX, r'^COSIGN_BOOTSTRAP_LINUX_AMD64_SHA256="([0-9a-f]+)"$', "Unix linux-amd64 pin"),
    "linux_arm64": capture(UNIX, r'^COSIGN_BOOTSTRAP_LINUX_ARM64_SHA256="([0-9a-f]+)"$', "Unix linux-arm64 pin"),
    "darwin_amd64": capture(UNIX, r'^COSIGN_BOOTSTRAP_DARWIN_AMD64_SHA256="([0-9a-f]+)"$', "Unix darwin-amd64 pin"),
    "darwin_arm64": capture(UNIX, r'^COSIGN_BOOTSTRAP_DARWIN_ARM64_SHA256="([0-9a-f]+)"$', "Unix darwin-arm64 pin"),
}
require(unix_pins["version"] == version, "Unix cosign version drift")
for platform in ("linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"):
    require(unix_pins[platform] == assets[platform]["sha256"], f"Unix {platform} digest drift")
    require(assets[platform]["name"] in UNIX, f"Unix {platform} filename drift")

windows_version = capture(WINDOWS, r"^\$CosignBootstrapVersion = '([^']+)'$", "Windows version pin")
windows_sha = capture(WINDOWS, r"^\$CosignBootstrapWindowsAmd64Sha256 = '([0-9a-f]+)'$", "Windows digest pin")
require(windows_version == version, "Windows cosign version drift")
require(windows_sha == assets["windows_amd64"]["sha256"], "Windows digest drift")
require(assets["windows_amd64"]["name"] in WINDOWS, "Windows filename drift")

unix_bootstrap = UNIX[UNIX.index("resolve_cosign_verifier() {") : UNIX.index("verify_release_authenticity() {")]
unix_download = unix_bootstrap.index("curl --retry 3 --retry-delay 1 --connect-timeout 20")
unix_hash = unix_bootstrap.index('got="$(sha256_file "$path")"')
unix_execute_ready = unix_bootstrap.index('COSIGN_VERIFIER="$path"')
require(unix_download < unix_hash < unix_execute_ready, "Unix verifier is usable before hash validation")
require('"$COSIGN_VERIFIER" verify-blob' in UNIX, "Unix verification does not use the resolved verifier")
require("eval " not in unix_bootstrap, "Unix bootstrap uses eval")

windows_bootstrap = WINDOWS[WINDOWS.index("function Resolve-CosignVerifier {") : WINDOWS.index("function Verify-ReleaseAuthenticity {")]
windows_download = windows_bootstrap.index("Invoke-Download -Uri $uri")
windows_hash = windows_bootstrap.index("Get-FileHash -LiteralPath $path -Algorithm SHA256")
windows_return = windows_bootstrap.index("return $path")
require(windows_download < windows_hash < windows_return, "Windows verifier is usable before hash validation")
require("& $cosignPath verify-blob" in WINDOWS, "Windows verification does not use the resolved verifier")
require("https://github.com/sigstore/cosign/releases/download/" in windows_bootstrap, "Windows bootstrap URL is not fixed HTTPS")
require("Invoke-WebRequest -Uri $Uri -OutFile $OutFile" in WINDOWS, "Windows retry helper does not use the fixed URI")

action = f"uses: sigstore/cosign-installer@{source['commit']}"
require(action in RELEASE, "release workflow uses a different cosign-installer source")
require(f"cosign-release: '{version}'" in RELEASE, "release workflow does not pin the same cosign version")

print(f"bootstrap verifier contract OK: cosign {version}, {len(assets)} pinned assets")
