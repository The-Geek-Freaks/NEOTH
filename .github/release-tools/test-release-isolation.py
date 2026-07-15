from __future__ import annotations

import pathlib
import re


WORKFLOW = pathlib.Path(__file__).parents[1] / "workflows" / "release.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")
JOB_PATTERN = re.compile(
    r"(?ms)^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
)
JOBS = {name: body for name, body in JOB_PATTERN.findall(TEXT)}
RUST_TOOLCHAIN_ACTION = (
    "uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30"
)
RUST_186_PIN = f"{RUST_TOOLCHAIN_ACTION} # stable\n        with:\n          toolchain: '1.86.0'"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"release isolation contract failed: {message}")


def job(name: str) -> str:
    require(name in JOBS, f"missing job {name}")
    return JOBS[name]


require(
    TEXT.count(RUST_TOOLCHAIN_ACTION) == TEXT.count(RUST_186_PIN),
    "a SHA-pinned rust-toolchain action lacks explicit Rust 1.86.0 selection",
)


prepare = job("prepare-release-assets")
build_signer = job("build-release-signer")
minisign = job("minisign-release-assets")
cosign = job("cosign-release-assets")
publish = job("release")

require("contents: write" not in minisign, "minisign job can write repository contents")
require("id-token: write" not in minisign, "minisign job has an OIDC token")
require("actions/checkout" not in minisign, "secret-bearing minisign job has a checkout")
require("secrets.NEOTH_RELEASE_MINISIGN_SECRET" in minisign, "minisign secret is not isolated")
require("neoth release sign" not in minisign, "minisign job executes the product signer")
require("tar xzf" not in minisign, "minisign job extracts a product archive")
require("--version" not in minisign, "minisign job executes a product version probe")
require("persist-credentials: false" in build_signer, "signer-build checkout persists credentials")
require("secrets." not in build_signer, "signer-build runner receives a secret")
require("signer_sha256" in build_signer, "isolated signer transfer is not byte-bound")
require("Cargo.lock" in build_signer, "signer-build gate does not require its lockfile")
require("cargo metadata --locked" in build_signer, "signer lockfile is not validated")
require("cargo fmt --check" in build_signer, "signer source formatting is not gated")
require("cargo test --locked" in build_signer, "signer tests do not use the lockfile")

secret_reference = "secrets.NEOTH_RELEASE_MINISIGN_SECRET"
require(
    secret_reference not in TEXT.replace(minisign, "", 1),
    "minisign secret is referenced outside its isolated job",
)
require("id-token: write" in cosign, "Cosign job lacks OIDC")
require("contents: write" not in cosign, "Cosign job can publish")
require("secrets." not in cosign, "Cosign job references a long-lived secret")
require("actions/checkout" not in cosign, "Cosign job has an unnecessary checkout")

require("contents: write" in publish, "publish job cannot create the release")
require("id-token: write" not in publish, "publish job has OIDC")
require("secrets." not in publish, "publish job references a signing secret")
require("actions/checkout" not in publish, "publish job has a checkout")
require("git fetch" not in publish, "checkout-free publish job still invokes git")
require("/git/ref/tags/" in publish, "publish job does not re-resolve the remote tag")
require("draft=false" in publish, "draft publication is not the final commit point")
require("remote draft asset set does not exactly match" in publish, "exact asset check missing")

require("provenance" not in TEXT.lower(), "Cosign bundle is mislabeled as provenance")
require(
    "--certificate-identity=https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@refs/tags/${GITHUB_REF_NAME}"
    in publish,
    "release notes omit exact Sigstore certificate identity",
)
require(
    "--certificate-oidc-issuer=https://token.actions.githubusercontent.com" in publish,
    "release notes omit exact Sigstore OIDC issuer",
)

require("CodeQL / Rust" in job("verify-release-version"), "Rust CodeQL gate missing")
require("CodeQL / JavaScript" in job("verify-release-version"), "JavaScript CodeQL gate missing")

musl_smoke = job("smoke-linux-musl-portable")
require("needs: build" in musl_smoke, "musl smoke is not bound to the build artifact")
require("actions/checkout" not in musl_smoke, "musl smoke has an unnecessary checkout")
require("secrets." not in musl_smoke, "musl smoke receives a signing secret")
require("actions: read" in musl_smoke, "musl smoke cannot read immutable artifacts")
require("sha256sum --check --strict" in musl_smoke, "musl archive sidecar is not verified")
require("expected_names" in musl_smoke, "musl archive exact-set validation is missing")
require("member.isreg()" in musl_smoke, "musl archive permits non-regular members")
require("neothd-gui" in musl_smoke, "musl smoke does not assert GUI absence")
require("neoth-keet-bridge" in musl_smoke, "musl smoke does not assert Keet absence")
for binary in ("neoth", "neothd", "neoth-migrate", "neoth-relay"):
    require(binary in musl_smoke, f"musl smoke omits {binary}")
require("--version" in musl_smoke, "musl binaries are not executed against the tag")
require("readelf -l" in musl_smoke, "musl smoke does not prove static portability")
require(
    "smoke-linux-musl-portable" in job("generate-package-manifests"),
    "musl smoke is outside the final release dependency graph",
)

for platform in ("linux", "macos"):
    preflight = job(f"preflight-{platform}-native")
    package = job(f"package-{platform}-native")
    smoke = job(f"smoke-{platform}-native")
    require("--write-preflight-receipt" in preflight, f"{platform} preflight receipt missing")
    require("--preflight-receipt" in package, f"{platform} package receipt verify missing")
    require("output=$(/" not in package, f"{platform} package job executes installed product")
    require("clean-machine smoke" not in package, f"{platform} product smoke shares package runner")
    require("--version" in smoke, f"{platform} fresh-runner smoke lacks runtime probe")
    require(
        f"smoke-{platform}-native" in job("generate-package-manifests"),
        f"{platform} smoke is outside release dependency graph",
    )

windows_package = job("package-windows-installer")
require("-DeleteKey" in windows_package, "Windows cleanup leaves imported private key")
require("Ephemeral Authenticode PFX cleanup failed" in windows_package, "Windows PFX cleanup is fail-open")
require("smoke-installer.ps1" not in windows_package, "Windows product smoke shares signing runner")
require("smoke-installer.ps1" in job("smoke-windows-installer"), "Windows fresh smoke missing")
require(
    "smoke-windows-installer" in job("generate-package-manifests"),
    "Windows smoke is outside release dependency graph",
)

macos_package = job("package-macos-native")
require("security import" in macos_package and " -x \\" in macos_package, "Apple key import is extractable")
require("test ! -e \"$KEYCHAIN\"" in macos_package, "Apple keychain cleanup lacks postcondition")

for producer, output_name in (
    (prepare, "signing_inputs_sha256"),
    (minisign, "minisign_signatures_sha256"),
    (cosign, "cosign_bundles_sha256"),
):
    require(output_name in producer, f"missing cross-job output {output_name}")
require("Verify every cross-job transfer byte" in publish, "publish lacks transfer binding checks")
require("NEOTH_INTERNAL_SIGNING_INPUTS.SHA256" in publish, "input transfer manifest missing")
require("NEOTH_INTERNAL_MINISIGN_SIGNATURES.SHA256" in publish, "minisign transfer manifest missing")
require("NEOTH_INTERNAL_COSIGN_BUNDLES.SHA256" in publish, "Cosign transfer manifest missing")

print("release key and artifact isolation contracts passed")
