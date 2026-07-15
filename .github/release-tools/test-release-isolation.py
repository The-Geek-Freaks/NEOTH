from __future__ import annotations

import pathlib
import re
import tomllib


REPOSITORY_ROOT = pathlib.Path(__file__).parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
WORKSPACE_MANIFEST = REPOSITORY_ROOT / "SRC" / "Cargo.toml"
PRODUCT_LOCKFILE = REPOSITORY_ROOT / "SRC" / "Cargo.lock"
PRODUCT_VERIFIER = REPOSITORY_ROOT / "SRC" / "neothd" / "src" / "updater" / "sig_verify.rs"
SIGNER_ROOT = REPOSITORY_ROOT / ".github" / "release-tools" / "neoth-release-signer"
SIGNER_MANIFEST_PATH = SIGNER_ROOT / "Cargo.toml"
SIGNER_LOCKFILE = SIGNER_ROOT / "Cargo.lock"
TEXT = WORKFLOW.read_text(encoding="utf-8")
WORKSPACE = tomllib.loads(WORKSPACE_MANIFEST.read_text(encoding="utf-8"))
PRODUCT_LOCK = tomllib.loads(PRODUCT_LOCKFILE.read_text(encoding="utf-8"))
PRODUCT_VERIFIER_TEXT = PRODUCT_VERIFIER.read_text(encoding="utf-8")
SIGNER_MANIFEST = tomllib.loads(SIGNER_MANIFEST_PATH.read_text(encoding="utf-8"))
SIGNER_LOCK = tomllib.loads(SIGNER_LOCKFILE.read_text(encoding="utf-8"))
JOB_PATTERN = re.compile(
    r"(?ms)^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
)
JOBS = {name: body for name, body in JOB_PATTERN.findall(TEXT)}
RUST_TOOLCHAIN_ACTION = (
    "uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30"
)
WORKSPACE_MSRV = (
    WORKSPACE.get("workspace", {}).get("package", {}).get("rust-version")
)
RELEASE_RUST_VERSION = (
    WORKSPACE_MSRV
    if isinstance(WORKSPACE_MSRV, str) and WORKSPACE_MSRV.count(".") == 2
    else f"{WORKSPACE_MSRV}.0"
)
RUST_MSRV_PIN = (
    f"{RUST_TOOLCHAIN_ACTION} # stable\n"
    "        with:\n"
    f"          toolchain: '{RELEASE_RUST_VERSION}'"
)
DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}
PATH_ATTRIBUTE = re.compile(r"#\s*\[[^\]]*\bpath\s*=", re.DOTALL)
INCLUDE_MACRO = re.compile(
    r"\binclude(?:_str|_bytes)?\s*!|\b(?:pub\s+)?use\s+[^;]*\binclude(?:_str|_bytes)?\b"
)
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
EXPECTED_SIGNER_DEPENDENCIES = {
    "anyhow",
    "base64",
    "blake2",
    "ed25519-dalek",
    "minisign-verify",
    "zeroize",
}
EXPECTED_SIGNER_DEV_DEPENDENCIES = {"tempfile"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"release isolation contract failed: {message}")


def job(name: str) -> str:
    require(name in JOBS, f"missing job {name}")
    return JOBS[name]


def is_within(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def dependency_specs(table: dict, prefix: tuple[str, ...] = ()):
    for key, value in table.items():
        current = (*prefix, key)
        if key in DEPENDENCY_TABLES and isinstance(value, dict):
            for name, spec in value.items():
                yield ".".join(current), name, spec
        elif isinstance(value, dict):
            yield from dependency_specs(value, current)


def locked_package_versions(lockfile: dict, package_name: str) -> set[tuple[str, str | None]]:
    return {
        (package["version"], package.get("source"))
        for package in lockfile.get("package", [])
        if package.get("name") == package_name
    }


def dependency_violation(name: str, spec: object) -> str | None:
    if isinstance(spec, str):
        if not spec.startswith("="):
            return f"registry dependency {name} is not exactly version-pinned"
        return None
    if not isinstance(spec, dict):
        return f"dependency {name} has an unsupported manifest shape"
    if "git" in spec:
        return f"dependency {name} uses a Git/network source"
    if "registry" in spec:
        return f"dependency {name} overrides the audited crates.io registry"
    if "workspace" in spec:
        return f"dependency {name} inherits from an external workspace"
    if "path" in spec:
        return f"dependency {name} uses a path source"
    version = spec.get("version")
    if not isinstance(version, str) or not version.startswith("="):
        return f"registry dependency {name} is not exactly version-pinned"
    return None


require(
    isinstance(WORKSPACE_MSRV, str)
    and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", WORKSPACE_MSRV) is not None,
    "workspace.package.rust-version is missing or invalid",
)
require(
    TEXT.count(RUST_TOOLCHAIN_ACTION) == TEXT.count(RUST_MSRV_PIN),
    "a SHA-pinned rust-toolchain action does not select the workspace MSRV "
    f"({RELEASE_RUST_VERSION})",
)

# Guard the guards against the concrete source-escape forms this contract
# exists to reject, including cfg_attr-based path indirection.
for sample in (
    '#[path = "../../../../SRC/neothd/src/updater/sig_keygen.rs"] mod signer;',
    '#[cfg_attr(unix, path = "../../../../SRC/product.rs")] mod product;',
):
    require(PATH_ATTRIBUTE.search(sample) is not None, "#[path] detector regressed")
for sample in (
    'include!("../../../../SRC/product.rs");',
    'const DATA: &str = include_str!("../../../../SRC/data");',
    'const DATA: &[u8] = include_bytes!("../../../../SRC/data");',
    'use std::include_bytes as embed_product;',
):
    require(INCLUDE_MACRO.search(sample) is not None, "include-macro detector regressed")
for name, spec in (
    ("outside", {"path": "../../../../SRC/neothd"}),
    ("local-path", {"path": "local-crate"}),
    ("git", {"git": "https://example.invalid/repository"}),
    ("registry", {"version": "=1.0.0", "registry": "external"}),
    ("workspace", {"workspace": True}),
):
    require(
        dependency_violation(name, spec) is not None,
        f"dependency isolation detector accepted forbidden {name} source",
    )
require(
    dependency_violation("pinned", "=1.0.0") is None,
    "dependency isolation detector rejected an exact crates.io pin",
)

signer_sources = sorted(SIGNER_ROOT.rglob("*.rs"))
require(bool(signer_sources), "isolated signer has no Rust sources")
for signer_entry in SIGNER_ROOT.rglob("*"):
    require(
        not signer_entry.is_symlink(),
        f"isolated signer tree contains a symlink: {signer_entry.relative_to(SIGNER_ROOT)}",
    )
for signer_source in signer_sources:
    relative_source = signer_source.relative_to(SIGNER_ROOT)
    require(
        is_within(signer_source, SIGNER_ROOT),
        f"isolated signer source escapes its tree: {relative_source}",
    )
    signer_text = signer_source.read_text(encoding="utf-8")
    require(
        PATH_ATTRIBUTE.search(signer_text) is None,
        f"isolated signer source uses a #[path] attribute: {relative_source}",
    )
    require(
        INCLUDE_MACRO.search(signer_text) is None,
        f"isolated signer source uses a compile-time include macro: {relative_source}",
    )

signer_package = SIGNER_MANIFEST.get("package", {})
require(
    signer_package.get("build") in (None, False),
    "isolated signer declares a custom build script",
)
require(not (SIGNER_ROOT / "build.rs").exists(), "isolated signer has an implicit build script")
require("workspace" not in SIGNER_MANIFEST, "isolated signer must remain a standalone crate")
require("patch" not in SIGNER_MANIFEST, "isolated signer manifest contains dependency patches")
require("replace" not in SIGNER_MANIFEST, "isolated signer manifest contains replacements")
require(
    set(SIGNER_MANIFEST.get("dependencies", {})) == EXPECTED_SIGNER_DEPENDENCIES,
    "isolated signer runtime dependency allowlist changed",
)
require(
    set(SIGNER_MANIFEST.get("dev-dependencies", {})) == EXPECTED_SIGNER_DEV_DEPENDENCIES,
    "isolated signer dev-dependency allowlist changed",
)
require(
    not SIGNER_MANIFEST.get("build-dependencies"),
    "isolated signer must not have build dependencies",
)

for target_kind in ("lib", "bin", "example", "test", "bench"):
    configured_targets = SIGNER_MANIFEST.get(target_kind, [])
    if isinstance(configured_targets, dict):
        configured_targets = [configured_targets]
    for target in configured_targets:
        target_path = target.get("path")
        if target_path is not None:
            require(
                isinstance(target_path, str)
                and is_within(SIGNER_ROOT / target_path, SIGNER_ROOT),
                f"isolated signer {target_kind} target escapes its tree",
            )

for table, dependency_name, dependency_spec in dependency_specs(SIGNER_MANIFEST):
    require(
        table in DEPENDENCY_TABLES,
        f"isolated signer has a target-specific dependency table: {table}",
    )
    violation = dependency_violation(dependency_name, dependency_spec)
    require(violation is None, f"{table}.{dependency_name}: {violation}")

for package in SIGNER_LOCK.get("package", []):
    source = package.get("source")
    if source is None:
        continue
    require(
        source == CRATES_IO_SOURCE,
        f"isolated signer lock contains a non-crates.io network source: {package['name']}",
    )
    require(
        isinstance(package.get("checksum"), str),
        f"isolated signer lock lacks a checksum for {package['name']}",
    )

signer_verifier_versions = locked_package_versions(SIGNER_LOCK, "minisign-verify")
product_verifier_versions = locked_package_versions(PRODUCT_LOCK, "minisign-verify")
require(
    len(signer_verifier_versions) == 1,
    "isolated signer must lock exactly one minisign-verify version",
)
require(
    signer_verifier_versions == product_verifier_versions,
    "isolated signer and product verifier resolve different minisign-verify versions",
)
require(
    "minisign_verify::PublicKey::from_base64" in PRODUCT_VERIFIER_TEXT
    and "minisign_verify::Signature::decode" in PRODUCT_VERIFIER_TEXT
    and re.search(
        r"\.verify\(\s*data,\s*&sig,\s*false\s*\)",
        PRODUCT_VERIFIER_TEXT,
        re.DOTALL,
    )
    is not None,
    "product verifier no longer uses the non-legacy minisign-verify contract",
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
