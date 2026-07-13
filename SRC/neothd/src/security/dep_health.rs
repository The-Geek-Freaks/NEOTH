//! GOLD-ADAPT-SNYK-03 / GOLD-ADAPT-SNYK-03b — dependency-health heuristics gate.
//! GOLD-ADAPT-SNYK-02 — manifest-change → scan-before-install gate.
//!
//! Provides a fast, offline typosquatting detector for packages about to be
//! installed via `npm install -g`. The check runs BEFORE the install alongside
//! the OSV malware gate (GOLD-ADAPT-GOOSE-01): that gate catches known-bad
//! packages by advisory ID; this one catches *look-alike* names that attackers
//! register to ride on popular packages' typos (e.g. `expres` → `express`).
//!
//! ## Registry-metadata health check (GOLD-ADAPT-SNYK-03b)
//!
//! `check_registry_health` queries `registry.npmjs.org/<name>` for two signals:
//! - **Deprecated**: the latest-version `deprecated` field is non-empty → the
//!   package maintainer explicitly marked it deprecated (warn, don't block).
//! - **Abandoned**: the latest-version publish time is older than
//!   `ABANDONED_SECS` → likely unmaintained (warn, don't block).
//!
//! Both signals are WARN-only — the same posture as the typosquat heuristic.
//! A registry hiccup (network error / 404 / timeout) fails OPEN so an offline
//! install is never bricked. The pure `parse_registry_health` function is
//! testable without any I/O.
//!
//! ## Manifest scan (GOLD-ADAPT-SNYK-02)
//!
//! `manifest_packages(path)` — pure — parses a `package.json`
//! `dependencies` + `devDependencies` object into a package-name list.
//! `scan_manifest(path, now)` — async — runs each package through all existing
//! gates (OSV severity + typosquat + registry-health) and collects `DepFinding`s.
//! This covers the AI-agent-driven `npm install` from a manifest path, which the
//! per-package wizard gate misses.
//!
//! // neoth: wire `scan_manifest` to a `neoth deps scan <manifest>` CLI subcommand
//! // and/or call it when a manifest-change is detected before a bulk install.
//! // The building block is shipped here; the CLI dispatch lives in cli/deps.rs
//! // (not yet wired — add `Deps(deps::DepsArgs)` to Commands enum + mod deps).
//!
//! ## Distance thresholds
//!
//! | name length | max edit distance |
//! |-------------|-------------------|
//! | < 4 chars   | 0 (exact match only, too short to be informative) |
//! | 4–7 chars   | 1 |
//! | ≥ 8 chars   | 2 |
//!
//! Rationale: short names (`vue`, `npm`) have almost no Levenshtein headroom
//! before every other 3-letter word matches. At 4+ chars, distance 1 is a
//! strong single-transposition/deletion signal. Distance 2 becomes safe to
//! surface only when the name is long enough that two edits leave an
//! unambiguous resemblance.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

/// High-traffic npm packages that are frequent typosquatting targets.
/// Curated to cover the AI-agent-install vector (tools NEOTH auto-installs
/// or that users commonly ask agents to install). Keep sorted for readability;
/// the runtime check is O(n) Levenshtein so order does not affect correctness.
const POPULAR_NPM: &[&str] = &[
    "@angular/cli",
    "@vue/cli",
    "axios",
    "babel-cli",
    "bcrypt",
    "chalk",
    "commander",
    "create-react-app",
    "debug",
    "dotenv",
    "eslint",
    "express",
    "http-server",
    "jest",
    "jsonwebtoken",
    "lodash",
    "minimist",
    "mocha",
    "moment",
    "next",
    "nodemon",
    "npm",
    "prettier",
    "react",
    "react-dom",
    "react-scripts",
    "semver",
    "ts-node",
    "typescript",
    "uuid",
    "vite",
    "vue",
    "webpack",
    "webpack-cli",
    "yarn",
    "zod",
];

// ── Public types ─────────────────────────────────────────────────────────────

/// A package name that appears to be a typosquat of a popular package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TyposquatHit {
    /// The name being installed.
    pub suspect: String,
    /// The popular package it closely resembles.
    pub resembles: String,
    /// Levenshtein edit distance between `suspect` and `resembles`.
    pub distance: usize,
}

impl TyposquatHit {
    /// Human-readable operator warning suitable for a `warn!` log field.
    pub fn describe(&self) -> String {
        format!(
            "`{}` looks like a typosquat of `{}` (edit distance {}) — \
             verify the package name before installing",
            self.suspect, self.resembles, self.distance
        )
    }
}

// ── Manifest scan types (GOLD-ADAPT-SNYK-02) ─────────────────────────────────

/// A security finding for one package in a scanned manifest.
///
/// Collected by [`scan_manifest`] and surfaced to the caller for display /
/// blocking decisions. The caller decides block vs. warn policy per kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DepFinding {
    /// The package name from the manifest.
    pub package: String,
    /// What kind of problem was found.
    pub kind: DepFindingKind,
}

/// Classification of a dependency finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DepFindingKind {
    /// OSV reports one or more CVE/GHSA advisories. Contains the advisory IDs
    /// and the max severity string (e.g. `"Critical"`).
    Vulnerable {
        advisory_ids: Vec<String>,
        max_severity: String,
    },
    /// OSV reports a `MAL-*` advisory — this package is flagged as malware.
    Malware { advisory_ids: Vec<String> },
    /// The package name is suspicious — looks like a typosquat of a popular name.
    PossibleTyposquat { resembles: String, distance: usize },
    /// The package is deprecated or abandoned per the npm registry.
    RegistryIssue { message: String },
}

impl DepFinding {
    /// Single-line human-readable summary suitable for a log line or CLI output.
    pub fn describe(&self) -> String {
        match &self.kind {
            DepFindingKind::Vulnerable {
                advisory_ids,
                max_severity,
            } => format!(
                "`{}` has {} advisory/ies ({}) — max severity: {}",
                self.package,
                advisory_ids.len(),
                advisory_ids.join(", "),
                max_severity
            ),
            DepFindingKind::Malware { advisory_ids } => format!(
                "`{}` is flagged as MALWARE by OSV ({})",
                self.package,
                advisory_ids.join(", ")
            ),
            DepFindingKind::PossibleTyposquat {
                resembles,
                distance,
            } => format!(
                "`{}` looks like a typosquat of `{}` (edit distance {})",
                self.package, resembles, distance
            ),
            DepFindingKind::RegistryIssue { message } => {
                format!("`{}` registry issue: {}", self.package, message)
            }
        }
    }
}

/// Parse a `package.json` manifest at `path` and return the list of package
/// names from `dependencies` + `devDependencies`.
///
/// Pure — reads the file and parses JSON; no network. Returns an empty `Vec`
/// on any I/O or parse error (fail-open posture: a malformed manifest must
/// never break an install flow). Never panics.
pub fn manifest_packages(manifest_path: &Path) -> Vec<String> {
    let content = match std::fs::read_to_string(manifest_path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let doc: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut names = Vec::new();
    for section in &["dependencies", "devDependencies"] {
        if let Some(obj) = doc.get(section).and_then(|v| v.as_object()) {
            for key in obj.keys() {
                if !key.is_empty() {
                    names.push(key.clone());
                }
            }
        }
    }
    names
}

/// Result of the fail-closed manifest scan used by the MCP install gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StrictManifestScan {
    /// Every parsed dependency received a conclusive OSV response and none met
    /// the operator's blocking policy.
    ProvenClean {
        /// SHA-256 of the exact manifest bytes parsed for this scan. Callers
        /// must compare this digest with the file again at authorization time.
        manifest_sha256: String,
        packages_scanned: usize,
        warnings: Vec<String>,
    },
    /// OSV conclusively found malware or an advisory at/above policy.
    Blocked { findings: Vec<String> },
    /// The file could not be fully parsed or at least one OSV lookup was
    /// inconclusive. This is deliberately distinct from clean.
    Unverified { code: StrictScanCode },
}

impl StrictManifestScan {
    pub fn is_proven_clean(&self) -> bool {
        matches!(self, Self::ProvenClean { .. })
    }
}

/// Stable, non-sensitive failure codes for WAL and model feedback. Parser and
/// transport details may contain manifest URLs or credentials and must never
/// cross that boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrictScanCode {
    ManifestReadFailed,
    ManifestDecodeFailed,
    ManifestParseFailed,
    UnsupportedDependencySource,
    UnsupportedManifest,
    NoScannableDependencies,
    MissingExactVersion,
    OsvUnverified,
    OsvResultMismatch,
}

impl StrictScanCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManifestReadFailed => "manifest_read_failed",
            Self::ManifestDecodeFailed => "manifest_decode_failed",
            Self::ManifestParseFailed => "manifest_parse_failed",
            Self::UnsupportedDependencySource => "unsupported_dependency_source",
            Self::UnsupportedManifest => "unsupported_manifest",
            Self::NoScannableDependencies => "no_scannable_dependencies",
            Self::MissingExactVersion => "missing_exact_version",
            Self::OsvUnverified => "osv_unverified",
            Self::OsvResultMismatch => "osv_result_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictPackageQuery {
    pub name: String,
    pub ecosystem: &'static str,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StrictPackageScan {
    ProvenClean {
        packages_scanned: usize,
        warnings: Vec<String>,
    },
    Blocked {
        findings: Vec<String>,
    },
    Unverified {
        code: StrictScanCode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ManifestPackage {
    name: String,
    ecosystem: &'static str,
    version: Option<String>,
}

fn exact_version(spec: &str) -> Option<String> {
    let trimmed = spec.trim().trim_matches(['"', '\'']);
    let candidate = trimmed.strip_prefix("==").unwrap_or(trimmed);
    let numeric = candidate.strip_prefix('v').unwrap_or(candidate);
    let core_end = numeric.find(['-', '+']).unwrap_or(numeric.len());
    let core = &numeric[..core_end];
    let core_segments = core.split('.').collect::<Vec<_>>();
    let exact_numeric_core = core_segments.len() >= 3
        && core_segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()));
    let suffix_is_nonempty = core_end == numeric.len() || core_end + 1 < numeric.len();
    (exact_numeric_core
        && suffix_is_nonempty
        && candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_')))
    .then(|| candidate.to_string())
}

fn exact_pypi_version(spec: &str) -> Option<String> {
    let trimmed = spec.trim().trim_matches(['"', '\'']);
    let candidate = trimmed.strip_prefix("==").unwrap_or(trimmed);
    if candidate.is_empty()
        || candidate.contains(['*', '<', '>', '~', '=', ';', '@', '/', '\\'])
        || candidate.chars().any(char::is_whitespace)
    {
        return None;
    }
    let (epoch, release_and_suffix) = candidate
        .split_once('!')
        .map_or((None, candidate), |(epoch, rest)| (Some(epoch), rest));
    if epoch.is_some_and(|epoch| epoch.is_empty() || !epoch.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    let release_end = release_and_suffix
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(release_and_suffix.len());
    let release = &release_and_suffix[..release_end];
    if release.is_empty()
        || release
            .split('.')
            .any(|segment| segment.is_empty() || !segment.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let suffix = &release_and_suffix[release_end..];
    let normalized_suffix = suffix
        .trim_start_matches(['.', '-', '_'])
        .to_ascii_lowercase();
    let suffix_ok = suffix.is_empty()
        || suffix.starts_with('+') && suffix.len() > 1
        || [
            "a", "b", "rc", "alpha", "beta", "pre", "preview", "post", "rev", "r", "dev",
        ]
        .iter()
        .any(|prefix| normalized_suffix.starts_with(prefix));
    (suffix_ok
        && suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_')))
    .then(|| candidate.to_string())
}

fn dependency_name(spec: &str) -> Option<String> {
    let name: String = spec
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '/' | '_' | '-' | '.'))
        .collect();
    (!name.is_empty()).then_some(name)
}

fn toml_dependency_table(
    table: &toml::value::Table,
    ecosystem: &'static str,
    out: &mut std::collections::BTreeSet<ManifestPackage>,
) -> Result<(), String> {
    for (alias, value) in table {
        if let Some(spec) = value.as_table() {
            let non_registry = [
                "git", "path", "url", "file", "source", "branch", "rev", "tag", "registry",
            ]
            .iter()
            .any(|key| spec.contains_key(*key));
            let inherited_workspace = spec
                .get("workspace")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            if non_registry || inherited_workspace {
                return Err("unsupported_dependency_source".to_string());
            }
        }
        let actual_name = value
            .as_table()
            .and_then(|t| t.get("package"))
            .and_then(toml::Value::as_str)
            .unwrap_or(alias);
        // Cargo's plain `1.2` means a semver range, not one exact release;
        // querying OSV with it as a concrete version could produce a false
        // clean. Only Pipfile's explicit `==x.y.z` is safe to pin here.
        let version = (ecosystem == "PyPI")
            .then(|| {
                value.as_str().or_else(|| {
                    value
                        .as_table()
                        .and_then(|t| t.get("version"))
                        .and_then(toml::Value::as_str)
                })
            })
            .flatten()
            .filter(|spec| spec.trim().starts_with("=="))
            .and_then(exact_pypi_version);
        out.insert(ManifestPackage {
            name: actual_name.to_string(),
            ecosystem,
            version,
        });
    }
    Ok(())
}

fn valid_registry_package_name(name: &str) -> bool {
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    };
    if let Some(scoped) = name.strip_prefix('@') {
        let Some((scope, package)) = scoped.split_once('/') else {
            return false;
        };
        !package.contains('/') && valid_segment(scope) && valid_segment(package)
    } else {
        !name.contains(['@', '/']) && valid_segment(name)
    }
}

fn valid_subresource_integrity(value: &str) -> bool {
    !value.is_empty()
        && value.split_whitespace().all(|digest| {
            let Some((algorithm, encoded)) = digest.split_once('-') else {
                return false;
            };
            matches!(algorithm, "sha1" | "sha256" | "sha384" | "sha512")
                && !encoded.is_empty()
                && encoded
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        })
}

fn canonical_npm_tarball(
    resolved: &str,
    package: &str,
    version: &str,
    allow_yarn_registry: bool,
) -> bool {
    let Ok(url) = url::Url::parse(resolved) else {
        return false;
    };
    let host_is_canonical = url.host_str() == Some("registry.npmjs.org")
        || allow_yarn_registry && url.host_str() == Some("registry.yarnpkg.com");
    let fragment_is_valid = match url.fragment() {
        None => true,
        Some(fragment) if allow_yarn_registry => {
            fragment.len() == 40 && fragment.chars().all(|c| c.is_ascii_hexdigit())
        }
        Some(_) => false,
    };
    let normalized_path = url
        .path()
        .to_ascii_lowercase()
        .replace("%2f", "/")
        .replace("%40", "@");
    let package = package.to_ascii_lowercase();
    let version = version.to_ascii_lowercase();
    let leaf = package.rsplit('/').next().unwrap_or(package.as_str());
    let expected_prefix = format!("/{package}/-/");
    let expected_file = format!("{leaf}-{version}.tgz");
    url.scheme() == "https"
        && host_is_canonical
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && fragment_is_valid
        && normalized_path.starts_with(&expected_prefix)
        && normalized_path.rsplit('/').next() == Some(expected_file.as_str())
}

fn npm_locked_package(
    fallback_name: &str,
    metadata: &serde_json::Map<String, serde_json::Value>,
) -> Result<ManifestPackage, String> {
    if metadata.contains_key("link") {
        return Err("unsupported_dependency_source".to_string());
    }
    let package = match metadata.get("name") {
        None => fallback_name,
        Some(serde_json::Value::String(name)) => name,
        Some(_) => return Err("npm lock package name is not a string".to_string()),
    };
    if !valid_registry_package_name(package) {
        return Err("npm lock package has an invalid registry name".to_string());
    }
    let version = metadata
        .get("version")
        .and_then(serde_json::Value::as_str)
        .and_then(exact_version)
        .ok_or_else(|| format!("npm lock dependency `{package}` has no exact version"))?;
    if let Some(resolved) = metadata.get("resolved") {
        let resolved = resolved
            .as_str()
            .ok_or_else(|| format!("npm lock dependency `{package}` has a non-string source"))?;
        if !canonical_npm_tarball(resolved, package, &version, false) {
            return Err("unsupported_dependency_source".to_string());
        }
    }
    let integrity = metadata
        .get("integrity")
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_subresource_integrity(value))
        .ok_or_else(|| format!("npm lock dependency `{package}` has no valid integrity"))?;
    debug_assert!(!integrity.is_empty());
    Ok(ManifestPackage {
        name: package.to_string(),
        ecosystem: "npm",
        version: Some(version),
    })
}

fn collect_npm_lock_tree(
    table: &serde_json::Map<String, serde_json::Value>,
    out: &mut std::collections::BTreeSet<ManifestPackage>,
) -> Result<(), String> {
    for (package, metadata) in table {
        if package.is_empty() {
            return Err("npm lock dependency has an empty package name".to_string());
        }
        let metadata = metadata
            .as_object()
            .ok_or_else(|| format!("npm lock metadata for `{package}` is not an object"))?;
        out.insert(npm_locked_package(package, metadata)?);
        if let Some(nested) = metadata.get("dependencies") {
            let nested = nested.as_object().ok_or_else(|| {
                format!("npm lock nested dependencies for `{package}` are not an object")
            })?;
            collect_npm_lock_tree(nested, out)?;
        }
    }
    Ok(())
}

fn npm_manifest_package(alias: &str, spec: &str) -> Result<Option<ManifestPackage>, String> {
    let spec = spec.trim();
    if ["file:", "link:", "workspace:"]
        .iter()
        .any(|p| spec.starts_with(p))
    {
        return Err("unsupported_dependency_source".to_string());
    }
    if spec.contains("://") || spec.starts_with("git+") || spec.starts_with("github:") {
        return Err("unsupported_dependency_source".to_string());
    }
    if let Some(target) = spec.strip_prefix("npm:") {
        let split_at = target
            .rfind('@')
            .filter(|index| *index > 0)
            .unwrap_or(target.len());
        let name = &target[..split_at];
        if !valid_registry_package_name(name) {
            return Err(format!("npm alias `{alias}` has no target package"));
        }
        let version = (split_at < target.len())
            .then(|| &target[split_at + 1..])
            .and_then(exact_version);
        return Ok(Some(ManifestPackage {
            name: name.to_string(),
            ecosystem: "npm",
            version,
        }));
    }
    if !valid_registry_package_name(alias) {
        return Err(format!(
            "npm dependency `{alias}` has an invalid registry name"
        ));
    }
    Ok(Some(ManifestPackage {
        name: alias.to_string(),
        ecosystem: "npm",
        version: exact_version(spec),
    }))
}

fn pnpm_lock_package(raw: &str) -> Result<ManifestPackage, String> {
    let normalized = raw
        .trim()
        .trim_start_matches('/')
        .split('(')
        .next()
        .unwrap_or("");
    if normalized.is_empty() {
        return Err("pnpm lock has an empty package key".to_string());
    }
    if let Some((name, version)) = normalized.rsplit_once('/') {
        let version = version.split('_').next().and_then(exact_version);
        if valid_registry_package_name(name) && version.is_some() {
            return Ok(ManifestPackage {
                name: name.to_string(),
                ecosystem: "npm",
                version,
            });
        }
    }
    let split_at = normalized
        .rfind('@')
        .filter(|index| *index > 0)
        .ok_or_else(|| format!("pnpm lock package `{raw}` has no exact version separator"))?;
    let name = &normalized[..split_at];
    let version = normalized[split_at + 1..]
        .split('_')
        .next()
        .and_then(exact_version);
    if !valid_registry_package_name(name) || version.is_none() {
        return Err(format!("pnpm lock package `{raw}` has no exact version"));
    }
    Ok(ManifestPackage {
        name: name.to_string(),
        ecosystem: "npm",
        version,
    })
}

fn pnpm_exact_version(raw: &str) -> Option<String> {
    raw.split('(')
        .next()
        .unwrap_or(raw)
        .split('_')
        .next()
        .and_then(exact_version)
}

fn validate_pnpm_lock_metadata(
    package: &ManifestPackage,
    metadata: &serde_yaml::Value,
) -> Result<(), String> {
    let metadata = metadata.as_mapping().ok_or_else(|| {
        format!(
            "pnpm lock package `{}` metadata is not a mapping",
            package.name
        )
    })?;
    let resolution = metadata
        .get(serde_yaml::Value::from("resolution"))
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or_else(|| format!("pnpm lock package `{}` has no resolution", package.name))?;
    for key in resolution.keys() {
        let Some(key) = key.as_str() else {
            return Err("unsupported_dependency_source".to_string());
        };
        if !matches!(key, "integrity" | "tarball") {
            return Err("unsupported_dependency_source".to_string());
        }
    }
    let integrity = resolution
        .get(serde_yaml::Value::from("integrity"))
        .and_then(serde_yaml::Value::as_str)
        .filter(|value| valid_subresource_integrity(value))
        .ok_or_else(|| {
            format!(
                "pnpm lock package `{}` has no valid integrity",
                package.name
            )
        })?;
    debug_assert!(!integrity.is_empty());
    if let Some(tarball) = resolution.get(serde_yaml::Value::from("tarball")) {
        let tarball = tarball
            .as_str()
            .ok_or_else(|| "unsupported_dependency_source".to_string())?;
        let version = package
            .version
            .as_deref()
            .ok_or_else(|| format!("pnpm lock package `{}` has no exact version", package.name))?;
        if !canonical_npm_tarball(tarball, &package.name, version, false) {
            return Err("unsupported_dependency_source".to_string());
        }
    }
    Ok(())
}

fn is_official_pypi_url(raw: &str) -> bool {
    url::Url::parse(raw).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some("pypi.org")
            && url.port().is_none()
            && url.path().trim_end_matches('/') == "/simple"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn pypi_lock_source_is_official(source: Option<&toml::Value>) -> bool {
    let Some(source) = source else {
        return true;
    };
    source.as_table().is_some_and(|table| {
        table.len() == 1
            && table
                .get("registry")
                .or_else(|| table.get("url"))
                .and_then(toml::Value::as_str)
                .is_some_and(is_official_pypi_url)
    })
}

#[derive(Default)]
struct YarnLockEntry {
    packages: Vec<String>,
    version: Option<String>,
    berry: bool,
    metadata_only: bool,
    resolved: Option<String>,
    integrity: Option<String>,
    resolution: Option<String>,
    checksum: Option<String>,
}

fn yarn_npm_descriptor(selector: &str) -> Result<(String, bool), String> {
    if selector == "__metadata" {
        return Ok((String::new(), false));
    }
    if [
        "file:",
        "link:",
        "workspace:",
        "patch:",
        "git+",
        "@exec:",
        "@http:",
        "@https:",
    ]
    .iter()
    .any(|protocol| selector.contains(protocol))
    {
        return Err("unsupported_dependency_source".to_string());
    }
    let registry_descriptor = |range: &str| {
        !range.is_empty()
            && !range.contains(['@', '/', '\\', ':'])
            && !range.chars().any(char::is_whitespace)
    };
    if let Some((package, range)) = selector.split_once("@npm:") {
        if !registry_descriptor(range) || !valid_registry_package_name(package) {
            return Err("unsupported_dependency_source".to_string());
        }
        return Ok((package.to_string(), true));
    }
    if let Some((package, range)) = selector
        .split_once("@virtual:")
        .and_then(|(package, rest)| rest.rsplit_once("#npm:").map(|(_, range)| (package, range)))
    {
        if !registry_descriptor(range) || !valid_registry_package_name(package) {
            return Err("unsupported_dependency_source".to_string());
        }
        return Ok((package.to_string(), true));
    }
    let split_at = selector.rfind('@').filter(|idx| *idx > 0);
    let package = split_at.map(|idx| &selector[..idx]).unwrap_or(selector);
    if !valid_registry_package_name(package) {
        return Err("yarn lock selector has an invalid package name".to_string());
    }
    Ok((package.to_string(), false))
}

fn yarn_resolution_coordinate(resolution: &str) -> Option<(&str, String)> {
    if let Some((package, version)) = resolution.rsplit_once("@npm:") {
        return exact_version(version).map(|version| (package, version));
    }
    let (package, rest) = resolution.split_once("@virtual:")?;
    let (_, version) = rest.rsplit_once("#npm:")?;
    exact_version(version).map(|version| (package, version))
}

fn finish_yarn_lock_entry(
    entry: YarnLockEntry,
    path: &Path,
    packages: &mut std::collections::BTreeSet<ManifestPackage>,
) -> Result<(), String> {
    if entry.metadata_only {
        return Ok(());
    }
    if entry.packages.is_empty() {
        return Err(format!(
            "{} contains an empty yarn selector",
            path.display()
        ));
    }
    let version = entry.version.ok_or_else(|| {
        format!(
            "{} dependency has no exact version metadata",
            path.display()
        )
    })?;
    if entry.berry {
        let resolution = entry
            .resolution
            .as_deref()
            .and_then(yarn_resolution_coordinate)
            .ok_or_else(|| "unsupported_dependency_source".to_string())?;
        if resolution.1 != version || entry.packages.iter().any(|package| package != resolution.0) {
            return Err("unsupported_dependency_source".to_string());
        }
        let checksum = entry
            .checksum
            .as_deref()
            .filter(|checksum| {
                !checksum.is_empty()
                    && checksum.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, '/' | '+' | '=' | '-' | '_')
                    })
            })
            .ok_or_else(|| format!("{} berry dependency has no checksum", path.display()))?;
        debug_assert!(!checksum.is_empty());
    } else {
        let resolved = entry
            .resolved
            .as_deref()
            .ok_or_else(|| format!("{} classic yarn dependency has no source", path.display()))?;
        if entry
            .packages
            .iter()
            .any(|package| !canonical_npm_tarball(resolved, package, &version, true))
        {
            return Err("unsupported_dependency_source".to_string());
        }
        entry
            .integrity
            .as_deref()
            .filter(|value| valid_subresource_integrity(value))
            .ok_or_else(|| {
                format!(
                    "{} classic yarn dependency has no valid integrity",
                    path.display()
                )
            })?;
    }
    for package in entry.packages {
        packages.insert(ManifestPackage {
            name: package,
            ecosystem: "npm",
            version: Some(version.clone()),
        });
    }
    Ok(())
}

fn parse_yarn_lock(
    body: &str,
    path: &Path,
    packages: &mut std::collections::BTreeSet<ManifestPackage>,
) -> Result<(), String> {
    let mut current: Option<YarnLockEntry> = None;
    for raw in body.lines() {
        if raw.trim().is_empty() || raw.starts_with('#') {
            continue;
        }
        if !raw.chars().next().is_some_and(char::is_whitespace) {
            if let Some(entry) = current.take() {
                finish_yarn_lock_entry(entry, path, packages)?;
            }
            let selectors = raw
                .trim()
                .strip_suffix(':')
                .ok_or_else(|| format!("{} contains a malformed selector", path.display()))?;
            let mut entry = YarnLockEntry::default();
            for selector in selectors.split(',') {
                let selector = selector.trim().trim_matches('"');
                let (package, berry) = yarn_npm_descriptor(selector)?;
                if package.is_empty() {
                    entry.metadata_only = true;
                } else {
                    entry.berry |= berry;
                    entry.packages.push(package);
                }
            }
            if entry.metadata_only && !entry.packages.is_empty() {
                return Err(format!(
                    "{} mixes yarn metadata and package selectors",
                    path.display()
                ));
            }
            entry.packages.sort();
            entry.packages.dedup();
            current = Some(entry);
            continue;
        }
        let entry = current
            .as_mut()
            .ok_or_else(|| format!("{} metadata appears before a selector", path.display()))?;
        let metadata = raw.trim();
        if let Some(value) = metadata
            .strip_prefix("version ")
            .or_else(|| metadata.strip_prefix("version:"))
        {
            entry.version = exact_version(value.trim().trim_matches(['"', '\'']));
        } else if let Some(value) = metadata.strip_prefix("resolved ") {
            entry.resolved = Some(value.trim().trim_matches(['"', '\'']).to_string());
        } else if let Some(value) = metadata.strip_prefix("integrity ") {
            entry.integrity = Some(value.trim().trim_matches(['"', '\'']).to_string());
        } else if let Some(value) = metadata.strip_prefix("resolution:") {
            entry.resolution = Some(value.trim().trim_matches(['"', '\'']).to_string());
        } else if let Some(value) = metadata.strip_prefix("checksum:") {
            entry.checksum = Some(value.trim().trim_matches(['"', '\'']).to_string());
        }
    }
    if let Some(entry) = current {
        finish_yarn_lock_entry(entry, path, packages)?;
    }
    Ok(())
}

#[cfg(test)]
fn parse_manifest_strict(path: &Path) -> Result<Vec<ManifestPackage>, String> {
    let body =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_manifest_body_strict(path, &body)
}

/// Validate that a resolver input is parseable and contains no non-registry
/// dependency source. Version ranges are permitted here because the exact
/// transitive versions are proven separately from an immutable lockfile.
pub fn validate_resolution_source_manifest(path: &Path) -> Result<(), String> {
    let body =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_manifest_body_strict(path, &body).map(|_| ())
}

fn parse_manifest_body_strict(path: &Path, body: &str) -> Result<Vec<ManifestPackage>, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("manifest path has no UTF-8 filename: {}", path.display()))?;
    let mut packages = std::collections::BTreeSet::new();

    match name {
        "package.json" | "package-lock.json" | "npm-shrinkwrap.json" | "Pipfile.lock" => {
            let doc: serde_json::Value =
                serde_json::from_str(body).map_err(|e| format!("parse {}: {e}", path.display()))?;
            if name == "package.json" {
                if doc.get("workspaces").is_some() {
                    return Err("unsupported_dependency_source".to_string());
                }
                for section in [
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ] {
                    if let Some(value) = doc.get(section) {
                        let table = value.as_object().ok_or_else(|| {
                            format!("{} `{section}` is not an object", path.display())
                        })?;
                        for (package, spec) in table {
                            let spec = spec.as_str().ok_or_else(|| {
                                format!("{} `{section}.{package}` is not a string", path.display())
                            })?;
                            if let Some(package) = npm_manifest_package(package, spec)? {
                                packages.insert(package);
                            }
                        }
                    }
                }
            } else if matches!(name, "package-lock.json" | "npm-shrinkwrap.json") {
                if let Some(value) = doc.get("packages") {
                    let table = value
                        .as_object()
                        .ok_or_else(|| format!("{} `packages` is not an object", path.display()))?;
                    for (package_path, metadata) in table {
                        let Some((_, package)) = package_path.rsplit_once("node_modules/") else {
                            continue;
                        };
                        let metadata = metadata.as_object().ok_or_else(|| {
                            format!(
                                "{} package `{package}` metadata is not an object",
                                path.display()
                            )
                        })?;
                        packages.insert(npm_locked_package(package, metadata)?);
                    }
                } else if let Some(value) = doc.get("dependencies") {
                    let table = value.as_object().ok_or_else(|| {
                        format!("{} `dependencies` is not an object", path.display())
                    })?;
                    collect_npm_lock_tree(table, &mut packages)?;
                } else {
                    return Err(format!(
                        "{} has neither `packages` nor `dependencies`",
                        path.display()
                    ));
                }
            } else {
                let mut saw_dependency_section = false;
                for section in ["default", "develop"] {
                    if let Some(value) = doc.get(section) {
                        saw_dependency_section = true;
                        let table = value.as_object().ok_or_else(|| {
                            format!("{} `{section}` is not an object", path.display())
                        })?;
                        for (package, metadata) in table {
                            if ["git", "path", "file", "uri"]
                                .iter()
                                .any(|key| metadata.get(*key).is_some())
                            {
                                return Err("unsupported_dependency_source".to_string());
                            }
                            let version = metadata
                                .get("version")
                                .and_then(serde_json::Value::as_str)
                                .and_then(exact_pypi_version)
                                .ok_or_else(|| {
                                    format!(
                                        "{} locked package `{package}` has no exact version",
                                        path.display()
                                    )
                                })?;
                            packages.insert(ManifestPackage {
                                name: package.clone(),
                                ecosystem: "PyPI",
                                version: Some(version),
                            });
                        }
                    }
                }
                if !saw_dependency_section {
                    return Err(format!(
                        "{} has neither `default` nor `develop`",
                        path.display()
                    ));
                }
            }
        }
        "Cargo.toml" | "Cargo.lock" | "pyproject.toml" | "Pipfile" | "poetry.lock" | "uv.lock" => {
            let doc: toml::Value =
                toml::from_str(body).map_err(|e| format!("parse {}: {e}", path.display()))?;
            if matches!(name, "Cargo.lock" | "poetry.lock" | "uv.lock") {
                let entries = doc
                    .get("package")
                    .and_then(toml::Value::as_array)
                    .ok_or_else(|| format!("{} has no `package` array", path.display()))?;
                let cargo_root = if name == "Cargo.lock" {
                    let manifest = path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join("Cargo.toml");
                    std::fs::read_to_string(manifest)
                        .ok()
                        .and_then(|body| toml::from_str::<toml::Value>(&body).ok())
                        .and_then(|manifest| {
                            let package = manifest.get("package")?;
                            Some((
                                package.get("name")?.as_str()?.to_string(),
                                exact_version(package.get("version")?.as_str()?)?,
                            ))
                        })
                } else {
                    None
                };
                let pypi_root = if name != "Cargo.lock" {
                    let manifest = path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join("pyproject.toml");
                    std::fs::read_to_string(manifest)
                        .ok()
                        .and_then(|body| toml::from_str::<toml::Value>(&body).ok())
                        .and_then(|manifest| {
                            let project = manifest.get("project").or_else(|| {
                                manifest.get("tool").and_then(|tool| tool.get("poetry"))
                            })?;
                            Some((
                                project.get("name")?.as_str()?.to_string(),
                                exact_pypi_version(project.get("version")?.as_str()?)?,
                            ))
                        })
                } else {
                    None
                };
                for entry in entries {
                    let table = entry.as_table().ok_or_else(|| {
                        format!("{} contains a non-table package entry", path.display())
                    })?;
                    let package = table
                        .get("name")
                        .and_then(toml::Value::as_str)
                        .ok_or_else(|| format!("{} package has no name", path.display()))?;
                    let version_parser: fn(&str) -> Option<String> = if name == "Cargo.lock" {
                        exact_version
                    } else {
                        exact_pypi_version
                    };
                    let version = table
                        .get("version")
                        .and_then(toml::Value::as_str)
                        .and_then(version_parser)
                        .ok_or_else(|| {
                            format!(
                                "{} package `{package}` has no exact version",
                                path.display()
                            )
                        })?;
                    if name == "Cargo.lock" {
                        match table.get("source") {
                            Some(toml::Value::String(source))
                                if matches!(
                                    source.as_str(),
                                    "registry+https://github.com/rust-lang/crates.io-index"
                                        | "sparse+https://index.crates.io/"
                                ) =>
                            {
                                if table
                                    .get("checksum")
                                    .and_then(toml::Value::as_str)
                                    .is_none()
                                {
                                    return Err(format!(
                                        "{} registry package `{package}` has no checksum",
                                        path.display()
                                    ));
                                }
                            }
                            None if cargo_root
                                .as_ref()
                                .is_some_and(|root| root.0 == package && root.1 == version) =>
                            {
                                continue;
                            }
                            _ => return Err("unsupported_dependency_source".to_string()),
                        }
                    } else if !pypi_lock_source_is_official(table.get("source")) {
                        let local_root = pypi_root
                            .as_ref()
                            .is_some_and(|root| root.0 == package && root.1 == version)
                            && table
                                .get("source")
                                .and_then(toml::Value::as_table)
                                .is_some_and(|source| {
                                    ["editable", "virtual", "path"].iter().any(|key| {
                                        source.get(*key).and_then(toml::Value::as_str) == Some(".")
                                    })
                                });
                        if local_root {
                            continue;
                        }
                        return Err("unsupported_dependency_source".to_string());
                    }
                    packages.insert(ManifestPackage {
                        name: package.to_string(),
                        ecosystem: if name == "Cargo.lock" {
                            "crates.io"
                        } else {
                            "PyPI"
                        },
                        version: Some(version),
                    });
                }
            } else if name == "Cargo.toml" {
                if doc.get("source").is_some() || doc.get("registries").is_some() {
                    return Err("unsupported_dependency_source".to_string());
                }
                for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(table) = doc.get(section).and_then(toml::Value::as_table) {
                        toml_dependency_table(table, "crates.io", &mut packages)?;
                    }
                }
                if let Some(workspace) = doc.get("workspace").and_then(toml::Value::as_table) {
                    if workspace
                        .get("members")
                        .and_then(toml::Value::as_array)
                        .is_some_and(|members| !members.is_empty())
                    {
                        return Err("unsupported_dependency_source".to_string());
                    }
                    if let Some(table) = workspace
                        .get("dependencies")
                        .and_then(toml::Value::as_table)
                    {
                        toml_dependency_table(table, "crates.io", &mut packages)?;
                    }
                }
                if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
                    for target in targets.values().filter_map(toml::Value::as_table) {
                        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                            if let Some(table) = target.get(section).and_then(toml::Value::as_table)
                            {
                                toml_dependency_table(table, "crates.io", &mut packages)?;
                            }
                        }
                    }
                }
                if let Some(patches) = doc.get("patch").and_then(toml::Value::as_table) {
                    for registry in patches.values().filter_map(toml::Value::as_table) {
                        toml_dependency_table(registry, "crates.io", &mut packages)?;
                    }
                }
            } else if name == "pyproject.toml" {
                if doc
                    .get("tool")
                    .and_then(|tool| tool.get("poetry"))
                    .is_some_and(|poetry| poetry.get("source").is_some())
                    || doc
                        .get("tool")
                        .and_then(|tool| tool.get("uv"))
                        .is_some_and(|uv| {
                            [
                                "sources",
                                "index",
                                "extra-index-url",
                                "index-url",
                                "workspace",
                            ]
                            .iter()
                            .any(|key| uv.get(*key).is_some())
                        })
                    || doc.get("tool").and_then(|tool| tool.get("pip")).is_some()
                {
                    return Err("unsupported_dependency_source".to_string());
                }
                if doc
                    .get("project")
                    .and_then(|project| project.get("dynamic"))
                    .and_then(toml::Value::as_array)
                    .is_some_and(|dynamic| {
                        dynamic.iter().filter_map(toml::Value::as_str).any(|field| {
                            field == "dependencies" || field == "optional-dependencies"
                        })
                    })
                {
                    return Err("unsupported_dependency_source".to_string());
                }
                if let Some(entries) = doc
                    .get("project")
                    .and_then(|v| v.get("dependencies"))
                    .and_then(toml::Value::as_array)
                {
                    for spec in entries.iter().filter_map(toml::Value::as_str) {
                        if spec.contains(" @ ") || spec.contains("://") || spec.contains("git+") {
                            return Err("unsupported_dependency_source".to_string());
                        }
                        if let Some(package) = dependency_name(spec) {
                            packages.insert(ManifestPackage {
                                name: package,
                                ecosystem: "PyPI",
                                version: None,
                            });
                        }
                    }
                }
                if let Some(optional) = doc
                    .get("project")
                    .and_then(|v| v.get("optional-dependencies"))
                    .and_then(toml::Value::as_table)
                {
                    for entries in optional.values().filter_map(toml::Value::as_array) {
                        for spec in entries.iter().filter_map(toml::Value::as_str) {
                            if spec.contains(" @ ") || spec.contains("://") || spec.contains("git+")
                            {
                                return Err("unsupported_dependency_source".to_string());
                            }
                            if let Some(package) = dependency_name(spec) {
                                packages.insert(ManifestPackage {
                                    name: package,
                                    ecosystem: "PyPI",
                                    version: None,
                                });
                            }
                        }
                    }
                }
                if let Some(build_requires) = doc
                    .get("build-system")
                    .and_then(|v| v.get("requires"))
                    .and_then(toml::Value::as_array)
                {
                    for spec in build_requires.iter().filter_map(toml::Value::as_str) {
                        if spec.contains(" @ ") || spec.contains("://") || spec.contains("git+") {
                            return Err("unsupported_dependency_source".to_string());
                        }
                        if let Some(package) = dependency_name(spec) {
                            packages.insert(ManifestPackage {
                                name: package,
                                ecosystem: "PyPI",
                                version: spec
                                    .split_once("==")
                                    .and_then(|(_, v)| exact_pypi_version(v)),
                            });
                        }
                    }
                }
                if let Some(groups) = doc.get("dependency-groups").and_then(toml::Value::as_table) {
                    for entries in groups.values().filter_map(toml::Value::as_array) {
                        for spec in entries.iter().filter_map(toml::Value::as_str) {
                            if spec.contains(" @ ") || spec.contains("://") || spec.contains("git+")
                            {
                                return Err("unsupported_dependency_source".to_string());
                            }
                            if let Some(package) = dependency_name(spec) {
                                packages.insert(ManifestPackage {
                                    name: package,
                                    ecosystem: "PyPI",
                                    version: spec
                                        .split_once("==")
                                        .and_then(|(_, v)| exact_pypi_version(v)),
                                });
                            }
                        }
                    }
                }
                if let Some(poetry) = doc
                    .get("tool")
                    .and_then(|v| v.get("poetry"))
                    .and_then(|v| v.get("dependencies"))
                    .and_then(toml::Value::as_table)
                {
                    for (package, spec) in poetry {
                        if package != "python" {
                            if spec.as_table().is_some_and(|table| {
                                ["git", "path", "url", "source"]
                                    .iter()
                                    .any(|key| table.contains_key(*key))
                            }) {
                                return Err("unsupported_dependency_source".to_string());
                            }
                            packages.insert(ManifestPackage {
                                name: package.clone(),
                                ecosystem: "PyPI",
                                version: spec.as_str().and_then(exact_pypi_version),
                            });
                        }
                    }
                }
                if let Some(poetry) = doc.get("tool").and_then(|v| v.get("poetry")) {
                    if let Some(table) = poetry
                        .get("dev-dependencies")
                        .and_then(toml::Value::as_table)
                    {
                        toml_dependency_table(table, "PyPI", &mut packages)?;
                    }
                    if let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) {
                        for group in groups.values().filter_map(toml::Value::as_table) {
                            if let Some(table) =
                                group.get("dependencies").and_then(toml::Value::as_table)
                            {
                                toml_dependency_table(table, "PyPI", &mut packages)?;
                            }
                        }
                    }
                }
            } else {
                for section in ["packages", "dev-packages"] {
                    if let Some(table) = doc.get(section).and_then(toml::Value::as_table) {
                        toml_dependency_table(table, "PyPI", &mut packages)?;
                    }
                }
            }
        }
        "requirements.txt" => {
            for (line_no, raw) in body.lines().enumerate() {
                let line = raw.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                if line.starts_with('-') || line.contains("git+") || line.contains("://") {
                    return Err("unsupported_dependency_source".to_string());
                }
                let package = dependency_name(line).ok_or_else(|| {
                    format!(
                        "{}:{} has no parseable package name",
                        path.display(),
                        line_no + 1
                    )
                })?;
                packages.insert(ManifestPackage {
                    name: package,
                    ecosystem: "PyPI",
                    version: line
                        .split_once("==")
                        .and_then(|(_, v)| exact_pypi_version(v)),
                });
            }
        }
        "pnpm-lock.yaml" => {
            let doc: serde_yaml::Value =
                serde_yaml::from_str(body).map_err(|e| format!("parse {}: {e}", path.display()))?;
            let root = doc
                .as_mapping()
                .ok_or_else(|| format!("{} root is not a YAML mapping", path.display()))?;
            let mut resolved_package_count = 0usize;
            if let Some(value) = root.get(serde_yaml::Value::from("packages")) {
                let entries = value.as_mapping().ok_or_else(|| {
                    format!("{} `packages` is not a YAML mapping", path.display())
                })?;
                for (raw, metadata) in entries {
                    let raw = raw.as_str().ok_or_else(|| {
                        format!("{} has a non-string package key", path.display())
                    })?;
                    let package = pnpm_lock_package(raw)?;
                    validate_pnpm_lock_metadata(&package, metadata)?;
                    packages.insert(package);
                    resolved_package_count += 1;
                }
            }
            let mut importer_dependency_count = 0usize;
            if let Some(value) = root.get(serde_yaml::Value::from("importers")) {
                let importers = value.as_mapping().ok_or_else(|| {
                    format!("{} `importers` is not a YAML mapping", path.display())
                })?;
                for importer in importers.values().filter_map(serde_yaml::Value::as_mapping) {
                    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
                        let Some(entries) = importer
                            .get(serde_yaml::Value::from(section))
                            .and_then(serde_yaml::Value::as_mapping)
                        else {
                            continue;
                        };
                        for (name, metadata) in entries {
                            importer_dependency_count += 1;
                            let name = name.as_str().ok_or_else(|| {
                                format!("{} has a non-string importer dependency", path.display())
                            })?;
                            let version_spec = metadata.as_str().or_else(|| {
                                metadata
                                    .as_mapping()
                                    .and_then(|mapping| {
                                        mapping.get(serde_yaml::Value::from("version"))
                                    })
                                    .and_then(serde_yaml::Value::as_str)
                            });
                            if version_spec.is_some_and(|version| {
                                ["link:", "file:", "workspace:"]
                                    .iter()
                                    .any(|prefix| version.starts_with(prefix))
                            }) {
                                return Err("unsupported_dependency_source".to_string());
                            }
                            let version =
                                version_spec.and_then(pnpm_exact_version).ok_or_else(|| {
                                    format!(
                                        "{} importer dependency `{name}` has no exact version",
                                        path.display()
                                    )
                                })?;
                            packages.insert(ManifestPackage {
                                name: name.to_string(),
                                ecosystem: "npm",
                                version: Some(version),
                            });
                        }
                    }
                }
            }
            if importer_dependency_count > 0 && resolved_package_count == 0 {
                return Err(format!(
                    "{} has importer dependencies but no resolved packages",
                    path.display()
                ));
            }
            if !root.contains_key(serde_yaml::Value::from("packages"))
                && !root.contains_key(serde_yaml::Value::from("importers"))
            {
                return Err(format!(
                    "{} has neither `packages` nor `importers`",
                    path.display()
                ));
            }
        }
        "go.mod" | "go.sum" => {
            let mut in_require_block = false;
            for raw in body.lines() {
                let line = raw.split("//").next().unwrap_or("").trim();
                if name == "go.mod" {
                    if line.starts_with("replace ") || line == "replace (" {
                        return Err("unsupported_dependency_source".to_string());
                    }
                    if line == "require (" {
                        in_require_block = true;
                        continue;
                    }
                    if in_require_block && line == ")" {
                        in_require_block = false;
                        continue;
                    }
                }
                let dependency = if name == "go.sum" || in_require_block {
                    line
                } else {
                    line.strip_prefix("require ").unwrap_or("")
                };
                if dependency.is_empty() {
                    continue;
                }
                let mut parts = dependency.split_whitespace();
                let (Some(package), Some(version)) = (parts.next(), parts.next()) else {
                    if name == "go.sum" {
                        return Err(format!("{} contains a malformed entry", path.display()));
                    }
                    continue;
                };
                let version =
                    exact_version(version.trim_end_matches("/go.mod")).ok_or_else(|| {
                        format!(
                            "{} package `{package}` has no exact version",
                            path.display()
                        )
                    })?;
                packages.insert(ManifestPackage {
                    name: package.to_string(),
                    ecosystem: "Go",
                    version: Some(version),
                });
            }
        }
        "yarn.lock" => {
            parse_yarn_lock(body, path, &mut packages)?;
        }
        other => return Err(format!("unsupported dependency manifest `{other}`")),
    }

    Ok(packages.into_iter().collect())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// SHA-256 of the current on-disk manifest bytes. Used by the MCP install
/// inspector to bind an allow decision to the exact snapshot OSV inspected.
pub fn manifest_sha256(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|e| format!("read {} for digest: {e}", path.display()))
}

fn classify_strict_verdict(
    package: &ManifestPackage,
    verdict: crate::security::osv_check::OsvVerdict,
    block_threshold: crate::security::osv_check::SeverityLevel,
) -> Result<Option<String>, StrictScanCode> {
    use crate::security::osv_check::{OsvVerdict, SeverityLevel};
    match verdict {
        OsvVerdict::Clean => Ok(None),
        OsvVerdict::Unknown { .. } => Err(StrictScanCode::OsvUnverified),
        OsvVerdict::Malicious { advisories } => Ok(Some(format!(
            "{} is OSV-flagged malware ({})",
            package.name,
            advisories.join(", ")
        ))),
        OsvVerdict::Vulnerable {
            advisories,
            max_severity,
        } => {
            let ids = advisories
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            if block_threshold != SeverityLevel::None && max_severity == SeverityLevel::None {
                return Err(StrictScanCode::OsvUnverified);
            }
            if block_threshold != SeverityLevel::None && max_severity >= block_threshold {
                Ok(Some(format!(
                    "{} has {max_severity:?} OSV advisories ({ids}); policy threshold is \
                     {block_threshold:?}",
                    package.name
                )))
            } else {
                Ok(None)
            }
        }
    }
}

/// Fail-closed OSV scan for a dependency manifest immediately before an
/// agent-requested install. Unlike the operator-facing report scanner, an
/// unreadable file or network error is `Unverified`, never clean.
pub async fn scan_manifest_strict(
    manifest_path: &Path,
    block_threshold: crate::security::osv_check::SeverityLevel,
) -> StrictManifestScan {
    // Read once: the digest and dependency parse must describe identical
    // bytes. Re-reading after network-bound OSV calls would create a TOCTOU
    // window where a clean verdict could be attached to different contents.
    let manifest_bytes = match std::fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return StrictManifestScan::Unverified {
                code: StrictScanCode::ManifestReadFailed,
            };
        }
    };
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let manifest_body = match std::str::from_utf8(&manifest_bytes) {
        Ok(body) => body,
        Err(_) => {
            return StrictManifestScan::Unverified {
                code: StrictScanCode::ManifestDecodeFailed,
            };
        }
    };
    let packages = match parse_manifest_body_strict(manifest_path, manifest_body) {
        Ok(packages) => packages,
        Err(reason) => {
            let code = if reason == "unsupported_dependency_source" {
                StrictScanCode::UnsupportedDependencySource
            } else if reason.starts_with("unsupported dependency manifest") {
                StrictScanCode::UnsupportedManifest
            } else {
                StrictScanCode::ManifestParseFailed
            };
            return StrictManifestScan::Unverified { code };
        }
    };
    if packages.iter().any(|package| package.version.is_none()) {
        return StrictManifestScan::Unverified {
            code: StrictScanCode::MissingExactVersion,
        };
    }
    let queries: Vec<crate::security::osv_check::PackageQuery<'_>> = packages
        .iter()
        .map(|package| crate::security::osv_check::PackageQuery {
            name: &package.name,
            ecosystem: package.ecosystem,
            version: package.version.as_deref(),
        })
        .collect();
    let verdicts = crate::security::osv_check::check_packages_batch(&queries).await;
    if verdicts.len() != packages.len() {
        return StrictManifestScan::Unverified {
            code: StrictScanCode::OsvResultMismatch,
        };
    }
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for (package, verdict) in packages.iter().zip(verdicts) {
        match classify_strict_verdict(package, verdict.clone(), block_threshold) {
            Ok(Some(finding)) => findings.push(finding),
            Ok(None) => {
                if let crate::security::osv_check::OsvVerdict::Vulnerable { max_severity, .. } =
                    verdict
                {
                    warnings.push(format!(
                        "{} has {max_severity:?} advisories below the {:?} policy",
                        package.name, block_threshold
                    ));
                }
            }
            Err(code) => return StrictManifestScan::Unverified { code },
        }
    }
    if findings.is_empty() {
        StrictManifestScan::ProvenClean {
            manifest_sha256,
            packages_scanned: packages.len(),
            warnings,
        }
    } else {
        StrictManifestScan::Blocked { findings }
    }
}

/// Fail-closed OSV scan for the exact registry coordinates extracted from a
/// direct package-manager command (`npm install x`, `cargo add x`, ...).
pub async fn scan_registry_packages_strict(
    requests: &[StrictPackageQuery],
    block_threshold: crate::security::osv_check::SeverityLevel,
) -> StrictPackageScan {
    if requests.is_empty() {
        return StrictPackageScan::Unverified {
            code: StrictScanCode::NoScannableDependencies,
        };
    }
    let packages: Vec<ManifestPackage> = requests
        .iter()
        .map(|request| ManifestPackage {
            name: request.name.clone(),
            ecosystem: request.ecosystem,
            version: request.version.clone(),
        })
        .collect();
    if packages.iter().any(|package| {
        package.version.is_none()
            || package.name.is_empty()
            || !package
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '/' | '_' | '-' | '.'))
    }) {
        return StrictPackageScan::Unverified {
            code: if packages.iter().any(|package| package.version.is_none()) {
                StrictScanCode::MissingExactVersion
            } else {
                StrictScanCode::ManifestParseFailed
            },
        };
    }
    let queries: Vec<crate::security::osv_check::PackageQuery<'_>> = packages
        .iter()
        .map(|package| crate::security::osv_check::PackageQuery {
            name: &package.name,
            ecosystem: package.ecosystem,
            version: package.version.as_deref(),
        })
        .collect();
    let verdicts = crate::security::osv_check::check_packages_batch(&queries).await;
    if verdicts.len() != packages.len() {
        return StrictPackageScan::Unverified {
            code: StrictScanCode::OsvResultMismatch,
        };
    }
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for (package, verdict) in packages.iter().zip(verdicts) {
        match classify_strict_verdict(package, verdict.clone(), block_threshold) {
            Ok(Some(finding)) => findings.push(finding),
            Ok(None) => {
                if let crate::security::osv_check::OsvVerdict::Vulnerable { max_severity, .. } =
                    verdict
                {
                    warnings.push(format!(
                        "{} has {max_severity:?} advisories below the {:?} policy",
                        package.name, block_threshold
                    ));
                }
            }
            Err(code) => return StrictPackageScan::Unverified { code },
        }
    }
    if findings.is_empty() {
        StrictPackageScan::ProvenClean {
            packages_scanned: packages.len(),
            warnings,
        }
    } else {
        StrictPackageScan::Blocked { findings }
    }
}

/// Scan all packages declared in a manifest through the existing security gates.
///
/// For each package name produced by [`manifest_packages`], runs:
/// 1. OSV advisory lookup (malware + CVE/GHSA severity) — async, fail-open.
/// 2. Typosquat heuristic — pure, offline.
/// 3. npm registry health (deprecated / abandoned) — async, fail-open.
///
/// Returns one [`DepFinding`] per problem found. A package with no issues
/// contributes zero entries. Network errors are silently swallowed (fail-open).
///
/// `now_unix` — current wall-clock seconds (use `crate::time::now_unix_i64()`
/// at the call site, or inject a fixed value in tests).
///
/// Consumer: the `neoth deps-scan <manifest>` CLI (`cli/deps.rs`) — an operator
/// vets a manifest before installing from it.
/// // neoth: also call this before any bulk `npm install` triggered from a
/// // manifest path (the install-flow consumer is still a follow-on).
pub async fn scan_manifest(manifest_path: &Path, now_unix: i64) -> Vec<DepFinding> {
    use crate::security::osv_check::{OsvVerdict, SeverityLevel};

    let packages = manifest_packages(manifest_path);
    let mut findings = Vec::new();

    for pkg in &packages {
        // 1. OSV advisory gate (async, fail-open).
        let verdict = crate::security::osv_check::check_package(pkg, "npm", None).await;
        match verdict {
            OsvVerdict::Malicious { advisories } => {
                findings.push(DepFinding {
                    package: pkg.clone(),
                    kind: DepFindingKind::Malware {
                        advisory_ids: advisories,
                    },
                });
            }
            OsvVerdict::Vulnerable {
                advisories,
                max_severity,
            } => {
                let ids = advisories.into_iter().map(|(id, _)| id).collect();
                let sev_label = format!("{max_severity:?}");
                // Only surface if not None (no useful data).
                if max_severity != SeverityLevel::None {
                    findings.push(DepFinding {
                        package: pkg.clone(),
                        kind: DepFindingKind::Vulnerable {
                            advisory_ids: ids,
                            max_severity: sev_label,
                        },
                    });
                }
            }
            OsvVerdict::Clean | OsvVerdict::Unknown { .. } => {
                // Unknown → fail-open, no finding.
            }
        }

        // 2. Typosquat heuristic (pure, offline).
        if let Some(hit) = typosquat_risk(pkg, "npm") {
            findings.push(DepFinding {
                package: pkg.clone(),
                kind: DepFindingKind::PossibleTyposquat {
                    resembles: hit.resembles,
                    distance: hit.distance,
                },
            });
        }

        // 3. npm registry health (async, fail-open).
        let rh = check_registry_health(pkg, now_unix).await;
        if let Some(msg) = rh.describe() {
            findings.push(DepFinding {
                package: pkg.clone(),
                kind: DepFindingKind::RegistryIssue { message: msg },
            });
        }
    }

    findings
}

// ── Registry-metadata health (GOLD-ADAPT-SNYK-03b) ───────────────────────────

/// How long without a new release before we consider a package abandoned.
/// Operator can tune by recompiling; surfaced as a warn, never a hard block.
// neoth: tunable — 2 years felt right for npm CLI toolchain packages (they tend
// to release at least once a year when actively maintained).
const ABANDONED_SECS: i64 = 2 * 365 * 24 * 60 * 60; // 2 years

/// Network timeout for the npm registry GET — fail open past this.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(6);

/// Health signal derived from the npm registry document for a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryHealth {
    /// The latest version carries a non-empty `deprecated` field.
    pub deprecated: bool,
    /// The deprecation message left by the maintainer, if any.
    pub deprecation_msg: Option<String>,
    /// Unix-second timestamp of the latest-version publish, if parseable.
    pub last_publish_unix: Option<i64>,
    /// True when `last_publish_unix` is older than [`ABANDONED_SECS`].
    pub abandoned: bool,
    /// Human-readable reason for the `abandoned` flag, if set.
    pub reason: Option<String>,
}

impl RegistryHealth {
    /// Returns `true` when neither flag is set — package looks healthy.
    pub fn is_healthy(&self) -> bool {
        !self.deprecated && !self.abandoned
    }

    /// Single-line operator warning. Returns `None` when nothing to warn about.
    pub fn describe(&self) -> Option<String> {
        match (self.deprecated, self.abandoned) {
            (false, false) => None,
            (true, _) => Some(format!(
                "npm package is deprecated{}",
                self.deprecation_msg
                    .as_deref()
                    .map(|m| format!(": {m}"))
                    .unwrap_or_default()
            )),
            (false, true) => Some(
                self.reason
                    .clone()
                    .unwrap_or_else(|| "npm package appears abandoned".to_string()),
            ),
        }
    }
}

/// Parse an ISO-8601 / RFC 3339 timestamp string to a Unix second.
///
/// The npm registry emits timestamps like `"2021-03-14T10:00:00.000Z"`.
/// chrono's `parse_from_rfc3339` handles fractional seconds natively but
/// requires the timezone expressed as `+00:00` rather than the `Z` shorthand
/// accepted by some parsers. We normalise `Z` → `+00:00` first.
fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    // Normalise trailing 'Z' (with or without fractional seconds) → '+00:00'.
    let normalised: std::borrow::Cow<str> = if let Some(stem) = s.strip_suffix('Z') {
        std::borrow::Cow::Owned(format!("{stem}+00:00"))
    } else {
        std::borrow::Cow::Borrowed(s)
    };
    chrono::DateTime::parse_from_rfc3339(&normalised)
        .ok()
        .map(|dt| dt.timestamp())
}

/// Parse a raw npm registry document into a [`RegistryHealth`] verdict.
///
/// Pure — no I/O, injected `now_unix` makes it unit-testable. Any missing or
/// malformed field is treated as healthy (defensive / fail-open for unknown
/// registry shapes). Never panics.
pub fn parse_registry_health(body: &serde_json::Value, now_unix: i64) -> RegistryHealth {
    // Locate the dist-tags.latest version string.
    let latest_ver = body
        .get("dist-tags")
        .and_then(|dt| dt.get("latest"))
        .and_then(|v| v.as_str());

    // ── Deprecation ──────────────────────────────────────────────────────────
    // `versions.<latest>.deprecated` is a non-empty string when set.
    let (deprecated, deprecation_msg) = latest_ver
        .and_then(|v| body.get("versions").and_then(|vs| vs.get(v)))
        .and_then(|ver_obj| ver_obj.get("deprecated"))
        .and_then(|d| d.as_str())
        .filter(|s| !s.is_empty())
        .map(|msg| (true, Some(msg.to_string())))
        .unwrap_or((false, None));

    // ── Abandon heuristic ─────────────────────────────────────────────────────
    // `time.<latest>` is an ISO-8601 string like "2021-03-14T10:00:00.000Z".
    let last_publish_unix: Option<i64> = latest_ver
        .and_then(|v| body.get("time").and_then(|t| t.get(v)))
        .and_then(|ts| ts.as_str())
        .and_then(parse_iso8601_to_unix)
        // Fall back: try `time.modified` (top-level registry modified date).
        .or_else(|| {
            body.get("time")
                .and_then(|t| t.get("modified"))
                .and_then(|ts| ts.as_str())
                .and_then(parse_iso8601_to_unix)
        });

    let (abandoned, reason) = match last_publish_unix {
        Some(ts) if (now_unix - ts) > ABANDONED_SECS => {
            let years = (now_unix - ts) / (365 * 24 * 60 * 60);
            (
                true,
                Some(format!(
                    "npm package last published ~{years} year(s) ago — may be abandoned"
                )),
            )
        }
        _ => (false, None),
    };

    RegistryHealth {
        deprecated,
        deprecation_msg,
        last_publish_unix,
        abandoned,
        reason,
    }
}

/// Query the npm registry for health metadata on `pkg`.
///
/// Mirrors the OSV-check client pattern exactly: same timeout, same fail-open
/// posture — a registry hiccup must never block an install.
///
/// `now_unix` is the current wall-clock second (use `crate::time::now_unix_i64()`
/// at the call site).
pub async fn check_registry_health(pkg: &str, now_unix: i64) -> RegistryHealth {
    // Healthy sentinel — returned on any error so the caller is never blocked.
    let healthy = RegistryHealth {
        deprecated: false,
        deprecation_msg: None,
        last_publish_unix: None,
        abandoned: false,
        reason: None,
    };

    // Percent-encode the package name (handles scoped packages like @anthropic-ai/claude-code).
    let encoded = percent_encode_pkg(pkg);
    let url = format!("https://registry.npmjs.org/{encoded}");

    let client = match reqwest::Client::builder().timeout(REGISTRY_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => return healthy,
    };
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return healthy,
    };
    if !resp.status().is_success() {
        return healthy;
    }
    match resp.json::<serde_json::Value>().await {
        Ok(body) => parse_registry_health(&body, now_unix),
        Err(_) => healthy,
    }
}

/// Minimal percent-encoding for npm package names.
///
/// Scoped packages like `@anthropic-ai/claude-code` need the `@` and `/` encoded
/// when used as a URL path segment: → `%40anthropic-ai%2Fclaude-code`.
fn percent_encode_pkg(pkg: &str) -> String {
    // The npm registry accepts the literal `@scope/name` form in the URL path
    // (it's how the registry CLI itself calls it), BUT the slash must be encoded
    // to avoid being interpreted as a path separator by HTTP routers. The `@`
    // is safe in path position but some proxies reject it — encode both to be safe.
    pkg.replace('@', "%40").replace('/', "%2F")
}

// ── Core heuristic ───────────────────────────────────────────────────────────

/// Return the maximum Levenshtein distance threshold for a name of a given
/// length. Returns `0` for names shorter than 4 characters, meaning only an
/// exact match would fire — but exact matches are explicitly excluded, so
/// effectively disabled for very short names.
fn threshold(name_len: usize) -> usize {
    if name_len < 4 {
        0
    } else if name_len < 8 {
        1
    } else {
        2
    }
}

/// Check whether `name` looks like a typosquat of a popular `ecosystem`
/// package.
///
/// Returns `Some(TyposquatHit)` iff:
/// - `ecosystem` is `"npm"` (no list exists for other ecosystems yet),
/// - `name` is NOT itself in the popular list (exact matches are legitimate),
/// - there exists a popular name within the Levenshtein distance threshold for
///   `name`'s length.
///
/// The first (shortest-distance, then alphabetically-first) hit is returned.
/// Callers should surface this as a WARNING — typosquatting is a heuristic and
/// must not hard-block installs unilaterally.
pub fn typosquat_risk(name: &str, ecosystem: &str) -> Option<TyposquatHit> {
    if !ecosystem.eq_ignore_ascii_case("npm") {
        // No curated list for this ecosystem yet.
        return None;
    }

    // Exact membership → legitimate popular package, no hit.
    if POPULAR_NPM.contains(&name) {
        return None;
    }

    let max_dist = threshold(name.len());
    if max_dist == 0 {
        // Name too short; any hit would be noise.
        return None;
    }

    // Find the closest popular name within the threshold.
    let mut best: Option<(&str, usize)> = None;
    for &popular in POPULAR_NPM {
        let d = strsim::levenshtein(name, popular);
        if d <= max_dist {
            let take = match best {
                None => true,
                Some((prev_name, prev_d)) => d < prev_d || (d == prev_d && popular < prev_name),
            };
            if take {
                best = Some((popular, d));
            }
        }
    }

    best.map(|(resembles, distance)| TyposquatHit {
        suspect: name.to_string(),
        resembles: resembles.to_string(),
        distance,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// "expres" is one deletion from "express" — must fire.
    #[test]
    fn typosquat_expres_flags_express() {
        let hit = typosquat_risk("expres", "npm").expect("expres must flag express");
        assert_eq!(hit.resembles, "express");
        assert_eq!(hit.distance, 1);
        assert!(hit.describe().contains("express"));
        assert!(hit.describe().contains("expres"));
    }

    /// An exact popular name is itself — must return None (not a typosquat).
    #[test]
    fn exact_popular_name_is_not_a_typosquat() {
        assert!(
            typosquat_risk("react", "npm").is_none(),
            "react is in the popular list, should not flag itself"
        );
        assert!(
            typosquat_risk("express", "npm").is_none(),
            "express is in the popular list, should not flag itself"
        );
    }

    /// A clearly-unrelated package name must not fire.
    #[test]
    fn bespoke_internal_package_is_clean() {
        assert!(
            typosquat_risk("my-bespoke-internal-pkg", "npm").is_none(),
            "unrelated name must not flag as typosquat"
        );
    }

    /// A short name (< 4 chars) with distance 1 must NOT fire — threshold is 0.
    #[test]
    fn short_name_distance_1_is_suppressed() {
        // "vuw" is distance 1 from "vue" (3 chars → threshold 0 → no hit).
        assert!(
            typosquat_risk("vuw", "npm").is_none(),
            "names shorter than 4 chars must not trigger the heuristic"
        );
        // "npm" is in the list; "nmp" (distance 1, 3 chars) must also be clean.
        assert!(
            typosquat_risk("nmp", "npm").is_none(),
            "3-char names must not trigger (threshold 0)"
        );
    }

    /// An unknown ecosystem with no curated list must always return None.
    #[test]
    fn non_npm_ecosystem_returns_none() {
        // "serde" is a crate name; no crates list, so must be None.
        assert!(
            typosquat_risk("serde", "crates").is_none(),
            "crates ecosystem has no list, must return None"
        );
        assert!(
            typosquat_risk("expres", "pypi").is_none(),
            "pypi ecosystem has no list, must return None"
        );
    }

    /// Distance-2 on a short (4–7 char) name must NOT fire — threshold is 1.
    #[test]
    fn distance_2_on_short_name_is_suppressed() {
        // "loadsh" (6 chars, threshold 1) is distance 2 from "lodash"
        // (the a/d pair is swapped = two substitutions) — must not flag.
        assert_eq!(strsim::levenshtein("loadsh", "lodash"), 2);
        assert!(
            typosquat_risk("loadsh", "npm").is_none(),
            "distance 2 must not fire for a 6-char name (threshold 1)"
        );
    }

    /// Verify describe() output contains suspect, resembles, and distance wording.
    #[test]
    fn describe_contains_expected_tokens() {
        let hit = TyposquatHit {
            suspect: "expres".to_string(),
            resembles: "express".to_string(),
            distance: 1,
        };
        let d = hit.describe();
        assert!(d.contains("expres"), "describe missing suspect: {d}");
        assert!(d.contains("express"), "describe missing resembles: {d}");
        assert!(d.contains('1'), "describe missing distance: {d}");
        assert!(d.contains("verify"), "describe missing action hint: {d}");
    }

    // ── RegistryHealth / parse_registry_health tests (pure, no network) ───────

    /// A registry doc with a non-empty `deprecated` field on the latest version
    /// must be flagged deprecated=true and carry the message.
    #[test]
    fn registry_health_deprecated_latest_version() {
        let body = serde_json::json!({
            "dist-tags": { "latest": "1.2.3" },
            "versions": {
                "1.2.3": {
                    "deprecated": "use `new-pkg` instead"
                }
            },
            "time": {
                "1.2.3": "2024-01-15T10:00:00.000Z"
            }
        });
        // now_unix: 2025-06-19 ≈ 1 year after publish — NOT abandoned
        let now = 1_750_000_000_i64;
        let health = parse_registry_health(&body, now);
        assert!(health.deprecated, "expected deprecated=true");
        assert_eq!(
            health.deprecation_msg.as_deref(),
            Some("use `new-pkg` instead")
        );
        assert!(
            !health.abandoned,
            "only 1 year old — should not be abandoned"
        );
        assert!(health.describe().is_some());
        assert!(health.describe().unwrap().contains("new-pkg"));
    }

    /// A doc whose latest publish time is 3 years before `now_unix` must be
    /// flagged abandoned=true.
    #[test]
    fn registry_health_abandoned_old_publish() {
        // Publish date: 2020-01-01 ≈ unix 1_577_836_800
        let body = serde_json::json!({
            "dist-tags": { "latest": "0.1.0" },
            "versions": { "0.1.0": {} },
            "time": {
                "0.1.0": "2020-01-01T00:00:00.000Z"
            }
        });
        // now_unix: 2023-06-01 ≈ 1_685_577_600 (~3.5 years later)
        let now = 1_685_577_600_i64;
        let health = parse_registry_health(&body, now);
        assert!(!health.deprecated, "no deprecated field");
        assert!(health.abandoned, "3+ years old — should be abandoned");
        assert!(health.reason.is_some());
        let reason = health.reason.as_deref().unwrap();
        assert!(
            reason.contains("year"),
            "reason should mention years: {reason}"
        );
        assert!(health.describe().is_some());
    }

    /// A fresh, non-deprecated doc must yield all-false (healthy).
    #[test]
    fn registry_health_fresh_healthy_doc() {
        // Published "recently" (now - 6 months)
        let recent_ts = 1_750_000_000_i64 - 6 * 30 * 24 * 60 * 60;
        // Build an ISO-8601 string from the timestamp (approximate — good enough
        // for a round-trip unit test of the parse path).
        let ts_str = chrono::DateTime::from_timestamp(recent_ts, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string())
            .unwrap_or_else(|| "2025-01-01T00:00:00+00:00".to_string());
        let body = serde_json::json!({
            "dist-tags": { "latest": "3.0.0" },
            "versions": { "3.0.0": {} },
            "time": { "3.0.0": ts_str }
        });
        let health = parse_registry_health(&body, 1_750_000_000);
        assert!(!health.deprecated);
        assert!(!health.abandoned);
        assert!(health.is_healthy());
        assert!(health.describe().is_none());
    }

    /// A malformed / empty doc must yield healthy (no panic, no false positive).
    #[test]
    fn registry_health_malformed_doc_is_healthy() {
        // Completely empty object
        let health = parse_registry_health(&serde_json::json!({}), 1_750_000_000);
        assert!(!health.deprecated);
        assert!(!health.abandoned);
        assert!(health.is_healthy());

        // Null body
        let health2 = parse_registry_health(&serde_json::Value::Null, 1_750_000_000);
        assert!(health2.is_healthy());

        // dist-tags present but no versions block
        let health3 = parse_registry_health(
            &serde_json::json!({ "dist-tags": { "latest": "1.0.0" } }),
            1_750_000_000,
        );
        assert!(health3.is_healthy());
    }

    /// percent_encode_pkg must encode scoped package names correctly.
    #[test]
    fn percent_encode_pkg_scoped() {
        assert_eq!(
            percent_encode_pkg("@anthropic-ai/claude-code"),
            "%40anthropic-ai%2Fclaude-code"
        );
        assert_eq!(percent_encode_pkg("lodash"), "lodash");
        assert_eq!(percent_encode_pkg("@openai/codex"), "%40openai%2Fcodex");
    }

    // ── manifest_packages (SNYK-02, pure) ─────────────────────────────────────

    /// A valid package.json with both deps and devDeps yields all names.
    #[test]
    fn manifest_packages_parses_deps_and_dev_deps() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package.json");
        std::fs::write(
            &path,
            r#"{
              "name": "my-app",
              "dependencies": {
                "express": "^4.18.0",
                "lodash": "^4.17.21"
              },
              "devDependencies": {
                "jest": "^29.0.0",
                "typescript": "^5.0.0"
              }
            }"#,
        )
        .unwrap();
        let mut names = manifest_packages(&path);
        names.sort();
        assert_eq!(names, ["express", "jest", "lodash", "typescript"]);
    }

    /// A package.json with no dep sections yields an empty list (no panic).
    #[test]
    fn manifest_packages_no_deps_section() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package.json");
        std::fs::write(&path, r#"{"name": "empty-pkg", "version": "1.0.0"}"#).unwrap();
        assert!(manifest_packages(&path).is_empty());
    }

    /// A malformed JSON file yields an empty list without panicking.
    #[test]
    fn manifest_packages_malformed_json_no_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package.json");
        std::fs::write(&path, "this is not json {{{").unwrap();
        assert!(manifest_packages(&path).is_empty());
    }

    /// A missing file yields an empty list without panicking.
    #[test]
    fn manifest_packages_missing_file_no_panic() {
        let path = std::path::Path::new("/this/path/does/not/exist/package.json");
        assert!(manifest_packages(path).is_empty());
    }

    #[test]
    fn strict_manifest_parser_covers_cargo_aliases_and_workspace_dependencies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Cargo.toml");
        std::fs::write(
            &path,
            r#"
                [dependencies]
                serde = "1"
                renamed = { package = "actual-crate", version = "2" }

                [workspace.dependencies]
                tokio = { version = "1", features = ["rt"] }
            "#,
        )
        .unwrap();
        let packages = parse_manifest_strict(&path).expect("strict Cargo parse");
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["actual-crate", "serde", "tokio"]);
        assert!(packages.iter().all(|p| p.ecosystem == "crates.io"));
    }

    #[test]
    fn strict_manifest_parser_covers_legacy_nested_npm_lock_dependencies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package-lock.json");
        std::fs::write(
            &path,
            r#"{
                "lockfileVersion": 1,
                "dependencies": {
                    "parent": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz",
                        "integrity": "sha512-parent",
                        "dependencies": {
                            "child": {
                                "version": "2.0.0",
                                "resolved": "https://registry.npmjs.org/child/-/child-2.0.0.tgz",
                                "integrity": "sha512-child"
                            }
                        }
                    }
                }
            }"#,
        )
        .unwrap();
        let packages = parse_manifest_strict(&path).expect("strict npm lock parse");
        let coordinates: Vec<(&str, Option<&str>)> = packages
            .iter()
            .map(|package| (package.name.as_str(), package.version.as_deref()))
            .collect();
        assert_eq!(
            coordinates,
            vec![("child", Some("2.0.0")), ("parent", Some("1.0.0"))]
        );
    }

    #[test]
    fn strict_npm_lock_accepts_only_the_exact_https_registry_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package-lock.json");
        std::fs::write(
            &path,
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/left-pad": {
                        "version": "1.3.0",
                        "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                        "integrity": "sha512-fixture"
                    }
                }
            }"#,
        )
        .unwrap();
        let packages = parse_manifest_strict(&path).expect("official npm registry URL");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "left-pad");
        assert_eq!(packages[0].version.as_deref(), Some("1.3.0"));
    }

    #[test]
    fn exact_versions_are_ecosystem_specific_and_never_wildcards() {
        assert_eq!(exact_version("1.2.3").as_deref(), Some("1.2.3"));
        assert!(exact_version("1.x").is_none());
        assert!(exact_version("1.latest").is_none());
        for version in ["1.0", "2024.1", "1!2.0", "2.0rc1"] {
            assert_eq!(exact_pypi_version(version).as_deref(), Some(version));
        }
        assert!(exact_pypi_version("1.*").is_none());
    }

    #[test]
    fn resolved_lockfiles_reject_missing_or_non_exact_versions() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        let cases = [
            (
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":{"node_modules/x":{"resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}}"#,
            ),
            (
                "Pipfile.lock",
                r#"{"default":{"requests":{"version":"==1.*"}},"develop":{}}"#,
            ),
            ("Cargo.lock", "version=4\n[[package]]\nname='fixture'\n"),
            (
                "pnpm-lock.yaml",
                "lockfileVersion: '9.0'\npackages:\n  x@1.x: {}\n",
            ),
            ("yarn.lock", "x@^1.0.0:\n  version \"1.x\"\n"),
            (
                "poetry.lock",
                "[[package]]\nname='requests'\nversion='1.*'\n",
            ),
            ("uv.lock", "[[package]]\nname='requests'\n"),
            ("go.sum", "example.com/module latest h1:fixture\n"),
        ];
        for (name, body) in cases {
            let path = dir.path().join(name);
            std::fs::write(&path, body).unwrap();
            assert!(
                parse_manifest_strict(&path).is_err(),
                "{name} must reject a missing/non-exact resolved version"
            );
        }
    }

    #[test]
    fn cargo_lock_accepts_only_canonical_crates_io_sources() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        let lock = dir.path().join("Cargo.lock");
        std::fs::write(
            &lock,
            r#"version = 4
[[package]]
name = "fixture"
version = "0.1.0"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://example.invalid/index"
checksum = "fixture"
"#,
        )
        .unwrap();
        assert!(parse_manifest_strict(&lock).is_err());

        std::fs::write(
            &lock,
            r#"version = 4
[[package]]
name = "fixture"
version = "0.1.0"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fixture"
"#,
        )
        .unwrap();
        let packages = parse_manifest_strict(&lock).expect("canonical crates.io lock");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "serde");
        assert_eq!(packages[0].version.as_deref(), Some("1.0.228"));
    }

    #[test]
    fn strict_manifest_parser_covers_pnpm_and_python_lockfiles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pnpm = dir.path().join("pnpm-lock.yaml");
        std::fs::write(
            &pnpm,
            r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      direct:
        version: 1.2.3
packages:
  '@scope/pkg@2.0.0':
    resolution: {integrity: sha512-scoped}
  transitive@3.0.0:
    resolution: {integrity: sha512-transitive}
"#,
        )
        .unwrap();
        let packages = parse_manifest_strict(&pnpm).expect("strict pnpm lock parse");
        let names: Vec<&str> = packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert_eq!(names, vec!["@scope/pkg", "direct", "transitive"]);

        for lock_name in ["poetry.lock", "uv.lock"] {
            let lock = dir.path().join(lock_name);
            std::fs::write(
                &lock,
                r#"
[[package]]
name = "requests"
version = "2.32.0"
"#,
            )
            .unwrap();
            let packages = parse_manifest_strict(&lock).expect("strict Python lock parse");
            assert_eq!(packages.len(), 1);
            assert_eq!(packages[0].name, "requests");
            assert_eq!(packages[0].version.as_deref(), Some("2.32.0"));
            assert_eq!(packages[0].ecosystem, "PyPI");
        }
    }

    #[test]
    fn package_json_aliases_resolve_to_the_registry_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package.json");
        std::fs::write(
            &path,
            r#"{"dependencies":{"compat":"npm:@scope/actual@1.2.3"}}"#,
        )
        .unwrap();
        let packages = parse_manifest_strict(&path).expect("strict package parse");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "@scope/actual");
        assert_eq!(packages[0].version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn npm_lock_aliases_scan_the_actual_registry_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package-lock.json");
        std::fs::write(
            &path,
            r#"{
                "lockfileVersion":3,
                "packages":{
                    "node_modules/compat":{
                        "name":"@scope/actual",
                        "version":"1.2.3",
                        "resolved":"https://registry.npmjs.org/%40scope%2factual/-/actual-1.2.3.tgz",
                        "integrity":"sha512-fixture"
                    }
                }
            }"#,
        )
        .unwrap();
        let packages = parse_manifest_strict(&path).expect("strict npm alias lock parse");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "@scope/actual");
        assert_eq!(packages[0].version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn pnpm_and_yarn_lock_sources_are_bound_to_canonical_registry_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pnpm = dir.path().join("pnpm-lock.yaml");
        std::fs::write(
            &pnpm,
            "lockfileVersion: '9.0'\npackages:\n  x@1.0.0:\n    resolution: {tarball: https://example.invalid/x.tgz, integrity: sha512-fixture}\n",
        )
        .unwrap();
        assert!(parse_manifest_strict(&pnpm).is_err());

        let yarn = dir.path().join("yarn.lock");
        std::fs::write(
            &yarn,
            "x@^1.0.0:\n  version \"1.0.0\"\n  resolved \"https://example.invalid/x-1.0.0.tgz\"\n  integrity sha512-fixture\n",
        )
        .unwrap();
        assert!(parse_manifest_strict(&yarn).is_err());

        std::fs::write(
            &yarn,
            "x@^1.0.0:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/x/-/x-1.0.0.tgz#0123456789abcdef0123456789abcdef01234567\"\n  integrity sha512-fixture\n",
        )
        .unwrap();
        let packages = parse_manifest_strict(&yarn).expect("canonical classic yarn lock");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "x");
    }

    #[test]
    fn berry_lock_resolutions_preserve_real_and_virtual_package_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let yarn = dir.path().join("yarn.lock");
        std::fs::write(
            &yarn,
            r#"
__metadata:
  version: 8
"@scope/pkg@npm:^2.0.0":
  version: 2.0.0
  resolution: "@scope/pkg@npm:2.0.0"
  checksum: fixture
"peer-pkg@virtual:abc#npm:^3.0.0":
  version: 3.0.0
  resolution: "peer-pkg@virtual:abc#npm:3.0.0"
  checksum: fixture
"#,
        )
        .unwrap();
        let packages = parse_manifest_strict(&yarn).expect("canonical berry lock");
        let coordinates = packages
            .iter()
            .map(|package| (package.name.as_str(), package.version.as_deref()))
            .collect::<Vec<_>>();
        assert_eq!(
            coordinates,
            vec![("@scope/pkg", Some("2.0.0")), ("peer-pkg", Some("3.0.0"))]
        );
    }

    #[test]
    fn strict_manifest_parser_fails_closed_on_unreadable_or_unsupported_input() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("package.json");
        assert!(parse_manifest_strict(&missing).is_err());

        let unsupported = dir.path().join("Gemfile.lock");
        std::fs::write(&unsupported, "GEM\n").unwrap();
        assert!(parse_manifest_strict(&unsupported).is_err());
    }

    #[test]
    fn strict_manifest_parser_rejects_non_registry_dependency_sources() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cases = [
            (
                "package.json",
                r#"{"dependencies":{"local":"file:./vendor/local"}}"#,
            ),
            (
                "Cargo.toml",
                "[dependencies]\nremote = { git = 'https://example.invalid/repo' }\n",
            ),
            (
                "pyproject.toml",
                "[project]\ndependencies = ['remote @ https://example.invalid/pkg.whl']\n",
            ),
            (
                "go.mod",
                "module example.test/x\nreplace example.test/a => ../local\n",
            ),
            (
                "yarn.lock",
                "\"alias@npm:actual@1.0.0\":\n  version \"1.0.0\"\n",
            ),
            (
                "package.json",
                r#"{"workspaces":["packages/*"],"dependencies":{}}"#,
            ),
            ("pyproject.toml", "[project]\ndynamic = ['dependencies']\n"),
            ("Cargo.toml", "[workspace]\nmembers = ['member']\n"),
            (
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.0.0","resolved":"https://registry.npmjs.org.evil.invalid/evil/-/evil-1.0.0.tgz","integrity":"sha512-fixture"}}}"#,
            ),
        ];
        for (name, body) in cases {
            let path = dir.path().join(name);
            std::fs::write(&path, body).unwrap();
            assert!(
                parse_manifest_strict(&path).is_err(),
                "{name} non-registry source must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn strict_direct_package_scan_rejects_an_empty_query_set_without_network() {
        assert_eq!(
            scan_registry_packages_strict(&[], crate::security::osv_check::SeverityLevel::High,)
                .await,
            StrictPackageScan::Unverified {
                code: StrictScanCode::NoScannableDependencies,
            }
        );
    }

    #[tokio::test]
    async fn strict_scan_never_queries_osv_without_an_exact_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package.json");
        std::fs::write(&path, r#"{"dependencies":{"left-pad":"^1.0.0"}}"#).unwrap();
        assert_eq!(
            scan_manifest_strict(&path, crate::security::osv_check::SeverityLevel::High).await,
            StrictManifestScan::Unverified {
                code: StrictScanCode::MissingExactVersion,
            }
        );
    }

    #[tokio::test]
    async fn strict_manifest_scan_returns_digest_of_exact_parsed_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package.json");
        std::fs::write(&path, r#"{"dependencies":{}}"#).unwrap();
        let expected = manifest_sha256(&path).unwrap();

        let result =
            scan_manifest_strict(&path, crate::security::osv_check::SeverityLevel::High).await;
        match result {
            StrictManifestScan::ProvenClean {
                manifest_sha256,
                packages_scanned,
                ..
            } => {
                assert_eq!(manifest_sha256, expected);
                assert_eq!(packages_scanned, 0);
            }
            other => panic!("empty valid manifest must be provably clean: {other:?}"),
        }
    }

    #[test]
    fn strict_verdict_requires_conclusive_osv_and_honours_policy() {
        use crate::security::osv_check::{OsvVerdict, SeverityLevel};
        let package = ManifestPackage {
            name: "example".into(),
            ecosystem: "npm",
            version: Some("1.0.0".into()),
        };
        assert!(
            classify_strict_verdict(
                &package,
                OsvVerdict::Unknown {
                    reason: "offline".into(),
                },
                SeverityLevel::High,
            )
            .is_err(),
            "an inconclusive lookup must never resolve the install gate"
        );
        let unclassified = OsvVerdict::Vulnerable {
            advisories: vec![("CVE-UNKNOWN".into(), SeverityLevel::None)],
            max_severity: SeverityLevel::None,
        };
        assert!(
            classify_strict_verdict(&package, unclassified, SeverityLevel::High).is_err(),
            "an advisory without severity cannot be proven below a blocking threshold"
        );
        let vulnerable = OsvVerdict::Vulnerable {
            advisories: vec![("CVE-1".into(), SeverityLevel::High)],
            max_severity: SeverityLevel::High,
        };
        assert!(
            classify_strict_verdict(&package, vulnerable.clone(), SeverityLevel::Critical)
                .unwrap()
                .is_none(),
            "below-policy advisories are scanned but warn-only"
        );
        assert!(
            classify_strict_verdict(&package, vulnerable, SeverityLevel::High)
                .unwrap()
                .is_some(),
            "at-policy advisories must block"
        );
    }

    /// DepFinding::describe produces human-readable output for all variants.
    #[test]
    fn dep_finding_describe_all_variants() {
        let vuln = DepFinding {
            package: "bad-pkg".to_string(),
            kind: DepFindingKind::Vulnerable {
                advisory_ids: vec!["CVE-2023-1".to_string()],
                max_severity: "High".to_string(),
            },
        };
        let d = vuln.describe();
        assert!(d.contains("bad-pkg"));
        assert!(d.contains("CVE-2023-1"));
        assert!(d.contains("High"));

        let malware = DepFinding {
            package: "evil".to_string(),
            kind: DepFindingKind::Malware {
                advisory_ids: vec!["MAL-2024-1".to_string()],
            },
        };
        assert!(malware.describe().contains("MALWARE"));
        assert!(malware.describe().contains("evil"));

        let typo = DepFinding {
            package: "expres".to_string(),
            kind: DepFindingKind::PossibleTyposquat {
                resembles: "express".to_string(),
                distance: 1,
            },
        };
        assert!(typo.describe().contains("typosquat"));
        assert!(typo.describe().contains("express"));

        let reg = DepFinding {
            package: "old-pkg".to_string(),
            kind: DepFindingKind::RegistryIssue {
                message: "npm package is deprecated".to_string(),
            },
        };
        assert!(reg.describe().contains("deprecated"));
    }
}
