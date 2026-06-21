//! `neoth-migrate import-config` — OpenClaw config → freedom.yaml provider stanzas.
//!
//! Reads two JSON files that OpenClaw (Jarvis gateway) writes:
//!
//!   • `auth.profiles`   — a map of profile-name → `{ provider, ... }`.
//!     Fields that look like keys/secrets are detected and SKIPPED.
//!   • `models.providers` — a list of `{ id, kind, ... }` provider
//!     records.
//!
//! The import converts those records to NEOTH `freedom.yaml` provider
//! stanzas (one per unique provider kind encountered).  **API keys are
//! NEVER read, stored, or printed.**  The output YAML contains a
//! `# TODO: add your key to credentials.yaml` comment in place of any
//! key field.
//!
//! ## Supported mappings
//!
//! | OpenClaw `kind`      | NEOTH `InferenceProvider` |
//! |----------------------|--------------------------|
//! | `claude-cli`         | `claude_cli`             |
//! | `gemini`             | `gemini_api`             |
//! | `openai`             | `openai_api`             |
//! | `openai-compat`      | `openai_compat`          |
//! | `anthropic` / `api`  | `anthropic_api`          |
//!
//! Unknown `kind` values are reported in `ImportConfigResult::skipped`.
//!
//! ## Key-safety invariant
//!
//! Any JSON field whose name contains a key-like substring (`key`,
//! `secret`, `token`, `password`, `credential`, `auth`) is silently
//! DROPPED before any further processing.  The resulting YAML stanzas
//! therefore contain NO secret material — the sanitiser runs on every
//! object encountered in both input files.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

// ── Key-safety ────────────────────────────────────────────────────────

/// Returns `true` if a JSON field name looks like it carries secret
/// material.  Case-insensitive; matches any of the listed substrings.
fn is_sensitive_field(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    ["key", "secret", "token", "password", "credential", "auth"]
        .iter()
        .any(|kw| low.contains(kw))
}

/// Strip all sensitive fields from a JSON object (recursively).  Returns
/// the sanitised value.  Non-object values pass through unchanged.
fn sanitise(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let cleaned: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .filter(|(k, _)| !is_sensitive_field(k))
                .map(|(k, v)| (k, sanitise(v)))
                .collect();
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sanitise).collect())
        }
        other => other,
    }
}

// ── OpenClaw wire shapes ──────────────────────────────────────────────

/// One entry from `auth.profiles` (after sanitising).
/// Only the `provider` field is used for mapping; the rest is informational.
#[derive(Debug, Deserialize)]
pub struct AuthProfile {
    pub provider: Option<String>,
    /// Catch-all for all non-sensitive remainder fields.
    #[serde(flatten)]
    pub _extra: BTreeMap<String, serde_json::Value>,
}

/// One entry from `models.providers` (after sanitising).
#[derive(Debug, Deserialize)]
pub struct ProviderRecord {
    /// Present in the OpenClaw wire format; kept for completeness but not
    /// consumed by the mapper (only `kind` + `base_url` are used).
    #[allow(dead_code)]
    pub id: Option<String>,
    pub kind: Option<String>,
    pub base_url: Option<String>,
    #[serde(flatten)]
    pub _extra: BTreeMap<String, serde_json::Value>,
}

// ── NEOTH provider stanza (output) ───────────────────────────────────

/// A freedom.yaml provider stanza suitable for pasting into
/// `inference.providers:`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeothProviderStanza {
    /// NEOTH InferenceProvider snake_case identifier.
    pub provider: String,
    /// Populated only for openai_compat where OpenClaw carries a base_url.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Human-readable note; always present so operators know what to do.
    pub note: String,
}

// ── Mapping ───────────────────────────────────────────────────────────

/// Map an OpenClaw `kind` string to the NEOTH InferenceProvider identifier.
///
/// Returns `None` for unknown kinds.
pub fn map_kind(kind: &str) -> Option<&'static str> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "claude-cli" | "claude_cli" => Some("claude_cli"),
        "gemini" | "gemini_api" => Some("gemini_api"),
        "openai" | "openai_api" => Some("openai_api"),
        "openai-compat" | "openai_compat" => Some("openai_compat"),
        "anthropic" | "anthropic_api" | "api" => Some("anthropic_api"),
        _ => None,
    }
}

// ── Import result ─────────────────────────────────────────────────────

/// Result returned by [`import_config`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportConfigResult {
    /// Provider stanzas to paste into freedom.yaml.
    pub stanzas: Vec<NeothProviderStanza>,
    /// OpenClaw kinds that had no NEOTH mapping (informational).
    pub skipped: Vec<String>,
    /// How many sensitive fields were dropped (non-zero = key-safety worked).
    pub sensitive_fields_dropped: usize,
}

// ── Public entry point ────────────────────────────────────────────────

/// Parse OpenClaw config files and return provider stanzas.
///
/// Both `auth_profiles_path` and `models_providers_path` are optional —
/// pass `None` to skip that input file.  At least one must be `Some`.
///
/// **Key safety:** all sensitive fields are stripped BEFORE deserialization
/// of the JSON values, so no key material ever reaches the output.
pub fn import_config(
    auth_profiles_path: Option<&Path>,
    models_providers_path: Option<&Path>,
) -> anyhow::Result<ImportConfigResult> {
    let mut seen_providers: BTreeSet<String> = BTreeSet::new();
    let mut stanzas: Vec<NeothProviderStanza> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut sensitive_fields_dropped: usize = 0;

    // ── auth.profiles ─────────────────────────────────────────────
    if let Some(path) = auth_profiles_path {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read auth.profiles at {}", path.display()))?;
        let v: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse auth.profiles JSON at {}", path.display()))?;
        let (clean, dropped) = sanitise_count(v);
        sensitive_fields_dropped = sensitive_fields_dropped.saturating_add(dropped);
        // auth.profiles may be a map of name → record, or an array
        let records: Vec<serde_json::Value> = match clean {
            serde_json::Value::Object(map) => map.into_values().collect(),
            serde_json::Value::Array(arr) => arr,
            other => vec![other],
        };
        for rec in records {
            if let Ok(profile) = serde_json::from_value::<AuthProfile>(rec) {
                if let Some(kind) = profile.provider {
                    process_kind(
                        &kind,
                        None,
                        &mut seen_providers,
                        &mut stanzas,
                        &mut skipped,
                    );
                }
            }
        }
    }

    // ── models.providers ──────────────────────────────────────────
    if let Some(path) = models_providers_path {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read models.providers at {}", path.display()))?;
        let v: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse models.providers JSON at {}", path.display()))?;
        let (clean, dropped) = sanitise_count(v);
        sensitive_fields_dropped = sensitive_fields_dropped.saturating_add(dropped);
        let records: Vec<serde_json::Value> = match clean {
            serde_json::Value::Array(arr) => arr,
            serde_json::Value::Object(map) => map.into_values().collect(),
            other => vec![other],
        };
        for rec in records {
            if let Ok(provider_rec) = serde_json::from_value::<ProviderRecord>(rec) {
                let kind = provider_rec.kind.as_deref().unwrap_or_default();
                process_kind(
                    kind,
                    provider_rec.base_url.as_deref(),
                    &mut seen_providers,
                    &mut stanzas,
                    &mut skipped,
                );
            }
        }
    }

    if auth_profiles_path.is_none() && models_providers_path.is_none() {
        anyhow::bail!("at least one of --auth-profiles or --models-providers must be provided");
    }

    Ok(ImportConfigResult {
        stanzas,
        skipped,
        sensitive_fields_dropped,
    })
}

/// Map one OpenClaw kind string into a stanza (deduplicates by provider).
fn process_kind(
    kind: &str,
    base_url: Option<&str>,
    seen: &mut BTreeSet<String>,
    stanzas: &mut Vec<NeothProviderStanza>,
    skipped: &mut Vec<String>,
) {
    if kind.is_empty() {
        return;
    }
    match map_kind(kind) {
        Some(neoth_provider) => {
            // Dedup: one stanza per NEOTH provider type.
            if seen.insert(neoth_provider.to_string()) {
                let note = if neoth_provider == "claude_cli" {
                    "OAuth via `claude` CLI — no API key required. \
                     Run `claude login` if not already authenticated."
                        .to_string()
                } else {
                    "Add your API key to credentials.yaml — \
                     NEVER put keys in freedom.yaml."
                        .to_string()
                };
                stanzas.push(NeothProviderStanza {
                    provider: neoth_provider.to_string(),
                    base_url: base_url.map(String::from),
                    note,
                });
            }
        }
        None => {
            let s = kind.to_string();
            if !skipped.contains(&s) {
                skipped.push(s);
            }
        }
    }
}

// ── Helper: sanitise + count dropped fields ──────────────────────────

/// Like `sanitise` but also counts how many sensitive fields were dropped.
fn sanitise_count(v: serde_json::Value) -> (serde_json::Value, usize) {
    let mut dropped = 0usize;
    let out = sanitise_counting(v, &mut dropped);
    (out, dropped)
}

fn sanitise_counting(v: serde_json::Value, dropped: &mut usize) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            // Split into two passes to avoid two &mut borrows on `dropped`
            // from two closures in the same iterator chain.
            let pairs: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            let mut cleaned = serde_json::Map::new();
            for (k, val) in pairs {
                if is_sensitive_field(&k) {
                    *dropped += 1;
                } else {
                    let v2 = sanitise_counting(val, dropped);
                    cleaned.insert(k, v2);
                }
            }
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.into_iter()
                .map(|v| sanitise_counting(v, dropped))
                .collect(),
        ),
        other => other,
    }
}

// ── Render to YAML comment block ──────────────────────────────────────

/// Render the stanzas as a YAML snippet ready to paste into freedom.yaml.
/// Includes a header comment warning about key placement.
pub fn render_yaml(result: &ImportConfigResult) -> String {
    let mut out = String::new();
    out.push_str("# Generated by neoth-migrate import-config\n");
    out.push_str(
        "# Paste these stanzas into your freedom.yaml under `inference.providers:`\n",
    );
    out.push_str(
        "# API KEYS: NEVER add keys here. Use credentials.yaml instead.\n",
    );
    out.push('\n');
    out.push_str("inference:\n");
    out.push_str("  providers:\n");
    for stanza in &result.stanzas {
        out.push_str(&format!("    - provider: {}\n", stanza.provider));
        if let Some(url) = &stanza.base_url {
            out.push_str(&format!("      base_url: \"{url}\"\n"));
        }
        out.push_str(&format!("      # {}\n", stanza.note));
    }
    if !result.skipped.is_empty() {
        out.push('\n');
        out.push_str("# The following OpenClaw kinds were not recognised and were skipped:\n");
        for s in &result.skipped {
            out.push_str(&format!("#   {s}\n"));
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    // ── Helpers ───────────────────────────────────────────────────

    fn write_tmp(json: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    // ── is_sensitive_field ───────────────────────────────────────

    #[test]
    fn sensitive_field_detection_covers_all_keywords() {
        for field in &["api_key", "apiKey", "secret", "access_token", "password", "credential", "auth_header"] {
            assert!(
                is_sensitive_field(field),
                "expected {field:?} to be detected as sensitive"
            );
        }
    }

    #[test]
    fn non_sensitive_fields_pass_through() {
        for field in &["provider", "kind", "id", "base_url", "model", "name"] {
            assert!(
                !is_sensitive_field(field),
                "expected {field:?} NOT to be sensitive"
            );
        }
    }

    // ── sanitise ─────────────────────────────────────────────────

    #[test]
    fn sanitise_drops_key_fields_from_object() {
        let v: serde_json::Value = serde_json::json!({
            "provider": "openai",
            "api_key": "sk-REAL_SECRET",
            "secret": "another-secret",
            "base_url": "https://api.openai.com/v1"
        });
        let clean = sanitise(v);
        let obj = clean.as_object().unwrap();
        assert!(!obj.contains_key("api_key"), "api_key must be dropped");
        assert!(!obj.contains_key("secret"), "secret must be dropped");
        assert_eq!(obj["provider"], "openai");
        assert!(obj.contains_key("base_url"));
    }

    #[test]
    fn sanitise_drops_nested_sensitive_fields() {
        let v: serde_json::Value = serde_json::json!({
            "outer": {
                "inner_key": "SHOULD_BE_DROPPED",
                "name": "keep_me"
            }
        });
        let clean = sanitise(v);
        let inner = clean["outer"].as_object().unwrap();
        assert!(!inner.contains_key("inner_key"));
        assert!(inner.contains_key("name"));
    }

    #[test]
    fn sanitise_count_returns_correct_drop_count() {
        let v: serde_json::Value = serde_json::json!({
            "api_key": "x",
            "secret_token": "y",
            "provider": "openai"
        });
        let (_clean, dropped) = sanitise_count(v);
        assert_eq!(dropped, 2, "two sensitive fields should be counted");
    }

    // ── map_kind ─────────────────────────────────────────────────

    #[test]
    fn map_kind_covers_all_supported_openclaw_values() {
        let cases = [
            ("claude-cli", "claude_cli"),
            ("claude_cli", "claude_cli"),
            ("gemini", "gemini_api"),
            ("gemini_api", "gemini_api"),
            ("openai", "openai_api"),
            ("openai_api", "openai_api"),
            ("openai-compat", "openai_compat"),
            ("openai_compat", "openai_compat"),
            ("anthropic", "anthropic_api"),
            ("anthropic_api", "anthropic_api"),
            ("api", "anthropic_api"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                map_kind(input),
                Some(expected),
                "map_kind({input:?}) should be {expected:?}"
            );
        }
    }

    #[test]
    fn map_kind_returns_none_for_unknown() {
        assert_eq!(map_kind("some-unknown-gateway"), None);
        assert_eq!(map_kind(""), None);
        assert_eq!(map_kind("gpt-4"), None);
    }

    // ── import_config — auth.profiles ─────────────────────────────

    #[test]
    fn import_config_parses_auth_profiles_map() {
        // auth.profiles as a JSON object (name → record)
        let json = serde_json::json!({
            "personal": { "provider": "claude-cli" },
            "work":     { "provider": "openai", "api_key": "sk-SHOULD_BE_DROPPED" }
        })
        .to_string();
        let f = write_tmp(&json);
        let result = import_config(Some(f.path()), None).unwrap();

        let providers: Vec<&str> = result.stanzas.iter().map(|s| s.provider.as_str()).collect();
        assert!(
            providers.contains(&"claude_cli"),
            "claude_cli should be in stanzas"
        );
        assert!(
            providers.contains(&"openai_api"),
            "openai_api should be in stanzas"
        );
        assert_eq!(result.skipped, Vec::<String>::new());
    }

    #[test]
    fn import_config_no_key_bytes_in_output() {
        // The auth profile contains a realistic-looking key — it must NEVER
        // appear anywhere in the result stanzas or notes.
        let secret = "sk-REAL_SECRET_KEY_VALUE_12345";
        let json = serde_json::json!({
            "default": {
                "provider": "openai",
                "api_key": secret,
                "openai_secret": secret
            }
        })
        .to_string();
        let f = write_tmp(&json);
        let result = import_config(Some(f.path()), None).unwrap();
        let yaml = render_yaml(&result);

        assert!(
            !yaml.contains(secret),
            "secret must not appear in YAML output; output was:\n{yaml}"
        );
        // Also check the serialised stanza JSON
        let json_out = serde_json::to_string(&result).unwrap();
        assert!(
            !json_out.contains(secret),
            "secret must not appear in JSON result; output was:\n{json_out}"
        );
        assert!(
            result.sensitive_fields_dropped >= 2,
            "should report at least 2 dropped fields; got {}",
            result.sensitive_fields_dropped
        );
    }

    // ── import_config — models.providers ──────────────────────────

    #[test]
    fn import_config_parses_models_providers_array() {
        let json = serde_json::json!([
            { "id": "p1", "kind": "gemini", "api_key": "SHOULD_DROP" },
            { "id": "p2", "kind": "openai-compat", "base_url": "http://localhost:11434/v1" },
            { "id": "p3", "kind": "unknown-future-gateway" }
        ])
        .to_string();
        let f = write_tmp(&json);
        let result = import_config(None, Some(f.path())).unwrap();

        let providers: Vec<&str> = result.stanzas.iter().map(|s| s.provider.as_str()).collect();
        assert!(providers.contains(&"gemini_api"));
        assert!(providers.contains(&"openai_compat"));
        // base_url preserved for openai-compat
        let compat = result
            .stanzas
            .iter()
            .find(|s| s.provider == "openai_compat")
            .unwrap();
        assert_eq!(compat.base_url.as_deref(), Some("http://localhost:11434/v1"));
        // unknown kind skipped
        assert!(
            result.skipped.contains(&"unknown-future-gateway".to_string()),
            "skipped list must contain unknown-future-gateway"
        );
    }

    #[test]
    fn import_config_deduplicates_same_provider_from_both_files() {
        // Both auth.profiles and models.providers declare openai — should
        // appear exactly once in stanzas.
        let auth_json = serde_json::json!({
            "work": { "provider": "openai", "api_key": "s1" }
        })
        .to_string();
        let models_json = serde_json::json!([
            { "id": "x", "kind": "openai", "api_key": "s2" }
        ])
        .to_string();
        let f1 = write_tmp(&auth_json);
        let f2 = write_tmp(&models_json);
        let result = import_config(Some(f1.path()), Some(f2.path())).unwrap();

        let openai_count = result
            .stanzas
            .iter()
            .filter(|s| s.provider == "openai_api")
            .count();
        assert_eq!(openai_count, 1, "openai_api must appear exactly once");
        // Both files had sensitive fields
        assert!(result.sensitive_fields_dropped >= 2);
    }

    #[test]
    fn import_config_errors_when_no_paths_given() {
        let err = import_config(None, None).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn import_config_errors_on_missing_file() {
        let err = import_config(Some(Path::new("/nonexistent/auth.json")), None).unwrap_err();
        assert!(err.to_string().contains("auth.profiles"));
    }

    #[test]
    fn import_config_errors_on_malformed_json() {
        let f = write_tmp("not json at all {{{");
        let err = import_config(Some(f.path()), None).unwrap_err();
        assert!(err.to_string().contains("auth.profiles"));
    }

    // ── render_yaml ───────────────────────────────────────────────

    #[test]
    fn render_yaml_contains_required_header_comment() {
        let result = ImportConfigResult {
            stanzas: vec![NeothProviderStanza {
                provider: "claude_cli".to_string(),
                base_url: None,
                note: "OAuth via `claude` CLI — no API key required. Run `claude login` if not already authenticated.".to_string(),
            }],
            skipped: vec![],
            sensitive_fields_dropped: 0,
        };
        let yaml = render_yaml(&result);
        assert!(
            yaml.contains("credentials.yaml"),
            "YAML must reference credentials.yaml"
        );
        assert!(
            yaml.contains("NEVER"),
            "YAML must contain NEVER warning about keys"
        );
        assert!(yaml.contains("claude_cli"));
    }

    #[test]
    fn render_yaml_includes_skipped_section_when_nonempty() {
        let result = ImportConfigResult {
            stanzas: vec![],
            skipped: vec!["mystery-gateway".to_string()],
            sensitive_fields_dropped: 0,
        };
        let yaml = render_yaml(&result);
        assert!(yaml.contains("mystery-gateway"));
        assert!(yaml.contains("not recognised"));
    }

    #[test]
    fn render_yaml_includes_base_url_for_openai_compat() {
        let result = ImportConfigResult {
            stanzas: vec![NeothProviderStanza {
                provider: "openai_compat".to_string(),
                base_url: Some("http://localhost:11434/v1".to_string()),
                note: "Add your API key to credentials.yaml".to_string(),
            }],
            skipped: vec![],
            sensitive_fields_dropped: 0,
        };
        let yaml = render_yaml(&result);
        assert!(yaml.contains("base_url"));
        assert!(yaml.contains("localhost:11434"));
    }

    // ── Full round-trip fixture test ──────────────────────────────

    #[test]
    fn full_round_trip_fixture_openclaw_config_to_provider_stanzas() {
        // Simulates a realistic OpenClaw auth.profiles + models.providers
        // pair.  Asserts: correct stanzas emitted, no key bytes leak,
        // unknown kinds in skipped list.
        let secret_key = "sk-ant-api03-FIXTURE_SECRET_XYZ";
        let auth_json = serde_json::json!({
            "claude_subscription": {
                "provider": "claude-cli",
                "display_name": "Claude (subscription)"
            },
            "gemini_pro": {
                "provider": "gemini",
                "api_key": secret_key,
                "token": "tok_fixture"
            }
        })
        .to_string();
        let models_json = serde_json::json!([
            {
                "id": "openai-main",
                "kind": "openai",
                "api_key": secret_key,
                "base_url": "https://api.openai.com/v1"
            },
            {
                "id": "local-lm",
                "kind": "openai-compat",
                "base_url": "http://127.0.0.1:1234/v1"
            },
            {
                "id": "legacy-hermes",
                "kind": "hermes-gateway",
                "password": "pw_fixture"
            }
        ])
        .to_string();

        let f_auth = write_tmp(&auth_json);
        let f_models = write_tmp(&models_json);
        let result = import_config(Some(f_auth.path()), Some(f_models.path())).unwrap();
        let yaml = render_yaml(&result);

        // Correct stanzas
        let providers: Vec<&str> = result.stanzas.iter().map(|s| s.provider.as_str()).collect();
        assert!(providers.contains(&"claude_cli"), "claude_cli missing");
        assert!(providers.contains(&"gemini_api"), "gemini_api missing");
        assert!(providers.contains(&"openai_api"), "openai_api missing");
        assert!(providers.contains(&"openai_compat"), "openai_compat missing");

        // Unknown kind is skipped
        assert!(
            result.skipped.contains(&"hermes-gateway".to_string()),
            "hermes-gateway must be in skipped; got {:?}",
            result.skipped
        );

        // No secret bytes in YAML or JSON
        assert!(
            !yaml.contains(secret_key),
            "secret_key must not appear in YAML; output:\n{yaml}"
        );
        let json_out = serde_json::to_string(&result).unwrap();
        assert!(
            !json_out.contains(secret_key),
            "secret_key must not appear in JSON; output:\n{json_out}"
        );
        assert!(
            !yaml.contains("tok_fixture"),
            "token must not appear in YAML"
        );
        assert!(!yaml.contains("pw_fixture"), "password must not appear in YAML");

        // Sensitive fields were counted
        assert!(
            result.sensitive_fields_dropped >= 4,
            "expected >=4 dropped fields (api_key×2, token, password); got {}",
            result.sensitive_fields_dropped
        );

        // base_url preserved for openai-compat
        let compat = result
            .stanzas
            .iter()
            .find(|s| s.provider == "openai_compat")
            .unwrap();
        assert_eq!(
            compat.base_url.as_deref(),
            Some("http://127.0.0.1:1234/v1")
        );
    }
}
