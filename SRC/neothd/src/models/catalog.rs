//! On-disk model catalog at `~/.neoth/models_catalog.json`.
//!
//! The catalog is plain JSON (not a SQLite view) because:
//!   - It is small (low hundreds of KB at the absolute most)
//!   - It is human-readable, so operators can hand-inspect what NEOTH
//!     thinks is current without firing a SQL query
//!   - It is rewritten atomically once per day, so write contention is
//!     non-existent
//!
//! Lifecycle:
//!   - **Load**: lazy on first read. Missing file → empty catalog
//!     (every provider reports `is_fresh() == false` so a refresh
//!     fires).
//!   - **Save**: atomic temp-then-rename, mode 0600 on POSIX,
//!     mirrors `cli::init` write_atomically + win_acl semantics.
//!   - **Freshness**: a per-provider `fetched_at_unix` + global TTL
//!     (default 24h). Stale slots are not deleted — the catalog
//!     keeps them around so `neoth models list --stale` can show the
//!     operator what's missing, and so a transient API outage
//!     doesn't wipe the operator's wizard select options.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Operator-defined short-form aliases for model ids.
///
/// Lives in `freedom.yaml` under `models.aliases: { "fast": "gpt-5.5", ... }`.
/// Aliases resolve BEFORE catalog validation so the alias itself never appears
/// in the catalog — only the real model id does. Aliases never shadow real model
/// ids: if an operator sets `alias = "gpt-5.5"` the alias is dead but harmless.
pub type ModelAliasMap = BTreeMap<String, String>;

/// Wire-format version. Bump when a non-backwards-compatible change
/// lands in the on-disk shape; older catalogs are then dropped on
/// load with a warn log.
pub const CATALOG_VERSION: u32 = 1;

/// Default freshness window — 24 hours. Operators with constrained
/// quota can dial this up via `freedom.yaml::models.ttl_secs`; the
/// catalog tolerates arbitrarily long TTLs.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// Filename of the on-disk catalog inside `~/.neoth/`.
pub const CATALOG_FILE: &str = "models_catalog.json";

/// Where this provider catalog was sourced from. Surfaced in
/// `neoth models show` so operators know whether the entry came
/// from a live CLI exec (most authoritative) or a REST list-models
/// call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceOrigin {
    /// `claude --models` / `gemini --models` / similar CLI-pull. Most
    /// trusted: the OAuth CLI has its own auth + service-side
    /// resolution.
    Cli,
    /// Provider REST `/v1/models` (or equivalent) endpoint. Needs an
    /// API key in [`crate::config::credentials`] / `freedom.yaml`.
    Api,
    /// Fallback hand-curated baseline shipped with NEOTH so the
    /// wizard always has SOMETHING to render in air-gapped /
    /// no-network setups. Bumped manually when the operator-facing
    /// defaults rot too far ahead of a discovery run.
    #[default]
    Bundled,
}

/// One model entry inside a provider catalog. Minimal field set —
/// the wizard only needs name + id + a one-line operator-readable
/// description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    /// API model identifier — exactly what NEOTH writes into
    /// `freedom.yaml::provider_model`. Example:
    /// `anthropic.claude-opus-4-7`, `gpt-5.5`,
    /// `gemini-3.1-pro-preview`.
    pub id: String,
    /// Operator-readable label. May coincide with `id` for providers
    /// that don't surface a separate display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// One-line description as returned by the provider (capability
    /// tier, special flags, etc.). Truncated to 200 chars on
    /// insertion so a verbose provider doesn't bloat the catalog.
    #[serde(default)]
    pub summary: Option<String>,
    /// Whether the provider flagged this model as deprecated /
    /// scheduled for sunset. NEOTH hides deprecated entries from
    /// the wizard's primary select but still surfaces them under
    /// `neoth models list --include-deprecated`.
    #[serde(default)]
    pub deprecated: bool,
}

impl ModelEntry {
    /// Convenience constructor used by [`sources`] implementations.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display_name: None,
            summary: None,
            deprecated: false,
        }
    }

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        let raw = summary.into();
        // Clamp to 200 chars to keep the catalog small. UTF-8 safe via
        // char_indices.
        let clamped = if raw.chars().count() > 200 {
            let cut = raw
                .char_indices()
                .nth(200)
                .map(|(i, _)| i)
                .unwrap_or(raw.len());
            format!("{}…", &raw[..cut])
        } else {
            raw
        };
        self.summary = Some(clamped);
        self
    }

    pub fn marked_deprecated(mut self) -> Self {
        self.deprecated = true;
        self
    }
}

/// All known models for one provider, plus the metadata needed to
/// decide whether a refresh fire.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCatalog {
    /// Unix-seconds of the last successful fetch. `0` (the default)
    /// flags the entry as "never fetched"; `is_fresh()` always
    /// returns false in that state.
    #[serde(default)]
    pub fetched_at_unix: u64,
    /// Where the entries came from — surfaced in
    /// `neoth models show <provider>`.
    #[serde(default = "default_source_origin")]
    pub source: SourceOrigin,
    /// Listed models, ordered by the provider's preference. The
    /// wizard renders the first non-deprecated entry as the
    /// default-selection.
    #[serde(default)]
    pub models: Vec<ModelEntry>,
    /// Error string from the most recent fetch attempt, or `None`
    /// when the last attempt succeeded. Surfaced by
    /// `neoth models show` so the operator sees WHY a provider is
    /// stale.
    #[serde(default)]
    pub last_error: Option<String>,
}

fn default_source_origin() -> SourceOrigin {
    SourceOrigin::Bundled
}

impl ProviderCatalog {
    /// True when the entry was fetched within `ttl_secs` of `now`.
    pub fn is_fresh(&self, now_unix: u64, ttl_secs: u64) -> bool {
        if self.fetched_at_unix == 0 {
            return false;
        }
        now_unix.saturating_sub(self.fetched_at_unix) < ttl_secs
    }

    /// Pick the first non-deprecated model as the recommended
    /// default. Returns `None` when the catalog is empty or every
    /// entry is deprecated.
    pub fn recommended_default(&self) -> Option<&ModelEntry> {
        self.models.iter().find(|m| !m.deprecated)
    }
}

/// Top-level on-disk shape. Keyed by NEOTH's `ProviderKind` snake_case
/// string ("openai_api", "gemini_api", "aws_bedrock", "claude_cli",
/// etc.) so callers in `cli::init` / `cli::catalog` can index by the
/// same identifier the rest of the daemon already uses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelsCatalog {
    /// Schema-version pin. Future incompatible changes bump this and
    /// older catalogs get dropped on load.
    #[serde(default = "default_catalog_version")]
    pub version: u32,
    /// Operator override for the freshness window (seconds). `None`
    /// → use [`DEFAULT_TTL_SECS`].
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Per-provider catalogs. Keyed by provider name string.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderCatalog>,
    /// Operator-defined model aliases loaded from
    /// `freedom.yaml::models.aliases`. Resolved by [`Self::resolve_alias`]
    /// before any catalog validation. Empty by default.
    ///
    /// Injected at load time by `cli::catalog` (or tests) — NOT persisted
    /// to `models_catalog.json` because aliases are operator config, not
    /// catalog data.
    #[serde(skip)]
    pub aliases: ModelAliasMap,
    /// The local path the catalog was loaded from. Skipped from
    /// serde so the file itself never embeds its own location.
    #[serde(skip)]
    path: Option<PathBuf>,
}

fn default_catalog_version() -> u32 {
    CATALOG_VERSION
}

/// Manual Default so a fresh in-memory catalog stamps the current
/// schema version. Derived `Default` would emit `version: 0`, which
/// `load_from` would then reject as a schema mismatch on the next
/// round-trip.
impl Default for ModelsCatalog {
    fn default() -> Self {
        Self {
            version: CATALOG_VERSION,
            ttl_secs: None,
            providers: BTreeMap::new(),
            aliases: ModelAliasMap::new(),
            path: None,
        }
    }
}

impl ModelsCatalog {
    /// Construct an in-memory catalog with no on-disk backing —
    /// useful for unit tests that want full isolation.
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Resolve the default on-disk path: `<home>/.neoth/<CATALOG_FILE>`.
    pub fn default_path(home: &Path) -> PathBuf {
        home.join(".neoth").join(CATALOG_FILE)
    }

    /// Load from disk. Missing file → empty catalog (NOT an error).
    /// Malformed JSON → warn-log + empty catalog. Wrong schema
    /// version → warn-log + empty catalog. The operator's wizard
    /// path keeps running with bundled defaults until the next
    /// refresh restocks the catalog.
    pub fn load_from(path: &Path) -> Self {
        let mut catalog: Self = match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(parsed) if parsed.version == CATALOG_VERSION => parsed,
                Ok(parsed) => {
                    tracing::warn!(
                        path = %path.display(),
                        loaded_version = parsed.version,
                        expected_version = CATALOG_VERSION,
                        "models_catalog.json schema mismatch — starting empty"
                    );
                    Self::default()
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "models_catalog.json malformed — starting empty"
                    );
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "models_catalog.json unreadable — starting empty"
                );
                Self::default()
            }
        };
        catalog.path = Some(path.to_path_buf());
        if catalog.version == 0 {
            catalog.version = CATALOG_VERSION;
        }
        catalog
    }

    /// Bind a path so a later [`Self::save`] knows where to write.
    /// Used by tests that want to round-trip through tempdirs.
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Inject operator aliases (from `freedom.yaml::models.aliases`).
    /// Aliases are runtime config, never written to disk.
    pub fn with_aliases(mut self, aliases: ModelAliasMap) -> Self {
        self.aliases = aliases;
        self
    }

    /// Resolve a model id through the alias layer.
    ///
    /// - If `model_id` matches a key in `self.aliases`, returns the
    ///   mapped real id.
    /// - If `model_id` is NOT an alias key, returns it unchanged —
    ///   real model ids pass through transparently.
    /// - Unknown alias: returns `Err` with a listing of configured aliases
    ///   so the operator sees what is available.
    ///
    /// Contract: aliases NEVER override real model ids. If an alias
    /// maps to an id that does not exist in the live catalog that is the
    /// provider's problem to surface at call time — not our job here.
    pub fn resolve_alias<'a>(&'a self, model_id: &'a str) -> Result<&'a str> {
        match self.aliases.get(model_id) {
            Some(real_id) => Ok(real_id.as_str()),
            None => {
                // Not found as an alias — it might be a literal model id.
                // Validate only if the alias map is non-empty: if the
                // operator configured aliases and the token is not among
                // them AND not among real catalog ids, surface an error.
                if self.aliases.is_empty() {
                    return Ok(model_id);
                }
                // Check whether it is a real model id in any provider.
                let is_real = self
                    .providers
                    .values()
                    .any(|pc| pc.models.iter().any(|m| m.id == model_id));
                if is_real || self.providers.is_empty() {
                    return Ok(model_id);
                }
                // Operator gave a token that is neither an alias nor a
                // known model id — tell them what aliases are available.
                let alias_list: Vec<&str> =
                    self.aliases.keys().map(String::as_str).collect();
                anyhow::bail!(
                    "unknown model alias or id {model_id:?}; \
                     configured aliases: {alias_list:?}"
                );
            }
        }
    }

    /// Persist atomically (temp + rename). No-op when the catalog has
    /// no path (in-memory mode). Parent directory created if absent.
    pub fn save(&self) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create catalog parent {}", parent.display()))?;
        }
        let body = serde_json::to_vec_pretty(self).context("serialize models_catalog.json")?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &body).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        // Mode-0600 on unix; Windows DACL handled at the parent dir.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    /// Read-only access to one provider's catalog.
    pub fn provider(&self, name: &str) -> Option<&ProviderCatalog> {
        self.providers.get(name)
    }

    /// Insert or replace one provider's catalog. Stamps `fetched_at_unix`
    /// with `now` and clears any prior `last_error`. Callers that want
    /// to record a fetch FAILURE should use [`Self::record_error`]
    /// instead.
    pub fn upsert(
        &mut self,
        name: impl Into<String>,
        source: SourceOrigin,
        models: Vec<ModelEntry>,
    ) {
        let name = name.into();
        self.providers.insert(
            name,
            ProviderCatalog {
                fetched_at_unix: now_unix(),
                source,
                models,
                last_error: None,
            },
        );
    }

    /// Record a failed fetch — leaves prior models intact (so the
    /// operator's wizard select still has options) but stamps the
    /// `last_error` field for telemetry.
    pub fn record_error(&mut self, name: impl Into<String>, error: impl Into<String>) {
        let name = name.into();
        let entry = self.providers.entry(name).or_default();
        entry.last_error = Some(error.into());
    }

    /// Effective TTL: operator override OR [`DEFAULT_TTL_SECS`].
    pub fn effective_ttl_secs(&self) -> u64 {
        self.ttl_secs.unwrap_or(DEFAULT_TTL_SECS)
    }

    /// Enumerate provider names that have NOT been refreshed within
    /// the TTL window. Used by the cron task + `neoth models refresh
    /// --stale-only`.
    pub fn stale_providers(&self, now_unix: u64) -> Vec<String> {
        let ttl = self.effective_ttl_secs();
        let mut stale: Vec<String> = self
            .providers
            .iter()
            .filter(|(_, pc)| !pc.is_fresh(now_unix, ttl))
            .map(|(name, _)| name.clone())
            .collect();
        stale.sort();
        stale
    }
}

/// Wall-clock unix seconds. Wraps `SystemTime` for ergonomics + test
/// stubbing. Aligned with `crate::providers::quota::now_unix`.
pub fn now_unix() -> u64 {
    crate::time::now_unix_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn entry(id: &str) -> ModelEntry {
        ModelEntry::new(id)
    }

    #[test]
    fn empty_catalog_round_trips_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let cat = ModelsCatalog::default().with_path(path.clone());
        cat.save().unwrap();

        let reloaded = ModelsCatalog::load_from(&path);
        assert_eq!(reloaded.version, CATALOG_VERSION);
        assert!(reloaded.providers.is_empty());
    }

    #[test]
    fn upsert_then_load_returns_same_provider_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut cat = ModelsCatalog::load_from(&path);
        cat.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![
                entry("claude-opus-4-7"),
                entry("claude-sonnet-4-6"),
                entry("claude-haiku-4-5-20251001"),
            ],
        );
        cat.save().unwrap();

        let reloaded = ModelsCatalog::load_from(&path);
        let provider = reloaded.provider("anthropic_api").unwrap();
        assert_eq!(provider.models.len(), 3);
        assert_eq!(provider.source, SourceOrigin::Api);
        assert_eq!(provider.models[0].id, "claude-opus-4-7");
    }

    #[test]
    fn missing_file_loads_empty_not_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does_not_exist.json");
        let cat = ModelsCatalog::load_from(&path);
        assert!(cat.providers.is_empty());
        assert_eq!(cat.version, CATALOG_VERSION);
    }

    #[test]
    fn malformed_json_loads_empty_not_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        let cat = ModelsCatalog::load_from(&path);
        assert!(cat.providers.is_empty());
    }

    #[test]
    fn wrong_schema_version_loads_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        // Schema version 999 — far in the future.
        std::fs::write(&path, br#"{"version":999,"ttl_secs":null,"providers":{}}"#).unwrap();
        let cat = ModelsCatalog::load_from(&path);
        // Loaded as empty so the operator's wizard still works with bundled defaults.
        assert!(cat.providers.is_empty());
    }

    #[test]
    fn is_fresh_uses_ttl_window() {
        let mut pc = ProviderCatalog::default();
        pc.fetched_at_unix = 1_000_000;
        assert!(pc.is_fresh(1_000_500, 1000), "within window");
        assert!(!pc.is_fresh(1_001_001, 1000), "just past window");
        assert!(!pc.is_fresh(2_000_000, 1000), "far past window");
    }

    #[test]
    fn never_fetched_is_never_fresh() {
        let pc = ProviderCatalog::default();
        // fetched_at_unix == 0; even with a generous TTL must return false.
        assert!(!pc.is_fresh(u64::MAX, u64::MAX));
    }

    #[test]
    fn recommended_default_skips_deprecated_entries() {
        let mut pc = ProviderCatalog::default();
        pc.models = vec![
            entry("gpt-5.1").marked_deprecated(),
            entry("gpt-5.4"),
            entry("gpt-5.5"),
        ];
        let recommended = pc.recommended_default().unwrap();
        assert_eq!(recommended.id, "gpt-5.4");
    }

    #[test]
    fn recommended_default_none_when_all_deprecated() {
        let mut pc = ProviderCatalog::default();
        pc.models = vec![
            entry("gpt-4o").marked_deprecated(),
            entry("gpt-4-turbo").marked_deprecated(),
        ];
        assert!(pc.recommended_default().is_none());
    }

    #[test]
    fn upsert_stamps_fetched_at_unix() {
        let mut cat = ModelsCatalog::default();
        cat.upsert("openai_api", SourceOrigin::Api, vec![entry("gpt-5.5")]);
        let p = cat.provider("openai_api").unwrap();
        assert!(p.fetched_at_unix > 0, "must stamp fetch time");
        assert!(p.last_error.is_none(), "happy path clears prior error");
    }

    #[test]
    fn record_error_preserves_existing_models() {
        let mut cat = ModelsCatalog::default();
        cat.upsert("openai_api", SourceOrigin::Api, vec![entry("gpt-5.5")]);
        cat.record_error("openai_api", "rate limited");
        let p = cat.provider("openai_api").unwrap();
        assert_eq!(p.models.len(), 1, "models from prior success preserved");
        assert_eq!(p.last_error.as_deref(), Some("rate limited"));
    }

    #[test]
    fn record_error_on_unknown_provider_creates_empty_entry() {
        let mut cat = ModelsCatalog::default();
        cat.record_error("never_seen", "401 unauthorized");
        let p = cat.provider("never_seen").unwrap();
        assert!(p.models.is_empty());
        assert_eq!(p.last_error.as_deref(), Some("401 unauthorized"));
    }

    #[test]
    fn stale_providers_lists_only_unfresh() {
        let mut cat = ModelsCatalog::default();
        cat.ttl_secs = Some(1000);

        let mut fresh = ProviderCatalog::default();
        fresh.fetched_at_unix = 1_000_000;
        let mut stale = ProviderCatalog::default();
        stale.fetched_at_unix = 1; // ancient
        let never = ProviderCatalog::default(); // fetched_at_unix == 0

        cat.providers.insert("fresh_p".into(), fresh);
        cat.providers.insert("stale_p".into(), stale);
        cat.providers.insert("never_p".into(), never);

        let list = cat.stale_providers(1_000_500);
        assert_eq!(list, vec!["never_p".to_string(), "stale_p".to_string()]);
    }

    #[test]
    fn effective_ttl_falls_back_to_default_when_unset() {
        let cat = ModelsCatalog::default();
        assert_eq!(cat.effective_ttl_secs(), DEFAULT_TTL_SECS);
    }

    #[test]
    fn effective_ttl_honours_operator_override() {
        let mut cat = ModelsCatalog::default();
        cat.ttl_secs = Some(3600);
        assert_eq!(cat.effective_ttl_secs(), 3600);
    }

    #[test]
    fn with_summary_clamps_long_strings() {
        let long = "x".repeat(500);
        let entry = ModelEntry::new("test-id").with_summary(&long);
        let summary = entry.summary.unwrap();
        // Clamped to 200 chars (+ the truncation marker).
        assert!(summary.chars().count() <= 201);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn with_summary_passes_through_short_strings() {
        let entry = ModelEntry::new("id").with_summary("short");
        assert_eq!(entry.summary.as_deref(), Some("short"));
    }

    #[test]
    fn default_path_is_under_neoth_subdir() {
        let home = Path::new("/tmp/fake_home");
        let path = ModelsCatalog::default_path(home);
        assert!(path.ends_with(".neoth/models_catalog.json"));
    }

    // ── alias map tests ───────────────────────────────────────────────────────

    fn alias_catalog() -> ModelsCatalog {
        let mut cat = ModelsCatalog::default();
        // Populate one provider with a real model id so resolve_alias can
        // distinguish "real id" from "unknown token" when the alias map is
        // non-empty.
        cat.upsert(
            "openai_api",
            SourceOrigin::Api,
            vec![entry("gpt-5.5"), entry("gpt-4o")],
        );
        let mut aliases = ModelAliasMap::new();
        aliases.insert("fast".to_string(), "gpt-5.5".to_string());
        aliases.insert("smart".to_string(), "gpt-4o".to_string());
        cat.with_aliases(aliases)
    }

    #[test]
    fn alias_resolves_to_real_model_id() {
        let cat = alias_catalog();
        assert_eq!(cat.resolve_alias("fast").unwrap(), "gpt-5.5");
        assert_eq!(cat.resolve_alias("smart").unwrap(), "gpt-4o");
    }

    #[test]
    fn real_model_id_passes_through_unchanged() {
        let cat = alias_catalog();
        // "gpt-5.5" is a real id in the catalog, not an alias key — passes.
        assert_eq!(cat.resolve_alias("gpt-5.5").unwrap(), "gpt-5.5");
    }

    #[test]
    fn unknown_alias_is_loud_error_listing_aliases() {
        let cat = alias_catalog();
        let err = cat.resolve_alias("turbo").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("turbo"),
            "error must mention the unknown token"
        );
        // Alias listing must appear so the operator knows what is valid.
        assert!(
            msg.contains("fast") || msg.contains("smart"),
            "error must list configured aliases: {msg}"
        );
    }

    #[test]
    fn empty_alias_map_passes_any_id_through() {
        // No aliases configured → every model_id is returned verbatim.
        let cat = ModelsCatalog::default();
        assert_eq!(
            cat.resolve_alias("some-future-model-xyz").unwrap(),
            "some-future-model-xyz"
        );
    }

    #[test]
    fn aliases_not_persisted_to_catalog_json() {
        // Aliases are runtime config — round-tripping through disk must drop them.
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut aliases = ModelAliasMap::new();
        aliases.insert("fast".into(), "gpt-5.5".into());
        let cat = ModelsCatalog::default()
            .with_path(path.clone())
            .with_aliases(aliases);
        cat.save().unwrap();

        // After reload the aliases field is empty (serde(skip)).
        let reloaded = ModelsCatalog::load_from(&path);
        assert!(
            reloaded.aliases.is_empty(),
            "aliases must not be written to or read from disk"
        );
    }
}
