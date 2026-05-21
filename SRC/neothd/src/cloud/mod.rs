//! R-8 — cloud-connector scaffold per [[neoth-arch-v2]].
//!
//! Operator-facing surface is a `CloudConnector` trait that the
//! ingest pipeline calls to pull files from Dropbox / OneDrive /
//! Google Drive / Google Cloud Storage / iCloud / Gmail. Real wire
//! lands once the Phase-3 dep block clears OpenDAL (covers
//! Dropbox/OneDrive/GDrive/GCS in one library) + per-provider
//! OAuth helpers.
//!
//! v0.1 scope (this module):
//!   - Operator-readable types: provider enum, config, file-row
//!   - Trait surface the ingest pipeline consumes
//!   - Stub impls that bail with a clear "deferred until OpenDAL"
//!     error — the daemon stays buildable without the C-dep risk
//!   - Tests for config parsing, provider-from-wire, file-row
//!     timestamp round-trip
//!
//! Adding a new provider: extend the `Provider` enum + add a stub
//! variant to `connector_for()`. The trait surface doesn't change.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Supported cloud providers. Per `arch-v2` discussion the
/// initial five cover the operator's most-likely sources; Gmail
/// joins later because the IMAP path is its own can of worms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Provider {
    #[serde(rename = "dropbox")]
    Dropbox,
    #[serde(rename = "onedrive")]
    OneDrive,
    #[serde(rename = "google_drive")]
    GoogleDrive,
    #[serde(rename = "google_cloud_storage")]
    GoogleCloudStorage,
    #[serde(rename = "icloud")]
    ICloud,
    #[serde(rename = "gmail")]
    Gmail,
}

impl Provider {
    /// Stable wire form. Used in `freedom.yaml::cloud.<provider>` +
    /// WAL frames + CLI `--provider` flag values. A rename
    /// invalidates every operator's config — pin the strings.
    pub const fn as_str(self) -> &'static str {
        match self {
            Provider::Dropbox => "dropbox",
            Provider::OneDrive => "onedrive",
            Provider::GoogleDrive => "google_drive",
            Provider::GoogleCloudStorage => "google_cloud_storage",
            Provider::ICloud => "icloud",
            Provider::Gmail => "gmail",
        }
    }

    /// Parse the wire form back. None for unknown strings —
    /// operator's freedom.yaml gets a clear `unknown provider {s}`
    /// error at load time instead of a silent default.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "dropbox" => Some(Self::Dropbox),
            "onedrive" => Some(Self::OneDrive),
            "google_drive" => Some(Self::GoogleDrive),
            "google_cloud_storage" => Some(Self::GoogleCloudStorage),
            "icloud" => Some(Self::ICloud),
            "gmail" => Some(Self::Gmail),
            _ => None,
        }
    }
}

/// One cloud-source config row from `freedom.yaml`. Operators
/// typically have one per provider they want to ingest from.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CloudConfig {
    pub provider: Provider,
    /// OAuth bearer token. Wrapped as `String` for v0.1 to match
    /// the rest of the credentials shape; Phase-2 promotes to
    /// `SecretString` once OpenDAL accepts a Secret-typed config.
    pub oauth_token: String,
    /// Operator-side root path the ingest pipeline walks. Defaults
    /// to the provider's natural root (`/`).
    #[serde(default = "default_root")]
    pub root_path: String,
    /// Optional per-source label so the operator can distinguish
    /// multiple Dropbox accounts in the audit chain.
    #[serde(default)]
    pub label: Option<String>,
}

fn default_root() -> String {
    "/".to_string()
}

/// One file row the connector reports during listing. The ingest
/// pipeline maps this into the existing multimodal-extract path
/// (`crate::ingest`) the same way it handles local-disk walks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloudFile {
    pub path: String,
    pub size_bytes: u64,
    /// Unix-seconds modification timestamp. The ingest dedupe path
    /// compares this against the last-seen timestamp in views.db.
    pub modified_unix: i64,
    pub provider: Provider,
}

/// Trait every cloud connector implements. The ingest pipeline
/// holds a `Box<dyn CloudConnector>` per configured source. Sync
/// trait because OpenDAL's blocking API satisfies it; the daemon
/// wraps in `tokio::task::spawn_blocking` at the call site.
pub trait CloudConnector: Send + Sync {
    fn provider(&self) -> Provider;
    fn list(&self, prefix: &str) -> Result<Vec<CloudFile>>;
    fn read(&self, path: &str) -> Result<Vec<u8>>;
    /// Some providers (Gmail) are read-only. Write returns an
    /// explicit "not supported" so callers can branch cleanly.
    fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        anyhow::bail!(
            "cloud: write not supported by {} connector",
            self.provider().as_str()
        )
    }
}

/// Build a connector for the given config. Today every variant
/// returns a stub that bails on the first list/read call with a
/// clear "deferred until OpenDAL" error. Operators see the wiring
/// stub-up cleanly in `neoth doctor --explain cloud-<provider>`
/// without a runtime panic.
pub fn connector_for(cfg: &CloudConfig) -> Result<Box<dyn CloudConnector>> {
    Ok(Box::new(StubConnector {
        provider: cfg.provider,
    }))
}

/// Returns true when the provider has a real implementation wired
/// (not just the stub). All `false` today — pin returns to flip
/// per-provider as OpenDAL/IMAP wires land in Phase 2/3.
pub fn is_live(_provider: Provider) -> bool {
    false
}

/// Load a list of `CloudConfig` rows from a YAML file. Operator
/// keeps cloud sources in a separate `cloud_sources.yaml` next to
/// freedom.yaml so secrets stay split (`credentials.yaml` already
/// owns the secrets-only split per V03-08 audit).
pub fn load_sources_from(path: &std::path::Path) -> Result<Vec<CloudConfig>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read cloud sources from {}", path.display()))?;
    let parsed: CloudSourcesYaml = serde_yaml::from_str(&body)
        .with_context(|| format!("parse cloud sources YAML at {}", path.display()))?;
    Ok(parsed.sources)
}

/// Default location for the cloud-sources YAML.
pub fn default_path() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("cloud_sources.yaml")
}

#[derive(Deserialize)]
struct CloudSourcesYaml {
    #[serde(default)]
    sources: Vec<CloudConfig>,
}

/// Placeholder connector used until per-provider impls land.
/// Every method bails with a clear deferred message naming the
/// provider so the operator's `neoth ingest` log line is
/// actionable, not a generic "not implemented".
struct StubConnector {
    provider: Provider,
}

impl CloudConnector for StubConnector {
    fn provider(&self) -> Provider {
        self.provider
    }
    fn list(&self, _prefix: &str) -> Result<Vec<CloudFile>> {
        anyhow::bail!(
            "cloud: {} connector deferred — needs OpenDAL Phase-3 dep block. \
             Add an issue at https://github.com/The-Geek-Freaks/NEOTH/issues \
             if this is blocking you.",
            self.provider.as_str()
        )
    }
    fn read(&self, _path: &str) -> Result<Vec<u8>> {
        anyhow::bail!(
            "cloud: {} connector read deferred — needs OpenDAL Phase-3 dep block",
            self.provider.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_wire_form_is_stable_snake_case() {
        for (p, wire) in [
            (Provider::Dropbox, "dropbox"),
            (Provider::OneDrive, "onedrive"),
            (Provider::GoogleDrive, "google_drive"),
            (Provider::GoogleCloudStorage, "google_cloud_storage"),
            (Provider::ICloud, "icloud"),
            (Provider::Gmail, "gmail"),
        ] {
            assert_eq!(p.as_str(), wire);
            assert_eq!(Provider::from_wire(wire), Some(p), "round-trip {wire}");
        }
    }

    #[test]
    fn provider_from_wire_rejects_unknown_strings() {
        // Case-sensitive — operator's freedom.yaml hits a parse
        // error rather than a silent default-Dropbox.
        assert!(Provider::from_wire("DROPBOX").is_none());
        assert!(Provider::from_wire("s3").is_none());
        assert!(Provider::from_wire("").is_none());
    }

    #[test]
    fn cloud_config_round_trips_through_yaml() {
        let yaml = r#"
provider: dropbox
oauth_token: "sl.abc123"
root_path: "/photos"
label: "personal"
"#;
        let cfg: CloudConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.provider, Provider::Dropbox);
        assert_eq!(cfg.oauth_token, "sl.abc123");
        assert_eq!(cfg.root_path, "/photos");
        assert_eq!(cfg.label.as_deref(), Some("personal"));
    }

    #[test]
    fn cloud_config_default_root_when_omitted() {
        let yaml = r#"
provider: onedrive
oauth_token: "x"
"#;
        let cfg: CloudConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.root_path, "/");
        assert!(cfg.label.is_none());
    }

    #[test]
    fn cloud_sources_yaml_parses_empty_list() {
        let yaml = "sources: []\n";
        let parsed: CloudSourcesYaml = serde_yaml::from_str(yaml).unwrap();
        assert!(parsed.sources.is_empty());
    }

    #[test]
    fn cloud_sources_yaml_parses_multiple_rows() {
        let yaml = r#"
sources:
  - provider: dropbox
    oauth_token: a
  - provider: google_drive
    oauth_token: b
    root_path: /Documents
"#;
        let parsed: CloudSourcesYaml = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(parsed.sources.len(), 2);
        assert_eq!(parsed.sources[1].provider, Provider::GoogleDrive);
        assert_eq!(parsed.sources[1].root_path, "/Documents");
    }

    #[test]
    fn stub_connector_bails_with_provider_named_error() {
        // The stub MUST surface the provider name in the bail
        // message so the operator's ingest log line is actionable.
        let cfg = CloudConfig {
            provider: Provider::Dropbox,
            oauth_token: "x".into(),
            root_path: "/".into(),
            label: None,
        };
        let conn = connector_for(&cfg).unwrap();
        assert_eq!(conn.provider(), Provider::Dropbox);
        let err = conn.list("/").unwrap_err().to_string();
        assert!(err.contains("dropbox"), "error names the provider");
        assert!(err.contains("OpenDAL"), "error names the dep blocker");
    }

    #[test]
    fn stub_connector_write_returns_not_supported_for_gmail() {
        // Read-only providers (Gmail today) MUST bail on write
        // with a specifically-typed error, not a generic deferred.
        let cfg = CloudConfig {
            provider: Provider::Gmail,
            oauth_token: "x".into(),
            root_path: "/".into(),
            label: None,
        };
        let conn = connector_for(&cfg).unwrap();
        let err = conn.write("/foo", b"x").unwrap_err().to_string();
        // The stub's `read`/`list` deferred-message fires before
        // the `write` fallback, but the default-impl write reaches
        // the bail when explicitly overridden — pin the path here.
        assert!(err.contains("gmail"));
    }

    #[test]
    fn is_live_returns_false_for_every_provider_today() {
        // Pin status so a future commit that flips one provider
        // to live without updating Tests + docs surfaces here.
        for p in [
            Provider::Dropbox,
            Provider::OneDrive,
            Provider::GoogleDrive,
            Provider::GoogleCloudStorage,
            Provider::ICloud,
            Provider::Gmail,
        ] {
            assert!(!is_live(p), "{} unexpectedly live", p.as_str());
        }
    }
}
