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
    /// Free-form per-connector options. Recognised keys today:
    ///   - `local_root` — absolute path to the operator's cloud-
    ///     vendor-desktop-client synced folder. When set, the
    ///     connector reads/writes that folder directly via
    ///     OpenDAL services-fs (R-8 Session 19); the vendor's
    ///     desktop client handles upstream sync.
    ///
    /// Forward-compat: future per-provider tunables (chunk size,
    /// rate limit, etc.) land here without changing the trait.
    #[serde(default)]
    pub connector_options: Option<std::collections::HashMap<String, String>>,
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

/// Build a connector for the given config. For providers with a
/// real wire today (currently the cloud-vendor-desktop-app sync
/// pattern via the local-fs OpenDAL backend), returns a live
/// connector; the remaining providers fall back to the stub that
/// bails with a clear deferred message.
///
/// The local-fs path lets an operator point NEOTH at the synced
/// folder of their Dropbox / OneDrive / GDrive / iCloud desktop
/// client. The desktop client owns OAuth + upstream sync; NEOTH
/// just reads + writes the local mirror. This was the explicit
/// arch-v2 stance ("cloud auth + transport are owned by the
/// cloud vendor's desktop client, NEOTH stays out of it").
pub fn connector_for(cfg: &CloudConfig) -> Result<Box<dyn CloudConnector>> {
    if let Some(root) = local_mirror_root(cfg) {
        return Ok(Box::new(LocalFsConnector::new(cfg.provider, root)?));
    }
    Ok(Box::new(StubConnector {
        provider: cfg.provider,
    }))
}

/// Pull the local mirror root from a CloudConfig. Operators set
/// `local_root: /home/alice/Dropbox` (or the platform equivalent)
/// in `cloud_sources.yaml`; absent → the connector falls back to
/// stub mode. CloudConfig's serde shape carries this in a
/// `connector_options` map for forward-compat with per-provider
/// extras.
fn local_mirror_root(cfg: &CloudConfig) -> Option<std::path::PathBuf> {
    cfg.connector_options
        .as_ref()
        .and_then(|m| m.get("local_root"))
        .map(std::path::PathBuf::from)
}

/// Returns true when the provider has a real implementation
/// reachable today. With OpenDAL services-fs live, every provider
/// can run in local-mirror mode when the operator points NEOTH at
/// the desktop client's synced folder.
pub fn is_live(_provider: Provider) -> bool {
    true
}

/// R2-P2-1 honesty surface (2026-05-22 Session 20). Classifies a
/// CloudConfig as one of:
///
/// - `LocalMirror` — `connector_options.local_root` is set; the
///   operator's desktop client (Dropbox / OneDrive / GDrive) owns
///   OAuth + upstream sync, NEOTH reads/writes the local mirror.
///   This is what NEOTH actually ships today.
/// - `StubFallback` — provider is configured but no `local_root`
///   pointer; runtime calls bail with the deferred message. README
///   must NOT advertise this as a live connector.
///
/// Used by `cli::doctor::check_cloud_archive_dest` to render
/// honest status instead of the prior "Pass when configured"
/// flattening. Pure function; no I/O.
pub fn connector_mode_of(cfg: &CloudConfig) -> ConnectorMode {
    if local_mirror_root(cfg).is_some() {
        ConnectorMode::LocalMirror
    } else {
        ConnectorMode::StubFallback
    }
}

/// R2-P2-1: surfaceable classification for `cli doctor` / GUI
/// settings render. Operator-readable wire form via [`ConnectorMode::as_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorMode {
    LocalMirror,
    StubFallback,
}

impl ConnectorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectorMode::LocalMirror => "local-mirror",
            ConnectorMode::StubFallback => "stub-fallback",
        }
    }
}

/// Live connector against a local filesystem root, powered by
/// OpenDAL services-fs. The R-8 Phase-3 dep block lifted in
/// Session 19 (2026-05-21) — opendal 0.56 ships pure-Rust without
/// the prior C-dep entanglements.
struct LocalFsConnector {
    provider: Provider,
    op: opendal::blocking::Operator,
}

impl LocalFsConnector {
    fn new(provider: Provider, root: std::path::PathBuf) -> Result<Self> {
        let root_str = root
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF8 local_root path: {}", root.display()))?;
        let builder = opendal::services::Fs::default().root(root_str);
        let async_op = opendal::Operator::new(builder)
            .with_context(|| format!("build OpenDAL fs operator at {}", root.display()))?
            .finish();
        let op = opendal::blocking::Operator::new(async_op)
            .context("wrap async OpenDAL operator in blocking shim")?;
        Ok(Self { provider, op })
    }
}

impl CloudConnector for LocalFsConnector {
    fn provider(&self) -> Provider {
        self.provider
    }

    fn list(&self, prefix: &str) -> Result<Vec<CloudFile>> {
        let entries = self
            .op
            .list(prefix)
            .with_context(|| format!("opendal list prefix={prefix}"))?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let path = entry.path().to_string();
            // OpenDAL emits a directory marker for the prefix
            // itself; skip so the caller doesn't see "" as a file.
            if path.is_empty() || path == prefix {
                continue;
            }
            let stat = self
                .op
                .stat(&path)
                .with_context(|| format!("opendal stat {path}"))?;
            // R2-P2-1 (2026-05-22 Session 20): populate modified_unix
            // from opendal's `last_modified` instead of dumping 0.
            // Reviewer flagged "modified_unix is im LocalFsConnector
            // aktuell immer 0" — the dedupe path was falling back to
            // size+path because of it. Now the LocalFsConnector
            // surfaces the actual mtime, matching what `stat()`
            // returns from the OS.
            let modified_unix = stat
                .last_modified()
                .map(|t| t.into_inner().as_second())
                .unwrap_or(0);
            out.push(CloudFile {
                path,
                size_bytes: stat.content_length(),
                modified_unix,
                provider: self.provider,
            });
        }
        Ok(out)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let buf = self
            .op
            .read(path)
            .with_context(|| format!("opendal read {path}"))?;
        Ok(buf.to_vec())
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        self.op
            .write(path, bytes.to_vec())
            .with_context(|| format!("opendal write {path}"))?;
        Ok(())
    }
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
            connector_options: None,
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
            connector_options: None,
        };
        let conn = connector_for(&cfg).unwrap();
        let err = conn.write("/foo", b"x").unwrap_err().to_string();
        // The stub's `read`/`list` deferred-message fires before
        // the `write` fallback, but the default-impl write reaches
        // the bail when explicitly overridden — pin the path here.
        assert!(err.contains("gmail"));
    }

    #[test]
    fn is_live_returns_true_now_that_opendal_local_fs_landed() {
        // R-8 Session 19 (2026-05-21): is_live flipped to true
        // across all providers because the LocalFsConnector path
        // works for every provider when the operator's desktop
        // client mirrors that provider to a local folder. Future
        // per-provider OAuth direct-API impls keep is_live=true;
        // pin the status here.
        for p in [
            Provider::Dropbox,
            Provider::OneDrive,
            Provider::GoogleDrive,
            Provider::GoogleCloudStorage,
            Provider::ICloud,
            Provider::Gmail,
        ] {
            assert!(is_live(p), "{} unexpectedly stub", p.as_str());
        }
    }

    // ── R-8 LocalFsConnector round-trip (Session 19) ────────────────

    fn cfg_with_local_root(provider: Provider, root: &std::path::Path) -> CloudConfig {
        let mut opts = std::collections::HashMap::new();
        opts.insert(
            "local_root".to_string(),
            root.to_string_lossy().into_owned(),
        );
        CloudConfig {
            provider,
            oauth_token: String::new(),
            root_path: "/".into(),
            label: None,
            connector_options: Some(opts),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_fs_connector_round_trip_write_read_list() {
        // OpenDAL's blocking shim spawns its own runtime; running
        // it inside a single-threaded tokio runtime panics with
        // "cannot start a runtime from within a runtime". We bridge
        // via spawn_blocking so the shim runs on a worker thread
        // outside the active runtime context. Daemon code paths
        // already wrap CloudConnector calls in spawn_blocking per
        // the trait doc-comment.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let entries = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<CloudFile>> {
            let cfg = {
                let mut opts = std::collections::HashMap::new();
                opts.insert(
                    "local_root".to_string(),
                    root.to_string_lossy().into_owned(),
                );
                CloudConfig {
                    provider: Provider::Dropbox,
                    oauth_token: String::new(),
                    root_path: "/".into(),
                    label: None,
                    connector_options: Some(opts),
                }
            };
            let conn = connector_for(&cfg)?;
            assert_eq!(conn.provider(), Provider::Dropbox);
            conn.write("hello.txt", b"world!")?;
            let got = conn.read("hello.txt")?;
            assert_eq!(got, b"world!");
            conn.list("/")
        })
        .await
        .unwrap()
        .unwrap();

        assert!(
            entries.iter().any(|e| e.path.contains("hello.txt")),
            "list must surface hello.txt; got {entries:?}"
        );
        let row = entries
            .iter()
            .find(|e| e.path.contains("hello.txt"))
            .unwrap();
        assert_eq!(row.size_bytes, 6);
        assert_eq!(row.provider, Provider::Dropbox);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_fs_connector_handles_missing_path_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let err = tokio::task::spawn_blocking(move || {
            let cfg = {
                let mut opts = std::collections::HashMap::new();
                opts.insert(
                    "local_root".to_string(),
                    root.to_string_lossy().into_owned(),
                );
                CloudConfig {
                    provider: Provider::OneDrive,
                    oauth_token: String::new(),
                    root_path: "/".into(),
                    label: None,
                    connector_options: Some(opts),
                }
            };
            let conn = connector_for(&cfg).unwrap();
            conn.read("does_not_exist.txt").unwrap_err().to_string()
        })
        .await
        .unwrap();
        assert!(
            err.contains("opendal read") || err.contains("does_not_exist"),
            "diagnostic must name the operation/path: {err}"
        );
    }

    #[test]
    fn connector_for_falls_back_to_stub_when_no_local_root() {
        // Backward compat: cloud_sources.yaml rows without
        // connector_options still route to the stub.
        let cfg = CloudConfig {
            provider: Provider::Gmail,
            oauth_token: "x".into(),
            root_path: "/".into(),
            label: None,
            connector_options: None,
        };
        let conn = connector_for(&cfg).unwrap();
        let err = conn.list("/").unwrap_err().to_string();
        assert!(err.contains("OpenDAL"), "stub fired: {err}");
    }

    // ── R2-P2-1 modified_unix + connector_mode tests ─────────────────────

    #[tokio::test]
    async fn r2_p2_1_modified_unix_populated_from_local_fs_mtime() {
        // Pre-fix the LocalFsConnector dumped modified_unix=0. Now it
        // pulls the actual mtime from OpenDAL via jiff::Timestamp.
        // Operators relying on size+mtime dedupe get the real signal.
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let err = tokio::task::spawn_blocking(move || -> Result<i64> {
            let dir = tempfile::tempdir().unwrap();
            let file_path = dir.path().join("fixture.txt");
            std::fs::write(&file_path, b"hello").unwrap();
            let mut opts = std::collections::HashMap::new();
            opts.insert(
                "local_root".to_string(),
                dir.path().to_string_lossy().into_owned(),
            );
            let cfg = CloudConfig {
                provider: Provider::Dropbox,
                oauth_token: "n/a".into(),
                root_path: "/".into(),
                label: None,
                connector_options: Some(opts),
            };
            let conn = connector_for(&cfg).unwrap();
            let entries = conn.list("/").unwrap();
            let fixture = entries
                .into_iter()
                .find(|e| e.path.ends_with("fixture.txt"))
                .expect("fixture in listing");
            Ok(fixture.modified_unix)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(
            err > 0,
            "R2-P2-1: modified_unix must be populated, got {err}"
        );
        // Sanity: should be within ~1h of "now" since we just wrote it
        // (allows for slow CI clocks).
        let diff = (err - now_unix).unsigned_abs();
        assert!(
            diff < 3600,
            "R2-P2-1: modified_unix {err} too far from now {now_unix}"
        );
    }

    #[test]
    fn r2_p2_1_connector_mode_classifies_local_mirror_vs_stub() {
        // Operator pointed at desktop-client synced folder →
        // LocalMirror. Operator configured the row but didn't set
        // local_root → StubFallback. Honest classification feeds the
        // doctor + GUI settings render.
        let with_root = CloudConfig {
            provider: Provider::Dropbox,
            oauth_token: "x".into(),
            root_path: "/".into(),
            label: None,
            connector_options: Some({
                let mut m = std::collections::HashMap::new();
                m.insert("local_root".to_string(), "/tmp/mirror".to_string());
                m
            }),
        };
        assert_eq!(connector_mode_of(&with_root), ConnectorMode::LocalMirror);
        assert_eq!(connector_mode_of(&with_root).as_str(), "local-mirror");

        let without_root = CloudConfig {
            provider: Provider::Gmail,
            oauth_token: "x".into(),
            root_path: "/".into(),
            label: None,
            connector_options: None,
        };
        assert_eq!(
            connector_mode_of(&without_root),
            ConnectorMode::StubFallback
        );
        assert_eq!(connector_mode_of(&without_root).as_str(), "stub-fallback");
    }
}
