//! WAL configuration — extracted from `config/mod.rs` as part of GOLD-ARCH-04.
//!
//! Contains `WalConfig`, `WalCompression`, and the standalone `wal:` stanza
//! loaders used by the WAL writer before the full `FreedomConfig` is parsed.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Workstream F (CT-10/E-20/V1x-06) — WAL compression policy.
///
/// Written by the wizard / operator into `freedom.yaml`. Consumed at segment
/// finalize time by the writer task. Default `compression = "none"` keeps
/// v0.1.x behaviour unchanged; flip to `"zstd_3"` in v0.2.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalConfig {
    /// Compression algorithm for newly-sealed segments.
    ///
    /// `"none"`   — v1 segments, no compression (v0.1.x default).
    /// `"zstd_3"` — v2 segments, zstd level-3 on the sealed frame body.
    ///
    /// Existing segments replay correctly regardless — the reader auto-detects
    /// header version and decompresses when the COMPRESSED flag is set.
    pub compression: WalCompression,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            compression: WalCompression::None,
        }
    }
}

/// Compression algorithm for WAL segments.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalCompression {
    /// No compression — v1 wire format (default for v0.1.x).
    #[default]
    None,
    /// zstd level-3 — v2 wire format with SEGMENT_FLAG_COMPRESSED.
    /// YAML key: `zstd_3` (explicit rename — snake_case would give `zstd3`).
    #[serde(rename = "zstd_3")]
    Zstd3,
}

/// Load the `wal:` sub-key from a `freedom.yaml` file.
///
/// Reads only the `wal:` stanza — does NOT parse the full `FreedomConfig`.
/// Returns `WalConfig::default()` (no compression) on any error so existing
/// operator setups with no `wal:` key keep working without changes.
pub fn load_wal_config(freedom_yaml_path: &Path) -> WalConfig {
    load_wal_config_strict(freedom_yaml_path).unwrap_or_default()
}

/// Like `load_wal_config` but surfaces parse errors.
pub fn load_wal_config_strict(freedom_yaml_path: &Path) -> Result<WalConfig> {
    let text = std::fs::read_to_string(freedom_yaml_path)
        .with_context(|| format!("read {}", freedom_yaml_path.display()))?;
    let value: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("parse {}", freedom_yaml_path.display()))?;
    match value.get("wal").cloned() {
        None | Some(serde_yaml::Value::Null) => Ok(WalConfig::default()),
        Some(wal_val) => {
            serde_yaml::from_value(wal_val).with_context(|| "parse freedom.yaml wal: stanza")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_wal_config_is_none_compression() {
        assert_eq!(WalConfig::default().compression, WalCompression::None);
    }

    #[test]
    fn wal_compression_serializes_snake_case() {
        let yaml = serde_yaml::to_string(&WalCompression::Zstd3).unwrap();
        assert!(yaml.contains("zstd_3"), "got: {yaml}");
    }

    #[test]
    fn load_wal_config_zstd3_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "wal:\n  compression: zstd_3\n").unwrap();
        let cfg = load_wal_config(&path);
        assert_eq!(cfg.compression, WalCompression::Zstd3);
    }

    #[test]
    fn load_wal_config_none_explicit_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "wal:\n  compression: none\n").unwrap();
        let cfg = load_wal_config(&path);
        assert_eq!(cfg.compression, WalCompression::None);
    }

    #[test]
    fn load_wal_config_missing_key_defaults_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "operator_id: test\n").unwrap();
        let cfg = load_wal_config(&path);
        assert_eq!(cfg.compression, WalCompression::None);
    }

    #[test]
    fn load_wal_config_missing_file_defaults_none() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_wal_config(&dir.path().join("nonexistent.yaml"));
        assert_eq!(cfg.compression, WalCompression::None);
    }
}
