//! Operator-owned document-discovery configuration.
//!
//! This is deliberately policy only.  It validates the portable YAML shape
//! without touching the filesystem; the daemon worker resolves roots with its
//! no-follow rules after the default-off runtime gate has admitted a task.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Maximum number of operator-selected document roots.  The runtime performs
/// its own bounded no-follow reconciliation over this small input set.
pub const MAX_DOC_INGEST_WATCH_PATHS: usize = 32;
pub const MIN_DOC_INGEST_MAX_PER_DAY: usize = 1;
pub const MAX_DOC_INGEST_MAX_PER_DAY: usize = 100;

/// Default-off document-discovery policy.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct DocIngestConfig {
    /// No worker, root resolution, state access, or filesystem access occurs
    /// until this explicit operator opt-in is true.
    pub enabled: bool,
    /// Absolute operator-selected roots.  A configured Obsidian vault is an
    /// additional runtime root and is intentionally not serialized here.
    pub watch_paths: Vec<String>,
    /// Bounded number of newly admitted pending document notices per rolling
    /// 24-hour period.
    pub max_per_day: usize,
}

impl Default for DocIngestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_paths: Vec::new(),
            max_per_day: 3,
        }
    }
}

impl DocIngestConfig {
    /// Validate only public configuration syntax.  Root existence,
    /// canonicalisation, containment, and link handling are runtime concerns
    /// of the no-follow worker and deliberately do not happen during config
    /// parsing.
    pub fn validate(&self, has_configured_vault: bool) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if !(MIN_DOC_INGEST_MAX_PER_DAY..=MAX_DOC_INGEST_MAX_PER_DAY).contains(&self.max_per_day) {
            return Err(format!(
                "doc_ingest.max_per_day must be between {MIN_DOC_INGEST_MAX_PER_DAY} and {MAX_DOC_INGEST_MAX_PER_DAY} when doc_ingest.enabled is true"
            ));
        }
        if self.watch_paths.len().saturating_add(usize::from(has_configured_vault))
            > MAX_DOC_INGEST_WATCH_PATHS
        {
            return Err(format!(
                "doc_ingest may contain at most {MAX_DOC_INGEST_WATCH_PATHS} roots including the configured Obsidian vault"
            ));
        }
        if self.watch_paths.is_empty() && !has_configured_vault {
            return Err(
                "doc_ingest.enabled requires at least one watch_paths entry or obsidian_vault"
                    .to_owned(),
            );
        }
        for raw in &self.watch_paths {
            let path = Path::new(raw);
            if raw.trim().is_empty() {
                return Err("doc_ingest.watch_paths must not contain empty paths".to_owned());
            }
            if !path.is_absolute() {
                return Err(format!(
                    "doc_ingest.watch_paths entry must be an absolute path: {raw}"
                ));
            }
        }
        Ok(())
    }
}
