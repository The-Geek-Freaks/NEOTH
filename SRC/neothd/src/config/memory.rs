//! Memory subsystem configuration.

use serde::{Deserialize, Serialize};

/// GOLD-WIRE-07 - memory subsystem tuning. One field today
/// (`vector_index`); a natural home for future retention / decay knobs.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct MemoryConfig {
    pub vector_index: VectorIndexConfig,
    /// GOLD-ADOPT-21 - when `true`, NEOTH generates an LLM title for each
    /// completed `neoth chat` session (via the cheap `inference.utility_provider`)
    /// and stores it as the card's `display_name`, which the next-session banner
    /// then prefers over the deterministic summary. Default `false`: it costs one
    /// extra (fast-model) call + a little latency at chat exit, so it's opt-in.
    #[serde(default)]
    pub name_sessions: bool,
    /// GR-039 - gate for the GOLD-WIRE-02 conversational-recall short-circuit
    /// in `neoth chat`. `true` (default, the shipped behaviour): recall-looking
    /// prompts ("do you remember when...") are answered straight from the local
    /// episode store without an LLM call. `false`: such prompts go to the
    /// provider like any other turn.
    #[serde(default = "default_recall_shortcut")]
    pub recall_shortcut: bool,
}

// Manual impl (not derived): `recall_shortcut` must default `true` on BOTH
// deserialization paths - a missing field inside an existing `memory:` block
// (field-level serde default) AND a missing `memory:` block entirely (struct
// `#[serde(default)]` -> `Default::default()`). A derived Default would make
// the second path silently disable the shipped behaviour.
impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            vector_index: VectorIndexConfig::default(),
            name_sessions: false,
            recall_shortcut: true,
        }
    }
}

fn default_recall_shortcut() -> bool {
    true
}

/// GOLD-WIRE-07 - similarity-recall vector-index backend selector.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct VectorIndexConfig {
    /// `brute_force` (default) is the always-available O(N) cosine scan over
    /// `idx_embedding`. `hnsw` activates the in-process HNSW index for
    /// `neoth recall --similar-to*`: the CLI cold-loads `<neoth_home>/
    /// embeddings.hnsw` per query, falling back to brute-force when the
    /// snapshot is absent/empty/unreadable OR the corpus is still under the
    /// brute-force ceiling (~50k) where the scan is faster than a cold load.
    /// The snapshot is NOT built automatically - run `neoth memory
    /// --rebuild-index` before HNSW recall returns results. `neoth doctor`
    /// flags a missing/stale snapshot when `hnsw` is selected.
    #[serde(default)]
    pub backend: VectorBackend,
}

/// GOLD-WIRE-07 - operator-visible vector-index backend. Serialises as
/// lowercase snake_case (`brute_force` / `hnsw`).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VectorBackend {
    /// O(N) cosine scan over `idx_embedding`. Always available. Default.
    #[default]
    BruteForce,
    /// In-process approximate nearest-neighbour via `hnsw_rs`. Opt-in; needs
    /// a built `embeddings.hnsw` snapshot to be useful (else falls back).
    Hnsw,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    use crate::config::FreedomConfig;

    /// GR-039: `recall_shortcut` must default `true` on BOTH paths - the
    /// derived-struct path (missing `memory:` block -> Default::default())
    /// and the field-level serde path (present block, absent field).
    #[test]
    fn memory_recall_shortcut_defaults_true_on_both_paths() {
        assert!(MemoryConfig::default().recall_shortcut);
        let cfg: MemoryConfig = serde_yaml::from_str("name_sessions: false").unwrap();
        assert!(
            cfg.recall_shortcut,
            "field-level serde default must be true"
        );
        let cfg: MemoryConfig = serde_yaml::from_str("recall_shortcut: false").unwrap();
        assert!(!cfg.recall_shortcut, "explicit false must stick");
    }

    #[test]
    fn memory_config_defaults_to_brute_force() {
        assert_eq!(
            MemoryConfig::default().vector_index.backend,
            VectorBackend::BruteForce,
            "default must keep the pre-WIRE-07 brute-force path"
        );
        assert_eq!(
            FreedomConfig::default().memory.vector_index.backend,
            VectorBackend::BruteForce
        );
    }

    #[test]
    fn vector_backend_serialises_snake_case_and_roundtrips() {
        let hnsw = serde_yaml::to_string(&VectorBackend::Hnsw).unwrap();
        assert!(hnsw.contains("hnsw"), "got: {hnsw}");
        let bf = serde_yaml::to_string(&VectorBackend::BruteForce).unwrap();
        assert!(bf.contains("brute_force"), "got: {bf}");
        let back: VectorBackend = serde_yaml::from_str(&hnsw).unwrap();
        assert_eq!(back, VectorBackend::Hnsw);
    }

    #[test]
    fn memory_config_parses_hnsw_from_freedom_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nmemory:\n  vector_index:\n    backend: hnsw\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.memory.vector_index.backend, VectorBackend::Hnsw);
    }

    fn write_yaml(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("freedom.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }
}
