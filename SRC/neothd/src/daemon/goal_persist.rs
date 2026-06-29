//! GOLD-FEAT-11 — cross-turn goal persistence.
//!
//! Persists the operator's active goal to `~/.neoth/current_goal.json` so it
//! survives across chat sessions without touching `freedom.yaml`. The goal is
//! injected as a `[CROSS-TURN GOAL]` system-prompt layer by
//! `pipeline::enriched_request::build_enriched_request` on every turn in both
//! `cli/chat.rs` and `cli/serve_pipeline.rs`.
//!
//! This is SEPARATE from `config::features::GoalConfig` (which drives the
//! dispatch-loop goal/grind judge via `freedom.yaml::goal`). The persistence
//! layer here injects a goal into the SYSTEM PROMPT on every turn — it is a
//! "sticky context" feature, not a dispatch-loop control.
//!
//! ## File format
//!
//! `~/.neoth/current_goal.json`:
//! ```json
//! { "goal": "...", "grind": null, "set_at_unix": 1750000000 }
//! ```
//!
//! `grind` is an optional additional directive (e.g. "keep pushing until
//! done"). Both fields are injected into the system prompt when present.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// File name inside `~/.neoth/`.
pub const GOAL_PERSIST_FILE: &str = "current_goal.json";

/// Persisted cross-turn goal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalPersist {
    /// One-shot or ongoing goal text injected into every system prompt.
    pub goal: Option<String>,
    /// Optional supplementary "grind" directive (e.g. "keep going until X").
    pub grind: Option<String>,
    /// Unix timestamp when this was last set.
    pub set_at_unix: i64,
}

impl GoalPersist {
    /// Load from `~/.neoth/current_goal.json`.
    ///
    /// Returns `None` when the file is absent (no goal set) or the JSON is
    /// corrupt (treat as cleared — never error on a read path called every
    /// turn). Corrupt files are logged at debug level.
    pub fn load(home: &Path) -> Option<GoalPersist> {
        let path = home.join(GOAL_PERSIST_FILE);
        if !path.exists() {
            return None;
        }
        match std::fs::read_to_string(&path) {
            Ok(s) => match serde_json::from_str::<GoalPersist>(&s) {
                Ok(g) => Some(g),
                Err(e) => {
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "goal_persist: corrupt JSON — treating as cleared"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %e,
                    "goal_persist: read error — treating as no goal"
                );
                None
            }
        }
    }

    /// Save to `~/.neoth/current_goal.json` using atomic write.
    pub fn save(home: &Path, persist: &GoalPersist) -> std::io::Result<()> {
        let path = home.join(GOAL_PERSIST_FILE);
        let bytes = serde_json::to_vec_pretty(persist)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::util::atomic_write::atomic_write(&path, &bytes)
    }

    /// Remove `~/.neoth/current_goal.json` (clear the goal).
    ///
    /// Returns `Ok(())` when the file is already absent.
    pub fn clear(home: &Path) -> std::io::Result<()> {
        let path = home.join(GOAL_PERSIST_FILE);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Render the goal (and optional grind) as a system-prompt injection block.
    /// Returns `None` when both `goal` and `grind` are `None`.
    pub fn as_system_layer(&self) -> Option<String> {
        match (&self.goal, &self.grind) {
            (None, None) => None,
            (goal, grind) => {
                let mut parts = Vec::new();
                parts.push("[CROSS-TURN GOAL]".to_string());
                if let Some(g) = goal {
                    parts.push(format!("Goal: {g}"));
                }
                if let Some(g) = grind {
                    parts.push(format!("Grind (relentless): {g}"));
                }
                Some(parts.join("\n"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_persist(goal: &str) -> GoalPersist {
        GoalPersist {
            goal: Some(goal.to_string()),
            grind: None,
            set_at_unix: 1_750_000_000,
        }
    }

    #[test]
    fn goal_persist_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let original = make_persist("finish the migration");
        GoalPersist::save(dir.path(), &original).unwrap();
        let loaded = GoalPersist::load(dir.path()).expect("should load");
        assert_eq!(original, loaded);
    }

    #[test]
    fn goal_persist_clear_removes_file() {
        let dir = tempdir().unwrap();
        GoalPersist::save(dir.path(), &make_persist("something")).unwrap();
        assert!(dir.path().join(GOAL_PERSIST_FILE).exists());
        GoalPersist::clear(dir.path()).unwrap();
        assert!(!dir.path().join(GOAL_PERSIST_FILE).exists());
        assert!(GoalPersist::load(dir.path()).is_none());
    }

    #[test]
    fn goal_persist_missing_file_returns_none() {
        let dir = tempdir().unwrap();
        assert!(GoalPersist::load(dir.path()).is_none());
    }

    #[test]
    fn goal_persist_clear_idempotent_when_already_absent() {
        let dir = tempdir().unwrap();
        // Should not error when file doesn't exist.
        GoalPersist::clear(dir.path()).unwrap();
    }

    #[test]
    fn as_system_layer_none_when_both_empty() {
        let g = GoalPersist {
            goal: None,
            grind: None,
            set_at_unix: 0,
        };
        assert!(g.as_system_layer().is_none());
    }

    #[test]
    fn as_system_layer_contains_goal_text() {
        let g = GoalPersist {
            goal: Some("ship FEAT-11".to_string()),
            grind: None,
            set_at_unix: 0,
        };
        let layer = g.as_system_layer().unwrap();
        assert!(layer.contains("[CROSS-TURN GOAL]"));
        assert!(layer.contains("ship FEAT-11"));
    }

    #[test]
    fn as_system_layer_contains_grind_when_set() {
        let g = GoalPersist {
            goal: None,
            grind: Some("keep going".to_string()),
            set_at_unix: 0,
        };
        let layer = g.as_system_layer().unwrap();
        assert!(layer.contains("Grind (relentless): keep going"));
    }

    #[test]
    fn corrupt_json_returns_none() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(GOAL_PERSIST_FILE), b"{ broken json [").unwrap();
        assert!(GoalPersist::load(dir.path()).is_none());
    }

    #[test]
    fn with_grind_roundtrips() {
        let dir = tempdir().unwrap();
        let original = GoalPersist {
            goal: Some("deploy v1.0".to_string()),
            grind: Some("never stop until green CI".to_string()),
            set_at_unix: 1_750_000_001,
        };
        GoalPersist::save(dir.path(), &original).unwrap();
        let loaded = GoalPersist::load(dir.path()).unwrap();
        assert_eq!(original, loaded);
    }
}
