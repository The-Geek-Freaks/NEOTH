//! Rollback snapshot policy configuration.

use serde::{Deserialize, Serialize};

/// B-Rollback snapshot policy. Defaults to capturing config writes +
/// outbound channel sends - the two mutation classes operators most
/// often regret. SQL mutations + MCP tool invocations + free-form
/// file writes are opt-in because their payload sizes are unbounded.
///
/// Per Konsens decision #4: WAL growth at the default is about 42 MB/year
/// for a typical operator; safe within the 5 GiB quota ceiling.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackConfig {
    /// Mutation kinds (snake_case) NEOTH should emit snapshots for.
    /// Empty list = rollback fully off (no automatic snapshots emitted).
    #[serde(default = "default_rollback_kinds")]
    pub capture_kinds: Vec<String>,
    /// Per-frame ceiling on `before_state` bytes. Snapshots whose
    /// captured state exceeds this cap are skipped + logged at WARN
    /// - prevents a single 10 MB file write from producing a
    /// runaway WAL frame.
    #[serde(default = "default_rollback_max_bytes")]
    pub max_snapshot_bytes: usize,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            capture_kinds: default_rollback_kinds(),
            max_snapshot_bytes: default_rollback_max_bytes(),
        }
    }
}

fn default_rollback_kinds() -> Vec<String> {
    vec!["config_write".to_string(), "channel_send".to_string()]
}

fn default_rollback_max_bytes() -> usize {
    65_536
}

impl RollbackConfig {
    /// True when the given mutation kind is in the capture allowlist.
    /// Case-insensitive match against the snake_case wire name.
    pub fn should_capture(&self, kind: &str) -> bool {
        let needle = kind.to_ascii_lowercase();
        self.capture_kinds
            .iter()
            .any(|k| k.eq_ignore_ascii_case(&needle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_default_captures_config_and_channel_send() {
        // A3: pin the Konsens-decision defaults so a refactor that
        // drifts them fails loudly rather than silently changing
        // operator behaviour.
        let cfg = RollbackConfig::default();
        assert!(cfg.should_capture("config_write"));
        assert!(cfg.should_capture("channel_send"));
        // NOT captured by default: file_write, mcp_tool_invoke,
        // sql_mutation. Operators opt in per kind.
        assert!(!cfg.should_capture("file_write"));
        assert!(!cfg.should_capture("mcp_tool_invoke"));
        assert!(!cfg.should_capture("sql_mutation"));
        // 64 KB per-frame cap matches Konsens recommendation.
        assert_eq!(cfg.max_snapshot_bytes, 65_536);
    }

    #[test]
    fn rollback_should_capture_is_case_insensitive_on_snake_case() {
        // Match is case-insensitive but snake_case-only - we do NOT
        // normalise CamelCase -> snake_case (that would invite typo
        // tolerance the operator can't audit).
        let cfg = RollbackConfig::default();
        assert!(cfg.should_capture("CONFIG_WRITE"));
        assert!(cfg.should_capture("Config_Write"));
        assert!(cfg.should_capture("config_write"));
        assert!(!cfg.should_capture("config_wrte")); // typo -> no match
        // Operator must use snake_case to match - `ConfigWrite`
        // (camelCase) intentionally does not match.
        assert!(!cfg.should_capture("ConfigWrite"));
    }

    #[test]
    fn rollback_empty_capture_kinds_means_disabled() {
        // Operator who wants rollback fully off can ship an empty list.
        let cfg = RollbackConfig {
            capture_kinds: vec![],
            max_snapshot_bytes: 65_536,
        };
        assert!(!cfg.should_capture("config_write"));
        assert!(!cfg.should_capture("channel_send"));
    }
}
