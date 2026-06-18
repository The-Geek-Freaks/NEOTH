//! Claude CLI provider configuration.
//!
//! This module owns the `claude_cli:` stanza and the small conversion boundary
//! into the Claude CLI adapter enum.

use serde::{Deserialize, Serialize};

/// `claude_cli:` stanza in `freedom.yaml`.
///
/// ```yaml
/// claude_cli:
///   backend: auto           # auto | tmux | subprocess
///   tmux:
///     session_scope: singleton
///     compaction_rotate_after: 10
///     idle_ttl_secs: 1800      # session sweeper TTL
///     idle_timeout_secs: 120   # per-request idle window
///     hard_timeout_secs: 300   # per-request absolute cap
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ClaudeCliConfig {
    /// Backend selection. `auto` (default) probes tmux availability +
    /// picks the best option; `tmux` forces warm-session mode (the
    /// only path that works reliably for tmux-based setups — see memory
    /// `neoth-claude-cli-tmux-mandatory.md`); `subprocess` forces the
    /// cold-start `claude --print` path (broken on some hosts but
    /// kept as a Windows-without-WSL escape hatch).
    #[serde(default)]
    pub backend: ClaudeCliBackendCfg,
    /// Tmux backend tuning. Ignored when `backend == subprocess`.
    #[serde(default)]
    pub tmux: ClaudeCliTmuxConfig,
    /// Env-var prefixes to strip from the spawned `claude` subprocess's
    /// environment, so the operator's OTHER agent-stack secrets never
    /// reach the model. Default empty — declare your own if you run NEOTH
    /// alongside another agent framework that exports prefixed env vars
    /// (e.g. `["MYGATEWAY_", "MYAGENT_"]`). NEOTH always strips its own
    /// `NEOTH_*` (except `NEOTH_LOG`), CI markers, `CLAUDECODE_*` and TMUX
    /// vars regardless of this list.
    #[serde(default)]
    pub scrub_env_prefixes: Vec<String>,
    /// Optional claude-cli session UUID to resume. When set, NEOTH passes
    /// `--resume <uuid>` to the subprocess/tmux warm session. If the
    /// corresponding `~/.claude/sessions/<uuid>.jsonl` is missing, the
    /// resume arg is stripped before spawn so claude-cli does not fail
    /// with "session not found".
    #[serde(default)]
    pub resume_session_id: Option<String>,
}

/// Serde-facing backend tag. Kept separate from the provider enum so the
/// `freedom.yaml` wire shape can stay stable independently of provider internals.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeCliBackendCfg {
    #[default]
    Auto,
    Tmux,
    Subprocess,
}

impl ClaudeCliBackendCfg {
    /// Lower the config-layer enum into the provider-layer enum the adapter
    /// constructor accepts.
    pub fn to_provider(self) -> crate::providers::claude_cli::ClaudeBackend {
        match self {
            Self::Auto => crate::providers::claude_cli::ClaudeBackend::Auto,
            Self::Tmux => crate::providers::claude_cli::ClaudeBackend::Tmux,
            Self::Subprocess => crate::providers::claude_cli::ClaudeBackend::Subprocess,
        }
    }
}

/// Tmux warm-session tuning. Defaults match bridge.py + claude_tmux's
/// pinned constants. Each field is optional in the YAML; missing fields
/// inherit the constants below.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaudeCliTmuxConfig {
    /// Session scope. `Singleton` (default) = one warm session per
    /// adapter (the v0.1 TmuxSlot wiring). `PerConversation` is the
    /// Agent-4 architecture that pools sessions keyed by
    /// conversation-id; deferred until the chat dispatch threads a
    /// `conversation_id` through `Request`. Set today + NEOTH warns
    /// at boot + falls back to singleton.
    #[serde(default)]
    pub session_scope: TmuxSessionScope,
    /// How many "Memory was condensed" responses trigger a fresh
    /// session. Bridge.py default = 10. Lower = more rotations
    /// (cleaner state, higher cold-start cost); higher = more drift.
    #[serde(default = "default_compaction_rotate_after")]
    pub compaction_rotate_after: u32,
    /// Session sweeper TTL — `cli/tmux_sweeper` kills warm sessions
    /// idle longer than this. Bridge.py default = 1800 (30 min).
    /// Honored by the sweeper task; tmux_session itself is
    /// indifferent.
    #[serde(default = "default_idle_ttl_secs")]
    pub idle_ttl_secs: u64,
    /// Per-request idle-window cap. No pane change for this many
    /// seconds = response complete. Bridge.py + claude_tmux default
    /// = 120. Read by `providers::mod::build_provider` and threaded into
    /// `ClaudeCliAdapter::new_with_backend_and_timeouts` (Pick #35).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Per-request absolute cap. claude_tmux returns
    /// `HardTimeoutNoOutput` past this. Bridge.py default = 300.
    /// Read alongside `idle_timeout_secs` at `providers/mod.rs`
    /// build-time (Pick #35).
    #[serde(default = "default_hard_timeout_secs")]
    pub hard_timeout_secs: u64,
}

impl Default for ClaudeCliTmuxConfig {
    fn default() -> Self {
        Self {
            session_scope: TmuxSessionScope::default(),
            compaction_rotate_after: default_compaction_rotate_after(),
            idle_ttl_secs: default_idle_ttl_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
            hard_timeout_secs: default_hard_timeout_secs(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TmuxSessionScope {
    #[default]
    Singleton,
    /// Reserved for the Agent-4 conversation-keyed pool. Logged +
    /// downgraded to `Singleton` at startup for v0.1.
    PerConversation,
}

fn default_compaction_rotate_after() -> u32 {
    10
}

fn default_idle_ttl_secs() -> u64 {
    1800
}

fn default_idle_timeout_secs() -> u64 {
    120
}

fn default_hard_timeout_secs() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_cli_config_default_is_auto_backend_with_bridge_py_tuning() {
        // Drift guard: the no-config-block fallback must match the
        // operator-tested bridge.py constants so freedom.yaml files
        // that don't mention `claude_cli:` behave like they did
        // before B-6 landed.
        let cfg = ClaudeCliConfig::default();
        assert_eq!(cfg.backend, ClaudeCliBackendCfg::Auto);
        assert_eq!(cfg.tmux.session_scope, TmuxSessionScope::Singleton);
        assert_eq!(cfg.tmux.compaction_rotate_after, 10);
        assert_eq!(cfg.tmux.idle_ttl_secs, 1800);
        assert_eq!(cfg.tmux.idle_timeout_secs, 120);
        assert_eq!(cfg.tmux.hard_timeout_secs, 300);
    }

    #[test]
    fn claude_cli_backend_cfg_lowers_to_provider_enum() {
        // The config-layer enum must round-trip into the providers
        // adapter's enum without losing variants — otherwise the
        // wizard's selection wouldn't reach the adapter.
        use crate::providers::claude_cli::ClaudeBackend as P;
        assert_eq!(ClaudeCliBackendCfg::Auto.to_provider(), P::Auto);
        assert_eq!(ClaudeCliBackendCfg::Tmux.to_provider(), P::Tmux);
        assert_eq!(ClaudeCliBackendCfg::Subprocess.to_provider(), P::Subprocess);
    }

    #[test]
    fn claude_cli_backend_serializes_snake_case() {
        // Operators read what they wrote — the on-disk form must
        // be canonical snake_case, not `Auto` / `Tmux` (which would
        // confuse anyone editing by hand).
        let cfg = ClaudeCliConfig {
            backend: ClaudeCliBackendCfg::Tmux,
            tmux: ClaudeCliTmuxConfig::default(),
            scrub_env_prefixes: Vec::new(),
            resume_session_id: None,
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        assert!(
            yaml.contains("backend: tmux"),
            "expected snake_case `tmux`, got: {yaml}"
        );
        assert!(
            yaml.contains("session_scope: singleton"),
            "expected snake_case scope, got: {yaml}"
        );
    }
}
