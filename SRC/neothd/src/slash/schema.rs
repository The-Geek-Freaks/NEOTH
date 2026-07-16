//! TOML schema for slash commands.
//!
//! Two flavours of slash command share this schema:
//!
//! 1. **Prompt-based** — `prompt` field carries an LLM template. Used
//!    by `/recall`, `/status`, `/jobs`, `/rollback`, `/help`. The
//!    dispatcher renders the prompt + sends it to the configured
//!    provider; the LLM produces the operator-facing reply.
//!
//! 2. **Action-based** (Session 15 Pick #30) — `action` field carries
//!    a typed [`SlashAction`] that the dispatcher executes directly,
//!    no LLM call. Used by `/wizard`, `/config`, `/provider`,
//!    `/connect`, `/disconnect`, `/reload`, `/autonomy`, `/quit` —
//!    state-changing commands where an LLM round-trip would add
//!    latency + non-determinism for no benefit.
//!
//! Per memory rule `neoth-slash-commands-and-settings-parity`, every
//! action-based command MUST pair with a GUI settings-panel entry so
//! operators on either surface have parity.
//!
//! ```toml
//! # ~/.neoth/commands/recall.toml — prompt-based
//! name        = "recall"
//! description = "Search memory for matching text"
//! prompt      = "Run a memory recall query for: {args}"
//! help        = "Usage: /recall <query>"
//! enabled     = true
//!
//! # built-in /wizard — action-based, no operator override needed
//! name        = "wizard"
//! description = "Re-run the onboarding wizard"
//! action      = "restart_wizard"
//! help        = "Usage: /wizard"
//! enabled     = true
//! ```

use serde::{Deserialize, Serialize};

/// Loaded slash command. Either operator-defined (from TOML) or built-in.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SlashCommand {
    /// Stable command name. Used to match the `/name args` prefix and to
    /// resolve overrides — operator-defined commands replace built-ins of
    /// the same name.
    pub name: String,
    /// One-line description shown by `/help`.
    pub description: String,
    /// Prompt template (prompt-based commands). `{args}` is substituted
    /// with the rest of the invocation line. `{operator}` substitutes
    /// the operator id. No other substitutions are supported in v0.1.
    /// Empty string for action-based commands (use `action` field).
    #[serde(default)]
    pub prompt: String,
    /// Action-based command — dispatcher executes this directly, no
    /// LLM call. `None` (default) keeps the legacy prompt-rendering
    /// path. See [`SlashAction`] for the variants.
    #[serde(default)]
    pub action: Option<SlashAction>,
    /// Optional longer help string shown when the operator types `/help name`.
    #[serde(default)]
    pub help: Option<String>,
    /// If false, the loader skips this command (operator wants to disable
    /// a built-in without deleting the override file).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// Action a slash command performs without round-tripping through an
/// LLM. Each variant maps to one operator-tweakable surface that ALSO
/// exists in the GUI settings panel (per memory rule
/// `neoth-slash-commands-and-settings-parity`). The dispatcher reads
/// this enum + dispatches into the corresponding handler.
///
/// `non_exhaustive` so future skill/plugin-registered actions don't
/// break older built consumers that match on the enum.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SlashAction {
    /// `/wizard` — re-run the onboarding wizard from the start.
    /// Skips the mode-selection (operator's already in CLI).
    RestartWizard,
    /// `/config [key] [value]` — when args empty: list every config
    /// field + current value. With args: validate + atomic-write the
    /// new value into freedom.yaml.
    ConfigGet,
    /// Dispatcher uses [`SlashAction::ConfigGet`] for both list +
    /// edit; this variant is reserved for the future split if list
    /// surfaces grow large enough to warrant separate commands.
    ConfigSet,
    /// `/provider [role] <kind> [--model M] [--key K] [--endpoint URL]` — switch one
    /// hemisphere's provider. `role` defaults to `left` per the
    /// chat dispatch fallback rule.
    ProviderSwitch,
    /// `/connect <channel>` — walk the operator through credential
    /// entry + candidate verification for any canonical registry adapter;
    /// persistence is compare-and-swap after the probe.
    ConnectChannel,
    /// `/disconnect <channel>` — revoke credentials + leave the
    /// adapter shell. Idempotent for already-disconnected channels.
    DisconnectChannel,
    /// `/skill <list|enable|disable|info> [name]` — skill registry surface.
    SkillRegistry,
    /// `/plugin <list|enable|disable|info> [id]` — WASM plugin registry.
    PluginRegistry,
    /// `/memory <view|tier|forget> [args]` — recall + tier inspection
    /// + GDPR-forget surface.
    MemoryView,
    /// `/consent <list|grant|revoke> [provider]` — V03-08 consent flow.
    ConsentManage,
    /// `/reload` — hot-reload freedom.yaml (Q-4 sentinel file route).
    ReloadConfig,
    /// `/autonomy <strict|standard|elevated|full|custom>` — switch
    /// autonomy level mid-session. Writes freedom.yaml + triggers
    /// reload.
    AutonomyLevel,
    /// `/quit` — exit the chat session cleanly. Drains the WAL,
    /// closes the channel adapters, returns to shell.
    Quit,
    /// `/background <prompt>` / `/btw <prompt>` — HERMES-02. Spawn a
    /// headless provider call in the background; deliver the result at
    /// the next idle turn. `btw` is an alias that conveys the same
    /// intent with a shorter name. Not destructive: read-only from the
    /// privilege-ceiling perspective (spawns a provider call, does NOT
    /// mutate config/state).
    BackgroundRun {
        /// True when the command was invoked as `/btw`; false for
        /// `/background`. Stored so WAL audit frames and display
        /// banners can show the exact command name the operator typed.
        btw: bool,
    },
}

impl SlashAction {
    /// Stable wire-form name for log lines + WAL audit payload.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RestartWizard => "restart_wizard",
            Self::ConfigGet => "config_get",
            Self::ConfigSet => "config_set",
            Self::ProviderSwitch => "provider_switch",
            Self::ConnectChannel => "connect_channel",
            Self::DisconnectChannel => "disconnect_channel",
            Self::SkillRegistry => "skill_registry",
            Self::PluginRegistry => "plugin_registry",
            Self::MemoryView => "memory_view",
            Self::ConsentManage => "consent_manage",
            Self::ReloadConfig => "reload_config",
            Self::AutonomyLevel => "autonomy_level",
            Self::Quit => "quit",
            Self::BackgroundRun { btw: false } => "background_run",
            Self::BackgroundRun { btw: true } => "btw_run",
        }
    }

    /// ADV-09: actions that MUTATE operator config / security state and
    /// so must require CLI + local auth — `dispatch_action` rejects them
    /// when the invocation arrives from a channel (privilege ceiling).
    /// Mixed read/write actions are classified by
    /// [`Self::is_destructive_with_args`], not flattened here.
    pub const fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::RestartWizard
                | Self::ConfigSet
                | Self::ProviderSwitch
                | Self::ConnectChannel
                | Self::DisconnectChannel
                | Self::ReloadConfig
        )
    }

    /// ADV-09 sub-command-aware ceiling. The mixed-mode registries
    /// actions are NOT flatly destructive: `/config <key>`, `/skill list`,
    /// `/plugin info`, `/memory tier`, `/consent list`, and `/autonomy` are
    /// reads. Their write forms require local CLI authentication.
    pub fn is_destructive_with_args(self, args: &str) -> bool {
        if self.is_destructive() {
            return true;
        }
        let sub = args.split_whitespace().next().unwrap_or("");
        match self {
            Self::ConfigGet => args.split_whitespace().count() >= 2,
            Self::SkillRegistry | Self::PluginRegistry => matches!(sub, "enable" | "disable"),
            Self::MemoryView => sub == "forget",
            Self::ConsentManage => matches!(sub, "grant" | "revoke"),
            Self::AutonomyLevel => !args.trim().is_empty(),
            _ => false,
        }
    }
}

impl Copy for SlashAction {}

/// ADV-09: origin surface of a slash-command invocation. The channel
/// privilege ceiling in [`crate::slash::dispatch_action`] rejects
/// destructive actions ([`SlashAction::is_destructive_with_args`]) when the
/// source is a channel — they require local CLI authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandSource {
    /// Local CLI (`neoth chat`) — trusted, full privilege.
    Cli,
    /// A messaging channel (Telegram / WhatsApp / Slack / ...).
    /// Destructive operator commands are rejected.
    Channel,
}

impl CommandSource {
    pub fn is_channel(self) -> bool {
        matches!(self, Self::Channel)
    }
}

fn default_enabled() -> bool {
    true
}

impl SlashCommand {
    /// Render the prompt with `{args}` and `{operator}` substituted.
    pub fn render(&self, args: &str, operator: Option<&str>) -> String {
        let op = operator.unwrap_or("operator");
        self.prompt
            .replace("{args}", args)
            .replace("{operator}", op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_args_and_operator() {
        let cmd = SlashCommand {
            name: "echo".into(),
            description: "Echo".into(),
            prompt: "Hi {operator}, you said: {args}".into(),
            action: None,
            help: None,
            enabled: true,
        };
        assert_eq!(
            cmd.render("hello world", Some("alex")),
            "Hi alex, you said: hello world",
        );
    }

    #[test]
    fn render_handles_missing_operator() {
        let cmd = SlashCommand {
            name: "echo".into(),
            description: "Echo".into(),
            prompt: "{operator}: {args}".into(),
            action: None,
            help: None,
            enabled: true,
        };
        assert_eq!(cmd.render("x", None), "operator: x");
    }

    #[test]
    fn parses_minimal_toml() {
        let toml_src = r#"
            name = "foo"
            description = "Foo it"
            prompt = "Do foo with: {args}"
        "#;
        let cmd: SlashCommand = toml::from_str(toml_src).unwrap();
        assert_eq!(cmd.name, "foo");
        assert!(cmd.enabled, "enabled defaults to true");
        assert!(cmd.help.is_none());
    }

    #[test]
    fn parses_full_toml() {
        let toml_src = r#"
            name = "rec"
            description = "Recall"
            prompt = "Recall: {args}"
            help = "Usage: /rec <query>"
            enabled = false
        "#;
        let cmd: SlashCommand = toml::from_str(toml_src).unwrap();
        assert_eq!(cmd.help.as_deref(), Some("Usage: /rec <query>"));
        assert!(!cmd.enabled);
    }
}
