//! Slash-action dispatcher — Session 15 Pick #31.
//!
//! Pure-function entry point that consumes a [`SlashAction`] + the
//! action args, executes the corresponding state-change OR diagnostic,
//! and returns operator-readable text. The chat dispatcher (chat.rs +
//! serve.rs) consults this BEFORE the LLM round-trip — action-based
//! commands never reach a provider, no token cost, no latency.
//!
//! Per memory rule `neoth-slash-commands-and-settings-parity`, every
//! action mirrored in this dispatcher MUST also surface in the GUI
//! settings panel. The dispatcher writes to `freedom.yaml` via the
//! existing `config::reload::ReloadController` so both surfaces hit
//! one source of truth.
//!
//! ## Today's scope (Pick #31)
//!
//! Foundation: 13 action handlers, each returning a structured
//! [`ActionOutcome`] that the caller renders. Six handlers fully
//! actionable today (config-list, consent-list, autonomy-show,
//! provider-show, skill-list, plugin-list — all read-only).
//! Seven write-path handlers (wizard restart, config-set, provider-
//! switch, channel connect/disconnect, memory mutations, reload-
//! request) emit a clearly-labelled `Pending` outcome with the
//! follow-up CLI command the operator can run today + the GUI tab
//! that ships the same surface. This gives operators the discovery
//! surface immediately while the per-handler wiring lands in
//! follow-up picks.

use super::schema::{CommandSource, SlashAction};
use crate::config::FreedomConfig;

/// What the dispatcher decided after seeing an action invocation.
/// Carries human-readable output the caller writes to stdout / sends
/// back to the channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionOutcome {
    /// Fully handled — `text` is the operator-facing result. Caller
    /// prints + skips the LLM call.
    Handled { text: String },
    /// Handler shipped but the write-path isn't fully wired yet.
    /// `text` carries the follow-up the operator can take today +
    /// the GUI tab that mirrors the action. Caller prints + skips
    /// the LLM call.
    Pending { text: String },
    /// Invalid args for this action (wrong arity, unknown channel
    /// name, ...). `text` carries the usage hint.
    InvalidArgs { text: String },
    /// `/quit` only — caller drains state + exits the process.
    Exit,
    /// ADV-09: a destructive action (config / consent / autonomy / channel
    /// mutation) was invoked from a CHANNEL. Rejected — it requires local
    /// CLI authentication. `text` is the operator-facing refusal the
    /// channel adapter sends back.
    ChannelPrivilegeBlocked { text: String },
}

impl ActionOutcome {
    /// Operator-facing rendering. Chat dispatcher calls this + writes
    /// the string to stdout / the channel.
    pub fn text(&self) -> &str {
        match self {
            Self::Handled { text }
            | Self::Pending { text }
            | Self::InvalidArgs { text }
            | Self::ChannelPrivilegeBlocked { text } => text,
            Self::Exit => "Exiting NEOTH chat session.",
        }
    }

    pub fn should_exit(&self) -> bool {
        matches!(self, Self::Exit)
    }

    /// ADV-09: true when the action was refused by the channel privilege
    /// ceiling. Channel adapters surface the text + do NOT fall through
    /// to the LLM.
    pub fn is_channel_blocked(&self) -> bool {
        matches!(self, Self::ChannelPrivilegeBlocked { .. })
    }
}

/// Dispatch one action. `args` is the trailing slice after the
/// command name (e.g. `/config foo bar` → `args = "foo bar"`).
/// `config` is the live `FreedomConfig` snapshot for read paths.
pub fn dispatch_action(
    action: SlashAction,
    args: &str,
    config: &FreedomConfig,
    source: CommandSource,
) -> ActionOutcome {
    // ADV-09 channel privilege ceiling: a destructive action arriving
    // from a channel is rejected outright — config / consent / autonomy /
    // channel mutation requires local CLI authentication so a Telegram
    // message can't reconfigure or escalate the daemon. CLI is trusted.
    if source.is_channel() && action.is_destructive() {
        return ActionOutcome::ChannelPrivilegeBlocked {
            text: format!(
                "⛔ `/{}` is a destructive operator command and cannot be run from a channel. \
                 Run it locally: `neoth` in a terminal on the host (CLI + local auth required).",
                action.as_str()
            ),
        };
    }
    let trimmed = args.trim();
    match action {
        SlashAction::RestartWizard => handle_wizard(),
        SlashAction::ConfigGet | SlashAction::ConfigSet => handle_config(trimmed, config),
        SlashAction::ProviderSwitch => handle_provider_switch(trimmed, config),
        SlashAction::ConnectChannel => handle_connect(trimmed),
        SlashAction::DisconnectChannel => handle_disconnect(trimmed),
        SlashAction::SkillRegistry => handle_skill(trimmed),
        SlashAction::PluginRegistry => handle_plugin(trimmed),
        SlashAction::MemoryView => handle_memory(trimmed),
        SlashAction::ConsentManage => handle_consent(trimmed),
        SlashAction::ReloadConfig => handle_reload(),
        SlashAction::AutonomyLevel => handle_autonomy(trimmed, config),
        SlashAction::Quit => ActionOutcome::Exit,
    }
}

// ── Handlers ─────────────────────────────────────────────────────────

fn handle_wizard() -> ActionOutcome {
    ActionOutcome::Pending {
        text: "/wizard — restart onboarding.\n\
               Run in your shell: `neoth init --force` (overwrites existing freedom.yaml).\n\
               GUI mirror: Settings → 'Re-run wizard' button."
            .into(),
    }
}

fn handle_config(args: &str, config: &FreedomConfig) -> ActionOutcome {
    if args.is_empty() {
        // List path — read-only, fully handled today.
        let mut lines = vec![String::from("Current freedom.yaml values:")];
        lines.push(format!(
            "  operator_id        = {:?}",
            config.operator_id.as_deref().unwrap_or("<unset>")
        ));
        lines.push(format!(
            "  language_primary   = {:?}",
            config.language_primary.as_deref().unwrap_or("<unset>")
        ));
        lines.push(format!(
            "  provider_kind      = {:?}",
            config
                .provider_kind
                .as_ref()
                .map(|k| format!("{k:?}"))
                .unwrap_or_else(|| "<unset>".to_string())
        ));
        lines.push(format!(
            "  autonomy           = {:?}",
            config.autonomy.as_str()
        ));
        lines.push(format!(
            "  review_gate        = {}",
            config.review_gate_enabled
        ));
        lines.push(String::new());
        lines.push("Edit by name: `/config <key> <value>`".into());
        lines.push("GUI mirror: Settings → Config tab.".into());
        return ActionOutcome::Handled {
            text: lines.join("\n"),
        };
    }
    // Edit path — pending until atomic-write wiring lands.
    let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
    if parts.len() < 2 {
        return ActionOutcome::InvalidArgs {
            text: format!(
                "/config — usage: `/config` (list) or `/config <key> <value>` (edit). Got: {args:?}"
            ),
        };
    }
    let (key, val) = (parts[0], parts[1].trim());
    ActionOutcome::Pending {
        text: format!(
            "/config {key} {val} — atomic-write coming in the follow-up Pick.\n\
             Today: edit ~/.neoth/freedom.yaml by hand then run `/reload`.\n\
             GUI mirror: Settings → Config tab → {key} field."
        ),
    }
}

fn handle_provider_switch(args: &str, _config: &FreedomConfig) -> ActionOutcome {
    if args.is_empty() {
        return ActionOutcome::InvalidArgs {
            text: "/provider — usage: `/provider [left|right|cerebellum] <kind> [--model M] [--key K]`.\n\
                   Valid kinds: claude_cli, openai_api, openai_compat, gemini_api, local_qwen, \
                   aws_bedrock, azure_openai."
                .into(),
        };
    }
    ActionOutcome::Pending {
        text: format!(
            "/provider {args} — hemisphere provider switch.\n\
             Today: edit ~/.neoth/freedom.yaml::inference.{{left,right,cerebellum}} then `/reload`.\n\
             GUI mirror: Settings → Hemispheres tab → per-role dropdowns.\n\
             Wiring lands in the V10-* follow-up sprint."
        ),
    }
}

fn handle_connect(args: &str) -> ActionOutcome {
    let channel = args.trim();
    if channel.is_empty() {
        return ActionOutcome::InvalidArgs {
            text: "/connect — usage: `/connect <channel>`. Channels: telegram, whatsapp, slack, discord, keet.".into(),
        };
    }
    let known = ["telegram", "whatsapp", "slack", "discord", "keet"];
    if !known.contains(&channel) {
        return ActionOutcome::InvalidArgs {
            text: format!(
                "/connect {channel} — unknown channel. Available: {}",
                known.join(", ")
            ),
        };
    }
    ActionOutcome::Pending {
        text: format!(
            "/connect {channel} — credential flow.\n\
             Today: run `neoth init --reconfigure` to walk the wizard for {channel}.\n\
             GUI mirror: Settings → Channels tab → '+ Connect {channel}'.\n\
             Live interactive credential prompt lands in the V10-* follow-up."
        ),
    }
}

fn handle_disconnect(args: &str) -> ActionOutcome {
    let channel = args.trim();
    if channel.is_empty() {
        return ActionOutcome::InvalidArgs {
            text: "/disconnect — usage: `/disconnect <channel>`.".into(),
        };
    }
    ActionOutcome::Pending {
        text: format!(
            "/disconnect {channel} — revoke credentials.\n\
             Today: remove the {channel} entry from ~/.neoth/credentials.yaml + `/reload`.\n\
             GUI mirror: Settings → Channels tab → 'Disconnect' button per row."
        ),
    }
}

fn handle_skill(args: &str) -> ActionOutcome {
    let sub = args.split_whitespace().next().unwrap_or("");
    match sub {
        "" | "list" => ActionOutcome::Handled {
            text: "Skill registry: run `neoth skill list` for the full table.\n\
                   GUI mirror: Settings → Skills tab."
                .into(),
        },
        "enable" | "disable" | "info" => ActionOutcome::Pending {
            text: format!(
                "/skill {args} — in-chat skill toggle.\n\
                 Today: `neoth skill {args}` from a shell.\n\
                 GUI mirror: Settings → Skills tab → per-row enable/disable."
            ),
        },
        other => ActionOutcome::InvalidArgs {
            text: format!(
                "/skill — unknown sub `{other}`. Use: list | enable <name> | disable <name> | info <name>."
            ),
        },
    }
}

fn handle_plugin(args: &str) -> ActionOutcome {
    let sub = args.split_whitespace().next().unwrap_or("");
    match sub {
        "" | "list" => ActionOutcome::Handled {
            text: "WASM plugin registry: run `neoth plugins list`.\n\
                   GUI mirror: Settings → Plugins tab.\n\
                   Build with `--features wasm-plugin-host` to enable the runtime."
                .into(),
        },
        "enable" | "disable" | "info" => ActionOutcome::Pending {
            text: format!(
                "/plugin {args} — V10-04 follow-up.\n\
                 Engine + manifest + discovery already shipped (Picks #24-#26).\n\
                 Dispatch wiring + per-plugin toggle land in the next V10-04 sprint."
            ),
        },
        other => ActionOutcome::InvalidArgs {
            text: format!(
                "/plugin — unknown sub `{other}`. Use: list | enable <id> | disable <id> | info <id>."
            ),
        },
    }
}

fn handle_memory(args: &str) -> ActionOutcome {
    let sub = args.split_whitespace().next().unwrap_or("");
    match sub {
        "" | "view" => ActionOutcome::Handled {
            text: "Memory tiers: run `neoth memory --tier hot|warm|cold|groundtruth`.\n\
                   GUI mirror: Settings → Memory tab → tier counters + recent entries."
                .into(),
        },
        "tier" | "forget" => ActionOutcome::Pending {
            text: format!(
                "/memory {args} — in-chat memory mutation.\n\
                 Today: `neoth memory {args}` from a shell.\n\
                 GUI mirror: Settings → Memory tab → tier-specific actions."
            ),
        },
        other => ActionOutcome::InvalidArgs {
            text: format!(
                "/memory — unknown sub `{other}`. Use: view [topic] | tier <name> | forget <topic>."
            ),
        },
    }
}

fn handle_consent(args: &str) -> ActionOutcome {
    let sub = args.split_whitespace().next().unwrap_or("");
    match sub {
        "" | "list" => ActionOutcome::Handled {
            text: "V03-08 outbound-LLM consent: run `neoth consent list`.\n\
                   GUI mirror: Settings → Privacy tab → consent matrix."
                .into(),
        },
        "grant" | "revoke" => ActionOutcome::Pending {
            text: format!(
                "/consent {args} — in-chat consent flip.\n\
                 Today: `neoth consent {args}` from a shell.\n\
                 GUI mirror: Settings → Privacy tab → per-provider toggles."
            ),
        },
        other => ActionOutcome::InvalidArgs {
            text: format!(
                "/consent — unknown sub `{other}`. Use: list | grant <provider> | revoke <provider>."
            ),
        },
    }
}

fn handle_reload() -> ActionOutcome {
    // Sentinel-file approach already lives in `config::reload`. The
    // dispatcher writes it; the daemon's polling loop picks it up
    // within 2s. Handler is fully wired today.
    let home = FreedomConfig::default_neoth_home();
    let sentinel = home.join(crate::config::reload::RELOAD_SENTINEL_NAME);
    match std::fs::write(&sentinel, b"reload\n") {
        Ok(_) => ActionOutcome::Handled {
            text: "/reload — sentinel file dropped at ~/.neoth/.reload-requested.\n\
                   Daemon picks it up within 2s and atomically swaps the live FreedomConfig.\n\
                   GUI mirror: Settings → Save button (auto-fires on field change)."
                .into(),
        },
        Err(e) => ActionOutcome::Handled {
            text: format!(
                "/reload — failed to drop sentinel: {e}.\n\
                 Check that ~/.neoth/ exists + is writable."
            ),
        },
    }
}

fn handle_autonomy(args: &str, config: &FreedomConfig) -> ActionOutcome {
    if args.is_empty() {
        return ActionOutcome::Handled {
            text: format!(
                "Current autonomy: {}\n\
                 Switch via `/autonomy <strict|standard|elevated|full|custom>`.\n\
                 GUI mirror: Settings → Autonomy slider.",
                config.autonomy.as_str()
            ),
        };
    }
    let valid = ["strict", "standard", "elevated", "full", "custom"];
    if !valid.contains(&args) {
        return ActionOutcome::InvalidArgs {
            text: format!(
                "/autonomy {args} — invalid level. Valid: {}.",
                valid.join(", ")
            ),
        };
    }
    ActionOutcome::Pending {
        text: format!(
            "/autonomy {args} — atomic write coming in the follow-up Pick.\n\
             Today: edit ~/.neoth/freedom.yaml::autonomy then `/reload`.\n\
             GUI mirror: Settings → Autonomy slider."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FreedomConfig {
        FreedomConfig::default()
    }

    #[test]
    fn quit_returns_exit_outcome() {
        let out = dispatch_action(SlashAction::Quit, "", &cfg(), CommandSource::Cli);
        assert!(out.should_exit());
    }

    #[test]
    fn config_with_no_args_lists_current_values() {
        let out = dispatch_action(SlashAction::ConfigGet, "", &cfg(), CommandSource::Cli);
        match out {
            ActionOutcome::Handled { text } => {
                assert!(text.contains("operator_id"));
                assert!(text.contains("autonomy"));
                assert!(text.contains("GUI mirror"));
            }
            other => panic!("expected Handled, got {other:?}"),
        }
    }

    #[test]
    fn config_with_one_arg_returns_invalid_args() {
        let out = dispatch_action(
            SlashAction::ConfigGet,
            "operator_id",
            &cfg(),
            CommandSource::Cli,
        );
        assert!(matches!(out, ActionOutcome::InvalidArgs { .. }));
    }

    #[test]
    fn config_with_two_args_returns_pending_with_gui_mirror() {
        let out = dispatch_action(
            SlashAction::ConfigGet,
            "operator_id alex",
            &cfg(),
            CommandSource::Cli,
        );
        match out {
            ActionOutcome::Pending { text } => {
                assert!(text.contains("operator_id"));
                assert!(text.contains("alex"));
                assert!(text.contains("GUI mirror"));
            }
            other => panic!("expected Pending, got {other:?}"),
        }
    }

    #[test]
    fn connect_rejects_unknown_channel() {
        let out = dispatch_action(
            SlashAction::ConnectChannel,
            "fax_machine",
            &cfg(),
            CommandSource::Cli,
        );
        match out {
            ActionOutcome::InvalidArgs { text } => {
                assert!(text.contains("unknown channel"));
                assert!(text.contains("telegram")); // surfaces the available list
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn connect_accepts_known_channel() {
        for ch in ["telegram", "whatsapp", "slack", "discord", "keet"] {
            let out = dispatch_action(SlashAction::ConnectChannel, ch, &cfg(), CommandSource::Cli);
            assert!(
                matches!(out, ActionOutcome::Pending { .. }),
                "{ch} must be accepted as a known channel name"
            );
        }
    }

    #[test]
    fn skill_list_returns_handled() {
        let out = dispatch_action(
            SlashAction::SkillRegistry,
            "list",
            &cfg(),
            CommandSource::Cli,
        );
        assert!(matches!(out, ActionOutcome::Handled { .. }));
    }

    #[test]
    fn skill_unknown_sub_returns_invalid_args() {
        let out = dispatch_action(
            SlashAction::SkillRegistry,
            "explode",
            &cfg(),
            CommandSource::Cli,
        );
        assert!(matches!(out, ActionOutcome::InvalidArgs { .. }));
    }

    #[test]
    fn autonomy_with_no_args_shows_current() {
        let out = dispatch_action(SlashAction::AutonomyLevel, "", &cfg(), CommandSource::Cli);
        match out {
            ActionOutcome::Handled { text } => {
                assert!(text.contains("Current autonomy"));
                assert!(text.contains("GUI mirror"));
            }
            other => panic!("expected Handled, got {other:?}"),
        }
    }

    #[test]
    fn autonomy_with_invalid_level_returns_invalid_args() {
        let out = dispatch_action(
            SlashAction::AutonomyLevel,
            "yolo",
            &cfg(),
            CommandSource::Cli,
        );
        assert!(matches!(out, ActionOutcome::InvalidArgs { .. }));
    }

    #[test]
    fn autonomy_with_valid_level_returns_pending() {
        for level in ["strict", "standard", "elevated", "full", "custom"] {
            let out = dispatch_action(
                SlashAction::AutonomyLevel,
                level,
                &cfg(),
                CommandSource::Cli,
            );
            assert!(
                matches!(out, ActionOutcome::Pending { .. }),
                "{level} must be accepted"
            );
        }
    }

    #[test]
    fn consent_list_returns_handled() {
        let out = dispatch_action(
            SlashAction::ConsentManage,
            "list",
            &cfg(),
            CommandSource::Cli,
        );
        assert!(matches!(out, ActionOutcome::Handled { .. }));
    }

    #[test]
    fn memory_view_returns_handled() {
        let out = dispatch_action(SlashAction::MemoryView, "view", &cfg(), CommandSource::Cli);
        assert!(matches!(out, ActionOutcome::Handled { .. }));
    }

    #[test]
    fn plugin_list_returns_handled() {
        let out = dispatch_action(
            SlashAction::PluginRegistry,
            "list",
            &cfg(),
            CommandSource::Cli,
        );
        assert!(matches!(out, ActionOutcome::Handled { .. }));
    }

    #[test]
    fn outcome_text_accessor_returns_non_empty_for_every_variant() {
        // Every variant must produce operator-readable output. A
        // silent action is the worst UX — operator types `/foo` and
        // sees nothing.
        assert!(
            !ActionOutcome::Handled { text: "x".into() }
                .text()
                .is_empty()
        );
        assert!(
            !ActionOutcome::Pending { text: "y".into() }
                .text()
                .is_empty()
        );
        assert!(
            !ActionOutcome::InvalidArgs { text: "z".into() }
                .text()
                .is_empty()
        );
        assert!(!ActionOutcome::Exit.text().is_empty());
        assert!(
            !ActionOutcome::ChannelPrivilegeBlocked { text: "b".into() }
                .text()
                .is_empty()
        );
    }

    // ── ADV-09 channel privilege ceiling ──────────────────────────────

    #[test]
    fn adv09_channel_blocks_destructive_action() {
        let out = dispatch_action(
            SlashAction::ConfigSet,
            "operator_id alex",
            &cfg(),
            CommandSource::Channel,
        );
        assert!(
            out.is_channel_blocked(),
            "destructive op from channel must block"
        );
        assert!(out.text().contains("channel"));
        assert!(out.text().contains("CLI"));
    }

    #[test]
    fn adv09_channel_blocks_autonomy_and_consent() {
        // The two most security-critical: raising autonomy / granting
        // consent via a channel message is privilege escalation.
        for a in [SlashAction::AutonomyLevel, SlashAction::ConsentManage] {
            let out = dispatch_action(a, "full", &cfg(), CommandSource::Channel);
            assert!(
                out.is_channel_blocked(),
                "{} must block from channel",
                a.as_str()
            );
        }
    }

    #[test]
    fn adv09_channel_allows_readonly_action() {
        // ConfigGet is read-only — a channel may still inspect config.
        let out = dispatch_action(SlashAction::ConfigGet, "", &cfg(), CommandSource::Channel);
        assert!(!out.is_channel_blocked(), "read-only op must NOT block");
        assert!(matches!(out, ActionOutcome::Handled { .. }));
    }

    #[test]
    fn adv09_cli_permits_destructive_action() {
        // CLI is trusted — the ceiling only applies to channels.
        let out = dispatch_action(SlashAction::ConfigSet, "", &cfg(), CommandSource::Cli);
        assert!(
            !out.is_channel_blocked(),
            "CLI must never be ceiling-blocked"
        );
    }

    #[test]
    fn adv09_is_destructive_matrix() {
        assert!(SlashAction::ConfigSet.is_destructive());
        assert!(SlashAction::AutonomyLevel.is_destructive());
        assert!(SlashAction::ConsentManage.is_destructive());
        assert!(SlashAction::ConnectChannel.is_destructive());
        assert!(!SlashAction::ConfigGet.is_destructive());
        assert!(!SlashAction::Quit.is_destructive());
    }
}
