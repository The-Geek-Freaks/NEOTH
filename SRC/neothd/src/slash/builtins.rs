//! Built-in slash commands. Compiled into the binary so a fresh install
//! ships with `/help`, `/recall`, `/status`, and `/jobs` already wired up.
//!
//! Operator-defined commands of the same name **override** these — see
//! [`super::loader::load_all`]. The prompts here intentionally rely on the
//! provider's own knowledge of NEOTH's commands rather than hand-rolled
//! response templates; the LLM is in the loop so the answer is contextual.

use super::schema::{SlashAction, SlashCommand};

/// Helper for prompt-based built-ins. Reduces noise in the long
/// command list below.
fn prompt_cmd(name: &str, description: &str, prompt: &str, help: &str) -> SlashCommand {
    SlashCommand {
        name: name.into(),
        description: description.into(),
        prompt: prompt.into(),
        action: None,
        help: Some(help.into()),
        enabled: true,
    }
}

/// Helper for action-based built-ins. Action commands don't render a
/// prompt — the dispatcher matches on `action` first.
fn action_cmd(name: &str, description: &str, action: SlashAction, help: &str) -> SlashCommand {
    SlashCommand {
        name: name.into(),
        description: description.into(),
        prompt: String::new(),
        action: Some(action),
        help: Some(help.into()),
        enabled: true,
    }
}

/// Built-in command set. Returned by `built_in_commands()` and merged with
/// operator overrides at load time.
///
/// Session 15 Pick #30 (memory rule
/// `neoth-slash-commands-and-settings-parity`): added action-based
/// built-ins for `/wizard`, `/config`, `/provider`, `/connect`,
/// `/disconnect`, `/skill`, `/plugin`, `/memory`, `/consent`,
/// `/reload`, `/autonomy`, `/quit`. Each pairs with a GUI settings-
/// panel entry — operators get parity on both surfaces.
pub fn built_in_commands() -> Vec<SlashCommand> {
    vec![
        SlashCommand {
            name: "help".into(),
            description: "List available commands.".into(),
            prompt: "Reply with a one-line summary of every slash command currently \
                 available, then any operator-specific notes. If {args} names \
                 one command, give a longer explanation of that command only."
                .into(),
            action: None,
            help: Some("Usage: /help [command-name]".into()),
            enabled: true,
        },
        SlashCommand {
            name: "recall".into(),
            description: "Search memory for matching text.".into(),
            prompt: "Search the operator's NEOTH memory for `{args}`. Surface the \
                 top 5 matches in chronological order with timestamps and the \
                 channel they came from. Do not hallucinate hits that aren't \
                 in the recall results."
                .into(),
            action: None,
            help: Some("Usage: /recall <query>".into()),
            enabled: true,
        },
        SlashCommand {
            name: "status".into(),
            description: "Daemon health snapshot.".into(),
            prompt: "Report the current NEOTH daemon status: WAL segment count, \
                 last consolidation pass result, active autonomy level, \
                 configured channels, and any warnings from the last hour. \
                 Be terse — table format, ≤ 10 lines."
                .into(),
            action: None,
            help: Some("Usage: /status".into()),
            enabled: true,
        },
        SlashCommand {
            name: "jobs".into(),
            description: "List scheduled cron jobs.".into(),
            prompt: "List every entry from ~/.neoth/jobs.yaml with its next-fire \
                 time and last outcome. Include the cron expression. Skip \
                 disabled jobs unless {args} contains 'all'."
                .into(),
            action: None,
            help: Some("Usage: /jobs [all]".into()),
            enabled: true,
        },
        // B-rollback: pre-op snapshot + restore. The actual fs snapshot
        // lives in `daemon::backup`; the slash command surfaces it to
        // the chat user so they can `/rollback` after a regretted file
        // change without dropping to CLI. The prompt routes through the
        // provider so the LLM can confirm what's about to be reverted
        // before the daemon executes (operator runs `neoth backup
        // restore` for actual restoration; this command is the
        // safety-check wrapper).
        SlashCommand {
            name: "rollback".into(),
            description: "Preview + restore the most recent NEOTH backup before a file op.".into(),
            prompt: "Read the latest entry in ~/.neoth/backups/ (filename + ts + \
                 size). Summarise what would be restored if the operator ran \
                 `neoth restore`. Do NOT execute the restore — surface the \
                 file list + the command to run. Refuse if {args} is anything \
                 other than 'preview' or empty."
                .into(),
            action: None,
            help: Some("Usage: /rollback [preview]".into()),
            enabled: true,
        },
        // C-11 / C-1: spawn the critic sub-agent on the preceding turn
        // so the operator can get a counter-argument on demand without
        // typing `/agent critic <claim>` by hand. {args} is the claim
        // text; empty {args} pulls the previous assistant turn.
        SlashCommand {
            name: "critic".into(),
            description: "Get an adversarial review of the preceding claim or plan.".into(),
            prompt: "Dispatch to the `critic` sub-agent with this body: {args}\n\n\
                 If {args} is empty, use the immediately preceding assistant \
                 message as the body. The critic returns a numbered list of \
                 objections — surface it verbatim. Do not soften the response."
                .into(),
            action: None,
            help: Some("Usage: /critic [claim]".into()),
            enabled: true,
        },
        // ── Action-based built-ins (Session 15 Pick #30) ────────────
        // Each pairs with a GUI settings-panel entry per the
        // settings-parity rule.
        action_cmd(
            "wizard",
            "Re-run the onboarding wizard from the start.",
            SlashAction::RestartWizard,
            "Usage: /wizard",
        ),
        action_cmd(
            "config",
            "List or edit freedom.yaml fields.",
            SlashAction::ConfigGet,
            "Usage: /config              — list every field + value\n\
             Usage: /config <key>        — show one field\n\
             Usage: /config <key> <val>  — atomic-write the field",
        ),
        action_cmd(
            "provider",
            "Switch the inference provider for one hemisphere.",
            SlashAction::ProviderSwitch,
            "Usage: /provider [role] <kind> [--model M] [--key K]\n\
             role defaults to `left`; kind ∈ claude_cli, openai_api, \
             openai_compat, gemini_api, local_qwen, aws_bedrock, \
             azure_openai.",
        ),
        action_cmd(
            "connect",
            "Connect a channel adapter (whatsapp / telegram / slack / discord / keet).",
            SlashAction::ConnectChannel,
            "Usage: /connect <channel>\n\
             Walks credential entry + token verification before the \
             adapter goes live.",
        ),
        action_cmd(
            "disconnect",
            "Disconnect a channel adapter + revoke its credentials.",
            SlashAction::DisconnectChannel,
            "Usage: /disconnect <channel>",
        ),
        action_cmd(
            "skill",
            "Skill registry — list / enable / disable / info.",
            SlashAction::SkillRegistry,
            "Usage: /skill list\n\
             Usage: /skill enable <name>\n\
             Usage: /skill disable <name>\n\
             Usage: /skill info <name>",
        ),
        action_cmd(
            "plugin",
            "WASM plugin registry — list / enable / disable / info.",
            SlashAction::PluginRegistry,
            "Usage: /plugin list\n\
             Usage: /plugin enable <id>\n\
             Usage: /plugin disable <id>\n\
             Usage: /plugin info <id>",
        ),
        action_cmd(
            "memory",
            "Inspect or prune memory tiers.",
            SlashAction::MemoryView,
            "Usage: /memory view [topic]\n\
             Usage: /memory tier <hot|warm|cold|groundtruth>\n\
             Usage: /memory forget <topic>      — GDPR-style erasure",
        ),
        action_cmd(
            "consent",
            "V03-08 outbound-LLM consent — list / grant / revoke.",
            SlashAction::ConsentManage,
            "Usage: /consent list\n\
             Usage: /consent grant <provider>\n\
             Usage: /consent revoke <provider>",
        ),
        action_cmd(
            "reload",
            "Hot-reload freedom.yaml without restarting the daemon.",
            SlashAction::ReloadConfig,
            "Usage: /reload",
        ),
        action_cmd(
            "autonomy",
            "Switch autonomy level mid-session.",
            SlashAction::AutonomyLevel,
            "Usage: /autonomy <strict|standard|elevated|full|custom>",
        ),
        action_cmd(
            "quit",
            "Exit the chat session cleanly.",
            SlashAction::Quit,
            "Usage: /quit",
        ),
        // ── NOOB-UX slash pair (Session 20 batch) ────────────────────
        // Three new prompt-based slash commands that mirror the CLI
        // subcommands shipped this session. Each routes the operator
        // to the canonical `neoth ...` invocation; the chat surface
        // doesn't render long blocks of text inline (operators on
        // small panels see truncation), the LLM gets a directive to
        // suggest the matching CLI command. Operator's autonomy
        // chooses whether to run it for them.
        prompt_cmd(
            "glossary",
            "Operator-readable cheat sheet for NEOTH terms.",
            "Run `neoth glossary` in a separate terminal and report which \
             terms the operator just looked up. If they ask about a specific \
             term, fetch that entry's body via `neoth glossary --term <name>` \
             and quote it verbatim.",
            "Usage: /glossary [term]\n\
             Mirrors `neoth glossary --term <name>`.",
        ),
        prompt_cmd(
            "privacy",
            "Pre-prompt privacy audit — see what hits cloud before sending.",
            "Run `neoth privacy audit` and quote the findings table. The \
             operator wants to know — without ambiguity — whether the next \
             chat call leaves their machine, and which channels relay data \
             off-host. Highlight every WARN-severity row.",
            "Usage: /privacy\n\
             Mirrors `neoth privacy audit`.",
        ),
        prompt_cmd(
            "tour",
            "First-launch operator tour — 5 stops, ~3 min read.",
            "Walk the operator through the `neoth tour` stops one at a time: \
             chat / memory / consent / audit / next. After each stop, wait \
             for them to confirm before moving on. They can jump to any stop \
             via `/tour <id>` or `neoth tour --step <id>`.",
            "Usage: /tour [step]\n\
             Mirrors `neoth tour --step <id>`.\n\
             Available stops: chat, memory, consent, audit, next.",
        ),
    ]
}

// Silence unused-import warning when prompt_cmd lands in the next
// pick (every built-in still uses the inline struct form today).
#[allow(dead_code)]
fn _prompt_cmd_anchor() -> SlashCommand {
    prompt_cmd("anchor", "anchor", "anchor", "anchor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_ins_include_all_required_commands() {
        let names: Vec<String> = built_in_commands().into_iter().map(|c| c.name).collect();
        // Legacy prompt-based built-ins
        assert!(names.contains(&"help".to_string()));
        assert!(names.contains(&"recall".to_string()));
        assert!(names.contains(&"status".to_string()));
        assert!(names.contains(&"jobs".to_string()));
        assert!(names.contains(&"rollback".to_string()));
        assert!(names.contains(&"critic".to_string()));
        // Pick #30 action-based built-ins
        assert!(names.contains(&"wizard".to_string()));
        assert!(names.contains(&"config".to_string()));
        assert!(names.contains(&"provider".to_string()));
        assert!(names.contains(&"connect".to_string()));
        assert!(names.contains(&"disconnect".to_string()));
        assert!(names.contains(&"skill".to_string()));
        assert!(names.contains(&"plugin".to_string()));
        assert!(names.contains(&"memory".to_string()));
        assert!(names.contains(&"consent".to_string()));
        assert!(names.contains(&"reload".to_string()));
        assert!(names.contains(&"autonomy".to_string()));
        assert!(names.contains(&"quit".to_string()));
    }

    #[test]
    fn every_action_built_in_has_action_field_set() {
        let action_names = [
            "wizard",
            "config",
            "provider",
            "connect",
            "disconnect",
            "skill",
            "plugin",
            "memory",
            "consent",
            "reload",
            "autonomy",
            "quit",
        ];
        let cmds = built_in_commands();
        for name in action_names {
            let cmd = cmds.iter().find(|c| c.name == name).expect("present");
            assert!(
                cmd.action.is_some(),
                "{name} must carry an action — empty prompt would silently do nothing"
            );
        }
    }

    #[test]
    fn every_prompt_built_in_has_action_none() {
        let prompt_names = ["help", "recall", "status", "jobs", "rollback", "critic"];
        let cmds = built_in_commands();
        for name in prompt_names {
            let cmd = cmds.iter().find(|c| c.name == name).expect("present");
            assert!(
                cmd.action.is_none(),
                "{name} is prompt-based — action MUST stay None or the dispatcher \
                 will skip the LLM call"
            );
            assert!(
                !cmd.prompt.is_empty(),
                "{name} prompt-based but prompt is empty"
            );
        }
    }

    #[test]
    fn no_duplicate_built_in_names() {
        let cmds = built_in_commands();
        let mut names: Vec<&str> = cmds.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        let unique = names.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(
            unique,
            names.len(),
            "duplicate built-in names break override semantics"
        );
    }

    #[test]
    fn every_built_in_has_help_text() {
        for cmd in built_in_commands() {
            assert!(
                cmd.help.is_some(),
                "{} must ship a help line — operators rely on /help <name>",
                cmd.name,
            );
            assert!(
                !cmd.description.is_empty(),
                "{} missing description",
                cmd.name
            );
            assert!(cmd.enabled, "built-in {} ships disabled — fix", cmd.name);
        }
    }

    #[test]
    fn built_in_names_are_unique() {
        let names: Vec<String> = built_in_commands().into_iter().map(|c| c.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "duplicate built-in command names: {names:?}",
        );
    }
}
