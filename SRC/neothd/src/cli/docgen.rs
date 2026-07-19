//! CLI-reference generator — DOC-01 anti-drift.
//!
//! Walks the live clap [`Command`] tree (the one `#[derive(Parser)]`
//! builds from `Cli`) and emits a markdown reference of every command,
//! subcommand, alias, and flag. Exposed via `neoth completions
//! --reference`.
//!
//! Why this exists: a hand-maintained CLI reference DRIFTS — a doc audit
//! found dozens of documented `neoth <cmd>` invocations that no longer
//! matched the real CLI (wrong names, subcommand-vs-flag, nonexistent
//! subcommands). For a product whose wedge is *verifiable* — every
//! documented command must actually work — that is a credibility hole.
//! Generating the reference FROM the clap tree makes drift impossible:
//! the `cli_commands_md_is_up_to_date` test regenerates and fails CI if
//! `docs/cli-commands.md` is stale, so the doc is always the CLI.

use clap::Command;

/// Render the full CLI reference as markdown from the clap root command.
/// Deterministic: subcommands are sorted by name, so the output is stable
/// across runs (the drift test compares it byte-for-byte).
pub fn render_cli_reference(root: &Command) -> String {
    let mut out = String::new();
    out.push_str("# NEOTH CLI reference\n\n");
    out.push_str(
        "> **Generated** from the clap command tree by `neoth completions --reference`.\n\
         > Do not edit by hand — it is the authoritative, drift-proof list of every\n\
         > command + flag. Regenerate with\n\
         > `NEOTH_REGEN_CLI_DOCS=1 cargo test -p neoth cli_commands_md_is_up_to_date`.\n\
         > For the operator *guide* (with prose + workflows) see\n\
         > [cli-reference.md](cli-reference.md); for the journey see\n\
         > [operator-journey.md](operator-journey.md).\n\n",
    );
    if let Some(about) = short_about(root) {
        out.push_str(&format!("`neoth` — {about}\n\n"));
    }
    out.push_str("---\n\n");

    let mut subs: Vec<&Command> = root.get_subcommands().collect();
    subs.sort_by_key(|c| c.get_name().to_string());
    for sub in subs {
        render_command(&mut out, "neoth", sub, 2);
    }
    let content_len = out.trim_end_matches('\n').len();
    out.truncate(content_len);
    out.push('\n');
    out
}

/// Append one command (and its nested subcommands) at the given heading
/// level. `parent` is the invocation prefix, e.g. `"neoth"` →
/// `"neoth wal"`.
fn render_command(out: &mut String, parent: &str, cmd: &Command, level: usize) {
    let path = format!("{parent} {}", cmd.get_name());
    let hashes = "#".repeat(level.min(6));
    out.push_str(&format!("{hashes} `{path}`"));
    if cmd.is_hide_set() {
        out.push_str(" _(hidden)_");
    }
    out.push('\n');

    if let Some(about) = short_about(cmd) {
        out.push_str(&format!("\n{about}\n"));
    }

    let aliases: Vec<String> = cmd.get_visible_aliases().map(|s| s.to_string()).collect();
    if !aliases.is_empty() {
        let joined = aliases
            .iter()
            .map(|a| format!("`{parent} {a}`"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("\n_Aliases:_ {joined}\n"));
    }

    // Operator-facing args only — drop the auto-injected help/version.
    let args: Vec<&clap::Arg> = cmd
        .get_arguments()
        .filter(|a| {
            let id = a.get_id().as_str();
            id != "help" && id != "version" && !a.is_hide_set()
        })
        .collect();
    if !args.is_empty() {
        out.push('\n');
        for arg in args {
            out.push_str(&format!("- {}\n", render_arg(arg)));
        }
    }
    out.push('\n');

    let mut subs: Vec<&Command> = cmd.get_subcommands().collect();
    subs.sort_by_key(|c| c.get_name().to_string());
    for s in subs {
        render_command(out, &path, s, level + 1);
    }
}

/// One arg as a markdown bullet: the flag/positional form + its first
/// line of help.
fn render_arg(arg: &clap::Arg) -> String {
    let help = arg
        .get_help()
        .map(|h| h.to_string())
        .or_else(|| arg.get_long_help().map(|h| h.to_string()))
        .map(|h| h.lines().next().unwrap_or("").trim().to_string())
        .unwrap_or_default();
    // Bool presence flags (SetTrue/SetFalse) and counters take NO value —
    // rendering `--critique <CRITIQUE>` misled operators into passing
    // `--critique true`, which clap rejects (error-hunt 2026-07-03).
    let takes_value = !matches!(
        arg.get_action(),
        clap::ArgAction::SetTrue
            | clap::ArgAction::SetFalse
            | clap::ArgAction::Count
            | clap::ArgAction::Help
            | clap::ArgAction::HelpShort
            | clap::ArgAction::HelpLong
            | clap::ArgAction::Version
    );
    let value = if takes_value {
        arg.get_value_names().map(|names| {
            names
                .iter()
                .map(|n| format!("<{n}>"))
                .collect::<Vec<_>>()
                .join(" ")
        })
    } else {
        None
    };

    let form = if arg.is_positional() {
        value
            .clone()
            .unwrap_or_else(|| format!("<{}>", arg.get_id()))
    } else {
        let mut flag = String::new();
        if let Some(s) = arg.get_short() {
            flag.push_str(&format!("-{s}"));
        }
        if let Some(l) = arg.get_long() {
            if !flag.is_empty() {
                flag.push_str(", ");
            }
            flag.push_str(&format!("--{l}"));
        }
        if flag.is_empty() {
            flag = arg.get_id().to_string();
        }
        match &value {
            Some(v) => format!("{flag} {v}"),
            None => flag,
        }
    };

    if help.is_empty() {
        format!("`{form}`")
    } else {
        format!("`{form}` — {help}")
    }
}

/// The command's concise about line (first line of the doc comment),
/// preferring `about` then the first line of `long_about`.
fn short_about(cmd: &Command) -> Option<String> {
    cmd.get_about()
        .map(|s| s.to_string())
        .or_else(|| cmd.get_long_about().map(|s| s.to_string()))
        .map(|s| s.lines().next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn reference() -> String {
        render_cli_reference(&crate::cli::Cli::command())
    }

    #[test]
    fn reference_covers_core_commands_with_real_invocation_paths() {
        let md = reference();
        // Every one of these is an operator-facing surface — the
        // reference MUST list it with its real `neoth <cmd>` path.
        for cmd in [
            "neoth init",
            "neoth serve",
            "neoth chat",
            "neoth recall",
            "neoth verify",
            "neoth privacy",
            "neoth wal",
            "neoth plugin",
            "neoth council",
            "neoth models",
            "neoth provider",
        ] {
            assert!(
                md.contains(&format!("`{cmd}`")),
                "reference missing `{cmd}`"
            );
        }
    }

    #[test]
    fn reference_surfaces_the_forgiving_aliases() {
        // The aliases added in the doc audit (model/skill/channels/
        // providers) must appear so operators see both forms work.
        let md = reference();
        assert!(md.contains("Aliases:"), "no alias section rendered");
        assert!(md.contains("`neoth model`"), "models→model alias missing");
        assert!(
            md.contains("`neoth providers`"),
            "provider→providers alias missing"
        );
    }

    #[test]
    fn reference_lists_wal_show_type_flag() {
        // The ship-blocker we implemented: `wal show --type` must be in
        // the generated reference (proves the generator descends into
        // subcommand flags, and pins the flag's existence).
        let md = reference();
        assert!(
            md.contains("`neoth wal show`"),
            "wal show subcommand missing"
        );
        assert!(
            md.contains("--type"),
            "wal show --type flag missing from reference"
        );
    }

    #[test]
    fn reference_keeps_private_release_helper_schema_cross_platform() {
        // Hidden machine-only commands are still part of the generated
        // drift contract. Their clap schema must therefore be identical on
        // Windows, macOS, and Linux even though execution is Windows-only.
        let md = reference();
        assert!(md.contains("`neoth internal bundle-transaction handoff`"));
        assert!(md.contains("`neoth internal bundle-transaction cleanup-handoff`"));
    }

    #[test]
    fn reference_is_deterministic() {
        // Two renders must be byte-identical (the drift test relies on
        // this). Catches any HashMap-iteration-order leak.
        assert_eq!(reference(), reference());
    }

    #[test]
    fn reference_ends_with_exactly_one_newline() {
        let md = reference();
        assert!(md.ends_with('\n'));
        assert!(!md.ends_with("\n\n"));
    }

    /// DOC-01 anti-drift guard. The committed `docs/cli-commands.md` MUST
    /// equal the freshly-rendered reference — so a new command / flag /
    /// alias / renamed subcommand fails CI until the doc is regenerated.
    /// Regenerate with `NEOTH_REGEN_CLI_DOCS=1 cargo test -p neoth
    /// cli_commands_md_is_up_to_date`.
    #[test]
    fn cli_commands_md_is_up_to_date() {
        let generated = reference();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/cli-commands.md");
        if std::env::var("NEOTH_REGEN_CLI_DOCS").is_ok() {
            std::fs::write(path, &generated).expect("write docs/cli-commands.md");
            return;
        }
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        // Normalise line endings so a CRLF checkout doesn't false-fail.
        let norm = |s: &str| s.replace("\r\n", "\n");
        assert_eq!(
            norm(&committed),
            norm(&generated),
            "docs/cli-commands.md is STALE — the CLI changed but the generated reference \
             was not regenerated. Run: NEOTH_REGEN_CLI_DOCS=1 cargo test -p neoth \
             cli_commands_md_is_up_to_date"
        );
    }
}
