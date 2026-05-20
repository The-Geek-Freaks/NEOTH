//! `neoth completions` — emit shell-completion scripts.
//!
//! Operators install completions once per shell:
//!
//! ```bash
//! # bash
//! neoth completions bash > /etc/bash_completion.d/neoth
//! # zsh
//! neoth completions zsh > "${fpath[1]}/_neoth"
//! # fish
//! neoth completions fish > ~/.config/fish/completions/neoth.fish
//! # PowerShell
//! neoth completions powershell | Out-String | Invoke-Expression
//! ```
//!
//! Generated via `clap_complete` from the live `Cli` definition — every
//! new subcommand picks up completions automatically without an extra
//! source-of-truth file.

use std::io;

use anyhow::Result;
use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{Shell, generate};

#[derive(Args, Debug, Clone)]
pub struct CompletionsArgs {
    /// Target shell. `bash | zsh | fish | powershell | elvish`.
    pub shell: CompletionShell,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
}

impl From<CompletionShell> for Shell {
    fn from(s: CompletionShell) -> Self {
        match s {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Zsh => Shell::Zsh,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::Powershell => Shell::PowerShell,
            CompletionShell::Elvish => Shell::Elvish,
        }
    }
}

pub async fn run_completions(args: CompletionsArgs) -> Result<()> {
    let mut cmd = super::Cli::command();
    let bin = cmd.get_name().to_string();
    generate(Shell::from(args.shell), &mut cmd, bin, &mut io::stdout());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn render_to_string(shell: Shell) -> String {
        let mut cmd = super::super::Cli::command();
        let bin = cmd.get_name().to_string();
        let mut buf = Cursor::new(Vec::<u8>::new());
        generate(shell, &mut cmd, bin, &mut buf);
        String::from_utf8(buf.into_inner()).expect("clap_complete emits utf-8")
    }

    #[test]
    fn bash_completion_mentions_every_subcommand() {
        let body = render_to_string(Shell::Bash);
        // Spot-check a handful of subcommands — every one of these is
        // exposed to the operator and must complete.
        for required in [
            "init",
            "serve",
            "chat",
            "recall",
            "groundtruth",
            "doctor",
            "events",
            "schema",
            "wal",
            "keys",
            "backup",
            "restore",
            "verify",
            "migrate",
        ] {
            assert!(
                body.contains(required),
                "bash completion missing subcommand `{required}`",
            );
        }
    }

    #[test]
    fn zsh_completion_renders_non_empty() {
        let body = render_to_string(Shell::Zsh);
        assert!(body.len() > 1000, "zsh completion suspiciously short");
        assert!(body.contains("_neoth"), "zsh completion must define _neoth");
    }

    #[test]
    fn fish_completion_uses_complete_command() {
        let body = render_to_string(Shell::Fish);
        assert!(body.contains("complete -c"));
        assert!(body.contains("neoth"));
    }

    #[test]
    fn powershell_completion_renders() {
        let body = render_to_string(Shell::PowerShell);
        assert!(body.contains("Register-ArgumentCompleter"));
    }

    #[test]
    fn elvish_completion_renders() {
        // Just ensure no panic and some content lands.
        let body = render_to_string(Shell::Elvish);
        assert!(!body.is_empty());
    }

    #[test]
    fn shell_enum_maps_to_clap_shell() {
        // Smoke check: round-trip every variant. If a new clap_complete
        // version renames `PowerShell`, this catches it at compile time.
        let mapped: Vec<Shell> = [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
            CompletionShell::Powershell,
            CompletionShell::Elvish,
        ]
        .into_iter()
        .map(Shell::from)
        .collect();
        assert_eq!(mapped.len(), 5);
    }
}
