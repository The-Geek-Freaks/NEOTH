//! NOOB-UX-5 — `neoth tour` first-launch operator tour.
//!
//! Per `PLAN/PROGRESS.md` NOOB-UX-5: "First-launch tour after the
//! wizard finishes — three or four interactive screens that show
//! 'this is how you send a message', 'this is where your memory
//! lives', 'this is how to revoke consent'. Lands as a separate
//! `neoth tour` CLI subcommand for now; the GUI gets a guided
//! overlay later."
//!
//! Pure stdout; no network, no mutation. Operator runs `neoth tour`
//! immediately post-`neoth init` (or any later time as a refresher).
//! `--step <id>` jumps to a single tour stop.

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct TourArgs {
    /// Show one tour stop only. Stops: `chat` / `memory` / `consent`
    /// / `audit` / `next`. Without this flag, prints every stop in
    /// order (the full guided tour).
    #[arg(long, value_name = "ID")]
    pub step: Option<String>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Clone, Debug, Serialize)]
pub struct TourStop {
    pub id: &'static str,
    pub title: &'static str,
    pub body: &'static str,
    pub try_command: &'static str,
}

pub const TOUR: &[TourStop] = &[
    TourStop {
        id: "chat",
        title: "1. Send a chat message",
        body: "NEOTH is reachable three ways: the CLI (`neoth chat \"hello\"`), \
               the desktop GUI (the chat tab), or any configured channel \
               (Telegram / Slack / WhatsApp). Every path lands the same \
               provider + WAL + permission gates. The CLI is the simplest \
               first call — provider is the one you picked in `neoth init`.",
        try_command: "neoth chat \"Hello — are you live?\"",
    },
    TourStop {
        id: "memory",
        title: "2. See what NEOTH remembers about you",
        body: "Every chat is logged to the WAL (`~/.neoth/wal/`) + indexed \
               into the recall views (`~/.neoth/views.db`). Operator-fact \
               claims grow PASSIVELY only when you opt in: \
               `profile.learn_enabled: true` in `~/.neoth/freedom.yaml`. \
               Manual decay-immune facts go via `neoth groundtruth add \
               \"<statement>\"`. Search what's there with `neoth recall \
               \"<query>\"`.",
        try_command: "neoth recall \"my name\"",
    },
    TourStop {
        id: "consent",
        title: "3. Revoke consent — make NEOTH forget something",
        body: "Two-tier forget: `neoth memory forget --topic X` marks the \
               topic tombstoned (recall surface skips it); add `--physical` \
               to overwrite the actual WAL payload bytes with zeros (GDPR-\
               grade hard-delete). Channel-side blocks live in \
               `~/.neoth/policy.yaml::channels` so a sender-id is refused \
               at the door.",
        try_command: "neoth memory forget --topic \"my password\"",
    },
    TourStop {
        id: "audit",
        title: "4. Check the privacy posture",
        body: "Before sending sensitive input, run `neoth privacy audit` \
               (L-08). It reports — without making any network call — \
               which provider the next chat would hit, whether profile \
               learning is on + on which provider (cloud or local), \
               which channels carry your messages off-machine, and how \
               WAL frames are sealed.",
        try_command: "neoth privacy audit",
    },
    TourStop {
        id: "next",
        title: "5. Where to go from here",
        body: "Glossary cheat sheet: `neoth glossary` (defines every NEOTH \
               term — plugin / channel / council / hemisphere / mode / \
               groundtruth / ...). Doctor diagnostics: `neoth doctor` runs \
               19 checks + reports gaps. Config reference: \
               `docs/configuration.md`. Sub-agents: `neoth agents list`. \
               Hooks: `neoth hooks list`. Skills: `neoth skills list`. \
               Modes: `neoth mode list`.",
        try_command: "neoth glossary",
    },
];

pub fn run_tour(args: TourArgs) -> Result<()> {
    let stops: Vec<&TourStop> = match args.step.as_deref() {
        Some(id) => {
            let filtered: Vec<_> = TOUR.iter().filter(|s| s.id == id).collect();
            if filtered.is_empty() {
                eprintln!(
                    "no tour stop with id `{id}`. Available: {}",
                    TOUR.iter()
                        .map(|s| s.id)
                        .collect::<Vec<_>>()
                        .join(" / ")
                );
                return Ok(());
            }
            filtered
        }
        None => TOUR.iter().collect(),
    };
    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&stops)?),
        OutputFormat::Jsonl => {
            for s in &stops {
                println!("{}", serde_json::to_string(s)?);
            }
        }
        OutputFormat::Table => {
            if args.step.is_none() {
                println!("# `neoth tour` — first-launch operator orientation\n");
                println!(
                    "Run any specific stop with `neoth tour --step <id>` \
                     (chat / memory / consent / audit / next).\n"
                );
            }
            for s in &stops {
                println!("## {}", s.title);
                println!();
                for line in s.body.lines() {
                    println!("{line}");
                }
                println!();
                println!("Try it: `{}`", s.try_command);
                println!();
                println!("{}", "-".repeat(60));
                println!();
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tour_has_at_least_four_stops() {
        // NOOB-UX-5 spec said "three or four interactive screens";
        // we ship five (added a 'next' pointer). Pin so a future
        // refactor that drops one fails here.
        assert!(TOUR.len() >= 4);
    }

    #[test]
    fn tour_covers_required_topics() {
        // Pin the required topic ids — operator-facing contract.
        let ids: Vec<&str> = TOUR.iter().map(|s| s.id).collect();
        for required in ["chat", "memory", "consent"] {
            assert!(ids.contains(&required), "tour missing stop: {required}");
        }
    }

    #[test]
    fn every_tour_stop_has_try_command_starting_with_neoth() {
        // Every stop must have a concrete `neoth ...` command the
        // operator can try. Pin so a future contributor who adds a
        // pure-prose stop without a hands-on action surfaces here.
        for s in TOUR {
            assert!(
                s.try_command.starts_with("neoth "),
                "stop `{}` try_command must start with `neoth `",
                s.id
            );
            assert!(!s.body.is_empty(), "stop `{}` body is empty", s.id);
            assert!(!s.title.is_empty(), "stop `{}` title is empty", s.id);
        }
    }

    #[test]
    fn tour_stop_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for s in TOUR {
            assert!(seen.insert(s.id), "duplicate tour stop id: {}", s.id);
        }
    }

    #[test]
    fn run_tour_with_unknown_step_does_not_error() {
        let args = TourArgs {
            step: Some("nonexistent".into()),
            output: OutputFormat::Table,
        };
        let r = run_tour(args);
        assert!(r.is_ok());
    }

    #[test]
    fn run_tour_full_walk_is_ok() {
        let args = TourArgs {
            step: None,
            output: OutputFormat::Table,
        };
        let r = run_tour(args);
        assert!(r.is_ok());
    }

    #[test]
    fn run_tour_single_step_is_ok() {
        let args = TourArgs {
            step: Some("chat".into()),
            output: OutputFormat::Table,
        };
        let r = run_tour(args);
        assert!(r.is_ok());
    }
}
