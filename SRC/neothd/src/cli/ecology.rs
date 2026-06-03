//! `neoth ecology` — CH-13 / F4-01 operator surface (read-only).
//!
//! `correlation` is the first Ecology slice: a deterministic, LLM-free scan of
//! the `0x63 COUNCIL_WINNER_SELECTED` WAL frames that reports when one provider
//! has won many consecutive outer-council debates (a low-dissent signal). It is
//! purely diagnostic — it changes nothing — so it works whether or not the
//! Ecology auto-scheduler (`ecology.enabled`) is on.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::ecology::correlation_detector::{detect_winner_streaks, scan_winner_records};

#[derive(Args, Debug, Clone)]
pub struct EcologyArgs {
    #[command(subcommand)]
    pub action: EcologyAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum EcologyAction {
    /// Report council-winner correlation: providers that won many consecutive
    /// outer-council debates (a low-dissent fitness signal). Read-only.
    Correlation {
        /// Minimum consecutive-win streak to report. Defaults to
        /// `freedom.yaml::ecology.correlation_min_streak` (5).
        #[arg(long)]
        min_streak: Option<usize>,
        /// Override the WAL directory (mostly for tests).
        #[arg(long, value_name = "DIR")]
        wal_dir: Option<PathBuf>,
    },
}

pub async fn run_ecology(args: EcologyArgs) -> Result<()> {
    match args.action {
        EcologyAction::Correlation {
            min_streak,
            wal_dir,
        } => {
            let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
            let min_streak = min_streak.unwrap_or(cfg.ecology.correlation_min_streak).max(1);
            let wal_dir = wal_dir.unwrap_or_else(FreedomConfig::default_wal_dir);

            let records = scan_winner_records(&wal_dir);
            let signals = detect_winner_streaks(&records, min_streak);

            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "total_winners": records.len(),
                            "min_streak": min_streak,
                            "signals": signals,
                        })
                    );
                }
                OutputFormat::Table => {
                    println!(
                        "council-winner correlation — {} winner(s) scanned, threshold {}",
                        records.len(),
                        min_streak
                    );
                    if signals.is_empty() {
                        println!(
                            "  (no low-dissent streaks ≥ {min_streak} — the council is surfacing diversity)"
                        );
                    } else {
                        for s in &signals {
                            println!(
                                "  ⚠ {} won {} consecutive debates (low-dissent signal)",
                                s.provider, s.streak_len
                            );
                        }
                    }
                }
            }
            Ok(())
        }
    }
}
