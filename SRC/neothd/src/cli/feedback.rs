//! `neoth feedback summary` — G-03 operator-facing consumer.
//!
//! Turns the raw `0xBB OPERATOR_FEEDBACK` frames (which `neoth wal show --type
//! operator_feedback` shows one-by-one) into an actionable AGGREGATE: how often
//! the operator pushed back over a recent window, the top correction-pattern
//! labels, and the resulting pressure level. The same aggregate drives the
//! profile-adapt cron's sustained-pushback self-dev proposal.
//!
//! Read-only over the WAL — no daemon required.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::feedback::consume::{FeedbackPressure, aggregate_recent_feedback};

#[derive(Args, Debug, Clone)]
pub struct FeedbackArgs {
    #[command(subcommand)]
    pub action: FeedbackAction,
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum FeedbackAction {
    /// Aggregate recent operator-correction (`0xBB`) signals into a report:
    /// count, top correction patterns, pressure level. The consumer side of
    /// the G-03 self-correction loop.
    Summary {
        /// Look-back window, e.g. `7d`, `48h`, `3600` (bare seconds). Default 7d.
        #[arg(long, default_value = "7d")]
        window: String,
    },
}

pub async fn run_feedback(args: FeedbackArgs) -> Result<()> {
    match args.action {
        FeedbackAction::Summary { window } => run_summary(&window, &args.output).await,
    }
}

async fn run_summary(window: &str, output: &OutputFormat) -> Result<()> {
    let window_secs = crate::cli::privacy::parse_duration(window)
        .map(|secs| secs as i64)
        .unwrap_or(7 * 24 * 3600);
    let home = FreedomConfig::default_neoth_home();
    let wal_dir = home.join("wal");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let summary = aggregate_recent_feedback(&wal_dir, window_secs, now);
    let pressure = summary.pressure();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "window_secs": summary.window_secs,
                "corrections": summary.corrections,
                "pressure": pressure.as_str(),
                "top_patterns": summary
                    .top_patterns
                    .iter()
                    .map(|(label, count)| serde_json::json!({ "pattern": label, "count": count }))
                    .collect::<Vec<_>>(),
                "latest_unix": summary.latest_unix,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Operator feedback (last {window})");
            println!("  corrections : {}", summary.corrections);
            println!("  pressure    : {}", pressure.as_str());
            if summary.top_patterns.is_empty() {
                println!("  patterns    : (none)");
            } else {
                println!("  top patterns:");
                for (label, count) in &summary.top_patterns {
                    println!("    {count:>4}  {label}");
                }
            }
            println!();
            match pressure {
                FeedbackPressure::Low => {
                    println!("  NEOTH is tracking your corrections well — nothing to act on.");
                }
                FeedbackPressure::Elevated => {
                    println!(
                        "  A noticeable run of corrections. Review the patterns above; the \
                         profile-adapt cron will propose an adjustment if it persists."
                    );
                }
                FeedbackPressure::High => {
                    println!(
                        "  Sustained pushback — the profile-adapt cron queues a self-dev \
                         proposal. Review it with `neoth self-dev review`."
                    );
                }
            }
        }
    }
    Ok(())
}
