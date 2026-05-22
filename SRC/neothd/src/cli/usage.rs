//! `neoth usage` — render the persisted usage log as a human-readable
//! or JSON rollup. QM-9 Phase 1 CLI surface. The Slint dashboard
//! panel (Phase 2) consumes the same `aggregate()` primitive.
//!
//! Default window: last 24h. Operator can widen with `--days N` or
//! pin a custom range with `--since-unix … --until-unix …`.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Args;

use crate::daemon::usage_log::{aggregate, UsageRollup};

/// CLI args for `neoth usage`.
#[derive(Args, Debug, Clone)]
pub struct UsageArgs {
    /// How many days back to aggregate (default 1).
    #[arg(long, default_value_t = 1)]
    pub days: u32,
    /// Output format: `table` (default) or `json`.
    #[arg(long, default_value = "table")]
    pub format: String,
    /// Optional explicit start unix timestamp (overrides --days).
    #[arg(long)]
    pub since_unix: Option<i64>,
    /// Optional explicit end unix timestamp (overrides --days).
    #[arg(long)]
    pub until_unix: Option<i64>,
}

/// Entry point for `Commands::Usage` dispatch.
pub fn run(home: &Path, args: UsageArgs) -> Result<()> {
    let format = UsageFormat::parse(&args.format).unwrap_or(UsageFormat::Table);
    match (args.since_unix, args.until_unix) {
        (Some(s), Some(u)) => run_usage_range(home, s, u, format),
        (Some(s), None) => {
            let now = now_unix()?;
            run_usage_range(home, s, now, format)
        }
        (None, Some(u)) => {
            let since = u - (args.days.max(1) as i64) * 86_400;
            run_usage_range(home, since, u, format)
        }
        (None, None) => run_usage(home, args.days, format),
    }
}

fn now_unix() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .with_context(|| "system clock before unix epoch")?
        .as_secs() as i64)
}

/// Output mode for `neoth usage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageFormat {
    Table,
    Json,
}

impl UsageFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "table" | "txt" | "human" => Some(Self::Table),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// Aggregate the usage window and render to stdout.
pub fn run_usage(home: &Path, days: u32, format: UsageFormat) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .with_context(|| "system clock before unix epoch")?
        .as_secs() as i64;
    let since = now - (days.max(1) as i64) * 86_400;
    let roll = aggregate(home, since, now);
    match format {
        UsageFormat::Json => {
            let body = serde_json::to_string_pretty(&roll)?;
            println!("{body}");
        }
        UsageFormat::Table => {
            print_table(&roll);
        }
    }
    Ok(())
}

/// Same shape as `run_usage` but takes since/until explicitly.
pub fn run_usage_range(
    home: &Path,
    since_unix: i64,
    until_unix: i64,
    format: UsageFormat,
) -> Result<()> {
    let roll = aggregate(home, since_unix, until_unix);
    match format {
        UsageFormat::Json => {
            let body = serde_json::to_string_pretty(&roll)?;
            println!("{body}");
        }
        UsageFormat::Table => print_table(&roll),
    }
    Ok(())
}

fn print_table(roll: &UsageRollup) {
    println!(
        "Usage rollup [{} .. {}]  calls={} ok={} err={} in_tok={} out_tok={} cost=${:.4}",
        roll.since_unix,
        roll.until_unix,
        roll.total_call_count,
        roll.total_ok_count,
        roll.total_err_count,
        roll.total_input_tokens,
        roll.total_output_tokens,
        roll.total_cost_usd,
    );
    if roll.per_provider.is_empty() {
        println!("  (no events in window — check ~/.neoth/usage/)");
        return;
    }
    println!(
        "{:<20} {:>6} {:>6} {:>6} {:>10} {:>10} {:>10} {:>10}",
        "provider", "calls", "ok", "err", "in_tok", "out_tok", "cost_usd", "mean_ms"
    );
    for p in &roll.per_provider {
        println!(
            "{:<20} {:>6} {:>6} {:>6} {:>10} {:>10} {:>10.4} {:>10.0}",
            p.provider,
            p.call_count,
            p.ok_count,
            p.err_count,
            p.input_tokens,
            p.output_tokens,
            p.cost_usd,
            p.mean_latency_ms,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::usage_log::{append, UsageEvent};
    use tempfile::tempdir;

    #[test]
    fn parse_format_accepts_known_aliases() {
        assert_eq!(UsageFormat::parse("table"), Some(UsageFormat::Table));
        assert_eq!(UsageFormat::parse("TXT"), Some(UsageFormat::Table));
        assert_eq!(UsageFormat::parse("HUMAN"), Some(UsageFormat::Table));
        assert_eq!(UsageFormat::parse("json"), Some(UsageFormat::Json));
        assert_eq!(UsageFormat::parse("JSON"), Some(UsageFormat::Json));
        assert_eq!(UsageFormat::parse("yaml"), None);
        assert_eq!(UsageFormat::parse(""), None);
    }

    #[test]
    fn run_usage_with_empty_home_prints_zero_rollup_without_error() {
        // Smoke: shouldn't panic when there's no usage dir at all.
        let dir = tempdir().unwrap();
        run_usage(dir.path(), 1, UsageFormat::Json).unwrap();
        run_usage(dir.path(), 1, UsageFormat::Table).unwrap();
    }

    #[test]
    fn run_usage_range_aggregates_events_in_explicit_window() {
        let dir = tempdir().unwrap();
        for ts in [1_779_494_400_i64, 1_779_494_500, 1_779_999_999] {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: ts,
                    provider: "openai_api".into(),
                    model: "gpt-5.5".into(),
                    input_tokens: 1,
                    output_tokens: 2,
                    cost_usd: 0.001,
                    latency_ms: 10,
                    ok: true,
                },
            )
            .unwrap();
        }
        // Both formats run to completion; we don't capture stdout here.
        run_usage_range(dir.path(), 1_779_494_400, 1_779_494_700, UsageFormat::Json).unwrap();
        run_usage_range(dir.path(), 0, i64::MAX, UsageFormat::Table).unwrap();
    }
}
