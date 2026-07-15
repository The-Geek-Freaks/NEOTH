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

use crate::daemon::usage_log::{UsageRollup, aggregate};
use crate::providers::cost::{Currency, convert_from_usd, format_amount};

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
    /// Display currency: USD (default) / EUR / GBP / CHF / JPY / CNY.
    /// Storage canonical stays USD; this only affects the rendering.
    /// Operator can also pin in `freedom.yaml::usage_currency`.
    #[arg(long)]
    pub currency: Option<String>,
}

/// Entry point for `Commands::Usage` dispatch.
pub fn run(home: &Path, args: UsageArgs) -> Result<()> {
    let format = UsageFormat::parse(&args.format).unwrap_or(UsageFormat::Table);
    let currency = resolve_currency(home, args.currency.as_deref());
    match (args.since_unix, args.until_unix) {
        (Some(s), Some(u)) => run_usage_range(home, s, u, format, currency),
        (Some(s), None) => {
            let now = now_unix()?;
            run_usage_range(home, s, now, format, currency)
        }
        (None, Some(u)) => {
            let since = u - (args.days.max(1) as i64) * 86_400;
            run_usage_range(home, since, u, format, currency)
        }
        (None, None) => run_usage(home, args.days, format, currency),
    }
}

/// Resolve the display currency. Precedence:
///   1. `--currency` flag (explicit operator override)
///   2. `freedom.yaml::usage_currency`
///   3. USD (default)
pub fn resolve_currency(home: &Path, flag: Option<&str>) -> Currency {
    if let Some(s) = flag {
        if let Some(c) = Currency::parse(s) {
            return c;
        }
    }
    let path = home.join("freedom.yaml");
    if let Ok(body) = std::fs::read_to_string(&path) {
        if let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body) {
            if let Some(s) = val.get("usage_currency").and_then(|v| v.as_str()) {
                if let Some(c) = Currency::parse(s) {
                    return c;
                }
            }
        }
    }
    Currency::default()
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
pub fn run_usage(home: &Path, days: u32, format: UsageFormat, currency: Currency) -> Result<()> {
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
            print_table(&roll, currency);
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
    currency: Currency,
) -> Result<()> {
    let roll = aggregate(home, since_unix, until_unix);
    match format {
        UsageFormat::Json => {
            let body = serde_json::to_string_pretty(&roll)?;
            println!("{body}");
        }
        UsageFormat::Table => print_table(&roll, currency),
    }
    Ok(())
}

fn print_table(roll: &UsageRollup, currency: Currency) {
    let total_in_target = convert_from_usd(roll.total_cost_usd, currency);
    println!(
        "Usage rollup [{} .. {}]  calls={} ok={} err={} in_tok={} out_tok={} cost={}",
        roll.since_unix,
        roll.until_unix,
        roll.total_call_count,
        roll.total_ok_count,
        roll.total_err_count,
        roll.total_input_tokens,
        roll.total_output_tokens,
        format_amount(total_in_target, currency),
    );
    // VIEW-02 + VIEW-07 — spend RATE / projection + overall latency tail.
    let burn_in_target = convert_from_usd(roll.burn_rate_usd_per_day, currency);
    let monthly_in_target = convert_from_usd(roll.projected_monthly_usd, currency);
    println!(
        "  spend rate: {}/day  ->  projected {}/month   |   latency p50={}ms p90={}ms",
        format_amount(burn_in_target, currency),
        format_amount(monthly_in_target, currency),
        roll.total_p50_latency_ms,
        roll.total_p90_latency_ms,
    );
    if roll.total_unknown_input_token_count > 0
        || roll.total_unknown_output_token_count > 0
        || roll.total_unknown_cost_count > 0
    {
        println!(
            "  unreported: input_tokens={} output_tokens={} cost={} (known totals above stay partial)",
            roll.total_unknown_input_token_count,
            roll.total_unknown_output_token_count,
            roll.total_unknown_cost_count,
        );
    }
    // VIEW-06 — session-type split (shown only when post-VIEW-06 data present).
    if roll.total_automated_count + roll.total_human_count > 0 {
        println!(
            "  session type: human={} automated={}",
            roll.total_human_count, roll.total_automated_count,
        );
    }
    // VIEW-03 — cache token economics (shown only when cache was used).
    if roll.total_cache_creation_tokens > 0 || roll.total_cache_read_tokens > 0 {
        let savings_in_target = convert_from_usd(roll.total_cache_savings_usd, currency);
        println!(
            "  cache: created={} read={}  net savings={}{}",
            roll.total_cache_creation_tokens,
            roll.total_cache_read_tokens,
            format_amount(savings_in_target.abs(), currency),
            if roll.total_cache_savings_usd < 0.0 {
                " (cost)"
            } else {
                ""
            },
        );
    }
    if roll.per_provider.is_empty() {
        println!("  (no events in window — check ~/.neoth/usage/)");
        return;
    }
    let cost_col = format!("cost_{}", currency.code().to_lowercase());
    println!(
        "{:<20} {:>6} {:>6} {:>6} {:>10} {:>10} {:>12} {:>8} {:>8} {:>8}",
        "provider",
        "calls",
        "ok",
        "err",
        "in_tok",
        "out_tok",
        cost_col,
        "mean_ms",
        "p50_ms",
        "p90_ms"
    );
    for p in &roll.per_provider {
        let cost_in_target = convert_from_usd(p.cost_usd, currency);
        println!(
            "{:<20} {:>6} {:>6} {:>6} {:>10} {:>10} {:>12} {:>8.0} {:>8} {:>8}",
            p.provider,
            p.call_count,
            p.ok_count,
            p.err_count,
            p.input_tokens,
            p.output_tokens,
            format_amount(cost_in_target, currency),
            p.mean_latency_ms,
            p.p50_latency_ms,
            p.p90_latency_ms,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::usage_log::{UsageEvent, append};
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
        run_usage(dir.path(), 1, UsageFormat::Json, Currency::Usd).unwrap();
        run_usage(dir.path(), 1, UsageFormat::Table, Currency::Eur).unwrap();
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
                    input_tokens: Some(1),
                    output_tokens: Some(2),
                    cost_usd: Some(0.001),
                    latency_ms: 10,
                    ok: true,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        run_usage_range(
            dir.path(),
            1_779_494_400,
            1_779_494_700,
            UsageFormat::Json,
            Currency::Usd,
        )
        .unwrap();
        run_usage_range(dir.path(), 0, i64::MAX, UsageFormat::Table, Currency::Gbp).unwrap();
    }

    #[test]
    fn resolve_currency_flag_wins_over_freedom_yaml() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("freedom.yaml"), "usage_currency: EUR\n").unwrap();
        assert_eq!(resolve_currency(dir.path(), Some("GBP")), Currency::Gbp);
        assert_eq!(resolve_currency(dir.path(), None), Currency::Eur);
        assert_eq!(resolve_currency(dir.path(), Some("invalid")), Currency::Eur);
    }

    #[test]
    fn resolve_currency_defaults_to_usd_on_no_config() {
        let dir = tempdir().unwrap();
        assert_eq!(resolve_currency(dir.path(), None), Currency::Usd);
    }
}
