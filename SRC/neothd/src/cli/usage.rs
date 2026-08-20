//! `neoth usage` — render the persisted usage log as a human-readable
//! or JSON rollup. QM-9 Phase 1 CLI surface. The Slint dashboard
//! panel (Phase 2) consumes the same `aggregate()` primitive.
//!
//! Default window: last 24h. Operator can widen with `--days N` or
//! pin a custom range with `--since-unix … --until-unix …`.

#[cfg(test)]
use std::fmt::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Args;

use crate::daemon::usage_log::{UsageRollup, WorkflowOtherTotals, aggregate};
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
    if let Some(s) = flag
        && let Some(c) = Currency::parse(s)
    {
        return c;
    }
    let path = home.join("freedom.yaml");
    if let Ok(body) = std::fs::read_to_string(&path)
        && let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body)
        && let Some(s) = val.get("usage_currency").and_then(|v| v.as_str())
        && let Some(c) = Currency::parse(s)
    {
        return c;
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
    let total_cost = format_known_cost(roll.total_cost_usd, currency);
    println!(
        "Usage rollup [{} .. {}]  calls={} ok={} err={} in_tok={} out_tok={} cost={}",
        roll.since_unix,
        roll.until_unix,
        roll.total_call_count,
        roll.total_ok_count,
        roll.total_err_count,
        roll.total_input_tokens,
        roll.total_output_tokens,
        total_cost,
    );
    // VIEW-02 + VIEW-07 — spend RATE / projection + overall latency tail.
    let burn = format_known_cost(roll.burn_rate_usd_per_day, currency);
    let monthly = format_known_cost(roll.projected_monthly_usd, currency);
    println!(
        "  spend rate: {}/day  ->  projected {}/month   |   latency p50={}ms p90={}ms",
        burn,
        monthly,
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
        let cost = format_known_cost(p.cost_usd, currency);
        println!(
            "{:<20} {:>6} {:>6} {:>6} {:>10} {:>10} {:>12} {:>8.0} {:>8} {:>8}",
            p.provider,
            p.call_count,
            p.ok_count,
            p.err_count,
            p.input_tokens,
            p.output_tokens,
            cost,
            p.mean_latency_ms,
            p.p50_latency_ms,
            p.p90_latency_ms,
        );
    }
    print_workflow_table(roll, currency);
}

/// Render the bounded ADOPT31-D2 breakdown from the same serialized rollup
/// consumed by GUI clients. Currency conversion applies only to known USD;
/// `unpriced` remains a count and never becomes a fabricated zero.
fn print_workflow_table(roll: &UsageRollup, currency: Currency) {
    if roll.workflow_rollup_schema != Some(1) {
        return;
    }
    if roll.per_workflow.is_empty() && roll.workflow_other.is_none() {
        return;
    }
    println!("\nWorkflow cost attribution (closed audited classes)");
    println!("{:<24} {:>8} {:>16} {:>10}", "workflow", "calls", "known_cost", "unpriced");
    for totals in &roll.per_workflow {
        print_workflow_row(
            totals.workflow.as_str(),
            totals.call_count,
            totals.known_cost_usd,
            totals.unknown_cost_count,
            currency,
        );
    }
    if let Some(other) = &roll.workflow_other {
        let label = format!("other ({} workflows)", other.omitted_workflow_count);
        print_workflow_other_row(&label, other, currency);
    }
}

fn print_workflow_row(
    label: &str,
    calls: u64,
    known_cost_usd: f64,
    unpriced: u64,
    currency: Currency,
) {
    let known_cost = format_known_cost(known_cost_usd, currency);
    println!("{label:<24} {calls:>8} {known_cost:>16} {unpriced:>10}");
}

fn print_workflow_other_row(label: &str, totals: &WorkflowOtherTotals, currency: Currency) {
    print_workflow_row(
        label,
        totals.call_count,
        totals.known_cost_usd,
        totals.unknown_cost_count,
        currency,
    );
}

/// Render finite known USD without allowing a selected display-currency
/// conversion to overflow. The USD fallback preserves the known amount and is
/// preferable to emitting `inf` or falsely calling a known call unpriced.
fn format_known_cost(known_cost_usd: f64, currency: Currency) -> String {
    let converted = convert_from_usd(known_cost_usd, currency);
    if converted.is_finite() && converted >= 0.0 {
        format_amount(converted, currency)
    } else {
        format!("{} (USD)", format_amount(known_cost_usd, Currency::Usd))
    }
}

/// Deterministic, content-free workflow rows for tests and alternate local
/// renderers. The main table intentionally uses the same static labels.
#[cfg(test)]
fn render_workflow_rows(roll: &UsageRollup, currency: Currency) -> String {
    let mut output = String::new();
    if roll.workflow_rollup_schema != Some(1) {
        return output;
    }
    for totals in &roll.per_workflow {
        let _ = writeln!(
            output,
            "{}\t{}\t{}\t{}",
            totals.workflow.as_str(),
            totals.call_count,
            format_known_cost(totals.known_cost_usd, currency),
            totals.unknown_cost_count,
        );
    }
    if let Some(other) = &roll.workflow_other {
        let _ = writeln!(
            output,
            "other ({})\t{}\t{}\t{}",
            other.omitted_workflow_count,
            other.call_count,
            format_known_cost(other.known_cost_usd, currency),
            other.unknown_cost_count,
        );
    }
    output
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

    #[test]
    fn workflow_rows_are_deterministic_and_keep_unpriced_distinct_from_free() {
        let roll = UsageRollup {
            workflow_rollup_schema: Some(1),
            per_workflow: vec![
                crate::daemon::usage_log::PerWorkflowTotals {
                    workflow: crate::daemon::usage_log::WorkflowKey(
                        crate::daemon::usage_log::WorkflowKind::ChatTurn,
                    ),
                    call_count: 4,
                    known_cost_usd: 0.0,
                    known_cost_count: 2,
                    unknown_cost_count: 2,
                    ..Default::default()
                },
                crate::daemon::usage_log::PerWorkflowTotals {
                    workflow: crate::daemon::usage_log::WorkflowKey(
                        crate::daemon::usage_log::WorkflowKind::Unclassified,
                    ),
                    call_count: 1,
                    unknown_cost_count: 1,
                    ..Default::default()
                },
            ],
            workflow_other: Some(WorkflowOtherTotals {
                omitted_workflow_count: 3,
                call_count: 5,
                known_cost_usd: 1.25,
                known_cost_count: 5,
                ..Default::default()
            }),
            ..Default::default()
        };
        let rendered = render_workflow_rows(&roll, Currency::Usd);
        assert_eq!(
            rendered,
            "chat_turn\t4\t$0.0000\t2\nunclassified\t1\t$0.0000\t1\nother (3)\t5\t$1.2500\t0\n"
        );
        let json = serde_json::to_value(&roll).unwrap();
        assert_eq!(json["workflow_rollup_schema"], 1);
        assert_eq!(json["per_workflow"][0]["known_cost_count"], 2);
        assert_eq!(json["per_workflow"][0]["unknown_cost_count"], 2);
        assert_eq!(json["workflow_other"]["omitted_workflow_count"], 3);
    }

    #[test]
    fn workflow_currency_rendering_falls_back_to_finite_usd_on_overflow() {
        let rendered = format_known_cost(f64::MAX, Currency::Jpy);
        assert!(rendered.ends_with(" (USD)"));
        assert!(!rendered.contains("inf"));
        assert!(!rendered.contains("NaN"));
    }
}
