//! `neoth quota` — per-provider 429 / backoff visibility.
//!
//! Reads + writes `~/.neoth/quota.json` via [`providers::quota::QuotaTracker`].
//! See `PLAN/SPEC_council_governance.md` §2.4 for the operator-facing UX.
//!
//! Today: scope is the provider-band 429 cascade (H5). Council-budget
//! commands (`set max_debates_per_day`, etc.) ship with the council
//! pipeline in a later phase — gated by the council module landing.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::providers::quota::{QuotaTracker, now_unix};

#[derive(Args, Debug, Clone)]
pub struct QuotaArgs {
    #[command(subcommand)]
    pub action: QuotaAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum QuotaAction {
    /// Show per-provider quota state. With `--provider X`, filter to one.
    Status {
        #[arg(long)]
        provider: Option<String>,
    },
    /// Reset the daily counter + clear any active backoff window for a
    /// single provider. Operator override — use sparingly. The 429 will
    /// re-trigger on the next call if the remote is still rate-limited.
    Reset { provider: String },
    /// Record an operator-observed daily request ceiling. Telemetry-only —
    /// NEOTH never refuses a call based on `--cap`; the only gating signal
    /// is an active 429 backoff window.
    SetCap { provider: String, cap: u32 },
}

pub async fn run_quota(args: QuotaArgs) -> Result<()> {
    let path = FreedomConfig::default_neoth_home().join("quota.json");
    match args.action {
        QuotaAction::Status { provider } => run_status(&path, provider.as_deref(), &args.output),
        QuotaAction::Reset { provider } => run_reset(&path, &provider, &args.output),
        QuotaAction::SetCap { provider, cap } => run_set_cap(&path, &provider, cap, &args.output),
    }
}

fn run_status(
    path: &std::path::Path,
    provider_filter: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let tracker = QuotaTracker::load_from(path).context("load quota state")?;
    let now = now_unix();
    let mut rows: Vec<_> = tracker
        .snapshot()
        .into_iter()
        .filter(|s| provider_filter.is_none_or(|p| p == s.provider))
        .collect();
    rows.sort_by(|a, b| a.provider.cmp(&b.provider));

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "now_unix": now,
                "providers": rows.iter().map(|s| serde_json::json!({
                    "provider": s.provider,
                    "requests_today": s.requests_today,
                    "estimated_daily_cap": s.estimated_daily_cap,
                    "healthy": s.is_healthy(now),
                    "backoff_remaining_secs": s.backoff_remaining_secs(now),
                    "last_429_unix": s.last_429_unix,
                    "last_retry_after_secs": s.last_retry_after_secs,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                if let Some(p) = provider_filter {
                    println!(
                        "# Quota state for {p}\n  (no entries — provider has not been called yet)"
                    );
                } else {
                    println!("# Quota state\n  (no providers tracked yet — make a call first)");
                }
                return Ok(());
            }
            println!("# Provider quota — last 24h");
            for s in &rows {
                let cap_label = s
                    .estimated_daily_cap
                    .map(|c| format!("{}/{c}", s.requests_today))
                    .unwrap_or_else(|| format!("{}/unlimited", s.requests_today));
                let health = if s.is_healthy(now) {
                    "OK".to_string()
                } else {
                    format!("BACKOFF {}s remaining", s.backoff_remaining_secs(now))
                };
                println!(
                    "  {:<16} requests={:<20} status={health}",
                    s.provider, cap_label
                );
                if let Some(last) = s.last_429_unix {
                    let retry = s
                        .last_retry_after_secs
                        .map(|r| format!("{r}s"))
                        .unwrap_or_else(|| "?".to_string());
                    println!("    last 429 at unix={last}, retry_after={retry}");
                }
            }
        }
    }
    Ok(())
}

fn run_reset(path: &std::path::Path, provider: &str, output: &OutputFormat) -> Result<()> {
    QuotaTracker::update_at(path, |tracker| {
        if tracker.get(provider).is_none() {
            anyhow::bail!(
                "no quota state recorded for `{provider}`. Use `neoth quota status` to see \
                 which providers have been called."
            );
        }
        tracker.reset(provider, now_unix());
        Ok(())
    })
    .context("save quota.json after reset")?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "reset": provider,
                    "ok": true,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("Reset quota for `{provider}`. Backoff cleared, daily counter zeroed.");
        }
    }
    Ok(())
}

fn run_set_cap(
    path: &std::path::Path,
    provider: &str,
    cap: u32,
    output: &OutputFormat,
) -> Result<()> {
    QuotaTracker::update_at(path, |tracker| {
        tracker.set_cap(provider, cap, now_unix());
        Ok(())
    })
    .context("save quota.json after set-cap")?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "operation": "quota.set-cap",
                    "provider": provider,
                    "estimated_daily_cap": cap,
                    "path": path,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("Recorded estimated daily cap for `{provider}`: {cap} requests/day");
            println!("  (telemetry only — NEOTH never refuses a call based on this)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reset_unknown_provider_errors_with_actionable_message() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("quota.json");
        let err = run_reset(&path, "openai_api", &OutputFormat::Json).unwrap_err();
        assert!(format!("{err:#}").contains("no quota state"));
    }

    #[test]
    fn set_cap_persists_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("quota.json");
        run_set_cap(&path, "openai_api", 200, &OutputFormat::Json).unwrap();
        let reloaded = QuotaTracker::load_from(&path).unwrap();
        assert_eq!(
            reloaded.get("openai_api").unwrap().estimated_daily_cap,
            Some(200)
        );
    }

    #[test]
    fn status_handles_empty_tracker() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("quota.json");
        run_status(&path, None, &OutputFormat::Json).unwrap();
        // No-op: just verifies it doesn't error on the empty case.
    }

    #[test]
    fn status_filters_by_provider() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("quota.json");
        {
            let mut t = QuotaTracker::load_from(&path).unwrap();
            t.record_success("openai_api", now_unix());
            t.record_success("gemini_api", now_unix());
            t.save().unwrap();
        }
        // Filter to one provider — we just verify it returns Ok; output
        // capture would require redirecting stdout.
        run_status(&path, Some("openai_api"), &OutputFormat::Json).unwrap();
        run_status(&path, Some("never-seen"), &OutputFormat::Table).unwrap();
    }
}
