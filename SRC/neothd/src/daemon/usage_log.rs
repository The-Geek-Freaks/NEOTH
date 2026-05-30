//! Persisted usage log — QM-9 Phase 1.
//!
//! Every provider call (success or error) appends one `UsageEvent`
//! line to `~/.neoth/usage/<YYYY-MM-DD>.jsonl`. The format is
//! intentionally JSONL: append-only is cheap, no migration risk, an
//! operator can `cat ~/.neoth/usage/2026-05-22.jsonl | jq` for
//! forensics. Rotation happens automatically by date — the writer
//! picks the file for "today" each call.
//!
//! Read side: `aggregate_since(home, since_unix) -> UsageRollup`
//! walks every `*.jsonl` file with a name in range and produces a
//! per-day + per-provider summary. The Slint dashboard panel (QM-9
//! Phase 2) consumes this; the CLI surface `neoth usage` is the
//! immediate operator interface.
//!
//! `ProviderMeter` (rolling 60s window in `providers/meter.rs`) is
//! complementary — that one feeds the live `/healthz` snapshot;
//! this one persists across daemon restarts so an operator who
//! reboots their laptop still sees yesterday's spend.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// One persisted usage event. Wire shape matches the JSONL we write
/// to disk + the JSON the Slint panel will read.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct UsageEvent {
    /// Unix seconds at record time.
    pub ts_unix: i64,
    /// Provider id (`openai_api`, `claude_cli`, `local_qwen`, …).
    pub provider: String,
    /// Model name as recorded by the adapter.
    pub model: String,
    /// Prompt tokens (`0` for providers that don't expose them).
    pub input_tokens: u32,
    /// Completion tokens.
    pub output_tokens: u32,
    /// USD cost predicted by the cost meter (`0.0` for local-only).
    pub cost_usd: f64,
    /// Latency in milliseconds.
    pub latency_ms: u64,
    /// True when the call completed successfully; false for errors
    /// (timeout, breaker open, parsed-error response, etc.).
    pub ok: bool,
}

/// Daily-keyed rollup for a single provider/model pair.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct PerProviderTotals {
    pub provider: String,
    pub call_count: u64,
    pub ok_count: u64,
    pub err_count: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub mean_latency_ms: f64,
}

/// Aggregate across the requested time range.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct UsageRollup {
    pub since_unix: i64,
    pub until_unix: i64,
    /// Total across every provider in the window.
    pub total_call_count: u64,
    pub total_ok_count: u64,
    pub total_err_count: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    /// Per-provider breakdown, sorted by `provider` alphabetically.
    pub per_provider: Vec<PerProviderTotals>,
}

/// Directory under `home` that holds the daily JSONL files.
pub fn usage_dir(home: &Path) -> PathBuf {
    home.join("usage")
}

/// File for "today" — `usage/YYYY-MM-DD.jsonl`. Derived from
/// `ts_unix` so callers can override for tests.
pub fn jsonl_file_for_ts(home: &Path, ts_unix: i64) -> PathBuf {
    let date = format_date_utc(ts_unix);
    usage_dir(home).join(format!("{date}.jsonl"))
}

/// Append one event to today's JSONL. Best-effort I/O: errors are
/// returned so the caller can decide whether to log; the daemon's
/// hot path should warn-and-continue on failure (a missing usage
/// row is worse than a failed reply).
pub fn append(home: &Path, event: &UsageEvent) -> std::io::Result<()> {
    fs::create_dir_all(usage_dir(home))?;
    let path = jsonl_file_for_ts(home, event.ts_unix);
    let mut line = serde_json::to_vec(event).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(&line)?;
    f.flush()?;
    Ok(())
}

/// Convenience: build an event with the current unix-seconds + write
/// it in one go. Caller passes the components.
pub fn record_now(
    home: &Path,
    provider: &str,
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
    cost_usd: f64,
    latency_ms: u64,
    ok: bool,
) -> std::io::Result<UsageEvent> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let ev = UsageEvent {
        ts_unix: now,
        provider: provider.to_string(),
        model: model.to_string(),
        input_tokens,
        output_tokens,
        cost_usd,
        latency_ms,
        ok,
    };
    append(home, &ev)?;
    Ok(ev)
}

/// GR-15 — testable core that records one provider call.
///
/// Collapses the `providers::cost::actual_cost_usd` + [`record_now`]
/// boilerplate that was duplicated verbatim across the chat-sync,
/// chat-stream, council-hemisphere, and MCP-loop call sites. Cost is
/// computed from the live price table ONLY on the success path; a
/// failed call records zero tokens + zero cost with `ok = false` so the
/// rollup still distinguishes ok-vs-err per provider.
///
/// The circuit-breaker half of the original GR-15 wrapper name is
/// already centralised inside every provider adapter via
/// `providers::circuit_breaker::run_with_breaker` (GR-04), so this
/// helper deliberately owns only the usage-metering consolidation —
/// re-wrapping the breaker here would double-settle the permit.
///
/// `home` is an explicit parameter so the function is unit-testable
/// against a tempdir without touching the operator's real `~/.neoth`.
pub fn record_provider_call(
    home: &Path,
    provider: &str,
    model: &str,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    latency_ms: u64,
    ok: bool,
) -> std::io::Result<UsageEvent> {
    let (input, output, cost) = if ok {
        let i = input_tokens.unwrap_or(0);
        let o = output_tokens.unwrap_or(0);
        (
            i,
            o,
            crate::providers::cost::actual_cost_usd(provider, model, i, o),
        )
    } else {
        // Error path: nothing worth charging — zero tokens, zero cost.
        (0, 0, 0.0)
    };
    record_now(home, provider, model, input, output, cost, latency_ms, ok)
}

/// GR-15 — best-effort convenience over [`record_provider_call`] that
/// resolves the default `~/.neoth` home and warns (never fails) on an
/// I/O error. This is what the hot chat / council / MCP-loop paths
/// call: a stuck disk must never break the operator's reply, but the
/// dropped usage row is surfaced as a `warn!` (no silent swallow).
pub fn record_provider_call_best_effort(
    provider: &str,
    model: &str,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    latency_ms: u64,
    ok: bool,
) {
    let home = crate::config::FreedomConfig::default_neoth_home();
    if let Err(e) = record_provider_call(
        &home,
        provider,
        model,
        input_tokens,
        output_tokens,
        latency_ms,
        ok,
    ) {
        tracing::warn!(error = %e, ok, "usage_log append failed (non-fatal)");
    }
}

/// Walk every `usage/*.jsonl` and aggregate events whose `ts_unix >=
/// since_unix` and `< until_unix`. Missing usage dir → empty rollup.
/// Malformed lines are skipped (logged at debug level via stderr
/// only when feature `usage-log-strict` is enabled — out of scope here).
pub fn aggregate(home: &Path, since_unix: i64, until_unix: i64) -> UsageRollup {
    let mut roll = UsageRollup {
        since_unix,
        until_unix,
        ..Default::default()
    };
    let dir = usage_dir(home);
    if !dir.exists() {
        return roll;
    }
    let mut per: std::collections::BTreeMap<String, PerProviderTotals> = Default::default();
    let mut latency_sum: std::collections::BTreeMap<String, u128> = Default::default();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return roll,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let Ok(body) = fs::read_to_string(&path) else {
            continue;
        };
        for line in body.lines() {
            let Ok(ev) = serde_json::from_str::<UsageEvent>(line) else {
                continue;
            };
            if ev.ts_unix < since_unix || ev.ts_unix >= until_unix {
                continue;
            }
            roll.total_call_count += 1;
            roll.total_input_tokens += ev.input_tokens as u64;
            roll.total_output_tokens += ev.output_tokens as u64;
            roll.total_cost_usd += ev.cost_usd;
            if ev.ok {
                roll.total_ok_count += 1;
            } else {
                roll.total_err_count += 1;
            }
            let totals = per
                .entry(ev.provider.clone())
                .or_insert_with(|| PerProviderTotals {
                    provider: ev.provider.clone(),
                    ..Default::default()
                });
            totals.call_count += 1;
            totals.input_tokens += ev.input_tokens as u64;
            totals.output_tokens += ev.output_tokens as u64;
            totals.cost_usd += ev.cost_usd;
            if ev.ok {
                totals.ok_count += 1;
            } else {
                totals.err_count += 1;
            }
            *latency_sum.entry(ev.provider).or_insert(0) += ev.latency_ms as u128;
        }
    }
    for (provider, mut totals) in per.into_iter() {
        let sum = *latency_sum.get(&provider).unwrap_or(&0);
        totals.mean_latency_ms = if totals.call_count > 0 {
            sum as f64 / totals.call_count as f64
        } else {
            0.0
        };
        roll.per_provider.push(totals);
    }
    roll.per_provider
        .sort_by(|a, b| a.provider.cmp(&b.provider));
    roll
}

/// Format unix-seconds as `YYYY-MM-DD` in UTC. Avoids pulling in
/// chrono — the JSONL filenames don't need timezone-aware rendering.
fn format_date_utc(ts_unix: i64) -> String {
    // Days since epoch (1970-01-01).
    let days = ts_unix.div_euclid(86_400);
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert days-since-epoch to (year, month, day). Pure arithmetic;
/// follows the Gauss-style algorithm used by tzdata generators.
fn days_to_ymd(days_since_epoch: i64) -> (i32, u32, u32) {
    // Civil-from-days from Howard Hinnant's "date" algorithms.
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let yy = if m <= 2 { y + 1 } else { y };
    (yy as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn format_date_utc_matches_known_epochs() {
        // 1970-01-01 00:00:00 UTC.
        assert_eq!(format_date_utc(0), "1970-01-01");
        // 2026-05-22 00:00:00 UTC: 20_595 days since epoch.
        // 20595 * 86400 = 1_779_408_000.
        assert_eq!(format_date_utc(1_779_408_000), "2026-05-22");
        // 2000-02-29 00:00:00 UTC (leap-year edge): 11_016 days since
        // epoch. 11016 * 86400 = 951_782_400.
        assert_eq!(format_date_utc(951_782_400), "2000-02-29");
    }

    #[test]
    fn append_creates_dir_and_writes_jsonl_line() {
        let dir = tempdir().unwrap();
        let ev = UsageEvent {
            ts_unix: 1_779_494_400,
            provider: "openai_api".into(),
            model: "gpt-5.5".into(),
            input_tokens: 100,
            output_tokens: 250,
            cost_usd: 0.0015,
            latency_ms: 800,
            ok: true,
        };
        append(dir.path(), &ev).unwrap();
        let file = jsonl_file_for_ts(dir.path(), ev.ts_unix);
        assert!(file.exists());
        let body = std::fs::read_to_string(&file).unwrap();
        assert!(body.ends_with('\n'));
        let parsed: UsageEvent = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(parsed, ev);
    }

    #[test]
    fn append_two_events_in_same_day_appends_two_lines() {
        let dir = tempdir().unwrap();
        let mut ev = UsageEvent {
            ts_unix: 1_779_494_400,
            provider: "claude_cli".into(),
            model: "claude-opus-4-7".into(),
            input_tokens: 100,
            output_tokens: 200,
            cost_usd: 0.01,
            latency_ms: 1200,
            ok: true,
        };
        append(dir.path(), &ev).unwrap();
        ev.ts_unix += 5;
        ev.input_tokens = 50;
        append(dir.path(), &ev).unwrap();
        let body = std::fs::read_to_string(jsonl_file_for_ts(dir.path(), ev.ts_unix)).unwrap();
        assert_eq!(body.lines().count(), 2);
    }

    #[test]
    fn aggregate_empty_dir_returns_zero_rollup() {
        let dir = tempdir().unwrap();
        let r = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(r.total_call_count, 0);
        assert!(r.per_provider.is_empty());
    }

    #[test]
    fn aggregate_filters_outside_window() {
        let dir = tempdir().unwrap();
        for (ts, prov) in [
            (1_779_494_400_i64, "openai_api"),
            (1_779_494_500, "openai_api"),
            (1_779_494_900, "claude_cli"),
        ] {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: ts,
                    provider: prov.into(),
                    model: "x".into(),
                    input_tokens: 10,
                    output_tokens: 20,
                    cost_usd: 0.001,
                    latency_ms: 100,
                    ok: true,
                },
            )
            .unwrap();
        }
        // Window covers only the first two.
        let r = aggregate(dir.path(), 1_779_494_400, 1_779_494_700);
        assert_eq!(r.total_call_count, 2);
        assert_eq!(r.per_provider.len(), 1);
        assert_eq!(r.per_provider[0].provider, "openai_api");
        assert_eq!(r.per_provider[0].call_count, 2);
    }

    #[test]
    fn aggregate_handles_malformed_lines_without_panic() {
        let dir = tempdir().unwrap();
        let file = jsonl_file_for_ts(dir.path(), 1_779_494_400);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            "{this is not json\n\
             {\"ts_unix\":1779494400,\"provider\":\"openai_api\",\"model\":\"x\",\
             \"input_tokens\":1,\"output_tokens\":2,\"cost_usd\":0.0,\
             \"latency_ms\":50,\"ok\":true}\n\
             garbage\n",
        )
        .unwrap();
        let r = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(r.total_call_count, 1);
    }

    #[test]
    fn aggregate_distinguishes_ok_from_err() {
        let dir = tempdir().unwrap();
        for ok in [true, true, false] {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: 1_779_494_400,
                    provider: "p".into(),
                    model: "m".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: 0,
                    ok,
                },
            )
            .unwrap();
        }
        let r = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(r.total_call_count, 3);
        assert_eq!(r.total_ok_count, 2);
        assert_eq!(r.total_err_count, 1);
    }

    #[test]
    fn aggregate_computes_per_provider_mean_latency() {
        let dir = tempdir().unwrap();
        for ms in [100u64, 200, 600] {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: 1_779_494_400,
                    provider: "x".into(),
                    model: "y".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: ms,
                    ok: true,
                },
            )
            .unwrap();
        }
        let r = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(r.per_provider.len(), 1);
        let totals = &r.per_provider[0];
        assert_eq!(totals.call_count, 3);
        let expected = 900.0 / 3.0;
        assert!((totals.mean_latency_ms - expected).abs() < 0.0001);
    }

    #[test]
    fn aggregate_sorts_per_provider_alphabetically() {
        let dir = tempdir().unwrap();
        for prov in ["zeta", "alpha", "middle"] {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: 1_779_494_400,
                    provider: prov.into(),
                    model: "m".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: 0,
                    ok: true,
                },
            )
            .unwrap();
        }
        let r = aggregate(dir.path(), 0, i64::MAX);
        let ids: Vec<&str> = r.per_provider.iter().map(|p| p.provider.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "middle", "zeta"]);
    }

    #[test]
    fn aggregate_skips_non_jsonl_files() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(usage_dir(dir.path())).unwrap();
        // Drop a non-.jsonl file in the dir — must be ignored.
        std::fs::write(usage_dir(dir.path()).join("README.md"), "ignored\n").unwrap();
        let r = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(r.total_call_count, 0);
    }

    #[test]
    fn record_now_writes_and_returns_event() {
        let dir = tempdir().unwrap();
        let ev = record_now(
            dir.path(),
            "openai_api",
            "gpt-5.5",
            10,
            20,
            0.0001,
            500,
            true,
        )
        .unwrap();
        let file = jsonl_file_for_ts(dir.path(), ev.ts_unix);
        let body = std::fs::read_to_string(&file).unwrap();
        let parsed: UsageEvent = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(parsed.provider, "openai_api");
        assert_eq!(parsed.input_tokens, 10);
    }

    // ── GR-15: record_provider_call consolidation ──────────────────────

    #[test]
    fn record_provider_call_ok_computes_cost_via_price_table() {
        let dir = tempdir().unwrap();
        let ev = record_provider_call(
            dir.path(),
            "openai_api",
            "gpt-5.5",
            Some(100),
            Some(50),
            250,
            true,
        )
        .unwrap();
        assert!(ev.ok);
        assert_eq!(ev.input_tokens, 100);
        assert_eq!(ev.output_tokens, 50);
        // Cost must equal the live price-table fn — pins that the helper
        // routes through actual_cost_usd rather than hardcoding a value
        // (robust to price-table changes; no magic literal to drift).
        assert_eq!(
            ev.cost_usd,
            crate::providers::cost::actual_cost_usd("openai_api", "gpt-5.5", 100, 50)
        );
    }

    #[test]
    fn record_provider_call_failure_zeroes_tokens_and_cost() {
        let dir = tempdir().unwrap();
        // Even with non-zero token hints, the error path records zeros so
        // a failed call never inflates the spend rollup.
        let ev = record_provider_call(
            dir.path(),
            "openai_api",
            "gpt-5.5",
            Some(999),
            Some(999),
            80,
            false,
        )
        .unwrap();
        assert!(!ev.ok);
        assert_eq!(ev.input_tokens, 0);
        assert_eq!(ev.output_tokens, 0);
        assert_eq!(ev.cost_usd, 0.0);
    }

    #[test]
    fn record_provider_call_none_tokens_treated_as_zero() {
        let dir = tempdir().unwrap();
        let ev = record_provider_call(dir.path(), "local_qwen", "qwen2.5-7b", None, None, 10, true)
            .unwrap();
        assert_eq!(ev.input_tokens, 0);
        assert_eq!(ev.output_tokens, 0);
        // Unpriced local model → cost 0.0 (drift guard: actual_cost_usd
        // returns 0.0 for unknown provider/model pairs).
        assert_eq!(ev.cost_usd, 0.0);
    }

    #[test]
    fn record_provider_call_round_trips_through_aggregate() {
        let dir = tempdir().unwrap();
        record_provider_call(
            dir.path(),
            "gemini_api",
            "gemini-3-pro",
            Some(5),
            Some(7),
            33,
            true,
        )
        .unwrap();
        let roll = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(roll.total_call_count, 1);
        assert_eq!(roll.total_ok_count, 1);
        assert_eq!(roll.total_input_tokens, 5);
        assert_eq!(roll.total_output_tokens, 7);
    }
}
