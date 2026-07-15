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
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

static USAGE_LOG_LOCK: Mutex<()> = Mutex::new(());

/// One persisted usage event. Wire shape matches the JSONL we write
/// to disk + the JSON the Slint panel will read.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct UsageEvent {
    /// Unix seconds at record time.
    pub ts_unix: i64,
    /// Provider id (`openai_api`, `claude_cli`, `local_qwen`, …).
    pub provider: String,
    /// Model name as recorded by the adapter.
    pub model: String,
    /// Prompt tokens reported by the concrete provider leaf. `None` means the
    /// provider did not report them; it must never be converted into a fake 0.
    #[serde(default)]
    pub input_tokens: Option<u32>,
    /// Completion tokens reported by the concrete provider leaf.
    #[serde(default)]
    pub output_tokens: Option<u32>,
    /// Actual USD cost when both token counts and a reviewed price row exist.
    /// `None` keeps unknown usage distinct from a genuinely free local call.
    #[serde(default)]
    pub cost_usd: Option<f64>,
    /// Latency in milliseconds.
    pub latency_ms: u64,
    /// True when the call completed successfully; false for errors
    /// (timeout, breaker open, parsed-error response, etc.).
    pub ok: bool,
    /// VIEW-03 — tokens written into the Anthropic prompt cache this turn
    /// (billed at 1.25× the normal input rate). `None` means not reported or
    /// not applicable. Legacy lines without this field deserialize as `None`.
    #[serde(default)]
    pub cache_creation_tokens: Option<u32>,
    /// VIEW-03 — tokens served from the Anthropic prompt cache this turn
    /// (billed at 0.10× the normal input rate). `None` means not reported or
    /// not applicable.
    #[serde(default)]
    pub cache_read_tokens: Option<u32>,
    /// VIEW-03 — net cache savings in USD for this call
    /// (read_savings − write_premium; can be negative on first-turn
    /// creation when no reads offset the 25% write premium yet).
    /// `None` when cache economics cannot be derived from reported values.
    #[serde(default)]
    pub cache_savings_usd: Option<f64>,
    /// VIEW-06 — true when this call was model-driven (council hemisphere,
    /// MCP agentic-loop hop) rather than a direct operator CLI turn.
    /// `#[serde(default)]` ensures pre-VIEW-06 JSONL lines deserialize as
    /// `false` (conservative: assume human).
    #[serde(default)]
    pub automated: bool,
    /// Unique request-bound provider-leaf attempt id. Legacy rows have none.
    #[serde(default)]
    pub invocation_id: Option<String>,
    /// Stable terminal result (`complete`, `stream_done`, `stream_error`, ...).
    #[serde(default)]
    pub outcome: Option<String>,
    /// Internal dispatch scope and typed caller metadata. These fields never
    /// contain prompts, responses or credentials.
    #[serde(default)]
    pub call_scope: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub call_type: Option<String>,
    #[serde(default)]
    pub streaming: bool,
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
    /// Calls whose provider omitted a token/cost dimension. Known totals above
    /// remain useful without misrepresenting an unknown as zero.
    #[serde(default)]
    pub unknown_input_token_count: u64,
    #[serde(default)]
    pub unknown_output_token_count: u64,
    #[serde(default)]
    pub unknown_cost_count: u64,
    pub mean_latency_ms: f64,
    /// VIEW-07 — median + 90th-percentile latency (ms) across this provider's
    /// calls in the window. The mean alone hides tail latency; p90 surfaces it.
    pub p50_latency_ms: u64,
    pub p90_latency_ms: u64,
    /// VIEW-03 — cache token economics for this provider across the window.
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_savings_usd: f64,
    /// VIEW-06 — per-provider session-type split.
    #[serde(default)]
    pub automated_count: u64,
    #[serde(default)]
    pub human_count: u64,
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
    #[serde(default)]
    pub total_unknown_input_token_count: u64,
    #[serde(default)]
    pub total_unknown_output_token_count: u64,
    #[serde(default)]
    pub total_unknown_cost_count: u64,
    /// VIEW-07 — overall latency percentiles across every provider (ms).
    pub total_p50_latency_ms: u64,
    pub total_p90_latency_ms: u64,
    /// VIEW-02 — spend RATE derived from `total_cost_usd` over the window:
    /// USD/day + the 30-day projection. Zero when the window has no spend.
    pub burn_rate_usd_per_day: f64,
    pub projected_monthly_usd: f64,
    /// VIEW-03 — cache token economics aggregated across all providers.
    pub total_cache_creation_tokens: u64,
    pub total_cache_read_tokens: u64,
    pub total_cache_savings_usd: f64,
    /// VIEW-06 — rollup-level session-type split.
    #[serde(default)]
    pub total_automated_count: u64,
    #[serde(default)]
    pub total_human_count: u64,
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
    let _guard = USAGE_LOG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    append_unlocked(home, event)
}

fn append_unlocked(home: &Path, event: &UsageEvent) -> std::io::Result<()> {
    fs::create_dir_all(usage_dir(home))?;
    let path = jsonl_file_for_ts(home, event.ts_unix);
    let mut line = serde_json::to_vec(event).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(&line)?;
    f.flush()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn provider_terminal_event(
    ts_unix: i64,
    provider: &str,
    model: &str,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    latency_ms: u64,
    ok: bool,
    cache_creation_tokens: Option<u32>,
    cache_read_tokens: Option<u32>,
    automated: bool,
    invocation_id: &str,
    outcome: &str,
    call_scope: &str,
    source: Option<&str>,
    call_type: Option<&str>,
    streaming: bool,
) -> UsageEvent {
    let reviewed_price = crate::providers::cost::lookup_price(provider, model);
    let cost_usd = match (input_tokens, output_tokens, reviewed_price) {
        (Some(input), Some(output), Some(_)) => Some(crate::providers::cost::actual_cost_usd(
            provider, model, input, output,
        )),
        (_, _, Some(price))
            if price.input_eur_per_mtok == 0.0 && price.output_eur_per_mtok == 0.0 =>
        {
            Some(0.0)
        }
        _ => None,
    };
    let cache_savings_usd = match (cache_creation_tokens, cache_read_tokens, reviewed_price) {
        (created, read, Some(_)) if created.is_some() || read.is_some() => {
            Some(crate::providers::cost::cache_savings_usd(
                provider,
                model,
                created.unwrap_or_default(),
                read.unwrap_or_default(),
            ))
        }
        _ => None,
    };
    UsageEvent {
        ts_unix,
        provider: provider.to_owned(),
        model: model.to_owned(),
        input_tokens,
        output_tokens,
        cost_usd,
        latency_ms,
        ok,
        cache_creation_tokens,
        cache_read_tokens,
        cache_savings_usd,
        automated,
        invocation_id: Some(invocation_id.to_owned()),
        outcome: Some(outcome.to_owned()),
        call_scope: Some(call_scope.to_owned()),
        source: source.map(str::to_owned),
        call_type: call_type.map(str::to_owned),
        streaming,
    }
}

/// Convenience: build an event with the current unix-seconds + write
/// it in one go. Caller passes the components.
#[allow(clippy::too_many_arguments)]
pub fn record_now(
    home: &Path,
    provider: &str,
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
    cost_usd: f64,
    latency_ms: u64,
    ok: bool,
    cache_creation_tokens: u32,
    cache_read_tokens: u32,
    cache_savings_usd: f64,
    automated: bool,
) -> std::io::Result<UsageEvent> {
    let now = crate::time::now_unix_i64();
    let ev = UsageEvent {
        ts_unix: now,
        provider: provider.to_string(),
        model: model.to_string(),
        input_tokens: Some(input_tokens),
        output_tokens: Some(output_tokens),
        cost_usd: Some(cost_usd),
        latency_ms,
        ok,
        cache_creation_tokens: Some(cache_creation_tokens),
        cache_read_tokens: Some(cache_read_tokens),
        cache_savings_usd: Some(cache_savings_usd),
        automated,
        invocation_id: None,
        outcome: Some(
            if ok {
                "complete"
            } else {
                "provider_call_failed"
            }
            .into(),
        ),
        call_scope: None,
        source: None,
        call_type: None,
        streaming: false,
    };
    append(home, &ev)?;
    Ok(ev)
}

/// GR-15 — testable core that records one provider call.
///
/// Collapses the `providers::cost::actual_cost_usd` + [`record_now`]
/// boilerplate that was duplicated verbatim across the chat-sync,
/// chat-stream, council-hemisphere, and MCP-loop call sites. Cost is
/// computed from the live price table only when the provider reported both
/// token dimensions and the exact provider/model has a reviewed price row.
/// Unknown values stay `None`, including failures, so forensic output cannot
/// confuse "not reported" with a genuine zero.
///
/// The circuit-breaker half of the original GR-15 wrapper name is
/// already centralised inside every provider adapter via
/// `providers::circuit_breaker::run_with_breaker` (GR-04), so this
/// helper deliberately owns only the usage-metering consolidation —
/// re-wrapping the breaker here would double-settle the permit.
///
/// `home` is an explicit parameter so the function is unit-testable
/// against a tempdir without touching the operator's real `~/.neoth`.
#[allow(clippy::too_many_arguments)]
pub fn record_provider_call(
    home: &Path,
    provider: &str,
    model: &str,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    latency_ms: u64,
    ok: bool,
    cache_creation_tokens: Option<u32>,
    cache_read_tokens: Option<u32>,
    automated: bool,
) -> std::io::Result<UsageEvent> {
    let reviewed_price = crate::providers::cost::lookup_price(provider, model);
    let cost_usd = match (input_tokens, output_tokens, reviewed_price) {
        (Some(input), Some(output), Some(_)) => Some(crate::providers::cost::actual_cost_usd(
            provider, model, input, output,
        )),
        (_, _, Some(price))
            if price.input_eur_per_mtok == 0.0 && price.output_eur_per_mtok == 0.0 =>
        {
            Some(0.0)
        }
        _ => None,
    };
    let cache_savings_usd = match (cache_creation_tokens, cache_read_tokens, reviewed_price) {
        (created, read, Some(_)) if created.is_some() || read.is_some() => {
            Some(crate::providers::cost::cache_savings_usd(
                provider,
                model,
                created.unwrap_or_default(),
                read.unwrap_or_default(),
            ))
        }
        _ => None,
    };
    let ev = UsageEvent {
        ts_unix: crate::time::now_unix_i64(),
        provider: provider.to_owned(),
        model: model.to_owned(),
        input_tokens,
        output_tokens,
        cost_usd,
        latency_ms,
        ok,
        cache_creation_tokens,
        cache_read_tokens,
        cache_savings_usd,
        automated,
        invocation_id: None,
        outcome: Some(
            if ok {
                "complete"
            } else {
                "provider_call_failed"
            }
            .into(),
        ),
        call_scope: None,
        source: None,
        call_type: None,
        streaming: false,
    };
    append(home, &ev)?;
    Ok(ev)
}

fn terminal_optional_u32(
    payload: &serde_json::Value,
    field: &'static str,
) -> anyhow::Result<Option<u32>> {
    let Some(value) = payload.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value.as_u64().ok_or_else(|| {
        anyhow::anyhow!("terminal usage field `{field}` is not an unsigned integer")
    })?;
    Ok(Some(u32::try_from(value).map_err(|_| {
        anyhow::anyhow!("terminal usage field `{field}` exceeds u32")
    })?))
}

fn terminal_required_str<'a>(
    payload: &'a serde_json::Value,
    field: &'static str,
) -> anyhow::Result<&'a str> {
    payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| anyhow::anyhow!("terminal usage field `{field}` is missing or empty"))
}

fn terminal_optional_str<'a>(
    payload: &'a serde_json::Value,
    field: &'static str,
) -> anyhow::Result<Option<&'a str>> {
    match payload.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("terminal usage field `{field}` is not a string")),
    }
}

fn usage_event_from_terminal_payload(payload: &[u8]) -> anyhow::Result<Option<UsageEvent>> {
    let value: serde_json::Value = serde_json::from_slice(payload)?;
    if value
        .get("usage_projection_schema")
        .and_then(serde_json::Value::as_str)
        != Some("neoth.provider-usage.v2")
    {
        // Historical terminal frames predate invocation-id-backed projection
        // and may already have a legacy JSONL row. Do not double-count them.
        return Ok(None);
    }
    let invocation_id = terminal_required_str(&value, "invocation_id")?;
    if invocation_id.len() != 64 || !invocation_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("terminal usage invocation_id is not canonical SHA-256 hex");
    }
    let ok = value
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| anyhow::anyhow!("terminal usage field `ok` is missing or invalid"))?;
    let outcome = terminal_required_str(&value, if ok { "terminal_kind" } else { "error_kind" })?;
    let ts_unix = value
        .get("ts_unix")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| anyhow::anyhow!("terminal usage field `ts_unix` is missing or invalid"))?;
    let latency_ms = value
        .get("latency_ms")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            value
                .get("latency_ns")
                .and_then(serde_json::Value::as_u64)
                .map(|latency_ns| latency_ns / 1_000_000)
        })
        .ok_or_else(|| anyhow::anyhow!("terminal usage latency is missing or invalid"))?;
    Ok(Some(provider_terminal_event(
        ts_unix,
        terminal_required_str(&value, "provider")?,
        value
            .get("wire_model")
            .and_then(serde_json::Value::as_str)
            .or_else(|| value.get("model").and_then(serde_json::Value::as_str))
            .filter(|model| !model.is_empty())
            .ok_or_else(|| anyhow::anyhow!("terminal usage wire model is missing or empty"))?,
        terminal_optional_u32(&value, "input_tokens")?,
        terminal_optional_u32(&value, "output_tokens")?,
        latency_ms,
        ok,
        terminal_optional_u32(&value, "cache_creation_tokens")?,
        terminal_optional_u32(&value, "cache_read_tokens")?,
        value
            .get("automated")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("terminal usage field `automated` is missing"))?,
        invocation_id,
        outcome,
        terminal_required_str(&value, "call_scope")?,
        terminal_optional_str(&value, "source")?,
        terminal_optional_str(&value, "call_type")?,
        value
            .get("streaming")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("terminal usage field `streaming` is missing"))?,
    )))
}

/// Rebuild missing JSONL projections from durable provider terminal WAL rows.
/// Invocation ids make retries idempotent: a crash after WAL commit and before
/// JSONL append is repaired once, while an already-projected attempt is skipped.
pub fn repair_from_terminal_wal(home: &Path) -> anyhow::Result<usize> {
    let _guard = USAGE_LOG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut persisted = std::collections::HashSet::new();
    let dir = usage_dir(home);
    if dir.exists() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
                continue;
            }
            for line in fs::read_to_string(&path)?.lines() {
                let Ok(event) = serde_json::from_str::<UsageEvent>(line) else {
                    continue;
                };
                if let Some(invocation_id) = event.invocation_id {
                    persisted.insert(invocation_id);
                }
            }
        }
    }

    let wal_dir = home.join("wal");
    if !wal_dir.exists() {
        return Ok(0);
    }
    let mut segments = fs::read_dir(&wal_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("wal"))
        .collect::<Vec<_>>();
    segments.sort();

    let mut candidates = std::collections::BTreeMap::<String, UsageEvent>::new();
    for segment in segments {
        let bytes = fs::read(&segment)?;
        crate::wal::scan::for_each_frame(&bytes, |_, frame| {
            if !matches!(
                frame.header.event_type,
                crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
                    | crate::wal::events::EVENT_TYPE_PROVIDER_ERROR
            ) {
                return Ok(());
            }
            let Some(event) = usage_event_from_terminal_payload(frame.payload)? else {
                return Ok(());
            };
            let invocation_id = event
                .invocation_id
                .as_ref()
                .expect("projectable provider terminal has invocation id")
                .clone();
            if let Some(previous) = candidates.insert(invocation_id.clone(), event.clone())
                && previous != event
            {
                anyhow::bail!(
                    "conflicting terminal usage payloads for invocation `{invocation_id}`"
                );
            }
            Ok(())
        })?;
    }

    let mut repaired = 0usize;
    for (invocation_id, event) in candidates {
        if persisted.insert(invocation_id) {
            append_unlocked(home, &event)?;
            repaired += 1;
        }
    }
    Ok(repaired)
}

/// Walk every `usage/*.jsonl` and aggregate events whose `ts_unix >=
/// since_unix` and `< until_unix`. Missing usage dir → empty rollup.
/// Malformed lines are skipped (logged at debug level via stderr
/// only when feature `usage-log-strict` is enabled — out of scope here).
pub fn aggregate(home: &Path, since_unix: i64, until_unix: i64) -> UsageRollup {
    if let Err(error) = repair_from_terminal_wal(home) {
        tracing::warn!(error = %error, "usage projection repair from terminal WAL failed");
    }
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
    // VIEW-07 — collect the raw latency samples per provider (+ overall) so we
    // can compute percentiles, not just the running mean.
    let mut latency_samples: std::collections::BTreeMap<String, Vec<u64>> = Default::default();
    let mut all_latency: Vec<u64> = Vec::new();
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
            match ev.input_tokens {
                Some(tokens) => roll.total_input_tokens += u64::from(tokens),
                None => roll.total_unknown_input_token_count += 1,
            }
            match ev.output_tokens {
                Some(tokens) => roll.total_output_tokens += u64::from(tokens),
                None => roll.total_unknown_output_token_count += 1,
            }
            match ev.cost_usd {
                Some(cost) => roll.total_cost_usd += cost,
                None => roll.total_unknown_cost_count += 1,
            }
            roll.total_cache_creation_tokens +=
                u64::from(ev.cache_creation_tokens.unwrap_or_default());
            roll.total_cache_read_tokens += u64::from(ev.cache_read_tokens.unwrap_or_default());
            roll.total_cache_savings_usd += ev.cache_savings_usd.unwrap_or_default();
            if ev.ok {
                roll.total_ok_count += 1;
            } else {
                roll.total_err_count += 1;
            }
            // VIEW-06 — accumulate session-type split at rollup level.
            if ev.automated {
                roll.total_automated_count += 1;
            } else {
                roll.total_human_count += 1;
            }
            let totals = per
                .entry(ev.provider.clone())
                .or_insert_with(|| PerProviderTotals {
                    provider: ev.provider.clone(),
                    ..Default::default()
                });
            totals.call_count += 1;
            match ev.input_tokens {
                Some(tokens) => totals.input_tokens += u64::from(tokens),
                None => totals.unknown_input_token_count += 1,
            }
            match ev.output_tokens {
                Some(tokens) => totals.output_tokens += u64::from(tokens),
                None => totals.unknown_output_token_count += 1,
            }
            match ev.cost_usd {
                Some(cost) => totals.cost_usd += cost,
                None => totals.unknown_cost_count += 1,
            }
            totals.cache_creation_tokens += u64::from(ev.cache_creation_tokens.unwrap_or_default());
            totals.cache_read_tokens += u64::from(ev.cache_read_tokens.unwrap_or_default());
            totals.cache_savings_usd += ev.cache_savings_usd.unwrap_or_default();
            if ev.ok {
                totals.ok_count += 1;
            } else {
                totals.err_count += 1;
            }
            // VIEW-06 — accumulate session-type split at per-provider level.
            if ev.automated {
                totals.automated_count += 1;
            } else {
                totals.human_count += 1;
            }
            all_latency.push(ev.latency_ms);
            latency_samples
                .entry(ev.provider)
                .or_default()
                .push(ev.latency_ms);
        }
    }
    for (provider, mut totals) in per.into_iter() {
        let mut samples = latency_samples.remove(&provider).unwrap_or_default();
        if !samples.is_empty() {
            let sum: u128 = samples.iter().map(|&x| x as u128).sum();
            totals.mean_latency_ms = sum as f64 / samples.len() as f64;
            samples.sort_unstable();
            totals.p50_latency_ms = percentile_u64(&samples, 50.0);
            totals.p90_latency_ms = percentile_u64(&samples, 90.0);
        }
        roll.per_provider.push(totals);
    }
    roll.per_provider
        .sort_by(|a, b| a.provider.cmp(&b.provider));
    // VIEW-07 — overall latency percentiles across every provider.
    if !all_latency.is_empty() {
        all_latency.sort_unstable();
        roll.total_p50_latency_ms = percentile_u64(&all_latency, 50.0);
        roll.total_p90_latency_ms = percentile_u64(&all_latency, 90.0);
    }
    // VIEW-02 — spend rate over the window → USD/day + 30-day projection.
    let window_secs = (until_unix - since_unix).max(1) as f64;
    roll.burn_rate_usd_per_day = roll.total_cost_usd / window_secs * 86_400.0;
    roll.projected_monthly_usd = roll.burn_rate_usd_per_day * 30.0;
    roll
}

/// Nearest-rank percentile over a SORTED-ascending slice (`p` in `0..=100`):
/// the sample at the `ceil(p% × n)`-th rank (1-indexed). Empty slice → 0.
fn percentile_u64(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len();
    let rank = ((p / 100.0) * n as f64).ceil().max(1.0) as usize;
    sorted[rank.min(n) - 1]
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
            input_tokens: Some(100),
            output_tokens: Some(250),
            cost_usd: Some(0.0015),
            latency_ms: 800,
            ok: true,
            ..Default::default()
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
            input_tokens: Some(100),
            output_tokens: Some(200),
            cost_usd: Some(0.01),
            latency_ms: 1200,
            ok: true,
            ..Default::default()
        };
        append(dir.path(), &ev).unwrap();
        ev.ts_unix += 5;
        ev.input_tokens = Some(50);
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
                    input_tokens: Some(10),
                    output_tokens: Some(20),
                    cost_usd: Some(0.001),
                    latency_ms: 100,
                    ok: true,
                    ..Default::default()
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
                    input_tokens: Some(0),
                    output_tokens: Some(0),
                    cost_usd: Some(0.0),
                    latency_ms: 0,
                    ok,
                    ..Default::default()
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
                    input_tokens: Some(0),
                    output_tokens: Some(0),
                    cost_usd: Some(0.0),
                    latency_ms: ms,
                    ok: true,
                    ..Default::default()
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
    fn percentile_u64_nearest_rank() {
        assert_eq!(percentile_u64(&[], 50.0), 0);
        let s = [100u64, 200, 600]; // already sorted ascending
        assert_eq!(percentile_u64(&s, 0.0), 100); // rank clamps to 1 → idx 0
        assert_eq!(percentile_u64(&s, 50.0), 200); // ceil(0.5*3)=2 → idx 1
        assert_eq!(percentile_u64(&s, 90.0), 600); // ceil(0.9*3)=3 → idx 2
        assert_eq!(percentile_u64(&s, 100.0), 600);
    }

    #[test]
    fn aggregate_computes_latency_percentiles() {
        // VIEW-07: ten calls 10..=100ms → p50=50, p90=90 (nearest-rank).
        let dir = tempdir().unwrap();
        for ms in [10u64, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: 1_779_494_400,
                    provider: "x".into(),
                    model: "m".into(),
                    input_tokens: Some(0),
                    output_tokens: Some(0),
                    cost_usd: Some(0.0),
                    latency_ms: ms,
                    ok: true,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let r = aggregate(dir.path(), 0, i64::MAX);
        let p = &r.per_provider[0];
        assert_eq!(p.p50_latency_ms, 50);
        assert_eq!(p.p90_latency_ms, 90);
        assert_eq!(r.total_p50_latency_ms, 50);
        assert_eq!(r.total_p90_latency_ms, 90);
    }

    #[test]
    fn aggregate_computes_burn_rate_and_monthly_projection() {
        // VIEW-02: $2.00 spend over a 2-day window → $1/day → $30/month.
        let dir = tempdir().unwrap();
        let day = 86_400i64;
        for (ts, cost) in [(0i64, 1.0f64), (day, 1.0)] {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: ts,
                    provider: "p".into(),
                    model: "m".into(),
                    input_tokens: Some(0),
                    output_tokens: Some(0),
                    cost_usd: Some(cost),
                    latency_ms: 1,
                    ok: true,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let r = aggregate(dir.path(), 0, 2 * day);
        assert!((r.total_cost_usd - 2.0).abs() < 1e-9);
        assert!(
            (r.burn_rate_usd_per_day - 1.0).abs() < 1e-9,
            "burn_rate got {}",
            r.burn_rate_usd_per_day
        );
        assert!((r.projected_monthly_usd - 30.0).abs() < 1e-9);
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
                    input_tokens: Some(0),
                    output_tokens: Some(0),
                    cost_usd: Some(0.0),
                    latency_ms: 0,
                    ok: true,
                    ..Default::default()
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
            0,
            0,
            0.0,
            false,
        )
        .unwrap();
        let file = jsonl_file_for_ts(dir.path(), ev.ts_unix);
        let body = std::fs::read_to_string(&file).unwrap();
        let parsed: UsageEvent = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(parsed.provider, "openai_api");
        assert_eq!(parsed.input_tokens, Some(10));
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
            None,
            None,
            false,
        )
        .unwrap();
        assert!(ev.ok);
        assert_eq!(ev.input_tokens, Some(100));
        assert_eq!(ev.output_tokens, Some(50));
        // Cost must equal the live price-table fn — pins that the helper
        // routes through actual_cost_usd rather than hardcoding a value
        // (robust to price-table changes; no magic literal to drift).
        assert_eq!(
            ev.cost_usd,
            Some(crate::providers::cost::actual_cost_usd(
                "openai_api",
                "gpt-5.5",
                100,
                50
            ))
        );
    }

    #[test]
    fn record_provider_call_failure_preserves_known_tokens_and_cost() {
        let dir = tempdir().unwrap();
        // A transport can fail after billing. If it reports usage, preserve it.
        let ev = record_provider_call(
            dir.path(),
            "openai_api",
            "gpt-5.5",
            Some(999),
            Some(999),
            80,
            false,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(!ev.ok);
        assert_eq!(ev.input_tokens, Some(999));
        assert_eq!(ev.output_tokens, Some(999));
        assert!(ev.cost_usd.is_some());
    }

    #[test]
    fn record_provider_call_none_tokens_remain_unknown_for_free_local_call() {
        let dir = tempdir().unwrap();
        let ev = record_provider_call(
            dir.path(),
            "local_qwen",
            "qwen2.5-7b",
            None,
            None,
            10,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(ev.input_tokens, None);
        assert_eq!(ev.output_tokens, None);
        assert_eq!(ev.cost_usd, Some(0.0));
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
            None,
            None,
            false,
        )
        .unwrap();
        let roll = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(roll.total_call_count, 1);
        assert_eq!(roll.total_ok_count, 1);
        assert_eq!(roll.total_input_tokens, 5);
        assert_eq!(roll.total_output_tokens, 7);
    }

    // ── VIEW-03: cache token economics ────────────────────────────────────

    #[test]
    fn cache_token_economics_round_trip_through_aggregate() {
        // Two calls: first creates cache (cc=100, cr=0), second reads it
        // (cc=0, cr=300).  Net savings = read_savings − write_premium; signs
        // may differ but the TOTAL must equal the sum of per-event values.
        let dir = tempdir().unwrap();
        record_provider_call(
            dir.path(),
            "anthropic_api",
            "claude-opus-4-7",
            Some(500),
            Some(100),
            300,
            true,
            Some(100), // cache creation
            None,
            false,
        )
        .unwrap();
        record_provider_call(
            dir.path(),
            "anthropic_api",
            "claude-opus-4-7",
            Some(200),
            Some(50),
            150,
            true,
            None,
            Some(300), // cache read
            false,
        )
        .unwrap();
        let roll = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(roll.total_call_count, 2);
        // Totals must match the sum of both events.
        assert_eq!(roll.total_cache_creation_tokens, 100);
        assert_eq!(roll.total_cache_read_tokens, 300);
        // per-provider must also carry the values.
        assert_eq!(roll.per_provider.len(), 1);
        let pp = &roll.per_provider[0];
        assert_eq!(pp.cache_creation_tokens, 100);
        assert_eq!(pp.cache_read_tokens, 300);
        // savings stored in rollup must equal sum of event savings.
        let expected_savings = roll.total_cache_savings_usd;
        // round-trip: savings in pp must match total (single provider).
        assert!((pp.cache_savings_usd - expected_savings).abs() < 1e-9);
    }

    #[test]
    fn pre_view03_jsonl_line_deserialises_with_zero_cache_fields() {
        // Old JSONL lines have no cache_* keys → must deserialise as zeros
        // (backward-compat via #[serde(default)]).
        let line = r#"{"ts_unix":1779494400,"provider":"openai_api","model":"gpt-4.1","input_tokens":10,"output_tokens":5,"cost_usd":0.001,"latency_ms":200,"ok":true}"#;
        let ev: UsageEvent = serde_json::from_str(line).unwrap();
        assert_eq!(ev.cache_creation_tokens, None);
        assert_eq!(ev.cache_read_tokens, None);
        assert_eq!(ev.cache_savings_usd, None);
        // And it round-trips through aggregate without panic.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(crate::daemon::usage_log::usage_dir(dir.path())).unwrap();
        let path = crate::daemon::usage_log::jsonl_file_for_ts(dir.path(), 1_779_494_400);
        std::fs::write(&path, format!("{line}\n")).unwrap();
        let roll = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(roll.total_call_count, 1);
        assert_eq!(roll.total_cache_creation_tokens, 0);
        assert_eq!(roll.total_cache_savings_usd, 0.0);
    }

    // ── VIEW-06: automated-vs-human session flag ──────────────────────────

    #[test]
    fn automated_vs_human_flag_round_trips_through_aggregate() {
        let dir = tempdir().unwrap();
        // Human call (direct CLI chat turn).
        record_provider_call(
            dir.path(),
            "claude_api",
            "claude-opus-4-5",
            Some(100),
            Some(50),
            200,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        // Automated call (council hemisphere).
        record_provider_call(
            dir.path(),
            "claude_api",
            "claude-opus-4-5",
            Some(80),
            Some(30),
            150,
            true,
            None,
            None,
            true,
        )
        .unwrap();
        let roll = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(roll.total_human_count, 1, "expected 1 human call");
        assert_eq!(roll.total_automated_count, 1, "expected 1 automated call");
        assert_eq!(roll.per_provider.len(), 1);
        let pp = &roll.per_provider[0];
        assert_eq!(pp.human_count, 1, "per-provider human_count");
        assert_eq!(pp.automated_count, 1, "per-provider automated_count");
    }

    #[test]
    fn pre_view06_backward_compat_defaults_automated_to_false() {
        // A raw JSONL line WITHOUT the `automated` field (pre-VIEW-06 format)
        // must deserialize without error and be counted as human (automated=false).
        let line = r#"{"ts_unix":1779494400,"provider":"openai_api","model":"gpt-4.1","input_tokens":10,"output_tokens":5,"cost_usd":0.001,"latency_ms":200,"ok":true,"cache_creation_tokens":0,"cache_read_tokens":0,"cache_savings_usd":0.0}"#;
        // Verify serde default kicks in.
        let ev: UsageEvent = serde_json::from_str(line).unwrap();
        assert!(
            !ev.automated,
            "pre-VIEW-06 event must default automated=false"
        );
        // Write it directly to the JSONL file (mimics pre-VIEW-06 on-disk data).
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(usage_dir(dir.path())).unwrap();
        let path = jsonl_file_for_ts(dir.path(), 1_779_494_400);
        std::fs::write(&path, format!("{line}\n")).unwrap();
        // aggregate must classify it as human (human_count=1, automated_count=0).
        let roll = aggregate(dir.path(), 0, i64::MAX);
        assert_eq!(roll.total_call_count, 1);
        assert_eq!(
            roll.total_human_count, 1,
            "pre-VIEW-06 record counts as human"
        );
        assert_eq!(roll.total_automated_count, 0);
    }
}
