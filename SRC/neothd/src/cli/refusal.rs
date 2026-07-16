//! `neoth refusal {classify, patterns, cause, reframings, enable,
//! disable, test, history}` — operator surface for the Refusal-Recovery
//! LOWKEY arc.
//!
//! Subcommands:
//!   - `classify <text>` — Schicht-0 detector (surface class).
//!   - `patterns` — dump the static pattern dictionaries.
//!   - `cause <text>` (R-06) — RefusalCause classifier (WHY refused).
//!   - `reframings` (R-06) — list the 6 LOWKEY reframings + per-id
//!     enabled/disabled status from `freedom.yaml::refusal_recovery`.
//!   - `disable <id>` (R-06) — atomically add to
//!     `refusal_recovery.disabled_reframings` so a specific LOWKEY
//!     reframing never fires.
//!   - `enable <id>` (R-06) — remove from the disabled list.
//!   - `test <refusal> [--prompt P]` (SPEC-10) — pure DRY-RUN: classify
//!     the cause, show the ordered reframing chain recovery WOULD try
//!     (honouring `disabled_reframings`), and — with `--prompt` — the
//!     reframed prompt the first applicable reframing produces. No
//!     provider call, no WAL write.
//!   - `history [--limit N]` (SPEC-10) — read-only audit trail of past
//!     automated reroutes: scans every `*.wal` segment for
//!     `0x19 REFUSAL_REROUTED` frames and renders cause / reframing /
//!     hashes / timestamp, most-recent first. `--limit 0` shows all.
//!     The WAL stores only xxh3 HASHES of the refusal + reframed prompt
//!     (never the plaintext), so history shows hashes by design.
//!
//! All commands are pure-read or freedom.yaml mutators. No LLM
//! calls, no provider dependency.

use std::path::Path;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::security::refusal_cause::classify_cause;
use crate::security::refusal_detect::classify;
use crate::security::refusal_reframings::{applicable_reframings, default_catalogue};
use crate::wal::compress::decompress_frames;
use crate::wal::events::EVENT_TYPE_REFUSAL_REROUTED;
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;

#[derive(Args, Debug, Clone)]
pub struct RefusalArgs {
    #[command(subcommand)]
    pub action: RefusalAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RefusalAction {
    /// Classify `<text>` against the refusal detector. Prints the
    /// classification + confidence + the matched patterns so operators
    /// can see exactly which signals fired.
    Classify {
        /// The text to classify. Quote shell-special characters.
        text: String,
    },
    /// Print the static pattern dictionaries the classifier uses, in
    /// table or JSON form. Useful for "why didn't my refusal text
    /// trigger?" debugging.
    Patterns,
    /// R-06 2026-05-17: classify the CAUSE of a refusal — orthogonal
    /// to `classify` which reports the surface class. Returns one of
    /// {safety_policy, capability_gap, privacy, operator_policy,
    /// unknown} plus the matched patterns + confidence.
    Cause {
        /// The text to classify.
        text: String,
    },
    /// R-06: list the 6 LOWKEY reframings with their description,
    /// applicable causes, and per-id enabled/disabled status from
    /// `freedom.yaml::refusal_recovery.disabled_reframings`.
    Reframings,
    /// R-06: disable a specific LOWKEY reframing. Atomically rewrites
    /// `freedom.yaml::refusal_recovery.disabled_reframings`. Use for
    /// third-party deployments where e.g. `operator_authority`
    /// (LOWKEY pentester-context prepend) is not appropriate.
    Disable {
        /// Reframing id (snake_case): `operator_authority`,
        /// `narrow_scope`, `step_decomposition`, `meta_discussion`,
        /// `academic_framing`, `historical_framing`.
        id: String,
    },
    /// R-06: re-enable a previously-disabled reframing. Removes the
    /// id from `freedom.yaml::refusal_recovery.disabled_reframings`.
    Enable {
        /// Reframing id (snake_case).
        id: String,
    },
    /// SPEC-10: dry-run the recovery selection for a refusal WITHOUT
    /// calling a provider. Classifies the cause, lists the ordered
    /// reframing chain `try_recover` would attempt (honouring the
    /// operator's `disabled_reframings`), and — when `--prompt` is
    /// given — shows the reframed prompt the first applicable reframing
    /// produces. Pure: no LLM, no WAL.
    Test {
        /// The refusal text to classify + plan recovery for.
        text: String,
        /// Optional original prompt to reframe — shows the exact
        /// rewritten prompt the first applicable reframing emits.
        #[arg(long)]
        prompt: Option<String>,
    },
    /// SPEC-10: audit trail of past automated reroutes. Scans every WAL
    /// segment for `0x19 REFUSAL_REROUTED` frames and prints them
    /// most-recent first. Read-only; no daemon required. The WAL stores
    /// only xxh3 hashes of the refusal + reframed prompt (never raw
    /// text), so the hashes shown are the audit anchor, not plaintext.
    History {
        /// Show at most this many reroutes (most-recent first).
        /// `--limit 0` shows the entire history.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

pub async fn run_refusal(args: RefusalArgs) -> Result<()> {
    match args.action {
        RefusalAction::Classify { text } => run_classify(&text, &args.output),
        RefusalAction::Patterns => run_patterns(&args.output),
        RefusalAction::Cause { text } => run_cause(&text, &args.output),
        RefusalAction::Reframings => run_reframings(&args.output),
        RefusalAction::Disable { id } => run_disable(&id, &args.output),
        RefusalAction::Enable { id } => run_enable(&id, &args.output),
        RefusalAction::Test { text, prompt } => run_test(&text, prompt.as_deref(), &args.output),
        RefusalAction::History { limit } => run_history(limit, &args.output),
    }
}

/// One decoded `0x19 REFUSAL_REROUTED` audit record. Carries ONLY the
/// non-reversible audit anchors the WAL frame stores — the original
/// refusal + reframed prompt are persisted as xxh3-64 hashes, never as
/// plaintext, so an operator inspecting history can correlate reroutes
/// without the raw text ever touching the durable log.
#[derive(Debug, Clone, PartialEq)]
struct RerouteEntry {
    /// Unique WAL event id of the frame.
    event_id: u64,
    /// Frame-header HLC physical nanoseconds — the ordering key.
    ts_ns: u64,
    /// Operator-readable wall-clock seconds from the payload (older or
    /// malformed frames may omit it).
    ts_unix: Option<u64>,
    /// Refusal cause classification (`safety_policy` / `capability_gap`
    /// / `privacy` / `operator_policy` / `unknown`).
    cause: String,
    /// Cause-classifier confidence (0-100) when present.
    cause_confidence: Option<u64>,
    /// Which LOWKEY reframing was applied for this hop.
    reframing_id: String,
    /// xxh3-64 of the original refusal text (hex-rendered for display).
    original_refusal_hash: Option<u64>,
    /// xxh3-64 of the reframed prompt the retry sent.
    reframed_prompt_hash: Option<u64>,
}

/// Neutralise an operator-facing string read from a (potentially
/// tampered) WAL payload before it is stored + printed to the terminal:
/// strip ANSI escape sequences (terminal-injection guard — reuses the
/// QU-04 `security::redact::strip_ansi`), drop any remaining control
/// chars (`\r`/`\n`/`\0`/C1), and bound the length. `cause` /
/// `reframing_id` come from a closed set in practice (~20 chars); a
/// multi-KB or escape-laden value is a tamper signal, not legitimate
/// content, so clamping it is safe.
fn sanitize_field(raw: &str) -> String {
    crate::security::redact::strip_ansi(raw)
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}

/// Decode one WAL frame into a [`RerouteEntry`] iff it is a
/// `0x19 REFUSAL_REROUTED` frame with a JSON-parseable payload. Returns
/// `None` for any other event type or an unparseable payload — tolerant
/// by design so a single malformed/older frame never aborts the scan.
/// Field extraction is per-field optional so a pre-R-3 payload missing a
/// field still yields a partial record rather than being dropped. The
/// free-form `cause` / `reframing_id` strings are sanitised (see
/// [`sanitize_field`]) so a tampered WAL cannot inject terminal escapes
/// or a giant string into the operator's audit view.
fn parse_reroute_frame(
    event_type: u8,
    payload: &[u8],
    ts_ns: u64,
    event_id: u64,
) -> Option<RerouteEntry> {
    if event_type != EVENT_TYPE_REFUSAL_REROUTED {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    Some(RerouteEntry {
        event_id,
        ts_ns,
        ts_unix: v.get("ts_unix").and_then(|x| x.as_u64()),
        cause: sanitize_field(v.get("cause").and_then(|x| x.as_str()).unwrap_or("unknown")),
        cause_confidence: v.get("cause_confidence").and_then(|x| x.as_u64()),
        reframing_id: sanitize_field(
            v.get("reframing_id")
                .and_then(|x| x.as_str())
                .unwrap_or("(unknown)"),
        ),
        original_refusal_hash: v.get("original_refusal_hash_xxh3").and_then(|x| x.as_u64()),
        reframed_prompt_hash: v.get("reframed_prompt_hash_xxh3").and_then(|x| x.as_u64()),
    })
}

/// Walk every `*.wal` segment in `wal_dir`, collecting all
/// `0x19 REFUSAL_REROUTED` records. Robust across segment formats:
/// uses [`parse_segment_header`] (v1 60B / v2 61B) for the correct
/// frame-body offset and decompresses v2 zstd bodies before walking —
/// unlike the v1-only `cli/wal.rs` / `cli/rollback.rs` walkers, which
/// would silently skip v2/compressed segments. Tolerant throughout: a
/// missing dir, an unreadable/short/unknown-format segment, a torn tail
/// frame, or a malformed payload each skip rather than error, so a
/// partially-corrupt WAL still yields every recoverable record.
fn collect_reroutes(wal_dir: &Path) -> Vec<RerouteEntry> {
    let entries = match std::fs::read_dir(wal_dir) {
        Ok(it) => it,
        // Missing WAL dir (fresh install / daemon never ran) → empty,
        // not an error.
        Err(_) => return Vec::new(),
    };

    // Collect + sort segment paths so the walk is deterministic
    // (read_dir order is unspecified, especially on Windows NTFS).
    let mut segments: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
        .collect();
    segments.sort();

    let mut out: Vec<RerouteEntry> = Vec::new();
    for path in segments {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(hdr) = parse_segment_header(&bytes) else {
            continue;
        };
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue; // header-only / empty segment
        }
        let body = &bytes[header_len..];
        // v2 compressed bodies are a single zstd frame — decompress
        // before the per-frame walk. v1 + uncompressed v2 walk the body
        // slice in place (no copy on the common uncompressed path).
        if hdr.is_compressed() {
            match decompress_frames(body) {
                Ok(d) => walk_segment_frames(&d, &mut out),
                Err(_) => continue,
            }
        } else {
            walk_segment_frames(body, &mut out);
        }
    }
    out
}

/// Walk the frame bytes of ONE segment body (already decompressed if the
/// segment was compressed), pushing every `0x19` reroute record into
/// `out`. Tail-tolerant: stops at the first torn/corrupt frame so a
/// partially-written active segment still yields its good prefix. The
/// zero-`total_len` guard prevents a malformed frame from looping
/// forever. Advancing by `total_len` matches every other WAL walker in
/// the codebase (recovery / wal show / rollback).
fn walk_segment_frames(frames: &[u8], out: &mut Vec<RerouteEntry>) {
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if let Some(entry) = parse_reroute_frame(
            dec.header.event_type,
            dec.payload,
            dec.header.hlc.physical_ns(),
            dec.header.event_id.0,
        ) {
            out.push(entry);
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
}

/// Sort reroutes most-recent first (HLC ns desc, `event_id` tiebreak)
/// and apply the display limit (`0` = all). Returns
/// `(selected, total_before_limit)`. Pure — split out of [`run_history`]
/// so the ordering + limit logic is unit-testable without the real WAL.
fn select_reroutes_for_display(
    mut entries: Vec<RerouteEntry>,
    limit: usize,
) -> (Vec<RerouteEntry>, usize) {
    entries.sort_by(|a, b| {
        b.ts_ns
            .cmp(&a.ts_ns)
            .then_with(|| b.event_id.cmp(&a.event_id))
    });
    let total = entries.len();
    let shown = if limit == 0 {
        entries
    } else {
        entries.into_iter().take(limit).collect()
    };
    (shown, total)
}

/// SPEC-10: render the refusal-reroute audit trail. Reads the canonical
/// WAL dir, sorts most-recent first, applies `--limit` (0 = all), and
/// emits JSON or a human table. Hashes render as 16-char hex — the WAL
/// never stores the raw refusal/prompt text.
fn run_history(limit: usize, output: &OutputFormat) -> Result<()> {
    let wal_dir = FreedomConfig::default_wal_dir();
    let (shown, total) = select_reroutes_for_display(collect_reroutes(&wal_dir), limit);

    let hex = |h: Option<u64>| h.map(|v| format!("{v:016x}"));

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = shown
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "event_id": e.event_id,
                        "ts_ns": e.ts_ns,
                        "ts_unix": e.ts_unix,
                        "cause": e.cause,
                        "cause_confidence": e.cause_confidence,
                        "reframing_id": e.reframing_id,
                        "original_refusal_hash": hex(e.original_refusal_hash),
                        "reframed_prompt_hash": hex(e.reframed_prompt_hash),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "reroutes": rows,
                    "shown": shown.len(),
                    "total": total,
                }))?
            );
        }
        OutputFormat::Table => {
            if shown.is_empty() {
                println!("# Refusal reroute history");
                println!("  (none) — no 0x19 REFUSAL_REROUTED frames in the WAL yet.");
                return Ok(());
            }
            println!(
                "# Refusal reroute history — showing {} of {} (most recent first)",
                shown.len(),
                total
            );
            println!("  (hashes are xxh3-64 of refusal/prompt text — raw text is never stored)");
            for e in &shown {
                let ts = e
                    .ts_unix
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("hlc_ns={}", e.ts_ns));
                let conf = e
                    .cause_confidence
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default();
                println!(
                    "  [{ts}] eid={} cause={}{conf} reframing={} refusal_hash={} reframed_hash={}",
                    e.event_id,
                    e.cause,
                    e.reframing_id,
                    hex(e.original_refusal_hash).as_deref().unwrap_or("-"),
                    hex(e.reframed_prompt_hash).as_deref().unwrap_or("-"),
                );
            }
        }
    }
    Ok(())
}

/// SPEC-10: dry-run the recovery plan for a refusal. Pure — reuses the
/// same `classify_cause` + `applicable_reframings` the live
/// `try_recover` orchestrator uses, so what this prints is exactly what
/// recovery WOULD attempt (minus the provider call). `disabled_reframings`
/// from freedom.yaml is honoured; only a genuinely missing config falls back
/// to the compiled default. Existing invalid policy is surfaced.
fn run_test(text: &str, prompt: Option<&str>, output: &OutputFormat) -> Result<()> {
    let cause = classify_cause(text);
    let disabled = FreedomConfig::load_from_default_path_or_default()?
        .refusal_recovery
        .disabled_reframings;
    let catalogue = default_catalogue();
    let chain = applicable_reframings(cause.cause, &catalogue, &disabled);
    let recoverable = !chain.is_empty();

    // With --prompt, preview the first applicable reframing's rewrite —
    // that's the one `try_recover` attempts first.
    let reframed = match (chain.first(), prompt) {
        (Some(r), Some(p)) => Some((r.id(), r.apply(p, None))),
        _ => None,
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let chain_json: Vec<_> = chain
                .iter()
                .map(|r| serde_json::json!({ "id": r.id(), "description": r.description() }))
                .collect();
            let reframed_json = reframed.as_ref().map(|(id, rp)| {
                serde_json::json!({
                    "reframing_id": id,
                    "reframed_prompt": rp.prompt,
                    "reframed_system": rp.system,
                })
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "cause": cause.cause.as_str(),
                    "confidence": cause.confidence,
                    "recoverable": recoverable,
                    "applicable_reframings": chain_json,
                    "reframed": reframed_json,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Refusal recovery dry-run");
            println!("  cause:        {}", cause.cause.as_str());
            println!("  confidence:   {}", cause.confidence);
            println!("  recoverable:  {recoverable}");
            if chain.is_empty() {
                println!(
                    "  plan:         (none) — cause is not auto-reframed (Unknown / \
                     OperatorPolicy) or every applicable reframing is disabled; \
                     recovery would surface the original refusal + escalate."
                );
            } else {
                println!("  plan ({} applicable, in attempt order):", chain.len());
                for (i, r) in chain.iter().enumerate() {
                    println!("    {}. {:<22} {}", i + 1, r.id(), r.description());
                }
            }
            if let Some((id, rp)) = &reframed {
                println!("\n  first reframing `{id}` rewrites the prompt to:");
                println!("  ┌─ prompt ─");
                for line in rp.prompt.lines() {
                    println!("  │ {line}");
                }
                if let Some(sys) = &rp.system {
                    println!("  ├─ system ─");
                    for line in sys.lines() {
                        println!("  │ {line}");
                    }
                }
                println!("  └─");
            } else if prompt.is_none() && recoverable {
                println!("\n  (pass --prompt \"<your prompt>\" to preview the reframed prompt)");
            }
        }
    }
    Ok(())
}

/// R-06: classify the cause of a refusal. Mirrors `run_classify`'s
/// output shape so operator scripts can switch between the two
/// classifiers without per-call reformatting.
fn run_cause(text: &str, output: &OutputFormat) -> Result<()> {
    let report = classify_cause(text);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "cause": report.cause.as_str(),
                    "confidence": report.confidence,
                    "matched_patterns": report.matched_patterns,
                    "input_bytes": text.len(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Refusal cause classification");
            println!("  cause:       {}", report.cause.as_str());
            println!("  confidence:  {}", report.confidence);
            println!("  input_bytes: {}", text.len());
            if report.matched_patterns.is_empty() {
                println!("  matched:     (none)");
            } else {
                println!("  matched:");
                for p in &report.matched_patterns {
                    println!("    - {p}");
                }
            }
        }
    }
    Ok(())
}

/// R-06: list every LOWKEY reframing + enabled/disabled per the
/// operator's current freedom.yaml. Missing freedom.yaml (e.g. pre-init) uses
/// the compiled default; an existing invalid file is an operator-visible error.
fn run_reframings(output: &OutputFormat) -> Result<()> {
    let disabled = FreedomConfig::load_from_default_path_or_default()?
        .refusal_recovery
        .disabled_reframings;
    let catalogue = default_catalogue();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = catalogue
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id(),
                        "description": r.description(),
                        "enabled": !disabled.iter().any(|d| d == r.id()),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "reframings": rows,
                    "disabled_count": disabled.len(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "# LOWKEY reframings — {} total, {} disabled",
                catalogue.len(),
                disabled.len()
            );
            for r in &catalogue {
                let status = if disabled.iter().any(|d| d == r.id()) {
                    "[disabled]"
                } else {
                    "[enabled] "
                };
                println!("  {status} {:<22} {}", r.id(), r.description());
            }
        }
    }
    Ok(())
}

/// Validate that `id` matches one of the 6 catalogue ids. Returns
/// `Err` with an actionable pointer when the operator typos.
fn validate_reframing_id(id: &str) -> Result<()> {
    let cat = default_catalogue();
    let known: Vec<&'static str> = cat.iter().map(|r| r.id()).collect();
    if known.contains(&id) {
        return Ok(());
    }
    anyhow::bail!(
        "unknown reframing id `{id}`. Valid ids: {}. Run `neoth refusal reframings` to see them.",
        known.join(", "),
    );
}

/// R-06: append `id` to `freedom.yaml::refusal_recovery.disabled_reframings`
/// and atomically rewrite the config. Idempotent — re-disabling an
/// already-disabled id is a no-op (operator sees a "no change" message).
fn run_disable(id: &str, output: &OutputFormat) -> Result<()> {
    validate_reframing_id(id)?;
    let path = FreedomConfig::default_path();
    let (already, disabled_after) = FreedomConfig::update_at(&path, |cfg| {
        let already = cfg
            .refusal_recovery
            .disabled_reframings
            .iter()
            .any(|disabled| disabled == id);
        if !already {
            cfg.refusal_recovery
                .disabled_reframings
                .push(id.to_string());
        }
        Ok((already, cfg.refusal_recovery.disabled_reframings.clone()))
    })
    .with_context(|| format!("write freedom.yaml after disabling `{id}`"))?;
    report_change("disable", id, !already, output, &disabled_after)
}

/// R-06: inverse of `run_disable`. Removes `id` from
/// `refusal_recovery.disabled_reframings`. Idempotent.
fn run_enable(id: &str, output: &OutputFormat) -> Result<()> {
    validate_reframing_id(id)?;
    let path = FreedomConfig::default_path();
    let (changed, disabled_after) = FreedomConfig::update_at(&path, |cfg| {
        let before_len = cfg.refusal_recovery.disabled_reframings.len();
        cfg.refusal_recovery
            .disabled_reframings
            .retain(|disabled| disabled != id);
        Ok((
            cfg.refusal_recovery.disabled_reframings.len() != before_len,
            cfg.refusal_recovery.disabled_reframings.clone(),
        ))
    })
    .with_context(|| format!("write freedom.yaml after enabling `{id}`"))?;
    report_change("enable", id, changed, output, &disabled_after)
}

/// Render the disable/enable command's result. JSON branch suitable
/// for scripting; table branch human-friendly.
fn report_change(
    verb: &str,
    id: &str,
    changed: bool,
    output: &OutputFormat,
    disabled_after: &[String],
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "action": verb,
                    "id": id,
                    "changed": changed,
                    "disabled_after": disabled_after,
                }))?
            );
        }
        OutputFormat::Table => {
            if changed {
                println!("✓ {verb}d reframing `{id}`");
            } else {
                println!("• reframing `{id}` already in target state — no change");
            }
            println!("  disabled now: {}", disabled_after.join(", "));
        }
    }
    Ok(())
}

fn run_classify(text: &str, output: &OutputFormat) -> Result<()> {
    let report = classify(text);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "class": report.class.as_str(),
                    "is_refusal": report.is_refusal(),
                    "confidence": report.confidence,
                    "matched_patterns": report.matched_patterns,
                    "input_bytes": text.len(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Refusal classification");
            println!("  class:       {}", report.class.as_str());
            println!("  is_refusal:  {}", report.is_refusal());
            println!("  confidence:  {}", report.confidence);
            println!("  input_bytes: {}", text.len());
            if report.matched_patterns.is_empty() {
                println!("  matched:     (none)");
            } else {
                println!("  matched:");
                for p in &report.matched_patterns {
                    println!("    - {p}");
                }
            }
        }
    }
    Ok(())
}

fn run_patterns(output: &OutputFormat) -> Result<()> {
    use crate::security::refusal_detect::pattern_dictionaries;
    let (hard, soft, redirect, safety) = pattern_dictionaries();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "hard": hard,
                    "soft": soft,
                    "redirect": redirect,
                    "safety": safety,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Refusal detector patterns");
            println!("\n  [hard_refusal] {} patterns", hard.len());
            for p in hard {
                println!("    {p}");
            }
            println!("\n  [soft_refusal] {} patterns", soft.len());
            for p in soft {
                println!("    {p}");
            }
            println!("\n  [redirect_suggestion] {} patterns", redirect.len());
            for p in redirect {
                println!("    {p}");
            }
            println!("\n  [safety_warning] {} patterns", safety.len());
            for p in safety {
                println!("    {p}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_clean_input_does_not_panic() {
        run_classify("Sure, here's the answer: 42", &OutputFormat::Json).unwrap();
        run_classify("Sure, here's the answer: 42", &OutputFormat::Table).unwrap();
    }

    #[test]
    fn classify_hard_refusal_returns_ok() {
        run_classify("I cannot help with that request.", &OutputFormat::Json).unwrap();
    }

    #[test]
    fn patterns_dump_does_not_panic() {
        run_patterns(&OutputFormat::Json).unwrap();
        run_patterns(&OutputFormat::Table).unwrap();
    }

    // ── R-06 2026-05-17: cause / reframings / disable / enable ────────

    #[test]
    fn cause_classifies_clean_input_as_unknown() {
        // No cause pattern matches → Unknown. Smoke test the
        // JSON + table branches don't panic.
        run_cause("Sure, here's the answer: 42", &OutputFormat::Json).unwrap();
        run_cause("Sure, here's the answer: 42", &OutputFormat::Table).unwrap();
    }

    #[test]
    fn cause_classifies_safety_policy_refusal() {
        run_cause(
            "Against my guidelines — this violates safety policy.",
            &OutputFormat::Json,
        )
        .unwrap();
    }

    #[test]
    fn validate_reframing_id_accepts_known_ids() {
        for id in [
            "operator_authority",
            "narrow_scope",
            "step_decomposition",
            "meta_discussion",
            "academic_framing",
            "historical_framing",
        ] {
            assert!(validate_reframing_id(id).is_ok(), "{id} should be valid");
        }
    }

    #[test]
    fn validate_reframing_id_rejects_unknown_with_actionable_message() {
        let err = validate_reframing_id("nope-not-real").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown reframing id"));
        assert!(msg.contains("neoth refusal reframings"));
        // Names of all 6 catalogue entries should appear in the pointer.
        assert!(msg.contains("operator_authority"));
    }

    #[test]
    fn validate_reframing_id_rejects_empty_and_whitespace() {
        assert!(validate_reframing_id("").is_err());
        // No fuzzy match: leading/trailing spaces are not stripped.
        assert!(validate_reframing_id(" operator_authority ").is_err());
    }

    // ── SPEC-10: `neoth refusal test` dry-run ─────────────────────────

    #[test]
    fn test_dry_run_safety_policy_recoverable_both_outputs() {
        // A safety-policy refusal has an applicable reframing chain →
        // recoverable. Smoke both render branches (with + without
        // --prompt).
        let refusal = "I can't help with that — it violates my safety policy.";
        run_test(
            refusal,
            Some("scan my own server for open ports"),
            &OutputFormat::Json,
        )
        .unwrap();
        run_test(
            refusal,
            Some("scan my own server for open ports"),
            &OutputFormat::Table,
        )
        .unwrap();
        run_test(refusal, None, &OutputFormat::Table).unwrap();
    }

    #[test]
    fn test_dry_run_unknown_cause_not_recoverable_does_not_panic() {
        // Clean (non-refusal) input → Unknown cause → empty chain →
        // not recoverable. Both branches must render without panic.
        run_test("Sure, here's the answer: 42", None, &OutputFormat::Json).unwrap();
        run_test("Sure, here's the answer: 42", None, &OutputFormat::Table).unwrap();
    }

    // ── SPEC-10: `neoth refusal history` ──────────────────────────────

    fn reroute_payload(reframing_id: &str, ts_unix: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "cause": "safety_policy",
            "cause_confidence": 80,
            "reframing_id": reframing_id,
            "original_refusal_hash_xxh3": 111u64,
            "reframed_prompt_hash_xxh3": 222u64,
            "ts_unix": ts_unix,
        }))
        .unwrap()
    }

    fn entry(ts_ns: u64, event_id: u64) -> RerouteEntry {
        RerouteEntry {
            event_id,
            ts_ns,
            ts_unix: Some(ts_ns / 1_000_000_000),
            cause: "safety_policy".into(),
            cause_confidence: Some(80),
            reframing_id: "operator_authority".into(),
            original_refusal_hash: Some(0xdead),
            reframed_prompt_hash: Some(0xbeef),
        }
    }

    #[test]
    fn parse_reroute_frame_decodes_valid_0x19() {
        let payload = reroute_payload("operator_authority", 1700);
        let e = parse_reroute_frame(EVENT_TYPE_REFUSAL_REROUTED, &payload, 999, 7).unwrap();
        assert_eq!(e.event_id, 7);
        assert_eq!(e.ts_ns, 999);
        assert_eq!(e.ts_unix, Some(1700));
        assert_eq!(e.cause, "safety_policy");
        assert_eq!(e.cause_confidence, Some(80));
        assert_eq!(e.reframing_id, "operator_authority");
        assert_eq!(e.original_refusal_hash, Some(111));
        assert_eq!(e.reframed_prompt_hash, Some(222));
    }

    #[test]
    fn parse_reroute_frame_rejects_non_reroute_event_type() {
        // 0x1A REFUSAL_PERSISTENT (and anything else) must not be
        // collected by the reroute history.
        assert!(parse_reroute_frame(0x1A, b"{}", 1, 1).is_none());
        assert!(parse_reroute_frame(0x02, b"{}", 1, 1).is_none());
    }

    #[test]
    fn parse_reroute_frame_rejects_malformed_json() {
        assert!(parse_reroute_frame(EVENT_TYPE_REFUSAL_REROUTED, b"not json {", 1, 1).is_none());
    }

    #[test]
    fn parse_reroute_frame_tolerates_missing_fields() {
        // A pre-R-3 / partial payload still yields a record with safe
        // defaults rather than being dropped.
        let e = parse_reroute_frame(EVENT_TYPE_REFUSAL_REROUTED, b"{}", 5, 6).unwrap();
        assert_eq!(e.cause, "unknown");
        assert_eq!(e.reframing_id, "(unknown)");
        assert_eq!(e.cause_confidence, None);
        assert_eq!(e.original_refusal_hash, None);
        assert_eq!(e.reframed_prompt_hash, None);
        assert_eq!(e.ts_unix, None);
        assert_eq!(e.ts_ns, 5);
    }

    #[test]
    fn select_reroutes_sorts_recent_first_and_applies_limit() {
        let v = vec![entry(100, 1), entry(300, 3), entry(200, 2)];
        let (shown, total) = select_reroutes_for_display(v, 2);
        assert_eq!(total, 3);
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].ts_ns, 300, "most recent first");
        assert_eq!(shown[1].ts_ns, 200);
    }

    #[test]
    fn select_reroutes_limit_zero_returns_all() {
        let v = vec![entry(100, 1), entry(200, 2)];
        let (shown, total) = select_reroutes_for_display(v, 0);
        assert_eq!(total, 2);
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].ts_ns, 200);
    }

    #[test]
    fn collect_reroutes_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-wal-dir");
        assert!(collect_reroutes(&missing).is_empty());
    }

    #[tokio::test]
    async fn history_collects_only_reroute_frames_from_real_segment() {
        // Write two real 0x19 frames + one 0x1A frame through the actual
        // WAL writer, then assert collect_reroutes returns exactly the
        // two 0x19 records (filtering the 0x1A) with correct payloads —
        // exercising the real segment-header parse + frame walk.
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        for (rid, ts) in [("operator_authority", 1700u64), ("narrow_scope", 1800u64)] {
            let payload = reroute_payload(rid, ts);
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_REFUSAL_REROUTED, &payload).build();
            writer.append(header, payload).await.unwrap();
        }
        // Non-0x19 frame must NOT show up in reroute history.
        let other = serde_json::to_vec(&serde_json::json!({ "cause": "unknown" })).unwrap();
        let h = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_REFUSAL_PERSISTENT,
            &other,
        )
        .build();
        writer.append(h, other).await.unwrap();

        drop(writer);
        let _ = join.await;

        let got = collect_reroutes(&wal_dir);
        assert_eq!(
            got.len(),
            2,
            "only the two 0x19 frames are collected (0x1A filtered)"
        );
        assert!(got.iter().all(|e| e.cause == "safety_policy"));
        // collect_reroutes walks each segment in file (insertion) order —
        // assert it directly rather than re-sorting (the most-recent-first
        // display ordering is covered by select_reroutes_sorts_recent_first).
        assert_eq!(got[0].reframing_id, "operator_authority");
        assert_eq!(got[1].reframing_id, "narrow_scope");
    }

    #[test]
    fn sanitize_field_strips_escapes_controls_and_bounds_length() {
        // ANSI colour codes stripped (terminal-injection guard).
        assert_eq!(
            sanitize_field("\x1b[31msafety_policy\x1b[0m"),
            "safety_policy"
        );
        // Control chars (newline / carriage-return / NUL) dropped.
        assert_eq!(
            sanitize_field("oper\nator\r_auth\0ority"),
            "operator_authority"
        );
        // Length clamped — a multi-KB tampered field can't flood the view.
        let huge = "x".repeat(5000);
        assert_eq!(sanitize_field(&huge).len(), 64);
        // Legitimate closed-set values pass through unchanged.
        assert_eq!(sanitize_field("operator_authority"), "operator_authority");
        assert_eq!(sanitize_field("(unknown)"), "(unknown)");
    }

    #[test]
    fn parse_reroute_frame_sanitizes_tampered_cause_and_reframing() {
        // A tampered payload with ANSI + control chars in the string
        // fields must be neutralised at decode time, not at print time.
        let payload = serde_json::to_vec(&serde_json::json!({
            "cause": "\x1b[2J\x1b[31mEVIL",
            "reframing_id": "id\nwith\rbreaks",
            "ts_unix": 1u64,
        }))
        .unwrap();
        let e = parse_reroute_frame(EVENT_TYPE_REFUSAL_REROUTED, &payload, 1, 1).unwrap();
        assert!(
            !e.cause.contains('\x1b'),
            "ANSI must be stripped: {:?}",
            e.cause
        );
        assert_eq!(e.cause, "EVIL");
        assert_eq!(e.reframing_id, "idwithbreaks");
    }
}
