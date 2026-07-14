//! `neoth council` — operator UI for the Pick #8 smartest-wins
//! features (Session 14 Pick #14).
//!
//! The Pick #8 stack shipped behind opt-in flags: `selection_mode`,
//! `self_reflect_enabled`, `refine_threshold`, etc. Editing
//! `freedom.yaml` by hand is error-prone (typos in enum variants,
//! missing fields silently default-off). This CLI surfaces the
//! controls + the memory-routing observability so operators see
//! what NEOTH has learned about their workload.
//!
//! Subcommands:
//!
//!   - `tune`        Toggle smartest-wins / self-reflect / refine
//!                   threshold in freedom.yaml atomically.
//!   - `weights`     Inspect `~/.neoth/routing_weights.json` —
//!                   per-(topic, role) Hebbian acceptance signals.
//!   - `show`        Print the current `council` config block.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::inference::SelectionMode;
use crate::memory::routing_weights::{RoutingWeights, now_unix};
use crate::wal::compress::decompress_frames;
use crate::wal::events::{
    EVENT_TYPE_COUNCIL_DIVERSITY_WARNING, EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL,
    EVENT_TYPE_COUNCIL_SKIP, EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED, EVENT_TYPE_COUNCIL_TRANSCRIPT,
    EVENT_TYPE_COUNCIL_WINNER_SELECTED,
};
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;

#[derive(Args, Debug, Clone)]
pub struct CouncilArgs {
    #[command(subcommand)]
    pub action: CouncilAction,

    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CouncilAction {
    /// Print the active `council` config block from freedom.yaml.
    Show,

    /// Atomically modify the `council` config block in freedom.yaml.
    /// Each flag is optional; only the ones you pass get updated.
    Tune {
        /// Set selection mode. Values: `legacy_majority` (default;
        /// v0.1 behaviour), `consensus_or_best` (Verdict::Consensus
        /// wins on agreement, else quality-score), `best_always`
        /// (always pick by quality score).
        #[arg(long, value_name = "MODE")]
        selection_mode: Option<String>,

        /// Toggle self-reflect refinement pass. `true` enables the
        /// threshold-gated, depth=0-only second-call refinement.
        #[arg(long)]
        self_reflect: Option<bool>,

        /// Composite quality score threshold below which the
        /// refinement pass fires (range [0.0, 1.0]; default 0.90).
        #[arg(long, value_name = "T")]
        refine_threshold: Option<f32>,

        /// Hard cap on LLM calls per user message (BudgetToken
        /// schema field; default 15).
        #[arg(long, value_name = "N")]
        max_calls: Option<u32>,

        /// Daily USD budget cap (set to 0 to disable).
        #[arg(long, value_name = "USD")]
        daily_usd_cap: Option<f32>,

        /// Print what would change without writing freedom.yaml.
        #[arg(long)]
        dry_run: bool,
    },

    /// Inspect the memory-routing weights. Each row records a
    /// `(topic_hash, hemisphere_role)` pair's Hebbian-decayed
    /// acceptance count. Read-only.
    Weights {
        /// Operator-readable cap on rows printed. Defaults to 20.
        #[arg(long, value_name = "N")]
        top_n: Option<usize>,

        /// Filter to one hemisphere role: `left`, `right`,
        /// `cerebellum`. Default: all three.
        #[arg(long, value_name = "ROLE")]
        role: Option<String>,
    },

    /// SPEC-03: list recent council decisions from the WAL audit trail
    /// (`0x60..=0x64` frames — synthesis / partial-refusal / skip /
    /// winner / diversity-warning) across every segment. Read-only.
    List {
        /// Max rows, most-recent first. Default 50; `0` = all.
        #[arg(long, value_name = "N")]
        limit: Option<usize>,

        /// Only show events at/after this unix timestamp (seconds).
        #[arg(long, value_name = "TS")]
        since_unix: Option<u64>,
    },

    /// SPEC-03: inspect every council WAL frame for one debate, keyed by
    /// the `prompt_hash` (the 16-hex xxh3 shown by `council list`). There
    /// is no opaque debate-id — the prompt_hash IS the linkage key.
    Inspect {
        /// The 16-hex `prompt_hash` copied from `council list`.
        #[arg(value_name = "PROMPT_HASH")]
        prompt_hash: String,
    },

    /// KF-01 — Council Replay Glass: reconstruct ONE debate as a
    /// chronological NARRATIVE timeline (convened → who refused → winner
    /// depth → diversity warning) from the WAL audit frames, keyed by
    /// `prompt_hash`. Richer than `inspect`'s raw frame list. NOTE: the
    /// hemispheres' actual response PROSE is NOT persisted in the WAL
    /// (only content hashes + metadata, for privacy), so replay
    /// reconstructs the debate STRUCTURE — WHAT the council did — not the
    /// verbatim text.
    Replay {
        /// The 16-hex `prompt_hash` copied from `council list`.
        #[arg(value_name = "PROMPT_HASH")]
        prompt_hash: String,
    },

    /// SPEC-03: persistently disable the council smart-trigger by writing
    /// `freedom.yaml::council.disabled = true`. Every turn then takes the
    /// single-hemisphere path (both CLI + channels) until you clear it
    /// with `--off`. The durable twin of `NEOTH_COUNCIL_DISABLE=1`.
    Suppress {
        /// Clear the suppression (`council.disabled = false`).
        #[arg(long)]
        off: bool,
    },

    /// KF-08: show the council per-message budget posture — the
    /// configured cap (`freedom.yaml::council`) plus the last debate's
    /// live runtime usage from `~/.neoth/council_budget.json` (written
    /// by the chat-layer council wrapper after each debate).
    Budget,

    /// GOLD-WIRE-04: list the available council voices — the specialist
    /// framings a hemisphere can debate as (set per slot via
    /// `freedom.yaml::inference.<slot>.voice`). Read-only.
    Voices,
}

pub async fn run_council(args: CouncilArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        CouncilAction::Show => run_show(&home, args.output),
        CouncilAction::Tune {
            selection_mode,
            self_reflect,
            refine_threshold,
            max_calls,
            daily_usd_cap,
            dry_run,
        } => run_tune(
            &home,
            selection_mode,
            self_reflect,
            refine_threshold,
            max_calls,
            daily_usd_cap,
            dry_run,
            args.output,
        ),
        CouncilAction::Weights { top_n, role } => {
            run_weights(&home, top_n, role.as_deref(), args.output)
        }
        CouncilAction::List { limit, since_unix } => {
            run_list(&home, limit, since_unix, args.output)
        }
        CouncilAction::Inspect { prompt_hash } => run_inspect(&home, &prompt_hash, args.output),
        CouncilAction::Replay { prompt_hash } => run_replay(&home, &prompt_hash, args.output),
        CouncilAction::Suppress { off } => run_suppress(&home, off, args.output),
        CouncilAction::Budget => run_budget(&home, args.output),
        CouncilAction::Voices => run_voices(args.output),
    }
}

/// GOLD-WIRE-04: list every council voice + its description. Pure read of
/// `CouncilVoice::ALL` — no config / WAL access.
fn run_voices(output: OutputFormat) -> Result<()> {
    use crate::council::types::CouncilVoice;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = CouncilVoice::ALL
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "id": v.as_str(),
                        "description": v.description(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Table => {
            println!("# Council voices (set per slot via freedom.yaml::inference.<slot>.voice)");
            for v in CouncilVoice::ALL {
                println!("  {:<26}  {}", v.as_str(), v.description());
            }
        }
    }
    Ok(())
}

fn run_show(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))?;
    let council = &cfg.council;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let j = json!({
                "selection_mode": selection_mode_as_str(council.selection_mode),
                "self_reflect_enabled": council.self_reflect_enabled,
                "refine_threshold": council.effective_refine_threshold(),
                "max_calls_per_user_message": council.effective_max_calls(),
                "daily_usd_cap": council.daily_usd_cap,
                "max_background_connections": council.effective_max_background_connections(),
                "diversity_bonus_weight": council.effective_diversity_bonus_weight(),
                "max_recursion_depth": council.effective_max_recursion_depth(),
            });
            println!("{}", serde_json::to_string_pretty(&j)?);
        }
        OutputFormat::Table => {
            println!("# council config (~/.neoth/freedom.yaml)");
            println!(
                "  selection_mode:           {}",
                selection_mode_as_str(council.selection_mode)
            );
            println!(
                "  self_reflect_enabled:     {}",
                council.self_reflect_enabled
            );
            println!(
                "  refine_threshold:         {:.2} (effective)",
                council.effective_refine_threshold()
            );
            println!(
                "  max_calls_per_user_msg:   {}",
                council.effective_max_calls()
            );
            println!(
                "  daily_usd_cap:            {}",
                council
                    .daily_usd_cap
                    .map(|n| format!("${n:.2}"))
                    .unwrap_or_else(|| "(none)".into())
            );
            println!(
                "  max_background_connect:   {}",
                council.effective_max_background_connections()
            );
            println!(
                "  diversity_bonus_weight:   {:.2}",
                council.effective_diversity_bonus_weight()
            );
            println!(
                "  max_recursion_depth:      {}",
                council.effective_max_recursion_depth()
            );
            println!();
            println!("(use `neoth council tune --selection-mode X --self-reflect true` to change)");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_tune(
    home: &std::path::Path,
    selection_mode: Option<String>,
    self_reflect: Option<bool>,
    refine_threshold: Option<f32>,
    max_calls: Option<u32>,
    daily_usd_cap: Option<f32>,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let yaml = home.join("freedom.yaml");
    if !yaml.exists() {
        anyhow::bail!(
            "freedom.yaml not found at {}. Run `neoth init` first.",
            yaml.display()
        );
    }
    let mut cfg = FreedomConfig::load_from_path(&yaml).context("load freedom.yaml")?;
    let mut changes: Vec<(&'static str, String, String)> = Vec::new();

    if let Some(mode_str) = selection_mode {
        let parsed = parse_selection_mode(&mode_str)?;
        let before = selection_mode_as_str(cfg.council.selection_mode).to_string();
        let after = selection_mode_as_str(parsed).to_string();
        if before != after {
            cfg.council.selection_mode = parsed;
            changes.push(("selection_mode", before, after));
        }
    }
    if let Some(sr) = self_reflect {
        let before = cfg.council.self_reflect_enabled;
        if before != sr {
            cfg.council.self_reflect_enabled = sr;
            changes.push(("self_reflect_enabled", before.to_string(), sr.to_string()));
        }
    }
    if let Some(t) = refine_threshold {
        if !(0.0..=1.0).contains(&t) {
            anyhow::bail!("refine_threshold {t} out of [0.0, 1.0]");
        }
        let before = cfg.council.refine_threshold.unwrap_or(0.9);
        cfg.council.refine_threshold = Some(t);
        changes.push((
            "refine_threshold",
            format!("{before:.2}"),
            format!("{t:.2}"),
        ));
    }
    if let Some(n) = max_calls {
        if n == 0 {
            anyhow::bail!("max_calls must be >= 1");
        }
        let before = cfg.council.effective_max_calls();
        cfg.council.max_calls_per_user_message = Some(n);
        changes.push((
            "max_calls_per_user_message",
            before.to_string(),
            n.to_string(),
        ));
    }
    if let Some(usd) = daily_usd_cap {
        let before = cfg
            .council
            .daily_usd_cap
            .map(|n| format!("${n:.2}"))
            .unwrap_or_else(|| "(none)".into());
        cfg.council.daily_usd_cap = if usd <= 0.0 { None } else { Some(usd) };
        let after = cfg
            .council
            .daily_usd_cap
            .map(|n| format!("${n:.2}"))
            .unwrap_or_else(|| "(none)".into());
        changes.push(("daily_usd_cap", before, after));
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let j = json!({
                "dry_run": dry_run,
                "changes": changes.iter()
                    .map(|(field, before, after)| json!({
                        "field": field,
                        "before": before,
                        "after": after,
                    }))
                    .collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&j)?);
        }
        OutputFormat::Table => {
            if changes.is_empty() {
                println!(
                    "[neoth council tune] no changes — every requested value already matched the current config"
                );
            } else {
                println!(
                    "# tune changes ({}{})",
                    changes.len(),
                    if dry_run { " — DRY RUN" } else { "" }
                );
                for (field, before, after) in &changes {
                    println!("  {field:<28} {before:>14} → {after}");
                }
            }
        }
    }

    if !dry_run && !changes.is_empty() {
        write_freedom_yaml(&yaml, &cfg)?;
    }
    Ok(())
}

fn run_weights(
    home: &std::path::Path,
    top_n: Option<usize>,
    role_filter: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let path = RoutingWeights::default_path(home);
    let weights = RoutingWeights::load_from(&path).context("load routing weights")?;
    let role_filter = role_filter.map(parse_role).transpose()?;

    let now = now_unix();
    let mut rows: Vec<_> = weights
        .rows
        .iter()
        .filter(|r| match role_filter {
            None => true,
            Some(r2) => r.hemisphere_role == r2,
        })
        .map(|r| {
            let memw = weights.load_memory_weight(r.topic_hash, r.hemisphere_role, now);
            (r, memw)
        })
        .collect();
    rows.sort_by(|(_, w_a), (_, w_b)| w_b.partial_cmp(w_a).unwrap_or(std::cmp::Ordering::Equal));
    let cap = top_n.unwrap_or(20);
    rows.truncate(cap);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let j: Vec<_> = rows
                .iter()
                .map(|(r, w)| {
                    json!({
                        "topic_hash": format!("{:016x}", r.topic_hash),
                        "hemisphere_role": role_to_str(r.hemisphere_role),
                        "success_count": r.success_count,
                        "decay_anchor_unix": r.decay_anchor_unix,
                        "memory_weight": w,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&j)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("# routing weights — empty");
                println!(
                    "  (no acceptance signals yet; weights accumulate when council selection_mode is non-legacy)"
                );
                return Ok(());
            }
            println!(
                "# routing weights (top {}, sorted by memory_weight DESC)",
                rows.len()
            );
            println!(
                "  {:<18} {:<12} {:>14} {:>10}",
                "topic_hash", "role", "success_count", "mem_weight"
            );
            println!(
                "  {:<18} {:<12} {:>14} {:>10}",
                "-".repeat(18),
                "-".repeat(12),
                "-".repeat(14),
                "-".repeat(10)
            );
            for (r, w) in rows {
                println!(
                    "  {:<18x} {:<12} {:>14.2} {:>10.3}",
                    r.topic_hash,
                    role_to_str(r.hemisphere_role),
                    r.success_count,
                    w
                );
            }
            println!();
            println!(
                "(weights decay via Hebbian factor per elapsed day; MAX_WEIGHT_DELTA = 0.05 const)"
            );
        }
    }
    Ok(())
}

fn parse_selection_mode(s: &str) -> Result<SelectionMode> {
    match s.to_ascii_lowercase().replace('-', "_").as_str() {
        "legacy_majority" | "legacy" => Ok(SelectionMode::LegacyMajority),
        "consensus_or_best" | "consensus" | "or_best" => Ok(SelectionMode::ConsensusOrBest),
        "best_always" | "best" | "always" => Ok(SelectionMode::BestAlways),
        other => anyhow::bail!(
            "invalid selection_mode `{other}`. Values: legacy_majority | consensus_or_best | best_always"
        ),
    }
}

fn parse_role(s: &str) -> Result<crate::config::inference::HemisphereRole> {
    use crate::config::inference::HemisphereRole;
    match s.to_ascii_lowercase().as_str() {
        "left" | "l" => Ok(HemisphereRole::Left),
        "right" | "r" => Ok(HemisphereRole::Right),
        "cerebellum" | "c" | "cere" => Ok(HemisphereRole::Cerebellum),
        other => anyhow::bail!("invalid role `{other}`. Values: left | right | cerebellum"),
    }
}

fn selection_mode_as_str(mode: SelectionMode) -> &'static str {
    match mode {
        SelectionMode::LegacyMajority => "legacy_majority",
        SelectionMode::ConsensusOrBest => "consensus_or_best",
        SelectionMode::BestAlways => "best_always",
    }
}

fn role_to_str(role: crate::config::inference::HemisphereRole) -> &'static str {
    use crate::config::inference::HemisphereRole;
    match role {
        HemisphereRole::Left => "left",
        HemisphereRole::Right => "right",
        HemisphereRole::Cerebellum => "cerebellum",
    }
}

fn write_freedom_yaml(path: &PathBuf, cfg: &FreedomConfig) -> Result<()> {
    let yaml = serde_yaml::to_string(cfg).context("serialize freedom.yaml")?;
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, yaml).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

// ── SPEC-03: council list / inspect (WAL audit reads) ─────────────────────

/// One council event parsed from a `0x60..=0x64` WAL frame.
#[derive(Debug, Clone)]
struct CouncilEventRow {
    event_id: u64,
    ts_ns: u64,
    ts_unix: Option<i64>,
    code: u8,
    code_name: &'static str,
    /// 16-hex xxh3 of the prompt that triggered the debate — the linkage
    /// key `council inspect` filters on. `None` if a frame predates the
    /// `prompt_hash` payload field.
    prompt_hash: Option<String>,
    payload: serde_json::Value,
}

/// Map a council WAL event-type byte to its short operator-facing name,
/// or `None` when the byte isn't in the council band — doubles as the
/// band filter for the WAL scan.
fn council_code_name(event_type: u8) -> Option<&'static str> {
    match event_type {
        EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED => Some("synthesis_attempted"),
        EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL => Some("partial_refusal"),
        EVENT_TYPE_COUNCIL_SKIP => Some("skip"),
        EVENT_TYPE_COUNCIL_WINNER_SELECTED => Some("winner_selected"),
        EVENT_TYPE_COUNCIL_DIVERSITY_WARNING => Some("diversity_warning"),
        EVENT_TYPE_COUNCIL_TRANSCRIPT => Some("transcript"),
        _ => None,
    }
}

/// A compact secondary-field summary per council code (the reason a turn
/// skipped, the depth a winner was selected at). Empty when the code has
/// no salient extra field.
fn council_row_summary(row: &CouncilEventRow) -> String {
    match row.code {
        EVENT_TYPE_COUNCIL_SKIP => row
            .payload
            .get("reason")
            .and_then(|v| v.as_str())
            .map(|s| format!("reason={s}"))
            .unwrap_or_default(),
        EVENT_TYPE_COUNCIL_WINNER_SELECTED => row
            .payload
            .get("depth")
            .and_then(|v| v.as_u64())
            .map(|d| format!("depth={d}"))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Multi-segment WAL scan collecting every council `0x60..=0x64` frame.
/// Mirrors the SPEC-10 refusal-history walker: glob+sort `*.wal`, parse
/// the v1/v2 segment header, decompress v2 zstd bodies, and walk frames.
/// A genuinely missing WAL directory is an empty history. Existing unreadable
/// segments, invalid headers/compression, and malformed council payloads are
/// surfaced so the audit UI cannot present a silently incomplete record. A
/// torn active tail remains tolerated after every fully decoded frame.
fn collect_council_events(wal_dir: &Path) -> Result<Vec<CouncilEventRow>> {
    if !wal_dir
        .try_exists()
        .with_context(|| format!("inspect council WAL directory {}", wal_dir.display()))?
    {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(wal_dir)
        .with_context(|| format!("read council WAL directory {}", wal_dir.display()))?;
    let mut segments = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("read entry in council WAL directory {}", wal_dir.display()))?
            .path();
        if path.extension().and_then(|s| s.to_str()) == Some("wal") {
            segments.push(path);
        }
    }
    segments.sort();

    let mut out: Vec<CouncilEventRow> = Vec::new();
    for path in segments {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read council WAL segment {}", path.display()))?;
        let hdr = parse_segment_header(&bytes)
            .with_context(|| format!("parse council WAL header {}", path.display()))?;
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue;
        }
        let body = &bytes[header_len..];
        if hdr.is_compressed() {
            let decompressed = decompress_frames(body)
                .with_context(|| format!("decompress council WAL segment {}", path.display()))?;
            walk_council_frames(&decompressed, &mut out)?;
        } else {
            walk_council_frames(body, &mut out)?;
        }
    }
    Ok(out)
}

/// Walk one (decompressed) segment body, pushing every council frame.
/// Tail-tolerant; the zero-`total_len` guard prevents an infinite loop on
/// a malformed frame.
fn walk_council_frames(frames: &[u8], out: &mut Vec<CouncilEventRow>) -> Result<()> {
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if let Some(code_name) = council_code_name(dec.header.event_type) {
            let payload: serde_json::Value =
                serde_json::from_slice(dec.payload).with_context(|| {
                    format!(
                        "decode council WAL payload for event {} (type 0x{:02X})",
                        dec.header.event_id.0, dec.header.event_type
                    )
                })?;
            let prompt_hash = payload
                .get("prompt_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let ts_unix = payload.get("ts_unix").and_then(|v| v.as_i64());
            out.push(CouncilEventRow {
                event_id: dec.header.event_id.0,
                ts_ns: dec.header.hlc.physical_ns(),
                ts_unix,
                code: dec.header.event_type,
                code_name,
                prompt_hash,
                payload,
            });
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    Ok(())
}

/// Sort most-recent-first (`ts_ns` desc, `event_id` tiebreak) + apply the
/// display limit (`0` = all). Pure — split out so the ordering + limit
/// logic is unit-testable without a real WAL. Returns `(shown, total)`.
fn select_council_for_display(
    mut rows: Vec<CouncilEventRow>,
    limit: usize,
) -> (Vec<CouncilEventRow>, usize) {
    rows.sort_by(|a, b| {
        b.ts_ns
            .cmp(&a.ts_ns)
            .then_with(|| b.event_id.cmp(&a.event_id))
    });
    let total = rows.len();
    let shown = if limit == 0 {
        rows
    } else {
        rows.into_iter().take(limit).collect()
    };
    (shown, total)
}

fn ts_label(row: &CouncilEventRow) -> String {
    row.ts_unix
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("hlc_ns={}", row.ts_ns))
}

/// `neoth council list` — read-only WAL audit of recent council decisions.
fn run_list(
    home: &Path,
    limit: Option<usize>,
    since_unix: Option<u64>,
    output: OutputFormat,
) -> Result<()> {
    let wal_dir = home.join("wal");
    let mut rows = collect_council_events(&wal_dir)?;
    if let Some(since) = since_unix {
        // Rows without a ts_unix payload field are kept (can't filter them
        // out without a timestamp; they're rare legacy frames).
        rows.retain(|r| r.ts_unix.map(|t| t as u64 >= since).unwrap_or(true));
    }
    let (shown, total) = select_council_for_display(rows, limit.unwrap_or(50));

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let events: Vec<_> = shown
                .iter()
                .map(|r| {
                    json!({
                        "event_id": r.event_id,
                        "ts_ns": r.ts_ns,
                        "ts_unix": r.ts_unix,
                        "code": format!("0x{:02X}", r.code),
                        "code_name": r.code_name,
                        "prompt_hash": r.prompt_hash,
                        "summary": council_row_summary(r),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "events": events,
                    "shown": shown.len(),
                    "total": total,
                }))?
            );
        }
        OutputFormat::Table => {
            if shown.is_empty() {
                println!("# Council decisions");
                println!(
                    "  (none) — no council 0x60-0x64 frames in the WAL yet. Council fires on \
                     complex/dissent-marked prompts; see `neoth council show` for the gates."
                );
                return Ok(());
            }
            println!(
                "# Council decisions — showing {} of {} (most recent first)",
                shown.len(),
                total
            );
            for r in &shown {
                let summary = council_row_summary(r);
                let summary = if summary.is_empty() {
                    String::new()
                } else {
                    format!(" {summary}")
                };
                println!(
                    "  [{}] eid={} {} prompt={}{}",
                    ts_label(r),
                    r.event_id,
                    r.code_name,
                    r.prompt_hash.as_deref().unwrap_or("-"),
                    summary,
                );
            }
            println!("(inspect one debate: `neoth council inspect <prompt_hash>`)");
        }
    }
    Ok(())
}

/// KF-01 — render ONE council frame as a narrative replay line. Pure;
/// unit-tested per code without a real WAL.
fn render_replay_line(row: &CouncilEventRow) -> String {
    match row.code {
        EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED => {
            "convened — synthesis attempted across the hemispheres".to_string()
        }
        EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL => {
            let refused = row
                .payload
                .get("refused_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let usable = row
                .payload
                .get("usable_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let roles = row
                .payload
                .get("refused")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|s| !s.is_empty())
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            format!("partial refusal — {refused} hemisphere(s) declined{roles}, {usable} usable")
        }
        EVENT_TYPE_COUNCIL_SKIP => {
            let reason = row
                .payload
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("unspecified");
            format!("skipped — {reason}")
        }
        EVENT_TYPE_COUNCIL_WINNER_SELECTED => {
            match row.payload.get("depth").and_then(|v| v.as_u64()) {
                Some(d) => format!("winner selected at depth {d}"),
                None => "winner selected".to_string(),
            }
        }
        EVENT_TYPE_COUNCIL_DIVERSITY_WARNING => {
            "diversity warning — hemispheres converged suspiciously (possible groupthink)"
                .to_string()
        }
        EVENT_TYPE_COUNCIL_TRANSCRIPT => {
            // KF-01 full — the verbatim hemisphere prose the operator
            // opted to persist. Header names the role + provider; the
            // text follows on its own indented lines.
            let role = row
                .payload
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("hemisphere");
            let provider = row
                .payload
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let text = row
                .payload
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let indented = text
                .lines()
                .map(|l| format!("       {l}"))
                .collect::<Vec<_>>()
                .join("\n");
            format!("transcript [{role} / {provider}]:\n{indented}")
        }
        _ => row.code_name.to_string(),
    }
}

/// KF-01 — `neoth council replay <prompt_hash>`: chronological NARRATIVE
/// reconstruction of one debate from the council WAL frames. By default the
/// hemisphere PROSE is NOT in the WAL (privacy — only content hashes +
/// metadata persist), so replay reconstructs the debate STRUCTURE. When the
/// operator opts into `freedom.yaml::council.persist_transcripts`, each
/// hemisphere's verbatim text is persisted as a `0x66 COUNCIL_TRANSCRIPT`
/// frame and replay renders it inline (and reports `transcripts_available`).
fn run_replay(home: &Path, prompt_hash: &str, output: OutputFormat) -> Result<()> {
    let wal_dir = home.join("wal");
    let mut rows: Vec<CouncilEventRow> = collect_council_events(&wal_dir)?
        .into_iter()
        .filter(|r| {
            r.prompt_hash
                .as_deref()
                .map(|h| h.eq_ignore_ascii_case(prompt_hash))
                .unwrap_or(false)
        })
        .collect();
    // Chronological (forward) — replay plays the debate in order.
    rows.sort_by(|a, b| a.ts_ns.cmp(&b.ts_ns).then(a.event_id.cmp(&b.event_id)));

    // KF-01 full: verbatim prose is present only when the operator opted
    // into `council.persist_transcripts` and a 0x66 frame was written.
    let transcripts_available = rows.iter().any(|r| r.code == EVENT_TYPE_COUNCIL_TRANSCRIPT);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let steps: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "event_id": r.event_id,
                        "code": r.code_name,
                        "narrative": render_replay_line(r),
                        "payload": r.payload,
                    })
                })
                .collect();
            let obj = serde_json::json!({
                "prompt_hash": prompt_hash,
                "steps": steps,
                "transcripts_available": transcripts_available,
            });
            println!("{}", serde_json::to_string(&obj)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!(
                    "No council debate found for prompt_hash `{prompt_hash}`. \
                     Run `neoth council list` to see recorded debates."
                );
                return Ok(());
            }
            println!("Council replay — debate {prompt_hash}\n");
            for (i, r) in rows.iter().enumerate() {
                println!("  {}. {}", i + 1, render_replay_line(r));
            }
            if transcripts_available {
                println!(
                    "\n(Verbatim hemisphere transcripts above are persisted because \
                     `freedom.yaml::council.persist_transcripts` is enabled — they are part \
                     of the auditable WAL record.)"
                );
            } else {
                println!(
                    "\n(Note: hemisphere response prose is not persisted — only the debate \
                     structure above + content hashes. Enable \
                     `freedom.yaml::council.persist_transcripts` to record verbatim \
                     transcripts for future debates. Replay reconstructs WHAT the council \
                     did, not the verbatim text.)"
                );
            }
        }
    }
    Ok(())
}

/// `neoth council inspect <prompt_hash>` — every council frame for one
/// debate, matched by the prompt_hash linkage key (case-insensitive).
fn run_inspect(home: &Path, prompt_hash: &str, output: OutputFormat) -> Result<()> {
    let wal_dir = home.join("wal");
    let needle = prompt_hash.trim();
    let matches: Vec<CouncilEventRow> = collect_council_events(&wal_dir)?
        .into_iter()
        .filter(|r| {
            r.prompt_hash
                .as_deref()
                .map(|h| h.eq_ignore_ascii_case(needle))
                .unwrap_or(false)
        })
        .collect();
    let (shown, total) = select_council_for_display(matches, 0);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let frames: Vec<_> = shown
                .iter()
                .map(|r| {
                    json!({
                        "event_id": r.event_id,
                        "ts_ns": r.ts_ns,
                        "ts_unix": r.ts_unix,
                        "code": format!("0x{:02X}", r.code),
                        "code_name": r.code_name,
                        "payload": r.payload,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "prompt_hash": needle,
                    "frames": frames,
                    "total": total,
                }))?
            );
        }
        OutputFormat::Table => {
            if shown.is_empty() {
                println!("# Council debate {needle}");
                println!(
                    "  (none) — no council frames carry that prompt_hash. Copy the exact \
                     16-hex value from `neoth council list`."
                );
                return Ok(());
            }
            println!("# Council debate {needle} — {total} frame(s)");
            for r in &shown {
                println!("  [{}] eid={} {}", ts_label(r), r.event_id, r.code_name);
                // Pretty-print the full payload indented so the operator
                // sees exactly what the audit chain recorded for this hop.
                if let Ok(pretty) = serde_json::to_string_pretty(&r.payload) {
                    for line in pretty.lines() {
                        println!("      {line}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// `neoth council suppress [--off]` — flip the persistent
/// `freedom.yaml::council.disabled` flag. `suppress` sets it true
/// (single-hemisphere path everywhere); `--off` clears it.
fn run_suppress(home: &Path, off: bool, output: OutputFormat) -> Result<()> {
    let yaml = home.join("freedom.yaml");
    if !yaml.exists() {
        anyhow::bail!(
            "freedom.yaml not found at {}. Run `neoth init` first.",
            yaml.display()
        );
    }
    let mut cfg = FreedomConfig::load_from_path(&yaml).context("load freedom.yaml")?;
    let new_value = !off;
    cfg.council.disabled = Some(new_value);
    write_freedom_yaml(&yaml, &cfg)?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "action": "suppress",
                "council_disabled": new_value,
            }))?
        ),
        OutputFormat::Table => {
            if new_value {
                println!(
                    "council suppressed — `council.disabled = true` written to freedom.yaml. \
                     Every turn (CLI + channels) now takes the single-hemisphere path. \
                     Re-enable with `neoth council suppress --off`."
                );
            } else {
                println!(
                    "council suppression cleared — `council.disabled = false`. The \
                     smart-trigger is active again (see `neoth council show` for the gates)."
                );
            }
        }
    }
    Ok(())
}

/// `neoth council budget` — KF-08 meter readout: the configured
/// per-message cap (`freedom.yaml::council`) + the last debate's live
/// runtime usage from the `council_budget.json` scratch file.
/// JSON body for `run_budget`'s machine output. Extracted so the
/// GUI-consumed contract is unit-testable: `neothd-gui`'s
/// `parse_council_budget` reads `max_recursion_depth` from exactly this
/// object to derive the 3^depth cost warning (GR-001 — the key was
/// missing, so the GUI warning never fired).
fn budget_json_body(cfg: &FreedomConfig, runtime: Option<serde_json::Value>) -> serde_json::Value {
    json!({
        "configured_cap": cfg.council.effective_max_calls(),
        "daily_usd_cap": cfg.council.daily_usd_cap,
        "max_recursion_depth": cfg.council.effective_max_recursion_depth(),
        "runtime": runtime,
    })
}

fn run_budget(home: &Path, output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))?;
    let cap = cfg.council.effective_max_calls();
    let daily_usd_cap = cfg.council.daily_usd_cap;
    let snap = crate::council::budget::load_budget_snapshot(home);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let runtime = snap.as_ref().map(|s| {
                json!({
                    "cap_at_last_debate": s.cap,
                    "used_last_msg": s.used_last_msg,
                    "exhausted_last_msg": s.exhausted_last_msg,
                    "exhaustions_rolling": s.exhaustions_rolling,
                    "updated_ts_unix": s.updated_ts_unix,
                })
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&budget_json_body(&cfg, runtime))?
            );
        }
        OutputFormat::Table => {
            println!("# council budget");
            println!("  configured cap (calls/message): {cap}");
            println!(
                "  daily USD cap:                  {}",
                daily_usd_cap
                    .map(|n| format!("${n:.2}"))
                    .unwrap_or_else(|| "(none)".into())
            );
            match snap {
                Some(s) => {
                    println!(
                        "  last debate: used {}/{} call(s){}",
                        s.used_last_msg,
                        s.cap,
                        if s.exhausted_last_msg {
                            "  (CAP HIT)"
                        } else {
                            ""
                        }
                    );
                    println!(
                        "  debates that hit the cap (lifetime): {}",
                        s.exhaustions_rolling
                    );
                    println!("  updated (unix): {}", s.updated_ts_unix);
                    if s.exhaustions_rolling > 0 {
                        println!(
                            "(cap-hits climbing? raise it: \
                             `neoth council tune --max-calls N`)"
                        );
                    }
                }
                None => println!("  runtime: (no council debate recorded yet)"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_selection_mode_accepts_all_aliases() {
        assert!(matches!(
            parse_selection_mode("legacy_majority").unwrap(),
            SelectionMode::LegacyMajority
        ));
        assert!(matches!(
            parse_selection_mode("legacy").unwrap(),
            SelectionMode::LegacyMajority
        ));
        assert!(matches!(
            parse_selection_mode("CONSENSUS_OR_BEST").unwrap(),
            SelectionMode::ConsensusOrBest
        ));
        assert!(matches!(
            parse_selection_mode("consensus-or-best").unwrap(),
            SelectionMode::ConsensusOrBest
        ));
        assert!(matches!(
            parse_selection_mode("best_always").unwrap(),
            SelectionMode::BestAlways
        ));
        assert!(matches!(
            parse_selection_mode("BEST").unwrap(),
            SelectionMode::BestAlways
        ));
    }

    #[test]
    fn parse_selection_mode_rejects_unknown() {
        let err = parse_selection_mode("nope").unwrap_err();
        assert!(err.to_string().contains("invalid selection_mode"));
    }

    #[test]
    fn parse_role_accepts_full_and_short() {
        use crate::config::inference::HemisphereRole;
        assert_eq!(parse_role("left").unwrap(), HemisphereRole::Left);
        assert_eq!(parse_role("L").unwrap(), HemisphereRole::Left);
        assert_eq!(parse_role("right").unwrap(), HemisphereRole::Right);
        assert_eq!(parse_role("r").unwrap(), HemisphereRole::Right);
        assert_eq!(
            parse_role("cerebellum").unwrap(),
            HemisphereRole::Cerebellum
        );
        assert_eq!(parse_role("c").unwrap(), HemisphereRole::Cerebellum);
    }

    #[test]
    fn parse_role_rejects_unknown() {
        let err = parse_role("hippocampus").unwrap_err();
        assert!(err.to_string().contains("invalid role"));
    }

    #[test]
    fn role_to_str_mirrors_parse_role() {
        use crate::config::inference::HemisphereRole;
        for r in [
            HemisphereRole::Left,
            HemisphereRole::Right,
            HemisphereRole::Cerebellum,
        ] {
            let s = role_to_str(r);
            assert_eq!(parse_role(s).unwrap(), r);
        }
    }

    #[test]
    fn selection_mode_as_str_round_trips() {
        for mode in [
            SelectionMode::LegacyMajority,
            SelectionMode::ConsensusOrBest,
            SelectionMode::BestAlways,
        ] {
            let s = selection_mode_as_str(mode);
            assert!(parse_selection_mode(s).is_ok());
        }
    }

    // ── SPEC-03: list / inspect / suppress ────────────────────────────

    #[test]
    fn council_code_name_maps_only_the_band() {
        assert_eq!(
            council_code_name(EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED),
            Some("synthesis_attempted")
        );
        assert_eq!(council_code_name(EVENT_TYPE_COUNCIL_SKIP), Some("skip"));
        assert_eq!(
            council_code_name(EVENT_TYPE_COUNCIL_WINNER_SELECTED),
            Some("winner_selected")
        );
        // Out-of-band bytes are not council events.
        assert_eq!(council_code_name(0x10), None);
        assert_eq!(council_code_name(0x21), None);
        assert_eq!(council_code_name(0x65), None); // CONSENT_DECISION, adjacent
    }

    fn row(event_id: u64, ts_ns: u64) -> CouncilEventRow {
        CouncilEventRow {
            event_id,
            ts_ns,
            ts_unix: None,
            code: EVENT_TYPE_COUNCIL_SKIP,
            code_name: "skip",
            prompt_hash: None,
            payload: serde_json::Value::Null,
        }
    }

    #[test]
    fn select_council_for_display_sorts_desc_and_limits() {
        let rows = vec![row(1, 100), row(2, 300), row(3, 200)];
        let (shown, total) = select_council_for_display(rows, 2);
        assert_eq!(total, 3);
        assert_eq!(shown.len(), 2);
        // Newest (ts_ns 300) first, then 200.
        assert_eq!(shown[0].ts_ns, 300);
        assert_eq!(shown[1].ts_ns, 200);
    }

    #[test]
    fn select_council_for_display_zero_limit_keeps_all() {
        let rows = vec![row(1, 100), row(2, 300)];
        let (shown, total) = select_council_for_display(rows, 0);
        assert_eq!(total, 2);
        assert_eq!(shown.len(), 2);
    }

    #[test]
    fn collect_council_events_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let rows = collect_council_events(&dir.path().join("nope")).unwrap();
        assert!(rows.is_empty());
    }

    // ── KF-01 replay ───────────────────────────────────────────────────

    fn row_coded(code: u8, code_name: &'static str, payload: serde_json::Value) -> CouncilEventRow {
        CouncilEventRow {
            event_id: 1,
            ts_ns: 1,
            ts_unix: None,
            code,
            code_name,
            prompt_hash: Some("abc".into()),
            payload,
        }
    }

    #[test]
    fn render_replay_line_renders_each_council_code() {
        assert!(
            render_replay_line(&row_coded(
                EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED,
                "synthesis_attempted",
                serde_json::Value::Null
            ))
            .contains("convened")
        );
        let pr = render_replay_line(&row_coded(
            EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL,
            "partial_refusal",
            json!({ "refused_count": 1, "usable_count": 2, "refused": ["left"] }),
        ));
        assert!(
            pr.contains("partial refusal")
                && pr.contains("1 hemisphere")
                && pr.contains("left")
                && pr.contains("2 usable"),
            "got: {pr}"
        );
        assert!(
            render_replay_line(&row_coded(
                EVENT_TYPE_COUNCIL_SKIP,
                "skip",
                json!({ "reason": "rate_cooldown" })
            ))
            .contains("rate_cooldown")
        );
        assert!(
            render_replay_line(&row_coded(
                EVENT_TYPE_COUNCIL_WINNER_SELECTED,
                "winner_selected",
                json!({ "depth": 2 })
            ))
            .contains("depth 2")
        );
        assert!(
            render_replay_line(&row_coded(
                EVENT_TYPE_COUNCIL_DIVERSITY_WARNING,
                "diversity_warning",
                serde_json::Value::Null
            ))
            .contains("groupthink")
        );
        // KF-01 full — the verbatim transcript arm renders role, provider,
        // and the (indented) prose.
        let tr = render_replay_line(&row_coded(
            EVENT_TYPE_COUNCIL_TRANSCRIPT,
            "transcript",
            json!({
                "role": "left",
                "provider": "local_qwen",
                "text": "I think the answer is 42.\nHere is why."
            }),
        ));
        assert!(
            tr.contains("transcript [left / local_qwen]")
                && tr.contains("I think the answer is 42.")
                && tr.contains("Here is why."),
            "got: {tr}"
        );
    }

    #[test]
    fn transcripts_available_flips_when_a_0x66_frame_is_present() {
        // The narrative-only debate (no 0x66) reports transcripts absent;
        // a debate carrying a transcript row reports them available. This
        // pins the honesty flag the replay footer + JSON depend on.
        let no_tr = [
            EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED,
            EVENT_TYPE_COUNCIL_SKIP,
        ];
        assert!(!no_tr.contains(&EVENT_TYPE_COUNCIL_TRANSCRIPT));
        let with_tr = [
            EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED,
            EVENT_TYPE_COUNCIL_TRANSCRIPT,
        ];
        assert!(with_tr.contains(&EVENT_TYPE_COUNCIL_TRANSCRIPT));
    }

    #[test]
    fn run_replay_missing_wal_is_ok() {
        // No wal dir under home → empty → "no debate" table line, Ok.
        let dir = tempfile::tempdir().unwrap();
        assert!(run_replay(dir.path(), "deadbeef", OutputFormat::Table).is_ok());
        assert!(run_replay(dir.path(), "deadbeef", OutputFormat::Json).is_ok());
    }

    #[test]
    fn council_row_summary_extracts_reason_and_depth() {
        let mut skip = row(1, 1);
        skip.code = EVENT_TYPE_COUNCIL_SKIP;
        skip.payload = json!({ "reason": "rate: cooldown" });
        assert_eq!(council_row_summary(&skip), "reason=rate: cooldown");

        let mut winner = row(2, 2);
        winner.code = EVENT_TYPE_COUNCIL_WINNER_SELECTED;
        winner.payload = json!({ "depth": 1 });
        assert_eq!(council_row_summary(&winner), "depth=1");

        // A code with no salient secondary field → empty summary.
        let mut synth = row(3, 3);
        synth.code = EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED;
        assert_eq!(council_row_summary(&synth), "");
    }

    #[test]
    fn run_suppress_round_trips_the_disabled_flag() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = dir.path().join("freedom.yaml");
        // Seed a default freedom.yaml (disabled = None initially).
        write_freedom_yaml(&yaml, &FreedomConfig::default()).unwrap();
        assert!(
            FreedomConfig::load_from_path(&yaml)
                .unwrap()
                .council
                .disabled
                .is_none()
        );

        // suppress (off = false) → disabled = Some(true).
        run_suppress(dir.path(), false, OutputFormat::Json).unwrap();
        assert_eq!(
            FreedomConfig::load_from_path(&yaml)
                .unwrap()
                .council
                .disabled,
            Some(true)
        );

        // --off → disabled = Some(false).
        run_suppress(dir.path(), true, OutputFormat::Json).unwrap();
        assert_eq!(
            FreedomConfig::load_from_path(&yaml)
                .unwrap()
                .council
                .disabled,
            Some(false)
        );
    }

    #[test]
    fn run_suppress_errors_without_freedom_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_suppress(dir.path(), false, OutputFormat::Json).unwrap_err();
        assert!(err.to_string().contains("freedom.yaml not found"));
    }

    /// GR-001: the GUI's `parse_council_budget` derives its 3^depth cost
    /// warning from `max_recursion_depth` in this JSON — pin the key.
    #[test]
    fn run_budget_json_includes_max_recursion_depth() {
        let body = budget_json_body(&FreedomConfig::default(), None);
        assert!(
            body.get("max_recursion_depth").is_some(),
            "GUI contract key missing: {body}"
        );
        assert!(body.get("configured_cap").is_some());
    }

    #[test]
    fn run_budget_renders_config_only_without_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        write_freedom_yaml(&dir.path().join("freedom.yaml"), &FreedomConfig::default()).unwrap();
        // No council_budget.json yet → config-only readout, no error.
        assert!(run_budget(dir.path(), OutputFormat::Json).is_ok());
    }

    #[test]
    fn run_budget_reads_snapshot_when_present() {
        let dir = tempfile::tempdir().unwrap();
        write_freedom_yaml(&dir.path().join("freedom.yaml"), &FreedomConfig::default()).unwrap();
        crate::council::budget::record_budget_outcome(dir.path(), 15, 15, 1000);
        assert!(run_budget(dir.path(), OutputFormat::Json).is_ok());
        let snap = crate::council::budget::load_budget_snapshot(dir.path()).unwrap();
        assert!(snap.exhausted_last_msg);
        assert_eq!(snap.used_last_msg, 15);
    }

    #[tokio::test]
    async fn wal_round_trip_collects_and_filters_council_frames() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();

        // Two frames for the SAME debate (same prompt_hash) — a SKIP and a
        // WINNER — plus a non-council frame that must NOT be collected.
        let hash = "00000000000000ab";
        let skip_payload = serde_json::to_vec(&json!({
            "prompt_hash": hash,
            "reason": "rate: cooldown",
            "ts_unix": 1000,
        }))
        .unwrap();
        writer
            .append(
                crate::wal::HeaderBuilder::new(EVENT_TYPE_COUNCIL_SKIP, &skip_payload).build(),
                skip_payload,
            )
            .await
            .unwrap();
        let win_payload = serde_json::to_vec(&json!({
            "prompt_hash": hash,
            "depth": 1,
            "ts_unix": 1001,
        }))
        .unwrap();
        writer
            .append(
                crate::wal::HeaderBuilder::new(EVENT_TYPE_COUNCIL_WINNER_SELECTED, &win_payload)
                    .build(),
                win_payload,
            )
            .await
            .unwrap();
        // A non-council frame (BOOT 0x10) — must be ignored by the band filter.
        let boot = serde_json::to_vec(&json!({ "x": 1 })).unwrap();
        writer
            .append(
                crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_BOOT, &boot).build(),
                boot,
            )
            .await
            .unwrap();

        let rows = collect_council_events(&wal_dir).unwrap();
        assert_eq!(rows.len(), 2, "only the 2 council frames, not BOOT");
        assert!(rows.iter().all(|r| r.prompt_hash.as_deref() == Some(hash)));
        assert!(rows.iter().any(|r| r.code_name == "skip"));
        assert!(rows.iter().any(|r| r.code_name == "winner_selected"));

        // Inspect-style filter by prompt_hash (case-insensitive) finds both.
        let matched: Vec<_> = rows
            .iter()
            .filter(|r| {
                r.prompt_hash
                    .as_deref()
                    .map(|h| h.eq_ignore_ascii_case("00000000000000AB"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(matched.len(), 2);
    }

    #[tokio::test]
    async fn council_audit_rejects_malformed_recognized_payload() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let (writer, join) = crate::wal::writer::spawn(wal_dir.join("000001.wal")).unwrap();
        let payload = b"not-json".to_vec();
        writer
            .append(
                crate::wal::HeaderBuilder::new(EVENT_TYPE_COUNCIL_SKIP, &payload).build(),
                payload,
            )
            .await
            .unwrap();
        drop(writer);
        join.await.unwrap();

        let error = collect_council_events(&wal_dir).unwrap_err();
        assert!(format!("{error:#}").contains("decode council WAL payload"));
    }
}
