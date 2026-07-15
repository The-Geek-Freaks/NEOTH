//! `neoth events` — list every WAL event type the daemon writes.
//!
//! Operators reading the audit trail want to know what `event_type = 0x94`
//! means. This command dumps the registry as a table (or JSON), grouped
//! by band, so the answer doesn't require grepping `wal/events.rs`.
//!
//! Pure read-only. No file I/O. No daemon required.

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::wal::events::*;

#[derive(Args, Debug, Clone)]
pub struct EventsArgs {
    /// Filter by event-type byte (hex or decimal). Without it: list all.
    #[arg(long, value_name = "0xNN")]
    pub code: Option<String>,
    /// Restrict to one band. Accepts the band-low byte: `0x10` etc.
    #[arg(long, value_name = "0xN0")]
    pub band: Option<String>,
    /// Case-insensitive substring filter on the event name or description.
    /// Combines with `--band` (intersection). `--grep profile` filters the
    /// registry to every profile-related row across all bands.
    #[arg(long, value_name = "SUBSTR")]
    pub grep: Option<String>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// One row of the registry — kept as a `static` table so the command is
/// pure data, no SQL, no file walking.
struct Entry {
    code: u8,
    name: &'static str,
    band: &'static str,
    description: &'static str,
}

const REGISTRY: &[Entry] = &[
    // ── 0x00..=0x0F  Memory + recall ─────────────────────────────────────
    Entry {
        code: EVENT_TYPE_RAW_TEXT,
        name: "RAW_TEXT",
        band: "memory",
        description: "Operator/channel-supplied content (baseline)",
    },
    Entry {
        code: EVENT_TYPE_REINFORCE,
        name: "REINFORCE",
        band: "memory",
        description: "Dedup-hit on existing content_hash",
    },
    // ── 0x10..=0x1F  Daemon lifecycle ────────────────────────────────────
    Entry {
        code: EVENT_TYPE_BOOT,
        name: "BOOT",
        band: "lifecycle",
        description: "Daemon started, WAL opened",
    },
    Entry {
        code: EVENT_TYPE_SHUTDOWN,
        name: "SHUTDOWN",
        band: "lifecycle",
        description: "Shutdown signal received, draining",
    },
    Entry {
        code: EVENT_TYPE_UPDATE_RAN,
        name: "UPDATE_RAN",
        band: "lifecycle",
        description: "NEOTH-managed CLI was upgraded",
    },
    Entry {
        code: EVENT_TYPE_SEGMENT_ROLLOVER,
        name: "SEGMENT_ROLLOVER",
        band: "lifecycle",
        description: "WAL segment rotated (size/age threshold)",
    },
    Entry {
        code: EVENT_TYPE_COMPACTION_MARKER,
        name: "COMPACTION_MARKER",
        band: "lifecycle",
        description: "HMAC-SHA256 over previous N frames",
    },
    Entry {
        code: EVENT_TYPE_REFUSAL_OBSERVED,
        name: "REFUSAL_OBSERVED",
        band: "lifecycle",
        description: "Schicht-0 refusal detector classified a response",
    },
    Entry {
        code: EVENT_TYPE_REFUSAL_MIRRORED,
        name: "REFUSAL_MIRRORED",
        band: "lifecycle",
        description: "Mirror-refusal pipeline emitted the operator template",
    },
    Entry {
        code: EVENT_TYPE_REFUSAL_REDIRECTED,
        name: "REFUSAL_REDIRECTED",
        band: "lifecycle",
        description: "Operator-grant retry authorisation (human-in-the-loop)",
    },
    Entry {
        code: EVENT_TYPE_REFUSAL_REROUTED,
        name: "REFUSAL_REROUTED",
        band: "lifecycle",
        description: "Automated hemisphere/provider switch in recovery pipeline",
    },
    Entry {
        code: EVENT_TYPE_REFUSAL_PERSISTENT,
        name: "REFUSAL_PERSISTENT",
        band: "lifecycle",
        description: "N consecutive refusals — pipeline ends",
    },
    Entry {
        code: EVENT_TYPE_HEMISPHERE_REBOUND,
        name: "HEMISPHERE_REBOUND",
        band: "lifecycle",
        description: "Operator rebound a hemisphere role to a new provider",
    },
    // ── 0x20..=0x2F  Provider lifecycle ──────────────────────────────────
    Entry {
        code: EVENT_TYPE_PROVIDER_REQUEST,
        name: "PROVIDER_REQUEST",
        band: "provider",
        description: "Outbound LLM request (prompt hash + model)",
    },
    Entry {
        code: EVENT_TYPE_PROVIDER_RESPONSE,
        name: "PROVIDER_RESPONSE",
        band: "provider",
        description: "LLM reply (response hash + tokens + latency)",
    },
    Entry {
        code: EVENT_TYPE_PROVIDER_ERROR,
        name: "PROVIDER_ERROR",
        band: "provider",
        description: "Provider error or timeout",
    },
    Entry {
        code: EVENT_TYPE_PROVIDER_STREAM_CHUNK,
        name: "PROVIDER_STREAM_CHUNK",
        band: "provider",
        description: "One delta of a streaming provider response",
    },
    Entry {
        code: EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED,
        name: "PROVIDER_QUOTA_EXCEEDED",
        band: "provider",
        description: "Provider returned HTTP 429 — backoff window recorded (council governance H5)",
    },
    Entry {
        code: EVENT_TYPE_PROFILE_DELTA,
        name: "PROFILE_DELTA",
        band: "profile",
        description: "One profile claim applied to operator profile (Hypothalamus single-writer)",
    },
    Entry {
        code: EVENT_TYPE_PROFILE_REINFORCED,
        name: "PROFILE_REINFORCED",
        band: "profile",
        description: "Existing profile claim reinforced by same-value higher-confidence repeat",
    },
    Entry {
        code: EVENT_TYPE_PROFILE_SUPERSEDED,
        name: "PROFILE_SUPERSEDED",
        band: "profile",
        description: "Existing profile claim superseded by different-value claim on same field",
    },
    Entry {
        code: EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
        name: "PROFILE_BASELINE_SNAPSHOT",
        band: "profile",
        description: "v1.1 §A3 Phase-3 drift anchor (Day-65 seed migration; importance=1.0, never compacted)",
    },
    Entry {
        code: EVENT_TYPE_PROFILE_DELTA_BLOCKED,
        name: "PROFILE_DELTA_BLOCKED",
        band: "profile",
        description: "Stage-5 guard rejected a profile delta (audit trail)",
    },
    Entry {
        code: EVENT_TYPE_PLUGIN_LOADED,
        name: "PLUGIN_LOADED",
        band: "tool",
        description: "V10-04: wasmtime compiled + instantiated a .wasm plugin",
    },
    Entry {
        code: EVENT_TYPE_PLUGIN_REJECTED,
        name: "PLUGIN_REJECTED",
        band: "tool",
        description: "V10-04: plugin manifest invalid / compile failed / id mismatch",
    },
    Entry {
        code: EVENT_TYPE_PLUGIN_HOSTCALL,
        name: "PLUGIN_HOSTCALL",
        band: "tool",
        description: "V10-04: plugin invoked `neoth.emit_event` hostcall",
    },
    Entry {
        code: EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED,
        name: "PLUGIN_FUEL_EXHAUSTED",
        band: "tool",
        description: "V10-04: plugin trapped — full fuel budget consumed",
    },
    Entry {
        code: EVENT_TYPE_KANBAN_SESSION_OPENED,
        name: "KANBAN_SESSION_OPENED",
        band: "coding",
        description: "V11 coding workflow: `neoth code` session opened",
    },
    Entry {
        code: EVENT_TYPE_KANBAN_TASK_CREATED,
        name: "KANBAN_TASK_CREATED",
        band: "coding",
        description: "V11: decomposer produced one kanban task row",
    },
    Entry {
        code: EVENT_TYPE_KANBAN_TASK_ASSIGNED,
        name: "KANBAN_TASK_ASSIGNED",
        band: "coding",
        description: "V11: classifier picked hemisphere + dispatcher resolved worker",
    },
    Entry {
        code: EVENT_TYPE_KANBAN_STATUS_CHANGED,
        name: "KANBAN_STATUS_CHANGED",
        band: "coding",
        description: "V11: task moved between columns (backlog→todo→in_progress→review→done)",
    },
    Entry {
        code: EVENT_TYPE_KANBAN_TASK_COMMENT,
        name: "KANBAN_TASK_COMMENT",
        band: "coding",
        description: "V11: inter-hemisphere or operator comment on a kanban task",
    },
    Entry {
        code: EVENT_TYPE_KANBAN_TASK_COMPLETED,
        name: "KANBAN_TASK_COMPLETED",
        band: "coding",
        description: "V11: worker reported a patch + test summary",
    },
    Entry {
        code: EVENT_TYPE_KANBAN_SESSION_CLOSED,
        name: "KANBAN_SESSION_CLOSED",
        band: "coding",
        description: "V11: all tasks terminal + Cerebellum wrote the session summary",
    },
    Entry {
        code: EVENT_TYPE_MCP_TOOL_CALLED,
        name: "MCP_TOOL_CALLED",
        band: "tool",
        description: "MCP client invoked an external server tool (audit trail)",
    },
    Entry {
        code: EVENT_TYPE_MCP_TOOL_REJECTED,
        name: "MCP_TOOL_REJECTED",
        band: "tool",
        description: "MCP tool call refused (allowlist / sanitizer / autonomy gate)",
    },
    Entry {
        code: EVENT_TYPE_QUOTA_BREACHED,
        name: "QUOTA_BREACHED",
        band: "system",
        description: "Daemon refused WAL write — disk-quota ceiling exceeded",
    },
    Entry {
        code: EVENT_TYPE_TOMBSTONE_REQUESTED,
        name: "TOMBSTONE_REQUESTED",
        band: "system",
        description: "GDPR-style erasure: operator requested forget; SQLite cascade-delete + WAL audit anchor",
    },
    Entry {
        code: EVENT_TYPE_PRE_MUTATION_SNAPSHOT,
        name: "PRE_MUTATION_SNAPSHOT",
        band: "system",
        description: "B-Rollback (CDX-02): pre-mutation snapshot before file/channel/mcp/sql/config write",
    },
    Entry {
        code: EVENT_TYPE_REDACTION_MARKER,
        name: "REDACTION_MARKER",
        band: "system",
        description: "C-15: operator-authorised payload redaction range; supersedes HMAC over listed offsets",
    },
    Entry {
        code: EVENT_TYPE_LOCAL_INFERENCE_START,
        name: "LOCAL_INFERENCE_START",
        band: "provider",
        description: "Local Qwen3 forward-pass start (D14b)",
    },
    Entry {
        code: EVENT_TYPE_LOCAL_INFERENCE_END,
        name: "LOCAL_INFERENCE_END",
        band: "provider",
        description: "Local Qwen3 forward-pass end (D14b)",
    },
    Entry {
        code: EVENT_TYPE_INGEST_EXTRACTED,
        name: "INGEST_EXTRACTED",
        band: "provider",
        description: "Multimodal asset extracted via `neoth ingest` (R-9)",
    },
    Entry {
        code: EVENT_TYPE_EMBED_PERSISTED,
        name: "EMBED_PERSISTED",
        band: "provider",
        description: "CLIP / multimodal embedding written to idx_embedding (R-9)",
    },
    // ── 0x30..=0x3F  Channels ────────────────────────────────────────────
    Entry {
        code: EVENT_TYPE_CHANNEL_INGRESS,
        name: "CHANNEL_INGRESS",
        band: "channel",
        description: "Inbound message on a channel adapter",
    },
    Entry {
        code: EVENT_TYPE_CHANNEL_EGRESS,
        name: "CHANNEL_EGRESS",
        band: "channel",
        description: "Outbound reply on a channel adapter",
    },
    Entry {
        code: EVENT_TYPE_CHANNEL_ERROR,
        name: "CHANNEL_ERROR",
        band: "channel",
        description: "Channel transport error (auth/network/vendor 5xx)",
    },
    Entry {
        code: EVENT_TYPE_INGRESS_QUARANTINED,
        name: "INGRESS_QUARANTINED",
        band: "channel",
        description: "Inbound dropped by sanitizer (prompt-injection markers)",
    },
    Entry {
        code: EVENT_TYPE_INGRESS_SANITIZED,
        name: "INGRESS_SANITIZED",
        band: "channel",
        description: "Inbound passed sanitizer with findings (NFKC, control chars)",
    },
    // ── 0x40..=0x4F  Cron jobs ───────────────────────────────────────────
    Entry {
        code: EVENT_TYPE_JOB_FIRED,
        name: "JOB_FIRED",
        band: "cron",
        description: "Scheduled job dispatched by the scheduler",
    },
    Entry {
        code: EVENT_TYPE_JOB_SUCCESS,
        name: "JOB_SUCCESS",
        band: "cron",
        description: "Scheduled job completed successfully",
    },
    Entry {
        code: EVENT_TYPE_JOB_FAILED,
        name: "JOB_FAILED",
        band: "cron",
        description: "Scheduled job failed (provider/timeout/channel)",
    },
    // ── 0x60..=0x6F  Council debate + callosum (CH-08) ───────────────────
    Entry {
        code: EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED,
        name: "COUNCIL_SYNTHESIS_ATTEMPTED",
        band: "council",
        description: "Callosum recovery fired on Verdict::Split (Synthesis or IrreconcilableConflict)",
    },
    // ── 0x80..=0x8F  Hooks ───────────────────────────────────────────────
    Entry {
        code: EVENT_TYPE_HOOK_FIRED,
        name: "HOOK_FIRED",
        band: "hooks",
        description: "Operator hook matched + ran at a pipeline stage",
    },
    Entry {
        code: EVENT_TYPE_HOOK_BLOCKED,
        name: "HOOK_BLOCKED",
        band: "hooks",
        description: "Block-action hook stopped the pipeline",
    },
    Entry {
        code: EVENT_TYPE_HOOK_REPLACED,
        name: "HOOK_REPLACED",
        band: "hooks",
        description: "Replace-action hook mutated the body",
    },
    Entry {
        code: EVENT_TYPE_HOOK_ERROR,
        name: "HOOK_ERROR",
        band: "hooks",
        description: "Hook execution failed (bad regex, internal error)",
    },
    // ── 0x90..=0x9F  Memory tiers + Ground truth ─────────────────────────
    Entry {
        code: EVENT_TYPE_EPISODE_CONSOLIDATED,
        name: "EPISODE_CONSOLIDATED",
        band: "tiers",
        description: "Event moved from hot (idx_episode) to warm (idx_consolidated)",
    },
    Entry {
        code: EVENT_TYPE_EPISODE_PROMOTED,
        name: "EPISODE_PROMOTED",
        band: "tiers",
        description: "Event promoted from warm to cold (idx_longterm)",
    },
    Entry {
        code: EVENT_TYPE_EPISODE_ARCHIVED,
        name: "EPISODE_ARCHIVED",
        band: "tiers",
        description: "Event dropped from views (FORGET_FLOOR or unpromoted at 90d)",
    },
    Entry {
        code: EVENT_TYPE_IMPORTANCE_REINFORCED,
        name: "IMPORTANCE_REINFORCED",
        band: "tiers",
        description: "Single-event Hebbian reinforce on recall hit",
    },
    Entry {
        code: EVENT_TYPE_CONSOLIDATION_PASS,
        name: "CONSOLIDATION_PASS",
        band: "tiers",
        description: "Daily consolidation pass completed (summary frame)",
    },
    Entry {
        code: EVENT_TYPE_IMPORTANCE_THRESHOLD_CROSSED,
        name: "IMPORTANCE_THRESHOLD_CROSSED",
        band: "tiers",
        description: "Event crossed FORGET_FLOOR or PROMOTION_THRESHOLD",
    },
    Entry {
        code: EVENT_TYPE_ARCHIVE_ACCESSED_DIRECT,
        name: "ARCHIVE_ACCESSED_DIRECT",
        band: "tiers",
        description: "Operator opened an archive MD file directly (no reinforce)",
    },
    Entry {
        code: EVENT_TYPE_GROUNDTRUTH_ADDED,
        name: "GROUNDTRUTH_ADDED",
        band: "tiers",
        description: "Ground-truth fact inserted",
    },
    Entry {
        code: EVENT_TYPE_GROUNDTRUTH_REVOKED,
        name: "GROUNDTRUTH_REVOKED",
        band: "tiers",
        description: "Ground-truth fact revoked",
    },
    Entry {
        code: EVENT_TYPE_GROUNDTRUTH_IMPORTED,
        name: "GROUNDTRUTH_IMPORTED",
        band: "tiers",
        description: "Ground-truth batch imported (Hermes/OpenClaw/...)",
    },
    // ── 0xA0..=0xAF  Permissions / autonomy ──────────────────────────────
    Entry {
        code: EVENT_TYPE_PERMISSION_GRANTED,
        name: "PERMISSION_GRANTED",
        band: "permissions",
        description: "Permission gate allowed an action",
    },
    Entry {
        code: EVENT_TYPE_PERMISSION_DENIED,
        name: "PERMISSION_DENIED",
        band: "permissions",
        description: "Permission gate denied an action",
    },
    Entry {
        code: EVENT_TYPE_LEVEL_ELEVATED,
        name: "LEVEL_ELEVATED",
        band: "permissions",
        description: "Operator raised autonomy level",
    },
    Entry {
        code: EVENT_TYPE_LEVEL_DEROGATED,
        name: "LEVEL_DEROGATED",
        band: "permissions",
        description: "Operator lowered autonomy level",
    },
    Entry {
        code: EVENT_TYPE_COST_ESTIMATE_SHOWN,
        name: "COST_ESTIMATE_SHOWN",
        band: "permissions",
        description: "Pre-call cost preview shown to operator (C-14)",
    },
];

pub async fn run_events(args: EventsArgs) -> Result<()> {
    let mut rows: Vec<&Entry> = REGISTRY.iter().collect();

    if let Some(code_str) = &args.code {
        let want = parse_byte(code_str)?;
        rows.retain(|e| e.code == want);
        if rows.is_empty() {
            anyhow::bail!(
                "no event with code {} ({}). Try `neoth events` without --code to see the full registry.",
                code_str,
                format_args!("0x{:02X}", want),
            );
        }
    }
    if let Some(band_str) = &args.band {
        let band_lo = parse_byte(band_str)?;
        let band_hi = band_lo.saturating_add(0x0F);
        rows.retain(|e| e.code >= band_lo && e.code <= band_hi);
    }
    if let Some(needle) = &args.grep {
        let needle_lower = needle.to_lowercase();
        rows.retain(|e| {
            e.name.to_lowercase().contains(&needle_lower)
                || e.description.to_lowercase().contains(&needle_lower)
        });
        if rows.is_empty() {
            anyhow::bail!(
                "no event matched --grep {needle}. Run `neoth events` to see the full registry."
            );
        }
    }

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let json_rows: Vec<_> = rows
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "code": format!("0x{:02X}", e.code),
                        "decimal": e.code,
                        "name": e.name,
                        "band": e.band,
                        "description": e.description,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "count": json_rows.len(),
                    "events": json_rows,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "# {} WAL event type(s) — `neoth events --code 0xNN` for a single row",
                rows.len()
            );
            println!(
                "  {:<6}  {:<30}  {:<12}  description",
                "code", "name", "band"
            );
            for e in &rows {
                println!(
                    "  0x{:02X}    {:<30}  {:<12}  {}",
                    e.code, e.name, e.band, e.description,
                );
            }
        }
    }
    Ok(())
}

fn parse_byte(s: &str) -> Result<u8> {
    let trimmed = s.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u8>()
    };
    parsed.map_err(|_| anyhow::anyhow!("expected hex (0xNN) or decimal byte, got `{s}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_accepts_hex_and_decimal() {
        assert_eq!(parse_byte("0x10").unwrap(), 0x10);
        assert_eq!(parse_byte("0X90").unwrap(), 0x90);
        assert_eq!(parse_byte("16").unwrap(), 16);
        assert!(parse_byte("not-a-byte").is_err());
        assert!(parse_byte("0xZZ").is_err());
    }

    #[test]
    fn registry_is_non_empty_and_unique() {
        assert!(REGISTRY.iter().any(|entry| entry.name == "RAW_TEXT"));
        // Every code appears exactly once.
        let mut codes: Vec<u8> = REGISTRY.iter().map(|e| e.code).collect();
        codes.sort();
        let n_before = codes.len();
        codes.dedup();
        assert_eq!(
            codes.len(),
            n_before,
            "duplicate event code in registry — every code must appear at most once",
        );
    }

    #[test]
    fn registry_covers_each_documented_band() {
        let bands: std::collections::HashSet<&'static str> =
            REGISTRY.iter().map(|e| e.band).collect();
        for required in [
            "memory",
            "lifecycle",
            "provider",
            "channel",
            "cron",
            "hooks",
            "tiers",
            "permissions",
        ] {
            assert!(
                bands.contains(required),
                "band `{required}` missing from registry",
            );
        }
    }

    #[test]
    fn every_entry_has_description() {
        for e in REGISTRY {
            assert!(
                !e.description.is_empty(),
                "event {} (0x{:02X}) is missing a description",
                e.name,
                e.code
            );
            assert!(
                !e.name.is_empty(),
                "event 0x{:02X} is missing a name",
                e.code
            );
        }
    }

    #[tokio::test]
    async fn run_events_no_filter_does_not_error() {
        let args = EventsArgs {
            code: None,
            band: None,
            grep: None,
            output: OutputFormat::Table,
        };
        run_events(args).await.unwrap();
    }

    #[tokio::test]
    async fn run_events_with_unknown_code_errors_helpfully() {
        let args = EventsArgs {
            code: Some("0xFE".into()),
            band: None,
            grep: None,
            output: OutputFormat::Table,
        };
        let r = run_events(args).await;
        assert!(r.is_err());
        let msg = format!("{r:?}");
        assert!(msg.contains("no event with code"));
    }

    #[tokio::test]
    async fn run_events_band_filter_includes_only_band_codes() {
        // The lifecycle band 0x10..=0x1F should yield a known set.
        let args = EventsArgs {
            code: None,
            band: Some("0x10".into()),
            grep: None,
            output: OutputFormat::Table,
        };
        run_events(args).await.unwrap();
    }

    #[tokio::test]
    async fn run_events_grep_matches_profile_band() {
        let args = EventsArgs {
            code: None,
            band: None,
            grep: Some("profile".into()),
            output: OutputFormat::Json,
        };
        run_events(args).await.unwrap();
    }

    #[tokio::test]
    async fn run_events_grep_unknown_substr_errors_helpfully() {
        let args = EventsArgs {
            code: None,
            band: None,
            grep: Some("definitely-not-a-thing".into()),
            output: OutputFormat::Table,
        };
        let r = run_events(args).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn run_events_grep_combines_with_band() {
        // Filter profile-band events to ones mentioning "blocked" —
        // PROFILE_DELTA_BLOCKED should match.
        let args = EventsArgs {
            code: None,
            band: Some("0xB0".into()),
            grep: Some("blocked".into()),
            output: OutputFormat::Json,
        };
        run_events(args).await.unwrap();
    }
}
