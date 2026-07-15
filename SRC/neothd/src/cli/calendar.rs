//! `neoth calendar` — EM-02b CalDAV calendar (VEVENT) operator surface.
//!
//! `list` issues a WebDAV `REPORT` for VEVENTs (read-only); `add` PUTs a new
//! event. The write is gated + audited through the SAME unified
//! `ExternalTaskWrite` path as `neoth todo` (autonomy/consent pre-flight +
//! fail-closed `0xC8 TODO_WRITE` audit) — a calendar PUT is an external network
//! mutation, so it carries the identical guarantees. Credentials come from the
//! same `caldav_{url,username,password}` the todo CalDAV provider uses.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::email::calendar::CalendarEvent;
use crate::tools::caldav::CreateOutcome;
use crate::tools::caldav_calendar;

#[derive(Args, Debug, Clone)]
pub struct CalendarArgs {
    #[command(subcommand)]
    pub action: CalendarAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CalendarAction {
    /// List VEVENTs in the configured CalDAV calendar collection. Read-only.
    List {
        /// Override the calendar collection URL (else
        /// `credentials.yaml::caldav_url` / `NEOTH_CALDAV_URL`).
        #[arg(long, value_name = "URL")]
        url: Option<String>,
    },
    /// Add (PUT) a new event. Gated + audited (`0xC8`) like every external
    /// write; idempotent by `(summary, start)` so a re-run never duplicates.
    Add {
        /// Event title (SUMMARY).
        summary: String,
        /// RFC-3339 / iCal start, e.g. `2026-05-30T09:00:00Z` or `2026-05-30`
        /// (date-only = all-day).
        #[arg(long)]
        start: String,
        /// RFC-3339 / iCal end. Defaults to `start`.
        #[arg(long)]
        end: Option<String>,
        /// Optional LOCATION.
        #[arg(long)]
        location: Option<String>,
        /// Optional DESCRIPTION.
        #[arg(long)]
        description: Option<String>,
        /// Override the calendar collection URL.
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        /// Skip the interactive confirm (non-interactive write).
        #[arg(long)]
        yes: bool,
    },
}

pub async fn run_calendar(args: CalendarArgs) -> Result<()> {
    let creds = crate::cli::todo::caldav_creds()?;
    match &args.action {
        CalendarAction::List { url } => {
            let cal_url = url.clone().unwrap_or_else(|| creds.url.clone());
            let events = caldav_calendar::list_events_against(
                &cal_url,
                &creds.username,
                creds.password.expose(),
            )
            .await?;
            render_events(&events, args.output);
            Ok(())
        }
        CalendarAction::Add {
            summary,
            start,
            end,
            location,
            description,
            url,
            yes,
        } => {
            let cal_url = url.clone().unwrap_or_else(|| creds.url.clone());
            let event = CalendarEvent {
                calendar_id: crate::email::calendar::PRIMARY_CALENDAR_ID.to_string(),
                event_id: String::new(),
                summary: summary.clone(),
                description: description.clone().unwrap_or_default(),
                location: location.clone().unwrap_or_default(),
                start_rfc3339: start.clone(),
                end_rfc3339: end.clone().unwrap_or_else(|| start.clone()),
                attendees: Vec::new(),
            };

            // EM-02b kill switch: when calendar writes are disabled the surface
            // refuses FAIL-CLOSED + audits the refusal (0xCB) so a disabled
            // surface is never silent. Checked before the autonomy gate.
            let cfg = crate::config::FreedomConfig::load_from_default_path_or_default()?;
            if !cfg.calendar.writes_enabled {
                emit_calendar_write_denied(
                    "caldav_calendar",
                    "add",
                    "calendar.writes_enabled = false",
                )
                .await;
                anyhow::bail!(
                    "calendar writes are disabled — set `calendar.writes_enabled: true` in \
                     freedom.yaml (or flip the `calendar_writes` safe-mode rail) to enable"
                );
            }

            // P0: every external write goes through the unified gate.
            crate::cli::todo::gate_external_task_write(*yes, "caldav_calendar", "add")?;
            let uid = caldav_calendar::event_uid(&event);
            let outcome = match caldav_calendar::create_event_against(
                &cal_url,
                &creds.username,
                creds.password.expose(),
                &event,
            )
            .await
            {
                Ok(o) => o,
                Err(e) => {
                    // COR-20: the write passed the kill switch + autonomy gate
                    // but the CalDAV network PUT failed. Emit CALENDAR_WRITE_FAILED
                    // (0xCE) BEFORE propagating so a network failure leaves a
                    // durable audit anchor instead of vanishing into the error
                    // chain. `{e:#}` is the full chain (URL + HTTP status, never
                    // credentials).
                    emit_calendar_write_failed("caldav_calendar", "add", &uid, &e.to_string())
                        .await;
                    return Err(e);
                }
            };
            // Audit the write (its OWN event 0xCA — calendar is a distinct
            // domain from 0xC8 TODO_WRITE). Metadata only: provider/action/uid +
            // a HASH of the title + start/end. Never the raw summary, never
            // credentials. Mirrors the todo path (audits regardless of outcome).
            emit_calendar_write(
                "caldav_calendar",
                "add",
                &uid,
                summary,
                start,
                &event.end_rfc3339,
            )
            .await;

            render_create_outcome(args.output, outcome, summary, &uid);
            Ok(())
        }
    }
}

fn render_events(events: &[CalendarEvent], output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({ "count": events.len(), "events": events })
            );
        }
        OutputFormat::Table => {
            if events.is_empty() {
                println!("(no events in the calendar collection)");
                return;
            }
            println!("{} event(s):", events.len());
            for e in events {
                let loc = if e.location.is_empty() {
                    String::new()
                } else {
                    format!("  @ {}", e.location)
                };
                println!(
                    "  {} — {} → {}{}",
                    e.summary, e.start_rfc3339, e.end_rfc3339, loc
                );
            }
        }
    }
}

fn render_create_outcome(output: OutputFormat, outcome: CreateOutcome, summary: &str, uid: &str) {
    // A CalDAV UID is a server-side correlation identifier and may encode
    // operator data. Keep it out of terminal transcripts and structured logs;
    // the stable opaque reference is enough to correlate a repeated command.
    let event_ref = calendar_value_hash(uid);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "action": "add",
                "outcome": match outcome {
                    CreateOutcome::Created => "created",
                    CreateOutcome::AlreadyExists => "already_exists",
                },
                "event_ref": event_ref,
            })
        ),
        OutputFormat::Table => match outcome {
            CreateOutcome::Created => println!("✓ created \"{summary}\" (ref {event_ref})"),
            CreateOutcome::AlreadyExists => {
                println!("• already exists: \"{summary}\" (ref {event_ref})");
            }
        },
    }
}

/// Current unix seconds (0 on a pre-epoch clock — only used as an audit ts).
fn now_unix() -> u64 {
    crate::time::now_unix_secs()
}

/// `0xCA CALENDAR_WRITE` audit payload. Metadata only — title and resource UID
/// are HASHED (xxh3-64 hex), never stored verbatim, so an external proof bundle
/// never leaks event text or a server identifier; no credentials.
fn calendar_write_payload(
    provider: &str,
    action: &str,
    uid: &str,
    summary: &str,
    start: &str,
    end: &str,
    now: u64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "provider": provider,
        "action": action,
        "uid_hash": calendar_value_hash(uid),
        "summary_hash": calendar_value_hash(summary),
        "start": start,
        "end": end,
        "ts_unix": now,
    }))
    .unwrap_or_default()
}

fn calendar_value_hash(value: &str) -> String {
    format!("{:016x}", xxhash_rust::xxh3::xxh3_64(value.as_bytes()))
}

/// Emit `0xCA CALENDAR_WRITE` via the shared external-write audit path
/// (daemon-forward-or-one-shot). Metadata only.
async fn emit_calendar_write(
    provider: &str,
    action: &str,
    uid: &str,
    summary: &str,
    start: &str,
    end: &str,
) {
    let payload = calendar_write_payload(provider, action, uid, summary, start, end, now_unix());
    crate::cli::todo::emit_oneshot_audit(
        crate::wal::events::EVENT_TYPE_CALENDAR_WRITE,
        payload,
        "CALENDAR_WRITE",
    )
    .await;
}

/// Emit `0xCB CALENDAR_WRITE_DENIED` — the durable record that a calendar write
/// was refused fail-closed (so a disabled surface is auditable, not silent).
async fn emit_calendar_write_denied(provider: &str, action: &str, reason: &str) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "provider": provider,
        "action": action,
        "reason": reason,
        "ts_unix": now_unix(),
    }))
    .unwrap_or_default();
    crate::cli::todo::emit_oneshot_audit(
        crate::wal::events::EVENT_TYPE_CALENDAR_WRITE_DENIED,
        payload,
        "CALENDAR_WRITE_DENIED",
    )
    .await;
}

/// `0xCE CALENDAR_WRITE_FAILED` audit payload. Metadata only — provider,
/// action, a hashed UID, and the top-level error (`reason`). The caller does not
/// persist the anyhow source chain because reqwest sources can contain the full
/// resource URL. Pure so it is unit-testable without a network.
fn calendar_write_failed_payload(
    provider: &str,
    action: &str,
    uid: &str,
    reason: &str,
    now: u64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "provider": provider,
        "action": action,
        "uid_hash": calendar_value_hash(uid),
        "reason": reason,
        "ts_unix": now,
    }))
    .unwrap_or_default()
}

/// Emit `0xCE CALENDAR_WRITE_FAILED` — a calendar write was attempted (passed
/// the kill switch + autonomy gate) but the CalDAV network PUT failed. COR-20:
/// the Err arm emits this BEFORE the error propagates so a network failure
/// leaves a durable audit anchor. Distinct from 0xCB DENIED (refused before any
/// network).
async fn emit_calendar_write_failed(provider: &str, action: &str, uid: &str, reason: &str) {
    let payload = calendar_write_failed_payload(provider, action, uid, reason, now_unix());
    crate::cli::todo::emit_oneshot_audit(
        crate::wal::events::EVENT_TYPE_CALENDAR_WRITE_FAILED,
        payload,
        "CALENDAR_WRITE_FAILED",
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_write_payload_hashes_title_and_omits_raw_text() {
        let p = calendar_write_payload(
            "caldav_calendar",
            "add",
            "neoth-evt-001",
            "Secret board meeting",
            "2026-05-30T09:00:00Z",
            "2026-05-30T10:00:00Z",
            1_700_000_000,
        );
        let v: serde_json::Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(v["provider"], "caldav_calendar");
        assert_eq!(v["action"], "add");
        assert_eq!(v["uid_hash"], calendar_value_hash("neoth-evt-001"));
        assert_eq!(v["start"], "2026-05-30T09:00:00Z");
        assert_eq!(v["end"], "2026-05-30T10:00:00Z");
        assert_eq!(v["ts_unix"], 1_700_000_000u64);
        // The raw title must NEVER appear; only a stable hash.
        assert!(
            !p.windows(6).any(|w| w == b"Secret"),
            "raw summary text must not be in the audit frame"
        );
        let expected = format!(
            "{:016x}",
            xxhash_rust::xxh3::xxh3_64(b"Secret board meeting")
        );
        assert_eq!(v["summary_hash"], expected);
        assert!(v.get("credentials").is_none());
    }

    #[test]
    fn calendar_write_payload_hash_is_deterministic() {
        let a = calendar_write_payload("p", "add", "u", "Lunch", "s", "e", 1);
        let b = calendar_write_payload("p", "add", "u", "Lunch", "s", "e", 1);
        assert_eq!(a, b);
    }

    #[test]
    fn calendar_write_failed_payload_captures_reason_without_credentials() {
        // COR-20: a network failure leaves a durable 0xCE audit anchor with the
        // provider/action/uid + the error reason — but never the credentials.
        let p = calendar_write_failed_payload(
            "caldav_calendar",
            "add",
            "neoth-evt-002",
            "connect to https://dav.example.com: connection refused",
            1_700_000_000,
        );
        let v: serde_json::Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(v["provider"], "caldav_calendar");
        assert_eq!(v["action"], "add");
        assert_eq!(v["uid_hash"], calendar_value_hash("neoth-evt-002"));
        assert_eq!(v["ts_unix"], 1_700_000_000u64);
        assert!(
            v["reason"]
                .as_str()
                .is_some_and(|r| r.contains("connection refused")),
            "the failure reason must be recorded for the audit trail"
        );
        // The frame distinguishes a network failure from a policy denial.
        assert!(v.get("summary_hash").is_none());
    }
}
