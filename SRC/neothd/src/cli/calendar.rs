//! `neoth calendar` — EM-02b CalDAV calendar (VEVENT) operator surface.
//!
//! `list` issues a WebDAV `REPORT` for VEVENTs (read-only); `add` PUTs a new
//! event. The write is gated + audited through the SAME unified
//! `ExternalTaskWrite` path as `neoth todo` (required canonical Gate decision
//! before the PUT, plus outcome evidence) — a calendar PUT is an external network
//! mutation, so it carries the identical guarantees. Credentials come from the
//! same `caldav_{url,username,password}` the todo CalDAV provider uses.

use anyhow::{Context, Result};
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
    /// Add (PUT) a new event. Gated and decision-audited like every external
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

            let binding = calendar_write_permission_binding(&cal_url, &creds.username, &event)?;
            crate::cli::todo::execute_external_task_write(
                *yes,
                "caldav_calendar",
                "add",
                &binding,
                || async {
                    let uid = caldav_calendar::event_uid(&event);
                    let outcome = match caldav_calendar::create_event_against(
                        &cal_url,
                        &creds.username,
                        creds.password.expose(),
                        &event,
                    )
                    .await
                    {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            emit_calendar_write_failed(
                                "caldav_calendar",
                                "add",
                                &uid,
                                &error.to_string(),
                            )
                            .await;
                            return Err(error);
                        }
                    };
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
                },
            )
            .await
        }
    }
}

/// Bind the exact CalDAV collection and VEVENT body before the mandatory Gate
/// decision. The URL and event remain private input to the digest helper; the
/// resulting TrustEvent carries only the opaque binding.
fn calendar_write_permission_binding(
    cal_url: &str,
    account_selector: &str,
    event: &CalendarEvent,
) -> Result<String> {
    let private_request = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "collection_url": cal_url,
        "account_selector": account_selector,
        "event": event,
    }))
    .context("serialize canonical calendar event permission binding")?;
    crate::cli::todo::external_task_request_binding("caldav_calendar", "add", private_request)
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
    use std::sync::atomic::{AtomicBool, Ordering};

    fn full_calendar_policy() -> crate::permissions::AutonomyPolicySnapshot {
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.autonomy = crate::permissions::AutonomyLevel::Full;
        cfg.autonomy_policy()
    }

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

    #[tokio::test]
    async fn calendar_admission_has_authenticated_ledger_before_injected_put() {
        let home = tempfile::tempdir().unwrap();
        let event = CalendarEvent {
            calendar_id: "primary".to_owned(),
            event_id: String::new(),
            summary: "private planning".to_owned(),
            description: "private detail".to_owned(),
            location: "private location".to_owned(),
            start_rfc3339: "2026-09-07T10:00:00Z".to_owned(),
            end_rfc3339: "2026-09-07T11:00:00Z".to_owned(),
            attendees: Vec::new(),
        };
        let binding = calendar_write_permission_binding(
            "https://dav.example/tasks",
            "operator@example.test",
            &event,
        )
        .unwrap();
        let put_called = AtomicBool::new(false);
        crate::cli::todo::execute_external_task_write_at(
            home.path(),
            full_calendar_policy(),
            true,
            "caldav_calendar",
            "add",
            &binding,
            || async {
                let ledger = crate::permissions::trust_ledger::TrustLedger::replay_subject_at_home(
                    home.path(),
                    crate::permissions::trust_ledger::LOCAL_SUBJECT,
                )
                .unwrap();
                assert_eq!(ledger.entries.len(), 1);
                put_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(put_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn calendar_dead_required_sink_cannot_reach_injected_put() {
        let binding = crate::cli::todo::external_task_request_binding(
            "caldav_calendar",
            "add",
            b"serialized private event",
        )
        .unwrap();
        let put_called = AtomicBool::new(false);
        let admission = crate::cli::todo::execute_external_task_write_with_sink(
            full_calendar_policy(),
            true,
            "caldav_calendar",
            "add",
            &binding,
            crate::permissions::PermissionAuditSink::Fail("dead test audit sink"),
            || async {
                put_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(admission.is_err());
        assert!(!put_called.load(Ordering::SeqCst));
    }

    #[test]
    fn calendar_permission_binding_is_collection_url_sensitive() {
        let event = CalendarEvent {
            calendar_id: "primary".to_owned(),
            event_id: String::new(),
            summary: "private planning".to_owned(),
            description: String::new(),
            location: String::new(),
            start_rfc3339: "2026-09-07T10:00:00Z".to_owned(),
            end_rfc3339: "2026-09-07T11:00:00Z".to_owned(),
            attendees: Vec::new(),
        };
        let first = calendar_write_permission_binding(
            "https://dav.example/a",
            "operator@example.test",
            &event,
        )
        .unwrap();
        let second = calendar_write_permission_binding(
            "https://dav.example/b",
            "operator@example.test",
            &event,
        )
        .unwrap();
        let different_account = calendar_write_permission_binding(
            "https://dav.example/a",
            "other@example.test",
            &event,
        )
        .unwrap();
        assert_ne!(
            first, second,
            "the allowed decision must bind the collection URL"
        );
        assert_ne!(
            first, different_account,
            "the allowed decision must bind the authenticated calendar account"
        );
    }
}
