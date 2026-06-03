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

            // P0: every external write goes through the unified gate + audit.
            crate::cli::todo::gate_external_task_write(*yes, "caldav_calendar", "add")?;
            let uid = caldav_calendar::event_uid(&event);
            let outcome = caldav_calendar::create_event_against(
                &cal_url,
                &creds.username,
                creds.password.expose(),
                &event,
            )
            .await?;
            // Audit the write attempt (metadata only — never credentials). Mirror
            // the todo path which audits regardless of Created/AlreadyExists.
            crate::cli::todo::emit_todo_write("caldav_calendar", "add", &uid, Some(summary)).await;

            match outcome {
                CreateOutcome::Created => {
                    render_msg(args.output, &format!("✓ created \"{summary}\" (uid {uid})"))
                }
                CreateOutcome::AlreadyExists => render_msg(
                    args.output,
                    &format!("• already exists: \"{summary}\" (uid {uid})"),
                ),
            }
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

fn render_msg(output: OutputFormat, msg: &str) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::json!({ "message": msg }));
        }
        OutputFormat::Table => println!("{msg}"),
    }
}
