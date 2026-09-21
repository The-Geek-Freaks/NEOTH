//! `neoth feedback` — aggregate operator feedback and record bounded
//! terminal-issued response signals.
//!
//! `summary` remains the read-only G-03 operator-feedback view. `response`
//! accepts only an opaque terminal receipt, its exact terminal-session
//! equality binding, a compare-and-swap revision, and a fixed signal.

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::feedback::consume::{FeedbackPressure, aggregate_recent_feedback};
use crate::feedback::response::{
    ResponseFeedbackOperation, ResponseFeedbackOutcome, ResponseFeedbackRejection, ResponseId,
    ResponseSignal, apply_response_feedback, read_response_feedback_status,
};

#[derive(Args, Debug, Clone)]
pub struct FeedbackArgs {
    #[command(subcommand)]
    pub action: FeedbackAction,
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum FeedbackAction {
    /// Aggregate recent operator-correction (`0xBB`) signals into a report.
    Summary {
        /// Look-back window, e.g. `7d`, `48h`, `3600` (bare seconds). Default 7d.
        #[arg(long, default_value = "7d")]
        window: String,
    },
    /// Apply or remove one fixed signal for a terminal-issued response.
    Response {
        #[command(subcommand)]
        action: ResponseFeedbackAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ResponseFeedbackAction {
    /// Read the current revision and active fixed signal for an exact receipt.
    Status {
        /// Opaque response id emitted with the completed chat terminal.
        #[arg(long)]
        response: String,
        /// Exact terminal session printed with that response id.
        #[arg(long)]
        session: String,
    },
    /// Set a fixed feedback signal for an exact terminal receipt.
    Set {
        /// Opaque response id emitted with the completed chat terminal.
        #[arg(long)]
        response: String,
        /// Exact terminal session printed with that response id.
        #[arg(long)]
        session: String,
        /// Expected response revision for the required compare-and-swap.
        #[arg(long)]
        revision: u64,
        /// Fixed response signal; freeform notes are intentionally unsupported.
        #[arg(long, value_enum)]
        signal: ResponseFeedbackSignal,
    },
    /// Remove the currently active signal for an exact terminal receipt.
    Remove {
        /// Opaque response id emitted with the completed chat terminal.
        #[arg(long)]
        response: String,
        /// Exact terminal session printed with that response id.
        #[arg(long)]
        session: String,
        /// Expected response revision for the required compare-and-swap.
        #[arg(long)]
        revision: u64,
    },
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseFeedbackSignal {
    NeedsCorrection,
    NotHelpful,
}

impl From<ResponseFeedbackSignal> for ResponseSignal {
    fn from(signal: ResponseFeedbackSignal) -> Self {
        match signal {
            ResponseFeedbackSignal::NeedsCorrection => Self::NeedsCorrection,
            ResponseFeedbackSignal::NotHelpful => Self::NotHelpful,
        }
    }
}

pub async fn run_feedback(args: FeedbackArgs) -> Result<()> {
    match args.action {
        FeedbackAction::Summary { window } => run_summary(&window, &args.output).await,
        FeedbackAction::Response { action } => run_response(action, &args.output),
    }
}

fn run_response(action: ResponseFeedbackAction, output: &OutputFormat) -> Result<()> {
    let action = match action {
        ResponseFeedbackAction::Status { response, session } => {
            return run_response_status(&response, &session, output);
        }
        action => action,
    };
    let (response, session, revision, operation) = match action {
        ResponseFeedbackAction::Set {
            response,
            session,
            revision,
            signal,
        } => (
            response,
            session,
            revision,
            ResponseFeedbackOperation::Set(signal.into()),
        ),
        ResponseFeedbackAction::Remove {
            response,
            session,
            revision,
        } => (
            response,
            session,
            revision,
            ResponseFeedbackOperation::Remove,
        ),
        ResponseFeedbackAction::Status { .. } => {
            unreachable!("status returns before mutation dispatch")
        }
    };

    // Parse before opening the private projection. The session flag is an
    // equality binding to the issued terminal receipt, not authentication.
    let outcome = match ResponseId::parse(&response) {
        Ok(response_id) => apply_response_feedback(
            &FreedomConfig::default_neoth_home(),
            &response_id,
            &session,
            revision,
            operation,
            crate::time::now_unix_i64(),
        )
        .unwrap_or_else(ResponseFeedbackOutcome::Rejected),
        Err(rejection) => ResponseFeedbackOutcome::Rejected(rejection),
    };
    render_response_outcome(&response, &session, outcome, output)
}

fn run_response_status(response: &str, session: &str, output: &OutputFormat) -> Result<()> {
    let body = match ResponseId::parse(response) {
        Ok(response_id) => match read_response_feedback_status(
            &FreedomConfig::default_neoth_home(),
            &response_id,
            session,
        ) {
            Ok(status) => response_status_ready_body(&status),
            Err(rejection) => response_status_rejected_body(response, session, rejection),
        },
        Err(rejection) => response_status_rejected_body(response, session, rejection),
    };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&body)?)
        }
        OutputFormat::Table => {
            println!("# Response feedback status");
            println!(
                "  status      : {}",
                body["status"].as_str().unwrap_or("rejected")
            );
            println!("  response    : {response}");
            println!("  session     : {session}");
            if let Some(revision) = body["current_revision"].as_u64() {
                println!("  revision    : {revision}");
            }
            if let Some(signal) = body["active_signal"].as_str() {
                println!("  active      : {signal}");
            }
            if let Some(rejection) = body["rejection"].as_str() {
                println!("  rejection   : {rejection}");
            }
        }
    }
    Ok(())
}

fn response_status_rejected_body(
    response: &str,
    session: &str,
    rejection: ResponseFeedbackRejection,
) -> serde_json::Value {
    serde_json::json!({
        "status": "rejected",
        "response_id": response,
        "session_id": session,
        "current_revision": serde_json::Value::Null,
        "active_signal": serde_json::Value::Null,
        "rejection": response_rejection_name(rejection),
    })
}

fn response_status_ready_body(
    status: &crate::feedback::response::ResponseTargetStatus,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ready",
        "response_id": status.response_id.as_str(),
        "session_id": status.session_id.as_str(),
        "current_revision": status.revision,
        "active_signal": status.active_signal.map(response_signal_name),
        "rejection": serde_json::Value::Null,
    })
}

fn response_signal_name(signal: ResponseSignal) -> &'static str {
    match signal {
        ResponseSignal::NeedsCorrection => "needs_correction",
        ResponseSignal::NotHelpful => "not_helpful",
    }
}

fn response_rejection_name(rejection: ResponseFeedbackRejection) -> &'static str {
    match rejection {
        ResponseFeedbackRejection::Malformed => "malformed",
        ResponseFeedbackRejection::Missing => "missing",
        ResponseFeedbackRejection::Foreign => "foreign",
        ResponseFeedbackRejection::Stale => "stale",
        ResponseFeedbackRejection::Unavailable => "unavailable",
    }
}

fn response_outcome_body(
    response: &str,
    session: &str,
    outcome: ResponseFeedbackOutcome,
) -> serde_json::Value {
    let (status, revision, signal, previous_signal, rejection) = match outcome {
        ResponseFeedbackOutcome::Set { signal, revision } => (
            "set",
            Some(revision),
            Some(response_signal_name(signal)),
            None,
            None,
        ),
        ResponseFeedbackOutcome::Replaced {
            previous,
            signal,
            revision,
        } => (
            "replaced",
            Some(revision),
            Some(response_signal_name(signal)),
            Some(response_signal_name(previous)),
            None,
        ),
        ResponseFeedbackOutcome::Removed { revision } => {
            ("removed", Some(revision), None, None, None)
        }
        ResponseFeedbackOutcome::Unchanged { revision } => {
            ("unchanged", Some(revision), None, None, None)
        }
        ResponseFeedbackOutcome::Rejected(rejection) => (
            "rejected",
            None,
            None,
            None,
            Some(response_rejection_name(rejection)),
        ),
    };
    serde_json::json!({
        "status": status,
        "response_id": response,
        "session_id": session,
        "revision": revision,
        "signal": signal,
        "previous_signal": previous_signal,
        "rejection": rejection,
    })
}

fn render_response_outcome(
    response: &str,
    session: &str,
    outcome: ResponseFeedbackOutcome,
    output: &OutputFormat,
) -> Result<()> {
    let body = response_outcome_body(response, session, outcome);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&body)?)
        }
        OutputFormat::Table => {
            println!("# Response feedback");
            println!(
                "  status      : {}",
                body["status"].as_str().unwrap_or("rejected")
            );
            println!("  response    : {response}");
            println!("  session     : {session}");
            if let Some(revision) = body["revision"].as_u64() {
                println!("  revision    : {revision}");
            }
            if let Some(signal) = body["signal"].as_str() {
                println!("  signal      : {signal}");
            }
            if let Some(previous) = body["previous_signal"].as_str() {
                println!("  previous    : {previous}");
            }
            if let Some(rejection) = body["rejection"].as_str() {
                println!("  rejection   : {rejection}");
            }
        }
    }
    Ok(())
}

async fn run_summary(window: &str, output: &OutputFormat) -> Result<()> {
    let window_secs = crate::cli::privacy::parse_duration(window)
        .map(|secs| secs as i64)
        .unwrap_or(7 * 24 * 3600);
    let home = FreedomConfig::default_neoth_home();
    let wal_dir = home.join("wal");
    let now = crate::time::now_unix_i64();
    let summary = aggregate_recent_feedback(&wal_dir, window_secs, now);
    let pressure = summary.pressure();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "window_secs": summary.window_secs,
                "corrections": summary.corrections,
                "pressure": pressure.as_str(),
                "top_patterns": summary.top_patterns.iter().map(|(label, count)| {
                    serde_json::json!({ "pattern": label, "count": count })
                }).collect::<Vec<_>>(),
                "latest_unix": summary.latest_unix,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Operator feedback (last {window})");
            println!("  corrections : {}", summary.corrections);
            println!("  pressure    : {}", pressure.as_str());
            if summary.top_patterns.is_empty() {
                println!("  patterns    : (none)");
            } else {
                println!("  top patterns:");
                for (label, count) in &summary.top_patterns {
                    println!("    {count:>4}  {label}");
                }
            }
            println!();
            match pressure {
                FeedbackPressure::Low => {
                    println!("  NEOTH is tracking your corrections well — nothing to act on.")
                }
                FeedbackPressure::Elevated => println!(
                    "  A noticeable run of corrections. Review the patterns above; the \\
                     profile-adapt cron will propose an adjustment if it persists."
                ),
                FeedbackPressure::High => println!(
                    "  Sustained pushback — the profile-adapt cron queues a self-dev \\
                     proposal. Review it with `neoth self-dev review`."
                ),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommand,
    }

    #[derive(Subcommand)]
    enum TestCommand {
        Feedback(FeedbackArgs),
    }

    #[test]
    fn response_set_requires_explicit_terminal_receipt_and_revision() {
        let parsed = TestCli::try_parse_from([
            "neoth",
            "feedback",
            "response",
            "set",
            "--response",
            "0123456789abcdef0123456789abcdef",
            "--session",
            "terminal",
            "--revision",
            "7",
            "--signal",
            "needs-correction",
        ])
        .expect("feedback command parses");
        assert!(matches!(
            parsed.command,
            TestCommand::Feedback(FeedbackArgs {
                action: FeedbackAction::Response {
                    action: ResponseFeedbackAction::Set {
                        revision: 7,
                        signal: ResponseFeedbackSignal::NeedsCorrection,
                        ..
                    }
                },
                ..
            })
        ));
        assert!(
            TestCli::try_parse_from([
                "neoth",
                "feedback",
                "response",
                "set",
                "--session",
                "terminal",
                "--revision",
                "0",
                "--signal",
                "not-helpful",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "neoth",
                "feedback",
                "response",
                "set",
                "--response",
                "0123456789abcdef0123456789abcdef",
                "--revision",
                "0",
                "--signal",
                "not-helpful",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "neoth",
                "feedback",
                "response",
                "set",
                "--response",
                "0123456789abcdef0123456789abcdef",
                "--session",
                "terminal",
                "--signal",
                "not-helpful",
            ])
            .is_err()
        );
    }

    #[test]
    fn response_command_accepts_only_fixed_signal_and_no_freeform_or_implicit_session() {
        assert!(
            TestCli::try_parse_from([
                "neoth",
                "feedback",
                "response",
                "set",
                "--response",
                "0123456789abcdef0123456789abcdef",
                "--session",
                "terminal",
                "--revision",
                "0",
                "--signal",
                "freeform",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "neoth",
                "feedback",
                "response",
                "set",
                "--response",
                "0123456789abcdef0123456789abcdef",
                "--session",
                "terminal",
                "--revision",
                "0",
                "--signal",
                "not-helpful",
                "--text",
                "explain",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "neoth",
                "feedback",
                "response",
                "remove",
                "--response",
                "0123456789abcdef0123456789abcdef",
                "--revision",
                "0",
            ])
            .is_err()
        );
    }

    #[test]
    fn response_status_requires_the_same_explicit_terminal_pair() {
        let parsed = TestCli::try_parse_from([
            "neoth",
            "feedback",
            "response",
            "status",
            "--response",
            "0123456789abcdef0123456789abcdef",
            "--session",
            "terminal",
        ])
        .expect("status command parses");
        assert!(matches!(
            parsed.command,
            TestCommand::Feedback(FeedbackArgs {
                action: FeedbackAction::Response {
                    action: ResponseFeedbackAction::Status { .. }
                },
                ..
            })
        ));
        assert!(
            TestCli::try_parse_from([
                "neoth",
                "feedback",
                "response",
                "status",
                "--response",
                "0123456789abcdef0123456789abcdef",
            ])
            .is_err()
        );

        let ready = response_status_ready_body(&crate::feedback::response::ResponseTargetStatus {
            response_id: ResponseId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            session_id: "terminal".into(),
            revision: 4,
            active_signal: Some(ResponseSignal::NotHelpful),
        });
        let rejected = response_status_rejected_body(
            "0123456789abcdef0123456789abcdef",
            "terminal",
            ResponseFeedbackRejection::Unavailable,
        );
        assert_eq!(ready["current_revision"].as_u64(), Some(4));
        assert_eq!(ready["active_signal"], "not_helpful");
        assert_eq!(rejected["status"], "rejected");
        assert!(rejected["current_revision"].is_null());
        assert!(rejected["active_signal"].is_null());
        assert_eq!(rejected["rejection"], "unavailable");
    }

    #[test]
    fn response_outcome_rendering_covers_successes_and_typed_rejections() {
        let response = "0123456789abcdef0123456789abcdef";
        let session = "terminal";
        let cases = [
            (
                ResponseFeedbackOutcome::Set {
                    signal: ResponseSignal::NeedsCorrection,
                    revision: 1,
                },
                "set",
                Some(1),
                Some("needs_correction"),
                None,
                None,
            ),
            (
                ResponseFeedbackOutcome::Replaced {
                    previous: ResponseSignal::NeedsCorrection,
                    signal: ResponseSignal::NotHelpful,
                    revision: 2,
                },
                "replaced",
                Some(2),
                Some("not_helpful"),
                Some("needs_correction"),
                None,
            ),
            (
                ResponseFeedbackOutcome::Removed { revision: 3 },
                "removed",
                Some(3),
                None,
                None,
                None,
            ),
            (
                ResponseFeedbackOutcome::Unchanged { revision: 3 },
                "unchanged",
                Some(3),
                None,
                None,
                None,
            ),
            (
                ResponseFeedbackOutcome::Rejected(ResponseFeedbackRejection::Stale),
                "rejected",
                None,
                None,
                None,
                Some("stale"),
            ),
        ];
        for (outcome, status, revision, signal, previous, rejection) in cases {
            let body = response_outcome_body(response, session, outcome);
            assert_eq!(body["status"], status);
            assert_eq!(body["revision"].as_u64(), revision);
            assert_eq!(body["signal"].as_str(), signal);
            assert_eq!(body["previous_signal"].as_str(), previous);
            assert_eq!(body["rejection"].as_str(), rejection);
        }
        for rejection in [
            ResponseFeedbackRejection::Malformed,
            ResponseFeedbackRejection::Missing,
            ResponseFeedbackRejection::Foreign,
            ResponseFeedbackRejection::Stale,
            ResponseFeedbackRejection::Unavailable,
        ] {
            assert_eq!(
                response_outcome_body(
                    response,
                    session,
                    ResponseFeedbackOutcome::Rejected(rejection)
                )["status"],
                "rejected"
            );
        }
    }
}
