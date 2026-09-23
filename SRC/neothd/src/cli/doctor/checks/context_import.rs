//! Context Import Doctor diagnostic (GOLD-CC-03 / GOLD-W257).
//!
//! This check deliberately obtains its view only from the authenticated live
//! connector-control status endpoint. It never reads configuration as proof of
//! readiness and it never plans, imports, repairs, or changes daemon state.

use std::path::Path;

use serde::Deserialize;

use super::super::{CheckDoc, CheckOutcome, CheckStatus};

const NAME: &str = "context import control-plane";
const LOCAL_IMPORT: &str = "local_import";

pub(crate) const DOCS: &[CheckDoc] = &[CheckDoc {
    name: NAME,
    purpose: "Reads the authenticated daemon-owned Context Import account status. A PASS means the live control plane reports exactly one active Local Import account with valid revisions; it does not mean an import has run or succeeded.",
    common_failures: "The daemon endpoint may be unavailable, the account may be paused or revoked, or the returned status may be missing, duplicated, malformed, or have invalid revisions. The status contract has no freshness timestamp, so Doctor cannot make a temporal-staleness claim from this response.",
    fix: "Start the owning daemon and inspect `neoth context import status`. Resume a deliberately paused account with the approved lifecycle command. Correct invalid control-plane state through its owning workflow; Doctor only observes it.",
}];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsStatus {
    accounts: Vec<AccountStatus>,
}

/// Exact success/error envelope emitted by connector-control `write_response`.
/// We parse the writer boundary before accepting the nested account payload.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusEnvelope {
    ok: bool,
    #[serde(default)]
    data: Option<AccountsStatus>,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountStatus {
    connector: String,
    lifecycle: String,
    policy_revision: u64,
    lifecycle_revision: u64,
}

/// Obtain the current daemon-owned status through the existing authenticated
/// Context client. Discovery, transport, and daemon errors mean the status is
/// unavailable; configuration presence is intentionally not consulted.
pub(crate) async fn check_context_import_control_plane(home: &Path) -> CheckOutcome {
    let args = crate::cli::context::ContextArgs {
        action: crate::cli::context::ContextAction::Import {
            action: crate::cli::context::ContextImportAction::Status,
        },
        output: crate::cli::OutputFormat::Table,
    };
    match crate::cli::context::request_at(home, &args).await {
        Ok(response) => classify_status_response(&response),
        Err(_) => CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail:
                "live daemon control-plane status unavailable; Context Import readiness is unknown"
                    .to_string(),
        },
    }
}

/// Strictly classify the content-free authenticated status contract. This is
/// pure so malformed and lifecycle cases stay testable without a daemon.
fn classify_status_response(response: &str) -> CheckOutcome {
    let envelope = match serde_json::from_str::<StatusEnvelope>(response) {
        Ok(envelope) => envelope,
        Err(_) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: "live daemon control-plane returned malformed Context Import status"
                    .to_string(),
            };
        }
    };
    if !envelope.ok {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail: "live daemon control-plane rejected the Context Import status request"
                .to_string(),
        };
    }
    let status = match (envelope.data, envelope.code) {
        (Some(status), None) => status,
        _ => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: "live daemon control-plane returned malformed Context Import status"
                    .to_string(),
            };
        }
    };

    let mut local_accounts = status
        .accounts
        .into_iter()
        .filter(|account| account.connector == LOCAL_IMPORT);
    let Some(account) = local_accounts.next() else {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: "live daemon control-plane reports no Local Import account; Context Import is unavailable"
                .to_string(),
        };
    };
    if local_accounts.next().is_some() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail: "live daemon control-plane reported duplicate Local Import accounts; status is invalid"
                .to_string(),
        };
    }
    if account.policy_revision == 0 || account.lifecycle_revision == 0 {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail:
                "live daemon control-plane reported zero Context Import revision; status is invalid"
                    .to_string(),
        };
    }

    match account.lifecycle.as_str() {
        "active" => CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: format!(
                "live daemon control-plane status available: Local Import lifecycle=active policy_revision={} lifecycle_revision={}",
                account.policy_revision, account.lifecycle_revision
            ),
        },
        "paused" => CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: format!(
                "live daemon control-plane status available: Local Import lifecycle=paused policy_revision={} lifecycle_revision={}; Context Import is paused",
                account.policy_revision, account.lifecycle_revision
            ),
        },
        "revoked" => CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: format!(
                "live daemon control-plane status available: Local Import lifecycle=revoked policy_revision={} lifecycle_revision={}; Context Import is revoked and unavailable",
                account.policy_revision, account.lifecycle_revision
            ),
        },
        _ => CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail: "live daemon control-plane returned an invalid Context Import lifecycle"
                .to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_success_envelope_with_active_status_passes_without_claiming_an_import_succeeded() {
        // Exact `write_response(Some(data))` wire shape: the account view is
        // nested under a successful connector-control response envelope.
        let outcome = classify_status_response(
            r#"{"ok":true,"data":{"accounts":[{"connector":"local_import","lifecycle":"active","policy_revision":7,"lifecycle_revision":11}]}}"#,
        );
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("status available"));
        assert!(!outcome.detail.contains("Ready"));
    }

    #[test]
    fn paused_and_revoked_live_statuses_are_explicitly_unavailable() {
        for lifecycle in ["paused", "revoked"] {
            let response = format!(
                r#"{{"ok":true,"data":{{"accounts":[{{"connector":"local_import","lifecycle":"{lifecycle}","policy_revision":7,"lifecycle_revision":11}}]}}}}"#
            );
            let outcome = classify_status_response(&response);
            assert_eq!(
                outcome.status,
                CheckStatus::Warn,
                "{lifecycle}: {outcome:?}"
            );
            assert!(outcome.detail.contains(lifecycle));
            assert!(outcome.detail.contains("unavailable") || outcome.detail.contains("paused"));
        }
    }

    #[test]
    fn missing_duplicate_malformed_and_zero_revision_statuses_never_pass() {
        for response in [
            r#"{"ok":true,"data":{"accounts":[]}}"#,
            r#"{"ok":true,"data":{"accounts":[{"connector":"local_import","lifecycle":"active","policy_revision":7,"lifecycle_revision":11},{"connector":"local_import","lifecycle":"active","policy_revision":7,"lifecycle_revision":12}]}}"#,
            r#"{"ok":true,"data":{"accounts":[{"connector":"local_import","lifecycle":"active","policy_revision":0,"lifecycle_revision":11}]}}"#,
            r#"{"ok":true,"data":{"accounts":[{"connector":"local_import","lifecycle":"active","policy_revision":7}]}}"#,
            r#"{"ok":false,"code":"authority_unavailable"}"#,
            "not json",
        ] {
            assert_ne!(classify_status_response(response).status, CheckStatus::Pass);
        }
    }

    #[test]
    fn error_envelope_and_unknown_lifecycle_fail_without_echoing_untrusted_text() {
        let rejected =
            classify_status_response(r#"{"ok":false,"code":"operator-controlled-error-text"}"#);
        assert_eq!(rejected.status, CheckStatus::Fail);
        assert!(!rejected.detail.contains("operator-controlled-error-text"));

        let outcome = classify_status_response(
            r#"{"ok":true,"data":{"accounts":[{"connector":"local_import","lifecycle":"stale","policy_revision":7,"lifecycle_revision":11}]}}"#,
        );
        assert_eq!(outcome.status, CheckStatus::Fail);
        assert!(outcome.detail.contains("invalid"));
        assert!(!outcome.detail.contains("stale"));
    }
}
