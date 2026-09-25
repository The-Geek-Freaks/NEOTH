//! Read-only authenticated typed permission-decision export for n8n.
//!
//! This projects the existing typed TrustLedger for one exact subject. It never
//! creates WAL/configuration state and exposes the ledger's authenticated-prefix
//! completeness rather than treating a live unsealed tail as an empty audit.

use serde::{Deserialize, Serialize};

use super::{ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome, parse_body};
use crate::permissions::trust_ledger::{TrustLedger, TrustLedgerCompleteness};

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 100;
const MAX_MATCHING_ENTRIES: usize = 256;
const MAX_DIRECTORY_ENTRIES: usize = 256;
const MAX_SEGMENTS: usize = 64;
const MAX_SEGMENT_PHYSICAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_PHYSICAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SEGMENT_LOGICAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_LOGICAL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionAuditRequest {
    pub subject: String,
    #[serde(default)]
    pub limit: Option<usize>,
    /// Inclusive lower bound over returned TrustEvent `decided_at_ns`, not WAL HLC.
    #[serde(default)]
    pub from_ns: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PermissionAuditEntry {
    pub event_id: u64,
    pub decided_at_ns: u64,
    pub action: String,
    pub outcome: String,
    pub autonomy_level: String,
    pub has_lease: bool,
    pub has_confirmation: bool,
}

#[derive(Debug, Serialize)]
pub struct PermissionAuditResponse {
    pub subject: String,
    /// This endpoint projects only authenticated typed TrustDecision evidence.
    /// It is not a reconstruction of legacy free-form permission/consent WAL
    /// frames, whose payloads intentionally remain outside this n8n surface.
    pub coverage: &'static str,
    pub decisions: Vec<PermissionAuditEntry>,
    pub total: usize,
    pub completeness: TrustLedgerCompleteness,
}

fn limit(request: &PermissionAuditRequest) -> usize {
    request.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

/// This online projection intentionally has tighter limits than a daemon-wide
/// recovery replay. Any scanner or matching-entry ceiling is a failed request,
/// never a partial `complete` history claim.
fn online_scan_limits() -> crate::wal::scan::HomeWalScanLimits {
    crate::wal::scan::HomeWalScanLimits {
        max_directory_entries: MAX_DIRECTORY_ENTRIES,
        max_segments: MAX_SEGMENTS,
        max_segment_physical_bytes: MAX_SEGMENT_PHYSICAL_BYTES,
        max_total_physical_bytes: MAX_TOTAL_PHYSICAL_BYTES,
        max_segment_logical_bytes: MAX_SEGMENT_LOGICAL_BYTES,
        max_total_logical_bytes: MAX_TOTAL_LOGICAL_BYTES,
    }
}

fn read_at(
    home: &std::path::Path,
    request: &PermissionAuditRequest,
) -> Result<PermissionAuditResponse, HandlerOutcome> {
    let ledger = TrustLedger::replay_subject_at_home_with_limits(
        home,
        &request.subject,
        online_scan_limits(),
        MAX_MATCHING_ENTRIES,
    )
    .map_err(|_| {
        HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            "permission audit replay failed",
            "inspect the authenticated primary WAL; malformed evidence or an online audit ceiling is not skipped",
        )
    })?;
    let from_ns = request.from_ns.unwrap_or(0);
    let filtered: Vec<_> = ledger
        .entries
        .into_iter()
        .filter(|entry| entry.event.decided_at_ns >= from_ns)
        .collect();
    let total = filtered.len();
    let decisions = filtered
        .into_iter()
        .take(limit(request))
        .map(|entry| PermissionAuditEntry {
            event_id: entry.event_id,
            decided_at_ns: entry.event.decided_at_ns,
            action: entry.event.action.as_str().to_owned(),
            outcome: match entry.event.outcome {
                crate::permissions::trust_ledger::TrustOutcome::Allowed => "allowed",
                crate::permissions::trust_ledger::TrustOutcome::Denied => "denied",
            }
            .to_owned(),
            autonomy_level: entry.event.autonomy_level.as_str().to_owned(),
            has_lease: entry.event.lease_id.is_some(),
            has_confirmation: entry.event.confirmation_source.is_some(),
        })
        .collect();
    Ok(PermissionAuditResponse {
        subject: ledger.subject,
        coverage: "typed_trust_decisions_only",
        decisions,
        total,
        completeness: ledger.completeness,
    })
}

pub async fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: PermissionAuditRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(outcome) => return outcome,
    };
    let home = state.home.clone();
    let response = match tokio::task::spawn_blocking(move || read_at(&home, &request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(outcome)) => return outcome,
        Err(_) => {
            return HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                "permission audit replay unavailable",
                "retry after checking the authenticated primary WAL",
            );
        }
    };
    match serde_json::to_value(response) {
        Ok(body) => HandlerOutcome::ok_json(body),
        Err(error) => HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("permission audit response serialisation failed: {error}"),
            "retry after checking the audit metadata",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn append_trust(
        writer: &crate::wal::writer::WalWriterHandle,
        subject: &str,
        outcome: crate::permissions::Decision,
        decided_at_ns: u64,
    ) {
        let event = crate::permissions::trust_ledger::TrustEvent::from_gate(
            &crate::permissions::Action::Read,
            crate::permissions::AutonomyLevel::Standard,
            &outcome,
            Some(subject),
            None,
            None,
            None,
            decided_at_ns,
        )
        .unwrap();
        crate::permissions::trust_ledger::append_to_writer(writer, &event)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn authenticated_wal_subject_limit_and_time_filter_are_explicit() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) =
            crate::wal::writer::spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf())
                .unwrap();
        append_trust(
            &writer,
            "subject-a",
            crate::permissions::Decision::Allow,
            10,
        )
        .await;
        append_trust(
            &writer,
            "subject-a",
            crate::permissions::Decision::Allow,
            20,
        )
        .await;
        append_trust(
            &writer,
            "subject-b",
            crate::permissions::Decision::Allow,
            30,
        )
        .await;
        drop(writer);
        join.await.unwrap();

        let response = read_at(
            home.path(),
            &PermissionAuditRequest {
                subject: "subject-a".into(),
                limit: Some(1),
                from_ns: None,
            },
        )
        .unwrap();
        assert_eq!(response.total, 2);
        assert_eq!(response.decisions.len(), 1);
        assert_eq!(response.coverage, "typed_trust_decisions_only");

        let filtered = read_at(
            home.path(),
            &PermissionAuditRequest {
                subject: "subject-a".into(),
                limit: None,
                from_ns: Some(20),
            },
        )
        .unwrap();
        assert_eq!(filtered.total, 1);
        assert_eq!(filtered.decisions[0].decided_at_ns, 20);
    }

    #[tokio::test]
    async fn malformed_generic_trust_payload_is_rejected_before_authenticated_write() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) =
            crate::wal::writer::spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf())
                .unwrap();
        let payload = b"not-json".to_vec();
        let error = writer
            .append_authenticated(
                crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
                    .event_subtype(crate::wal::events::ExtendedSubtype::TrustDecision as u8)
                    .build(),
                payload,
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("generic TrustDecision payload is malformed")
        );
        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn tampered_authenticated_typed_trust_history_fails_closed_in_reader() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        append_trust(&writer, "local", crate::permissions::Decision::Allow, 10).await;
        drop(writer);
        join.await.unwrap();
        let mut bytes = std::fs::read(&segment).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&segment, bytes).unwrap();

        let error = read_at(
            home.path(),
            &PermissionAuditRequest {
                subject: "local".into(),
                limit: None,
                from_ns: None,
            },
        )
        .unwrap_err();
        assert_eq!(error.error_code(), Some(ApiErrorCode::UpstreamError));
    }

    #[tokio::test]
    async fn online_physical_cap_fails_closed_before_sparse_oversize_payload_is_read() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        append_trust(&writer, "local", crate::permissions::Decision::Allow, 10).await;
        drop(writer);
        join.await.unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&segment)
            .unwrap()
            .set_len(MAX_TOTAL_PHYSICAL_BYTES + 1)
            .unwrap();

        let error = read_at(
            home.path(),
            &PermissionAuditRequest {
                subject: "local".into(),
                limit: None,
                from_ns: None,
            },
        )
        .unwrap_err();
        assert_eq!(error.error_code(), Some(ApiErrorCode::UpstreamError));
    }

    #[tokio::test]
    async fn live_unsealed_tail_preserves_authenticated_decision_and_reports_incomplete_prefix() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) =
            crate::wal::writer::spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf())
                .unwrap();
        append_trust(&writer, "local", crate::permissions::Decision::Allow, 10).await;
        let tail = b"ordinary tail".to_vec();
        writer
            .append(crate::wal::HeaderBuilder::new(0x7f, &tail).build(), tail)
            .await
            .unwrap();
        let response = read_at(
            home.path(),
            &PermissionAuditRequest {
                subject: "local".into(),
                limit: None,
                from_ns: None,
            },
        )
        .unwrap();
        assert_eq!(response.decisions.len(), 1);
        assert!(matches!(
            response.completeness,
            TrustLedgerCompleteness::IncompleteAuthenticatedPrefix { .. }
        ));
        drop(writer);
        join.await.unwrap();
    }
}
