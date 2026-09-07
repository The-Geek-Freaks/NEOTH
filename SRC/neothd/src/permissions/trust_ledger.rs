//! Typed, append-only evidence for resolved autonomy decisions.
//!
//! The legacy `PERMISSION_GRANTED` / `PERMISSION_DENIED` frames remain the
//! compatibility audit surface. This module adds a closed, metadata-only
//! `TrustDecision` extended frame that can be replayed per exact subject key
//! without parsing free-form action debug output.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::writer::WalWriterHandle;

use super::{Action, ActionKind, AutonomyLevel, Decision};

pub const TRUST_EVENT_SCHEMA_VERSION: u8 = 1;
pub const LOCAL_SUBJECT: &str = "local";
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_LEASE_ID_BYTES: usize = 128;
const MAX_CONFIRMATION_SOURCE_BYTES: usize = 128;

/// The resolved outcome of one autonomy decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustOutcome {
    Allowed,
    Denied,
}

/// Closed, secret-safe payload for one final autonomy decision.
///
/// `reason_sha256` binds the operator-visible legacy reason without copying
/// paths, command fragments, or provider-controlled text into the new ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEvent {
    pub schema_version: u8,
    pub subject: String,
    pub action: ActionKind,
    pub autonomy_level: AutonomyLevel,
    pub outcome: TrustOutcome,
    pub reason_sha256: Option<String>,
    pub lease_id: Option<String>,
    pub confirmation_source: Option<String>,
    pub authorization_id: Option<String>,
    pub request_binding_sha256: Option<String>,
    pub decided_at_ns: u64,
}

impl TrustEvent {
    /// Build closed trust evidence for a boundary that already resolved its
    /// final policy decision outside [`super::gate::Gate`].
    ///
    /// Callers must pass the action and policy snapshot that made the decision,
    /// then append the returned event through one of the canonical helpers
    /// below. This avoids recreating a free-form per-subsystem audit schema.
    pub(crate) fn from_resolved_decision(
        action: &Action,
        autonomy_level: AutonomyLevel,
        decision: &Decision,
        subject: Option<&str>,
        lease_id: Option<&str>,
        confirmation_source: Option<&str>,
        request_binding_sha256: Option<&str>,
        decided_at_ns: u64,
    ) -> Result<Self> {
        Self::from_decision_fields(
            action,
            autonomy_level,
            decision,
            subject,
            lease_id,
            confirmation_source,
            request_binding_sha256,
            decided_at_ns,
        )
    }

    pub(crate) fn from_gate(
        action: &Action,
        autonomy_level: AutonomyLevel,
        decision: &Decision,
        subject: Option<&str>,
        lease_id: Option<&str>,
        confirmation_source: Option<&str>,
        request_binding_sha256: Option<&str>,
        decided_at_ns: u64,
    ) -> Result<Self> {
        Self::from_decision_fields(
            action,
            autonomy_level,
            decision,
            subject,
            lease_id,
            confirmation_source,
            request_binding_sha256,
            decided_at_ns,
        )
    }

    fn from_decision_fields(
        action: &Action,
        autonomy_level: AutonomyLevel,
        decision: &Decision,
        subject: Option<&str>,
        lease_id: Option<&str>,
        confirmation_source: Option<&str>,
        request_binding_sha256: Option<&str>,
        decided_at_ns: u64,
    ) -> Result<Self> {
        let subject = subject
            .map(str::trim)
            .filter(|subject| !subject.is_empty())
            .unwrap_or(LOCAL_SUBJECT)
            .to_owned();
        let (authorization_id, intrinsic_binding) = match action {
            Action::PaidProviderCall {
                authorization_id,
                request_binding_sha256,
                ..
            }
            | Action::UnboundedPaidProviderCall {
                authorization_id,
                request_binding_sha256,
                ..
            } => (
                Some(authorization_id.clone()),
                Some(request_binding_sha256.as_str()),
            ),
            Action::ExternalTtsSynthesis {
                request_binding_sha256,
                ..
            }
            | Action::ExternalHttpRequest {
                request_binding_sha256,
                ..
            } => (None, Some(request_binding_sha256.as_str())),
            _ => (None, None),
        };
        if let (Some(explicit), Some(intrinsic)) = (request_binding_sha256, intrinsic_binding) {
            ensure!(
                explicit == intrinsic,
                "explicit permission request binding does not match the action binding"
            );
        }
        let (outcome, reason) = match decision {
            Decision::Allow => (TrustOutcome::Allowed, None),
            Decision::Deny(reason) | Decision::Confirm(reason) => {
                (TrustOutcome::Denied, Some(reason.as_str()))
            }
        };
        let event = Self {
            schema_version: TRUST_EVENT_SCHEMA_VERSION,
            subject,
            action: action.kind(),
            autonomy_level,
            outcome,
            reason_sha256: reason.map(sha256_hex),
            lease_id: lease_id.map(str::to_owned),
            confirmation_source: confirmation_source.map(str::to_owned),
            authorization_id,
            request_binding_sha256: request_binding_sha256
                .or(intrinsic_binding)
                .map(str::to_owned),
            decided_at_ns,
        };
        event.validate()?;
        Ok(event)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("serialize TrustEvent")
    }

    fn decode(payload: &[u8]) -> Result<Self> {
        let event: Self = serde_json::from_slice(payload).context("decode TrustEvent")?;
        event.validate()?;
        Ok(event)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == TRUST_EVENT_SCHEMA_VERSION,
            "unsupported TrustEvent schema version {}",
            self.schema_version
        );
        validate_label("TrustEvent subject", &self.subject, MAX_SUBJECT_BYTES)?;
        for (label, value, max_bytes) in [
            (
                "TrustEvent lease id",
                self.lease_id.as_deref(),
                MAX_LEASE_ID_BYTES,
            ),
            (
                "TrustEvent confirmation source",
                self.confirmation_source.as_deref(),
                MAX_CONFIRMATION_SOURCE_BYTES,
            ),
        ] {
            if let Some(value) = value {
                validate_label(label, value, max_bytes)?;
            }
        }
        for (label, digest) in [
            ("TrustEvent reason digest", self.reason_sha256.as_deref()),
            (
                "TrustEvent authorization id",
                self.authorization_id.as_deref(),
            ),
            (
                "TrustEvent request binding",
                self.request_binding_sha256.as_deref(),
            ),
        ] {
            if let Some(digest) = digest {
                ensure!(
                    is_lower_hex_64(digest),
                    "{label} must be 64 lowercase hexadecimal characters"
                );
            }
        }
        Ok(())
    }
}

/// One replayed typed trust frame, ordered by HLC and immutable header identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustLedgerEntry {
    pub event_id: u64,
    pub hlc_physical_ns: u64,
    pub hlc_logical: u32,
    pub node_id_hex: String,
    pub event: TrustEvent,
}

/// Deterministic, subject-scoped replay of typed trust decisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustLedger {
    pub subject: String,
    pub entries: Vec<TrustLedgerEntry>,
    pub completeness: TrustLedgerCompleteness,
}

/// Whether inspection covered a complete authenticated WAL history or only a
/// verified prefix before an open writer's unmarked tail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TrustLedgerCompleteness {
    Complete,
    IncompleteAuthenticatedPrefix {
        boundaries: Vec<TrustLedgerBoundary>,
    },
}

/// One retained-WAL segment's verified-prefix boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustLedgerBoundary {
    pub segment_name: String,
    pub authenticated_through: usize,
    pub logical_len: usize,
}

impl TrustLedger {
    /// Replay every retained home-WAL segment, fail closed on malformed typed
    /// frames or WAL integrity errors, then return only this exact subject.
    pub fn replay_subject_at_home(home: &Path, subject: &str) -> Result<Self> {
        validate_label("trust ledger subject filter", subject, MAX_SUBJECT_BYTES)?;
        let mut entries = Vec::new();
        let mut frame_identities = BTreeSet::new();
        let scan = crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
            home,
            crate::wal::scan::supported_home_scan_limits(),
            |_, frame| {
                if frame.header.event_type != EVENT_TYPE_EXTENDED
                    || frame.header.event_subtype != ExtendedSubtype::TrustDecision as u8
                {
                    return Ok(());
                }
                let event = TrustEvent::decode(frame.payload)
                    .context("typed TrustDecision frame is malformed")?;
                let node_id_hex = hex::encode(frame.header.node_id.as_bytes());
                ensure!(
                    frame_identities.insert((
                        node_id_hex.clone(),
                        frame.header.hlc.physical_ns(),
                        frame.header.hlc.logical(),
                        frame.header.event_id.0,
                    )),
                    "typed trust ledger contains a duplicate immutable frame identity"
                );
                if event.subject == subject {
                    entries.push(TrustLedgerEntry {
                        event_id: frame.header.event_id.0,
                        hlc_physical_ns: frame.header.hlc.physical_ns(),
                        hlc_logical: frame.header.hlc.logical(),
                        node_id_hex,
                        event,
                    });
                }
                Ok(())
            },
        )
        .with_context(|| {
            format!(
                "replay TrustLedger for subject {subject:?}: WAL is tamper-suspect or unreadable"
            )
        })?;
        entries.sort_by(|left, right| {
            (
                left.hlc_physical_ns,
                left.hlc_logical,
                &left.node_id_hex,
                left.event_id,
            )
                .cmp(&(
                    right.hlc_physical_ns,
                    right.hlc_logical,
                    &right.node_id_hex,
                    right.event_id,
                ))
        });
        let completeness = if scan.complete {
            TrustLedgerCompleteness::Complete
        } else {
            TrustLedgerCompleteness::IncompleteAuthenticatedPrefix {
                boundaries: scan
                    .boundaries
                    .into_iter()
                    .map(|boundary| TrustLedgerBoundary {
                        segment_name: boundary.segment_name,
                        authenticated_through: boundary.authenticated_through,
                        logical_len: boundary.logical_len,
                    })
                    .collect(),
            }
        };
        Ok(Self {
            subject: subject.to_owned(),
            entries,
            completeness,
        })
    }
}

pub(crate) async fn append_to_writer(writer: &WalWriterHandle, event: &TrustEvent) -> Result<()> {
    let payload = event.encode()?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(ExtendedSubtype::TrustDecision as u8)
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
    writer
        .append_authenticated(header, payload)
        .await
        .context("append typed TrustDecision frame")?;
    Ok(())
}

/// Build and append exactly one resolved decision through a locally owned WAL
/// writer. Direct authority boundaries use this instead of inventing a second
/// trust-event encoder; required-audit callers must propagate an error.
pub(crate) struct ResolvedTrustDecision<'a> {
    pub action: &'a Action,
    pub autonomy_level: AutonomyLevel,
    pub decision: &'a Decision,
    pub subject: Option<&'a str>,
    pub lease_id: Option<&'a str>,
    pub confirmation_source: Option<&'a str>,
    pub request_binding_sha256: Option<&'a str>,
    pub decided_at_ns: u64,
}

pub(crate) async fn append_resolved_decision_to_writer(
    writer: &WalWriterHandle,
    resolved: ResolvedTrustDecision<'_>,
) -> Result<()> {
    let event = TrustEvent::from_resolved_decision(
        resolved.action,
        resolved.autonomy_level,
        resolved.decision,
        resolved.subject,
        resolved.lease_id,
        resolved.confirmation_source,
        resolved.request_binding_sha256,
        resolved.decided_at_ns,
    )?;
    append_to_writer(writer, &event).await
}

pub(crate) async fn append_to_daemon(home: &Path, event: &TrustEvent) -> Result<()> {
    let payload = event.encode()?;
    crate::daemon::audit_rpc::try_post_audit_frame_with_subtype(
        home,
        EVENT_TYPE_EXTENDED,
        ExtendedSubtype::TrustDecision as u8,
        &payload,
    )
    .await
    .map_err(|error| anyhow::anyhow!(error))
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_label(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    ensure!(
        value.len() <= max_bytes,
        "{label} exceeds {max_bytes} bytes"
    );
    ensure!(
        !value.chars().any(char::is_control),
        "{label} contains a control character"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::Action;
    use crate::wal::writer::spawn_for_home;
    use tempfile::tempdir;

    fn paid_action() -> Action {
        Action::PaidProviderCall {
            provider: "provider".into(),
            model: "model".into(),
            authorization_id: "a".repeat(64),
            request_binding_sha256: "b".repeat(64),
            eur_estimate: 0.1,
        }
    }

    #[tokio::test]
    async fn replay_is_subject_isolated_deterministic_and_tamper_loud() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (writer, join) = spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        let allow = TrustEvent::from_gate(
            &paid_action(),
            AutonomyLevel::Elevated,
            &Decision::Allow,
            Some("peer-a"),
            Some("lease-a"),
            Some("capability_lease"),
            None,
            10,
        )
        .unwrap();
        let deny = TrustEvent::from_gate(
            &Action::ExecArbitrary,
            AutonomyLevel::Standard,
            &Decision::Deny("operator declined".into()),
            Some("peer-b"),
            None,
            None,
            None,
            11,
        )
        .unwrap();
        append_to_writer(&writer, &allow).await.unwrap();
        append_to_writer(&writer, &deny).await.unwrap();
        drop(writer);
        join.await.unwrap();

        let first = TrustLedger::replay_subject_at_home(home.path(), "peer-a").unwrap();
        let second = TrustLedger::replay_subject_at_home(home.path(), "peer-a").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.entries[0].event.subject, "peer-a");
        assert_eq!(first.entries[0].event.outcome, TrustOutcome::Allowed);
        assert!(
            TrustLedger::replay_subject_at_home(home.path(), "peer-b")
                .unwrap()
                .entries
                .iter()
                .all(|entry| entry.event.subject == "peer-b")
        );

        let mut bytes = std::fs::read(&segment).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&segment, bytes).unwrap();
        assert!(TrustLedger::replay_subject_at_home(home.path(), "peer-a").is_err());
    }

    #[tokio::test]
    async fn replay_accepts_hlc_distinct_frames_with_one_physical_event_id() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) =
            spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf()).unwrap();
        let event = TrustEvent::from_gate(
            &Action::Read,
            AutonomyLevel::Standard,
            &Decision::Allow,
            Some("peer-a"),
            None,
            None,
            None,
            10,
        )
        .unwrap();
        let payload = event.encode().unwrap();
        let first = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::TrustDecision as u8)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
        let mut second = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::TrustDecision as u8)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
        second.event_id = first.event_id;
        second.hlc = crate::wal::Hlc::new(
            first.hlc.physical_ns(),
            first.hlc.logical().checked_add(1).unwrap(),
        )
        .unwrap();
        writer.append(first, payload.clone()).await.unwrap();
        writer.append(second, payload).await.unwrap();
        drop(writer);
        join.await.unwrap();

        let ledger = TrustLedger::replay_subject_at_home(home.path(), "peer-a").unwrap();
        assert_eq!(ledger.entries.len(), 2);
        assert_eq!(ledger.entries[0].event_id, ledger.entries[1].event_id);
        assert_ne!(ledger.entries[0].hlc_logical, ledger.entries[1].hlc_logical);
    }

    #[tokio::test]
    async fn live_writer_reports_complete_after_authenticated_trust_append_then_prefix_after_tail()
    {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) =
            spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf()).unwrap();
        let event = TrustEvent::from_gate(
            &Action::Read,
            AutonomyLevel::Standard,
            &Decision::Allow,
            Some("live-subject"),
            None,
            None,
            None,
            10,
        )
        .unwrap();
        append_to_writer(&writer, &event).await.unwrap();

        let complete = TrustLedger::replay_subject_at_home(home.path(), "live-subject")
            .expect("forced marker makes the live decision inspectable");
        assert!(matches!(
            complete.completeness,
            TrustLedgerCompleteness::Complete
        ));
        assert_eq!(complete.entries.len(), 1);

        let ordinary_tail = b"ordinary live WAL tail".to_vec();
        writer
            .append(
                crate::wal::HeaderBuilder::new(0x7F, &ordinary_tail).build(),
                ordinary_tail,
            )
            .await
            .unwrap();
        let prefix = TrustLedger::replay_subject_at_home(home.path(), "live-subject")
            .expect("accepted prefix remains inspectable while a live tail is explicit");
        assert!(matches!(
            prefix.completeness,
            TrustLedgerCompleteness::IncompleteAuthenticatedPrefix { .. }
        ));
        assert_eq!(prefix.entries.len(), 1, "unmarked tail is not projected");
        drop(writer);
        join.await.unwrap();
    }

    #[test]
    fn rejects_unsafe_subjects_and_noncanonical_digests() {
        assert!(TrustLedger::replay_subject_at_home(Path::new("."), " \n").is_err());
        let mut event = TrustEvent::from_gate(
            &Action::Read,
            AutonomyLevel::Standard,
            &Decision::Allow,
            None,
            None,
            None,
            None,
            1,
        )
        .unwrap();
        event.request_binding_sha256 = Some("BAD".into());
        assert!(event.encode().is_err());
    }
}
