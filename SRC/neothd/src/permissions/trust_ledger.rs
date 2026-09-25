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

use super::gate::PermissionAuditSink;
use super::{Action, ActionKind, AutonomyLevel, Decision};

/// Historical generic Gate audit schema. Its encoded bytes remain stable.
pub const TRUST_EVENT_SCHEMA_VERSION: u8 = 1;
/// Typed, immutable durable-admission receipt schema carried by `TrustEvent`.
pub const TRUST_ADMISSION_EVENT_SCHEMA_VERSION: u8 = 2;
/// Schema for the private-record/recovery descriptor itself.
pub const TRUST_ADMISSION_DESCRIPTOR_SCHEMA_VERSION: u8 = 1;
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

/// Immutable expectation for exactly one durable `TrustDecision` receipt.
///
/// This is deliberately not a capability. A same-user process can serialize a
/// syntactically valid copy; only the authenticated primary-WAL receipt proves
/// that the resolved Gate decision was appended. Recovery code may deserialize
/// this record, but the custom deserializer validates every bounded field
/// before it becomes usable as an expected receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustAdmissionDescriptor {
    schema_version: u8,
    operation_id_sha256: String,
    subject: String,
    action: ActionKind,
    outcome: TrustOutcome,
    autonomy_level: AutonomyLevel,
    request_binding_sha256: String,
    lease_id: Option<String>,
    confirmation_source: Option<String>,
    reason_sha256: Option<String>,
    policy_snapshot_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustAdmissionDescriptorWire {
    schema_version: u8,
    operation_id_sha256: String,
    subject: String,
    action: ActionKind,
    outcome: TrustOutcome,
    autonomy_level: AutonomyLevel,
    request_binding_sha256: String,
    lease_id: Option<String>,
    confirmation_source: Option<String>,
    reason_sha256: Option<String>,
    policy_snapshot_sha256: String,
}

impl TryFrom<TrustAdmissionDescriptorWire> for TrustAdmissionDescriptor {
    type Error = anyhow::Error;

    fn try_from(wire: TrustAdmissionDescriptorWire) -> Result<Self> {
        let descriptor = Self {
            schema_version: wire.schema_version,
            operation_id_sha256: wire.operation_id_sha256,
            subject: wire.subject,
            action: wire.action,
            outcome: wire.outcome,
            autonomy_level: wire.autonomy_level,
            request_binding_sha256: wire.request_binding_sha256,
            lease_id: wire.lease_id,
            confirmation_source: wire.confirmation_source,
            reason_sha256: wire.reason_sha256,
            policy_snapshot_sha256: wire.policy_snapshot_sha256,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

impl<'de> Deserialize<'de> for TrustAdmissionDescriptor {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TrustAdmissionDescriptorWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

impl TrustAdmissionDescriptor {
    /// Gate is the sole producer of production descriptors. The constructor is
    /// limited to the permissions parent so sibling gate code can resolve the
    /// existing policy/lease/confirmation state without exposing construction
    /// to egress consumers.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_gate_resolution(
        operation_id_sha256: &str,
        action: &Action,
        autonomy_level: AutonomyLevel,
        decision: &Decision,
        subject: Option<&str>,
        lease_id: Option<&str>,
        confirmation_source: Option<&str>,
        request_binding_sha256: &str,
        policy_snapshot_sha256: String,
    ) -> Result<Self> {
        let subject = subject
            .map(str::trim)
            .filter(|subject| !subject.is_empty())
            .unwrap_or(LOCAL_SUBJECT)
            .to_owned();
        let (outcome, reason_sha256) = match decision {
            Decision::Allow => (TrustOutcome::Allowed, None),
            Decision::Deny(reason) | Decision::Confirm(reason) => {
                (TrustOutcome::Denied, Some(sha256_hex(reason)))
            }
        };
        let descriptor = Self {
            schema_version: TRUST_ADMISSION_DESCRIPTOR_SCHEMA_VERSION,
            operation_id_sha256: operation_id_sha256.to_owned(),
            subject,
            action: action.kind(),
            outcome,
            autonomy_level,
            request_binding_sha256: request_binding_sha256.to_owned(),
            lease_id: lease_id.map(str::to_owned),
            confirmation_source: confirmation_source.map(str::to_owned),
            reason_sha256,
            policy_snapshot_sha256,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub(crate) fn operation_id_sha256(&self) -> &str {
        &self.operation_id_sha256
    }
    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }
    pub(crate) const fn action(&self) -> ActionKind {
        self.action
    }
    pub(crate) const fn outcome(&self) -> TrustOutcome {
        self.outcome
    }
    pub(crate) fn request_binding_sha256(&self) -> &str {
        &self.request_binding_sha256
    }
    pub(crate) fn lease_id(&self) -> Option<&str> {
        self.lease_id.as_deref()
    }
    pub(crate) fn confirmation_source(&self) -> Option<&str> {
        self.confirmation_source.as_deref()
    }
    pub(crate) fn reason_sha256(&self) -> Option<&str> {
        self.reason_sha256.as_deref()
    }
    pub(crate) fn policy_snapshot_sha256(&self) -> &str {
        &self.policy_snapshot_sha256
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == TRUST_ADMISSION_DESCRIPTOR_SCHEMA_VERSION,
            "unsupported TrustAdmissionDescriptor schema version {}",
            self.schema_version
        );
        validate_label(
            "TrustAdmissionDescriptor subject",
            &self.subject,
            MAX_SUBJECT_BYTES,
        )?;
        validate_digest(
            "TrustAdmissionDescriptor operation id",
            &self.operation_id_sha256,
        )?;
        validate_digest(
            "TrustAdmissionDescriptor request binding",
            &self.request_binding_sha256,
        )?;
        validate_digest(
            "TrustAdmissionDescriptor policy snapshot",
            &self.policy_snapshot_sha256,
        )?;
        for (label, value, max_bytes) in [
            (
                "TrustAdmissionDescriptor lease id",
                self.lease_id.as_deref(),
                MAX_LEASE_ID_BYTES,
            ),
            (
                "TrustAdmissionDescriptor confirmation source",
                self.confirmation_source.as_deref(),
                MAX_CONFIRMATION_SOURCE_BYTES,
            ),
        ] {
            if let Some(value) = value {
                validate_label(label, value, max_bytes)?;
            }
        }
        if let Some(reason_sha256) = self.reason_sha256.as_deref() {
            validate_digest("TrustAdmissionDescriptor reason digest", reason_sha256)?;
        }
        Ok(())
    }

    /// Materialize the only schema-2 trust event form. The writer chooses the
    /// receipt timestamp; it is intentionally excluded from logical matching.
    pub(crate) fn to_schema2_event(&self, decided_at_ns: u64) -> Result<TrustEvent> {
        self.validate()?;
        let event = TrustEvent {
            schema_version: TRUST_ADMISSION_EVENT_SCHEMA_VERSION,
            subject: self.subject.clone(),
            action: self.action,
            autonomy_level: self.autonomy_level,
            outcome: self.outcome,
            reason_sha256: self.reason_sha256.clone(),
            lease_id: self.lease_id.clone(),
            confirmation_source: self.confirmation_source.clone(),
            authorization_id: None,
            request_binding_sha256: Some(self.request_binding_sha256.clone()),
            operation_id_sha256: Some(self.operation_id_sha256.clone()),
            policy_snapshot_sha256: Some(self.policy_snapshot_sha256.clone()),
            decided_at_ns,
        };
        event.validate()?;
        Ok(event)
    }

    pub(crate) fn matches_event(&self, event: &TrustEvent) -> bool {
        event.schema_version == TRUST_ADMISSION_EVENT_SCHEMA_VERSION
            && event.operation_id_sha256.as_deref() == Some(self.operation_id_sha256())
            && event.subject == self.subject
            && event.action == self.action
            && event.outcome == self.outcome
            && event.autonomy_level == self.autonomy_level
            && event.request_binding_sha256.as_deref() == Some(self.request_binding_sha256())
            && event.lease_id.as_deref() == self.lease_id()
            && event.confirmation_source.as_deref() == self.confirmation_source()
            && event.reason_sha256.as_deref() == self.reason_sha256()
            && event.policy_snapshot_sha256.as_deref() == Some(self.policy_snapshot_sha256())
            && event.authorization_id.is_none()
    }
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
    /// Present only in schema 2 durable-admission receipts. `skip_serializing`
    /// preserves byte-for-byte schema-1 serialization for generic Gate audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id_sha256: Option<String>,
    /// Present only in schema 2 durable-admission receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_snapshot_sha256: Option<String>,
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
            operation_id_sha256: None,
            policy_snapshot_sha256: None,
            decided_at_ns,
        };
        event.validate()?;
        Ok(event)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("serialize TrustEvent")
    }

    pub(crate) fn decode(payload: &[u8]) -> Result<Self> {
        let event: Self = serde_json::from_slice(payload).context("decode TrustEvent")?;
        event.validate()?;
        Ok(event)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(
                self.schema_version,
                TRUST_EVENT_SCHEMA_VERSION | TRUST_ADMISSION_EVENT_SCHEMA_VERSION
            ),
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
            (
                "TrustEvent operation id",
                self.operation_id_sha256.as_deref(),
            ),
            (
                "TrustEvent policy snapshot",
                self.policy_snapshot_sha256.as_deref(),
            ),
        ] {
            if let Some(digest) = digest {
                ensure!(
                    is_lower_hex_64(digest),
                    "{label} must be 64 lowercase hexadecimal characters"
                );
            }
        }
        match self.schema_version {
            TRUST_EVENT_SCHEMA_VERSION => ensure!(
                self.operation_id_sha256.is_none() && self.policy_snapshot_sha256.is_none(),
                "schema-1 TrustEvent must not carry durable-admission fields"
            ),
            TRUST_ADMISSION_EVENT_SCHEMA_VERSION => {
                ensure!(
                    self.operation_id_sha256.is_some() && self.policy_snapshot_sha256.is_some(),
                    "schema-2 TrustEvent requires operation id and policy snapshot"
                );
                ensure!(
                    self.request_binding_sha256.is_some(),
                    "schema-2 TrustEvent requires request binding"
                );
                ensure!(
                    self.authorization_id.is_none(),
                    "schema-2 TrustEvent must not carry a generic authorization id"
                );
            }
            _ => unreachable!("version was validated above"),
        }
        Ok(())
    }

    pub(crate) const fn is_durable_admission(&self) -> bool {
        self.schema_version == TRUST_ADMISSION_EVENT_SCHEMA_VERSION
    }
}

/// Parse an extended TrustDecision payload for generic append/RPC guards.
/// Schema 1 is a legacy/generic audit record; a valid schema 2 record is a
/// typed durable admission and must flow through the append-once transaction.
pub(crate) fn is_durable_trust_admission_payload(payload: &[u8]) -> Result<bool> {
    Ok(TrustEvent::decode(payload)?.is_durable_admission())
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

/// Recovery result from authenticated primary-WAL evidence. `prefix` makes an
/// accepted live prefix explicit: a caller must never reinterpret an absent
/// value behind an unsealed tail as proof that no prior request exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum AuthenticatedDecisionLookup {
    Absent {
        prefix: TrustLedgerCompleteness,
    },
    Exact {
        entry: Box<TrustLedgerEntry>,
        prefix: TrustLedgerCompleteness,
    },
    Duplicate {
        prefix: TrustLedgerCompleteness,
    },
    Conflict {
        prefix: TrustLedgerCompleteness,
    },
}

/// Terminal result of the writer-owned exactly-once TrustDecision transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustDecisionOnceOutcome {
    ExistingExact,
    AppendedExact,
}

/// Fail-closed result for a closed durable-admission append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustDecisionOnceError {
    Conflict,
    Duplicate,
    Indeterminate,
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
        Self::replay_subject_at_home_with_limits(
            home,
            subject,
            crate::wal::scan::supported_home_scan_limits(),
            usize::MAX,
        )
    }

    /// Replay a bounded authenticated WAL prefix for a read-only projection.
    ///
    /// Callers that expose this path online must supply their own I/O and
    /// matching-entry ceilings. Reaching either ceiling is an error rather than
    /// evidence that no further decision exists.
    pub(crate) fn replay_subject_at_home_with_limits(
        home: &Path,
        subject: &str,
        limits: crate::wal::scan::HomeWalScanLimits,
        max_matching_entries: usize,
    ) -> Result<Self> {
        validate_label("trust ledger subject filter", subject, MAX_SUBJECT_BYTES)?;
        ensure!(
            max_matching_entries > 0,
            "trust ledger matching-entry ceiling must be positive"
        );
        let mut entries = Vec::new();
        let mut frame_identities = BTreeSet::new();
        let scan = crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
            home,
            limits,
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
                    ensure!(
                        entries.len() < max_matching_entries,
                        "trust ledger matching-entry ceiling exceeded"
                    );
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

/// Find one immutable durable-admission receipt in the authenticated WAL
/// prefix. Only a matching schema-2 `TrustDecision` is evidence. A single
/// operation id bound to any different descriptor is a conflict even when a
/// matching record also exists; that prevents a descriptor forgery from being
/// hidden behind a prior successful receipt.
pub(crate) fn find_authenticated_decision_at_home(
    home: &Path,
    expected: &TrustAdmissionDescriptor,
) -> Result<AuthenticatedDecisionLookup> {
    expected.validate()?;
    let mut exact = None;
    let mut exact_count = 0usize;
    let mut conflict = false;
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
                .context("typed TrustDecision frame is malformed during durable receipt lookup")?;
            if !event.is_durable_admission()
                || event.operation_id_sha256.as_deref() != Some(expected.operation_id_sha256())
            {
                return Ok(());
            }
            if expected.matches_event(&event) {
                exact_count = exact_count.saturating_add(1);
                if exact.is_none() {
                    exact = Some(TrustLedgerEntry {
                        event_id: frame.header.event_id.0,
                        hlc_physical_ns: frame.header.hlc.physical_ns(),
                        hlc_logical: frame.header.hlc.logical(),
                        node_id_hex: hex::encode(frame.header.node_id.as_bytes()),
                        event,
                    });
                }
            } else {
                conflict = true;
            }
            Ok(())
        },
    )
    .with_context(|| {
        format!(
            "look up durable TrustDecision operation {} in authenticated primary WAL",
            expected.operation_id_sha256()
        )
    })?;
    let prefix = completeness_from_authenticated_scan(scan);
    if conflict {
        Ok(AuthenticatedDecisionLookup::Conflict { prefix })
    } else if exact_count > 1 {
        Ok(AuthenticatedDecisionLookup::Duplicate { prefix })
    } else if let Some(entry) = exact {
        Ok(AuthenticatedDecisionLookup::Exact {
            entry: Box::new(entry),
            prefix,
        })
    } else {
        Ok(AuthenticatedDecisionLookup::Absent { prefix })
    }
}

/// Dispatch the closed durable-admission transaction through the caller's
/// existing writer/RPC authority. Unlike generic Gate audit, this never falls
/// back to an unaudited append: no sink, an identity mismatch, and every
/// transport error are indeterminate and must block the effect.
pub(crate) async fn audit_trust_admission_once(
    sink: PermissionAuditSink<'_>,
    home: &Path,
    expected: &TrustAdmissionDescriptor,
) -> std::result::Result<TrustDecisionOnceOutcome, TrustDecisionOnceError> {
    if expected.validate().is_err() {
        return Err(TrustDecisionOnceError::Indeterminate);
    }
    match sink {
        PermissionAuditSink::Writer(writer) => {
            writer
                .append_trust_decision_once(home, expected.clone())
                .await
        }
        PermissionAuditSink::WriterWithSession(writer, _) => {
            writer
                .append_trust_decision_once(home, expected.clone())
                .await
        }
        PermissionAuditSink::DaemonRpc(bound_home) => {
            let same_home = crate::daemon::audit_rpc::homes_same_identity(bound_home, home)
                .map_err(|_| TrustDecisionOnceError::Indeterminate)?;
            if !same_home {
                return Err(TrustDecisionOnceError::Indeterminate);
            }
            crate::daemon::audit_rpc::try_post_trust_decision_once(bound_home, expected).await
        }
        PermissionAuditSink::None => Err(TrustDecisionOnceError::Indeterminate),
        #[cfg(test)]
        PermissionAuditSink::Fail(_) => Err(TrustDecisionOnceError::Indeterminate),
    }
}

fn completeness_from_authenticated_scan(
    scan: crate::wal::scan::AuthenticatedPrefixScan,
) -> TrustLedgerCompleteness {
    if scan.complete {
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
    }
}

pub(crate) async fn append_to_writer(writer: &WalWriterHandle, event: &TrustEvent) -> Result<()> {
    append_to_writer_in(writer, event, None).await
}

/// Append a non-durable TrustDecision with an optional already-admitted WAL
/// context. Standalone callers retain zero attribution through the wrapper.
pub(crate) async fn append_to_writer_in(
    writer: &WalWriterHandle,
    event: &TrustEvent,
    wal_session: Option<crate::wal::WalSessionContext>,
) -> Result<()> {
    ensure!(
        !event.is_durable_admission(),
        "schema-2 durable TrustDecision must use append_trust_decision_once"
    );
    let payload = event.encode()?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(ExtendedSubtype::TrustDecision as u8)
        .session_context(wal_session)
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
    append_resolved_decision_to_writer_in(writer, resolved, None).await
}

/// Contextual counterpart for an already-admitted caller. It accepts only the
/// typed capability and leaves all serialized TrustDecision content unchanged.
pub(crate) async fn append_resolved_decision_to_writer_in(
    writer: &WalWriterHandle,
    resolved: ResolvedTrustDecision<'_>,
    wal_session: Option<crate::wal::WalSessionContext>,
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
    append_to_writer_in(writer, &event, wal_session).await
}

pub(crate) async fn append_to_daemon(home: &Path, event: &TrustEvent) -> Result<()> {
    ensure!(
        !event.is_durable_admission(),
        "schema-2 durable TrustDecision must use the typed daemon admission RPC"
    );
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

fn validate_digest(label: &str, value: &str) -> Result<()> {
    ensure!(
        is_lower_hex_64(value),
        "{label} must be 64 lowercase hexadecimal characters"
    );
    Ok(())
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
    async fn bounded_replay_rejects_a_second_matching_authenticated_decision() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) =
            spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf()).unwrap();
        for decided_at_ns in [10, 20] {
            let event = TrustEvent::from_gate(
                &Action::Read,
                AutonomyLevel::Standard,
                &Decision::Allow,
                Some("bounded-subject"),
                None,
                None,
                None,
                decided_at_ns,
            )
            .unwrap();
            append_to_writer(&writer, &event).await.unwrap();
        }
        drop(writer);
        join.await.unwrap();

        let accepted = TrustLedger::replay_subject_at_home_with_limits(
            home.path(),
            "bounded-subject",
            crate::wal::scan::HomeWalScanLimits::default(),
            2,
        )
        .unwrap();
        assert_eq!(accepted.entries.len(), 2);
        let error = TrustLedger::replay_subject_at_home_with_limits(
            home.path(),
            "bounded-subject",
            crate::wal::scan::HomeWalScanLimits::default(),
            1,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("matching-entry ceiling exceeded"));
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

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    async fn durable_descriptor(
        operation_byte: char,
        binding_byte: char,
    ) -> TrustAdmissionDescriptor {
        crate::permissions::Gate::for_level(AutonomyLevel::Full)
            .resolve_trust_admission(
                &Action::ChannelSend,
                &digest(operation_byte),
                &digest(binding_byte),
            )
            .await
            .expect("full policy must resolve a valid durable descriptor")
    }

    #[tokio::test]
    async fn schema_one_encoding_stays_compatible_and_schema_two_is_closed() {
        let legacy = TrustEvent::from_gate(
            &Action::Read,
            AutonomyLevel::Standard,
            &Decision::Allow,
            None,
            None,
            None,
            None,
            7,
        )
        .unwrap();
        let legacy_json: serde_json::Value =
            serde_json::from_slice(&legacy.encode().unwrap()).unwrap();
        assert_eq!(legacy.schema_version, TRUST_EVENT_SCHEMA_VERSION);
        assert!(legacy_json.get("operation_id_sha256").is_none());
        assert!(legacy_json.get("policy_snapshot_sha256").is_none());
        assert!(!is_durable_trust_admission_payload(&legacy.encode().unwrap()).unwrap());

        let descriptor = durable_descriptor('a', 'b').await;
        let durable = descriptor.to_schema2_event(9).unwrap();
        let durable_json: serde_json::Value =
            serde_json::from_slice(&durable.encode().unwrap()).unwrap();
        assert_eq!(durable.schema_version, TRUST_ADMISSION_EVENT_SCHEMA_VERSION);
        assert_eq!(
            durable_json["operation_id_sha256"],
            serde_json::Value::String(digest('a'))
        );
        assert!(is_durable_trust_admission_payload(&durable.encode().unwrap()).unwrap());

        let mut missing_policy = durable_json;
        missing_policy
            .as_object_mut()
            .unwrap()
            .remove("policy_snapshot_sha256");
        assert!(TrustEvent::decode(&serde_json::to_vec(&missing_policy).unwrap()).is_err());
    }

    #[tokio::test]
    async fn descriptor_recovery_deserialization_is_strict_and_gate_denial_is_a_descriptor() {
        let allowed = durable_descriptor('c', 'd').await;
        let serialized = serde_json::to_value(&allowed).unwrap();
        let recovered: TrustAdmissionDescriptor =
            serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(recovered, allowed);

        let mut unknown = serialized.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<TrustAdmissionDescriptor>(unknown).is_err());

        let mut malformed = serialized;
        malformed.as_object_mut().unwrap().insert(
            "request_binding_sha256".into(),
            serde_json::Value::String("BAD".into()),
        );
        assert!(serde_json::from_value::<TrustAdmissionDescriptor>(malformed).is_err());

        let denied = crate::permissions::Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(crate::permissions::ConfirmStrategy::FailClosed)
            .resolve_trust_admission(&Action::ChannelSend, &digest('e'), &digest('f'))
            .await
            .expect("a static/failed confirmation denial remains a descriptor");
        assert_eq!(denied.outcome(), TrustOutcome::Denied);
        assert_eq!(denied.subject(), LOCAL_SUBJECT);
    }

    #[tokio::test]
    async fn lookup_uses_only_authenticated_prefix_and_exact_descriptor() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) =
            spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf()).unwrap();
        let expected = durable_descriptor('1', '2').await;
        assert_eq!(
            writer
                .append_trust_decision_once(home.path(), expected.clone())
                .await
                .unwrap(),
            TrustDecisionOnceOutcome::AppendedExact
        );
        assert!(matches!(
            find_authenticated_decision_at_home(home.path(), &expected).unwrap(),
            AuthenticatedDecisionLookup::Exact {
                prefix: TrustLedgerCompleteness::Complete,
                ..
            }
        ));

        let tail = b"ordinary unsealed tail".to_vec();
        writer
            .append(crate::wal::HeaderBuilder::new(0x7F, &tail).build(), tail)
            .await
            .unwrap();
        assert!(matches!(
            find_authenticated_decision_at_home(home.path(), &expected).unwrap(),
            AuthenticatedDecisionLookup::Exact {
                prefix: TrustLedgerCompleteness::IncompleteAuthenticatedPrefix { .. },
                ..
            }
        ));
        drop(writer);
        join.await.unwrap();
    }
}
