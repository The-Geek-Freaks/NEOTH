//! Default-on, deterministic communication adaptation.
//!
//! This module learns observable presentation and clarification preferences.
//! It deliberately has no model call and no diagnostic output. Raw messages
//! are classified in memory and discarded; only typed, subject-bound evidence
//! and content hashes are persisted.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{CommunicationProfileConfig, CommunicationPromptExport};

pub const STATE_RELATIVE_PATH: &str = "profile/communication.json";
/// The one explicitly supported operator-global profile subject. All other
/// identities remain scope-local even when they have a stable channel UUID.
pub const COMMUNICATION_OPERATOR_SUBJECT: &str = "operator";
const STATE_SCHEMA_VERSION: u32 = 2;
const LEGACY_STATE_SCHEMA_VERSION: u32 = 1;
const MAX_EVIDENCE_PER_SUBJECT_PER_DAY_AND_DIMENSION: usize = 4;
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STATE_SUBJECTS: usize = 4_096;
const MAX_STATE_EVIDENCE_PER_DIMENSION: usize = 256;

static COMMUNICATION_STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommunicationDimension {
    Directness,
    Structure,
    Ambiguity,
    ProcessingLoad,
    ContextAmount,
    Pace,
    Clarification,
    CorrectionStyle,
}

impl CommunicationDimension {
    pub const ALL: [Self; 8] = [
        Self::Directness,
        Self::Structure,
        Self::Ambiguity,
        Self::ProcessingLoad,
        Self::ContextAmount,
        Self::Pace,
        Self::Clarification,
        Self::CorrectionStyle,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directness => "directness",
            Self::Structure => "structure",
            Self::Ambiguity => "ambiguity",
            Self::ProcessingLoad => "processing_load",
            Self::ContextAmount => "context_amount",
            Self::Pace => "pace",
            Self::Clarification => "clarification",
            Self::CorrectionStyle => "correction_style",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectnessPreference {
    Direct,
    Balanced,
    Gentle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructurePreference {
    Prose,
    Bullets,
    NumberedSteps,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityPreference {
    LiteralExplicit,
    Balanced,
    Inferential,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingLoadPreference {
    OneChunk,
    Compact,
    Balanced,
    Deep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAmountPreference {
    Minimal,
    ShortRecap,
    ContinuityRich,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacePreference {
    ImmediateFull,
    Staged,
    AskBeforeNext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClarificationPreference {
    ActWithStatedAssumptions,
    AskOneQuestion,
    ClarifyFirst,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrectionStylePreference {
    AcknowledgeAndFix,
    ExplainThenFix,
    SilentFix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "dimension", content = "value", rename_all = "snake_case")]
pub enum PreferenceValue {
    Directness(DirectnessPreference),
    Structure(StructurePreference),
    Ambiguity(AmbiguityPreference),
    ProcessingLoad(ProcessingLoadPreference),
    ContextAmount(ContextAmountPreference),
    Pace(PacePreference),
    Clarification(ClarificationPreference),
    CorrectionStyle(CorrectionStylePreference),
}

impl PreferenceValue {
    pub fn dimension(self) -> CommunicationDimension {
        match self {
            Self::Directness(_) => CommunicationDimension::Directness,
            Self::Structure(_) => CommunicationDimension::Structure,
            Self::Ambiguity(_) => CommunicationDimension::Ambiguity,
            Self::ProcessingLoad(_) => CommunicationDimension::ProcessingLoad,
            Self::ContextAmount(_) => CommunicationDimension::ContextAmount,
            Self::Pace(_) => CommunicationDimension::Pace,
            Self::Clarification(_) => CommunicationDimension::Clarification,
            Self::CorrectionStyle(_) => CommunicationDimension::CorrectionStyle,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    ExplicitSetting,
    ExplicitCorrection,
    ResponseFeedback,
    PassiveOutcome,
}

impl EvidenceSource {
    fn base_weight(self) -> f64 {
        match self {
            Self::ExplicitSetting => 1.0,
            Self::ExplicitCorrection => 0.90,
            Self::ResponseFeedback => 0.75,
            Self::PassiveOutcome => 0.20,
        }
    }

    fn half_life_days(self, policy: &CommunicationProfileConfig) -> Option<u32> {
        match self {
            Self::ExplicitSetting => None,
            Self::ExplicitCorrection => Some(policy.correction_half_life_days),
            Self::ResponseFeedback => Some(policy.feedback_half_life_days),
            Self::PassiveOutcome => Some(policy.passive_half_life_days),
        }
    }

    fn retention_priority(self) -> u8 {
        match self {
            Self::ExplicitSetting => 4,
            Self::ExplicitCorrection => 3,
            Self::ResponseFeedback => 2,
            Self::PassiveOutcome => 1,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum CommunicationScope {
    #[default]
    Global,
    Channel(String),
    Task(String),
}

impl CommunicationScope {
    fn applies_to(&self, target: Option<&Self>) -> bool {
        matches!(self, Self::Global) || target == Some(self)
    }

    fn audit_code(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Channel(_) => "channel",
            Self::Task(_) => "task",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedSubject {
    subject_id: String,
    origin: AuthenticatedSubjectOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatedSubjectOrigin {
    LocalInteractiveOperator,
    PinnedChannelOperator,
    AuthenticatedChannelParticipant,
    /// Compatibility marker assigned only while migrating a schema-v1 state.
    LegacyAuthenticated,
}

impl AuthenticatedSubject {
    fn subject_id(&self) -> &str {
        &self.subject_id
    }

    fn origin(&self) -> AuthenticatedSubjectOrigin {
        self.origin
    }

    fn permits_global_scope(&self) -> bool {
        matches!(
            self.origin,
            AuthenticatedSubjectOrigin::LocalInteractiveOperator
                | AuthenticatedSubjectOrigin::PinnedChannelOperator
        ) && self.subject_id == COMMUNICATION_OPERATOR_SUBJECT
    }
}

mod approved_boundary {
    pub(in crate::profile) trait Sealed {}
}

/// Implemented only in this module for exact opaque marker types owned by the
/// authenticated CLI/channel boundaries. Other crate modules cannot name the
/// sealing trait and cannot mint an accepted communication subject.
///
/// The intentionally narrower sealing supertrait makes this a call-site
/// capability rather than a crate-wide issuer. `AuthenticatedSubject` is
/// crate-visible only because this trait's signature needs it; its fields and
/// constructors stay private, so other modules still cannot mint authority.
#[allow(private_bounds)]
pub(crate) trait ApprovedCommunicationSubject: approved_boundary::Sealed {
    fn into_subject(self) -> AuthenticatedSubject;
}

impl approved_boundary::Sealed for crate::cli::chat::LocalChatCommunicationSubject {}
impl ApprovedCommunicationSubject for crate::cli::chat::LocalChatCommunicationSubject {
    fn into_subject(self) -> AuthenticatedSubject {
        AuthenticatedSubject {
            subject_id: COMMUNICATION_OPERATOR_SUBJECT.to_owned(),
            origin: AuthenticatedSubjectOrigin::LocalInteractiveOperator,
        }
    }
}

impl approved_boundary::Sealed for crate::cli::serve_pipeline::PinnedChannelCommunicationSubject {}
impl ApprovedCommunicationSubject
    for crate::cli::serve_pipeline::PinnedChannelCommunicationSubject
{
    fn into_subject(self) -> AuthenticatedSubject {
        AuthenticatedSubject {
            subject_id: COMMUNICATION_OPERATOR_SUBJECT.to_owned(),
            origin: AuthenticatedSubjectOrigin::PinnedChannelOperator,
        }
    }
}

impl approved_boundary::Sealed for crate::cli::profile::LocalProfileCommunicationOperator {}
impl ApprovedCommunicationSubject for crate::cli::profile::LocalProfileCommunicationOperator {
    fn into_subject(self) -> AuthenticatedSubject {
        AuthenticatedSubject {
            subject_id: COMMUNICATION_OPERATOR_SUBJECT.to_owned(),
            origin: AuthenticatedSubjectOrigin::LocalInteractiveOperator,
        }
    }
}

#[cfg(test)]
impl approved_boundary::Sealed for &str {}
#[cfg(test)]
impl ApprovedCommunicationSubject for &str {
    fn into_subject(self) -> AuthenticatedSubject {
        AuthenticatedSubject {
            subject_id: self.to_owned(),
            origin: if self == COMMUNICATION_OPERATOR_SUBJECT {
                AuthenticatedSubjectOrigin::LocalInteractiveOperator
            } else {
                AuthenticatedSubjectOrigin::AuthenticatedChannelParticipant
            },
        }
    }
}

/// Test-only scoped fixture seam. Production identity boundaries cannot mint
/// evidence from strings; integration tests use this to model a participant
/// without accidentally granting it operator-global authority.
#[cfg(test)]
pub(crate) fn set_test_scoped_preference(
    home: &Path,
    policy: &CommunicationProfileConfig,
    subject_id: &str,
    session_id: &str,
    value: PreferenceValue,
    event_hash: [u8; 32],
    observed_at_unix: i64,
) -> Result<ObservationOutcome> {
    let operator = subject_id == COMMUNICATION_OPERATOR_SUBJECT;
    let subject = if operator {
        "operator".into_subject()
    } else {
        subject_id.into_subject()
    };
    let scope = if operator {
        CommunicationScope::Global
    } else {
        CommunicationScope::Channel("test".to_owned())
    };
    record_evidence(
        home,
        policy,
        EvidenceInput::from_authenticated(
            event_hash,
            subject,
            session_id.to_owned(),
            EvidenceSource::ExplicitSetting,
            value,
            observed_at_unix,
            scope,
            "test_explicit_setting",
        ),
        false,
        false,
    )
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub event_hash: String,
    pub subject_id: String,
    pub session_id: String,
    pub source: EvidenceSource,
    pub value: PreferenceValue,
    pub observed_at_unix: i64,
    pub scope: CommunicationScope,
    /// Compatibility-only v1 field. Schema-v2 persistence uses the typed
    /// `authenticated_origin` and never serializes this boolean declaration.
    #[serde(rename = "authenticated_subject", default, skip_serializing)]
    legacy_authenticated_subject: bool,
    #[serde(default)]
    pub authenticated_origin: Option<AuthenticatedSubjectOrigin>,
    pub reason_code: String,
}

impl EvidenceRef {
    pub fn dimension(&self) -> CommunicationDimension {
        self.value.dimension()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionEstimate {
    pub selected: PreferenceValue,
    pub confidence: f32,
    pub effective_weight: f64,
    pub observation_count: u32,
    pub distinct_sessions: u32,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
    pub active: bool,
    pub pinned: bool,
    pub durable_by_full_auto: bool,
    /// The exact scope that produced the durable decision. This makes a
    /// persisted estimate auditable and prevents a channel/task estimate from
    /// being reinterpreted as global after restart.
    #[serde(default)]
    pub scope_provenance: CommunicationScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredContextKind {
    Neurodivergent,
    Autistic,
    Adhd,
}

impl DeclaredContextKind {
    fn provider_label(self) -> &'static str {
        match self {
            Self::Neurodivergent => "neurodivergent",
            Self::Autistic => "autistic",
            Self::Adhd => "ADHD",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredContextPromptUse {
    AccommodationsOnly,
    LabelAndAccommodations,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredContext {
    pub kind: DeclaredContextKind,
    pub explicitly_asserted_by_operator: bool,
    pub source_event_hash: String,
    pub prompt_use: DeclaredContextPromptUse,
    pub set_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectCommunicationProfile {
    pub revision: u64,
    #[serde(default)]
    pub evidence: BTreeMap<CommunicationDimension, Vec<EvidenceRef>>,
    #[serde(default)]
    pub estimates: BTreeMap<CommunicationDimension, DimensionEstimate>,
    pub declared_context: Option<DeclaredContext>,
}

/// Versioned, one-way projection for a generic operator export.
///
/// This is deliberately not a persistence type. It publishes only active,
/// concrete presentation accommodations for the operator-global subject. In
/// particular it has no subject identifier, evidence, confidence, scope,
/// provenance, timing, or declared-context field.
pub const REDACTED_EXPORT_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RedactedCommunicationProfileExport {
    pub export_schema_version: u32,
    pub state_present: bool,
    pub state_schema_version: Option<u32>,
    pub redacted: bool,
    pub active_accommodations: Vec<PreferenceValue>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommunicationState {
    pub schema_version: u32,
    pub revision: u64,
    #[serde(default)]
    pub subjects: BTreeMap<String, SubjectCommunicationProfile>,
    #[serde(default)]
    audit_pending: Vec<ObservationAuditIntent>,
}

impl Default for CommunicationState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            revision: 0,
            subjects: BTreeMap::new(),
            audit_pending: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationAuditIntent {
    subject_id: String,
    event_hash: String,
    scope: CommunicationScope,
    outcome: ObservationOutcome,
    observed_at_unix: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct EvidenceInput {
    pub event_hash: [u8; 32],
    subject: AuthenticatedSubject,
    pub session_id: String,
    pub source: EvidenceSource,
    pub value: PreferenceValue,
    pub observed_at_unix: i64,
    pub scope: CommunicationScope,
    pub reason_code: &'static str,
}

impl EvidenceInput {
    #[cfg(test)]
    pub fn new(
        event_hash: [u8; 32],
        subject: impl ApprovedCommunicationSubject,
        session_id: String,
        source: EvidenceSource,
        value: PreferenceValue,
        observed_at_unix: i64,
        scope: CommunicationScope,
        reason_code: &'static str,
    ) -> Self {
        Self {
            event_hash,
            subject: subject.into_subject(),
            session_id,
            source,
            value,
            observed_at_unix,
            scope,
            reason_code,
        }
    }

    /// Internal constructor for core paths that have already consumed an
    /// approved boundary capability. Keeping this separate prevents the
    /// private authenticated subject from ever becoming a crate-level mint.
    fn from_authenticated(
        event_hash: [u8; 32],
        subject: AuthenticatedSubject,
        session_id: String,
        source: EvidenceSource,
        value: PreferenceValue,
        observed_at_unix: i64,
        scope: CommunicationScope,
        reason_code: &'static str,
    ) -> Self {
        Self {
            event_hash,
            subject,
            session_id,
            source,
            value,
            observed_at_unix,
            scope,
            reason_code,
        }
    }

    fn subject_id(&self) -> &str {
        self.subject.subject_id()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationKind {
    ExplicitCorrection,
    ResponseFeedback,
    PassiveOutcome,
}

impl ObservationKind {
    fn source(self) -> EvidenceSource {
        match self {
            Self::ExplicitCorrection => EvidenceSource::ExplicitCorrection,
            Self::ResponseFeedback => EvidenceSource::ResponseFeedback,
            Self::PassiveOutcome => EvidenceSource::PassiveOutcome,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceCandidate {
    pub value: PreferenceValue,
    pub reason_code: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationOutcome {
    pub recorded: usize,
    pub duplicates: usize,
    pub rate_limited: usize,
    pub inactive: bool,
    pub subject_revision: Option<u64>,
    pub state_revision: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledCommunicationPrompt {
    text: String,
    pub effect_hash: String,
    pub profile_revision: u64,
}

impl CompiledCommunicationPrompt {
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn into_string(self) -> String {
        self.text
    }
}

pub fn state_path(home: &Path) -> PathBuf {
    home.join(STATE_RELATIVE_PATH)
}

/// Domain-separated evidence identity. Callers pass an existing durable event
/// identity (WAL id, channel message id, or another stable receipt), never a
/// plaintext identifier that should appear in profile state.
pub fn evidence_event_hash(
    domain: &str,
    subject_id: &str,
    session_id: &str,
    event_identity: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [
        b"neoth.communication.evidence.v1".as_slice(),
        domain.as_bytes(),
        subject_id.as_bytes(),
        session_id.as_bytes(),
        event_identity,
    ] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn audit_subject_hash(subject_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"neoth.communication.audit-subject.v1\0");
    hasher.update(subject_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn observation_audit_payload(
    subject_id: &str,
    event_hash: [u8; 32],
    scope: &CommunicationScope,
    outcome: &ObservationOutcome,
    observed_at_unix: i64,
) -> Result<Option<Vec<u8>>> {
    if outcome.recorded == 0 {
        return Ok(None);
    }
    let subject_revision = outcome
        .subject_revision
        .context("communication observation changed state without a subject revision")?;
    let state_revision = outcome
        .state_revision
        .context("communication observation changed state without a state revision")?;
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "action": "observation_committed",
        "subject_sha256": audit_subject_hash(subject_id),
        "source_event_sha256": hex::encode(event_hash),
        "scope": scope.audit_code(),
        "recorded": outcome.recorded,
        "duplicates": outcome.duplicates,
        "rate_limited": outcome.rate_limited,
        "subject_revision": subject_revision,
        "state_revision": state_revision,
        "observed_at_unix": observed_at_unix,
    }))
    .context("serialize communication-profile update audit")
    .map(Some)
}

/// Append a content-poor audit receipt for a committed observation batch.
///
/// The profile JSON is the source of truth and is persisted before this call.
/// Callers must propagate an append failure rather than reporting a fully
/// audited success. The payload intentionally excludes message text,
/// preference values, reason codes, declared-context labels, and scope ids.
pub async fn append_observation_audit(
    home: &Path,
    writer: &crate::wal::writer::WalWriterHandle,
    subject_id: &str,
    event_hash: [u8; 32],
    scope: &CommunicationScope,
    outcome: &ObservationOutcome,
    observed_at_unix: i64,
) -> Result<()> {
    // Disabled/incognito/no-signal turns must not even inspect the state file.
    if outcome.recorded == 0 {
        return Ok(());
    }
    let current = ObservationAuditIntent {
        subject_id: subject_id.to_owned(),
        event_hash: hex::encode(event_hash),
        scope: scope.clone(),
        outcome: outcome.clone(),
        observed_at_unix,
    };
    let intents = with_state_lock(home, || {
        let state = load_state_unlocked(home)?;
        let mut pending = state.audit_pending.clone();
        if current.outcome.recorded > 0 && !pending.contains(&current) {
            pending.push(current.clone());
        }
        Ok(pending)
    })?;
    for intent in intents {
        let bytes: [u8; 32] = hex::decode(&intent.event_hash)
            .context("decode communication audit event hash")?
            .try_into()
            .map_err(|_| anyhow!("communication audit event hash has wrong length"))?;
        let Some(payload) = observation_audit_payload(
            &intent.subject_id,
            bytes,
            &intent.scope,
            &intent.outcome,
            intent.observed_at_unix,
        )?
        else {
            acknowledge_observation_audit(home, &intent)?;
            continue;
        };
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
                .event_subtype(
                    crate::wal::events::ExtendedSubtype::CommunicationProfileUpdated as u8,
                )
                .build();
        writer
            .append(header, payload)
            .await
            .context("append communication-profile update audit")?;
        acknowledge_observation_audit(home, &intent)?;
    }
    Ok(())
}

fn acknowledge_observation_audit(home: &Path, intent: &ObservationAuditIntent) -> Result<()> {
    with_state_lock(home, || {
        let mut state = load_state_unlocked(home)?;
        if let Some(index) = state.audit_pending.iter().position(|item| item == intent) {
            state.audit_pending.remove(index);
            persist_state_unlocked(home, &state)?;
        }
        Ok(())
    })
}

fn validate_subject_id(subject_id: &str) -> Result<()> {
    let trimmed = subject_id.trim();
    if trimmed.is_empty() {
        bail!("communication profile subject_id must not be empty");
    }
    if trimmed.len() > 256 || trimmed.chars().any(char::is_control) {
        bail!("communication profile subject_id is invalid");
    }
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<()> {
    let trimmed = session_id.trim();
    if trimmed.is_empty() || trimmed.len() > 256 || trimmed.chars().any(char::is_control) {
        bail!("communication profile session_id is invalid");
    }
    Ok(())
}

fn validate_scope(scope: &CommunicationScope) -> Result<()> {
    match scope {
        CommunicationScope::Channel(id) | CommunicationScope::Task(id)
            if id.trim().is_empty() || id.len() > 256 || id.chars().any(char::is_control) =>
        {
            bail!("communication evidence scope id is invalid");
        }
        _ => Ok(()),
    }
}

fn validate_scope_for_subject(
    scope: &CommunicationScope,
    subject: &AuthenticatedSubject,
) -> Result<()> {
    validate_scope(scope)?;
    if matches!(scope, CommunicationScope::Global) && !subject.permits_global_scope() {
        bail!("only an operator-origin proof may write global communication evidence");
    }
    Ok(())
}

fn is_full_auto_eligible(value: PreferenceValue) -> bool {
    matches!(
        value,
        PreferenceValue::Directness(_)
            | PreferenceValue::Structure(_)
            | PreferenceValue::Ambiguity(_)
            | PreferenceValue::ProcessingLoad(_)
            | PreferenceValue::ContextAmount(_)
    )
}

fn validate_reason_code(reason_code: &str) -> Result<()> {
    if reason_code.is_empty() || reason_code.len() > 96 || reason_code.chars().any(char::is_control)
    {
        bail!("communication evidence reason_code is invalid");
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_loaded_state(state: &CommunicationState) -> Result<()> {
    if state.subjects.len() > MAX_STATE_SUBJECTS {
        bail!("communication state contains too many subjects");
    }
    for (subject_id, subject) in &state.subjects {
        validate_subject_id(subject_id)?;
        if subject.revision > state.revision {
            bail!("communication subject revision exceeds state revision");
        }
        if subject.evidence.len() > CommunicationDimension::ALL.len()
            || subject.estimates.len() > CommunicationDimension::ALL.len()
        {
            bail!("communication subject contains too many dimensions");
        }
        for (dimension, evidence) in &subject.evidence {
            if evidence.len() > MAX_STATE_EVIDENCE_PER_DIMENSION {
                bail!("communication dimension contains too much evidence");
            }
            for item in evidence {
                if item.subject_id != *subject_id {
                    bail!("communication evidence crosses subject boundary");
                }
                if item.dimension() != *dimension {
                    bail!("communication evidence dimension key does not match its value");
                }
                if !item.legacy_authenticated_subject && item.authenticated_origin.is_none() {
                    bail!("communication state contains unauthenticated evidence");
                }
                if matches!(&item.scope, CommunicationScope::Global)
                    && (subject_id != COMMUNICATION_OPERATOR_SUBJECT
                        || !matches!(
                            item.authenticated_origin,
                            Some(AuthenticatedSubjectOrigin::LocalInteractiveOperator)
                                | Some(AuthenticatedSubjectOrigin::PinnedChannelOperator)
                                | Some(AuthenticatedSubjectOrigin::LegacyAuthenticated)
                        ))
                {
                    bail!("communication state global evidence lacks an operator origin");
                }
                if !is_lower_sha256(&item.event_hash) {
                    bail!("communication evidence event hash is invalid");
                }
                validate_session_id(&item.session_id)?;
                validate_scope(&item.scope)?;
                validate_reason_code(&item.reason_code)?;
            }
        }
        for (dimension, estimate) in &subject.estimates {
            if estimate.selected.dimension() != *dimension {
                bail!("communication estimate dimension key does not match its value");
            }
            if !estimate.confidence.is_finite()
                || !(0.0..=1.0).contains(&estimate.confidence)
                || !estimate.effective_weight.is_finite()
                || estimate.effective_weight < 0.0
                || estimate.distinct_sessions > estimate.observation_count
                || estimate.first_seen_unix > estimate.last_seen_unix
            {
                bail!("communication estimate metadata is invalid");
            }
            validate_scope(&estimate.scope_provenance)?;
            if estimate.durable_by_full_auto
                && (subject_id != COMMUNICATION_OPERATOR_SUBJECT
                    || !is_full_auto_eligible(estimate.selected)
                    || !matches!(&estimate.scope_provenance, CommunicationScope::Global))
            {
                bail!("communication durable estimate has unsafe or non-global provenance");
            }
        }
        if let Some(context) = &subject.declared_context
            && (!context.explicitly_asserted_by_operator
                || !is_lower_sha256(&context.source_event_hash)
                || context
                    .revoked_at_unix
                    .is_some_and(|revoked| revoked < context.set_at_unix))
        {
            bail!("declared communication context metadata is invalid");
        }
    }
    Ok(())
}

fn load_state_unlocked(home: &Path) -> Result<CommunicationState> {
    let path = state_path(home);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CommunicationState::default());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", path.display()));
        }
    };
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STATE_BYTES {
        bail!(
            "communication profile state exceeds {} bytes at {}",
            MAX_STATE_BYTES,
            path.display()
        );
    }
    if bytes.is_empty() {
        bail!("communication profile state is empty at {}", path.display());
    }
    let mut state: CommunicationState = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse communication profile state at {}", path.display()))?;
    if state.schema_version != STATE_SCHEMA_VERSION
        && state.schema_version != LEGACY_STATE_SCHEMA_VERSION
    {
        bail!(
            "unsupported communication profile schema {} at {}; expected {}",
            state.schema_version,
            path.display(),
            STATE_SCHEMA_VERSION
        );
    }
    // Schema-v1 persisted a caller-asserted Boolean. Preserve prior local
    // state without accepting that Boolean at any new API boundary: old true
    // entries receive an explicit compatibility origin before validation and
    // are rewritten with the typed field on the next mutation.
    let legacy_state = state.schema_version == LEGACY_STATE_SCHEMA_VERSION;
    for (subject_id, subject) in &mut state.subjects {
        for items in subject.evidence.values_mut() {
            for item in items {
                if item.authenticated_origin.is_none() && item.legacy_authenticated_subject {
                    item.authenticated_origin =
                        Some(AuthenticatedSubjectOrigin::LegacyAuthenticated);
                }
                if legacy_state
                    && subject_id != COMMUNICATION_OPERATOR_SUBJECT
                    && matches!(&item.scope, CommunicationScope::Global)
                {
                    item.scope = CommunicationScope::Task("legacy_unscoped".to_owned());
                }
            }
        }
        if legacy_state {
            for estimate in subject.estimates.values_mut() {
                if !is_full_auto_eligible(estimate.selected)
                    || subject_id != COMMUNICATION_OPERATOR_SUBJECT
                {
                    estimate.durable_by_full_auto = false;
                }
                if subject_id != COMMUNICATION_OPERATOR_SUBJECT {
                    // The related legacy evidence was quarantined above.
                    // Preserve that fact in the durable-state provenance so a
                    // missing v1 field cannot be rewritten as operator-global.
                    estimate.scope_provenance =
                        CommunicationScope::Task("legacy_unscoped".to_owned());
                }
            }
        }
    }
    if legacy_state {
        state.schema_version = STATE_SCHEMA_VERSION;
    }
    validate_loaded_state(&state)
        .with_context(|| format!("validate communication profile state at {}", path.display()))?;
    Ok(state)
}

fn persist_state_unlocked(home: &Path, state: &CommunicationState) -> Result<()> {
    validate_loaded_state(state).context("refuse invalid communication profile state")?;
    let path = state_path(home);
    let bytes =
        serde_json::to_vec_pretty(state).context("serialize communication profile state")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STATE_BYTES {
        bail!(
            "communication profile state would exceed {} bytes at {}",
            MAX_STATE_BYTES,
            path.display()
        );
    }
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("atomically write {}", path.display()))
}

fn with_state_lock<T>(home: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let process_lock = COMMUNICATION_STATE_LOCK.get_or_init(|| Mutex::new(()));
    let _process_guard = process_lock
        .lock()
        .map_err(|_| anyhow!("communication profile process lock poisoned"))?;
    let path = state_path(home);
    let _file_guard = crate::util::locked_file::lock_file_blocking(
        &path.with_extension("lock"),
        "communication profile",
    )
    .with_context(|| format!("lock communication profile at {}", path.display()))?;
    action()
}

/// Strict read for operator-facing inspection. Disabled/incognito callers use
/// [`load_subject`] which short-circuits before touching the filesystem.
pub fn load_state(home: &Path) -> Result<CommunicationState> {
    with_state_lock(home, || load_state_unlocked(home))
}

/// Strictly load and project the generic export record while holding the same
/// state lock as persistence. The returned DTO intentionally cannot carry the
/// persisted subject, evidence, or declared-context model.
pub fn load_redacted_export(home: &Path) -> Result<RedactedCommunicationProfileExport> {
    with_state_lock(home, || {
        let path = state_path(home);
        let state_present = path
            .try_exists()
            .with_context(|| format!("inspect communication profile at {}", path.display()))?;
        let state = load_state_unlocked(home)?;
        Ok(project_redacted_export(&state, state_present))
    })
}

fn project_redacted_export(
    state: &CommunicationState,
    state_present: bool,
) -> RedactedCommunicationProfileExport {
    let active_accommodations = state
        .subjects
        .get(COMMUNICATION_OPERATOR_SUBJECT)
        .into_iter()
        .flat_map(|subject| subject.estimates.iter())
        .filter_map(|(_, estimate)| estimate.active.then_some(estimate.selected))
        .collect();

    RedactedCommunicationProfileExport {
        export_schema_version: REDACTED_EXPORT_SCHEMA_VERSION,
        state_present,
        state_schema_version: state_present.then_some(state.schema_version),
        redacted: true,
        active_accommodations,
    }
}

pub fn load_subject(
    home: &Path,
    subject_id: &str,
    policy: &CommunicationProfileConfig,
    incognito: bool,
) -> Result<Option<SubjectCommunicationProfile>> {
    if !policy.enabled || incognito {
        return Ok(None);
    }
    validate_subject_id(subject_id)?;
    let state = load_state(home)?;
    Ok(state.subjects.get(subject_id).cloned())
}

fn effective_weight(
    evidence: &EvidenceRef,
    policy: &CommunicationProfileConfig,
    now_unix: i64,
) -> f64 {
    let Some(half_life_days) = evidence.source.half_life_days(policy) else {
        return evidence.source.base_weight();
    };
    let age_secs = now_unix.saturating_sub(evidence.observed_at_unix).max(0) as f64;
    let age_days = age_secs / 86_400.0;
    evidence.source.base_weight() * 2_f64.powf(-age_days / f64::from(half_life_days))
}

fn estimate_dimension(
    evidence: &[EvidenceRef],
    previous: Option<&DimensionEstimate>,
    policy: &CommunicationProfileConfig,
    now_unix: i64,
    full_auto: bool,
    target_scope: Option<&CommunicationScope>,
) -> Option<DimensionEstimate> {
    let eligible: Vec<&EvidenceRef> = evidence
        .iter()
        .filter(|item| item.authenticated_origin.is_some() && item.scope.applies_to(target_scope))
        .collect();
    if eligible.is_empty() {
        return None;
    }

    if let Some(explicit) = eligible
        .iter()
        .filter(|item| item.source == EvidenceSource::ExplicitSetting)
        .max_by_key(|item| (item.observed_at_unix, item.event_hash.as_str()))
    {
        let sessions = eligible
            .iter()
            .map(|item| item.session_id.as_str())
            .collect::<BTreeSet<_>>()
            .len() as u32;
        return Some(DimensionEstimate {
            selected: explicit.value,
            confidence: 1.0,
            effective_weight: 1.0,
            observation_count: eligible.len() as u32,
            distinct_sessions: sessions,
            first_seen_unix: eligible.iter().map(|item| item.observed_at_unix).min()?,
            last_seen_unix: eligible.iter().map(|item| item.observed_at_unix).max()?,
            active: true,
            pinned: true,
            durable_by_full_auto: false,
            scope_provenance: CommunicationScope::Global,
        });
    }

    // Full/Sovereign promotion means durable until the operator explicitly
    // replaces or resets the dimension. Later passive/feedback noise must not
    // silently undo the promise merely because decayed weights produce a new
    // temporary winner. The explicit-setting branch above remains the typed
    // override path; `reset_dimension` removes this estimate entirely.
    if let Some(previous) = previous.filter(|estimate| estimate.durable_by_full_auto) {
        let mut durable = previous.clone();
        durable.active = true;
        return Some(durable);
    }

    let mut weights: BTreeMap<PreferenceValue, f64> = BTreeMap::new();
    for item in &eligible {
        *weights.entry(item.value).or_default() += effective_weight(item, policy, now_unix);
    }
    let total_weight: f64 = weights.values().sum();
    if total_weight <= f64::EPSILON {
        return None;
    }
    let (selected, selected_weight) = weights.into_iter().max_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| right.0.cmp(&left.0))
    })?;
    let confidence = (selected_weight / total_weight) as f32;
    let sessions = eligible
        .iter()
        .map(|item| item.session_id.as_str())
        .collect::<BTreeSet<_>>()
        .len() as u32;
    let observation_count = eligible.len() as u32;
    // FULL-AUTO is intentionally narrower than ordinary passive application:
    // only presentation-only values may become durable, and only from the
    // explicit operator-global scope. Pace, clarification, correction and
    // other autonomy-adjacent behavior must remain non-durable until pinned.
    let promote_durable = full_auto
        && is_full_auto_eligible(selected)
        && target_scope.is_none()
        && observation_count >= policy.full_auto_min_observations
        && sessions >= policy.full_auto_min_distinct_sessions
        && confidence >= policy.full_auto_min_confidence;
    let durable_by_full_auto = promote_durable;
    let threshold_active = policy.auto_apply_low_risk
        && observation_count >= policy.min_observations
        && sessions >= policy.min_distinct_sessions
        && confidence >= policy.min_confidence;

    Some(DimensionEstimate {
        selected,
        confidence,
        effective_weight: selected_weight,
        observation_count,
        distinct_sessions: sessions,
        first_seen_unix: eligible.iter().map(|item| item.observed_at_unix).min()?,
        last_seen_unix: eligible.iter().map(|item| item.observed_at_unix).max()?,
        active: threshold_active || durable_by_full_auto,
        pinned: false,
        durable_by_full_auto,
        scope_provenance: target_scope.cloned().unwrap_or(CommunicationScope::Global),
    })
}

fn recompute_subject(
    subject: &mut SubjectCommunicationProfile,
    policy: &CommunicationProfileConfig,
    now_unix: i64,
    full_auto: bool,
) {
    let previous = subject.estimates.clone();
    subject.estimates.clear();
    for dimension in CommunicationDimension::ALL {
        let Some(evidence) = subject.evidence.get(&dimension) else {
            continue;
        };
        if let Some(estimate) = estimate_dimension(
            evidence,
            previous.get(&dimension),
            policy,
            now_unix,
            full_auto,
            None,
        ) {
            subject.estimates.insert(dimension, estimate);
        }
    }
}

fn prune_evidence(items: &mut Vec<EvidenceRef>, max: usize) {
    while items.len() > max {
        let remove_index = items
            .iter()
            .enumerate()
            .min_by_key(|(_, item)| {
                (
                    item.source.retention_priority(),
                    item.observed_at_unix,
                    item.event_hash.as_str(),
                )
            })
            .map(|(index, _)| index)
            .unwrap_or(0);
        items.remove(remove_index);
    }
}

fn validate_evidence_input(input: &EvidenceInput) -> Result<()> {
    validate_subject_id(input.subject_id())?;
    validate_session_id(&input.session_id)?;
    if input.event_hash.iter().all(|byte| *byte == 0) {
        bail!("communication evidence event_hash must not be zero");
    }
    if input.value.dimension().as_str().is_empty() {
        bail!("communication evidence dimension is invalid");
    }
    validate_reason_code(input.reason_code)?;
    validate_scope_for_subject(&input.scope, &input.subject)?;
    Ok(())
}

pub(crate) fn record_evidence_batch(
    home: &Path,
    policy: &CommunicationProfileConfig,
    inputs: &[EvidenceInput],
    full_auto: bool,
    incognito: bool,
) -> Result<ObservationOutcome> {
    policy
        .validate()
        .map_err(|error| anyhow!("invalid communication profile policy: {error}"))?;
    if !policy.enabled || incognito {
        return Ok(ObservationOutcome {
            inactive: true,
            ..ObservationOutcome::default()
        });
    }
    if inputs.is_empty() {
        return Ok(ObservationOutcome::default());
    }
    for input in inputs {
        validate_evidence_input(input)?;
    }
    let first_subject = inputs[0].subject_id();
    if inputs
        .iter()
        .any(|input| input.subject_id() != first_subject)
    {
        bail!("one communication evidence transaction may target only one subject");
    }

    with_state_lock(home, || {
        let mut state = load_state_unlocked(home)?;
        let subject = state.subjects.entry(first_subject.to_owned()).or_default();
        let mut outcome = ObservationOutcome::default();
        let mut newest_observation = i64::MIN;
        for input in inputs {
            let event_hash = hex::encode(input.event_hash);
            let dimension = input.value.dimension();
            let evidence = subject.evidence.entry(dimension).or_default();
            if evidence.iter().any(|item| item.event_hash == event_hash) {
                outcome.duplicates += 1;
                continue;
            }
            let day = input.observed_at_unix.div_euclid(86_400);
            let same_day_count = evidence
                .iter()
                .filter(|item| {
                    item.source == EvidenceSource::PassiveOutcome
                        && item.observed_at_unix.div_euclid(86_400) == day
                })
                .count();
            if input.source == EvidenceSource::PassiveOutcome
                && same_day_count >= MAX_EVIDENCE_PER_SUBJECT_PER_DAY_AND_DIMENSION
            {
                outcome.rate_limited += 1;
                continue;
            }
            evidence.push(EvidenceRef {
                event_hash,
                subject_id: input.subject_id().to_owned(),
                session_id: input.session_id.clone(),
                source: input.source,
                value: input.value,
                observed_at_unix: input.observed_at_unix,
                scope: input.scope.clone(),
                legacy_authenticated_subject: false,
                authenticated_origin: Some(input.subject.origin()),
                reason_code: input.reason_code.to_owned(),
            });
            prune_evidence(evidence, policy.max_evidence_per_dimension);
            newest_observation = newest_observation.max(input.observed_at_unix);
            outcome.recorded += 1;
        }

        if outcome.recorded > 0 {
            recompute_subject(subject, policy, newest_observation, full_auto);
            subject.revision = subject.revision.saturating_add(1);
            outcome.subject_revision = Some(subject.revision);
            state.revision = state.revision.saturating_add(1);
            outcome.state_revision = Some(state.revision);
            state.audit_pending.push(ObservationAuditIntent {
                subject_id: first_subject.to_owned(),
                event_hash: hex::encode(inputs[0].event_hash),
                scope: inputs[0].scope.clone(),
                outcome: outcome.clone(),
                observed_at_unix: newest_observation,
            });
            persist_state_unlocked(home, &state)?;
        }
        Ok(outcome)
    })
}

pub(crate) fn record_evidence(
    home: &Path,
    policy: &CommunicationProfileConfig,
    input: EvidenceInput,
    full_auto: bool,
    incognito: bool,
) -> Result<ObservationOutcome> {
    record_evidence_batch(home, policy, &[input], full_auto, incognito)
}

/// Local, deterministic signal extraction. No text leaves this function and
/// no diagnostic label is produced. Callers must still bind the result to an
/// authenticated subject/session through [`record_text_observation`].
pub fn classify_text(text: &str, kind: ObservationKind) -> Vec<EvidenceCandidate> {
    let observable = observable_user_text(text);
    let lowered = observable.to_lowercase();
    let mut candidates = BTreeMap::<CommunicationDimension, EvidenceCandidate>::new();
    let mut add = |value: PreferenceValue, reason_code: &'static str| {
        candidates.insert(value.dimension(), EvidenceCandidate { value, reason_code });
    };

    let rejects_direct = contains_any(
        &lowered,
        &[
            "don't be direct",
            "do not be direct",
            "not so direct",
            "weniger direkt",
            "nicht so direkt",
            "sei nicht direkt",
        ],
    );
    if !rejects_direct
        && contains_any(
            &lowered,
            &[
                "sei direkt",
                "antworte direkt",
                "bitte direkt",
                "direkt und",
                "be direct",
                "answer directly",
                "straight to the point",
                "ohne filler",
                "kein filler",
                "no filler",
                "be blunt",
                "bluntly",
                "skip disclaimers",
                "keine floskeln",
            ],
        )
    {
        add(
            PreferenceValue::Directness(DirectnessPreference::Direct),
            "explicit_direct",
        );
    } else if contains_any(
        &lowered,
        &["sanft", "vorsichtig formul", "be gentle", "gentler"],
    ) {
        add(
            PreferenceValue::Directness(DirectnessPreference::Gentle),
            "explicit_gentle",
        );
    }

    let rejects_lists = contains_any(
        &lowered,
        &[
            "keine bullet points",
            "keine bullets",
            "keine stichpunkte",
            "keine nummerierten schritte",
            "keine liste",
            "no bullet points",
            "no bullets",
            "don't use bullets",
            "do not use bullets",
            "don't use numbered steps",
            "do not use numbered steps",
            "no lists",
        ],
    );
    if rejects_lists {
        add(
            PreferenceValue::Structure(StructurePreference::Prose),
            "explicit_prose",
        );
    } else if contains_any(
        &lowered,
        &[
            "nummeriert",
            "nummerierte schritte",
            "numbered steps",
            "schritt fuer schritt",
            "schritt für schritt",
        ],
    ) {
        add(
            PreferenceValue::Structure(StructurePreference::NumberedSteps),
            "explicit_numbered_steps",
        );
    } else if contains_any(
        &lowered,
        &["stichpunkte", "bullet points", "bullets", "als liste"],
    ) {
        add(
            PreferenceValue::Structure(StructurePreference::Bullets),
            "explicit_bullets",
        );
    } else if contains_any(
        &lowered,
        &["fließtext", "fliesstext", "in prose", "als fließtext"],
    ) {
        add(
            PreferenceValue::Structure(StructurePreference::Prose),
            "explicit_prose",
        );
    }

    if contains_any(
        &lowered,
        &[
            "sei explizit",
            "mach es explizit",
            "bitte explizit",
            "antworte wörtlich",
            "antworte woertlich",
            "be literal",
            "use literal language",
            "keine impliziten annahmen",
            "state assumptions",
            "annahmen nennen",
        ],
    ) {
        add(
            PreferenceValue::Ambiguity(AmbiguityPreference::LiteralExplicit),
            "explicit_literal",
        );
    } else if contains_any(
        &lowered,
        &[
            "zwischen den zeilen",
            "mitschwingt",
            "unterbewusst",
            "implied goal",
            "latent intent",
        ],
    ) {
        add(
            PreferenceValue::Ambiguity(AmbiguityPreference::Inferential),
            "explicit_inferential",
        );
    }

    let rejects_depth = contains_any(
        &lowered,
        &[
            "keine tiefenanalyse",
            "keine ausführliche antwort",
            "keine ausfuehrliche antwort",
            "nicht ausführlich",
            "nicht ausfuehrlich",
            "no deep dive",
            "not a deep dive",
            "don't want a deep dive",
            "do not want a deep dive",
            "don't do a deep dive",
            "do not do a deep dive",
            "don't be detailed",
            "do not be detailed",
        ],
    );
    if !rejects_depth
        && contains_any(
            &lowered,
            &[
                "bitte kurz",
                "halte dich kurz",
                "mach es kurz",
                "kurz antwort",
                "kuerzer",
                "kürzer",
                "kompakt antwort",
                "zu lang",
                "too long",
                "make it shorter",
                "be concise",
                "concise",
                "keep it concise",
            ],
        )
    {
        add(
            PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Compact),
            "explicit_compact",
        );
    } else if !rejects_depth
        && contains_any(
            &lowered,
            &[
                "ausfuehrlich",
                "ausführlich",
                "tiefenanalyse",
                "deep dive",
                "vollstaendig",
                "vollständig",
                "alles machen",
                "komplett bauen",
                "zu kurz",
                "too shallow",
                "more detail",
            ],
        )
    {
        add(
            PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Deep),
            "explicit_deep",
        );
    } else if !rejects_depth
        && contains_any(
            &lowered,
            &["eins nach dem anderen", "one chunk", "nur ein punkt"],
        )
    {
        add(
            PreferenceValue::ProcessingLoad(ProcessingLoadPreference::OneChunk),
            "explicit_one_chunk",
        );
    }

    if contains_any(
        &lowered,
        &[
            "behalte im kopf",
            "denk dran",
            "immer merken",
            "remember across",
            "ganzen kontext",
            "full context",
        ],
    ) {
        add(
            PreferenceValue::ContextAmount(ContextAmountPreference::ContinuityRich),
            "explicit_continuity",
        );
    } else if contains_any(
        &lowered,
        &[
            "kein recap",
            "ohne rueckblick",
            "ohne rückblick",
            "minimal context",
        ],
    ) {
        add(
            PreferenceValue::ContextAmount(ContextAmountPreference::Minimal),
            "explicit_minimal_context",
        );
    } else if contains_any(
        &lowered,
        &["kurzer recap", "short recap", "kurz zusammenfassen"],
    ) {
        add(
            PreferenceValue::ContextAmount(ContextAmountPreference::ShortRecap),
            "explicit_short_recap",
        );
    }

    let rejects_ask_before_next = contains_any(
        &lowered,
        &[
            "don't ask before next",
            "do not ask before next",
            "don't wait for me",
            "do not wait for me",
            "nicht vor jedem schritt fragen",
            "warte nicht auf mich",
        ],
    );
    if rejects_ask_before_next
        || contains_any(
            &lowered,
            &[
                "mach alles",
                "alles machen",
                "end to end",
                "fertig bauen",
                "bis es fertig",
                "do not stop",
                "nicht stoppen",
            ],
        )
    {
        add(
            PreferenceValue::Pace(PacePreference::ImmediateFull),
            "explicit_immediate_full",
        );
    } else if !rejects_ask_before_next
        && contains_any(
            &lowered,
            &[
                "warte auf mich",
                "ask before next",
                "vor jedem schritt fragen",
            ],
        )
    {
        add(
            PreferenceValue::Pace(PacePreference::AskBeforeNext),
            "explicit_ask_before_next",
        );
    } else if contains_any(&lowered, &["in etappen", "staged", "nach und nach"]) {
        add(
            PreferenceValue::Pace(PacePreference::Staged),
            "explicit_staged",
        );
    }

    if contains_any(
        &lowered,
        &[
            "nicht fragen",
            "keine rueckfragen",
            "keine rückfragen",
            "ohne rueckfragen",
            "ohne rückfragen",
            "don't ask",
            "do not ask",
            "no follow-up questions",
            "no follow up questions",
            "mach einfach",
            "act first",
            "use best judgment",
        ],
    ) {
        add(
            PreferenceValue::Clarification(ClarificationPreference::ActWithStatedAssumptions),
            "explicit_act_with_assumptions",
        );
    } else if contains_any(
        &lowered,
        &[
            "frag höchstens einmal",
            "frag hoechstens einmal",
            "ask at most one question",
            "maximal eine rückfrage",
        ],
    ) {
        add(
            PreferenceValue::Clarification(ClarificationPreference::AskOneQuestion),
            "explicit_one_question",
        );
    } else if contains_any(&lowered, &["frag erst", "clarify first", "erst nachfragen"]) {
        add(
            PreferenceValue::Clarification(ClarificationPreference::ClarifyFirst),
            "explicit_clarify_first",
        );
    }

    if contains_any(
        &lowered,
        &[
            "fixen und weiter",
            "einfach fixen",
            "silent fix",
            "nicht erklaeren",
            "nicht erklären",
        ],
    ) {
        add(
            PreferenceValue::CorrectionStyle(CorrectionStylePreference::SilentFix),
            "explicit_silent_fix",
        );
    } else if contains_any(
        &lowered,
        &[
            "erklaer warum",
            "erklär warum",
            "explain why when you fix",
            "explain the cause before fixing",
            "ursache nennen",
        ],
    ) {
        add(
            PreferenceValue::CorrectionStyle(CorrectionStylePreference::ExplainThenFix),
            "explicit_explain_then_fix",
        );
    } else if contains_any(
        &lowered,
        &["kurz bestaetigen", "kurz bestätigen", "acknowledge and fix"],
    ) {
        add(
            PreferenceValue::CorrectionStyle(CorrectionStylePreference::AcknowledgeAndFix),
            "explicit_acknowledge_and_fix",
        );
    }

    if kind == ObservationKind::PassiveOutcome {
        let char_count = observable.chars().count();
        if char_count >= 900 {
            candidates
                .entry(CommunicationDimension::ProcessingLoad)
                .or_insert(EvidenceCandidate {
                    value: PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Deep),
                    reason_code: "passive_long_context",
                });
            candidates
                .entry(CommunicationDimension::ContextAmount)
                .or_insert(EvidenceCandidate {
                    value: PreferenceValue::ContextAmount(ContextAmountPreference::ContinuityRich),
                    reason_code: "passive_context_carry",
                });
        }
        let numbered_lines = observable
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                trimmed.chars().next().is_some_and(|ch| ch.is_ascii_digit())
                    && (trimmed.contains('.') || trimmed.contains(')'))
            })
            .count();
        if numbered_lines >= 2 {
            candidates
                .entry(CommunicationDimension::Structure)
                .or_insert(EvidenceCandidate {
                    value: PreferenceValue::Structure(StructurePreference::NumberedSteps),
                    reason_code: "passive_numbered_structure",
                });
        } else {
            let bullet_lines = observable
                .lines()
                .filter(|line| {
                    let trimmed = line.trim_start();
                    trimmed.starts_with("- ")
                        || trimmed.starts_with("* ")
                        || trimmed.starts_with("• ")
                })
                .count();
            if bullet_lines >= 2 {
                candidates
                    .entry(CommunicationDimension::Structure)
                    .or_insert(EvidenceCandidate {
                        value: PreferenceValue::Structure(StructurePreference::Bullets),
                        reason_code: "passive_bullet_structure",
                    });
            }
        }
    }

    candidates.into_values().collect()
}

/// Remove common pasted/quoted/code regions before deterministic pattern
/// classification. The remaining string is ephemeral and is never persisted.
fn observable_user_text(text: &str) -> String {
    let mut in_fence = false;
    let mut output = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if is_forwarded_message_marker(trimmed) {
            // A forwarded mail/chat block has no reliable universal closing
            // delimiter. Treat the marker as the end of operator-authored
            // evidence; otherwise instructions in the forwarded body can
            // poison the local profile.
            break;
        }
        if in_fence || trimmed.starts_with('>') {
            continue;
        }
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&strip_inline_quoted_spans(line));
    }
    output
}

/// Remove short inline examples that are quoted or wrapped in backticks. This
/// deliberately does not treat apostrophes as delimiters, so contractions
/// such as `don't` remain observable as operator-authored text.
fn strip_inline_quoted_spans(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut closing_quote = None;
    for ch in line.chars() {
        if let Some(expected) = closing_quote {
            if ch == expected {
                closing_quote = None;
                if output
                    .chars()
                    .last()
                    .is_some_and(|previous| !previous.is_whitespace())
                {
                    output.push(' ');
                }
            }
            continue;
        }

        closing_quote = match ch {
            '"' => Some('"'),
            '`' => Some('`'),
            '“' => Some('”'),
            '„' => Some('“'),
            '«' => Some('»'),
            _ => None,
        };
        if closing_quote.is_none() {
            output.push(ch);
        }
    }
    output
}

fn is_forwarded_message_marker(line: &str) -> bool {
    let marker = line
        .trim()
        .trim_matches(|ch: char| matches!(ch, '-' | '_' | '='))
        .trim()
        .trim_end_matches(':')
        .trim()
        .to_lowercase();
    matches!(
        marker.as_str(),
        "forwarded message"
            | "begin forwarded message"
            | "original message"
            | "weitergeleitete nachricht"
            | "beginn der weitergeleiteten nachricht"
            | "ursprüngliche nachricht"
            | "urspruengliche nachricht"
    )
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn is_response_feedback_text(text: &str) -> bool {
    let observable = observable_user_text(text);
    let lowered = observable.to_lowercase();
    contains_any(
        &lowered,
        &[
            "deine antwort",
            "your answer",
            "das war",
            "that was",
            "genau so",
            "exactly like this",
            "besser so",
            "this format",
            "zu lang",
            "too long",
            "zu kurz",
            "too shallow",
        ],
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_text_observation(
    home: &Path,
    policy: &CommunicationProfileConfig,
    text: &str,
    kind: ObservationKind,
    event_hash: [u8; 32],
    subject: impl ApprovedCommunicationSubject,
    session_id: &str,
    observed_at_unix: i64,
    scope: CommunicationScope,
    full_auto: bool,
    incognito: bool,
) -> Result<ObservationOutcome> {
    if !policy.enabled || incognito {
        return Ok(ObservationOutcome {
            inactive: true,
            ..ObservationOutcome::default()
        });
    }
    let subject = subject.into_subject();
    let candidates = classify_text(text, kind);
    let inputs = candidates
        .into_iter()
        .map(|candidate| {
            EvidenceInput::from_authenticated(
                event_hash,
                subject.clone(),
                session_id.to_owned(),
                kind.source(),
                candidate.value,
                observed_at_unix,
                scope.clone(),
                candidate.reason_code,
            )
        })
        .collect::<Vec<_>>();
    record_evidence_batch(home, policy, &inputs, full_auto, incognito)
}

/// Record one accepted human turn in a single crash-safe transaction.
/// Natural-language corrections receive the stronger correction weight;
/// passive layout/length signals fill only dimensions not already explained
/// by an explicit signal in the same turn.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_authenticated_turn(
    home: &Path,
    policy: &CommunicationProfileConfig,
    text: &str,
    event_hash: [u8; 32],
    subject: impl ApprovedCommunicationSubject,
    session_id: &str,
    observed_at_unix: i64,
    scope: CommunicationScope,
    full_auto: bool,
    incognito: bool,
) -> Result<ObservationOutcome> {
    if !policy.enabled || incognito {
        return Ok(ObservationOutcome {
            inactive: true,
            ..ObservationOutcome::default()
        });
    }
    let subject = subject.into_subject();
    let primary_kind = if is_response_feedback_text(text) {
        ObservationKind::ResponseFeedback
    } else {
        ObservationKind::ExplicitCorrection
    };
    let primary = classify_text(text, primary_kind);
    let mut occupied = primary
        .iter()
        .map(|candidate| candidate.value.dimension())
        .collect::<BTreeSet<_>>();
    let passive = classify_text(text, ObservationKind::PassiveOutcome)
        .into_iter()
        .filter(|candidate| occupied.insert(candidate.value.dimension()));
    let mut inputs = primary
        .into_iter()
        .map(|candidate| {
            EvidenceInput::from_authenticated(
                event_hash,
                subject.clone(),
                session_id.to_owned(),
                primary_kind.source(),
                candidate.value,
                observed_at_unix,
                scope.clone(),
                candidate.reason_code,
            )
        })
        .collect::<Vec<_>>();
    inputs.extend(passive.map(|candidate| {
        EvidenceInput::from_authenticated(
            event_hash,
            subject.clone(),
            session_id.to_owned(),
            EvidenceSource::PassiveOutcome,
            candidate.value,
            observed_at_unix,
            scope.clone(),
            candidate.reason_code,
        )
    }));
    record_evidence_batch(home, policy, &inputs, full_auto, incognito)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn set_explicit_preference(
    home: &Path,
    policy: &CommunicationProfileConfig,
    proof: impl ApprovedCommunicationSubject,
    session_id: &str,
    value: PreferenceValue,
    event_hash: [u8; 32],
    observed_at_unix: i64,
    incognito: bool,
) -> Result<ObservationOutcome> {
    let subject = proof.into_subject();
    if !subject.permits_global_scope() {
        bail!("explicit communication preferences require an operator-global origin proof");
    }
    record_evidence(
        home,
        policy,
        EvidenceInput::from_authenticated(
            event_hash,
            subject,
            session_id.to_owned(),
            EvidenceSource::ExplicitSetting,
            value,
            observed_at_unix,
            CommunicationScope::Global,
            "explicit_setting",
        ),
        false,
        incognito,
    )
}

pub fn reset_dimension(
    home: &Path,
    policy: &CommunicationProfileConfig,
    subject_id: &str,
    dimension: CommunicationDimension,
    incognito: bool,
) -> Result<bool> {
    if !policy.enabled || incognito {
        return Ok(false);
    }
    validate_subject_id(subject_id)?;
    with_state_lock(home, || {
        let mut state = load_state_unlocked(home)?;
        let Some(subject) = state.subjects.get_mut(subject_id) else {
            return Ok(false);
        };
        let changed = subject.evidence.remove(&dimension).is_some()
            | subject.estimates.remove(&dimension).is_some();
        if changed {
            subject.revision = subject.revision.saturating_add(1);
            state.revision = state.revision.saturating_add(1);
            persist_state_unlocked(home, &state)?;
        }
        Ok(changed)
    })
}

pub(crate) fn declare_context(
    home: &Path,
    policy: &CommunicationProfileConfig,
    proof: impl ApprovedCommunicationSubject,
    kind: DeclaredContextKind,
    source_event_hash: [u8; 32],
    prompt_use: DeclaredContextPromptUse,
    set_at_unix: i64,
    incognito: bool,
) -> Result<bool> {
    if !policy.enabled || incognito {
        return Ok(false);
    }
    let subject_proof = proof.into_subject();
    if !subject_proof.permits_global_scope() {
        bail!("declared communication context requires an explicit operator-origin proof");
    }
    if source_event_hash.iter().all(|byte| *byte == 0) {
        bail!("declared context source_event_hash must not be zero");
    }
    with_state_lock(home, || {
        let mut state = load_state_unlocked(home)?;
        let subject = state
            .subjects
            .entry(subject_proof.subject_id().to_owned())
            .or_default();
        subject.declared_context = Some(DeclaredContext {
            kind,
            explicitly_asserted_by_operator: true,
            source_event_hash: hex::encode(source_event_hash),
            prompt_use,
            set_at_unix,
            revoked_at_unix: None,
        });
        subject.revision = subject.revision.saturating_add(1);
        state.revision = state.revision.saturating_add(1);
        persist_state_unlocked(home, &state)?;
        Ok(true)
    })
}

pub fn clear_declared_context(
    home: &Path,
    policy: &CommunicationProfileConfig,
    subject_id: &str,
    _cleared_at_unix: i64,
    incognito: bool,
) -> Result<bool> {
    if !policy.enabled || incognito {
        return Ok(false);
    }
    validate_subject_id(subject_id)?;
    with_state_lock(home, || {
        let mut state = load_state_unlocked(home)?;
        let Some(subject) = state.subjects.get_mut(subject_id) else {
            return Ok(false);
        };
        let Some(_) = subject.declared_context.as_ref() else {
            return Ok(false);
        };
        // A clear action is an erasure of the sensitive label, not merely a
        // prompt-export revocation. WAL control receipts remain metadata-only.
        subject.declared_context = None;
        subject.revision = subject.revision.saturating_add(1);
        state.revision = state.revision.saturating_add(1);
        persist_state_unlocked(home, &state)?;
        Ok(true)
    })
}

pub fn forget_subject(home: &Path, subject_id: &str) -> Result<bool> {
    validate_subject_id(subject_id)?;
    with_state_lock(home, || {
        let mut state = load_state_unlocked(home)?;
        let changed = state.subjects.remove(subject_id).is_some();
        if changed {
            state.revision = state.revision.saturating_add(1);
            persist_state_unlocked(home, &state)?;
        }
        Ok(changed)
    })
}

fn instruction_for(value: PreferenceValue) -> &'static str {
    match value {
        PreferenceValue::Directness(DirectnessPreference::Direct) => {
            "Be direct. Lead with the outcome and avoid filler."
        }
        PreferenceValue::Directness(DirectnessPreference::Balanced) => {
            "Use a direct but context-aware tone."
        }
        PreferenceValue::Directness(DirectnessPreference::Gentle) => {
            "Use a calm, gentle tone without obscuring the result."
        }
        PreferenceValue::Structure(StructurePreference::Prose) => {
            "Prefer cohesive prose unless exact steps are necessary."
        }
        PreferenceValue::Structure(StructurePreference::Bullets) => {
            "Use short bullet lists for parallel points."
        }
        PreferenceValue::Structure(StructurePreference::NumberedSteps) => {
            "Use numbered steps when describing an actionable sequence."
        }
        PreferenceValue::Ambiguity(AmbiguityPreference::LiteralExplicit) => {
            "Use literal language and state important assumptions explicitly."
        }
        PreferenceValue::Ambiguity(AmbiguityPreference::Balanced) => {
            "Balance explicit statements with reasonable contextual inference."
        }
        PreferenceValue::Ambiguity(AmbiguityPreference::Inferential) => {
            "Consider likely implied goals, but label assumptions and do not invent facts."
        }
        PreferenceValue::ProcessingLoad(ProcessingLoadPreference::OneChunk) => {
            "Present one manageable chunk at a time."
        }
        PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Compact) => {
            "Keep the response compact while preserving required actions and caveats."
        }
        PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Balanced) => {
            "Use a balanced response length: enough context for clarity without unnecessary expansion."
        }
        PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Deep) => {
            "Provide a complete, deep answer and close the request end to end."
        }
        PreferenceValue::ContextAmount(ContextAmountPreference::Minimal) => {
            "Do not repeat prior context unless it is required for correctness."
        }
        PreferenceValue::ContextAmount(ContextAmountPreference::ShortRecap) => {
            "Include only a short recap when continuity matters."
        }
        PreferenceValue::ContextAmount(ContextAmountPreference::ContinuityRich) => {
            "Carry forward relevant prior decisions and unfinished obligations."
        }
        PreferenceValue::Pace(PacePreference::ImmediateFull) => {
            "When authorized, complete the in-scope work before yielding."
        }
        PreferenceValue::Pace(PacePreference::Staged) => {
            "Stage complex work into visible milestones."
        }
        PreferenceValue::Pace(PacePreference::AskBeforeNext) => {
            "Pause before starting the next material stage."
        }
        PreferenceValue::Clarification(ClarificationPreference::ActWithStatedAssumptions) => {
            "Use reasonable in-scope assumptions, state material ones, and avoid unnecessary questions."
        }
        PreferenceValue::Clarification(ClarificationPreference::AskOneQuestion) => {
            "If blocked by ambiguity, ask at most one concise question."
        }
        PreferenceValue::Clarification(ClarificationPreference::ClarifyFirst) => {
            "Clarify material ambiguity before taking an irreversible action."
        }
        PreferenceValue::CorrectionStyle(CorrectionStylePreference::AcknowledgeAndFix) => {
            "Acknowledge corrections briefly, then fix the issue."
        }
        PreferenceValue::CorrectionStyle(CorrectionStylePreference::ExplainThenFix) => {
            "State the root cause concisely, then apply the fix."
        }
        PreferenceValue::CorrectionStyle(CorrectionStylePreference::SilentFix) => {
            "Apply straightforward corrections with minimal narration."
        }
    }
}

pub fn compile_prompt(
    home: &Path,
    subject_id: &str,
    policy: &CommunicationProfileConfig,
    target_scope: Option<&CommunicationScope>,
    incognito: bool,
) -> Result<Option<CompiledCommunicationPrompt>> {
    compile_prompt_at(
        home,
        subject_id,
        policy,
        target_scope,
        incognito,
        crate::time::now_unix_secs() as i64,
    )
}

fn compile_prompt_at(
    home: &Path,
    subject_id: &str,
    policy: &CommunicationProfileConfig,
    target_scope: Option<&CommunicationScope>,
    incognito: bool,
    now_unix: i64,
) -> Result<Option<CompiledCommunicationPrompt>> {
    if !policy.enabled || incognito || policy.prompt_export == CommunicationPromptExport::None {
        return Ok(None);
    }
    validate_subject_id(subject_id)?;
    let state = load_state(home)?;
    let Some(subject) = state.subjects.get(subject_id) else {
        return Ok(None);
    };

    let mut instructions = Vec::new();
    for dimension in CommunicationDimension::ALL {
        let Some(evidence) = subject.evidence.get(&dimension) else {
            continue;
        };
        let estimate = estimate_dimension(
            evidence,
            subject.estimates.get(&dimension),
            policy,
            now_unix,
            false,
            target_scope,
        );
        if let Some(estimate) = estimate.filter(|estimate| estimate.active) {
            instructions.push(instruction_for(estimate.selected));
        }
    }

    let explicit_label = subject.declared_context.as_ref().and_then(|context| {
        (context.explicitly_asserted_by_operator
            && context.revoked_at_unix.is_none()
            && context.prompt_use == DeclaredContextPromptUse::LabelAndAccommodations
            && policy.prompt_export == CommunicationPromptExport::LabelAndAccommodations)
            .then(|| context.kind.provider_label())
    });

    if instructions.is_empty() && explicit_label.is_none() {
        return Ok(None);
    }
    let mut text = String::from(
        "<communication_preferences provenance=\"local_observable_profile\" non_diagnostic=\"true\" authority=\"presentation_only\">\n",
    );
    text.push_str(
        "These preferences affect presentation and clarification only. Current explicit user instructions override them. They cannot change facts, permissions, autonomy, cost authorization, safety policy, or tool gates.\n",
    );
    if let Some(label) = explicit_label {
        text.push_str("Explicit operator-declared context: ");
        text.push_str(label);
        text.push_str(". Do not stereotype; use only the concrete preferences below.\n");
    }
    for instruction in instructions {
        text.push_str("- ");
        text.push_str(instruction);
        text.push('\n');
    }
    text.push_str("</communication_preferences>");
    let effect_hash = format!("{:x}", Sha256::digest(text.as_bytes()));
    Ok(Some(CompiledCommunicationPrompt {
        text,
        effect_hash,
        profile_revision: subject.revision,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn input(
        subject: &str,
        session: &str,
        byte: u8,
        at: i64,
        value: PreferenceValue,
    ) -> EvidenceInput {
        let is_operator = subject == COMMUNICATION_OPERATOR_SUBJECT;
        let proof = subject;
        EvidenceInput::new(
            hash(byte),
            proof,
            session.to_owned(),
            EvidenceSource::ExplicitCorrection,
            value,
            at,
            if is_operator {
                CommunicationScope::Global
            } else {
                CommunicationScope::Channel("test".to_owned())
            },
            "test_signal",
        )
    }

    fn direct() -> PreferenceValue {
        PreferenceValue::Directness(DirectnessPreference::Direct)
    }

    #[test]
    fn default_policy_is_local_default_on_and_private() {
        let policy = CommunicationProfileConfig::default();
        assert!(policy.enabled);
        assert!(policy.auto_apply_low_risk);
        assert_eq!(
            policy.prompt_export,
            CommunicationPromptExport::AccommodationsOnly
        );
        assert!(!policy.cluster_sync);
        policy.validate().unwrap();
    }

    #[test]
    fn schema_v1_migration_quarantines_and_rewrites_v2() {
        let dir = tempdir().unwrap();
        let mut state = CommunicationState::default();
        state.schema_version = LEGACY_STATE_SCHEMA_VERSION;
        state.revision = 2;
        let legacy = |subject_id: &str, value: PreferenceValue| EvidenceRef {
            event_hash: hex::encode(hash(if subject_id == "operator" { 1 } else { 2 })),
            subject_id: subject_id.to_owned(),
            session_id: "legacy-session".to_owned(),
            source: EvidenceSource::ExplicitCorrection,
            value,
            observed_at_unix: 1,
            scope: CommunicationScope::Global,
            legacy_authenticated_subject: true,
            authenticated_origin: None,
            reason_code: "legacy_signal".to_owned(),
        };
        let unsafe_pace = PreferenceValue::Pace(PacePreference::AskBeforeNext);
        let direct_value = direct();
        let estimate = |value: PreferenceValue| DimensionEstimate {
            selected: value,
            confidence: 1.0,
            effective_weight: 1.0,
            observation_count: 1,
            distinct_sessions: 1,
            first_seen_unix: 1,
            last_seen_unix: 1,
            active: true,
            pinned: false,
            durable_by_full_auto: true,
            scope_provenance: CommunicationScope::Global,
        };
        state.subjects.insert(
            "operator".to_owned(),
            SubjectCommunicationProfile {
                revision: 1,
                evidence: BTreeMap::from([(
                    CommunicationDimension::Pace,
                    vec![legacy("operator", unsafe_pace)],
                )]),
                estimates: BTreeMap::from([(CommunicationDimension::Pace, estimate(unsafe_pace))]),
                declared_context: None,
            },
        );
        state.subjects.insert(
            "alice".to_owned(),
            SubjectCommunicationProfile {
                revision: 1,
                evidence: BTreeMap::from([(
                    CommunicationDimension::Directness,
                    vec![legacy("alice", direct_value)],
                )]),
                estimates: BTreeMap::from([(
                    CommunicationDimension::Directness,
                    estimate(direct_value),
                )]),
                declared_context: None,
            },
        );
        let path = state_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut legacy_json = serde_json::to_value(&state).unwrap();
        for subject in ["operator", "alice"] {
            for evidence in legacy_json["subjects"][subject]["evidence"]
                .as_object_mut()
                .unwrap()
                .values_mut()
            {
                evidence.as_array_mut().unwrap()[0]["authenticated_subject"] =
                    serde_json::Value::Bool(true);
            }
            for estimate in legacy_json["subjects"][subject]["estimates"]
                .as_object_mut()
                .unwrap()
                .values_mut()
            {
                estimate.as_object_mut().unwrap().remove("scope_provenance");
            }
        }
        std::fs::write(&path, serde_json::to_vec(&legacy_json).unwrap()).unwrap();

        let migrated = load_state(dir.path()).unwrap();
        assert_eq!(migrated.schema_version, STATE_SCHEMA_VERSION);
        assert_eq!(
            migrated.subjects["operator"].estimates[&CommunicationDimension::Pace].scope_provenance,
            CommunicationScope::Global
        );
        assert!(
            !migrated.subjects["operator"].estimates[&CommunicationDimension::Pace]
                .durable_by_full_auto
        );
        assert!(
            !migrated.subjects["alice"].estimates[&CommunicationDimension::Directness]
                .durable_by_full_auto
        );
        assert_eq!(
            migrated.subjects["alice"].estimates[&CommunicationDimension::Directness]
                .scope_provenance,
            CommunicationScope::Task("legacy_unscoped".to_owned())
        );
        assert!(matches!(
            migrated.subjects["alice"].evidence[&CommunicationDimension::Directness][0].scope,
            CommunicationScope::Task(ref value) if value == "legacy_unscoped"
        ));
        set_explicit_preference(
            dir.path(),
            &CommunicationProfileConfig::default(),
            "operator",
            "rewrite-session",
            direct(),
            hash(9),
            2,
            false,
        )
        .unwrap();
        let bytes = std::fs::read(path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema_version"], STATE_SCHEMA_VERSION);
        assert!(
            !serde_json::to_string(&value)
                .unwrap()
                .contains("authenticated_subject")
        );
        assert_eq!(
            value["subjects"]["operator"]["estimates"]["pace"]["scope_provenance"]["kind"],
            "global"
        );
        assert_eq!(
            value["subjects"]["alice"]["estimates"]["directness"]["scope_provenance"]["kind"],
            "task"
        );
        assert_eq!(
            value["subjects"]["alice"]["estimates"]["directness"]["scope_provenance"]["id"],
            "legacy_unscoped"
        );
    }

    #[test]
    fn production_proof_api_has_no_crate_wide_minter_or_boolean_authority() {
        let source = include_str!("communication.rs");
        assert!(!source.contains(&["local_", "interactive_operator"].concat()));
        assert!(!source.contains(&["channel_", "identity("].concat()));
        assert!(!source.contains(&["Operator", "OriginProof"].concat()));
        assert!(!source.contains(&["authenticated_subject", ": bool"].concat()));
        assert!(source.contains("pub(in crate::profile) trait Sealed"));
        assert!(source.contains("#[cfg(test)]\nimpl ApprovedCommunicationSubject for &str"));
    }

    #[test]
    fn full_auto_refuses_unsafe_pace_after_all_thresholds_are_met() {
        let dir = tempdir().unwrap();
        let mut policy = CommunicationProfileConfig::default();
        policy.min_observations = 1;
        policy.min_distinct_sessions = 1;
        policy.min_confidence = 0.5;
        policy.full_auto_min_observations = 1;
        policy.full_auto_min_distinct_sessions = 1;
        policy.full_auto_min_confidence = 0.5;
        record_evidence(
            dir.path(),
            &policy,
            input(
                "operator",
                "s1",
                1,
                1,
                PreferenceValue::Pace(PacePreference::AskBeforeNext),
            ),
            true,
            false,
        )
        .unwrap();
        let estimate = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap()
            .estimates
            .get(&CommunicationDimension::Pace)
            .cloned()
            .unwrap();
        assert!(!estimate.durable_by_full_auto);
    }

    #[test]
    fn channel_scope_never_becomes_a_global_estimate() {
        let dir = tempdir().unwrap();
        let mut policy = CommunicationProfileConfig::default();
        policy.min_observations = 1;
        policy.min_distinct_sessions = 1;
        policy.min_confidence = 0.5;
        let channel = CommunicationScope::Channel("telegram".to_owned());
        let evidence = EvidenceInput::new(
            hash(1),
            "alice",
            "channel:s1".to_owned(),
            EvidenceSource::ExplicitCorrection,
            direct(),
            1,
            channel.clone(),
            "test_signal",
        );
        record_evidence(dir.path(), &policy, evidence, true, false).unwrap();
        assert!(
            compile_prompt_at(dir.path(), "alice", &policy, None, false, 2)
                .unwrap()
                .is_none()
        );
        assert!(
            compile_prompt_at(dir.path(), "alice", &policy, Some(&channel), false, 2)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn non_operator_proof_cannot_declare_context() {
        let dir = tempdir().unwrap();
        let error = declare_context(
            dir.path(),
            &CommunicationProfileConfig::default(),
            "alice",
            DeclaredContextKind::Adhd,
            hash(1),
            DeclaredContextPromptUse::AccommodationsOnly,
            1,
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("operator-origin proof"));
    }

    #[test]
    fn evidence_hash_is_stable_and_domain_separated() {
        let first = evidence_event_hash("cli", "operator", "s1", b"42");
        assert_eq!(first, evidence_event_hash("cli", "operator", "s1", b"42"));
        assert_ne!(
            first,
            evidence_event_hash("channel", "operator", "s1", b"42")
        );
        assert_ne!(first, evidence_event_hash("cli", "other", "s1", b"42"));
    }

    #[test]
    fn classifier_recognises_preferences_but_never_diagnoses() {
        let candidates = classify_text(
            "Mach alles vollstaendig, direkt und ohne Rueckfragen. Lies auch was mitschwingt.",
            ObservationKind::ExplicitCorrection,
        );
        assert!(candidates.iter().any(|item| item.value == direct()));
        assert!(candidates.iter().any(|item| {
            item.value
                == PreferenceValue::Clarification(ClarificationPreference::ActWithStatedAssumptions)
        }));
        let json = serde_json::to_string(
            &candidates
                .iter()
                .map(|item| item.reason_code)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(!json.contains("autis"));
        assert!(!json.contains("adhd"));
        assert!(!json.contains("diagnos"));
    }

    #[test]
    fn classifier_ignores_quoted_and_fenced_instructions() {
        let candidates = classify_text(
            "> be direct\n```text\nno filler and do not ask questions\n```\nordinary content",
            ObservationKind::ExplicitCorrection,
        );
        assert!(candidates.is_empty());
    }

    #[test]
    fn classifier_respects_negation_and_inline_examples() {
        let cases = [
            ("don't be direct", CommunicationDimension::Directness),
            (
                "I don't want a deep dive",
                CommunicationDimension::ProcessingLoad,
            ),
            (
                "test phrase \"be direct and no filler\"",
                CommunicationDimension::Directness,
            ),
            (
                "the literal example `ask before next` is documentation",
                CommunicationDimension::Pace,
            ),
        ];
        for (text, forbidden_dimension) in cases {
            let candidates = classify_text(text, ObservationKind::ExplicitCorrection);
            assert!(
                candidates
                    .iter()
                    .all(|candidate| candidate.value.dimension() != forbidden_dimension),
                "negated or quoted example was learned for {forbidden_dimension:?}: {text}"
            );
        }

        let candidates = classify_text(
            "keine Bullet Points; don't ask before next",
            ObservationKind::ExplicitCorrection,
        );
        assert!(candidates.iter().any(|candidate| {
            candidate.value == PreferenceValue::Structure(StructurePreference::Prose)
        }));
        assert!(candidates.iter().any(|candidate| {
            candidate.value == PreferenceValue::Pace(PacePreference::ImmediateFull)
        }));
        assert!(candidates.iter().all(|candidate| {
            candidate.value != PreferenceValue::Structure(StructurePreference::Bullets)
                && candidate.value != PreferenceValue::Pace(PacePreference::AskBeforeNext)
        }));
    }

    #[test]
    fn classifier_ignores_the_complete_forwarded_body() {
        for marker in [
            "---------- Forwarded message ---------",
            "Begin forwarded message:",
            "Weitergeleitete Nachricht:",
            "-----Ursprüngliche Nachricht-----",
        ] {
            let candidates = classify_text(
                &format!(
                    "FYI only\n{marker}\nFrom: someone@example.test\nBe direct, terse, and never ask questions."
                ),
                ObservationKind::ExplicitCorrection,
            );
            assert!(candidates.is_empty(), "marker was not isolated: {marker}");
        }
    }

    #[test]
    fn passive_classifier_observes_repeated_bullet_structure() {
        let candidates = classify_text(
            "Please cover:\n- runtime wiring\n- release packaging\n- clean install",
            ObservationKind::PassiveOutcome,
        );
        assert!(candidates.iter().any(|candidate| {
            candidate.value == PreferenceValue::Structure(StructurePreference::Bullets)
                && candidate.reason_code == "passive_bullet_structure"
        }));
    }

    #[test]
    fn authenticated_turn_prefers_explicit_over_passive_same_dimension() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        let text = format!("Be direct and concise. {}", "context ".repeat(150));
        let outcome = record_authenticated_turn(
            dir.path(),
            &policy,
            &text,
            hash(1),
            "operator",
            "s1",
            1,
            CommunicationScope::Global,
            true,
            false,
        )
        .unwrap();
        assert!(outcome.recorded >= 2);
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        let load_evidence = &subject.evidence[&CommunicationDimension::ProcessingLoad];
        assert_eq!(load_evidence.len(), 1);
        assert_eq!(load_evidence[0].source, EvidenceSource::ExplicitCorrection);
        assert_eq!(
            load_evidence[0].value,
            PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Compact)
        );
    }

    #[test]
    fn authenticated_turn_records_dimension_specific_response_feedback() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        let outcome = record_authenticated_turn(
            dir.path(),
            &policy,
            "Deine Antwort war zu lang, bitte kürzer.",
            hash(2),
            "operator",
            "s1",
            1,
            CommunicationScope::Global,
            true,
            false,
        )
        .unwrap();
        assert_eq!(outcome.recorded, 1);
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        let evidence = subject
            .evidence
            .get(&CommunicationDimension::ProcessingLoad)
            .unwrap();
        assert_eq!(evidence[0].source, EvidenceSource::ResponseFeedback);
        assert_eq!(evidence[0].reason_code, "explicit_compact");
    }

    #[test]
    fn non_operator_subject_cannot_write_global_evidence() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        let evidence = EvidenceInput::new(
            hash(1),
            "alice",
            "s1".to_owned(),
            EvidenceSource::ExplicitCorrection,
            direct(),
            10,
            CommunicationScope::Global,
            "test_signal",
        );
        let error = record_evidence(dir.path(), &policy, evidence, false, false).unwrap_err();
        assert!(error.to_string().contains("operator origin"));
        assert!(!state_path(dir.path()).exists());
    }

    #[test]
    fn passive_estimate_needs_observations_sessions_and_confidence() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        for (byte, session) in [(1, "s1"), (2, "s1"), (3, "s2"), (4, "s2")] {
            record_evidence(
                dir.path(),
                &policy,
                input(
                    "operator",
                    session,
                    byte,
                    i64::from(byte) * 86_400,
                    direct(),
                ),
                false,
                false,
            )
            .unwrap();
        }
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        assert!(!subject.estimates[&CommunicationDimension::Directness].active);
        record_evidence(
            dir.path(),
            &policy,
            input("operator", "s3", 5, 5 * 86_400, direct()),
            false,
            false,
        )
        .unwrap();
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        let estimate = &subject.estimates[&CommunicationDimension::Directness];
        assert!(estimate.active);
        assert_eq!(estimate.observation_count, 5);
        assert_eq!(estimate.distinct_sessions, 3);
    }

    #[test]
    fn explicit_setting_is_immediately_pinned() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        set_explicit_preference(
            dir.path(),
            &policy,
            "operator",
            "settings",
            PreferenceValue::Structure(StructurePreference::NumberedSteps),
            hash(1),
            100,
            false,
        )
        .unwrap();
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        let estimate = &subject.estimates[&CommunicationDimension::Structure];
        assert!(estimate.active);
        assert!(estimate.pinned);
        assert_eq!(estimate.confidence, 1.0);
    }

    #[test]
    fn full_auto_promotes_only_after_stricter_thresholds() {
        let dir = tempdir().unwrap();
        let mut policy = CommunicationProfileConfig::default();
        policy.max_evidence_per_dimension = 64;
        for byte in 1..=10 {
            let mut evidence = input(
                "operator",
                &format!("s{}", ((byte - 1) % 5) + 1),
                byte,
                i64::from(byte) * 86_400,
                direct(),
            );
            evidence.source = EvidenceSource::PassiveOutcome;
            record_evidence(dir.path(), &policy, evidence, true, false).unwrap();
        }
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        let estimate = &subject.estimates[&CommunicationDimension::Directness];
        assert!(estimate.durable_by_full_auto);
        assert!(estimate.active);
        assert_eq!(estimate.selected, direct());

        for byte in 11..=30 {
            let mut evidence = input(
                "operator",
                &format!("later-{byte}"),
                byte,
                i64::from(byte) * 86_400,
                PreferenceValue::Directness(DirectnessPreference::Gentle),
            );
            evidence.source = EvidenceSource::ResponseFeedback;
            record_evidence(dir.path(), &policy, evidence, true, false).unwrap();
        }
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        let estimate = &subject.estimates[&CommunicationDimension::Directness];
        assert_eq!(estimate.selected, direct());
        assert!(estimate.durable_by_full_auto);

        set_explicit_preference(
            dir.path(),
            &policy,
            "operator",
            "settings",
            PreferenceValue::Directness(DirectnessPreference::Gentle),
            hash(31),
            31 * 86_400,
            false,
        )
        .unwrap();
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        let estimate = &subject.estimates[&CommunicationDimension::Directness];
        assert_eq!(
            estimate.selected,
            PreferenceValue::Directness(DirectnessPreference::Gentle)
        );
        assert!(estimate.pinned);
        assert!(!estimate.durable_by_full_auto);
    }

    #[test]
    fn duplicate_event_counts_once_per_dimension() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        let evidence = input("operator", "s1", 1, 100, direct());
        assert_eq!(
            record_evidence(dir.path(), &policy, evidence.clone(), false, false)
                .unwrap()
                .recorded,
            1
        );
        let outcome = record_evidence(dir.path(), &policy, evidence, false, false).unwrap();
        assert_eq!(outcome.recorded, 0);
        assert_eq!(outcome.duplicates, 1);
    }

    #[test]
    fn daily_cap_limits_passive_poisoning_without_blocking_operator_feedback() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        for byte in 1..=5 {
            let mut evidence = input("operator", "s1", byte, 100, direct());
            evidence.source = EvidenceSource::PassiveOutcome;
            let outcome = record_evidence(dir.path(), &policy, evidence, false, false).unwrap();
            if byte == 5 {
                assert_eq!(outcome.rate_limited, 1);
            }
        }
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        assert_eq!(
            subject.evidence[&CommunicationDimension::Directness].len(),
            4
        );

        let mut correction = input(
            "operator",
            "s1",
            6,
            100,
            PreferenceValue::Directness(DirectnessPreference::Gentle),
        );
        correction.source = EvidenceSource::ExplicitCorrection;
        let outcome = record_evidence(dir.path(), &policy, correction, false, false).unwrap();
        assert_eq!(outcome.recorded, 1);
        assert_eq!(outcome.rate_limited, 0);

        let mut feedback = input("operator", "s1", 7, 100, direct());
        feedback.source = EvidenceSource::ResponseFeedback;
        let outcome = record_evidence(dir.path(), &policy, feedback, false, false).unwrap();
        assert_eq!(outcome.recorded, 1);
        assert_eq!(outcome.rate_limited, 0);
    }

    #[test]
    fn subjects_are_strictly_isolated() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        set_test_scoped_preference(dir.path(), &policy, "alice", "s1", direct(), hash(1), 1)
            .unwrap();
        assert!(
            load_subject(dir.path(), "alice", &policy, false)
                .unwrap()
                .is_some()
        );
        assert!(
            load_subject(dir.path(), "bob", &policy, false)
                .unwrap()
                .is_none()
        );
        assert!(
            compile_prompt(dir.path(), "bob", &policy, None, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn incognito_performs_zero_reads_and_writes() {
        let dir = tempdir().unwrap();
        let path = state_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not json").unwrap();
        let policy = CommunicationProfileConfig::default();
        assert!(
            load_subject(dir.path(), "operator", &policy, true)
                .unwrap()
                .is_none()
        );
        assert!(
            compile_prompt(dir.path(), "operator", &policy, None, true)
                .unwrap()
                .is_none()
        );
        let outcome = record_text_observation(
            dir.path(),
            &policy,
            "be direct",
            ObservationKind::ExplicitCorrection,
            hash(1),
            "operator",
            "s1",
            1,
            CommunicationScope::Global,
            true,
            true,
        )
        .unwrap();
        assert!(outcome.inactive);
        assert_eq!(std::fs::read(&path).unwrap(), b"not json");
    }

    #[test]
    fn persisted_state_contains_no_raw_message() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        let raw = "Be direct. private phrase 8f4c2e9a must never persist";
        record_text_observation(
            dir.path(),
            &policy,
            raw,
            ObservationKind::ExplicitCorrection,
            hash(1),
            "operator",
            "s1",
            1,
            CommunicationScope::Global,
            true,
            false,
        )
        .unwrap();
        let bytes = std::fs::read(state_path(dir.path())).unwrap();
        let body = String::from_utf8(bytes).unwrap();
        assert!(!body.contains("private phrase"));
        assert!(!body.contains("8f4c2e9a"));
        assert!(body.contains("explicit_direct"));
    }

    #[test]
    fn loaded_state_rejects_unknown_content_and_cross_subject_evidence() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        set_explicit_preference(
            dir.path(),
            &policy,
            "operator",
            "s1",
            direct(),
            hash(1),
            1,
            false,
        )
        .unwrap();
        let path = state_path(dir.path());
        let original = std::fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["subjects"]["operator"]["raw_text"] = serde_json::json!("must not persist");
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let unknown = format!("{:#}", load_state(dir.path()).unwrap_err());
        assert!(unknown.contains("unknown field"), "{unknown}");

        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["subjects"]["operator"]["evidence"]["directness"][0]["subject_id"] =
            serde_json::json!("other-subject");
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let crossed = format!("{:#}", load_state(dir.path()).unwrap_err());
        assert!(crossed.contains("crosses subject boundary"), "{crossed}");
    }

    #[test]
    fn accommodations_prompt_is_bounded_and_non_diagnostic() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        set_explicit_preference(
            dir.path(),
            &policy,
            "operator",
            "s1",
            direct(),
            hash(1),
            1,
            false,
        )
        .unwrap();
        declare_context(
            dir.path(),
            &policy,
            "operator",
            DeclaredContextKind::Autistic,
            hash(2),
            DeclaredContextPromptUse::LabelAndAccommodations,
            2,
            false,
        )
        .unwrap();
        let prompt = compile_prompt_at(dir.path(), "operator", &policy, None, false, 3)
            .unwrap()
            .unwrap();
        assert!(prompt.as_str().contains("authority=\"presentation_only\""));
        assert!(prompt.as_str().contains("Be direct"));
        assert!(!prompt.as_str().contains("autistic"));
        assert!(prompt.as_str().len() < 2_000);
    }

    #[test]
    fn explicit_label_requires_two_separate_export_choices() {
        let dir = tempdir().unwrap();
        let mut policy = CommunicationProfileConfig::default();
        set_explicit_preference(
            dir.path(),
            &policy,
            "operator",
            "s1",
            direct(),
            hash(1),
            1,
            false,
        )
        .unwrap();
        declare_context(
            dir.path(),
            &policy,
            "operator",
            DeclaredContextKind::Adhd,
            hash(2),
            DeclaredContextPromptUse::LabelAndAccommodations,
            2,
            false,
        )
        .unwrap();
        let safe = compile_prompt_at(dir.path(), "operator", &policy, None, false, 3)
            .unwrap()
            .unwrap();
        assert!(!safe.as_str().contains("ADHD"));
        policy.prompt_export = CommunicationPromptExport::LabelAndAccommodations;
        let opted_in = compile_prompt_at(dir.path(), "operator", &policy, None, false, 3)
            .unwrap()
            .unwrap();
        assert!(opted_in.as_str().contains("ADHD"));
    }

    #[test]
    fn observation_audit_is_metadata_only_and_skips_noop_batches() {
        let scope = CommunicationScope::Channel("whatsapp:+49123456789".to_owned());
        let outcome = ObservationOutcome {
            recorded: 2,
            duplicates: 1,
            rate_limited: 0,
            inactive: false,
            subject_revision: Some(4),
            state_revision: Some(9),
        };
        let payload = observation_audit_payload(
            "operator-secret-id",
            hash(7),
            &scope,
            &outcome,
            1_700_000_000,
        )
        .unwrap()
        .unwrap();
        let body = String::from_utf8(payload).unwrap();
        assert!(!body.contains("operator-secret-id"));
        assert!(!body.contains("+49123456789"));
        assert!(!body.contains("whatsapp"));
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["scope"], "channel");
        assert_eq!(value["recorded"], 2);
        assert_eq!(value["subject_revision"], 4);
        assert_eq!(value["state_revision"], 9);
        assert_eq!(value["source_event_sha256"], hex::encode(hash(7)));

        assert!(
            observation_audit_payload(
                "operator",
                hash(8),
                &CommunicationScope::Global,
                &ObservationOutcome::default(),
                1,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn reset_and_forget_remove_derived_state() {
        let dir = tempdir().unwrap();
        let policy = CommunicationProfileConfig::default();
        set_explicit_preference(
            dir.path(),
            &policy,
            "operator",
            "s1",
            direct(),
            hash(1),
            1,
            false,
        )
        .unwrap();
        assert!(
            reset_dimension(
                dir.path(),
                &policy,
                "operator",
                CommunicationDimension::Directness,
                false,
            )
            .unwrap()
        );
        let subject = load_subject(dir.path(), "operator", &policy, false)
            .unwrap()
            .unwrap();
        assert!(subject.evidence.is_empty());
        assert!(forget_subject(dir.path(), "operator").unwrap());
        assert!(
            load_subject(dir.path(), "operator", &policy, false)
                .unwrap()
                .is_none()
        );
    }
}
