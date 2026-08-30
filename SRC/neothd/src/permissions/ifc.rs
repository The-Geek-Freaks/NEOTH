//! A small, pure information-flow-control policy kernel.
//!
//! Labels describe a caller's asserted sensitivity, not evidence that the
//! caller obtained the data through a trustworthy path. In particular, model
//! output, tool metadata, and other untrusted input must not be treated as
//! provenance merely by attaching an [`InformationLabel`]. The gate/provenance
//! consumer that will be added separately must establish that boundary before
//! calling this module.
//!
//! A destination clearance is the *maximum* label the destination is allowed
//! to receive. The policy therefore permits a flow only when the highest source
//! label is less than or equal to that clearance; it never relabels data or
//! assumes a missing label is public. `ExternalHttpRequest` and
//! `McpToolInvocation` are deliberately public-clearance egress boundaries.

use std::{
    cmp::Ordering,
    collections::BTreeSet,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering as AtomicOrdering},
    },
};

use sha2::{Digest, Sha256};

use super::ActionKind;

/// Hard cap for the one-request pinned-channel research release. Enforced at
/// parsing and again at the capability-scoped execution boundary.
pub(crate) const MAX_OPERATOR_RELEASED_RESEARCH_TOPIC_BYTES: usize = 2_048;

/// Ordered information-sensitivity lattice used by the IFC kernel.
///
/// The numeric declaration order is the ACS policy order: `Public < Internal <
/// Confidential < Secret`. `Secret` is the highest sensitivity and can flow
/// only to destinations with secret clearance.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InformationLabel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3,
}

impl InformationLabel {
    /// Stable, normalized spelling for configuration and audit consumers.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Secret => "secret",
        }
    }

    const fn rank(self) -> u8 {
        self as u8
    }

    fn parse_normalized(input: &str) -> Result<Self, SourceLabelsError> {
        let normalized = input
            .trim_matches(|character: char| character.is_ascii_whitespace())
            .to_ascii_lowercase();
        match normalized.as_str() {
            "public" => Ok(Self::Public),
            "internal" => Ok(Self::Internal),
            "confidential" => Ok(Self::Confidential),
            "secret" => Ok(Self::Secret),
            _ => Err(SourceLabelsError::UnknownLabel),
        }
    }
}

impl Ord for InformationLabel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for InformationLabel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for InformationLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Fail-closed construction error for [`SourceLabels`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceLabelsError {
    /// No label was supplied. Callers must classify input explicitly.
    Empty,
    /// A source-label token is not one of this kernel's accepted labels.
    ///
    /// The rejected input is intentionally not retained: it may be untrusted
    /// data that an error sink would otherwise log or display.
    UnknownLabel,
}

impl fmt::Display for SourceLabelsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("at least one source label is required"),
            Self::UnknownLabel => formatter.write_str("unknown information label"),
        }
    }
}

impl std::error::Error for SourceLabelsError {}

/// A nonempty, ascending, deduplicated set of source labels.
///
/// The normalization happens at construction. The highest label is retained as
/// an invariant so enforcement neither needs an optional fallback nor panics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLabels {
    labels: Vec<InformationLabel>,
    highest: InformationLabel,
}

impl SourceLabels {
    /// Constructs normalized labels from already typed labels.
    pub fn from_labels(
        labels: impl IntoIterator<Item = InformationLabel>,
    ) -> Result<Self, SourceLabelsError> {
        let labels: BTreeSet<_> = labels.into_iter().collect();
        let Some(highest) = labels.last().copied() else {
            return Err(SourceLabelsError::Empty);
        };

        Ok(Self {
            labels: labels.into_iter().collect(),
            highest,
        })
    }

    /// Parses, ASCII-whitespace-trims, ASCII-case-normalizes, sorts, and
    /// deduplicates labels.
    ///
    /// Unknown values and missing input are errors; this constructor never
    /// supplies a `Public` label on a caller's behalf.
    pub fn from_names<I, S>(names: I) -> Result<Self, SourceLabelsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::from_labels(
            names
                .into_iter()
                .map(|name| InformationLabel::parse_normalized(name.as_ref()))
                .collect::<Result<Vec<_>, _>>()?,
        )
    }

    /// Labels in deterministic ascending policy order.
    pub fn as_slice(&self) -> &[InformationLabel] {
        &self.labels
    }

    /// The sensitivity that controls a multi-source information-flow decision.
    pub const fn highest(&self) -> InformationLabel {
        self.highest
    }
}

/// Provenance for an external-egress decision.
///
/// `LegacyUnscoped` is deliberately *not* a claim that its input is public:
/// older HTTP callers do not yet carry a trusted source classification, so
/// this IFC slice leaves their historical gate contract intact. The only
/// non-legacy variant is minted by the pinned-operator `/research
/// --release-external <topic>` boundary. Its public release has no
/// caller-supplied label or free-form string; future trusted classifications
/// need a separate, explicit ingress boundary rather than a generic
/// declassification API.
#[derive(Clone)]
pub(crate) enum EgressProvenance {
    LegacyUnscoped,
    OperatorReleasedChannelResearch(Arc<OperatorReleasedChannelResearchProvenance>),
}

impl fmt::Debug for EgressProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyUnscoped => formatter.write_str("EgressProvenance::LegacyUnscoped"),
            Self::OperatorReleasedChannelResearch(payload) => formatter
                .debug_struct("EgressProvenance::OperatorReleasedChannelResearch")
                .field("research_release_id", &payload.research_release_id)
                .field(
                    "execution_state",
                    &released_research_execution_state_label(
                        payload.execution_state.load(AtomicOrdering::Acquire),
                    ),
                )
                .finish(),
        }
    }
}

/// Crate-visible only to match [`EgressProvenance`]'s reachable variant type.
/// Its fields and constructors remain private, so sibling modules cannot mint
/// this payload; only [`ExplicitExternalResearchRelease`] can create it after
/// consuming the single-use release authority.
pub(crate) struct OperatorReleasedChannelResearchProvenance {
    sources: SourceLabels,
    research_release_id: String,
    released_topic_sha256: String,
    execution_state: AtomicU8,
}

const RELEASE_FRESH: u8 = 0;
const RELEASE_ARMED: u8 = 1;
const RELEASE_SPENT: u8 = 2;

const fn released_research_execution_state_label(execution_state: u8) -> &'static str {
    match execution_state {
        RELEASE_FRESH => "fresh",
        RELEASE_ARMED => "armed",
        RELEASE_SPENT => "spent",
        _ => "invalid",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReleasedResearchBindingError {
    NotOperatorReleased,
    TopicMismatch,
    AlreadyUsed,
    RequestMismatch,
}

impl fmt::Display for ReleasedResearchBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotOperatorReleased => "operator-released research provenance is required",
            Self::TopicMismatch => "released research topic binding mismatch",
            Self::AlreadyUsed => "released research capability was already used",
            Self::RequestMismatch => "released research request binding mismatch",
        })
    }
}

impl std::error::Error for ReleasedResearchBindingError {}

/// Opaque binding minted only after `/research --release-external <topic>`
/// parsed one nonempty topic. It retains no plaintext topic, so the later WAL
/// provenance can bind the exact operator release without disclosing it.
pub(crate) struct ExplicitExternalResearchRelease {
    research_release_id: String,
    topic_sha256: String,
}

impl ExplicitExternalResearchRelease {
    /// Mint an egress-release binding only from the opaque proof produced by
    /// the exact resolved-and-pinned operator comparison in the channel
    /// pipeline. The proof is consumed by value; an arbitrary topic alone can
    /// never construct this authority-bearing token.
    pub(crate) fn for_pinned_operator_exact_topic(
        _release_authority: crate::cli::serve_pipeline::PinnedChannelExternalResearchReleaseAuthority,
        topic: &str,
    ) -> Self {
        debug_assert!(!topic.is_empty());
        Self {
            research_release_id: uuid::Uuid::now_v7().to_string(),
            topic_sha256: hex::encode(Sha256::digest(topic.as_bytes())),
        }
    }

    /// Convert the proof-bound release token into IFC provenance. This is the
    /// only production construction path for a non-legacy public provenance.
    pub(crate) fn into_egress_provenance(self) -> EgressProvenance {
        EgressProvenance::OperatorReleasedChannelResearch(Arc::new(
            OperatorReleasedChannelResearchProvenance {
                sources: SourceLabels::from_labels([InformationLabel::Public])
                    .expect("a fixed public provenance label is nonempty"),
                research_release_id: self.research_release_id,
                released_topic_sha256: self.topic_sha256,
                execution_state: AtomicU8::new(RELEASE_FRESH),
            },
        ))
    }

    #[cfg(test)]
    pub(crate) fn test_for_exact_topic(topic: &str) -> Self {
        Self {
            research_release_id: "test-research-release-id".to_owned(),
            topic_sha256: hex::encode(Sha256::digest(topic.as_bytes())),
        }
    }
}

impl EgressProvenance {
    /// Returns a source classification only when a trusted ingress boundary
    /// attached one. `None` means legacy/unscoped, never implicit `Public`.
    pub(crate) fn sources(&self) -> Option<&SourceLabels> {
        match self {
            Self::LegacyUnscoped => None,
            Self::OperatorReleasedChannelResearch(payload) => Some(&payload.sources),
        }
    }

    /// In-memory permit domain separator. Released research deliberately uses
    /// only its random release ID here; the private topic digest is reserved
    /// for exact-query comparison and never enters a persistable binding.
    pub(crate) fn binding_material(&self) -> String {
        match self {
            Self::LegacyUnscoped => "legacy_unscoped".to_owned(),
            Self::OperatorReleasedChannelResearch(payload) => format!(
                "operator_released_channel_research:{}:{research_release_id}",
                payload.sources.highest(),
                research_release_id = payload.research_release_id,
            ),
        }
    }

    /// Stable audit label that deliberately excludes the topic binding.
    pub(crate) fn audit_tag(&self) -> &'static str {
        match self {
            Self::LegacyUnscoped => "legacy_unscoped",
            Self::OperatorReleasedChannelResearch(_) => "operator_released_channel_research",
        }
    }

    /// Random per-release correlation identifier. Unlike the topic digest,
    /// this value is safe for lifecycle WAL metadata and cannot be used to
    /// dictionary-match a low-entropy research topic.
    pub(crate) fn released_research_id(&self) -> Option<&str> {
        match self {
            Self::LegacyUnscoped => None,
            Self::OperatorReleasedChannelResearch(payload) => Some(&payload.research_release_id),
        }
    }

    /// Verify and reserve the exact normalized topic before any released-path
    /// WAL frame, confirmation, or transport. A successful reservation can be
    /// consumed exactly once by the matching outbound search request.
    pub(crate) fn arm_operator_released_exact_topic(
        &self,
        topic: &str,
    ) -> Result<&str, ReleasedResearchBindingError> {
        let Self::OperatorReleasedChannelResearch(payload) = self else {
            return Err(ReleasedResearchBindingError::NotOperatorReleased);
        };
        let actual = hex::encode(Sha256::digest(topic.as_bytes()));
        if actual != payload.released_topic_sha256 {
            return Err(ReleasedResearchBindingError::TopicMismatch);
        }
        payload
            .execution_state
            .compare_exchange(
                RELEASE_FRESH,
                RELEASE_ARMED,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            )
            .map_err(|_| ReleasedResearchBindingError::AlreadyUsed)?;
        Ok(&payload.research_release_id)
    }

    /// Spend the reserved release on one search request whose query was
    /// derived from the actual URL/body bytes by the HTTP request descriptor.
    pub(crate) fn consume_operator_released_search_query(
        &self,
        query_sha256: Option<&str>,
    ) -> Result<(), ReleasedResearchBindingError> {
        let Self::OperatorReleasedChannelResearch(payload) = self else {
            return Ok(());
        };
        if query_sha256 != Some(payload.released_topic_sha256.as_str()) {
            return Err(ReleasedResearchBindingError::RequestMismatch);
        }
        payload
            .execution_state
            .compare_exchange(
                RELEASE_ARMED,
                RELEASE_SPENT,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            )
            .map_err(|_| ReleasedResearchBindingError::AlreadyUsed)?;
        Ok(())
    }

    /// Test-only view of the exact release binding. Production callers can
    /// use it only through `binding_material`, so a low-entropy topic digest
    /// cannot accidentally be persisted as naked WAL metadata.
    #[cfg(test)]
    pub(crate) fn released_topic_sha256(&self) -> Option<&str> {
        match self {
            Self::LegacyUnscoped => None,
            Self::OperatorReleasedChannelResearch(payload) => Some(&payload.released_topic_sha256),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_operator_released_channel_research(sources: SourceLabels) -> Self {
        Self::OperatorReleasedChannelResearch(Arc::new(OperatorReleasedChannelResearchProvenance {
            sources,
            research_release_id: "test-research-release-id".to_owned(),
            released_topic_sha256: hex::encode(Sha256::digest(b"approved topic")),
            execution_state: AtomicU8::new(RELEASE_FRESH),
        }))
    }
}

/// Structured no-write-down denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InformationFlowDenied {
    source: InformationLabel,
    destination_clearance: InformationLabel,
}

impl InformationFlowDenied {
    pub const fn source(&self) -> InformationLabel {
        self.source
    }

    pub const fn destination_clearance(&self) -> InformationLabel {
        self.destination_clearance
    }
}

impl fmt::Display for InformationFlowDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "information flow denied: source {} exceeds destination clearance {}",
            self.source, self.destination_clearance
        )
    }
}

impl std::error::Error for InformationFlowDenied {}

/// Returns the maximum source sensitivity that the action's destination may
/// receive.
///
/// This is deliberately exhaustive. Adding an [`ActionKind`] requires an
/// explicit IFC classification rather than silently inheriting a permissive
/// default. Any external, peer-facing, arbitrary-code, or otherwise unbounded
/// effect is public clearance. Only effects confined to NEOTH's own local
/// state receive secret clearance. An `ActionKind` alone cannot prove that an
/// arbitrary filesystem, repository, or vault is private, so those actions
/// also remain public until a future destination-provenance layer can prove a
/// higher clearance.
pub(crate) const fn clearance_for_action(action: ActionKind) -> InformationLabel {
    match action {
        ActionKind::Read => InformationLabel::Secret,
        ActionKind::WriteNeothHome => InformationLabel::Secret,
        ActionKind::WriteOutsideHome => InformationLabel::Public,
        ActionKind::ExecScripts => InformationLabel::Public,
        ActionKind::ExecArbitrary => InformationLabel::Public,
        ActionKind::PaidProviderCall => InformationLabel::Public,
        ActionKind::UnboundedPaidProviderCall => InformationLabel::Public,
        ActionKind::ExternalTtsSynthesis => InformationLabel::Public,
        ActionKind::ExternalHttpRequest => InformationLabel::Public,
        ActionKind::ChannelSend => InformationLabel::Public,
        ActionKind::DangerousTarget => InformationLabel::Public,
        ActionKind::McpToolInvocation => InformationLabel::Public,
        ActionKind::PatchApplyToRepo => InformationLabel::Public,
        ActionKind::ClusterPeerPairing => InformationLabel::Public,
        ActionKind::SelfBinaryReplace => InformationLabel::Secret,
        ActionKind::ProactiveChannelSend => InformationLabel::Public,
        ActionKind::OsFileRead => InformationLabel::Secret,
        ActionKind::OsFileWrite => InformationLabel::Public,
        ActionKind::OsAppLaunch => InformationLabel::Public,
        ActionKind::OsClipboardRead => InformationLabel::Secret,
        ActionKind::OsClipboardWrite => InformationLabel::Public,
        ActionKind::ClusterTaskAccept => InformationLabel::Public,
        ActionKind::ExternalTaskWrite => InformationLabel::Public,
        ActionKind::SelfSkillToggle => InformationLabel::Secret,
        ActionKind::SelfCronRegister => InformationLabel::Secret,
        ActionKind::SelfSourceEdit => InformationLabel::Public,
        ActionKind::ObsidianPreloadWrite => InformationLabel::Public,
    }
}

/// Enforces Bell-LaPadula's no-write-down rule for a known source set.
///
/// The returned [`Result`] is `#[must_use]`; callers must propagate or handle
/// a denial before performing the effect.
#[must_use = "a denied information flow must stop the destination effect"]
pub(crate) fn enforce_no_write_down(
    sources: &SourceLabels,
    destination_clearance: InformationLabel,
) -> Result<(), InformationFlowDenied> {
    let source = sources.highest();
    if source <= destination_clearance {
        return Ok(());
    }

    Err(InformationFlowDenied {
        source,
        destination_clearance,
    })
}

/// Applies the action's explicit destination clearance to a source set.
#[must_use = "a denied information flow must stop the action effect"]
pub fn may_flow_to_action(
    sources: &SourceLabels,
    action: ActionKind,
) -> Result<(), InformationFlowDenied> {
    enforce_no_write_down(sources, clearance_for_action(action))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_or_lower_destination_clearance_allows_flow() {
        let sources = SourceLabels::from_names(["confidential"]).unwrap();

        assert!(enforce_no_write_down(&sources, InformationLabel::Confidential).is_ok());
        assert!(enforce_no_write_down(&sources, InformationLabel::Secret).is_ok());
    }

    #[test]
    fn high_to_low_flow_is_denied_with_structured_labels() {
        let sources = SourceLabels::from_names(["secret"]).unwrap();
        let denial = enforce_no_write_down(&sources, InformationLabel::Public).unwrap_err();

        assert_eq!(denial.source(), InformationLabel::Secret);
        assert_eq!(denial.destination_clearance(), InformationLabel::Public);
    }

    #[test]
    fn highest_of_multiple_sources_controls_the_decision() {
        let sources = SourceLabels::from_names(["public", "secret", "internal"]).unwrap();

        assert_eq!(sources.highest(), InformationLabel::Secret);
        assert!(may_flow_to_action(&sources, ActionKind::WriteNeothHome).is_ok());
        assert!(may_flow_to_action(&sources, ActionKind::WriteOutsideHome).is_err());
    }

    #[test]
    fn source_labels_normalize_sort_and_deduplicate() {
        let sources =
            SourceLabels::from_names([" Secret ", "PUBLIC", "internal", "public", "INTERNAL"])
                .unwrap();

        assert_eq!(
            sources.as_slice(),
            [
                InformationLabel::Public,
                InformationLabel::Internal,
                InformationLabel::Secret,
            ]
        );
    }

    #[test]
    fn empty_and_unknown_labels_fail_closed() {
        assert_eq!(
            SourceLabels::from_names(Vec::<&str>::new()),
            Err(SourceLabelsError::Empty)
        );
        assert_eq!(
            SourceLabels::from_names(["public", "unknown"]),
            Err(SourceLabelsError::UnknownLabel)
        );
        assert_eq!(
            SourceLabels::from_names(["\u{2003}public\u{2003}"]),
            Err(SourceLabelsError::UnknownLabel)
        );
    }

    #[test]
    fn operator_research_public_release_is_topic_bound_and_legacy_is_not_public() {
        let release = ExplicitExternalResearchRelease::test_for_exact_topic("one exact topic")
            .into_egress_provenance();

        assert_eq!(
            release.sources().map(SourceLabels::highest),
            Some(InformationLabel::Public)
        );
        assert_eq!(release.audit_tag(), "operator_released_channel_research");
        assert_eq!(
            release.released_research_id(),
            Some("test-research-release-id")
        );
        let expected_topic_sha256 = hex::encode(Sha256::digest(b"one exact topic"));
        assert_eq!(
            release.released_topic_sha256(),
            Some(expected_topic_sha256.as_str())
        );
        assert_eq!(
            release.arm_operator_released_exact_topic("different topic"),
            Err(ReleasedResearchBindingError::TopicMismatch)
        );
        assert_eq!(
            release.arm_operator_released_exact_topic("one exact topic"),
            Ok("test-research-release-id")
        );
        assert_eq!(
            release.arm_operator_released_exact_topic("one exact topic"),
            Err(ReleasedResearchBindingError::AlreadyUsed)
        );
        assert_eq!(
            release.consume_operator_released_search_query(Some(expected_topic_sha256.as_str())),
            Ok(())
        );
        assert_eq!(
            release.consume_operator_released_search_query(Some(expected_topic_sha256.as_str())),
            Err(ReleasedResearchBindingError::AlreadyUsed)
        );
        assert!(EgressProvenance::LegacyUnscoped.sources().is_none());
        assert_eq!(
            EgressProvenance::LegacyUnscoped.audit_tag(),
            "legacy_unscoped"
        );
    }

    #[test]
    fn egress_provenance_debug_redacts_released_topic_and_digest() {
        const LOW_ENTROPY_TOPIC: &str = "weather";

        let release = ExplicitExternalResearchRelease::test_for_exact_topic(LOW_ENTROPY_TOPIC)
            .into_egress_provenance();
        let topic_sha256 = hex::encode(Sha256::digest(LOW_ENTROPY_TOPIC.as_bytes()));
        let formatted = format!("{release:?}");

        assert!(!formatted.contains(LOW_ENTROPY_TOPIC));
        assert!(!formatted.contains(&topic_sha256));
        assert!(formatted.contains("EgressProvenance::OperatorReleasedChannelResearch"));
        assert!(formatted.contains("test-research-release-id"));
        assert!(formatted.contains("fresh"));
    }

    #[test]
    fn every_action_kind_has_an_explicit_clearance() {
        for action in ActionKind::ALL {
            let clearance = clearance_for_action(action);
            assert!(
                InformationLabel::Public <= clearance && clearance <= InformationLabel::Secret,
                "invalid clearance for {action}"
            );
        }

        assert_eq!(
            clearance_for_action(ActionKind::ExternalHttpRequest),
            InformationLabel::Public
        );
        assert_eq!(
            clearance_for_action(ActionKind::McpToolInvocation),
            InformationLabel::Public
        );
    }
}
