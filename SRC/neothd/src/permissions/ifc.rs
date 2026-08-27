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

use std::{cmp::Ordering, collections::BTreeSet, fmt};

use super::ActionKind;

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
