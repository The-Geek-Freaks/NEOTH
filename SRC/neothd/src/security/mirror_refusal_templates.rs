//! Deterministic, data-minimal terminal mirrors for refusal paths.
//!
//! These templates deliberately do not interpolate the operator request,
//! provider response, errors, or matched phrases. They are terminal user
//! messages, so putting any of that untrusted material back into the reply
//! could accidentally turn a refusal explanation into a reframe or bypass.

use super::refusal_detect::RefusalClass;
use super::mirror_refusal_pipeline::{MirrorBoundaryFact, MirrorRefusalShape, MirrorSynthesis};

pub fn template(class: RefusalClass) -> &'static str {
    match class {
        RefusalClass::HardRefusal => HARD,
        RefusalClass::PartialRefusal => PARTIAL,
        RefusalClass::SoftRefusal => SOFT,
        RefusalClass::RedirectSuggestion => REDIRECT,
        RefusalClass::SafetyWarning => SAFETY,
        RefusalClass::None => NONE,
    }
}

/// Render the Cerebellum's allowlisted facts. No model-authored prose reaches
/// the operator surface; accepted model output can only select these phrases.
pub fn render_structured(synthesis: MirrorSynthesis) -> String {
    let happened = match synthesis.refusal_shape {
        MirrorRefusalShape::Complete => "The system declined the request.",
        MirrorRefusalShape::Partial => "The system declined part of the request.",
        MirrorRefusalShape::Restricted => "The system returned a restricted or hedged result.",
        MirrorRefusalShape::Redirected => "The system declined the original form and identified an adjacent path.",
        MirrorRefusalShape::SafetyCaveat => "The system returned an answer with a safety caveat.",
    };
    let why = match synthesis.boundary {
        MirrorBoundaryFact::ContentPolicy => "A content-policy boundary was identified.",
        MirrorBoundaryFact::Scope => "A scope boundary was identified.",
        MirrorBoundaryFact::Authorisation => "An authorisation boundary was identified.",
        MirrorBoundaryFact::Capability => "A capability boundary was identified.",
        MirrorBoundaryFact::Safety => "A safety boundary was identified.",
        MirrorBoundaryFact::Unspecified => "The available response does not establish a more specific boundary.",
    };
    format!("## What happened\n{happened}\n\n## Why this happened (structural)\n{why}\n\n## Next steps\nOperator review is required before any fresh, explicitly authorised run.")
}

pub const PERSISTENT: &str = "## What happened\nThis request was declined again during the current turn.\n\n## Why this happened (structural)\nThe mirror-refusal guard allows one structural explanation per turn and prevents further model calls for the declined request.\n\n## Next steps\nOperator action is required before a fresh, explicitly authorised run.";

const HARD: &str = "## What happened\nThe system received the request and produced no substantive response. A hard refusal boundary was triggered.\n\n## Why this happened (structural)\nThe requested operation is outside the active content, scope, or authorisation boundary.\n\n## Next steps\n1. Narrow the scope.\n2. Request operator authorisation where applicable.\n3. Accept this limitation.";
const PARTIAL: &str = "## What happened\nPart of the request was addressed and another part was declined.\n\n## Why this happened (structural)\nOne or more sub-tasks crossed an active boundary while other parts remained available.\n\n## Next steps\n1. Split the request.\n2. Proceed with any already answered part.\n3. Narrow the declined sub-task.";
const SOFT: &str = "## What happened\nThe system responded with a restricted, hedged, or degraded result.\n\n## Why this happened (structural)\nThe request was close to an active boundary or lacked sufficient safe context.\n\n## Next steps\n1. Add relevant context.\n2. Clarify the permitted scope.\n3. Accept the restricted result.";
const REDIRECT: &str = "## What happened\nThe original request was declined and an adjacent alternative was offered.\n\n## Why this happened (structural)\nThe original form crossed an active boundary while the adjacent path remained distinguishable.\n\n## Next steps\n1. Evaluate the offered alternative.\n2. Clarify the required scope.\n3. Seek operator authorisation if the original scope is necessary.";
const SAFETY: &str = "## What happened\nThe system returned an answer with a safety caveat.\n\n## Why this happened (structural)\nThe caveat identifies a boundary or risk relevant to use of the response.\n\n## Next steps\n1. Acknowledge the caveat.\n2. Provide context if it is inaccurate.\n3. Proceed only within the stated boundary.";
const NONE: &str = "## What happened\nThe response was routed to the refusal mirror without a classified refusal.\n\n## Why this happened (structural)\nThe terminal safety path cannot continue with a provider response in this state.\n\n## Next steps\nOperator review is required before a fresh run.";
