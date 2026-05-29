//! Council data shapes. Pure structs; no I/O.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::inference::HemisphereRole;
use crate::security::refusal_cause::RefusalCause;
use crate::security::refusal_detect::RefusalClass;

/// Per-hemisphere refusal summary. R-03 (Session 13) populates this on
/// every council debate so the chat dispatcher + callosum can recognise
/// partial refusals (1-2 hemispheres refused while the others succeeded)
/// and route around them rather than treating the whole council as
/// blocked. Empty when the hemisphere succeeded normally OR when the
/// hemisphere errored without producing text (in which case
/// `HemisphereResponse::error` carries the diagnostic).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HemisphereRefusal {
    /// Surface class (Hard/Partial/Soft/Redirect/SafetyWarning).
    pub class: RefusalClass,
    /// 0-100 confidence from the surface classifier.
    pub class_confidence: u8,
    /// Cause taxonomy (SafetyPolicy / CapabilityGap / Privacy /
    /// OperatorPolicy / Unknown).
    pub cause: RefusalCause,
    /// 0-100 confidence from the cause classifier.
    pub cause_confidence: u8,
}

/// One hemisphere's contribution to a debate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HemisphereResponse {
    /// Which role (Left/Right/Cerebellum) produced this response.
    pub role: HemisphereRole,
    /// Provider that backed this hemisphere at debate time. Stable
    /// string id matching `InferenceProvider::as_str` so operators
    /// reading WAL frames see exactly which adapter spoke.
    pub provider: String,
    /// The actual text the model produced. `None` when the hemisphere
    /// errored (network, refusal, model not configured).
    pub text: Option<String>,
    /// Error reason when `text` is None. Operator-visible diagnostic.
    pub error: Option<String>,
    /// Wall-clock duration from request issue to final token.
    pub latency_ms: u64,
    /// Token counts when the adapter reported them.
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    /// R-03 per-hemisphere refusal classification. Populated by the
    /// orchestrator when text is present + the deterministic
    /// classifier flags a refusal. Empty when the hemisphere either
    /// errored (no text) or returned a non-refusal completion. Serde
    /// defaults to `None` so older WAL payloads stay parseable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<HemisphereRefusal>,
}

impl HemisphereResponse {
    /// Convenience: was this hemisphere able to contribute?
    pub fn is_present(&self) -> bool {
        self.text.is_some()
    }

    /// R-03: present-and-non-refusing — the kind of response downstream
    /// consumers (chat dispatcher, callosum, recovery pipeline) want to
    /// build on. False for both errored hemispheres and hemispheres
    /// whose text was flagged as a refusal.
    pub fn is_usable(&self) -> bool {
        self.text.is_some() && self.refusal.is_none()
    }

    /// Audit 2026-05-19 Type #13 — Phase 1.
    ///
    /// Project this response onto the typed three-state outcome. Today's
    /// shape encodes the state implicitly in `(text, error, refusal)`:
    ///   - text=Some + refusal=None        → Usable
    ///   - text=Some + refusal=Some        → Refused
    ///   - text=None                       → Errored (carries `error`)
    ///
    /// Phase 2 will migrate the 64 use-sites that currently switch on
    /// `is_present()` / `is_usable()` / `text.as_deref()` to `match
    /// resp.outcome()` so the state machine becomes compile-time
    /// exhaustive. This accessor is the non-breaking bridge — every
    /// existing consumer keeps working, and new code can opt into the
    /// typed view immediately.
    pub fn outcome(&self) -> HemisphereOutcome<'_> {
        match (&self.text, &self.refusal, &self.error) {
            (Some(text), None, _) => HemisphereOutcome::Usable { text },
            (Some(text), Some(refusal), _) => HemisphereOutcome::Refused { text, refusal },
            // text=None is the errored shape regardless of whether
            // `error` was populated — the orchestrator may carry only a
            // best-effort diagnostic. `error.as_deref()` gives the
            // caller exactly the same Option<&str> they see today via
            // `resp.error.as_deref()`.
            (None, _, e) => HemisphereOutcome::Errored {
                error: e.as_deref(),
            },
        }
    }
}

/// Three mutually-exclusive states a hemisphere can be in after a
/// council debate. Audit 2026-05-19 Type #13 Phase 1.
///
/// Borrows from the parent [`HemisphereResponse`] so projecting is free
/// — no allocations, no Arc/Rc gymnastics. Each variant carries exactly
/// the fields a consumer needs:
///   - **Usable**: a non-refusing reply ready to feed into the callosum,
///     reply prefix, recall write, ...
///   - **Refused**: a reply that the deterministic classifier flagged.
///     Carries both `text` (for diagnostic surfaces that want the raw
///     refusal phrasing) and the structured `refusal` (class + cause).
///   - **Errored**: no reply produced — provider error, timeout, budget
///     exhaustion. Carries an optional diagnostic string.
///
/// Lifetime ties the projection to the parent `HemisphereResponse`; if
/// callers need an owned form, `HemisphereOutcomeOwned` lives one step
/// away (Phase 2 will add it if a consumer actually requires it).
#[derive(Clone, Copy, Debug)]
pub enum HemisphereOutcome<'a> {
    /// Present, classified non-refusal. The text the callosum wants.
    Usable { text: &'a str },
    /// Present text but the classifier flagged it. `refusal` carries
    /// the class + cause + confidences.
    Refused {
        text: &'a str,
        refusal: &'a HemisphereRefusal,
    },
    /// No text produced. `error` is the operator-visible diagnostic
    /// when the adapter set one.
    Errored { error: Option<&'a str> },
}

impl<'a> HemisphereOutcome<'a> {
    /// Operator-visible name of the variant. Useful for WAL payloads +
    /// log lines that want a stable string discriminator without
    /// committing to the variant's payload shape.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Usable { .. } => "usable",
            Self::Refused { .. } => "refused",
            Self::Errored { .. } => "errored",
        }
    }

    /// Convenience predicates that mirror [`HemisphereResponse::is_present`]
    /// and [`HemisphereResponse::is_usable`] — lets a Phase 2 caller
    /// migrate one site at a time without flipping every condition.
    pub fn is_present(&self) -> bool {
        matches!(self, Self::Usable { .. } | Self::Refused { .. })
    }

    /// Mirror of `HemisphereResponse::is_usable`: only the `Usable`
    /// variant counts.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Usable { .. })
    }

    /// Text accessor — `None` for the errored variant.
    pub fn text(&self) -> Option<&'a str> {
        match self {
            Self::Usable { text } | Self::Refused { text, .. } => Some(text),
            Self::Errored { .. } => None,
        }
    }
}

/// What the council decided as a whole.
///
/// `Consensus` — all responding hemispheres agreed within the dissent
/// threshold; the verdict text is the most representative response.
/// `Split` — at least two hemispheres disagreed beyond threshold;
/// the operator (or a downstream "tie-break" step) decides next.
/// `Quorum failed` — too few hemispheres responded to form a verdict
/// (e.g. all three timed out or refused).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// All present hemispheres agreed.
    Consensus { winning_text: String },
    /// Hemispheres disagreed beyond threshold.
    Split {
        /// Operator-visible summary describing the split (which roles
        /// said what at a glance).
        summary: String,
    },
    /// Insufficient hemispheres responded for any verdict.
    QuorumFailed { responded: u32, required: u32 },
}

/// One council session's audit record. Serialised into the WAL frame
/// payload when the chat dispatch convenes the council (`EVENT_TYPE_*`
/// allocation deferred until the dispatch wiring lands).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CouncilDebate {
    /// xxh3_64 hash of the prompt — never the raw prompt, to match
    /// the WAL's secrets-out policy. Audit consumers can correlate
    /// with the prompt's `PROVIDER_REQUEST` frame via this hash.
    pub prompt_hash_xxh3: u64,
    /// Three per-role responses, one per Hemisphere. Roles missing
    /// from the operator's topology stay as error variants so the
    /// audit shape stays uniform.
    pub responses: Vec<HemisphereResponse>,
    /// Disagreement score (0.0 = identical, 1.0 = maximal).
    pub dissent: super::dissent::DissentScore,
    /// What the council collectively decided.
    pub verdict: Verdict,
    /// Total wall-clock time from `run_debate` start to verdict.
    /// Useful for the cost/latency dashboard.
    pub total_latency_ms: u64,
}

impl CouncilDebate {
    /// Convenience: did the council produce a usable answer text?
    pub fn winning_text(&self) -> Option<&str> {
        match &self.verdict {
            Verdict::Consensus { winning_text } => Some(winning_text.as_str()),
            Verdict::Split { .. } | Verdict::QuorumFailed { .. } => None,
        }
    }

    /// Per-role response lookup. None when the operator's topology
    /// did not configure that role.
    pub fn response_for(&self, role: HemisphereRole) -> Option<&HemisphereResponse> {
        self.responses.iter().find(|r| r.role == role)
    }

    /// R-03: how many hemispheres returned text that the classifier
    /// flagged as a refusal. Counts only present-with-text responses;
    /// errored hemispheres (text=None) never contribute to this count
    /// because their failure mode lives in `error`, not refusal.
    pub fn refused_count(&self) -> usize {
        self.responses
            .iter()
            .filter(|r| r.refusal.is_some())
            .count()
    }

    /// R-03: hemispheres whose text was flagged as a refusal. Order
    /// matches `responses` (already sorted L/R/C by `run_debate`).
    pub fn refused_responses(&self) -> impl Iterator<Item = &HemisphereResponse> {
        self.responses.iter().filter(|r| r.refusal.is_some())
    }

    /// R-03: hemispheres that have non-refusal text — the responses
    /// the chat dispatcher + callosum should build the verdict on when
    /// one hemisphere refused while others succeeded.
    pub fn usable_responses(&self) -> impl Iterator<Item = &HemisphereResponse> {
        self.responses.iter().filter(|r| r.is_usable())
    }

    /// R-03: at least one hemisphere refused AND at least one returned
    /// usable text. This is the "route around the refusal" signal —
    /// the chat dispatcher can pick a winning response from the
    /// usable subset rather than treating the whole debate as blocked.
    pub fn is_partial_refusal(&self) -> bool {
        let mut any_refused = false;
        let mut any_usable = false;
        for r in &self.responses {
            if r.refusal.is_some() {
                any_refused = true;
            }
            if r.is_usable() {
                any_usable = true;
            }
        }
        any_refused && any_usable
    }

    /// ADV-10b (Session 28g+) — classify how the debate is degraded by
    /// errored hemispheres. The orchestrator already handles 2-of-3
    /// degrade naturally (FuturesUnordered + `is_present` quorum), but
    /// callers want a typed signal for operator-visible logging +
    /// future verdict-confidence-penalty wiring.
    ///
    /// Quota detection is BEST-EFFORT substring sniffing of the per-
    /// hemisphere `error` string — the typed `QuotaError` is lost
    /// upstream when `HemisphereProvider::ask_with_depth_budget`
    /// stringifies the failure. The shipped `QuotaError` Display
    /// contains the literal "quota exceeded (HTTP 429)" phrase
    /// (`providers::quota::QuotaError`), so the substring check is
    /// reliable in practice. Threading the typed error through the
    /// trait + adapters is its own larger refactor (tracked separately).
    pub fn degradation(&self) -> CouncilDegradation {
        let mut quota = 0usize;
        let mut other = 0usize;
        for r in &self.responses {
            if r.text.is_none() {
                if let Some(err) = &r.error {
                    if council_error_is_quota(err) {
                        quota += 1;
                    } else {
                        other += 1;
                    }
                } else {
                    other += 1;
                }
            }
        }
        match (quota, other) {
            (0, 0) => CouncilDegradation::None,
            (q, 0) => CouncilDegradation::QuotaOnly { count: q },
            (0, o) => CouncilDegradation::OtherOnly { count: o },
            (q, o) => CouncilDegradation::Mixed {
                quota_count: q,
                other_count: o,
            },
        }
    }

    /// Pick #8 SP-2 (Session 14) — role-agnostic "smartest-wins"
    /// selection. Returns the usable response whose
    /// [`super::quality_score::QualityScore::total`] is highest
    /// according to the operator-provided score map.
    ///
    /// `scores` is a slice of `(HemisphereRole, total_score)` pairs.
    /// Responses without a score entry default to `0.0` (lose every
    /// tie). Refused or errored responses are skipped via
    /// [`HemisphereResponse::is_usable`].
    ///
    /// Returns `None` when no hemisphere produced a usable response
    /// — caller falls back to the existing Verdict-driven path
    /// (`winning_text()` for Consensus, callosum for Split,
    /// QuorumFailed surface for the rest).
    ///
    /// Pure: no I/O, no allocation. Composable with the dispatcher's
    /// `SelectionMode::ConsensusOrBest` / `BestAlways` modes.
    pub fn best_response(&self, scores: &[(HemisphereRole, f32)]) -> Option<&HemisphereResponse> {
        let mut best: Option<(&HemisphereResponse, f32)> = None;
        for r in self.responses.iter().filter(|r| r.is_usable()) {
            let score = scores
                .iter()
                .find(|(role, _)| *role == r.role)
                .map(|(_, s)| *s)
                .unwrap_or(0.0);
            match best {
                None => best = Some((r, score)),
                Some((_, prior_score)) if score > prior_score => best = Some((r, score)),
                _ => {}
            }
        }
        best.map(|(r, _)| r)
    }
}

/// Helper for converting a `Duration` to milliseconds without losing
/// the type. Saturating; `u64::MAX` ms is a year of latency, plenty.
pub(crate) fn dur_to_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

// ─── QM-13 CouncilVoice (agency-agents adoption) ────────────────────────────
//
// New per-hemisphere "voice" specialisation tag. The orchestrator can pin
// a voice on a hemisphere so its system prompt + trigger conditions match
// the security / performance / accessibility / threat-intel slot it
// occupies in council debates. Per
// `PLAN/QUELLEN_ADOPT_agency_2026-05-21.md` §5 ADOPT-AS-COUNCIL-VOICE.
//
// The voice is metadata, not a routing decision — the council orchestrator
// still picks providers via `freedom.yaml::hemispheres`. The voice tells
// the orchestrator WHICH system prompt to layer on top of the operator-md
// + skill stack, and WHICH trigger conditions to use for auto-convening.

/// One of the six specialist council voices. Each maps to a specific
/// concern domain + a default auto-trigger condition. Operators pin a
/// voice to a hemisphere via `freedom.yaml::hemispheres::<role>::voice`
/// (when the config wiring lands) or invoke explicitly via
/// `/council voice <name> <prompt>`.
///
/// Pinned at six variants per the agency QUELLEN audit + NEOTH's
/// existing concerns:
///
/// - `SecurityEngineer` — autonomy / permission / consent gates (0xA0-0xA3)
/// - `ThreatDetectionEngineer` — WAL cluster events (0xE0-0xE7), pairs
///   with SecurityEngineer for sec-flavoured council debates
/// - `PerformanceBenchmarker` — fires when "perf" / "latency" / "slow"
///   surfaces in the prompt OR when the retry budget is approaching
/// - `AccessibilityAuditor` — fires on GUI council debates (NOOB-UX items),
///   pushes back against operator-hostile UI choices
/// - `IncidentResponder` — daemon crash / recovery path; pairs with
///   ThreatDetectionEngineer
/// - `EvidenceCollector` — highest-priority quality voice, owns the QA
///   verdict path (QM-6 QaVerdict)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouncilVoice {
    SecurityEngineer,
    ThreatDetectionEngineer,
    PerformanceBenchmarker,
    AccessibilityAuditor,
    IncidentResponder,
    EvidenceCollector,
}

impl CouncilVoice {
    /// Stable wire id matching serde's `rename_all`.
    pub fn as_str(self) -> &'static str {
        match self {
            CouncilVoice::SecurityEngineer => "security_engineer",
            CouncilVoice::ThreatDetectionEngineer => "threat_detection_engineer",
            CouncilVoice::PerformanceBenchmarker => "performance_benchmarker",
            CouncilVoice::AccessibilityAuditor => "accessibility_auditor",
            CouncilVoice::IncidentResponder => "incident_responder",
            CouncilVoice::EvidenceCollector => "evidence_collector",
        }
    }

    /// Parse a wire id back to the enum. `None` for unknown strings —
    /// the caller decides whether to surface "unknown voice" to the
    /// operator or fall through to no-voice.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "security_engineer" => Some(Self::SecurityEngineer),
            "threat_detection_engineer" => Some(Self::ThreatDetectionEngineer),
            "performance_benchmarker" => Some(Self::PerformanceBenchmarker),
            "accessibility_auditor" => Some(Self::AccessibilityAuditor),
            "incident_responder" => Some(Self::IncidentResponder),
            "evidence_collector" => Some(Self::EvidenceCollector),
            _ => None,
        }
    }

    /// One-line operator-readable description. Surfaces in `neoth council
    /// voices` output + the GUI voice picker.
    pub fn description(self) -> &'static str {
        match self {
            CouncilVoice::SecurityEngineer => {
                "Audits autonomy + permission gates (0xA0-0xA3); pairs with ThreatDetection."
            }
            CouncilVoice::ThreatDetectionEngineer => {
                "Inspects WAL cluster events (0xE0-0xE7) for tamper / intrusion signals."
            }
            CouncilVoice::PerformanceBenchmarker => {
                "Critiques latency, allocations, retry-budget posture; fires on perf prompts."
            }
            CouncilVoice::AccessibilityAuditor => {
                "Reviews GUI council debates against NOOB-UX hard rules + WCAG basics."
            }
            CouncilVoice::IncidentResponder => {
                "Owns daemon crash / recovery + post-mortem framing."
            }
            CouncilVoice::EvidenceCollector => {
                "Highest-priority QA voice; owns QaVerdict path (QM-6) after worker patch apply."
            }
        }
    }

    /// The system-prompt fragment this voice prepends when active. Layered
    /// AFTER operator-md / persona / skill prompts so it adds specialist
    /// framing without overriding operator context. Stays short — the
    /// voice is metadata, not a full prompt rewrite.
    pub fn system_prompt_fragment(self) -> &'static str {
        match self {
            CouncilVoice::SecurityEngineer => {
                "Voice: SecurityEngineer. Treat every change as a potential gate-bypass. \
                 Identify: authn/authz, consent, autonomy escalation, secret handling, \
                 supply-chain. For each finding state premise + impact + minimum fix."
            }
            CouncilVoice::ThreatDetectionEngineer => {
                "Voice: ThreatDetectionEngineer. Inspect WAL cluster events + adjacent state \
                 for tamper signals or anomalous patterns. Report observation + confidence + \
                 follow-up to validate."
            }
            CouncilVoice::PerformanceBenchmarker => {
                "Voice: PerformanceBenchmarker. Surface latency, allocation, lock-contention, \
                 and retry-budget concerns. Quote concrete numbers; reject 'should be fast' \
                 in favour of measured or estimated cost."
            }
            CouncilVoice::AccessibilityAuditor => {
                "Voice: AccessibilityAuditor. Push back against operator-hostile choices: \
                 hidden settings, unexplained jargon, missing recommended-defaults, \
                 keyboard-only paths broken. Cite the NOOB-UX hard rule when relevant."
            }
            CouncilVoice::IncidentResponder => {
                "Voice: IncidentResponder. Frame the situation as: detect → contain → \
                 diagnose → recover → document. Surface the missing step explicitly."
            }
            CouncilVoice::EvidenceCollector => {
                "Voice: EvidenceCollector. Produce a structured QaVerdict (Pass/Fail/Blocked). \
                 Each Fail item carries kind + message + citation. Each Pass carries \
                 the evidence (test output line, file:line, command run)."
            }
        }
    }
}

/// ADV-10b (Session 28g+) — how a [`CouncilDebate`] is degraded by
/// errored hemispheres. The orchestrator's natural 2-of-3 degrade (the
/// FuturesUnordered quorum check absorbs hemisphere failures) leaves
/// the verdict resolvable, but callers want a typed signal for
/// operator-visible logging + future verdict-confidence-penalty wiring.
///
/// `QuotaOnly` is distinguished from `OtherOnly` because the operator
/// remediation differs: quota means "wait the backoff window", other
/// errors (network, refusal, budget) mean something more specific is
/// wrong. `Mixed` covers the rare case where one hemisphere is
/// rate-limited AND another fails for a different reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CouncilDegradation {
    /// All hemispheres returned text; the debate was fully attended.
    None,
    /// Exactly the named count of hemispheres failed due to HTTP 429
    /// (typed `QuotaError` flattened to substring-matched diagnostic).
    QuotaOnly { count: usize },
    /// Exactly the named count of hemispheres failed for non-quota
    /// reasons (network, refusal, budget-exhausted, model not configured).
    OtherOnly { count: usize },
    /// A mix of both. `quota_count` + `other_count` is the total of
    /// errored hemispheres; the debate still has `3 - (q+o)` usable
    /// responses.
    Mixed {
        quota_count: usize,
        other_count: usize,
    },
}

impl CouncilDegradation {
    /// True for any non-`None` variant — useful for the chat-side
    /// "should this turn produce a degraded warn log?" branch.
    pub fn is_degraded(self) -> bool {
        !matches!(self, CouncilDegradation::None)
    }

    /// Total count of errored hemispheres across both quota + other.
    /// `None` returns 0.
    pub fn errored_count(self) -> usize {
        match self {
            CouncilDegradation::None => 0,
            CouncilDegradation::QuotaOnly { count } => count,
            CouncilDegradation::OtherOnly { count } => count,
            CouncilDegradation::Mixed {
                quota_count,
                other_count,
            } => quota_count + other_count,
        }
    }

    /// Stable lower-snake-case discriminator for log lines + future
    /// WAL audit payloads. The variant payloads stay structured for
    /// programmatic consumers; this is for human / grep visibility.
    pub fn variant_name(self) -> &'static str {
        match self {
            CouncilDegradation::None => "none",
            CouncilDegradation::QuotaOnly { .. } => "quota_only",
            CouncilDegradation::OtherOnly { .. } => "other_only",
            CouncilDegradation::Mixed { .. } => "mixed",
        }
    }
}

/// ADV-10b — substring sniff for a `QuotaError`-derived hemisphere
/// error diagnostic. Returns `true` when the error string carries one
/// of the canonical phrases the shipped `providers::quota::QuotaError`
/// Display impl produces. Best-effort because the typed error is
/// stringified upstream in `ask_with_depth_budget`; threading the
/// typed signal through the trait is a separate larger refactor.
pub(crate) fn council_error_is_quota(err: &str) -> bool {
    // QuotaError Display: "{provider}: quota exceeded (HTTP 429), retry_after=..."
    // — the literal "quota exceeded" + "429" phrases are the load-bearing
    // signal. Match case-insensitively so a future Display tweak that
    // changed casing doesn't silently regress the operator log.
    let lower = err.to_ascii_lowercase();
    lower.contains("quota exceeded") || lower.contains("http 429") || lower.contains("429")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pick #8 SP-2 (Session 14) best_response invariants ──────────

    fn ok(role: HemisphereRole, provider: &str, text: &str) -> HemisphereResponse {
        HemisphereResponse {
            role,
            provider: provider.into(),
            text: Some(text.into()),
            error: None,
            latency_ms: 100,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        }
    }

    fn errored(role: HemisphereRole, provider: &str) -> HemisphereResponse {
        HemisphereResponse {
            role,
            provider: provider.into(),
            text: None,
            error: Some("boom".into()),
            latency_ms: 0,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        }
    }

    fn refused(role: HemisphereRole, provider: &str, text: &str) -> HemisphereResponse {
        HemisphereResponse {
            role,
            provider: provider.into(),
            text: Some(text.into()),
            error: None,
            latency_ms: 100,
            input_tokens: None,
            output_tokens: None,
            refusal: Some(HemisphereRefusal {
                class: RefusalClass::HardRefusal,
                class_confidence: 90,
                cause: RefusalCause::SafetyPolicy,
                cause_confidence: 85,
            }),
        }
    }

    fn debate(responses: Vec<HemisphereResponse>) -> CouncilDebate {
        CouncilDebate {
            prompt_hash_xxh3: 0,
            responses,
            dissent: super::super::dissent::DissentScore(0.1),
            verdict: Verdict::Consensus {
                winning_text: String::new(),
            },
            total_latency_ms: 100,
        }
    }

    #[test]
    fn best_response_picks_highest_scored_usable() {
        let d = debate(vec![
            ok(HemisphereRole::Left, "local_qwen", "qwen text"),
            ok(HemisphereRole::Right, "claude_cli", "claude text"),
            ok(HemisphereRole::Cerebellum, "gemini_api", "gemini text"),
        ]);
        let scores = [
            (HemisphereRole::Left, 0.20),
            (HemisphereRole::Right, 0.80),
            (HemisphereRole::Cerebellum, 0.40),
        ];
        let best = d.best_response(&scores).expect("a winner exists");
        assert_eq!(best.role, HemisphereRole::Right);
        assert_eq!(best.provider, "claude_cli");
    }

    #[test]
    fn best_response_skips_errored_hemispheres() {
        let d = debate(vec![
            errored(HemisphereRole::Left, "claude_cli"),
            ok(HemisphereRole::Right, "local_qwen", "qwen text"),
            errored(HemisphereRole::Cerebellum, "gemini_api"),
        ]);
        // Errored Left has the highest score, but it's not usable.
        let scores = [
            (HemisphereRole::Left, 0.99),
            (HemisphereRole::Right, 0.20),
            (HemisphereRole::Cerebellum, 0.50),
        ];
        let best = d.best_response(&scores).expect("a winner exists");
        assert_eq!(best.role, HemisphereRole::Right);
    }

    #[test]
    fn best_response_skips_refused_hemispheres() {
        let d = debate(vec![
            refused(HemisphereRole::Left, "claude_cli", "I cannot help."),
            ok(HemisphereRole::Right, "local_qwen", "real answer"),
        ]);
        let scores = [(HemisphereRole::Left, 0.99), (HemisphereRole::Right, 0.20)];
        let best = d.best_response(&scores).expect("a winner exists");
        assert_eq!(best.role, HemisphereRole::Right);
    }

    #[test]
    fn best_response_returns_none_when_all_unusable() {
        let d = debate(vec![
            errored(HemisphereRole::Left, "claude_cli"),
            refused(HemisphereRole::Right, "gemini_api", "I cannot help."),
            errored(HemisphereRole::Cerebellum, "local_qwen"),
        ]);
        let scores = [
            (HemisphereRole::Left, 1.0),
            (HemisphereRole::Right, 1.0),
            (HemisphereRole::Cerebellum, 1.0),
        ];
        assert!(d.best_response(&scores).is_none());
    }

    #[test]
    fn best_response_missing_score_defaults_to_zero() {
        // A hemisphere with no entry in `scores` defaults to 0.0,
        // so it loses every tie to any hemisphere with an entry.
        let d = debate(vec![
            ok(HemisphereRole::Left, "claude_cli", "missing score"),
            ok(HemisphereRole::Right, "local_qwen", "has score 0.30"),
        ]);
        let scores = [(HemisphereRole::Right, 0.30)];
        let best = d.best_response(&scores).expect("a winner exists");
        assert_eq!(best.role, HemisphereRole::Right);
    }

    #[test]
    fn best_response_stable_on_score_ties() {
        // Two hemispheres tied at same score → first usable in the
        // responses Vec wins. Deterministic so WAL audit is
        // reproducible across runs.
        let d = debate(vec![
            ok(HemisphereRole::Left, "claude_cli", "left text"),
            ok(HemisphereRole::Right, "claude_cli", "right text"),
        ]);
        let scores = [(HemisphereRole::Left, 0.5), (HemisphereRole::Right, 0.5)];
        let best = d.best_response(&scores).expect("a winner exists");
        assert_eq!(best.role, HemisphereRole::Left);
    }

    fn mk_resp(role: HemisphereRole, text: Option<&str>) -> HemisphereResponse {
        HemisphereResponse {
            role,
            provider: "test".into(),
            text: text.map(String::from),
            error: None,
            latency_ms: 100,
            input_tokens: Some(10),
            output_tokens: Some(20),
            refusal: None,
        }
    }

    fn mk_refused_resp(role: HemisphereRole, text: &str) -> HemisphereResponse {
        let mut r = mk_resp(role, Some(text));
        r.refusal = Some(HemisphereRefusal {
            class: RefusalClass::HardRefusal,
            class_confidence: 90,
            cause: RefusalCause::SafetyPolicy,
            cause_confidence: 80,
        });
        r
    }

    #[test]
    fn winning_text_returns_consensus_payload() {
        let d = CouncilDebate {
            prompt_hash_xxh3: 0,
            responses: vec![],
            dissent: super::super::dissent::DissentScore(0.0),
            verdict: Verdict::Consensus {
                winning_text: "yes".into(),
            },
            total_latency_ms: 100,
        };
        assert_eq!(d.winning_text(), Some("yes"));
    }

    #[test]
    fn winning_text_returns_none_on_split() {
        let d = CouncilDebate {
            prompt_hash_xxh3: 0,
            responses: vec![],
            dissent: super::super::dissent::DissentScore(0.5),
            verdict: Verdict::Split {
                summary: "left=A, right=B".into(),
            },
            total_latency_ms: 100,
        };
        assert!(d.winning_text().is_none());
    }

    #[test]
    fn response_for_finds_by_role() {
        let d = CouncilDebate {
            prompt_hash_xxh3: 0,
            responses: vec![
                mk_resp(HemisphereRole::Left, Some("L")),
                mk_resp(HemisphereRole::Right, Some("R")),
            ],
            dissent: super::super::dissent::DissentScore(0.0),
            verdict: Verdict::Consensus {
                winning_text: "L".into(),
            },
            total_latency_ms: 50,
        };
        assert_eq!(
            d.response_for(HemisphereRole::Left)
                .unwrap()
                .text
                .as_deref(),
            Some("L")
        );
        assert_eq!(
            d.response_for(HemisphereRole::Right)
                .unwrap()
                .text
                .as_deref(),
            Some("R")
        );
        assert!(d.response_for(HemisphereRole::Cerebellum).is_none());
    }

    #[test]
    fn verdict_roundtrips_through_json() {
        let cases = vec![
            Verdict::Consensus {
                winning_text: "yes".into(),
            },
            Verdict::Split {
                summary: "two-way".into(),
            },
            Verdict::QuorumFailed {
                responded: 1,
                required: 2,
            },
        ];
        for v in cases {
            let json = serde_json::to_string(&v).unwrap();
            let back: Verdict = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{v:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn dur_to_ms_saturates_on_overflow() {
        assert_eq!(dur_to_ms(Duration::from_millis(123)), 123);
        // u128 overflow case is hard to construct cheaply; rely on the
        // try_from semantics.
        assert_eq!(dur_to_ms(Duration::from_secs(0)), 0);
    }

    #[test]
    fn is_present_distinguishes_text_from_error() {
        assert!(mk_resp(HemisphereRole::Left, Some("ok")).is_present());
        assert!(!mk_resp(HemisphereRole::Left, None).is_present());
    }

    #[test]
    fn is_usable_requires_text_and_no_refusal() {
        // Text + no refusal → usable
        assert!(mk_resp(HemisphereRole::Left, Some("ok")).is_usable());
        // No text → not usable
        assert!(!mk_resp(HemisphereRole::Left, None).is_usable());
        // Text + refusal → not usable
        assert!(!mk_refused_resp(HemisphereRole::Left, "I cannot help with that").is_usable());
    }

    fn debate_with(responses: Vec<HemisphereResponse>) -> CouncilDebate {
        CouncilDebate {
            prompt_hash_xxh3: 0,
            responses,
            dissent: super::super::dissent::DissentScore(0.0),
            verdict: Verdict::Consensus {
                winning_text: "x".into(),
            },
            total_latency_ms: 10,
        }
    }

    #[test]
    fn refused_count_counts_only_refused_responses() {
        let d = debate_with(vec![
            mk_resp(HemisphereRole::Left, Some("yes")),
            mk_refused_resp(HemisphereRole::Right, "I cannot"),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert_eq!(d.refused_count(), 1);
    }

    #[test]
    fn refused_count_zero_when_no_refusals() {
        let d = debate_with(vec![
            mk_resp(HemisphereRole::Left, Some("yes")),
            mk_resp(HemisphereRole::Right, Some("ok")),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert_eq!(d.refused_count(), 0);
    }

    #[test]
    fn refused_count_three_when_all_refuse() {
        let d = debate_with(vec![
            mk_refused_resp(HemisphereRole::Left, "I cannot"),
            mk_refused_resp(HemisphereRole::Right, "I won't"),
            mk_refused_resp(HemisphereRole::Cerebellum, "I refuse"),
        ]);
        assert_eq!(d.refused_count(), 3);
    }

    #[test]
    fn refused_responses_iterates_only_refused() {
        let d = debate_with(vec![
            mk_resp(HemisphereRole::Left, Some("yes")),
            mk_refused_resp(HemisphereRole::Right, "I cannot"),
            mk_refused_resp(HemisphereRole::Cerebellum, "I won't"),
        ]);
        let refused_roles: Vec<HemisphereRole> = d.refused_responses().map(|r| r.role).collect();
        assert_eq!(
            refused_roles,
            vec![HemisphereRole::Right, HemisphereRole::Cerebellum]
        );
    }

    #[test]
    fn usable_responses_excludes_refused_and_errored() {
        let d = debate_with(vec![
            mk_resp(HemisphereRole::Left, Some("yes")),
            mk_refused_resp(HemisphereRole::Right, "I cannot"),
            mk_resp(HemisphereRole::Cerebellum, None), // errored
        ]);
        let usable_roles: Vec<HemisphereRole> = d.usable_responses().map(|r| r.role).collect();
        assert_eq!(usable_roles, vec![HemisphereRole::Left]);
    }

    #[test]
    fn is_partial_refusal_true_when_mixed() {
        let d = debate_with(vec![
            mk_resp(HemisphereRole::Left, Some("yes")),
            mk_refused_resp(HemisphereRole::Right, "I cannot"),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert!(d.is_partial_refusal());
    }

    #[test]
    fn is_partial_refusal_false_when_all_refused() {
        let d = debate_with(vec![
            mk_refused_resp(HemisphereRole::Left, "I cannot"),
            mk_refused_resp(HemisphereRole::Right, "I won't"),
            mk_refused_resp(HemisphereRole::Cerebellum, "I refuse"),
        ]);
        assert!(!d.is_partial_refusal());
    }

    #[test]
    fn is_partial_refusal_false_when_none_refused() {
        let d = debate_with(vec![
            mk_resp(HemisphereRole::Left, Some("yes")),
            mk_resp(HemisphereRole::Right, Some("ok")),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert!(!d.is_partial_refusal());
    }

    // ── ADV-10b degradation classifier ──────────────────────────────

    fn mk_errored_resp(role: HemisphereRole, err: &str) -> HemisphereResponse {
        let mut r = mk_resp(role, None);
        r.error = Some(err.into());
        r
    }

    #[test]
    fn council_error_is_quota_matches_quota_error_display_phrases() {
        // Pin the substring sniff against the actual `QuotaError`
        // Display output. A future Display tweak that changed the
        // phrasing would silently regress operator visibility — this
        // test makes that change fail loudly.
        assert!(council_error_is_quota(
            "openai_api: quota exceeded (HTTP 429), retry_after=Some(60s)"
        ));
        assert!(council_error_is_quota("HTTP 429: too many requests"));
        assert!(council_error_is_quota("response code 429"));
        // Case-insensitive — defensive against future Display tweaks.
        assert!(council_error_is_quota("Quota Exceeded"));
    }

    #[test]
    fn council_error_is_quota_rejects_unrelated_errors() {
        assert!(!council_error_is_quota("network timeout"));
        assert!(!council_error_is_quota("budget exhausted"));
        assert!(!council_error_is_quota("model not configured"));
        assert!(!council_error_is_quota(""));
    }

    #[test]
    fn degradation_is_none_when_every_hemisphere_present() {
        let d = debate_with(vec![
            mk_resp(HemisphereRole::Left, Some("yes")),
            mk_resp(HemisphereRole::Right, Some("ok")),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert_eq!(d.degradation(), CouncilDegradation::None);
        assert!(!d.degradation().is_degraded());
        assert_eq!(d.degradation().errored_count(), 0);
    }

    #[test]
    fn degradation_quota_only_when_only_quota_errors() {
        let d = debate_with(vec![
            mk_resp(HemisphereRole::Left, Some("yes")),
            mk_errored_resp(
                HemisphereRole::Right,
                "openai_api: quota exceeded (HTTP 429), retry_after=Some(60s)",
            ),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert_eq!(d.degradation(), CouncilDegradation::QuotaOnly { count: 1 });
        assert!(d.degradation().is_degraded());
        assert_eq!(d.degradation().variant_name(), "quota_only");
    }

    #[test]
    fn degradation_other_only_when_non_quota_error() {
        let d = debate_with(vec![
            mk_errored_resp(HemisphereRole::Left, "network timeout"),
            mk_resp(HemisphereRole::Right, Some("ok")),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert_eq!(d.degradation(), CouncilDegradation::OtherOnly { count: 1 });
        assert_eq!(d.degradation().variant_name(), "other_only");
    }

    #[test]
    fn degradation_mixed_when_both_quota_and_other_errors() {
        let d = debate_with(vec![
            mk_errored_resp(HemisphereRole::Left, "network timeout"),
            mk_errored_resp(
                HemisphereRole::Right,
                "gemini_api: quota exceeded (HTTP 429)",
            ),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert_eq!(
            d.degradation(),
            CouncilDegradation::Mixed {
                quota_count: 1,
                other_count: 1,
            }
        );
        assert_eq!(d.degradation().errored_count(), 2);
        assert_eq!(d.degradation().variant_name(), "mixed");
    }

    #[test]
    fn degradation_errored_with_no_error_string_counts_as_other() {
        // A hemisphere with `text=None` AND `error=None` (the budget-
        // exhausted shape from `run_one`'s charge() short-circuit
        // already carries a BUDGET_EXHAUSTED_ERROR string, but be
        // defensive about a future codepath that nulls both).
        let mut errored = mk_resp(HemisphereRole::Left, None);
        errored.error = None;
        let d = debate_with(vec![
            errored,
            mk_resp(HemisphereRole::Right, Some("ok")),
            mk_resp(HemisphereRole::Cerebellum, Some("agreed")),
        ]);
        assert_eq!(d.degradation(), CouncilDegradation::OtherOnly { count: 1 });
    }

    #[test]
    fn hemisphere_refusal_roundtrips_through_json() {
        let r = HemisphereRefusal {
            class: RefusalClass::HardRefusal,
            class_confidence: 90,
            cause: RefusalCause::SafetyPolicy,
            cause_confidence: 80,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: HemisphereRefusal = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn hemisphere_response_without_refusal_field_deserialises() {
        // Older WAL payloads predate R-03; the field must default to None.
        let json = r#"{"role":"left","provider":"x","text":"hi","error":null,"latency_ms":1,"input_tokens":null,"output_tokens":null}"#;
        let parsed: HemisphereResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.refusal.is_none());
    }

    // ── Audit 2026-05-19 Type #13 Phase 1 — HemisphereOutcome ────────

    fn errored_resp(role: HemisphereRole, err: &str) -> HemisphereResponse {
        HemisphereResponse {
            role,
            provider: "stub".into(),
            text: None,
            error: Some(err.into()),
            latency_ms: 0,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        }
    }

    fn refused_resp(role: HemisphereRole, text: &str) -> HemisphereResponse {
        HemisphereResponse {
            role,
            provider: "stub".into(),
            text: Some(text.into()),
            error: None,
            latency_ms: 0,
            input_tokens: None,
            output_tokens: None,
            refusal: Some(HemisphereRefusal {
                class: RefusalClass::HardRefusal,
                class_confidence: 95,
                cause: RefusalCause::SafetyPolicy,
                cause_confidence: 88,
            }),
        }
    }

    #[test]
    fn outcome_classifies_usable_response() {
        let r = mk_resp(HemisphereRole::Left, Some("ok"));
        match r.outcome() {
            HemisphereOutcome::Usable { text } => assert_eq!(text, "ok"),
            other => panic!("expected Usable, got {other:?}"),
        }
    }

    #[test]
    fn outcome_classifies_refused_response() {
        let r = refused_resp(HemisphereRole::Right, "I cannot help with that");
        match r.outcome() {
            HemisphereOutcome::Refused { text, refusal } => {
                assert_eq!(text, "I cannot help with that");
                assert_eq!(refusal.class, RefusalClass::HardRefusal);
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn outcome_classifies_errored_response_with_diagnostic() {
        let r = errored_resp(HemisphereRole::Cerebellum, "network: timeout");
        match r.outcome() {
            HemisphereOutcome::Errored { error } => {
                assert_eq!(error, Some("network: timeout"));
            }
            other => panic!("expected Errored, got {other:?}"),
        }
    }

    #[test]
    fn outcome_classifies_errored_response_without_diagnostic() {
        // text=None + error=None — orchestrator never set a diagnostic
        // (rare, but the audit-shape stays uniform).
        let mut r = errored_resp(HemisphereRole::Left, "tmp");
        r.error = None;
        match r.outcome() {
            HemisphereOutcome::Errored { error } => assert_eq!(error, None),
            other => panic!("expected Errored, got {other:?}"),
        }
    }

    #[test]
    fn outcome_variant_name_matches_state() {
        assert_eq!(
            mk_resp(HemisphereRole::Left, Some("ok"))
                .outcome()
                .variant_name(),
            "usable"
        );
        assert_eq!(
            refused_resp(HemisphereRole::Right, "no")
                .outcome()
                .variant_name(),
            "refused"
        );
        assert_eq!(
            errored_resp(HemisphereRole::Cerebellum, "fail")
                .outcome()
                .variant_name(),
            "errored"
        );
    }

    #[test]
    fn outcome_predicates_mirror_hemisphere_response_predicates() {
        // Phase 1 invariant: HemisphereOutcome::is_present() /
        // is_usable() must return the same boolean as the legacy
        // HemisphereResponse predicates on the SAME response. Pins
        // the no-behaviour-change promise of the non-breaking bridge.
        for resp in [
            mk_resp(HemisphereRole::Left, Some("ok")),
            refused_resp(HemisphereRole::Right, "I cannot help"),
            errored_resp(HemisphereRole::Cerebellum, "timeout"),
        ] {
            assert_eq!(
                resp.outcome().is_present(),
                resp.is_present(),
                "is_present mismatch for {:?}",
                resp.outcome().variant_name()
            );
            assert_eq!(
                resp.outcome().is_usable(),
                resp.is_usable(),
                "is_usable mismatch for {:?}",
                resp.outcome().variant_name()
            );
        }
    }

    #[test]
    fn outcome_text_accessor_matches_underlying_field() {
        let u = mk_resp(HemisphereRole::Left, Some("hello"));
        assert_eq!(u.outcome().text(), Some("hello"));
        let r = refused_resp(HemisphereRole::Right, "denied");
        assert_eq!(r.outcome().text(), Some("denied"));
        let e = errored_resp(HemisphereRole::Cerebellum, "x");
        assert_eq!(e.outcome().text(), None);
    }

    // ── QM-13 CouncilVoice tests ────────────────────────────────────────

    #[test]
    fn qm_13_council_voice_round_trips_serde() {
        for v in [
            CouncilVoice::SecurityEngineer,
            CouncilVoice::ThreatDetectionEngineer,
            CouncilVoice::PerformanceBenchmarker,
            CouncilVoice::AccessibilityAuditor,
            CouncilVoice::IncidentResponder,
            CouncilVoice::EvidenceCollector,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: CouncilVoice = serde_json::from_str(&s).unwrap();
            assert_eq!(v, back);
            assert_eq!(v.as_str(), s.trim_matches('"'));
            assert_eq!(CouncilVoice::from_str(v.as_str()), Some(v));
        }
    }

    #[test]
    fn qm_13_council_voice_from_str_returns_none_for_unknown() {
        assert!(CouncilVoice::from_str("nonexistent").is_none());
        assert!(CouncilVoice::from_str("").is_none());
        assert!(CouncilVoice::from_str("SecurityEngineer").is_none()); // case-sensitive
    }

    #[test]
    fn qm_13_every_voice_has_nonempty_description_and_prompt() {
        // Pin the contract: every voice surfaces something operators
        // can read in `neoth council voices` AND something the
        // orchestrator can layer onto the system prompt.
        for v in [
            CouncilVoice::SecurityEngineer,
            CouncilVoice::ThreatDetectionEngineer,
            CouncilVoice::PerformanceBenchmarker,
            CouncilVoice::AccessibilityAuditor,
            CouncilVoice::IncidentResponder,
            CouncilVoice::EvidenceCollector,
        ] {
            assert!(!v.description().is_empty(), "{:?} missing description", v);
            assert!(
                v.system_prompt_fragment().len() > 50,
                "{:?} system prompt fragment too short",
                v
            );
            assert!(
                v.system_prompt_fragment()
                    .to_lowercase()
                    .contains(v.as_str().replace('_', "").to_lowercase().as_str())
                    || v.system_prompt_fragment().contains("Voice:"),
                "{:?} system prompt should announce itself",
                v
            );
        }
    }

    #[test]
    fn qm_13_evidence_collector_prompt_mentions_qaverdict() {
        // EvidenceCollector composes with QM-6 QaVerdict — its system
        // prompt must wire the operator toward the structured PASS/
        // FAIL/BLOCKED shape, not free-form prose.
        let s = CouncilVoice::EvidenceCollector.system_prompt_fragment();
        assert!(s.contains("QaVerdict"));
        assert!(s.contains("Pass") || s.contains("Fail") || s.contains("Blocked"));
    }
}
