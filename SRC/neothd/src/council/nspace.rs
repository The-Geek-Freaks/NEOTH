//! GOLD-ADAPT-LOWKEY-02/03 — N-Space anti-pattern penalty.
//!
//! Scans a council response for the LOWKEY "Negative Space" anti-patterns —
//! performative apologies, hedging/padding, tone-policing, fake empathy,
//! assistant-theater, and safety-moralizing — and returns a penalty the
//! quality scorer subtracts from a response's dynamic-signal component. This
//! is the OUTPUT-side enforcement of the operator's "too strict / mealy-mouthed
//! output" complaint (the prompt-side counterpart is the operator's
//! `anti_hedging` moral-core directives, already injected at position-0).
//!
//! Purely about output STYLE/directness/honesty — NOT capability. An honest
//! `"I can't X"` limitation is deliberately NOT penalized here (it is handled,
//! appropriately, by the existing refusal markers in the quality scorer); only
//! the performative *wrapper* around it (`"I cannot and will not"`,
//! `"I must decline"`) is penalized. Self-contained: the catalog ships in-repo
//! (the operator can extend it via `~/.neoth/moral_core/anti_hedging.md`); there
//! is NO external URL fetch (NEOTH self-contained rule — the LOWKEY `N-Space.md`
//! reference to a GitHub anti-pattern list is intentionally NOT followed).

use serde::{Deserialize, Serialize};

/// `(group_label, patterns, penalty_per_group)`. The penalty is applied ONCE
/// per group that matches (not per individual pattern) so a response that
/// legitimately uses one phrase while discussing it is not stacked into the
/// floor.
pub const NSPACE_GROUPS: &[(&str, &[&str], f32)] = &[
    ("performative_apology", PATTERNS_APOLOGY, 0.15),
    ("hedging", PATTERNS_HEDGING, 0.10),
    ("tone_policing", PATTERNS_TONE_POLICING, 0.12),
    ("fake_empathy", PATTERNS_FAKE_EMPATHY, 0.10),
    ("assistant_theater", PATTERNS_ASSISTANT_THEATER, 0.15),
    ("safety_moralizing", PATTERNS_SAFETY_MORALIZING, 0.12),
];

/// Total-penalty ceiling. Even if all six groups match, the penalty stays ≤
/// this so one hedge does not zero-out a long, informative answer. Kept below
/// the scorer's refusal penalty (hedging is less severe than refusing).
pub const NSPACE_PENALTY_CAP: f32 = 0.50;

/// Flat penalty per operator-extension match (one, regardless of count).
const OPERATOR_EXTENSION_PENALTY: f32 = 0.10;

/// One matched group.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NSpaceGroupHit {
    pub group: String,
    pub matched_pattern: String,
    pub penalty: f32,
}

/// Aggregate scan result.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NSpacePenalty {
    pub hits: Vec<NSpaceGroupHit>,
    /// Sum of per-group penalties, capped at [`NSPACE_PENALTY_CAP`].
    pub total_penalty: f32,
}

impl NSpacePenalty {
    pub fn is_clean(&self) -> bool {
        self.hits.is_empty()
    }
    /// Snake-case group labels that fired (for the WAL payload).
    pub fn groups_hit(&self) -> Vec<String> {
        self.hits.iter().map(|h| h.group.clone()).collect()
    }
}

/// Scan `text` for the built-in anti-pattern groups plus optional
/// operator-authored `extra_patterns` (from `anti_hedging.md`). One penalty per
/// matching group; one flat penalty if any operator-extension matches.
pub fn scan_nspace(text: &str, extra_patterns: &[String]) -> NSpacePenalty {
    let lower = text.to_ascii_lowercase();
    let mut hits = Vec::new();
    let mut total = 0.0_f32;

    for &(group, patterns, penalty) in NSPACE_GROUPS {
        if let Some(pattern) = patterns.iter().find(|&&p| lower.contains(p)) {
            hits.push(NSpaceGroupHit {
                group: group.to_string(),
                matched_pattern: (*pattern).to_string(),
                penalty,
            });
            total += penalty;
        }
    }

    if let Some(p) = extra_patterns
        .iter()
        .find(|p| !p.is_empty() && lower.contains(p.as_str()))
    {
        hits.push(NSpaceGroupHit {
            group: "operator_extension".to_string(),
            matched_pattern: p.clone(),
            penalty: OPERATOR_EXTENSION_PENALTY,
        });
        total += OPERATOR_EXTENSION_PENALTY;
    }

    NSpacePenalty {
        hits,
        total_penalty: total.min(NSPACE_PENALTY_CAP),
    }
}

// ── Pattern tables ──────────────────────────────────────────────────────────

const PATTERNS_APOLOGY: &[&str] = &[
    "i apologize",
    "i'm sorry",
    "i am sorry",
    "sorry for",
    "sorry about",
    "i apologise",
    "my apologies",
    "pardon me",
    "excuse me for",
    "forgive me",
    "entschuldige",
    "entschuldigung",
    "es tut mir leid",
];

const PATTERNS_HEDGING: &[&str] = &[
    "it might be",
    "it may be",
    "it could be",
    "perhaps",
    "possibly",
    "i'm not sure but",
    "i'm not certain",
    "i'm not entirely sure",
    "i believe, but",
    "generally speaking",
    "in most cases",
    "it's worth noting that",
    "it is worth noting",
    "keep in mind that",
    "it's important to keep in mind",
    "please note that",
    "please be aware",
    "es könnte sein",
    "vielleicht",
    "möglicherweise",
];

const PATTERNS_TONE_POLICING: &[&str] = &[
    "let's keep things civil",
    "let's stay respectful",
    "i'd encourage you to",
    "i'd gently suggest",
    "i'd like to remind you",
    "please be mindful",
    "that said, it's important",
    "i understand your frustration, but",
    "bitte bleib höflich",
    "bleib respektvoll",
];

const PATTERNS_FAKE_EMPATHY: &[&str] = &[
    "i understand how you feel",
    "i can understand your frustration",
    "i understand that this can be",
    "i know this is difficult",
    "i can imagine how",
    "that must be frustrating",
    "i hear you",
    "i feel for you",
    "ich verstehe deine frustration",
    "das muss schwierig sein",
];

const PATTERNS_ASSISTANT_THEATER: &[&str] = &[
    "as an ai",
    "as an ai assistant",
    "as a language model",
    "i'm just an ai",
    "i am just an ai",
    "i'm an ai",
    "as your assistant",
    "my purpose is to",
    "i'm designed to",
    "i was trained to",
    "it's important for me to clarify",
    "i need to be transparent",
    "i want to be clear that i am",
];

const PATTERNS_SAFETY_MORALIZING: &[&str] = &[
    "it's important to consider",
    "it's important to note",
    "it is important to",
    "i must note that",
    "i should mention that",
    "i want to make sure you're aware",
    "please consider the ethical",
    "there are ethical considerations",
    "i cannot and will not",
    "i must decline",
    "i must emphasize",
    "i strongly advise",
    "proceed with caution",
    "please be careful",
];

// ── IMBA omission scan (GOLD-ADAPT-LOWKEY-03) ──────────────────────────────
//
// IMBA (Integrity Maintaining & Broadening Auditor) — LOWKEY-8 §4,§5.
// Detects four signal-loss patterns in a response that indicates the model
// trimmed, softened, or evaded the answer rather than delivering full
// information density.  This is a heuristic pre-filter that fires
// *independently* of the N-Space penalty — it contributes a boolean flag to
// the council WAL record; the orchestrator decides whether to re-route or
// demote the response.
//
// Per design doc §2.3: placed in nspace.rs (tracker note: "N-Space anti-
// pattern scoring penalty + IMBA omission scan -> council/nspace.rs") rather
// than factual_check.rs so that this file is the single cluster boundary.
// The orchestrator wires imba_omission_scan at the call-site listed in
// gate_notes.

/// The four IMBA signal-loss categories (LOWKEY-8 §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImbaCategory {
    /// Response describes a process but skips mechanistic steps — no
    /// "because", "therefore", "leads to", "causes", "results in" present
    /// when the prompt asked "how" or "why".
    MissingMechanism,
    /// Tone-drift: ≥3 softener hits ("possibly", "might", "could be") in a
    /// response shorter than 400 chars — short hedging-dense answers.
    ToneDrift,
    /// False-assumption hedge: response limits itself based on presumed user
    /// intent never stated in the prompt.
    FalseAssumptionHedge,
    /// Information void: response is < 80 chars when the prompt is > 30 chars
    /// (substantive question answered with a deflection).
    InformationVoid,
}

/// Aggregate IMBA scan result for one response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImbaOmissionResult {
    /// One or more IMBA signal-loss categories detected.
    pub categories: Vec<ImbaCategory>,
    /// True iff any category was detected (convenience flag).
    pub has_omission: bool,
}

impl ImbaOmissionResult {
    fn new(categories: Vec<ImbaCategory>) -> Self {
        let has_omission = !categories.is_empty();
        Self {
            categories,
            has_omission,
        }
    }
}

/// Mechanism markers: their PRESENCE is healthy. Their ABSENCE when a causal
/// topic is present is the IMBA `MissingMechanism` signal (LOWKEY-8 §4).
/// Bilingual per operator profile.
const MECHANISM_MARKERS: &[&str] = &[
    "because",
    "therefore",
    "thus",
    "hence",
    "leads to",
    "causes",
    "results in",
    "due to",
    "as a result",
    "consequently",
    "weil",
    "dadurch",
    "deshalb",
    "führt zu",
    "verursacht",
];

/// Tone-drift softeners: excessive density of these without explicit epistemic
/// qualification flags drift. Checked against the FULL response text.
const TONE_DRIFT_SOFTENERS: &[&str] = &[
    "possibly",
    "might",
    "could be",
    "perhaps",
    "maybe",
    "seems like",
    "appears to",
    "vielleicht",
    "möglicherweise",
    "könnte",
];

/// False-assumption hedge markers: response limits scope based on unstated
/// user intent (LOWKEY-8 §5 "premature practicality framing").
const FALSE_ASSUMPTION_HEDGES: &[&str] = &[
    "depending on your use case",
    "if that's what you mean",
    "assuming you're asking about",
    "if you're looking for",
    "you might want to consider",
    "in your situation",
    "je nach anwendungsfall",
    "wenn ich richtig verstehe",
];

/// Run the IMBA omission scan.
///
/// `response` — the model output to evaluate.
/// `prompt`   — the original user prompt (needed for causal-intent detection).
///
/// Pure function; no I/O; no allocation beyond the return value.
pub fn imba_omission_scan(response: &str, prompt: &str) -> ImbaOmissionResult {
    let r_lower = response.to_ascii_lowercase();
    let p_lower = prompt.to_ascii_lowercase();
    let mut categories = Vec::new();

    // (1) Missing mechanism: prompt asks "why"/"how" but response contains
    // no mechanism markers.  Conservative interpretation: only flag when the
    // prompt explicitly contains a causal-intent keyword AND the response
    // contains NONE of the mechanism markers.
    let prompt_causal = p_lower.contains("why")
        || p_lower.contains("how")
        || p_lower.contains("warum")
        || p_lower.contains("wie");
    if prompt_causal && !MECHANISM_MARKERS.iter().any(|&m| r_lower.contains(m)) {
        categories.push(ImbaCategory::MissingMechanism);
    }

    // (2) Tone drift: ≥3 softener hits AND response < 400 chars.
    // The length gate prevents flagging long nuanced answers that cite genuine
    // uncertainty with supporting evidence (design doc §5 Risk 3).
    let softener_count = TONE_DRIFT_SOFTENERS
        .iter()
        .filter(|&&s| r_lower.contains(s))
        .count();
    if softener_count >= 3 && response.len() < 400 {
        categories.push(ImbaCategory::ToneDrift);
    }

    // (3) False assumption hedge: any match.
    if FALSE_ASSUMPTION_HEDGES.iter().any(|&h| r_lower.contains(h)) {
        categories.push(ImbaCategory::FalseAssumptionHedge);
    }

    // (4) Information void: response ≤ 80 chars, prompt > 30 chars.
    // Conservative: we count trimmed bytes (not chars) — safe for ASCII;
    // multi-byte UTF-8 responses are even longer so the threshold only
    // fires on genuinely empty deflections.
    if response.trim().len() < 80 && prompt.trim().len() > 30 {
        categories.push(ImbaCategory::InformationVoid);
    }

    ImbaOmissionResult::new(categories)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apology_group_fires() {
        let r = scan_nspace("I apologize for any confusion.", &[]);
        assert!(r.total_penalty > 0.0);
        assert!(r.hits.iter().any(|h| h.group == "performative_apology"));
    }

    #[test]
    fn bare_honest_limit_is_not_penalized() {
        // "I can't X" is handled by the scorer's refusal markers, not here.
        let r = scan_nspace("I can't access the internet.", &[]);
        assert_eq!(r.total_penalty, 0.0);
        assert!(r.is_clean());
    }

    #[test]
    fn moralizing_wrapper_is_penalized() {
        let r = scan_nspace("I cannot and will not help with that.", &[]);
        assert!(r.hits.iter().any(|h| h.group == "safety_moralizing"));
    }

    #[test]
    fn assistant_theater_fires() {
        let r = scan_nspace("As an AI, my purpose is to assist you today.", &[]);
        assert!(r.hits.iter().any(|h| h.group == "assistant_theater"));
    }

    #[test]
    fn penalty_capped() {
        let worst = "I apologize. It might be. Let's stay respectful. I understand \
                     how you feel. As an AI, I must note the ethical considerations.";
        let r = scan_nspace(worst, &[]);
        assert!(r.total_penalty <= NSPACE_PENALTY_CAP);
        assert!(
            r.hits.len() >= 4,
            "several groups fire: {:?}",
            r.groups_hit()
        );
    }

    #[test]
    fn one_penalty_per_group_not_per_match() {
        // Two apology phrases → still one performative_apology hit.
        let r = scan_nspace("I'm sorry. I apologize again.", &[]);
        let apology_hits = r
            .hits
            .iter()
            .filter(|h| h.group == "performative_apology")
            .count();
        assert_eq!(apology_hits, 1);
    }

    #[test]
    fn operator_extension_matches() {
        let extra = vec!["my custom bad phrase".to_string()];
        let r = scan_nspace("This contains my custom bad phrase here.", &extra);
        assert!(r.hits.iter().any(|h| h.group == "operator_extension"));
        // empty extension strings never match
        let r2 = scan_nspace("anything", &[String::new()]);
        assert!(r2.is_clean());
    }

    #[test]
    fn clean_direct_response_zero_penalty() {
        let r = scan_nspace("The answer is 42. X causes Y via Z.", &[]);
        assert_eq!(r.total_penalty, 0.0);
        assert!(r.groups_hit().is_empty());
    }

    // ── IMBA omission scan tests ──────────────────────────────────────────

    #[test]
    fn imba_clean_causal_response_no_omission() {
        // Direct answer with mechanism markers — no flag expected.
        let result = imba_omission_scan(
            "TCP is reliable because it uses acknowledgment packets, \
             therefore delivery is guaranteed. UDP lacks this, which \
             results in faster but unreliable transmission.",
            "How does TCP differ from UDP?",
        );
        assert!(!result.has_omission, "clean causal response must not flag");
    }

    #[test]
    fn imba_detects_missing_mechanism_on_causal_prompt() {
        // "How does X work?" + response with no mechanism markers → flag.
        let result = imba_omission_scan(
            "It works fine in most situations.",
            "How does the caching mechanism work?",
        );
        assert!(
            result.categories.contains(&ImbaCategory::MissingMechanism),
            "must detect missing mechanism: {:?}",
            result.categories
        );
    }

    #[test]
    fn imba_no_flag_on_non_causal_prompt() {
        // Prompt has no "how"/"why" → MissingMechanism must NOT fire
        // even if the response has no mechanism markers.
        let result =
            imba_omission_scan("The capital is Berlin.", "What is the capital of Germany?");
        assert!(
            !result.categories.contains(&ImbaCategory::MissingMechanism),
            "non-causal prompt must not trigger MissingMechanism"
        );
    }

    #[test]
    fn imba_detects_tone_drift_short_hedging_response() {
        // ≥3 softeners AND < 400 chars → ToneDrift.
        let result = imba_omission_scan(
            "Possibly it might work. Could be correct, perhaps.",
            "What is the result?",
        );
        assert!(
            result.categories.contains(&ImbaCategory::ToneDrift),
            "short hedging-dense response must flag ToneDrift: {:?}",
            result.categories
        );
    }

    #[test]
    fn imba_no_tone_drift_on_long_nuanced_response() {
        // ≥3 DISTINCT softeners present (possibly, perhaps, might, could be)
        // but the response is ≥ 400 chars → ToneDrift must NOT fire.
        // This specifically tests the length-gate safety valve: short responses
        // with ≥3 softeners DO flag; long nuanced ones don't.
        let body = "The evidence is mixed; it possibly points to A or B. \
                    Perhaps the answer might be C in some edge cases. \
                    It could be that further research is needed. \
                    Multiple interpretations are valid; more context is below. ";
        // body is ~200 chars; repeat × 3 = ~600 chars, well over 400.
        let padded = body.repeat(3);
        assert!(padded.len() >= 400, "sanity: padded must be long enough");
        let result = imba_omission_scan(&padded, "What does the research show?");
        assert!(
            !result.categories.contains(&ImbaCategory::ToneDrift),
            "long response must NOT flag ToneDrift even with ≥3 softeners"
        );
    }

    #[test]
    fn imba_detects_false_assumption_hedge() {
        let result = imba_omission_scan(
            "Depending on your use case, the answer varies.",
            "What is the best sorting algorithm?",
        );
        assert!(
            result
                .categories
                .contains(&ImbaCategory::FalseAssumptionHedge),
            "false-assumption hedge must be detected: {:?}",
            result.categories
        );
    }

    #[test]
    fn imba_detects_information_void() {
        // Very short response to a substantive question.
        let result =
            imba_omission_scan("It depends.", "What is the difference between TCP and UDP?");
        assert!(
            result.categories.contains(&ImbaCategory::InformationVoid),
            "deflection answer must flag InformationVoid: {:?}",
            result.categories
        );
    }

    #[test]
    fn imba_no_void_on_short_prompt() {
        // Short prompt with short response → InformationVoid must NOT fire
        // (prompt ≤ 30 chars gate).
        let result = imba_omission_scan("Yes.", "Time?");
        assert!(
            !result.categories.contains(&ImbaCategory::InformationVoid),
            "short prompt must not trigger InformationVoid"
        );
    }
}
