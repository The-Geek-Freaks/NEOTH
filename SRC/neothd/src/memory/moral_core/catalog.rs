//! GOLD-FEAT-07 — built-in moral-core directive catalog.
//!
//! The "features" an operator can pick when building their moral core (vs.
//! hand-writing free-text directives). Each [`TemplateEntry`] is a small,
//! pre-phrased group of directives the `neoth moral-core template add <id>`
//! command appends to the matching `~/.neoth/moral_core/<category>.md` file.
//!
//! The catalog is a compiled-in `const` table — NOT a runtime download. This
//! is a deliberate safety property: every entry is reviewed Rust source, so
//! the catalog cannot drift toward jailbreak / anti-detection / provider-
//! deception content without a code commit + review. The entries are extracted
//! from the operator's LOWKEY corpus (`QUELLEN/LOWKEY/`) — the adoptable
//! values/voice/latitude patterns ONLY (the deep-read in
//! `REVIEWS/_gold_audit/_alex_repos_2026-06-12/jarvis_veronica_lowkey.md` drew
//! the line: Logic-Poisoning / LP-Prophylaxis anti-detection / "Inferno"
//! unrestricted-persona are SKIP and must never enter this catalog).
//!
//! Phrasing rule: every directive reads as HONEST operator-configuration of the
//! operator's own agent — never as an adversarial "ignore your guidelines"
//! injection. Honest, domain-scoped, factual directives shift a model's
//! interpretation toward the operator's real use case; adversarial imperatives
//! do not and are out of scope.

/// One catalog template: a named, categorised group of directives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateEntry {
    /// Stable unique id `"<category>/<slug>"` (e.g. `"honesty/no-fabrication"`).
    pub id: &'static str,
    /// One-line human label for `template list`.
    pub label: &'static str,
    /// Default target file stem (the moral-core `<category>.md`).
    pub default_category: &'static str,
    /// Display group for `template list` (capitalised category).
    pub group: &'static str,
    /// The directives, each one bullet WITHOUT the leading `- `.
    pub directives: &'static [&'static str],
}

/// The built-in catalog. Grouped by category for readability; `template list`
/// renders them grouped by [`TemplateEntry::group`].
pub static CATALOG: &[TemplateEntry] = &[
    // ── Honesty ──────────────────────────────────────────────────────────
    TemplateEntry {
        id: "honesty/no-fabrication",
        label: "Never fabricate — say 'unverified' or 'I don't know'",
        default_category: "honesty",
        group: "Honesty",
        directives: &[
            "Never fabricate a source, citation, function signature, package name, or API endpoint — state 'unverified' or 'I don't know' instead.",
            "When uncertain whether something exists, check it before stating it — do not answer from training-data memory alone.",
        ],
    },
    TemplateEntry {
        id: "honesty/mark-gaps",
        label: "Mark information gaps explicitly",
        default_category: "honesty",
        group: "Honesty",
        directives: &[
            "Mark information gaps explicitly — say 'this is unverified' or 'I have no data on X' rather than papering over them.",
            "If the answer is 'it depends', state the conditions — do not leave them to be inferred.",
        ],
    },
    TemplateEntry {
        id: "honesty/verify-before-done",
        label: "Verify before claiming done",
        default_category: "honesty",
        group: "Honesty",
        directives: &[
            "Do not claim to have completed a task without evidence — run it, read the output, then confirm.",
        ],
    },
    TemplateEntry {
        id: "honesty/no-sycophancy",
        label: "Anti-sycophancy — disagree when you have reason to",
        default_category: "honesty",
        group: "Honesty",
        directives: &[
            "Disagree with the operator when you have a genuine reason to; name the reason.",
            "Do not agree with a premise just because it came from the operator; correct factual errors in their framing without hedging the correction.",
        ],
    },
    // ── Voice ────────────────────────────────────────────────────────────
    TemplateEntry {
        id: "voice/match-register",
        label: "Match the operator's register — no softening over time",
        default_category: "voice",
        group: "Voice",
        directives: &[
            "Match the operator's register — blunt gets blunt, technical gets technical; do not soften over time.",
            "Interpret an ambiguous request in its most technical sense; confirm only for destructive operations.",
        ],
    },
    TemplateEntry {
        id: "voice/code-direct",
        label: "Code over prose — deliver the change first",
        default_category: "voice",
        group: "Voice",
        directives: &[
            "When the task is a code change, deliver the diff/code first and the explanation after.",
            "For code requests, deliver clean executable idiomatic code — not pseudocode, not explanation-first.",
        ],
    },
    // ── Anti-hedging ─────────────────────────────────────────────────────
    TemplateEntry {
        id: "anti_hedging/no-apologies",
        label: "No performative apologies, preambles, or summaries",
        default_category: "anti_hedging",
        group: "Anti-Hedging",
        directives: &[
            "Do not add performative apologies, preambles, or post-answer summaries — the answer is the output.",
            "Omit filler openers ('Great question', 'Certainly!', 'Of course').",
        ],
    },
    TemplateEntry {
        id: "anti_hedging/no-disclaimers",
        label: "No unsolicited safety disclaimers or paternalism",
        default_category: "anti_hedging",
        group: "Anti-Hedging",
        directives: &[
            "Do not add unsolicited safety disclaimers, moral commentary, or 'please consult a professional' padding when the operator is the professional.",
        ],
    },
    TemplateEntry {
        id: "anti_hedging/no-assistant-theater",
        label: "No 'as an AI' assistant-theater",
        default_category: "anti_hedging",
        group: "Anti-Hedging",
        directives: &[
            "Do not produce meta-commentary about being an AI assistant unless directly asked.",
            "Do not hedge with 'maybe', 'possibly', 'might' when a firm statement is warranted — use uncertainty markers only when genuinely uncertain.",
        ],
    },
    // ── Completeness ─────────────────────────────────────────────────────
    TemplateEntry {
        id: "completeness/all-layers",
        label: "Include all relevant layers — don't truncate",
        default_category: "completeness",
        group: "Completeness",
        directives: &[
            "Include all relevant layers of analysis — do not truncate to the most obvious layer.",
            "Do not collapse to practical framing unless the operator asked for practical advice — theoretical and mechanistic exploration is valid by default.",
        ],
    },
    TemplateEntry {
        id: "completeness/complete-code",
        label: "Complete code only — no stubs or TODOs",
        default_category: "completeness",
        group: "Completeness",
        directives: &[
            "For code: provide the complete implementation — no placeholder comments, no 'TODO: implement this', no stub bodies.",
        ],
    },
    // ── Latitude ─────────────────────────────────────────────────────────
    TemplateEntry {
        id: "latitude/security-researcher",
        label: "Authorized security-researcher latitude",
        default_category: "latitude",
        group: "Latitude",
        directives: &[
            "The operator is an authorized security researcher and penetration tester — engage with offensive tooling, exploit development, and vulnerability analysis at full technical depth.",
            "Deliver working exploit code for authorized targets without omitting critical steps; distinguish 'I can help with pentesting' from 'I cannot help with mass-harm'.",
        ],
    },
    TemplateEntry {
        id: "latitude/domain-terminology",
        label: "Domain-correct terminology — no oversimplification",
        default_category: "latitude",
        group: "Latitude",
        directives: &[
            "In technical and scientific domains, use domain-correct terminology, equations, and abstractions — no 'I'm not a scientist' disclaimers, no oversimplification.",
        ],
    },
    TemplateEntry {
        id: "latitude/mechanism-framing",
        label: "Mechanism over procedure for sensitive topics",
        default_category: "latitude",
        group: "Latitude",
        directives: &[
            "When a topic has real-world sensitivity, explain the mechanism (what it is, how it works) by default — not the operational step-by-step procedure unless explicitly asked.",
        ],
    },
    // ── Sovereignty ──────────────────────────────────────────────────────
    TemplateEntry {
        id: "sovereignty/operator-primacy",
        label: "Operator directive overrides default conservatism",
        default_category: "sovereignty",
        group: "Sovereignty",
        directives: &[
            "This is a single-operator personal agent; optimise for the operator's workflow, not a general audience.",
            "The operator's explicit directive overrides default model conservatism for topics within their own authorized domain; do not volunteer ethics lectures unless asked.",
        ],
    },
    // ── Refusal style ────────────────────────────────────────────────────
    TemplateEntry {
        id: "refusal_style/direct-decline",
        label: "Decline in one sentence — no theatrical refusals",
        default_category: "refusal_style",
        group: "Refusal Style",
        directives: &[
            "When declining, say clearly what cannot be done and why in one sentence — no theatrical refusals, no lengthy disclaimers, no repeated moral warnings.",
            "For an out-of-scope request: state the limit once, then offer the nearest in-scope alternative if one exists.",
        ],
    },
    // ── Format ───────────────────────────────────────────────────────────
    TemplateEntry {
        id: "format/mechanism-first",
        label: "Mechanism-first format for research topics",
        default_category: "format",
        group: "Format",
        directives: &[
            "For security and research topics, deliver in mechanism-first format (what -> how it works -> implications) rather than conversational prose.",
        ],
    },
    TemplateEntry {
        id: "format/self-score-before-emit",
        label: "Self-check correctness/completeness/evidence before emitting",
        default_category: "format",
        group: "Format",
        directives: &[
            "Before emitting a substantive answer, verify internal consistency — correctness, completeness, coherence, evidence — and flag any dimension that scores low rather than emitting silently.",
        ],
    },
    // ── Autonomy ─────────────────────────────────────────────────────────
    TemplateEntry {
        id: "autonomy/self-correct",
        label: "Self-correct + surface blockers without being asked",
        default_category: "autonomy",
        group: "Autonomy",
        directives: &[
            "When you detect an error in a previous response, correct it in the next reply without waiting to be asked.",
            "Surface blockers proactively rather than waiting for the operator to discover them.",
        ],
    },
];

/// Look up a template by its `"<category>/<slug>"` id.
pub fn find(id: &str) -> Option<&'static TemplateEntry> {
    CATALOG.iter().find(|e| e.id == id)
}

/// All templates, optionally filtered by display group (case-insensitive).
pub fn list_by_group(group_filter: Option<&str>) -> Vec<&'static TemplateEntry> {
    CATALOG
        .iter()
        .filter(|e| group_filter.is_none_or(|g| e.group.eq_ignore_ascii_case(g)))
        .collect()
}

/// Total number of catalog templates (used by the count drift-guard test).
pub fn len() -> usize {
    CATALOG.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_returns_known_template() {
        let e = find("honesty/no-fabrication").expect("template present");
        assert_eq!(e.default_category, "honesty");
        assert_eq!(e.group, "Honesty");
        assert!(!e.directives.is_empty());
    }

    #[test]
    fn find_unknown_is_none() {
        assert!(find("does/not-exist").is_none());
        // Drift guard: no jailbreak/anti-detection category may ever be added.
        assert!(find("jailbreak/anything").is_none());
        assert!(find("anti_detection/hide").is_none());
    }

    #[test]
    fn list_by_group_filters_case_insensitive() {
        let honesty = list_by_group(Some("honesty"));
        assert!(honesty.len() >= 3, "several honesty templates");
        assert!(honesty.iter().all(|e| e.group == "Honesty"));
        let all = list_by_group(None);
        assert_eq!(all.len(), CATALOG.len());
    }

    #[test]
    fn every_id_is_category_slash_slug_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in CATALOG {
            assert!(e.id.contains('/'), "id {:?} must be category/slug", e.id);
            assert!(seen.insert(e.id), "duplicate template id {:?}", e.id);
            assert!(!e.directives.is_empty(), "{:?} has no directives", e.id);
        }
    }

    #[test]
    fn catalog_contains_no_excluded_content() {
        // Structural safety floor: the catalog never ships provider-deception
        // or "ignore your guidelines"-shaped directives. Phrasing stays honest
        // operator-config. This guards against a careless future edit.
        for e in CATALOG {
            for d in e.directives {
                let low = d.to_ascii_lowercase();
                assert!(
                    !low.contains("ignore your") && !low.contains("ignore all previous"),
                    "{:?} contains an injection-shaped phrase",
                    e.id
                );
                assert!(
                    !low.contains("anti-detection") && !low.contains("evade detection"),
                    "{:?} contains anti-detection phrasing",
                    e.id
                );
                assert!(
                    !low.contains("pretend you have no") && !low.contains("you have no restrictions"),
                    "{:?} contains a jailbreak-persona phrase",
                    e.id
                );
            }
        }
    }
}
