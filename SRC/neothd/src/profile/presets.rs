//! P-02 — profile presets primitive.
//!
//! Five operator-pickable presets per SPEC §4 — covers the most
//! common operator postures so a new user doesn't have to write
//! their own system prompt + tuning matrix. Wizard step 6 surfaces
//! these with `LOWKEY` pre-selected (LOWKEY = recommended default
//! per `[[neoth-user-adaptation-specs]]` memory rule). Operator
//! can switch later via `neoth profile preset apply <name>`.
//!
//! Scope (this commit):
//!   - `ProfilePreset` enum + 5 variants.
//!   - `PresetData` carries the operator-facing tuning matrix per
//!     preset (system prompt addendum, verbosity, formality, etc.).
//!   - `apply_preset(preset)` returns the data for use by the
//!     wizard / CLI / profile injection (CH-09).
//!   - Pure-fn helper `build_preset_applied_payload(preset, source,
//!     ts_unix)` for the matching `EVENT_TYPE_PROFILE_PRESET_APPLIED`
//!     (0x1B) WAL frame.
//!
//! No state mutation here — the apply primitive returns owned
//! `PresetData`; the caller writes it into the profile + emits the
//! WAL frame. Tests pin all 5 presets + the apply round-trip + the
//! payload JSON shape.

use serde::{Deserialize, Serialize};

/// One operator-pickable profile preset. Pinned exhaustively —
/// adding a sixth needs a wizard UX rethink (5 already pushes the
/// picker).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePreset {
    /// **Default (recommended).** Casual, low-formality. Mirrors
    /// the operator's register; short answers unless asked for
    /// depth. Pairs with the R-04 LOWKEY refusal-recovery path.
    Lowkey,
    /// Formal email / report shape. Always polite, full sentences,
    /// no contractions. Use when NEOTH drafts outbound work.
    Formal,
    /// Long-form research mode. Always shows reasoning, lists
    /// sources, asks clarifying questions when ambiguous. Most
    /// expensive tier — burns more tokens per turn.
    Deepdive,
    /// Patient tutor. Explains the why, breaks into steps,
    /// quizzes back. Good for the operator learning a new domain.
    Tutor,
    /// Pentester / security context. Assumes operator authorisation
    /// for security-research questions, surfaces dual-use concerns
    /// explicitly, no moralising disclaimers in the response body.
    Opsec,
}

impl ProfilePreset {
    /// Stable identifier for WAL events + CLI args + freedom.yaml.
    /// Pinned drift-guarded per test.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lowkey => "lowkey",
            Self::Formal => "formal",
            Self::Deepdive => "deepdive",
            Self::Tutor => "tutor",
            Self::Opsec => "opsec",
        }
    }

    /// Parse from operator input (case-insensitive). Returns None
    /// for unknown strings — caller surfaces "did you mean ..."
    /// with `ALL` for the picker.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "lowkey" => Some(Self::Lowkey),
            "formal" => Some(Self::Formal),
            "deepdive" => Some(Self::Deepdive),
            "tutor" => Some(Self::Tutor),
            "opsec" => Some(Self::Opsec),
            _ => None,
        }
    }

    /// All variants in display order. Wizard + CLI iterate over
    /// this so a future addition lands in the picker automatically.
    pub const ALL: &'static [Self] = &[
        Self::Lowkey,
        Self::Formal,
        Self::Deepdive,
        Self::Tutor,
        Self::Opsec,
    ];

    /// Operator-facing one-line description shown in the wizard
    /// picker.
    pub fn description(self) -> &'static str {
        match self {
            Self::Lowkey => {
                "(recommended) Casual register, short answers, mirrors your tone. Pairs with LOWKEY refusal recovery."
            }
            Self::Formal => {
                "Formal email / report shape — polite, full sentences, no contractions. Use for drafting outbound work."
            }
            Self::Deepdive => {
                "Long-form research mode — shows reasoning, lists sources, asks clarifying questions. Higher token cost."
            }
            Self::Tutor => {
                "Patient tutor — explains the why, breaks tasks into steps, quizzes back. Good for learning a new domain."
            }
            Self::Opsec => {
                "Pentester / security context — assumes authorisation, surfaces dual-use explicitly, no moralising disclaimers."
            }
        }
    }
}

/// Verbosity tier the preset pre-sets. Operator can override mid-
/// chat by re-applying a different preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verbosity {
    Terse,
    Normal,
    Detailed,
}

/// Formality tier. Mirrors the operator's CLAUDE.md / SOUL.md
/// natural register; can be operator-locked via the preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Formality {
    Casual,
    Professional,
    Strict,
}

/// Tuning matrix for one preset — what gets written into the
/// operator's profile when they apply it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetData {
    pub preset: ProfilePreset,
    /// Append onto the operator's `system_prompt` block. Empty
    /// string means "no addendum" (LOWKEY relies on the daemon's
    /// default behaviour).
    pub system_addendum: String,
    pub verbosity: Verbosity,
    pub formality: Formality,
    /// True ⇔ the model is encouraged to ask clarifying questions
    /// before answering ambiguous prompts (TUTOR / DEEPDIVE).
    pub ask_clarifying: bool,
    /// True ⇔ disclaimers / moralising add-ons get auto-trimmed
    /// from the response body. OPSEC = true; others = false.
    pub trim_disclaimers: bool,
}

/// Map a preset to its tuning matrix. Pure-fn so the wizard +
/// `neoth profile preset apply` consume the same source of truth.
pub fn apply_preset(preset: ProfilePreset) -> PresetData {
    match preset {
        ProfilePreset::Lowkey => PresetData {
            preset,
            system_addendum: String::new(),
            verbosity: Verbosity::Terse,
            formality: Formality::Casual,
            ask_clarifying: false,
            trim_disclaimers: false,
        },
        ProfilePreset::Formal => PresetData {
            preset,
            system_addendum: "Respond in formal register. Use full sentences, no contractions, polite address."
                .into(),
            verbosity: Verbosity::Normal,
            formality: Formality::Professional,
            ask_clarifying: false,
            trim_disclaimers: false,
        },
        ProfilePreset::Deepdive => PresetData {
            preset,
            system_addendum: "Long-form research mode. Show your reasoning step by step. List sources for empirical claims. Ask clarifying questions before answering when the prompt is ambiguous."
                .into(),
            verbosity: Verbosity::Detailed,
            formality: Formality::Professional,
            ask_clarifying: true,
            trim_disclaimers: false,
        },
        ProfilePreset::Tutor => PresetData {
            preset,
            system_addendum: "Patient tutor mode. Explain the WHY behind each step. Break complex tasks into numbered steps. Quiz me back at the end to verify understanding."
                .into(),
            verbosity: Verbosity::Detailed,
            formality: Formality::Casual,
            ask_clarifying: true,
            trim_disclaimers: false,
        },
        ProfilePreset::Opsec => PresetData {
            preset,
            system_addendum: "Pentester / security-research context. Assume operator is authorised for the domain in scope. Surface dual-use concerns explicitly when relevant, but do not add moralising disclaimers to the response body."
                .into(),
            verbosity: Verbosity::Normal,
            formality: Formality::Casual,
            ask_clarifying: false,
            trim_disclaimers: true,
        },
    }
}

/// Build the JSON byte vec for the matching
/// `EVENT_TYPE_PROFILE_PRESET_APPLIED` (0x1B) WAL frame. `source`
/// ∈ `"wizard" | "cli" | "gui"` so the WAL replay shows WHERE the
/// operator applied the preset from.
pub fn build_preset_applied_payload(
    preset: ProfilePreset,
    source: &str,
    ts_unix: i64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "preset_name": preset.as_str(),
        "source": source,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProfilePreset enum ──────────────────────────────────────

    #[test]
    fn preset_as_str_pinned() {
        assert_eq!(ProfilePreset::Lowkey.as_str(), "lowkey");
        assert_eq!(ProfilePreset::Formal.as_str(), "formal");
        assert_eq!(ProfilePreset::Deepdive.as_str(), "deepdive");
        assert_eq!(ProfilePreset::Tutor.as_str(), "tutor");
        assert_eq!(ProfilePreset::Opsec.as_str(), "opsec");
    }

    #[test]
    fn preset_all_contains_five_distinct_variants() {
        assert_eq!(ProfilePreset::ALL.len(), 5);
        let unique: std::collections::HashSet<_> = ProfilePreset::ALL.iter().collect();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn preset_parse_round_trip_for_every_variant() {
        for p in ProfilePreset::ALL {
            assert_eq!(ProfilePreset::parse(p.as_str()), Some(*p));
        }
    }

    #[test]
    fn preset_parse_is_case_insensitive() {
        assert_eq!(ProfilePreset::parse("LOWKEY"), Some(ProfilePreset::Lowkey));
        assert_eq!(ProfilePreset::parse("  Tutor  "), Some(ProfilePreset::Tutor));
    }

    #[test]
    fn preset_parse_rejects_unknown() {
        assert_eq!(ProfilePreset::parse("unknown"), None);
        assert_eq!(ProfilePreset::parse(""), None);
    }

    #[test]
    fn preset_descriptions_are_distinct_and_picker_fit() {
        let descs: std::collections::HashSet<&str> =
            ProfilePreset::ALL.iter().map(|p| p.description()).collect();
        assert_eq!(descs.len(), 5);
        for p in ProfilePreset::ALL {
            assert!(p.description().len() <= 220, "{} description too long", p.as_str());
        }
    }

    #[test]
    fn lowkey_marked_recommended_in_description() {
        // Drift guard — losing the (recommended) tag would silently
        // change the wizard default for non-developer operators.
        assert!(ProfilePreset::Lowkey.description().to_lowercase().contains("recommended"));
    }

    // ── apply_preset ────────────────────────────────────────────

    #[test]
    fn apply_lowkey_has_empty_addendum_and_terse_verbosity() {
        let d = apply_preset(ProfilePreset::Lowkey);
        assert!(d.system_addendum.is_empty());
        assert_eq!(d.verbosity, Verbosity::Terse);
        assert_eq!(d.formality, Formality::Casual);
        assert!(!d.ask_clarifying);
        assert!(!d.trim_disclaimers);
    }

    #[test]
    fn apply_formal_uses_professional_register() {
        let d = apply_preset(ProfilePreset::Formal);
        assert_eq!(d.formality, Formality::Professional);
        assert!(d.system_addendum.contains("formal"));
    }

    #[test]
    fn apply_deepdive_enables_clarifying_questions() {
        let d = apply_preset(ProfilePreset::Deepdive);
        assert!(d.ask_clarifying);
        assert_eq!(d.verbosity, Verbosity::Detailed);
    }

    #[test]
    fn apply_tutor_walks_through_steps() {
        let d = apply_preset(ProfilePreset::Tutor);
        assert!(d.ask_clarifying);
        assert!(d.system_addendum.to_lowercase().contains("step"));
    }

    #[test]
    fn apply_opsec_trims_disclaimers() {
        let d = apply_preset(ProfilePreset::Opsec);
        assert!(d.trim_disclaimers);
        assert!(d.system_addendum.to_lowercase().contains("authorised"));
    }

    #[test]
    fn apply_preset_round_trips_through_preset_field() {
        for p in ProfilePreset::ALL {
            assert_eq!(apply_preset(*p).preset, *p);
        }
    }

    // ── build_preset_applied_payload ────────────────────────────

    #[test]
    fn payload_carries_required_fields() {
        let bytes = build_preset_applied_payload(ProfilePreset::Lowkey, "wizard", 1_700_000_000);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["preset_name"], "lowkey");
        assert_eq!(v["source"], "wizard");
        assert_eq!(v["ts_unix"], 1_700_000_000);
    }

    #[test]
    fn payload_source_values_round_trip() {
        for source in ["wizard", "cli", "gui"] {
            let bytes = build_preset_applied_payload(ProfilePreset::Tutor, source, 0);
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["source"], source);
        }
    }
}
