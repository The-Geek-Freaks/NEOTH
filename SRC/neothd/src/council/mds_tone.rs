//! GOLD-ADAPT-LOWKEY-08 — Dynamic-persona MDS tone modifier.
//!
//! Given a per-turn *input intensity* signal derived from the operator's
//! current prompt (character count, urgency markers, command vs. question
//! register), selects and injects a tone-modifier string into the
//! `persona_override` slot of `EnrichmentInputs`, making NEOTH's tone
//! adapt dynamically per-turn within the LOWKEY/Lowkey persona posture.
//!
//! The classifier is **pure-fn over `&str`** — no I/O, no DB, no allocations
//! beyond a single `String` return. Safe to call in the hot path of
//! `build_prompt_bundle` once per turn.
//!
//! **Bilingual (DE/EN):** urgency markers include German synonyms
//! ("sofort", "dringend", "jetzt", "JETZT", "bitte dringend") following
//! the LOWKEY-03 nspace pattern precedent.
//!
//! **No WAL event:** following LOWKEY-05/07 precedent, per-turn annotation
//! uses `eprintln!` to STDERR only — all WAL byte bands are occupied.

use serde::{Deserialize, Serialize};

/// Per-turn prompt intensity level — drives tone-modifier selection.
///
/// Ordered from least to most intense. `PartialOrd` is implemented
/// explicitly (not derived) to guard against variant reordering bugs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputIntensity {
    /// Very short or greeting-style prompt — no tone change needed.
    Low,
    /// Normal working prompt (30–199 chars, no urgency markers).
    Medium,
    /// Long prompt (≥200 chars) OR contains urgency marker(s).
    High,
    /// ALL-CAPS + exclamation, OR 3+ urgency markers in a short prompt.
    Urgent,
}

impl InputIntensity {
    /// Numeric level for ordering comparisons.
    fn level(self) -> u8 {
        match self {
            InputIntensity::Low => 0,
            InputIntensity::Medium => 1,
            InputIntensity::High => 2,
            InputIntensity::Urgent => 3,
        }
    }
}

impl PartialOrd for InputIntensity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.level().cmp(&other.level()))
    }
}

impl Ord for InputIntensity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.level().cmp(&other.level())
    }
}

/// Urgency marker patterns — bilingual (EN + DE).
/// Case-insensitive matching is applied at the call site.
const URGENCY_MARKERS: &[&str] = &[
    // English
    "asap",
    "urgent",
    "urgently",
    "immediately",
    "right now",
    "right away",
    "critical",
    "emergency",
    "nowait",
    // German
    "sofort",
    "dringend",
    "dringendst",
    "jetzt sofort",
    "bitte dringend",
    "eilig",
    "notfall",
];

/// Simple greeting patterns that classify a short prompt as `Low` regardless
/// of length. Matched as whole-prompt prefix/suffix after trim + lower.
const GREETING_PATTERNS: &[&str] = &[
    "hi", "hallo", "hey", "hello", "guten morgen", "guten tag", "guten abend",
    "moin", "servus", "jo", "ok", "okay", "ja", "nein", "danke", "thanks",
    "thx", "bitte", "bye", "tschüss", "ciao", "later",
];

/// Count how many urgency markers appear in `text` (case-insensitive).
fn count_urgency_markers(text: &str) -> usize {
    let lower = text.to_lowercase();
    URGENCY_MARKERS
        .iter()
        .filter(|&&m| lower.contains(m))
        .count()
}

/// Count ALL-CAPS words in `text` (≥2 uppercase letters, no digits).
fn count_caps_words(text: &str) -> usize {
    text.split_whitespace()
        .filter(|w| {
            let letters: String = w.chars().filter(|c| c.is_alphabetic()).collect();
            letters.len() >= 2 && letters.chars().all(|c| c.is_uppercase())
        })
        .count()
}

/// Classify the intensity of a single operator prompt.
///
/// Pure function — no I/O, no side effects. Suitable for the hot dispatch
/// path (`build_prompt_bundle` / channel handler).
///
/// Priority order (high wins):
/// 1. ALL-CAPS + exclamation → Urgent
/// 2. 3+ urgency markers in short prompt → Urgent
/// 3. Any urgency marker → High (overrides greeting / short-prompt Low)
/// 4. Long prompt (≥200 chars) → High
/// 5. Greeting pattern (short prompt, no markers) → Low
/// 6. Short prompt (<30 chars, no markers) → Low
/// 7. Default → Medium
pub fn classify_intensity(prompt: &str) -> InputIntensity {
    let trimmed = prompt.trim();
    let lower = trimmed.to_lowercase();
    let char_count = trimmed.chars().count();

    // ── ALL-CAPS + exclamation → Urgent (checked first) ─────────────────
    let has_exclamation = trimmed.ends_with('!') || trimmed.contains("!!");
    let caps_words = count_caps_words(trimmed);
    if caps_words >= 1 && has_exclamation {
        return InputIntensity::Urgent;
    }

    // ── Urgency-marker count ─────────────────────────────────────────────
    // Checked BEFORE greeting fast-path so "mach das sofort" (14 chars)
    // returns High rather than Low — urgency beats brevity.
    let urgency_count = count_urgency_markers(trimmed);

    // ── 3+ urgency markers in a short prompt → Urgent ───────────────────
    if urgency_count >= 3 && char_count < 200 {
        return InputIntensity::Urgent;
    }

    // ── Any urgency marker → High ────────────────────────────────────────
    if urgency_count >= 1 {
        return InputIntensity::High;
    }

    // ── Long prompt (≥200 chars) → High ─────────────────────────────────
    if char_count >= 200 {
        return InputIntensity::High;
    }

    // ── Greeting fast-path (short, no urgency) → Low ─────────────────────
    if char_count <= 30 {
        let is_greeting = GREETING_PATTERNS
            .iter()
            .any(|&pat| lower == pat || lower.starts_with(&format!("{pat} ")) || lower.ends_with(&format!(" {pat}")));
        if is_greeting {
            return InputIntensity::Low;
        }
    }

    // ── Very short with no markers → Low ────────────────────────────────
    if char_count < 30 {
        return InputIntensity::Low;
    }

    // ── Default: Medium ──────────────────────────────────────────────────
    InputIntensity::Medium
}

/// Return a tone-modifier string that augments `base_persona` for the given
/// `intensity`, or `None` for `Low` (no change needed at that band).
///
/// The base persona is preserved: the modifier is APPENDED so the
/// operator's static `tweaks.toml::persona_override` is never lost.
/// Example: base=`"blunt, no padding"`, intensity=High →
/// `"blunt, no padding — keep answer short, skip preamble"`.
pub fn modifier_for_intensity(intensity: InputIntensity, base: Option<&str>) -> Option<String> {
    let suffix = match intensity {
        InputIntensity::Low => return None,
        InputIntensity::Medium => "be direct, no filler",
        InputIntensity::High => "keep answer short, skip preamble",
        InputIntensity::Urgent => "one-sentence answer first, then elaboration only if needed",
    };

    Some(match base {
        Some(b) if !b.trim().is_empty() => format!("{} — {}", b.trim(), suffix),
        _ => suffix.to_string(),
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_intensity ────────────────────────────────────────────────

    #[test]
    fn greeting_is_low_intensity() {
        assert_eq!(classify_intensity("hi"), InputIntensity::Low);
        assert_eq!(classify_intensity("hallo"), InputIntensity::Low);
        assert_eq!(classify_intensity("hey"), InputIntensity::Low);
        assert_eq!(classify_intensity("danke"), InputIntensity::Low);
        assert_eq!(classify_intensity("ok"), InputIntensity::Low);
    }

    #[test]
    fn very_short_no_marker_is_low() {
        // 15-char prompt, no urgency, no greeting match → Low
        assert_eq!(classify_intensity("kurze Antwort?"), InputIntensity::Low);
    }

    #[test]
    fn normal_working_prompt_is_medium() {
        let prompt = "Erklär mir kurz wie async/await in Rust funktioniert.";
        // 54 chars, no urgency → Medium
        assert_eq!(classify_intensity(prompt), InputIntensity::Medium);
    }

    #[test]
    fn long_prompt_is_high() {
        let prompt = "x".repeat(250);
        assert_eq!(classify_intensity(&prompt), InputIntensity::High);
    }

    #[test]
    fn urgency_marker_en_escalates_to_high() {
        assert_eq!(classify_intensity("fix this asap"), InputIntensity::High);
        assert_eq!(classify_intensity("urgent: server is down"), InputIntensity::High);
        assert_eq!(
            classify_intensity("I need this immediately"),
            InputIntensity::High
        );
    }

    #[test]
    fn urgency_marker_de_escalates_to_high() {
        assert_eq!(classify_intensity("mach das sofort"), InputIntensity::High);
        assert_eq!(
            classify_intensity("das ist dringend bitte"),
            InputIntensity::High
        );
    }

    #[test]
    fn allcaps_bang_is_urgent() {
        assert_eq!(classify_intensity("FIX THIS NOW!"), InputIntensity::Urgent);
        assert_eq!(classify_intensity("DEPLOY NOW!"), InputIntensity::Urgent);
    }

    #[test]
    fn three_urgency_markers_short_is_urgent() {
        // "asap", "urgent", "critical" in one short sentence
        assert_eq!(
            classify_intensity("asap urgent critical fix needed"),
            InputIntensity::Urgent
        );
    }

    #[test]
    fn two_urgency_markers_is_still_high_not_urgent() {
        // only 2 markers + short → High (not Urgent)
        assert_eq!(
            classify_intensity("urgent and sofort fix this"),
            InputIntensity::High
        );
    }

    // ── InputIntensity ordering ────────────────────────────────────────────

    #[test]
    fn intensity_ordering_is_correct() {
        assert!(InputIntensity::Low < InputIntensity::Medium);
        assert!(InputIntensity::Medium < InputIntensity::High);
        assert!(InputIntensity::High < InputIntensity::Urgent);
        assert!(InputIntensity::Urgent >= InputIntensity::High);
        assert!(InputIntensity::Medium >= InputIntensity::Medium);
    }

    // ── modifier_for_intensity ─────────────────────────────────────────────

    #[test]
    fn modifier_for_low_is_none() {
        assert!(modifier_for_intensity(InputIntensity::Low, None).is_none());
        assert!(modifier_for_intensity(InputIntensity::Low, Some("blunt")).is_none());
    }

    #[test]
    fn modifier_for_medium_returns_some() {
        let m = modifier_for_intensity(InputIntensity::Medium, None).unwrap();
        assert!(m.contains("direct"));
    }

    #[test]
    fn modifier_for_high_contains_skip_preamble() {
        let m = modifier_for_intensity(InputIntensity::High, None).unwrap();
        assert!(m.contains("short") || m.contains("preamble"));
    }

    #[test]
    fn modifier_for_urgent_contains_one_sentence() {
        let m = modifier_for_intensity(InputIntensity::Urgent, None).unwrap();
        assert!(m.contains("one-sentence") || m.contains("first"));
    }

    #[test]
    fn base_persona_preserved_in_modifier() {
        let m =
            modifier_for_intensity(InputIntensity::High, Some("blunt, no padding")).unwrap();
        assert!(m.starts_with("blunt, no padding"));
        assert!(m.contains("—"));
    }

    #[test]
    fn base_persona_preserved_in_urgent() {
        let m = modifier_for_intensity(InputIntensity::Urgent, Some("blunt")).unwrap();
        assert!(m.contains("blunt")); // base persona preserved
        assert!(m.contains("one-sentence"));
    }

    #[test]
    fn modifier_for_medium_with_base() {
        let m =
            modifier_for_intensity(InputIntensity::Medium, Some("laconic")).unwrap();
        assert!(m.starts_with("laconic"));
        assert!(m.contains("direct"));
    }

    #[test]
    fn min_intensity_boundary_medium_threshold() {
        // Medium is >= Medium → should be applied
        assert!(InputIntensity::Medium >= InputIntensity::Medium);
        // Low is NOT >= Medium → should be skipped
        assert!(!(InputIntensity::Low >= InputIntensity::Medium));
    }

    // ── Integration sanity: classify → modifier round-trip ─────────────────

    #[test]
    fn mds_tone_high_intensity_augments_persona_override() {
        let intensity = classify_intensity("Fix this NOW!");
        assert!(intensity >= InputIntensity::High);
        let result = modifier_for_intensity(intensity, Some("blunt"));
        assert!(result.is_some());
    }

    #[test]
    fn mds_tone_urgent_fix_roundtrip() {
        let intensity = classify_intensity("DEPLOY NOW!");
        assert_eq!(intensity, InputIntensity::Urgent);
        let m = modifier_for_intensity(intensity, Some("direct mode")).unwrap();
        assert!(m.contains("direct mode"));
        assert!(m.contains("one-sentence"));
    }
}
