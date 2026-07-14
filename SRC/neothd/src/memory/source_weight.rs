//! JV-MEM-02 — Source-weight provenance calibration.
//!
//! Ported from Jarvis `fact-registry-source-weighting-generate.mjs:57-83`.
//! Provides a `weight_multiplier` in (0, 1] derived from three orthogonal
//! provenance axes (ref-count, source kind, backend) plus a
//! `verification_bonus`.  The multiplier is multiplied into
//! [`crate::memory::tiers::ranking_score`] inside `composite_score` so that
//! memories backed by more and better-verified sources rank higher.
//!
//! ## Design
//!
//! ### ref table — source count bonus
//! A fact or episode corroborated by *N* independent source references is
//! more reliable than one that appears only once. The bonus tops out at 1.0
//! to avoid raw count inflation:
//!
//! ```text
//! source_bonus = min(1.0, source_count × SOURCE_COUNT_STEP)
//! ```
//!
//! ### kind table — source-kind calibration
//! Different memory sources have different credibility priors.  The
//! `SourceKind` enum covers the sources that `event_type` can resolve to in
//! NEOTH's WAL:
//!
//! | Kind               | Multiplier | Notes                           |
//! |--------------------|------------|---------------------------------|
//! | `OperatorCli`      | 1.00       | Direct operator input — highest |
//! | `ChannelIngress`   | 0.85       | Channel/external messages       |
//! | `SelfReflection`   | 0.80       | Daemon-generated introspection  |
//! | `ImportedExternal` | 0.70       | Bulk imports (OKF, foreign)     |
//! | `Unknown`          | 0.60       | Fallback for unrecognised types |
//!
//! ### backend table — provider-backend calibration
//! The provider backend that produced the memory affects certainty.  A
//! local-only model may hallucinate more than a well-calibrated cloud model.
//!
//! | Backend   | Multiplier | Notes                    |
//! |-----------|------------|--------------------------|
//! | `Operator` | 1.00      | Human-authored, no model |
//! | `Cloud`    | 0.95      | Remote API inference     |
//! | `Local`    | 0.88      | Local on-device model    |
//! | `Unknown`  | 0.90      | No backend tag present   |
//!
//! ### Combining the axes
//!
//! ```text
//! weight_multiplier = kind_mult × backend_mult × (BASE + source_bonus + verification_bonus)
//! ```
//!
//! clamped to (0, 1].  The additive bonus path raises the multiplier toward 1
//! when the evidence base is wide and independently confirmed; the
//! multiplicative kind/backend path scales the whole result down when the
//! source is less trustworthy by construction.
//!
//! `BASE + source_bonus + verification_bonus` sums to at most 1.0 by
//! construction:
//!
//! * `BASE` (0.40): the minimum contribution of any source even with
//!   zero corroboration and no verification.
//! * `source_bonus` ≤ 0.40: `min(source_count × 0.10, 0.40)`.
//! * `verification_bonus` ≤ 0.20: flat 0.20 when the source is verified,
//!   else 0.  In NEOTH the `trust` field encodes operator verification:
//!   `trust ≥ 2` → verified.
//!
//! The additive sub-formula therefore lives in [0.40, 1.00], and after
//! kind × backend multiplication the final result stays in (0, 1].
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::memory::source_weight::{weight_multiplier, SourceKind, Backend};
//! use crate::wal::events::EVENT_TYPE_RAW_TEXT;
//!
//! let kind    = SourceKind::from_event_type(EVENT_TYPE_RAW_TEXT);
//! let backend = Backend::from_operator_id(hit.operator_id.as_deref());
//! let mult    = weight_multiplier(kind, backend, 1 /*source_count*/, true /*verified*/);
//! let score   = base_score * mult;
//! ```

/// Source-kind classification derived from the WAL `event_type` byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// Direct operator CLI input (`EVENT_TYPE_RAW_TEXT = 0x01`).
    OperatorCli,
    /// External channel message (`EVENT_TYPE_CHANNEL_INGRESS = 0x32`).
    ChannelIngress,
    /// Daemon self-reflection / hindsight / eval events (`0x60..=0x6F` council
    /// band + `0x80..=0x8F` reflection band — all daemon-generated).
    SelfReflection,
    /// Bulk-imported external content (OKF `0x70..=0x7F` / foreign import).
    ImportedExternal,
    /// Unrecognised or unclassified event type.
    Unknown,
}

impl SourceKind {
    /// Derive the source kind from the WAL `event_type` byte.
    ///
    /// Bands are taken from `wal/events.rs`'s band comment table.
    pub fn from_event_type(event_type: u8) -> Self {
        match event_type {
            // 0x01 RAW_TEXT — direct operator CLI entry
            0x01 => Self::OperatorCli,
            // 0x32 CHANNEL_INGRESS — external channel message
            0x32 => Self::ChannelIngress,
            // 0x60..=0x6F council band / 0x80..=0x8F would be reflection if it
            // existed — treat daemon-generated events as self-reflection
            0x60..=0x6F => Self::SelfReflection,
            // 0x70..=0x7F OKF / foreign-import band
            0x70..=0x7F => Self::ImportedExternal,
            // Everything else: memory ops (0x02..=0x0F), provider ops
            // (0x20..=0x2F), proactivity ops (0x40..=0x5F), etc. — no strong
            // provenance signal → Unknown.
            _ => Self::Unknown,
        }
    }

    /// Per-kind credibility multiplier ∈ (0, 1].
    pub fn multiplier(self) -> f64 {
        match self {
            Self::OperatorCli => 1.00,
            Self::ChannelIngress => 0.85,
            Self::SelfReflection => 0.80,
            Self::ImportedExternal => 0.70,
            Self::Unknown => 0.60,
        }
    }
}

/// Provider backend classification derived from the `operator_id` tag.
///
/// In NEOTH the `operator_id` field on an episode carries the provider name
/// (e.g. `"claude_cli"`, `"local_qwen"`, `"openai_api"`). When the field is
/// `None` the operator typed the content directly — no model involved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Human-authored, no inference model involved.
    Operator,
    /// Cloud / remote API inference.
    Cloud,
    /// Local on-device model inference.
    Local,
    /// No backend tag or unrecognised tag.
    Unknown,
}

impl Backend {
    /// Derive the backend from the `operator_id` field of an episode row.
    ///
    /// Convention (from `memory/indexer.rs` and `providers/`):
    /// * `None` / missing → `Operator` (the human typed this).
    /// * `"local_*"` prefix → `Local`.
    /// * Any other non-empty string → `Cloud`.
    pub fn from_operator_id(operator_id: Option<&str>) -> Self {
        match operator_id {
            None | Some("") => Self::Operator,
            Some(id) if id.starts_with("local_") || id.starts_with("local-") => Self::Local,
            Some(_) => Self::Cloud,
        }
    }

    /// Per-backend credibility multiplier ∈ (0, 1].
    pub fn multiplier(self) -> f64 {
        match self {
            Self::Operator => 1.00,
            Self::Cloud => 0.95,
            Self::Local => 0.88,
            Self::Unknown => 0.90,
        }
    }
}

// ── Bonus constants ──────────────────────────────────────────────────────────

/// Minimum contribution of any source (no corroboration, no verification).
const BASE: f64 = 0.40;
/// Bonus earned per additional corroborating source reference, up to `SOURCE_BONUS_CAP`.
const SOURCE_COUNT_STEP: f64 = 0.10;
/// Maximum source-count bonus (4 or more independent references caps out).
const SOURCE_BONUS_CAP: f64 = 0.40;
/// Bonus earned when the source has been explicitly verified (operator trust ≥ 2).
const VERIFICATION_BONUS: f64 = 0.20;

// ── Public API ───────────────────────────────────────────────────────────────

/// Compute the combined source-weight multiplier ∈ (0, 1].
///
/// # Parameters
/// - `kind`: the source kind classification.
/// - `backend`: the provider backend classification.
/// - `source_count`: number of independent references corroborating this fact
///   (typically 1 for a single episode; higher for merged/verified facts).
/// - `verified`: `true` when the source has been explicitly verified by the
///   operator (i.e. `trust ≥ 2` in NEOTH's trust tagging system).
///
/// # Returns
/// A multiplier in (0, 1] that the caller should multiply into the raw
/// retrieval score. Higher = more trustworthy provenance.
pub fn weight_multiplier(
    kind: SourceKind,
    backend: Backend,
    source_count: u32,
    verified: bool,
) -> f64 {
    let source_bonus = (source_count as f64 * SOURCE_COUNT_STEP).min(SOURCE_BONUS_CAP);
    let verification_bonus = if verified { VERIFICATION_BONUS } else { 0.0 };
    let additive = (BASE + source_bonus + verification_bonus).min(1.0);
    let mult = kind.multiplier() * backend.multiplier() * additive;
    // Clamp to (0, 1]: the formula is monotone in additive and both multipliers
    // are positive, so the lower bound of BASE > 0 guarantees mult > 0 always.
    mult.clamp(f64::MIN_POSITIVE, 1.0)
}

/// Convenience helper: derive both axes from the fields present on an
/// `EpisodeHit`-like row and compute the weight multiplier.
///
/// - `event_type`: the WAL event type byte (from `idx_episode.event_type`).
/// - `operator_id`: the provider tag (from `idx_episode.operator_id`).
/// - `trust`: the NEOTH trust byte — `≥ 2` counts as verified.
/// - `source_count`: number of independent corroborating references.
pub fn weight_multiplier_for_hit(
    event_type: u8,
    operator_id: Option<&str>,
    trust: u8,
    source_count: u32,
) -> f64 {
    let kind = SourceKind::from_event_type(event_type);
    let backend = Backend::from_operator_id(operator_id);
    let verified = trust >= 2;
    weight_multiplier(kind, backend, source_count, verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SourceKind classification ──────────────────────────────────────

    #[test]
    fn source_kind_from_event_type_classifies_correctly() {
        assert_eq!(SourceKind::from_event_type(0x01), SourceKind::OperatorCli);
        assert_eq!(
            SourceKind::from_event_type(0x32),
            SourceKind::ChannelIngress
        );
        assert_eq!(
            SourceKind::from_event_type(0x60),
            SourceKind::SelfReflection
        );
        assert_eq!(
            SourceKind::from_event_type(0x6F),
            SourceKind::SelfReflection
        );
        assert_eq!(
            SourceKind::from_event_type(0x70),
            SourceKind::ImportedExternal
        );
        assert_eq!(
            SourceKind::from_event_type(0x7F),
            SourceKind::ImportedExternal
        );
        // Memory ops, provider ops, proactivity — all Unknown.
        assert_eq!(SourceKind::from_event_type(0x02), SourceKind::Unknown);
        assert_eq!(SourceKind::from_event_type(0x21), SourceKind::Unknown);
        assert_eq!(SourceKind::from_event_type(0x42), SourceKind::Unknown);
        assert_eq!(SourceKind::from_event_type(0xFF), SourceKind::Unknown);
    }

    #[test]
    fn source_kind_multipliers_are_ordered_and_in_range() {
        // OperatorCli is most trusted, Unknown is least.
        let vals = [
            SourceKind::OperatorCli.multiplier(),
            SourceKind::ChannelIngress.multiplier(),
            SourceKind::SelfReflection.multiplier(),
            SourceKind::ImportedExternal.multiplier(),
            SourceKind::Unknown.multiplier(),
        ];
        // Strictly decreasing
        for w in vals.windows(2) {
            assert!(w[0] > w[1], "expected strictly decreasing: {w:?}");
        }
        // All in (0, 1]
        for v in vals {
            assert!(v > 0.0 && v <= 1.0, "out of range: {v}");
        }
    }

    // ── Backend classification ─────────────────────────────────────────

    #[test]
    fn backend_from_operator_id_classifies_correctly() {
        assert_eq!(Backend::from_operator_id(None), Backend::Operator);
        assert_eq!(Backend::from_operator_id(Some("")), Backend::Operator);
        assert_eq!(
            Backend::from_operator_id(Some("local_qwen")),
            Backend::Local
        );
        assert_eq!(
            Backend::from_operator_id(Some("local-ouro")),
            Backend::Local
        );
        assert_eq!(
            Backend::from_operator_id(Some("claude_cli")),
            Backend::Cloud
        );
        assert_eq!(
            Backend::from_operator_id(Some("openai_api")),
            Backend::Cloud
        );
        assert_eq!(Backend::from_operator_id(Some("anthropic")), Backend::Cloud);
    }

    #[test]
    fn backend_multipliers_are_in_range() {
        for backend in [
            Backend::Operator,
            Backend::Cloud,
            Backend::Local,
            Backend::Unknown,
        ] {
            let m = backend.multiplier();
            assert!(
                m > 0.0 && m <= 1.0,
                "backend {backend:?} mult {m} out of (0,1]"
            );
        }
        // Operator is max trust.
        assert_eq!(Backend::Operator.multiplier(), 1.0);
    }

    // ── weight_multiplier core invariants ─────────────────────────────

    #[test]
    fn weight_multiplier_higher_source_count_raises_score() {
        // More corroborating sources → higher weight. All else equal.
        let low = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 1, false);
        let mid = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 2, false);
        let high = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 4, false);
        assert!(
            high >= mid && mid >= low,
            "source count must raise weight: low={low} mid={mid} high={high}"
        );
    }

    #[test]
    fn weight_multiplier_source_count_caps_at_4() {
        // 4+ sources saturate the source_bonus — going beyond 4 adds nothing.
        let at4 = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 4, false);
        let at8 = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 8, false);
        let at100 = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 100, false);
        assert!((at4 - at8).abs() < 1e-12, "cap at 4: at4={at4} at8={at8}");
        assert!(
            (at4 - at100).abs() < 1e-12,
            "cap at 4: at4={at4} at100={at100}"
        );
    }

    #[test]
    fn weight_multiplier_verified_raises_score() {
        // Verification bonus raises the score over unverified.
        let unverified = weight_multiplier(SourceKind::ChannelIngress, Backend::Cloud, 1, false);
        let verified = weight_multiplier(SourceKind::ChannelIngress, Backend::Cloud, 1, true);
        assert!(
            verified > unverified,
            "verified must outrank unverified: {verified} vs {unverified}"
        );
    }

    #[test]
    fn weight_multiplier_unknown_source_gets_baseline() {
        // Unknown source with a single reference and no verification:
        // kind=0.60, backend=0.90 (Unknown), additive=BASE=0.40
        let mult = weight_multiplier(SourceKind::Unknown, Backend::Unknown, 1, false);
        // source_count=1 → source_bonus=0.10, additive=0.40+0.10=0.50
        let expected = 0.60 * 0.90 * 0.50;
        assert!(
            (mult - expected).abs() < 1e-9,
            "unknown source baseline wrong: got {mult} expected {expected}"
        );
        assert!(mult > 0.0 && mult <= 1.0, "out of (0,1]: {mult}");
    }

    #[test]
    fn weight_multiplier_always_in_unit_interval() {
        // Full grid sweep: no combination should produce a value outside (0, 1].
        let kinds = [
            SourceKind::OperatorCli,
            SourceKind::ChannelIngress,
            SourceKind::SelfReflection,
            SourceKind::ImportedExternal,
            SourceKind::Unknown,
        ];
        let backends = [
            Backend::Operator,
            Backend::Cloud,
            Backend::Local,
            Backend::Unknown,
        ];
        for kind in kinds {
            for backend in backends {
                for count in [0u32, 1, 2, 4, 10, 100] {
                    for verified in [false, true] {
                        let m = weight_multiplier(kind, backend, count, verified);
                        assert!(
                            m > 0.0 && m <= 1.0,
                            "out of (0,1]: kind={kind:?} backend={backend:?} count={count} verified={verified} m={m}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn weight_multiplier_best_case_is_operator_cli_many_sources_verified() {
        // OperatorCli + Operator backend + many sources + verified should be 1.0.
        // kind=1.0, backend=1.0, additive=(0.40+0.40+0.20)=1.0 → 1.0.
        let best = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 4, true);
        assert!(
            (best - 1.0).abs() < 1e-12,
            "best case must be 1.0: got {best}"
        );
    }

    // ── weight_multiplier_for_hit convenience helper ───────────────────

    #[test]
    fn weight_multiplier_for_hit_trust2_is_verified() {
        // weight_multiplier_for_hit(event_type, operator_id, trust, source_count)
        // trust=1 (medium, unverified) at source_count=1.
        let unverified = weight_multiplier_for_hit(0x01, None, 1, 1);
        // trust=2 (operator-explicit, verified) at source_count=1 → verification bonus.
        let verified = weight_multiplier_for_hit(0x01, None, 2, 1);
        assert!(
            verified > unverified,
            "trust=2 (verified) must outrank trust=1: verified={verified} unverified={unverified}"
        );
        // Cross-check: trust=2 + source_count=1 must match the manual call with verified=true.
        let manual = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 1, true);
        assert!(
            (verified - manual).abs() < 1e-12,
            "helper must match manual call: {verified} vs {manual}"
        );
        // And trust=1 must match unverified manual call.
        let manual_uv = weight_multiplier(SourceKind::OperatorCli, Backend::Operator, 1, false);
        assert!(
            (unverified - manual_uv).abs() < 1e-12,
            "helper (trust=1) must match manual unverified: {unverified} vs {manual_uv}"
        );
    }

    #[test]
    fn weight_multiplier_for_hit_channel_ingress_lower_than_raw_text() {
        // Channel ingress (0x32) should rank lower than operator CLI (0x01)
        // given the same trust/source_count.
        let cli = weight_multiplier_for_hit(0x01, None, 1, 1);
        let chan = weight_multiplier_for_hit(0x32, Some("claude_cli"), 1, 1);
        assert!(
            cli > chan,
            "operator CLI must outrank channel ingress: cli={cli} chan={chan}"
        );
    }

    #[test]
    fn weight_multiplier_for_hit_local_model_lower_than_no_model() {
        // Memory from a local model (operator_id="local_qwen") ranks lower than
        // one typed directly by the operator (operator_id=None).
        let op = weight_multiplier_for_hit(0x01, None, 1, 2);
        let local = weight_multiplier_for_hit(0x01, Some("local_qwen"), 1, 2);
        assert!(
            op > local,
            "operator backend must outrank local model: op={op} local={local}"
        );
    }
}
