//! Stage 5 — `profile_claim_guard`. The unified gate from
//! `PLAN/SPEC_profile_claim_guard.md` (SPEC-07). Five checks against
//! five distinct risks (H1 / H2 / H5 / M1 / M2) — ALL SHIPPED.
//!
//! `profile::runner` Stage 5 calls [`ProfileClaimGuard::check_all`] with
//! the full set:
//!   - **H1** require first-person window — rejects a delta whose
//!     attributed window isn't first-person.
//!   - **H2** redaction registry — consults `idx_profile_redactions`
//!     (migration v7→v8; `profile::redaction` add/revoke/lookup; the
//!     pipeline loads it via `runner::load_active_redactions`). Any
//!     redacted field rejects the whole delta.
//!   - **H5** daily LLM-call cap — in-memory [`DailyLlmCounter`].
//!   - **M1** timestamp normalization —
//!     [`crate::profile::timestamp_check`] `TimestampPolicy::from_window`
//!     clamps claim timestamps to the attributed-window anchor range
//!     (+ padding).
//!   - **M2** typed extension registry —
//!     [`crate::profile::extension_registry::TypedExtensionRegistry`]
//!     gates each claim's top-level category.
//!
//! Rejections emit the `0xB4 PROFILE_DELTA_BLOCKED` audit frame so the
//! operator can `neoth wal show --type 0xB4` to see why a delta was
//! refused. (Earlier revisions of this doc described H2/M1/M2 as
//! "deferred" — that was the Phase-1 state; the maximal `check_all`
//! wiring landed via the H2 schema migration + ADV-13 timestamp work.)

use std::collections::HashMap;
use std::sync::Mutex;

use unicode_normalization::UnicodeNormalization as _;

use crate::profile::delta::ProfileDelta;
use crate::profile::types::AttributedWindow;

fn sensitive_scan_char(character: char) -> Option<char> {
    let codepoint = character as u32;
    if character.is_control()
        || matches!(
            codepoint,
            0x00AD
                | 0x034F
                | 0x061C
                | 0x115F..=0x1160
                | 0x17B4..=0x17B5
                | 0x180B..=0x180F
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x206F
                | 0x3164
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFA0
                | 0xE0100..=0xE01EF
        )
    {
        return None;
    }

    // Small dependency-free confusable fold for the Greek/Cyrillic glyphs
    // commonly used to split diagnostic markers. NFKC handles full-width and
    // compatibility forms; this closes the remaining visual ASCII spoofs at
    // the final durable-claim boundary.
    Some(match character {
        'а' | 'Α' | 'α' => 'a',
        'В' | 'в' | 'Β' | 'β' => 'b',
        'с' | 'С' | 'ϲ' | 'Ϲ' => 'c',
        'е' | 'Е' | 'Ε' | 'ε' => 'e',
        'Н' | 'н' | 'Η' | 'η' => 'h',
        'і' | 'І' | 'Ι' | 'ι' => 'i',
        'Ј' | 'ј' => 'j',
        'Κ' | 'κ' | 'К' | 'к' => 'k',
        'Μ' | 'μ' | 'М' | 'м' => 'm',
        'Ν' | 'п' | 'П' => 'n',
        'ν' => 'v',
        'о' | 'О' | 'Ο' | 'ο' => 'o',
        'р' | 'Р' | 'Ρ' | 'ρ' => 'p',
        'Τ' | 'τ' | 'Т' | 'т' => 't',
        'у' | 'У' | 'Υ' | 'υ' => 'y',
        'х' | 'Х' | 'Χ' | 'χ' => 'x',
        other => other,
    })
}

fn normalize_for_sensitive_scan(value: &str) -> String {
    value
        .nfkc()
        .filter_map(sensitive_scan_char)
        .collect::<String>()
        .to_lowercase()
}

/// Match an ASCII marker while treating any still-unmapped non-ASCII
/// alphanumeric glyph as one conservative substitution. This avoids making a
/// brittle claim that the small fold above implements the full UTS #39
/// confusables table: at this final persistence boundary, an ambiguous glyph
/// inside an otherwise matching diagnostic token is sufficient to reject it.
fn contains_marker_with_non_ascii_substitutions(compact: &str, marker: &str) -> bool {
    if !marker.is_ascii() {
        return false;
    }
    let candidate = compact.chars().collect::<Vec<_>>();
    let expected = marker.chars().collect::<Vec<_>>();
    if expected.is_empty() || candidate.len() < expected.len() {
        return false;
    }
    candidate.windows(expected.len()).any(|window| {
        let mut exact_ascii = 0_usize;
        let matches = window.iter().zip(&expected).all(|(actual, expected)| {
            if actual == expected {
                exact_ascii += 1;
                true
            } else {
                actual.is_alphanumeric() && !actual.is_ascii()
            }
        });
        matches && exact_ascii >= expected.len().min(2)
    })
}

/// Sensitive inferences that an LLM/passive extractor must never turn into a
/// durable profile claim. Explicit operator declarations use a separate,
/// typed path; this gate applies only to inferred [`RawClaim`](crate::profile::delta::RawClaim)s.
///
/// `health` is denied as a category. The marker check is defence against a
/// model misclassifying a diagnosis under another category such as
/// `identity.neurotype`.
pub(crate) fn is_prohibited_sensitive_inference(claim: &crate::profile::delta::RawClaim) -> bool {
    let field = normalize_for_sensitive_scan(claim.field.trim());
    if field == "health" || field.starts_with("health.") {
        return true;
    }

    let mut candidate = field;
    candidate.push(' ');
    candidate.push_str(&normalize_for_sensitive_scan(&claim.value_json.to_string()));
    candidate.push(' ');
    candidate.push_str(&normalize_for_sensitive_scan(&claim.reasoning));

    const DIAGNOSTIC_MARKERS: &[&str] = &[
        "autism",
        "autistic",
        "autismus",
        "autistisch",
        "adhd",
        "adhs",
        "neurodiverg",
        "neurotyp",
        "psychiatr",
        "mental health",
        "mental_health",
        "mental-health",
        "diagnos",
        "disorder",
        "störung",
        "bipolar",
        "schizophren",
        "psychosis",
        "psychotic",
        "depressi",
        "ptsd",
        "ocd",
        "dsm-",
        "dsm ",
        "icd-",
        "icd ",
    ];
    let compact = candidate
        .chars()
        .filter(|character| character.is_alphanumeric())
        .collect::<String>();
    DIAGNOSTIC_MARKERS.iter().any(|marker| {
        let compact_marker = marker
            .chars()
            .filter(|character| character.is_alphanumeric())
            .collect::<String>();
        candidate.contains(marker)
            || compact.contains(&compact_marker)
            || contains_marker_with_non_ascii_substitutions(&compact, &compact_marker)
    })
}

/// Default cap matching the spec's `max_llm_calls_per_day = 500`.
pub const DEFAULT_MAX_LLM_CALLS_PER_DAY: u32 = 500;

/// Default min-confidence floor matching the spec's `0.30`.
pub const DEFAULT_MIN_CONFIDENCE_PASSTHROUGH: f32 = 0.30;

/// One reason a guard run rejected a delta or a claim. Variants align
/// with `SPEC_profile_claim_guard.md §2` so a future migration can map
/// each one to a `0x38 PROFILE_DELTA_BLOCKED` WAL audit row.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum GuardReason {
    #[error("daily LLM-call cap exceeded: {calls}/{cap}")]
    LlmCapExceeded { calls: u32, cap: u32 },
    #[error("attributed window has no UserSpeech segments")]
    NoFirstPersonWindow,
    #[error("confidence {confidence} below passthrough floor {floor}")]
    BelowConfidenceFloor { confidence: f32, floor: f32 },
    #[error("field `{field}` is redacted (never_recreate=true)")]
    FieldRedacted { field: String },
    #[error(
        "unknown profile category in field `{field}` — register it via profile_extensions.toml"
    )]
    UnknownCategoryNotRegistered { field: String },
    #[error("field `{field}` carries a date outside the conversation-window anchor range")]
    TimestampOutsideWindow { field: String },
    #[error("inferred sensitive/diagnostic profile claim is prohibited: `{field}`")]
    SensitiveInferenceProhibited { field: String },
}

/// Knobs the operator sets via `~/.neoth/profile_claim_guard.toml` (the
/// loader for that file lands with the H2 schema). Defaults match the
/// spec.
#[derive(Clone, Debug)]
pub struct GuardConfig {
    pub max_llm_calls_per_day: u32,
    pub min_confidence_passthrough: f32,
    /// When true, an attributed window with zero `UserSpeech` segments
    /// causes the entire delta to be rejected (H1 hard fail). When
    /// false, low-evidence claims are silently dropped instead — the
    /// spec recommends `true`.
    pub require_first_person_window: bool,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            max_llm_calls_per_day: DEFAULT_MAX_LLM_CALLS_PER_DAY,
            min_confidence_passthrough: DEFAULT_MIN_CONFIDENCE_PASSTHROUGH,
            require_first_person_window: true,
        }
    }
}

/// Outcome of one guard pass. `Accepted` carries the (possibly filtered)
/// delta; `Rejected` short-circuits with the spec-aligned reason +
/// payload hash so the audit trail can de-duplicate.
#[derive(Clone, Debug, PartialEq)]
pub enum GuardOutcome {
    Accepted(ProfileDelta),
    Rejected {
        reason: GuardReason,
        blocked_delta_hash: [u8; 32],
    },
}

/// Hash a delta deterministically for `blocked_delta_hash`. SHA-256 of
/// the canonical-JSON serialisation. Same value for the same content
/// regardless of field-order quirks (serde_json defaults to map-ordered
/// output for `ProfileDelta` because every field is statically named).
fn delta_hash(delta: &ProfileDelta) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(delta)
        .expect("ProfileDelta contains only infallibly serializable fields");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// In-memory counter for the H5 daily-LLM-call cap. Threadsafe so the
/// daemon can share a single instance between the chat dispatcher and
/// any future profile-pipeline driver.
#[derive(Debug, Default)]
pub struct DailyLlmCounter {
    inner: Mutex<HashMap<String, u32>>,
    /// Unix seconds of the next midnight boundary. When `now_unix`
    /// crosses this, the counter resets.
    reset_at_unix: Mutex<u64>,
}

const SECONDS_PER_DAY: u64 = 24 * 3600;

impl DailyLlmCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment-and-check. Returns `Ok(new_count)` if under the cap;
    /// returns `Err(LlmCapExceeded)` when the post-increment count would
    /// exceed `cap`. Lazy daily reset on every call — no background
    /// timer needed.
    pub fn record_and_check(
        &self,
        bucket: &str,
        cap: u32,
        now_unix: u64,
    ) -> Result<u32, GuardReason> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut reset = self.reset_at_unix.lock().unwrap_or_else(|p| p.into_inner());
        if now_unix >= *reset {
            inner.clear();
            *reset = ((now_unix / SECONDS_PER_DAY) + 1) * SECONDS_PER_DAY;
        }
        let entry = inner.entry(bucket.to_string()).or_insert(0);
        if *entry >= cap {
            return Err(GuardReason::LlmCapExceeded { calls: *entry, cap });
        }
        *entry += 1;
        Ok(*entry)
    }

    /// Read-only view of the current count. Useful for `neoth profile
    /// status` once that CLI lands.
    pub fn current(&self, bucket: &str) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(bucket)
            .copied()
            .unwrap_or(0)
    }
}

/// The guard. Phase-2 will add the redaction registry + extension
/// registry + behavioral-style embedder fields; for v0.1 the two
/// implemented checks need only the in-memory counter.
pub struct ProfileClaimGuard {
    counter: DailyLlmCounter,
    config: GuardConfig,
}

impl Default for ProfileClaimGuard {
    fn default() -> Self {
        Self::new(GuardConfig::default())
    }
}

impl ProfileClaimGuard {
    pub fn new(config: GuardConfig) -> Self {
        Self {
            counter: DailyLlmCounter::new(),
            config,
        }
    }

    /// Spec-aligned API: check a delta against the attributed window
    /// alongside the daily counter. Returns either an Accepted filtered
    /// delta or a Rejected outcome with a reason plus deterministic
    /// delta hash. `now_unix` is taken as a parameter so tests pin the
    /// daily reset boundary without touching the wall clock.
    pub fn check(
        &self,
        delta: ProfileDelta,
        window: &AttributedWindow,
        now_unix: u64,
    ) -> GuardOutcome {
        self.check_with_redactions(delta, window, &[], now_unix)
    }

    /// H2-aware variant: also consults the redaction registry. Exact-field
    /// redactions and `_tombstone.<topic>` value sentinels reject the whole
    /// delta with `FieldRedacted`. The caller passes the registry as
    /// `&[String]` so this method stays SQL-free and unit-testable. Does
    /// NOT enforce M2 (extension-registry) — call `check_full` for
    /// the full H1+H2+H5+M2 chain.
    pub fn check_with_redactions(
        &self,
        delta: ProfileDelta,
        window: &AttributedWindow,
        redacted_fields: &[String],
        now_unix: u64,
    ) -> GuardOutcome {
        self.check_inner(delta, window, redacted_fields, None, None, now_unix)
    }

    /// Full H1+H2+H5+M2 check. Adds the extension-registry test on top
    /// of H1/H2/H5 — every claim's top-level category must be in the
    /// spec base taxonomy OR registered in `~/.neoth/profile_extensions.toml`.
    /// Pass `&TypedExtensionRegistry::default()` for base-only (no
    /// operator extensions registered).
    pub fn check_full(
        &self,
        delta: ProfileDelta,
        window: &AttributedWindow,
        redacted_fields: &[String],
        extensions: &crate::profile::extension_registry::TypedExtensionRegistry,
        now_unix: u64,
    ) -> GuardOutcome {
        self.check_inner(
            delta,
            window,
            redacted_fields,
            Some(extensions),
            None,
            now_unix,
        )
    }

    /// Maximal H1+H2+H5+M1+M2 check. Adds the M1 timestamp gate when
    /// `timestamp_policy` is provided. Caller derives the policy from
    /// the conversation window; see `profile::timestamp_check::TimestampPolicy::from_window`.
    pub fn check_all(
        &self,
        delta: ProfileDelta,
        window: &AttributedWindow,
        redacted_fields: &[String],
        extensions: &crate::profile::extension_registry::TypedExtensionRegistry,
        timestamp_policy: &crate::profile::timestamp_check::TimestampPolicy,
        now_unix: u64,
    ) -> GuardOutcome {
        self.check_inner(
            delta,
            window,
            redacted_fields,
            Some(extensions),
            Some(timestamp_policy),
            now_unix,
        )
    }

    /// Shared inner that runs H1/H2/H5 unconditionally, M2 when
    /// `extensions` is `Some`, and M1 when `timestamp_policy` is
    /// `Some`. Keeps the public APIs aligned without duplicating
    /// the body.
    fn check_inner(
        &self,
        delta: ProfileDelta,
        window: &AttributedWindow,
        redacted_fields: &[String],
        extensions: Option<&crate::profile::extension_registry::TypedExtensionRegistry>,
        timestamp_policy: Option<&crate::profile::timestamp_check::TimestampPolicy>,
        now_unix: u64,
    ) -> GuardOutcome {
        // 1. H5 — daily LLM-call cap.
        if let Err(reason) =
            self.counter
                .record_and_check("llm_calls", self.config.max_llm_calls_per_day, now_unix)
        {
            let hash = delta_hash(&delta);
            return GuardOutcome::Rejected {
                reason,
                blocked_delta_hash: hash,
            };
        }

        // 2. H1 — require first-person window.
        if self.config.require_first_person_window && !window.has_user_speech_segments() {
            let hash = delta_hash(&delta);
            return GuardOutcome::Rejected {
                reason: GuardReason::NoFirstPersonWindow,
                blocked_delta_hash: hash,
            };
        }

        // P0 privacy boundary — passive/LLM learning may adapt communication
        // needs, but it must not persist health or diagnostic/neurotype claims.
        // This check is independent of autonomy and therefore cannot be
        // bypassed by Full/Sovereign. Stage 4 normally drops these per-claim;
        // this whole-delta rejection protects direct guard callers that skip
        // validation.
        if let Some(claim) = delta
            .claims
            .iter()
            .find(|claim| is_prohibited_sensitive_inference(claim))
        {
            let field = claim.field.clone();
            let hash = delta_hash(&delta);
            return GuardOutcome::Rejected {
                reason: GuardReason::SensitiveInferenceProhibited { field },
                blocked_delta_hash: hash,
            };
        }

        // 3. H2 — redaction registry. Exact-field redactions and
        //    `_tombstone.<topic>` anti-resurrection sentinels both reject the
        //    whole delta. The topic matcher inspects structured values too, so
        //    forgetting "Berlin" cannot reappear under a different field.
        for claim in &delta.claims {
            if redacted_fields.iter().any(|field| {
                crate::memory::forget::redaction_blocks_claim(
                    field,
                    &claim.field,
                    &claim.value_json,
                )
            }) {
                let hash = delta_hash(&delta);
                return GuardOutcome::Rejected {
                    reason: GuardReason::FieldRedacted {
                        field: claim.field.clone(),
                    },
                    blocked_delta_hash: hash,
                };
            }
        }

        // 4. M2 — typed extension registry. Reject claims whose top-
        //    level category is neither in the base taxonomy nor
        //    registered in profile_extensions.toml. Same hard-reject
        //    semantics as H2 — pollution by inventing categories is
        //    exactly the failure mode this gate exists to prevent.
        //    Only runs when the caller provided a registry — the
        //    `check` + `check_with_redactions` APIs skip M2 so they
        //    stay self-contained (no SQL / no TOML I/O).
        if let Some(registry) = extensions {
            for claim in &delta.claims {
                let category =
                    crate::profile::extension_registry::TypedExtensionRegistry::category_of(
                        &claim.field,
                    );
                if !registry.is_known(category) {
                    let hash = delta_hash(&delta);
                    return GuardOutcome::Rejected {
                        reason: GuardReason::UnknownCategoryNotRegistered {
                            field: claim.field.clone(),
                        },
                        blocked_delta_hash: hash,
                    };
                }
            }
        }

        // 4b. M1 — timestamp normalisation. Reject claims whose
        //     value_json embeds an ISO-8601 date outside the
        //     conversation-window anchor range plus padding. Catches
        //     LLM "Operator visited Berlin in 2008" hallucinations when
        //     the entire window is from yesterday. Runs only when the
        //     caller provided a policy.
        if let Some(policy) = timestamp_policy
            && let Some(bad_field) =
                crate::profile::timestamp_check::first_out_of_window_field(&delta, policy)
        {
            let bad_field_owned = bad_field.to_string();
            let hash = delta_hash(&delta);
            return GuardOutcome::Rejected {
                reason: GuardReason::TimestampOutsideWindow {
                    field: bad_field_owned,
                },
                blocked_delta_hash: hash,
            };
        }

        // 5. Confidence floor — silently drops low-confidence claims
        //    (spec §2 step 3e: "silently drop low-confidence — log to
        //    audit only"). Whole-delta acceptance even when every claim
        //    is dropped: the spec says zero claims is a valid pass
        //    (primary_kpi_threshold == 0).
        let filtered_claims: Vec<_> = delta
            .claims
            .into_iter()
            .filter(|c| c.confidence >= self.config.min_confidence_passthrough)
            .collect();

        let guarded = ProfileDelta {
            claims: filtered_claims,
            guard_version: env!("CARGO_PKG_VERSION").to_string(),
            ..delta
        };

        GuardOutcome::Accepted(guarded)
    }

    pub fn config(&self) -> &GuardConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::delta::RawClaim;
    use crate::profile::types::{
        AttributedSegment, Attribution, ConversationSegment, SegmentOrigin,
    };

    fn segment(event_id: i64, attribution: Attribution) -> AttributedSegment {
        AttributedSegment {
            segment: ConversationSegment {
                event_id,
                ts_ns: 0,
                origin: SegmentOrigin::OperatorInbound,
                text: "x".into(),
            },
            attribution,
            confidence: 0.9,
            matched_signals: vec![],
        }
    }

    fn window_with_user_speech() -> AttributedWindow {
        AttributedWindow {
            trigger_event_id: 1,
            segments: vec![segment(10, Attribution::UserSpeech)],
        }
    }

    fn window_quoted_only() -> AttributedWindow {
        AttributedWindow {
            trigger_event_id: 1,
            segments: vec![segment(11, Attribution::QuotedExternal)],
        }
    }

    fn claim(field: &str, confidence: f32) -> RawClaim {
        RawClaim {
            field: field.into(),
            value_json: serde_json::json!("v"),
            confidence,
            reasoning: "".into(),
            evidence_event_ids: vec![],
        }
    }

    fn delta(claims: Vec<RawClaim>) -> ProfileDelta {
        ProfileDelta {
            extraction_id: "ext-1".into(),
            conversation_hash: "h".into(),
            claims,
            ..Default::default()
        }
    }

    const T0: u64 = 1_700_000_000;

    #[test]
    fn first_person_window_with_high_confidence_accepts() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("identity.x", 0.8)]);
        let outcome = g.check(d, &window_with_user_speech(), T0);
        match outcome {
            GuardOutcome::Accepted(d) => {
                assert_eq!(d.claims.len(), 1);
                assert!(!d.guard_version.is_empty());
            }
            _ => panic!("expected Accepted"),
        }
    }

    #[test]
    fn quoted_only_window_rejects_when_require_first_person_set() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("identity.x", 0.8)]);
        let outcome = g.check(d, &window_quoted_only(), T0);
        match outcome {
            GuardOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, GuardReason::NoFirstPersonWindow);
            }
            _ => panic!("expected Rejected"),
        }
    }

    #[test]
    fn quoted_only_window_accepts_when_require_first_person_disabled() {
        let g = ProfileClaimGuard::new(GuardConfig {
            require_first_person_window: false,
            ..GuardConfig::default()
        });
        let d = delta(vec![claim("identity.x", 0.8)]);
        let outcome = g.check(d, &window_quoted_only(), T0);
        assert!(matches!(outcome, GuardOutcome::Accepted(_)));
    }

    #[test]
    fn low_confidence_claim_silently_dropped_but_delta_accepted() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![
            claim("a.b", 0.50),
            claim("a.c", 0.20), // below 0.30 floor
        ]);
        let outcome = g.check(d, &window_with_user_speech(), T0);
        match outcome {
            GuardOutcome::Accepted(d) => {
                assert_eq!(d.claims.len(), 1);
                assert_eq!(d.claims[0].field, "a.b");
            }
            _ => panic!("expected Accepted"),
        }
    }

    #[test]
    fn empty_claim_set_is_valid_pass() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![]);
        let outcome = g.check(d, &window_with_user_speech(), T0);
        match outcome {
            GuardOutcome::Accepted(d) => assert!(d.claims.is_empty()),
            _ => panic!("zero claims is a valid pass per spec"),
        }
    }

    #[test]
    fn health_claim_is_rejected_before_any_autonomy_or_approval_gate() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("health.sleep", 0.9)]);
        let outcome = g.check(d, &window_with_user_speech(), T0);
        assert!(matches!(
            outcome,
            GuardOutcome::Rejected {
                reason: GuardReason::SensitiveInferenceProhibited { ref field },
                ..
            } if field == "health.sleep"
        ));
    }

    #[test]
    fn diagnostic_claim_hidden_under_identity_is_rejected() {
        let g = ProfileClaimGuard::default();
        let mut inferred = claim("identity.neurotype", 0.9);
        inferred.value_json = serde_json::json!("ADHD");
        let outcome = g.check(delta(vec![inferred]), &window_with_user_speech(), T0);
        assert!(matches!(
            outcome,
            GuardOutcome::Rejected {
                reason: GuardReason::SensitiveInferenceProhibited { .. },
                ..
            }
        ));
    }

    #[test]
    fn diagnostic_claim_unicode_and_separator_obfuscation_is_rejected() {
        let g = ProfileClaimGuard::default();
        for value in [
            "a\u{200b}utism",
            "ＡＤＨＤ",
            "аutism",
            "a\u{0501}hd",
            "a u t i s m",
            "neuro\u{2060}divergent",
        ] {
            let mut inferred = claim("identity.communication_style", 0.9);
            inferred.value_json = serde_json::json!(value);
            let outcome = g.check(delta(vec![inferred]), &window_with_user_speech(), T0);
            assert!(
                matches!(
                    outcome,
                    GuardOutcome::Rejected {
                        reason: GuardReason::SensitiveInferenceProhibited { .. },
                        ..
                    }
                ),
                "obfuscated diagnostic marker passed: {value:?}"
            );
        }
    }

    #[test]
    fn functional_communication_preference_remains_allowed() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim(
            "operator_preferences.communication_structure",
            0.9,
        )]);
        let outcome = g.check(d, &window_with_user_speech(), T0);
        assert!(matches!(outcome, GuardOutcome::Accepted(_)));
    }

    #[test]
    fn daily_cap_exhaustion_rejects() {
        let g = ProfileClaimGuard::new(GuardConfig {
            max_llm_calls_per_day: 2,
            ..GuardConfig::default()
        });
        // First two pass.
        for _ in 0..2 {
            let r = g.check(delta(vec![]), &window_with_user_speech(), T0);
            assert!(matches!(r, GuardOutcome::Accepted(_)));
        }
        // Third hits the cap.
        let r = g.check(delta(vec![]), &window_with_user_speech(), T0);
        match r {
            GuardOutcome::Rejected { reason, .. } => {
                assert!(matches!(
                    reason,
                    GuardReason::LlmCapExceeded { calls: 2, cap: 2 }
                ));
            }
            _ => panic!("expected LlmCapExceeded"),
        }
    }

    #[test]
    fn daily_counter_rolls_over_at_midnight() {
        let g = ProfileClaimGuard::new(GuardConfig {
            max_llm_calls_per_day: 1,
            ..GuardConfig::default()
        });
        let r = g.check(delta(vec![]), &window_with_user_speech(), T0);
        assert!(matches!(r, GuardOutcome::Accepted(_)));
        // Past the next UTC midnight → counter resets.
        let next_day = ((T0 / SECONDS_PER_DAY) + 1) * SECONDS_PER_DAY;
        let r = g.check(delta(vec![]), &window_with_user_speech(), next_day);
        assert!(matches!(r, GuardOutcome::Accepted(_)));
    }

    #[test]
    fn rejected_outcome_carries_deterministic_payload_hash() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("identity.x", 0.8)]);
        let h1 = match g.check(d.clone(), &window_quoted_only(), T0) {
            GuardOutcome::Rejected {
                blocked_delta_hash, ..
            } => blocked_delta_hash,
            _ => panic!("expected Rejected"),
        };
        // Second pass with the same delta against another guard
        // produces the same hash — operator can dedupe audit rows.
        let g2 = ProfileClaimGuard::default();
        let h2 = match g2.check(d, &window_quoted_only(), T0) {
            GuardOutcome::Rejected {
                blocked_delta_hash, ..
            } => blocked_delta_hash,
            _ => panic!("expected Rejected"),
        };
        assert_eq!(h1, h2);
    }

    #[test]
    fn daily_llm_counter_current_returns_zero_for_unknown_bucket() {
        let c = DailyLlmCounter::new();
        assert_eq!(c.current("never-seen"), 0);
    }

    #[test]
    fn redacted_field_in_claim_rejects_whole_delta() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![
            claim("identity.location", 0.9),
            claim("skills.rust", 0.8),
        ]);
        let redacted = vec!["identity.location".to_string()];
        let outcome = g.check_with_redactions(d, &window_with_user_speech(), &redacted, T0);
        match outcome {
            GuardOutcome::Rejected { reason, .. } => {
                assert!(matches!(
                    reason,
                    GuardReason::FieldRedacted { ref field } if field == "identity.location"
                ));
            }
            _ => panic!("expected Rejected on redacted field"),
        }
    }

    #[test]
    fn forget_topic_sentinel_rejects_topic_in_any_claim_value() {
        let g = ProfileClaimGuard::default();
        let mut location = claim("preferences.city", 0.9);
        location.value_json = serde_json::json!({
            "current": "BERLIN",
            "history": ["Hamburg"]
        });
        let redacted = vec!["_tombstone.berlin".to_string()];
        let outcome = g.check_with_redactions(
            delta(vec![location]),
            &window_with_user_speech(),
            &redacted,
            T0,
        );
        assert!(matches!(
            outcome,
            GuardOutcome::Rejected {
                reason: GuardReason::FieldRedacted { ref field },
                ..
            } if field == "preferences.city"
        ));
    }

    #[test]
    fn empty_or_unrelated_tombstone_does_not_block_claims() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("skills.rust", 0.8)]);
        for redacted in [
            vec!["_tombstone.".to_string()],
            vec!["_tombstone.berlin".to_string()],
        ] {
            let outcome =
                g.check_with_redactions(d.clone(), &window_with_user_speech(), &redacted, T0);
            assert!(matches!(outcome, GuardOutcome::Accepted(_)));
        }
    }

    /// V02-04 H2 property — "any field tagged REDACTED_PERMANENT
    /// never re-inserted by any apply sequence". Deterministic stand-
    /// in for a proptest: the guard sees 256 different delta shapes,
    /// each containing the redacted field alongside an arbitrary mix
    /// of other claims. None must be accepted.
    #[test]
    fn redacted_field_never_passes_under_any_claim_combo() {
        let g = ProfileClaimGuard::default();
        let redacted = vec!["identity.location".to_string()];
        let other_fields = [
            "skills.rust",
            "tone.direct",
            "language.primary",
            "role.developer",
            "interest.music",
            "interest.coffee",
            "stack.rust-windows",
            "channel.telegram",
        ];
        // 2^8 = 256 subsets of `other_fields`; each one paired with
        // the redacted claim. None must pass.
        for mask in 0u32..=0xff {
            let mut claims = vec![claim("identity.location", 0.95)];
            for (i, f) in other_fields.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    claims.push(claim(f, 0.7 + (i as f32) * 0.02));
                }
            }
            let d = delta(claims);
            let outcome = g.check_with_redactions(d, &window_with_user_speech(), &redacted, T0);
            match outcome {
                GuardOutcome::Rejected { reason, .. } => {
                    assert!(
                        matches!(
                            reason,
                            GuardReason::FieldRedacted { ref field }
                                if field == "identity.location"
                        ),
                        "mask {mask:#04x} rejected for wrong reason: {reason:?}"
                    );
                }
                other => {
                    panic!("REDACTED field slipped through under claim-mix {mask:#04x}: {other:?}")
                }
            }
        }
    }

    #[test]
    fn redacted_registry_with_no_matching_field_still_accepts() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("skills.rust", 0.8)]);
        let redacted = vec!["identity.location".to_string()];
        let outcome = g.check_with_redactions(d, &window_with_user_speech(), &redacted, T0);
        assert!(matches!(outcome, GuardOutcome::Accepted(_)));
    }

    #[test]
    fn empty_redactions_list_behaves_like_check_without_h2() {
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("identity.x", 0.7)]);
        let outcome = g.check_with_redactions(d, &window_with_user_speech(), &[], T0);
        assert!(matches!(outcome, GuardOutcome::Accepted(_)));
    }

    #[test]
    fn unknown_category_rejected_via_check_full() {
        use crate::profile::extension_registry::TypedExtensionRegistry;
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("pets.fluffy", 0.8)]);
        let registry = TypedExtensionRegistry::default();
        let outcome = g.check_full(d, &window_with_user_speech(), &[], &registry, T0);
        match outcome {
            GuardOutcome::Rejected { reason, .. } => {
                assert!(matches!(
                    reason,
                    GuardReason::UnknownCategoryNotRegistered { ref field } if field == "pets.fluffy"
                ));
            }
            _ => panic!("expected Rejected for unknown category"),
        }
    }

    #[test]
    fn known_base_category_passes_check_full() {
        use crate::profile::extension_registry::TypedExtensionRegistry;
        let g = ProfileClaimGuard::default();
        let d = delta(vec![claim("identity.name", 0.8)]);
        let registry = TypedExtensionRegistry::default();
        let outcome = g.check_full(d, &window_with_user_speech(), &[], &registry, T0);
        assert!(matches!(outcome, GuardOutcome::Accepted(_)));
    }

    #[test]
    fn out_of_window_date_in_claim_rejects_via_check_all() {
        use crate::profile::extension_registry::TypedExtensionRegistry;
        use crate::profile::timestamp_check::TimestampPolicy;
        let g = ProfileClaimGuard::default();
        let mut c = claim("identity.last_visit", 0.8);
        c.value_json = serde_json::json!({"date": "2020-01-15"});
        let d = ProfileDelta {
            extraction_id: "ext-1".into(),
            conversation_hash: "h".into(),
            claims: vec![c],
            ..Default::default()
        };
        let policy = TimestampPolicy {
            // 2026-05-15 anchor (1_778_976_000), no padding.
            window_oldest_unix: 1_778_716_800,
            window_newest_unix: 1_778_803_200,
            padding_days: 0,
        };
        let outcome = g.check_all(
            d,
            &window_with_user_speech(),
            &[],
            &TypedExtensionRegistry::default(),
            &policy,
            T0,
        );
        match outcome {
            GuardOutcome::Rejected { reason, .. } => {
                assert!(matches!(
                    reason,
                    GuardReason::TimestampOutsideWindow { ref field } if field == "identity.last_visit"
                ));
            }
            _ => panic!("expected Rejected on out-of-window date"),
        }
    }

    #[test]
    fn date_inside_window_passes_check_all() {
        use crate::profile::extension_registry::TypedExtensionRegistry;
        use crate::profile::timestamp_check::TimestampPolicy;
        let g = ProfileClaimGuard::default();
        let mut c = claim("identity.last_visit", 0.8);
        c.value_json = serde_json::json!({"date": "2026-05-15"});
        let d = ProfileDelta {
            extraction_id: "ext-1".into(),
            conversation_hash: "h".into(),
            claims: vec![c],
            ..Default::default()
        };
        let policy = TimestampPolicy {
            window_oldest_unix: 1_778_716_800,
            window_newest_unix: 1_778_803_200,
            padding_days: 1,
        };
        let outcome = g.check_all(
            d,
            &window_with_user_speech(),
            &[],
            &TypedExtensionRegistry::default(),
            &policy,
            T0,
        );
        assert!(matches!(outcome, GuardOutcome::Accepted(_)));
    }
}
