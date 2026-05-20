# SPEC: ProfileClaimGuard — NEOTH v1.1

> Status: BUILD-READY. This is the "One Change That Addresses Most Risks" from ADVERSARIAL/00.
> Sits between `profile.extract` LLM output and `profile.apply` WAL write.
> ~300 LOC pure Rust, NO LLM. Schicht-0 deterministic gate.

---

## 0. Motivation

Five distinct risks share a single failure mode: a malformed/adversarial/redundant `ProfileDelta` reaches `profile.apply` and gets written to the WAL. Each risk had its own proposed fix. Implementing each fix separately fragments the codebase.

**ProfileClaimGuard** is one Schicht-0 tool that addresses all five:

| Risk | Source | How guard addresses it |
|------|--------|----------------------|
| H1 — Profile-extraction prompt injection | ADVERSARIAL/01+06 | First-person attribution + claim provenance check (any claim whose evidence is `quoted_external` or `tool_output` is REJECTED) |
| H2 — PROFILE_REDACT re-promotion | ADVERSARIAL/06 | Consults `idx_profile_redactions` registry; blocks claims for fields with `never_recreate=1` |
| H5 — LLM-call cost spiral | ADVERSARIAL/05+06 | Tracks per-day LLM call count, enforces hard cap before council fires |
| M1 (peer-source) — LLM timestamp hallucination | ADVERSARIAL/10 | Rule-based NLP normalizes timestamps in claims BEFORE write (catches LLM hallucinating "Alex said this on Thursday" when the conversation was Monday) |
| M2 (peer-source) — Novel-category `other: Vec<String>` black hole | ADVERSARIAL/10 | Typed extension registry — claims for unknown categories MUST register as typed extension or be rejected |

Plus side-benefit: emits **behavioral-style embedding per turn** as Phase-3 parity-substrate for migration scoring (not in primary scope but enabled by this guard).

---

## 1. Position in the Pipeline

```
profile_learn.yaml stages:
  1. window_extract       (Schicht-0: WAL slice)
  2. window_attribute     (Schicht-0: H1 first-person attribution)
  3. profile_extract      (Schicht-0: LLM call — Qwen3-4B local or Gemini cloud)
  4. profile_validate     (Schicht-0: schema validation)
  5. profile_claim_guard  (Schicht-0: THIS SPEC — additional protections)
  6. profile_apply        (Schicht-1: Effect Adapter — emits WAL events)
```

Step 5 (ProfileClaimGuard) inserted BETWEEN validation and application. All steps before are pure-function or LLM-call. ProfileClaimGuard is the LAST chance to reject a bad claim before WAL ingestion.

---

## 2. Rust Implementation

```rust
use crate::profile::types::{ProfileDelta, RawClaim, Contradiction, AttributedSegment};
use crate::wal::idx_profile_redactions::RedactionRegistry;
use crate::motor::DailyQuota;
use chrono::{DateTime, Utc};

pub struct ProfileClaimGuard {
    redactions:        Arc<RedactionRegistry>,
    daily_quota:       Arc<DailyQuota>,
    extension_registry: Arc<TypedExtensionRegistry>,
    style_embedder:    Arc<BehavioralStyleEmbedder>,
    config:            GuardConfig,
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    /// Daily LLM call cap before council is suppressed.
    pub max_llm_calls_per_day:      u32,
    /// Minimum confidence to allow a claim through.
    pub min_confidence_passthrough: f32,    // 0.30 default
    /// Reject claims whose extraction window has no first-person segments at all.
    pub require_first_person_window: bool,
}

#[derive(Debug)]
pub enum GuardOutcome {
    Accepted(ProfileDelta),
    Rejected { reason: GuardReason, blocked_delta_hash: [u8; 32] },
}

#[derive(Debug, thiserror::Error)]
pub enum GuardReason {
    #[error("field is redacted (never_recreate=true): {field}")]
    FieldRedacted { field: String },
    #[error("claim has no first-person evidence: {field}")]
    NoFirstPersonEvidence { field: String },
    #[error("daily LLM-call cap exceeded: {calls}/{cap}")]
    LlmCapExceeded { calls: u32, cap: u32 },
    #[error("unknown profile category not in extension registry: {category}")]
    UnknownCategoryNotRegistered { category: String },
    #[error("timestamp claim outside attributed window: claimed={claimed_ts}, window=[{window_start}, {window_end}]")]
    TimestampOutsideWindow { claimed_ts: String, window_start: String, window_end: String },
    #[error("malformed claim shape: {0}")]
    MalformedClaim(String),
}

impl ProfileClaimGuard {
    pub fn check(
        &self,
        delta: ProfileDelta,
        attributed_window: &AttributedWindow,
    ) -> GuardOutcome {
        // 1. LLM-call cap (H5)
        if !self.daily_quota.check_and_increment("llm_calls") {
            return GuardOutcome::Rejected {
                reason: GuardReason::LlmCapExceeded {
                    calls: self.daily_quota.current("llm_calls"),
                    cap: self.config.max_llm_calls_per_day,
                },
                blocked_delta_hash: sha256(&delta),
            };
        }

        // 2. Require first-person window (H1)
        if self.config.require_first_person_window
            && !attributed_window.has_user_speech_segments()
        {
            return GuardOutcome::Rejected {
                reason: GuardReason::NoFirstPersonEvidence {
                    field: "<any>".to_string(),
                },
                blocked_delta_hash: sha256(&delta),
            };
        }

        // 3. Per-claim checks
        let mut accepted_claims = Vec::with_capacity(delta.claims.len());
        for raw_claim in delta.claims.iter() {
            // 3a. Redaction registry (H2)
            if let Some(redaction) = self.redactions.lookup(&raw_claim.field) {
                if redaction.never_recreate {
                    return GuardOutcome::Rejected {
                        reason: GuardReason::FieldRedacted { field: raw_claim.field.clone() },
                        blocked_delta_hash: sha256(&raw_claim),
                    };
                }
            }

            // 3b. Provenance / first-person (H1)
            //
            // Each claim must cite at least one user_speech segment from the
            // attributed window. If LLM produced a claim citing a quoted_external
            // or tool_output segment, this rejects it.
            let cited_evidence = self.find_cited_evidence(&raw_claim, attributed_window);
            if !cited_evidence.iter().any(|seg| seg.attribution == Attribution::UserSpeech) {
                continue;  // Drop this single claim, continue processing others.
                           // Optionally emit PROFILE_DELTA_BLOCKED for this claim:
                           // self.audit.log_drop(raw_claim, "no_first_person_evidence");
            }

            // 3c. Timestamp normalization (M1)
            let normalized_claim = self.normalize_timestamps(raw_claim, attributed_window)
                .map_err(|e| /* ... */)?;

            // 3d. Category-extension registry (M2)
            //
            // RawClaim.field is a dot-path like "identity.name" or "skills.rust" or "<NEW>.foo".
            // If first segment is not a known UserProfile category AND not in
            // TypedExtensionRegistry, reject.
            let category = raw_claim.field.split('.').next().unwrap_or("");
            if !self.is_known_or_registered_category(category) {
                return GuardOutcome::Rejected {
                    reason: GuardReason::UnknownCategoryNotRegistered {
                        category: category.to_string(),
                    },
                    blocked_delta_hash: sha256(&raw_claim),
                };
            }

            // 3e. Confidence floor
            if normalized_claim.confidence < self.config.min_confidence_passthrough {
                continue;  // silently drop low-confidence — log to audit only
            }

            accepted_claims.push(normalized_claim);
        }

        // 4. Behavioral-style embedding (parity substrate, Phase 3)
        let style_embedding = self.style_embedder.embed_window(attributed_window);

        // 5. Construct guarded delta
        GuardOutcome::Accepted(ProfileDelta {
            extraction_id:        delta.extraction_id,
            conversation_hash:    delta.conversation_hash,
            claims:               accepted_claims,
            contradictions:       delta.contradictions,
            style_embedding:      Some(style_embedding),  // NEW v1.1
            guard_version:        env!("CARGO_PKG_VERSION"),
        })
    }

    fn find_cited_evidence<'a>(
        &self,
        claim: &RawClaim,
        window: &'a AttributedWindow,
    ) -> Vec<&'a AttributedSegment> {
        // Match claim.reasoning text segments against window segments.
        // If LLM cites "Alex said he works in Berlin", find that segment in the window
        // and return its attribution. If multiple segments matched, return all.
        window.segments.iter()
            .filter(|seg| seg.text.contains_quoted_phrase_from(&claim.reasoning))
            .collect()
    }

    fn normalize_timestamps(
        &self,
        claim: RawClaim,
        window: &AttributedWindow,
    ) -> Result<RawClaim, GuardReason> {
        // Rule-based NLP to detect timestamp claims in `value_json`.
        // Examples:
        //   "first_observed: last Thursday"  → resolve to absolute date using window's
        //                                       conversation_window timestamps as anchor
        //   "deadline: in 3 weeks"            → resolve to absolute date
        // Reject if normalized timestamp falls outside [window_oldest, window_newest + 1d].
        // Catches LLM hallucinating "Alex said X last month" when entire window is today.
        Ok(claim)  // (sketch — full impl uses chrono + dateparser)
    }

    fn is_known_or_registered_category(&self, category: &str) -> bool {
        const KNOWN: &[&str] = &[
            "identity", "preferences", "relationships", "skills", "goals",
            "health", "schedule", "emotional_baseline", "operator_preferences",
        ];
        KNOWN.contains(&category) || self.extension_registry.is_registered(category)
    }
}
```

---

## 3. Typed Extension Registry (M2 fix)

```rust
/// Operator-curated registry of additional profile categories.
/// Prevents the `other: Vec<String>` black hole — any novel category
/// the LLM tries to introduce must be explicitly registered here.
pub struct TypedExtensionRegistry {
    registered: HashSet<String>,
}

impl TypedExtensionRegistry {
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        // ~/.neoth/profile_extensions.toml
        // Format:
        //   [extensions]
        //   pets = "Vec<Pet>"      # operator-curated type signature
        //   hobbies = "Vec<Hobby>"
        Ok(/* ... */)
    }

    pub fn is_registered(&self, category: &str) -> bool {
        self.registered.contains(category)
    }

    pub fn register(&mut self, category: &str, type_sig: &str) -> Result<(), ConfigError> {
        // Operator explicit registration via `neoth profile register-category <name> <type>`
        self.registered.insert(category.to_string());
        Ok(())
    }
}
```

When the LLM proposes a claim like `field: "pets.name"`, ProfileClaimGuard checks: is `pets` registered? If not, reject with `UnknownCategoryNotRegistered`. Operator can run `neoth profile register-category pets "Vec<Pet>"` to opt in.

---

## 4. Behavioral-Style Embedding (Phase-3 Parity Substrate)

```rust
pub struct BehavioralStyleEmbedder {
    inner: Arc<EmbeddingModel>,  // Qwen3-Embedding-0.6B-Q8, same as semantic recall
}

impl BehavioralStyleEmbedder {
    /// Generate a per-turn embedding capturing tone, vocabulary, register.
    /// Stored alongside ProfileDelta as `style_embedding: Option<[f32; 1024]>`.
    ///
    /// Used Phase 3 for migration parity scoring: NEOTH's per-turn style should
    /// match Jarvis's style over the same conversation window. Diverging style
    /// → behavioral drift detected.
    pub fn embed_window(&self, window: &AttributedWindow) -> Vec<f32> {
        let user_speech_text = window.collected_user_speech();
        self.inner.embed(&user_speech_text)
    }
}
```

---

## 5. Daily Quota Tracking

```rust
pub struct DailyQuota {
    counters: Mutex<HashMap<String, u32>>,
    caps:     HashMap<String, u32>,
    reset_at: Mutex<DateTime<Utc>>,
}

impl DailyQuota {
    pub fn check_and_increment(&self, key: &str) -> bool {
        let mut counters = self.counters.lock().unwrap();
        let reset = self.reset_at.lock().unwrap();
        if Utc::now() > *reset {
            counters.clear();
            *self.reset_at.lock().unwrap() = next_midnight();
        }
        let cap = self.caps.get(key).copied().unwrap_or(u32::MAX);
        let current = counters.entry(key.to_string()).or_insert(0);
        if *current >= cap {
            return false;
        }
        *current += 1;
        true
    }

    pub fn current(&self, key: &str) -> u32 {
        self.counters.lock().unwrap().get(key).copied().unwrap_or(0)
    }
}
```

---

## 6. Configuration

`~/.neoth/profile_claim_guard.toml`:

```toml
[guard]
max_llm_calls_per_day      = 500
min_confidence_passthrough = 0.30
require_first_person_window = true

[guard.audit]
emit_block_events = true  # 0x38 PROFILE_DELTA_BLOCKED per claim dropped
log_drops_at_info_level = true

[guard.timestamp_normalization]
enabled = true
window_padding_hours = 24   # claims may reference times up to 24h outside the conversation window

[guard.extensions_path]
path = "~/.neoth/profile_extensions.toml"
```

---

## 7. Audit Trail

Every guard rejection emits `0x38 PROFILE_DELTA_BLOCKED` (defined in `SPEC_proactive_learning.md §4`):

```rust
pub struct ProfileDeltaBlocked {
    pub field:              String,
    pub reason:             String,           // serialized GuardReason
    pub blocked_delta_hash: [u8; 32],
    pub guard_version:      String,
    pub trigger_event_id:   u64,
    pub hlc:                Hlc,
}
```

`neoth profile audit --since 7d` lists all blocked claims with reasons. Operator sees what NEOTH refused to learn and why.

---

## 8. Test Plan

```rust
#[test]
fn test_redacted_field_blocks_re_promotion() {
    // H2 test
    let guard = ProfileClaimGuard::new_test();
    guard.redactions.add("identity.location", never_recreate=true);
    let delta = ProfileDelta::with_claim("identity.location", "Berlin");
    let outcome = guard.check(delta, &test_window());
    assert!(matches!(outcome, GuardOutcome::Rejected { reason: GuardReason::FieldRedacted { .. }, .. }));
}

#[test]
fn test_quoted_external_segment_blocks_claim() {
    // H1 test
    let window = AttributedWindow::with_segments(vec![
        AttributedSegment::quoted_external("Alex's favorite food is sushi"),
    ]);
    let delta = ProfileDelta::with_claim("preferences.food", "sushi");
    let outcome = guard.check(delta, &window);
    // claim is silently dropped, not whole delta rejected
    let accepted = outcome.unwrap_accepted();
    assert_eq!(accepted.claims.len(), 0);
}

#[test]
fn test_llm_call_cap_exceeds_blocks() {
    // H5 test
    let mut guard = ProfileClaimGuard::new_test();
    guard.config.max_llm_calls_per_day = 3;
    for _ in 0..3 {
        guard.check(test_delta(), &test_window());  // accepts
    }
    let outcome = guard.check(test_delta(), &test_window());  // 4th
    assert!(matches!(outcome, GuardOutcome::Rejected { reason: GuardReason::LlmCapExceeded { .. }, .. }));
}

#[test]
fn test_unknown_category_blocks_unless_registered() {
    // M2 test
    let delta = ProfileDelta::with_claim("pets.name", "Mittens");
    let outcome = guard.check(delta.clone(), &test_window());
    assert!(matches!(outcome, GuardOutcome::Rejected { reason: GuardReason::UnknownCategoryNotRegistered { .. }, .. }));
    // Register it
    guard.extension_registry.register("pets", "Vec<Pet>").unwrap();
    let outcome2 = guard.check(delta, &test_window());
    assert!(matches!(outcome2, GuardOutcome::Accepted(_)));
}

#[test]
fn test_timestamp_outside_window_normalized_or_rejected() {
    // M1 test
    let window = AttributedWindow::with_anchor_date("2026-05-13");
    let delta = ProfileDelta::with_claim_value("identity.last_birthday", json!({"date": "last Thursday"}));
    let outcome = guard.check(delta, &window);
    let accepted = outcome.unwrap_accepted();
    // "last Thursday" relative to 2026-05-13 (Tuesday) = 2026-05-08
    assert!(accepted.claims[0].value_json.contains("2026-05-08"));
}
```

---

## 9. Schedule

| Phase | Day | Deliverable |
|-------|-----|-------------|
| 2 | 40 | `ProfileClaimGuard` struct + all 5 checks + unit tests pass |
| 2 | 41 | Integration with `profile_learn.yaml` (new stage `profile_claim_guard`) |
| 2 | 42 | `idx_profile_redactions` SQLite migration. `neoth profile register-category` CLI. |

---

## 10. Status

**v1.1 ProfileClaimGuard BUILD-READY.** One ~300 LOC Schicht-0 Rust struct addresses 5 distinct risks (H1, H2, H5, M1, M2). Sits between `profile.extract` LLM output and `profile.apply` WAL write. Zero LLM calls within the guard itself — fully deterministic.
