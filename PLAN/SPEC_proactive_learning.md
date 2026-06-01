# SPEC: Proactive User-Profile Learning — NEOTH v1.1

**Version:** 1.1
**Last-Updated:** 2026-05-16
**Implementation-Status:** SHIPPED (Stages 1-6 + orchestrator) — see `SRC/neothd/src/profile/{window_extract, window_attribute, extract, validate, claim_guard, apply, runner}.rs` and PROGRESS.md "Phase 2 SPEC_proactive_learning" + "Profile pipeline 6 of 6 stages live"

<!-- status: SHIPPED  parent: 00_DESIGN_v1.0_FINAL.md  framework: tool_framework_v4_1.md -->
<!-- wire: event_schema_version=4  header: SPEC_wire_header_v2_slim.md -->
<!-- 2026-05-16 R-1 Gremium fix: was event_schema_version=5; adding RegionTag::Hypothalamus=6 does NOT change PayloadPrefixV4 byte layout — schema-version bumps gate ONLY wire-format-layout changes. See SPEC_wire_header_v2_slim §6 for migration policy. -->
<!-- scope: Phase 2 Day 38-42 (core), Day 50-55 (Council), Phase 3 Day 65 (seed) -->
<!-- v1.1 fixes: H1 prompt-injection, H2 REDACT re-promotion, H4 decay strategy, H8 refusal feedback loop, A3 PROFILE_BASELINE_SNAPSHOT, plus ProfileClaimGuard delegation -->
<!-- v1.1 brand: NEOTH (was NEOTH), CLI `neoth` (was neothctl), config `~/.neoth/` -->

---

## 1. Brain-Region Extension: Hypothalamus = 6

### 1.1 Rationale for Name

`region_tag` values are index-routing tags, not anatomy claims (v0.8 s1 decision).

| Candidate | Decision |
|-----------|----------|
| `UserState = 6` | Rejected: too generic -- BasalGanglia already routes tool-habit state |
| `Cortex = 6` | Rejected: implies reasoning, wrong write-index function |
| `Hypothalamus = 6` | **Accepted**: drives homeostasis (stable set-points), long-term regulation. Maps to a user-profile index that stabilises over time and decays without reinforcement. |

Functional justification: homeostatic regulators maintain stable set-points against drift. The user-profile region does exactly that: a long-lived, confidence-weighted model of the user that resists noise but responds to sustained evidence. Name communicates *rate-of-change* (slow, homeostatic) not anatomy.

### 1.2 Updated Enum

```rust
#[repr(u8)]
pub enum RegionTag {
    None         = 0,
    Hippocampus  = 1,   // episodic           -> idx_episode
    Amygdala     = 2,   // importance scores  -> idx_importance (single-writer)
    Insula       = 3,   // council state      -> idx_council
    Cerebellum   = 4,   // provider stats     -> idx_motor   (single-writer)
    BasalGanglia = 5,   // tool-router cache  -> idx_habit
    Hypothalamus = 6,   // user-profile state -> idx_profile  (single-writer)
}
```

### 1.3 idx_profile Index Invariants

Enforced at WAL ingress (same pattern as existing region invariants in v0.8 s1):

- `Hypothalamus` events MUST carry `profile_field: ProfileField` + `delta_hash: [u8; 16]` in payload.
- Single-writer invariant: only the `profile.apply` Effect Adapter (Schicht-1) emits events with `region_tag = Hypothalamus`. All other writers -> `MalformedRegionEvent` rejection.
- `idx_profile` is a materialised view over all non-tombstoned, non-REDACTED Hypothalamus events, keyed by `ProfileField` discriminant.

---

## 2. Profile Schema

### 2.1 Typed Rust Structs

```rust
/// A single profile claim with confidence metadata and evidence traceability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileClaim<T> {
    pub value:              T,
    pub confidence:         f32,           // [0.0 .. 1.0]
    pub evidence_event_ids: Vec<u64>,      // WAL event_ids that introduced/confirmed this
    pub first_observed_ts:  Hlc,
    pub last_confirmed_ts:  Hlc,
    pub decay_rate:         f32,           // per-day multiplier; default 0.995
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub schema_version:       u16,         // bump on breaking field changes
    pub identity:             Identity,
    pub preferences:          Preferences,
    pub relationships:        Vec<Relationship>,
    pub skills:               Vec<Skill>,
    pub goals:                Vec<Goal>,
    pub health:               Health,
    pub schedule:             Schedule,
    pub emotional_baseline:   EmotionalBaseline,
    pub operator_preferences: OperatorPreferences,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Identity {
    pub name:      Option<ProfileClaim<String>>,
    pub age:       Option<ProfileClaim<u8>>,
    pub role:      Option<ProfileClaim<String>>,
    pub location:  Option<ProfileClaim<String>>,    // city-level; precise coords require opt-in
    pub languages: Vec<ProfileClaim<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Preferences {
    pub food:                Vec<ProfileClaim<String>>,
    pub music:               Vec<ProfileClaim<String>>,
    pub work_patterns:       Option<ProfileClaim<String>>,
    pub sleep_schedule:      Option<ProfileClaim<String>>,
    pub communication_style: Option<ProfileClaim<CommStyle>>,
    pub vocabulary:          Vec<ProfileClaim<String>>,      // recurring terms user uses
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommStyle { Blunt, Formal, Casual, TechnicalDense, Other(String) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub name:               String,
    pub role:               String,
    pub sentiment:          Option<ProfileClaim<Sentiment>>,
    pub last_mentioned_ts:  Hlc,
    pub evidence_event_ids: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sentiment { Positive, Neutral, Negative, Mixed }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub domain:             String,
    pub level:              Option<ProfileClaim<SkillLevel>>,
    pub evidence_event_ids: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SkillLevel { Beginner, Intermediate, Advanced, Expert }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Goal {
    pub description: ProfileClaim<String>,
    pub horizon:     GoalHorizon,
    pub status:      GoalStatus,
    pub deadline:    Option<ProfileClaim<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GoalHorizon { ShortTerm, MediumTerm, LongTerm }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GoalStatus { Active, Paused, Completed, Abandoned }

/// PII category -- requires freedom.yaml opt-in: profile.learn.health = true
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Health {
    pub conditions:     Vec<ProfileClaim<String>>,
    pub medications:    Vec<ProfileClaim<String>>,
    pub allergies:      Vec<ProfileClaim<String>>,
    pub fitness_habits: Vec<ProfileClaim<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Schedule {
    pub routines:           Vec<ProfileClaim<String>>,
    pub important_dates:    Vec<ProfileClaim<String>>,
    pub recurring_patterns: Vec<ProfileClaim<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmotionalBaseline {
    pub typical_state:   Option<ProfileClaim<String>>,
    pub stressors:       Vec<ProfileClaim<String>>,
    pub energy_patterns: Option<ProfileClaim<String>>,
}

/// How user wants NEOTH to behave.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperatorPreferences {
    pub preferred_response_style: Option<ProfileClaim<String>>,
    pub disliked_patterns:        Vec<ProfileClaim<String>>,
    pub language_mode:            Option<ProfileClaim<String>>,
    pub autonomy_level:           Option<ProfileClaim<String>>,
}
```

### 2.2 ProfileDelta (extractor output)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDelta {
    pub extraction_id:     [u8; 16],    // random per call; idempotency key for profile.apply
    pub conversation_hash: [u8; 32],    // SHA-256 of the extraction window input
    pub claims:            Vec<RawClaim>,
    pub contradictions:    Vec<Contradiction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawClaim {
    pub field:      String,             // dot-path: "identity.name", "skills[Rust]"
    pub value_json: String,
    pub confidence: f32,
    pub reasoning:  String,             // one sentence why this follows from the window
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contradiction {
    pub field:             String,
    pub old_value_json:    String,
    pub new_value_json:    String,
    pub evidence_sentence: String,
}
```

---

## 3. Extraction Pipeline

### 3.1 pipelines/profile_learn.yaml

```yaml
# Framework v4.1 Schicht-1 Pipeline
# Triggered by WAL event 0x0E PROVIDER_RESPONSE

name: profile_learn
version: "1.0"
content_hash: ""          # SHA-256 of this file, filled at load-time (G.2 compliance)
schicht: 1

trigger:
  event_type: 0x0E        # PROVIDER_RESPONSE
  condition: "scope != SESSION_LEDGER_INTERNAL"
  # H8 fix: refusal feedback loop prevention. Exclude refusal-mirror events from
  # the extraction trigger. Otherwise: refusal → mirror → user engagement →
  # profile learns "user values reflection" → Block-B primes Left toward hedging
  # → more refusals → death spiral.
  exclude_event_types:
    - 0x16  # REFUSAL_OBSERVED
    - 0x17  # REFUSAL_MIRRORED
    - 0x18  # REFUSAL_REDIRECTED
    - 0x19  # REFUSAL_PERSISTENT
  exclude_originators:
    - Council  # Council verdicts not user-speech

execution_model: sequential
max_duration_ms: 8000
cost_budget_usd: 0.027    # ~800 tokens at Gemini 3.1 Pro; daily cap via Cerebellum

stages:

  - id: window_extract
    tool: context.window_slice
    schicht: 0
    inputs:
      event_id: "{{trigger.event_id}}"
      turns_back: 2
      include_current_user_msg: true
      include_current_response: true
    outputs: [conversation_window]
    # Deterministic: no LLM. Pure WAL slice of last 2 turn-pairs.

  - id: window_attribute
    # H1 fix: first-person attribution pass — distinguish authentic user speech
    # from quoted/pasted external text. Pure Schicht-0 deterministic NLP heuristic.
    tool: profile.attribute_segments
    schicht: 0
    inputs:
      conversation_window: "{{stages.window_extract.conversation_window}}"
    outputs: [attributed_window]
    # Each segment tagged with one of:
    #   user_speech       — first-person from operator, eligible for extraction
    #   quoted_external   — paste/quote/reddit/forwarded — NOT eligible
    #   tool_output       — agent or pipeline-produced text — NOT eligible
    #   ambiguous         — confidence < 0.6 on attribution — NOT eligible
    # Heuristics: quote markers (">", code blocks, "Operator schrieb:"), first-person
    # pronouns ratio, syntactic patterns (forwarded headers, URL-only segments).
    # Documented in profile.attribute_segments tool spec.

  - id: profile_extract
    tool: profile.extract
    schicht: 0
    inputs:
      # H1 fix: only user_speech segments fed to LLM; quoted_external dropped
      attributed_window: "{{stages.window_attribute.attributed_window}}"
      existing_profile_summary: "{{idx_profile.summary_for_extractor}}"
      seed: "{{sha256(stages.window_attribute.attributed_window) | take_u64}}"
    outputs: [profile_delta]
    model: right_hemisphere     # Gemini 3.1 Pro (Phase 2) — Phase 3+: local_qwen3_4b via SPEC_local_inference.md (A1/H3 fix)
    temperature: 0.0
    seed_mode: deterministic    # G.1: fixed seed from attributed_window hash
    max_tokens: 800
    inject_lowkey: false        # extractor needs neutral lens; LOWKEY not in prompt
    # H1 fix: explicit system-prompt instruction that profile claims must be
    # backed by user_speech attribution. Quoted/forwarded content cannot become
    # claims — even if the LLM disagrees.
    system_prompt_constraint: "claims_only_from_first_person_user_speech"
    on_refusal: mirror_pipeline # G.6: SPEC_mirror_refusal.md

  - id: profile_validate
    tool: profile.validate
    schicht: 0
    inputs:
      delta: "{{stages.profile_extract.profile_delta}}"
      attributed_window: "{{stages.window_attribute.attributed_window}}"
    outputs: [validated_delta]
    # Pure schema validation + provenance check (H1 fix).
    # Rejects: malformed JSON, unknown fields, confidence outside [0,1],
    # claims that reference quoted_external/tool_output/ambiguous segments.

  - id: profile_claim_guard
    # H1+H2+H5 unified gate — see SPEC_profile_claim_guard.md.
    tool: profile.claim_guard
    schicht: 0
    inputs:
      delta: "{{stages.profile_validate.validated_delta}}"
      attributed_window: "{{stages.window_attribute.attributed_window}}"
      redaction_registry_snapshot: "{{idx_profile_redactions.current}}"
    outputs: [guarded_delta]
    # Functions:
    # - Timestamp normalization via rule-NLP (catches LLM time-hallucinations)
    # - Novel-category routing (typed extension registry — never `other: Vec<String>`)
    # - Redaction registry check (H2 fix — blocks PROFILE_REDACT re-promotion)
    # - Behavioral-style embedding for parity-substrate (Phase 3)
    # - Per-day global LLM-call cap enforcement (cost-spiral prevention)
    # Pure Schicht-0 — deterministic, no LLM.

  - id: profile_apply
    tool: profile.apply
    schicht: 1              # Effect Adapter -- Schicht-1 boundary
    effect_adapter: true
    idempotency_key: "{{stages.profile_claim_guard.guarded_delta.extraction_id}}"
    inputs:
      delta: "{{stages.profile_claim_guard.guarded_delta}}"
      trigger_event_id: "{{trigger.event_id}}"
    outputs: [applied_event_ids]
    # Emits PROFILE_DELTA / PROFILE_REINFORCE / PROFILE_SUPERSEDE WAL events.
    # Single-writer enforced by region_tag=Hypothalamus gate.

primary_kpi: "profile_delta.claims | length"
primary_kpi_threshold: 0     # 0 claims is valid (nothing extractable)
```

### 3.2 Tool Responsibilities (G.7 single-responsibility)

| Tool | Schicht | Does | Does NOT |
|------|---------|------|----------|
| `context.window_slice` | 0 | Slice WAL by turn count | Parse semantics |
| `profile.extract` | 0 | LLM call -> ProfileDelta JSON | Validate schema, write WAL |
| `profile.validate` | 0 | Schema-validate ProfileDelta | Extract, write, apply |
| `profile.apply` | 1 Effect Adapter | Emit WAL events, update idx_profile | Extract, validate, decide |

### 3.3 Determinism (G.1 compliance)

`profile.extract` is a pure function of its inputs:

- `conversation_window`: deterministic WAL slice
- `seed = take_u64(sha256(conversation_window))` -- same window -> same seed
- `temperature = 0.0`, model pinned to `gemini-3.1-pro-{pinned-version}`
- `inject_lowkey = false` -- no session-variable prompt contamination

Same conversation window -> byte-identical `ProfileDelta`. Verified by `test_profile_extraction_deterministic`.

`extraction_reasoning_hash = sha256(prompt_bytes || response_bytes)` logged to WAL at each extraction (G.9). Inspectable via `neothctl profile inspect <event_id>`.

---

## 4. WAL Event Types (v1.1 additions)

<!-- event_schema_version stays at 4: new event_type codes do not alter PayloadPrefixV4 byte layout. R-1 Gremium 2026-05-16. -->
<!-- PROFILE band relocated 2026-05-15: original 0x30-0x39 collided with CHANNEL band (SP-5 C-prime). Authoritative codes 0xB0-0xBF (Hypothalamus band) — see `wal/events.rs` and SPEC_wal_lifecycle.md §N authoritative event-code registry. -->


All new event types use `region_tag = Hypothalamus = 6`. Payload prefix byte `0x06`.

| Code | Name | Key payload fields | Trigger |
|------|------|--------------------|--------|
| `0x30` | `PROFILE_DELTA` | `field`, `new_value_json`, `confidence`, `evidence_event_ids`, `delta_hash` | New claim from profile.apply |
| `0x31` | `PROFILE_REINFORCE` | `field`, `old_confidence`, `new_confidence`, `evidence_event_id` | Same claim re-observed |
| `0x32` | `PROFILE_SUPERSEDE` | `field`, `old_value_json`, `new_value_json`, `old_event_id`, `contradiction_sentence` | Contradiction detected |
| `0x33` | `PROFILE_REDACT` | `field`, `redact_scope`, `operator_id`, `never_recreate: bool` | `neoth profile redact` |
| `0x34` | `PROFILE_PAUSE` | `scope: {session/day/forever}`, `until_ts: Option<Hlc>` | `neoth profile pause` |
| `0x35` | `PROFILE_RESUME` | `paused_since_event_id: u64` | `neoth profile resume` |
| `0x36` | `PROFILE_EXPORT` | `format: {json/md}`, `confidence_floor: f32`, `export_hash: [u8;32]` | `neoth profile export` |
| **`0x37`** | **`PROFILE_BASELINE_SNAPSHOT`** | **`profile_json: Value`, `seeded_from_source: String`, `snapshot_hash: [u8;32]`** | **Phase-3 Day 65 seed migration (A3 fix)** |
| `0x38` | `PROFILE_DELTA_BLOCKED` | `field`, `reason: {redacted|pii_gate|provenance_fail|guard_rejected}`, `blocked_delta_hash` | H1/H2 fix — guard rejected a candidate claim |
| `0x39` | `PROFILE_LLM_CAP_HIT` | `daily_count`, `cap`, `dropped_extraction_window_hash` | H5 fix — daily cost cap exceeded |

### 4.1 PROFILE_REDACT vs PROFILE_SUPERSEDE

**PROFILE_SUPERSEDE**: claim replaced by new evidence. Old claim tombstoned (`flags |= SUPERSEDED`). Audit trail preserved; WAL reader reconstructs full claim history.

**PROFILE_REDACT** (H2 fix — persistent redaction registry):
- Operator-initiated removal. Sets `flags |= REDACTED` on all prior events for the field.
- `idx_profile` drops the field immediately.
- **NEW v1.1: persistent redaction-registry table** `idx_profile_redactions`:
  ```sql
  CREATE TABLE idx_profile_redactions (
      field_path TEXT NOT NULL PRIMARY KEY,
      redacted_at_hlc BLOB NOT NULL,  -- HLC bytes
      reason TEXT,
      never_recreate INTEGER NOT NULL DEFAULT 1,  -- 0 = allowed to re-learn later; 1 = permanent block
      operator_id BLOB NOT NULL
  );
  ```
- `profile.claim_guard` (the new ProfileClaimGuard, see `SPEC_profile_claim_guard.md`) consults `idx_profile_redactions` on EVERY candidate claim. If `field_path` exists with `never_recreate=1`: emit `0x38 PROFILE_DELTA_BLOCKED` (no new PROFILE_DELTA). No re-promotion.
- The redaction event records only field name and operator_id; the old value is zero-filled in the WAL segment on next compaction. Audit trail records *that* a redaction occurred, not *what* was redacted.

### 4.2 PROFILE_BASELINE_SNAPSHOT (A3 fix — Phase-3 anchor)

**Purpose:** captures a ground-truth profile state at Phase-3 Day 65 seed migration. Required for Phase-4 Ecology drift detection — without it, drift comparison has no anchor.

**Constraints:**
- Emitted ONCE per node, at Phase-3 Day 65 seed migration completion.
- `importance = 1.0` (highest), `flags = 0` (no TOMBSTONE permitted), `never_compacted = true`.
- Compaction policy: compactor MUST refuse to evict `PROFILE_BASELINE_SNAPSHOT` events regardless of age or tombstone flag (Framework G.11 read-only constraint applied to compactor).
- Payload contains full seeded `UserProfile` as JSON + `snapshot_hash` for tamper-detection.
- Phase 4 Ecology drift scanner consumes this event read-only as comparison anchor:
  ```
  drift_score(field, time_window) = abs(idx_profile[field].confidence - snapshot[field].confidence)
  ```
  Fields with `drift_score > 0.4` over 30 days: operator drift alert emitted.

---

## 5. Hebbian Reinforcement and Decay

### 5.1 Reinforcement

On each `PROFILE_REINFORCE` event for field F:

```
new_confidence = min(1.0, old_confidence + 0.1 * (1.0 - old_confidence))
```

Asymptotic approach to 1.0. Claim at confidence 0.5 reaches 0.95 after approximately 26 reinforcements.

### 5.2 Decay (H4 fix — nightly batch, NOT on-read lazy)

**Problem v0.9:** "On-read lazily (Phase 2 acceptable)" puts decay computation on the critical path of every Block-B assembly (every LLM call). With 200+ profile fields across 9 categories, lazy on-read = milliseconds added to every recall query.

**Fix v1.1:** Decay computed in two paths, **never on-read**:

1. **Nightly batch (primary):** `pipelines/profile_decay_tick.yaml` runs once per day at 03:30 local (same window as `wal_compact`). Recomputes `confidence` for all active fields. Writes back to `idx_profile` materialized table. After this run, `idx_profile.confidence` is the authoritative current value — readers consume directly.

2. **On-reinforce immediate (secondary):** When `PROFILE_REINFORCE` fires for field F, the decay-since-last-confirmed-ts is computed inline and combined with the reinforcement formula in a single update:
   ```rust
   pub fn reinforce_with_decay(
       claim: &ProfileClaim<T>,
       now: Hlc,
       reinforcement_event_id: u64,
   ) -> ProfileClaim<T> {
       let days_since = days_between(claim.last_confirmed_ts, now);
       let decayed = claim.confidence * claim.decay_rate.powi(days_since as i32);
       let reinforced = f32::min(1.0, decayed + 0.1 * (1.0 - decayed));
       ProfileClaim {
           confidence: reinforced,
           last_confirmed_ts: now,
           evidence_event_ids: {
               let mut v = claim.evidence_event_ids.clone();
               v.push(reinforcement_event_id);
               v
           },
           ..claim.clone()
       }
   }
   ```

**Block-B assembly does ZERO decay computation.** Reads `idx_profile.confidence` as-is. Maximum staleness = 24 hours (until next nightly tick).

**Trade-off accepted:** a field reinforced at 23:00 won't appear with updated confidence in Block-B until 03:30 the next day. Operator-visible behavior: profile-driven recall ranking slightly lags new evidence by up to 24h. This is acceptable for a homeostatic-regulated user-profile-state (slow-drift by design).

Default `decay_rate = 0.995`. At 0.995/day: `ln(0.5) / ln(0.995) ≈ 138 days` to half-confidence.

```yaml
# pipelines/profile_decay_tick.yaml
name: profile_decay_tick
schicht: 1
schedule:
  cron: "30 3 * * *"     # daily 03:30, in same window as wal_compact
stages:
  - id: scan_active_fields
    tool: profile.list_active_fields
    schicht: 0
  - id: compute_decay
    tool: profile.batch_decay
    schicht: 0
    inputs:
      fields: "{{stages.scan_active_fields.fields}}"
      now: "{{wall_clock_hlc}}"
  - id: write_idx_profile
    tool: profile.batch_update_idx
    schicht: 1
    effect_adapter: true
    idempotency_key: "decay_tick_{{date_today}}"
```

### 5.3 Auto-drop threshold

`confidence < 0.1` -> field excluded from `idx_profile` active view. Originating WAL events remain for audit. Field reactivates if new evidence raises confidence above 0.1.

### 5.4 Contradiction handling

`profile.apply` compares each `RawClaim` against current `idx_profile`:

- Value identical or compatible -> emit `PROFILE_REINFORCE`.
- Value contradicts existing claim -> emit `PROFILE_SUPERSEDE`.
- No existing claim -> emit `PROFILE_DELTA`.

String semantic contradiction detection is conservative: only exact-inverse pairs (e.g., vegan vs. carnivore for food) trigger SUPERSEDE. Ambiguous cases emit a new `PROFILE_DELTA` alongside the old. Both coexist with separate confidence scores until one decays below 0.1.

---

## 6. Confidence-Gated Prompt Injection

### 6.1 Block-B injection

Block-B (default 1500 tokens, hard 3000, per v0.8 s3) receives a profile summary section:

```
[USER PROFILE -- confidence >= 0.6 fields only]
identity.name: <operator-name> (conf=0.97)
preferences.communication_style: BluntDirect (conf=0.91)
preferences.language_mode: German UI / English code (conf=0.99)
skills: security_research Expert (conf=0.88), Rust Advanced (conf=0.76)
operator_preferences.disliked_patterns: no_apologies, no_emojis (conf=0.95)
```

Fields with `confidence < 0.6` are omitted from Block-B. Block-B profile section budget: 200 tokens default. Overflow: drop lowest-confidence fields first.

### 6.2 Block-C recall ranking bias

Block-C (`Stable Recall`) candidate scoring adds a `profile_relevance_bonus`:

- User message concept matches a profile `skills.domain` -> +0.15 bonus to cosine score for events tagged with that skill domain.
- `preferences.communication_style = TechnicalDense` -> up-weight events with high technical vocabulary density.

Scoring hint only. Profile relevance does not override WAL importance scores.

### 6.3 Council consultation

During Council dissent resolution (Phase 2, Day 50-55), Callosum MAY consult `idx_profile` to break ties:

- Profile confidence >= 0.7: Callosum may cite profile in `CouncilVerdict.reasoning`.
- Profile confidence < 0.7: advisory, not authoritative.

Council sees only the Block-B formatted summary (200-token format). Council members do not see raw `evidence_event_ids` or raw confidence floats.

---

## 7. Privacy Controls

### 7.1 CLI commands

```bash
# Show active profile (confidence >= 0.1, formatted)
neothctl profile show

# Show WAL trace per claim
neothctl profile show --raw

# Redact (GDPR-style; value zero-filled in WAL on next compaction)
neothctl profile redact identity.location
neothctl profile redact health               # entire category
neothctl profile redact --all

# Pause learning
neothctl profile pause                       # session scope (default)
neothctl profile pause --scope=day
neothctl profile pause --scope=forever

# Resume
neothctl profile resume

# Export
neothctl profile export                      # JSON to stdout
neothctl profile export --format=md
neothctl profile export --confidence-floor=0.7

# Inspect extraction reasoning for a specific WAL event
neothctl profile inspect <event_id>
# -> prints: extraction_reasoning_hash, prompt_byte_count, response_byte_count, delta summary
```

### 7.2 freedom.yaml flags

```yaml
profile:
  learn:
    enabled: true                    # master switch
    require_approval: false          # if true: PROFILE_DELTA held pending until operator approves
    identity: true
    preferences: true
    relationships: true
    skills: true
    goals: true
    health: false                    # PII -- OFF by default, requires explicit opt-in
    schedule: true
    emotional_baseline: true
    operator_preferences: true
  decay_rate_override: null          # null = use per-field default (0.995)
  confidence_injection_floor: 0.6
  daily_cost_cap_usd: 1.00
```

PII categories (`health`, precise `identity.location`) are `false` by default. Enabling requires explicit operator action in freedom.yaml.

### 7.3 Approval gate

When `require_approval = true`: `profile.apply` emits `PROFILE_DELTA` with `flags |= SYNTHETIC` (pending). Event held in staging queue. `neothctl profile approve` (or `--all`) promotes to active.

---

## 8. Anti-Pattern Conformance (G.1-G.13)

| Anti-Pattern | How addressed |
|---|---|
| **G.1 Stateful Tool** | `profile.extract` has zero state. Input = conversation window bytes. Output = ProfileDelta JSON. All state in WAL only, accessed via `idx_profile` view. No in-memory mutation outside Effect Adapter append-write. |
| **G.2 Self-Modifying Tool** | `profile_learn.yaml` is immutable post-load. `content_hash` verified on every instantiation. Hash mismatch -> `PIPELINE_INTEGRITY_FAIL`, pipeline refuses to start. |
| **G.3 Goal-Seeking Tool** | `profile.extract` extracts only what is *in* the conversation window. No completeness objective. Empty delta is valid output. Extractor prompt states explicitly: extract only what is clearly stated, not what would complete the profile. |
| **G.4 Meta-Decision-Making** | Pipeline-Router decides when `profile_learn` runs (PROVIDER_RESPONSE trigger). `profile.extract` does not decide whether to run itself, does not call other tools, does not modify pipeline config. |
| **G.5 Emergent Composition** | No inline composition. All stages declared in `profile_learn.yaml`. `profile.extract` does not call `profile.validate` or `profile.apply`. |
| **G.6 Refusal-Umgehung** | If Gemini refuses extraction (PII concern), `on_refusal: mirror_pipeline` triggers per `SPEC_mirror_refusal.md`. No silent fallback. Operator receives `MIRROR_REFUSAL_TRIGGERED` notification. |
| **G.7 Scope-Inflation** | Three tools, three responsibilities, no overlap (s3.2 table). |
| **G.8 Starke Emergenz** | Extraction is deterministic (temp=0, fixed seed). Reinforcement and decay formulas are algebraic. No adaptive internal state. No behaviour not derivable from inputs + formulas in this spec. |
| **G.9 Black-Box** | Every extraction logs `extraction_reasoning_hash` (SHA-256 of prompt+response bytes) to WAL. `neothctl profile inspect <event_id>` returns full hash, token counts, delta summary. |
| **G.10 Magic Scale Assumption** | Confidence formula is explicit Hebbian (s5.1). No claim that more conversations -> accurate profile without the reinforcement mechanism explicitly firing. Profile at 0 evidence = empty profile. |
| **G.11 Closed-Loop Ecology** | Phase-4 Ecology scanner reads `idx_profile` for drift detection. Ecology emits zero WAL events. Drift reports go to operator as human-readable output only. |
| **G.12 Level-Confusion** | `profile.extract` = Schicht 0 (pure function). `profile_learn.yaml` = Schicht 1 (orchestrator). `idx_profile` = Schicht 2 read source for Ecology. No Schicht-0 tool writes to Schicht-2 storage. |
| **G.13 Bateson-III-Claims** | Profile is *descriptive* (records observations). Not *prescriptive* (does not define who the user is). `UserProfile` carries no autonomy claims. Profile cannot modify itself or trigger its own reinforcement. It is data, consulted by pipelines. |

---

## 9. Integration into v0.8 Schedule

### 9.1 Day-30 MVP

No profile learning. Profile system not shipped. Day-30 acceptance criteria unchanged. Profile code may exist behind a feature flag, but zero WAL events 0x30-0x36 emitted in MVP.

### 9.2 Phase 2 -- ProfileExtractor (Day 38-42)

Prerequisite: Right Hemisphere (Gemini) wired (Phase 2 base, Day 31-37).

| Day | Deliverable |
|-----|-------------|
| 38 | `UserProfile` / `ProfileClaim<T>` / `ProfileDelta` structs. Unit tests for Hebbian math (s5.1-5.2). |
| 39 | `profile.extract` tool (Schicht-0 Gemini wrapper, temp=0, seed). `test_profile_extraction_deterministic` passes. |
| 40 | `profile.validate` tool. `profile.apply` Effect Adapter. WAL events 0x30-0x33 emitted correctly. |
| 41 | `profile_learn.yaml` pipeline wired to PROVIDER_RESPONSE trigger. `idx_profile` view created. |
| 42 | `neothctl profile` CLI (show/redact/pause/resume/export/inspect). `freedom.yaml` PII gates. Full test suite (s10). |

### 9.3 Phase 2 -- Council Integration (Day 50-55)

Prerequisite: Council debate pipeline (Phase 2 base).

| Day | Deliverable |
|-----|-------------|
| 50 | Block-B profile injection (confidence >= 0.6 gate, 200-token budget). `test_profile_injection_confidence_gate`. |
| 51-52 | Block-C recall ranking `profile_relevance_bonus` (+0.15 for skill-domain match). |
| 53-55 | Callosum profile consultation in dissent resolution. Council adversarial tests updated for profile-conflict scenarios. |

### 9.4 Phase 3 Day 65 -- Jarvis Seed Migration

The operator's existing `HIPPOCAMPUS_CORE.md` "About the user" section provides the initial profile seed.

Migration procedure:
1. Parse `HIPPOCAMPUS_CORE.md` entries (name, role, language preference, communication style, skills, stressors).
2. For each entry: synthesise a `PROFILE_DELTA` WAL event with `confidence = 0.7`, `evidence_event_ids = []`, `originator = MIGRATION_TOOL`.
3. Operator reviews seeded profile via `neothctl profile show --raw`, approves or redacts.
4. After approval: `PROFILE_RESUME` event emitted. Live extraction layers on seeded values.

### 9.5 Phase 4 -- Hebbian Tuning + Drift Detection

Ecology scanner reads `idx_profile` across weeks:

- Rapid confidence decay in stable fields -> possible life change, operator alert.
- Fields never confirmed despite 30+ days active -> candidate for auto-drop review.
- 3+ PROFILE_SUPERSEDE events on same field in 14 days -> drift cluster alert.

Ecology emits reports only. No automated profile modifications.

---

## 10. Test Plan

All tests in `tests/profile_learning.rs`.

```rust
// 1. Deterministic extraction
// Feed identical conversation window twice (different wall-clock).
// Assert: ProfileDelta claim content byte-identical (excluding extraction_id).
#[test] fn test_profile_extraction_deterministic()

// 2. Hebbian decay math
// confidence = 1.0, decay_rate = 0.995. Simulate 138 days without reinforce.
// Assert: confidence in [0.49, 0.51].
#[test] fn test_profile_decay_to_zero_after_138_days()

// 3. Reinforcement strengthens
// confidence = 0.5. Apply 5 PROFILE_REINFORCE. Assert confidence ~= 0.691.
#[test] fn test_profile_reinforce_strengthens()

// 4. Contradiction emits SUPERSEDE
// Insert PROFILE_DELTA: identity.name = "Sam".
// Extract window with "my name is not Sam, it is Samuel".
// Assert: profile.apply emits PROFILE_SUPERSEDE (old=Sam, new=Samuel).
// Assert: idx_profile.identity.name = Some(ProfileClaim { value: "Samuel", ... }).
#[test] fn test_profile_supersede_contradicts()

// 5. Redact removes from idx, preserves audit event
// Insert PROFILE_DELTA: identity.location = "Berlin".
// Run: neothctl profile redact identity.location.
// Assert: idx_profile.identity.location = None.
// Assert: WAL contains PROFILE_REDACT with region_tag=Hypothalamus.
// Assert: original PROFILE_DELTA has flags |= REDACTED.
#[test] fn test_profile_redact_removes_from_idx()

// 6. Pause stops learning
// Emit PROFILE_PAUSE. Trigger PROVIDER_RESPONSE -> profile_learn pipeline.
// Assert: pipeline aborts at window_extract with PausedError.
// Assert: no PROFILE_DELTA emitted.
#[test] fn test_profile_pause_stops_learning()

// 7. PII opt-in required
// freedom.yaml: profile.learn.health = false.
// Conversation contains "I have diabetes".
// Assert: profile.apply does NOT emit PROFILE_DELTA for health fields.
// Assert: logs contain PII_BLOCKED event with field=health.
// Set health = true. Assert: same conversation produces PROFILE_DELTA for health.
#[test] fn test_profile_pii_opt_in_required()

// 8. Block-B injection gate
// Insert profile: field_a conf=0.8, field_b conf=0.5, field_c conf=0.3.
// Assemble Block-B. Assert: only field_a appears in Block-B profile section.
#[test] fn test_profile_injection_confidence_gate()
```

---

## 11. Default Privacy Posture

| Dimension | Default | Override |
|---|---|---|
| Learning enabled | ON | `profile.learn.enabled = false` |
| Health fields | OFF (PII opt-in) | `profile.learn.health = true` |
| Precise location | OFF (PII opt-in) | `profile.learn.identity.location = true` |
| Approval gate | OFF | `profile.learn.require_approval = true` |
| Confidence injection floor | 0.6 | `confidence_injection_floor: X` |
| Daily cost cap | $1.00/day | `daily_cost_cap_usd: X` |
| Profile shared with Council | Aggregate summary only | Not configurable (by design) |
| Profile to outbound providers | Never | Not configurable (by design) |
| WAL audit trail on redact | Event type preserved, value zeroed | Not configurable (by design) |

---

## 12. File Map

| File | Purpose |
|------|---------|
| `src/profile/types.rs` | `UserProfile`, `ProfileClaim<T>`, `ProfileDelta`, all sub-structs |
| `src/profile/extract.rs` | `profile.extract` tool -- Schicht-0 Gemini wrapper |
| `src/profile/validate.rs` | `profile.validate` tool -- schema-only, no LLM |
| `src/profile/apply.rs` | `profile.apply` Effect Adapter -- WAL emit + idx_profile write |
| `src/profile/hebbian.rs` | `reinforce()`, `decay()`, `auto_drop_check()` pure functions |
| `src/wal/region_tag.rs` | Add `Hypothalamus = 6` + payload invariant check |
| `pipelines/profile_learn.yaml` | Extraction pipeline |
| `src/cli/profile.rs` | `neothctl profile` subcommands |
| `tests/profile_learning.rs` | Test suite (8 tests, s10) |
| `config/freedom.yaml` | Add `profile.learn.*` flags |

---

*Sub-spec of `00_DESIGN_v0.8_FINAL.md`. Normative for v0.9 profile system.*  
*All decisions traceable to `tool_framework_v4_1.md` G.1-G.13 and v0.8 region_tag invariants.*
