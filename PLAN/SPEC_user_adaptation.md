# SPEC: User Adaptation — Behavior Patterns + Profile Presets + Proactive Self-Development

> Status: BUILD-READY (planning)
> Phase: 2 (extends `SPEC_proactive_learning.md` already at 6/6 stages live)
> Trigger: operator 2026-05-16 — "Verhaltensmuster erkennung für user, user profiling für anpassung an den user, profil selector in gui - profil presets - 5 stück mit empfehlung (lowkey basis maybe), proactive selbst entwicklung für neoth aufgrundlage des peofils des nutzers"

---

## 0. Scope

This spec adds four interconnected capabilities to NEOTH's user-adaptation surface:

1. **Behavior-pattern detection** — passive observation of *when*, *how*, and *what* the operator does. Complements the existing claim-based profile (which captures *who* and *what they say*).
2. **Profile presets** — 5 operator-selectable starting points that bundle persona / tone / verbosity / refusal-style / autonomy defaults into one switch. Default recommendation: **LOWKEY** (blunt, technical, no padding).
3. **GUI profile selector** — Slint wizard screen + post-onboarding switcher. Operator picks one of the 5 presets (or "Custom") and NEOTH reconfigures itself.
4. **Proactive self-development** — periodic review where NEOTH inspects its own behavior-pattern + profile state and proposes adjustments (persona override, sampling params, response length defaults) to better match the operator. Operator-gated under autonomy.

The existing `profile_learn.yaml` pipeline (window_extract → window_attribute → extract → validate → claim_guard → apply) stays unchanged. This spec adds a parallel observation surface that feeds **the same** `idx_profile` view via a new `behavior_*` field-path namespace.

---

## 1. Behavior-Pattern Detection

### 1.1 Pattern Taxonomy

Five passive observation channels — all derived from WAL events the daemon already writes, no new instrumentation in chat dispatch required:

| Channel | Source events | Example claim |
|---------|---------------|---------------|
| **Temporal** | `RAW_TEXT` ts_ns + channel | `behavior.active_hours = [9..12, 14..18, 22..02]` |
| **Cadence** | Inter-turn gaps in episodic rows | `behavior.median_turn_gap_seconds = 240` |
| **Length** | `RAW_TEXT` body bytes | `behavior.median_prompt_chars = 87` + `behavior.prefers_short_replies = true` (when median *response* approval > rejection) |
| **Topic** | FTS5 + ctx-mode chunk hits | `behavior.frequent_topics = ["rust", "wal", "security"]` |
| **Tone** | Mirror-refusal classifier + ingress-sanitizer findings | `behavior.assertive_register = 0.82` (high-confidence inferred from imperative-mood + first-person frequency) |

### 1.2 Storage

All behavior claims live in the existing `idx_profile` table under the `behavior` top-level category. **No new schema needed** — the `TypedExtensionRegistry::BASE_CATEGORIES` const adds `"behavior"` as the 10th base category.

```rust
// Before:
pub const BASE_CATEGORIES: &[&str] = &[
    "identity", "preferences", "relationships", "skills", "goals",
    "health", "schedule", "emotional_baseline", "operator_preferences",
];

// After:
pub const BASE_CATEGORIES: &[&str] = &[
    "identity", "preferences", "relationships", "skills", "goals",
    "health", "schedule", "emotional_baseline", "operator_preferences",
    "behavior",  // NEW
];
```

### 1.3 Aggregation Pipeline

New cron-driven module `behavior::aggregate`:

1. **Daily roll-up** — once per local-midnight, walk the prior 24h of episodic rows + compute per-channel statistics. Emit `PROFILE_DELTA` (0xB0) events for each derived `behavior.*` claim.
2. **Reinforce path** — when a derived value matches an existing claim, the existing apply-adapter contradiction-resolver fires `PROFILE_REINFORCED` (0xB1) and bumps confidence.
3. **Decay** — uses the existing Hebbian decay schedule (memory-tier framework). Behavior claims drift naturally if observation evidence stops arriving.

**No new WAL event types** — `PROFILE_DELTA` / `PROFILE_REINFORCED` / `PROFILE_SUPERSEDED` already in the Hypothalamus band (0xB0-0xBF) cover behavior claims.

### 1.4 Pure-Function Estimators

Each channel exposes a pure-function `Estimator` trait:

```rust
pub trait Estimator {
    fn name(&self) -> &'static str;
    fn estimate(&self, window: &EpisodicWindow) -> Vec<RawClaim>;
}
```

Five implementations: `TemporalEstimator`, `CadenceEstimator`, `LengthEstimator`, `TopicEstimator`, `ToneEstimator`. Each estimator is independently unit-testable against synthetic episodic windows — no LLM, no I/O.

### 1.5 Privacy

Behavior claims **never leave the machine**. They're derived from WAL events already on disk; they never flow into outbound LLM requests unless the operator explicitly enables `inference.share_behavior_with_provider = true` (default `false`, gated by `Action::PaidProviderCall` permission).

---

## 2. Profile Presets

### 2.1 The 5 Presets

| ID | Name | Persona override | Sampling | Reply length | Refusal style | Autonomy hint |
|---|---|---|---|---|---|---|
| `lowkey` | **LOWKEY** *(recommended)* | "Blunt, technical, no padding. Direct, German if German, no apologies, no disclaimers." | `temperature=0.3, top_p=0.9` | Short by default | Mirror + retry (LOWKEY tricks) | elevated |
| `standard` | Friendly Assistant | "Helpful, balanced, friendly. Explain when asked." | `temperature=0.5, top_p=0.95` | Medium | Standard | standard |
| `concise` | Concise | "Minimal output. No chitchat. Answer the question, stop." | `temperature=0.2, top_p=0.9` | Very short | Standard | standard |
| `mentor` | Mentor | "Patient teacher. Walk through reasoning step-by-step. Anticipate follow-up questions." | `temperature=0.4, top_p=0.95` | Long | Standard | strict |
| `sparring` | Sparring Partner | "Adversarial. Challenge claims. Argue the counter-position. Force the operator to defend their reasoning." | `temperature=0.6, top_p=0.95` | Medium | Mirror + escalate | standard |

### 2.2 Preset Schema

Each preset is a typed struct, **not** a free-form YAML. Defined in `presets::PROFILE_PRESETS` as a compile-time `&[ProfilePreset]` so the wizard can list them without I/O.

```rust
pub struct ProfilePreset {
    pub id: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub recommended: bool,
    pub persona_override: &'static str,
    pub sampling: SamplingConfig,
    pub default_reply_length: ReplyLength,
    pub refusal_style: RefusalStyle,
    pub autonomy_hint: AutonomyLevel,
}

pub enum ReplyLength { Short, Medium, Long }
pub enum RefusalStyle { Standard, MirrorRetry, MirrorEscalate }
```

### 2.3 Applying a Preset

`presets::apply(preset_id, &mut FreedomConfig)` mutates:
- `freedom.yaml::autonomy` → preset.autonomy_hint
- `tweaks.toml::persona_override` → preset.persona_override
- `freedom.yaml::inference.default_slot.sampling` → preset.sampling (when local_qwen)
- A new `freedom.yaml::operator_profile_preset: String` field records which preset is active (or `"custom"` after operator edits)

### 2.4 Audit Trail

A new WAL event in the existing lifecycle band:

| Code | Name | Payload |
|------|------|---------|
| `0x1B` | `PROFILE_PRESET_APPLIED` | `{preset_id, prior_preset_id, source: "wizard"|"cli"|"gui", ts_unix}` |

Allows `neoth wal show --type 0x1B` to surface every preset switch the operator made.

---

## 3. GUI Profile Selector

### 3.1 Wizard Screen

New Slint screen inserted between step5 (provider) and step6 (channels):

```
┌──────────────────────────────────────────┐
│ Step 5c — Profile Preset                │
├──────────────────────────────────────────┤
│ How should NEOTH talk to you?           │
│                                          │
│ ⊙ LOWKEY  (recommended)                 │
│   Blunt, technical, no padding.         │
│                                          │
│ ○ Friendly Assistant                    │
│   Helpful + balanced.                   │
│                                          │
│ ○ Concise                                │
│   Minimal output. Answers the question. │
│                                          │
│ ○ Mentor                                 │
│   Walks through reasoning step-by-step. │
│                                          │
│ ○ Sparring Partner                       │
│   Argues the counter-position.          │
│                                          │
│ ○ Custom — I'll configure manually      │
│                                          │
│           [ Back ]   [ Next ]            │
└──────────────────────────────────────────┘
```

### 3.2 Post-Wizard Switcher

A "Profile" panel in the main GUI sidebar lets the operator switch presets at any time. Switch fires `PROFILE_PRESET_APPLIED` + reloads the relevant config files (no daemon restart).

### 3.3 CLI Parity

`neoth profile preset {list, apply <id>, current}`:
- `list` prints all 5 presets + their full settings. JSON or table.
- `apply <id>` mutates the config files + emits the audit frame.
- `current` reports the active preset id from `freedom.yaml::operator_profile_preset`.

---

## 4. Proactive Self-Development

### 4.1 Goal

Periodically (default daily, configurable cron), NEOTH:
1. Reads its own behavior-pattern claims from `idx_profile WHERE field LIKE 'behavior.%'`.
2. Compares against the active preset's *expected* behavior signature.
3. Computes a delta — "operator's median reply length is 600 chars but preset `concise` expects ≤200".
4. Proposes adjustments (e.g. raise `tweaks.toml::persona_override`'s brevity directive).
5. **Requires operator confirmation** before applying — autonomy gate at `standard` level.

### 4.2 Mechanism

New module `self_dev::propose_adjustments`:

```rust
pub struct Adjustment {
    pub field: AdjustmentField,
    pub current_value: serde_json::Value,
    pub proposed_value: serde_json::Value,
    pub reason: String,                 // operator-readable
    pub confidence: f32,                // [0..1]; <0.6 suppressed
}

pub enum AdjustmentField {
    PersonaOverride,
    Temperature,
    TopP,
    ReplyLengthDefault,
    AutonomyLevel,
}

pub fn propose_adjustments(
    profile: &ProfileSummary,
    active_preset: &ProfilePreset,
    history_days: u32,
) -> Vec<Adjustment>;
```

### 4.3 Operator UX

`neoth self-dev review` — CLI command that:
- Lists proposed adjustments with their reasoning.
- Operator approves individually (`--approve <field>`), all (`--approve-all`), or rejects.
- Rejected adjustments record a `SELF_DEV_REJECTED` WAL frame so future runs don't re-propose the same change for N days (configurable cooldown).

### 4.4 WAL Event Codes

| Code | Name | Purpose |
|------|------|---------|
| `0x1C` | `SELF_DEV_PROPOSED` | Adjustment surfaced to operator |
| `0x1D` | `SELF_DEV_APPLIED` | Operator approved + config mutated |
| `0x1E` | `SELF_DEV_REJECTED` | Operator declined |

All in the lifecycle band (0x10-0x1F) — these are operator-state-changing events, parallel to `UPDATE_RAN`.

### 4.5 Safety Rails

- Adjustments **never** rewrite `freedom.yaml` directly. They go through the same atomic-write + DACL/chmod path as `cli/init.rs::write_freedom_yaml_and_credentials`.
- `Adjustment::confidence < 0.6` is suppressed silently — no operator-fatiguing low-confidence noise.
- A daily cap (`max_proposals_per_day = 3`) prevents adjustment-spam if the behavior-pattern detector is noisy.
- Operator can disable the whole subsystem via `freedom.yaml::self_dev.enabled = false`.

---

## 5. Test Plan

### Per-channel estimator tests
Each `Estimator` impl gets unit tests against synthetic `EpisodicWindow` fixtures:
- empty window → empty claims
- single-channel skew (all messages between 22:00 and 02:00) → `behavior.active_hours` covers that range
- mixed-language window → `behavior.languages = ["de", "en"]` proportions

### Preset apply round-trip
- Apply each of the 5 presets → assert `freedom.yaml` round-trips to the expected values
- "Custom" path → `operator_profile_preset = "custom"` + no overrides applied

### Self-dev proposal logic
- Behavior matches preset exactly → 0 proposals
- Behavior diverges on one dimension → exactly 1 proposal pointing at that field
- Cooldown active → suppressed even if delta present

### GUI integration
- Slint screen renders all 5 presets with the recommended marker on `lowkey`
- Selecting "Custom" advances to step6 without writing preset overrides
- Apply-from-sidebar fires the WAL audit frame

### CLI parity
- `neoth profile preset list` returns all 5 + their settings
- `neoth profile preset apply lowkey` mutates files atomically
- `neoth self-dev review` with no proposals exits clean with operator-friendly message

---

## 6. Schedule

| Phase | Day | Deliverable |
|-------|-----|-------------|
| 2 | 1-2 | `behavior::estimator` trait + 5 impls + tests (no daemon wiring yet) |
| 2 | 3 | `presets::PROFILE_PRESETS` + `apply` + `neoth profile preset` CLI |
| 2 | 4 | WAL events 0x1B/0x1C/0x1D/0x1E + cli/events.rs registry |
| 2 | 5-6 | `behavior::aggregate` cron job + `idx_profile` apply path wiring |
| 2 | 7-8 | `self_dev::propose_adjustments` + `neoth self-dev review` CLI |
| 2 | 9-10 | Slint wizard step5c + post-wizard sidebar switcher |

Total: ~10 focused engineering days.

---

## 7. Anti-Pattern Conformance

| Rule | How addressed |
|------|---------------|
| G.1 (no Schicht-0 LLM call) | Every estimator is pure-function — no LLM in the behavior pipeline. Self-dev is also pure (compares stored claims against preset signatures). |
| G.5 (no emergent composition) | Presets are typed structs, not free-form YAML. The wizard offers exactly 6 paths (5 presets + Custom); operator cannot construct novel composites. |
| G.10 (no magic scale) | Daily cap + confidence floor + cooldown all explicit. No "the system gets smarter over time" handwaving. |

---

## 8. Status

**BUILD-READY**. Every dependency lives in shipped code:
- `idx_profile` view: shipped (schema v7)
- Profile apply with contradiction resolver: shipped
- `TypedExtensionRegistry::BASE_CATEGORIES`: shipped (just need to add `"behavior"`)
- `Tweaks::persona_override`: shipped
- `Permissions::evaluate(action, level)`: shipped
- Cron runner: shipped
- WAL band 0x10-0x1F has space at 0x1B-0x1E

No new dependencies. No new tables. Pure additive surface on top of the profile pipeline.
