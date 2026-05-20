# MUNIN — Design v0.9 FINAL (was: AGENTER)

> **Project renamed: AGENTER → MUNIN** (Norse: Odin's memory-raven, literally "Memory").
> **Status:** Build-ready. v0.8 was final-spec; v0.9 adds Proactive User-Profile Learning + project rename.
> **Tagline:** *Munin remembers.*

---

## 0. Rename: AGENTER → MUNIN

| Was | Wird |
|-----|------|
| Project dir `AGENTER/` | `MUNIN/` (operator action: directory rename post-confirmation) |
| Binary `agenterd` | `muninnd` (Norse spelling, two-n) |
| CLI `agenterctl` | `munin` (short, command-as-verb: `munin recall`, `munin profile`) |
| Config `~/.agenter/` | `~/.munin/` |
| Brain region "originator" enum unchanged (LEFT/RIGHT/CALLOSUM/COUNCIL) — names per role, not anatomy |
| WAL magic `"AGNT"` | `"MUNN"` (4 bytes, ASCII) |

**Rationale:** Odin's two ravens were Huginn (Thought) und Muninn (Memory). Muninn flew daily through all worlds and returned with what he saw — a perfect operational metaphor for a continuous-learning agent. Marvel-Norse pantheon parallel to Jarvis. Single-word brand, 5 letters, viral-short.

**Future expansion path:** if operator ever wants a thought/reasoning-twin to Munin's memory-twin → name = **HUGIN**.

All other v0.8 decisions stand. WAL magic change is the only binary-format change — costs nothing since no WAL data exists yet.

---

## 1. NEW FEATURE: Proactive User-Profile Learning

Per `SPEC_proactive_learning.md` (619 lines, 27 KB). Summary here.

### 1.1 What it does

Munin continuously builds and refines a structured profile of the operator (Alex) from every conversation, every channel inbound, every vault edit. The profile is:
- **Versioned** (every field tracks when first observed, last confirmed)
- **Evidence-linked** (every claim cites the event_ids that introduced/reinforced it)
- **Confidence-scored** (0..1, Hebbian reinforce + time decay)
- **Operator-controlled** (show/redact/pause/export commands)
- **Auditable** (every PROFILE_DELTA event in WAL, fully replayable)

### 1.2 Brain region #6: Hypothalamus

Added to `region_tag` enum:
```rust
#[repr(u8)]
pub enum RegionTag {
    None         = 0,
    Hippocampus  = 1,  // episodic
    Amygdala     = 2,  // importance
    Insula       = 3,  // council
    Cerebellum   = 4,  // provider stats
    BasalGanglia = 5,  // tool habit
    Hypothalamus = 6,  // NEW v0.9: long-term user-profile state (homeostasis, drives)
}
```

**Why Hypothalamus:** in real biology, hypothalamus regulates slow homeostatic set-points (body-temp, hunger, sleep cycles) — exactly the timescale and function of a user-profile that drifts on weeks, not seconds. Not metaphor — functional signal that this index changes slowly.

**Hard invariant:** only `profile.apply` Effect Adapter writes to region_tag=Hypothalamus. Single-writer.

### 1.3 Profile schema (typed Rust struct)

```rust
pub struct UserProfile {
    pub identity:       Versioned<Identity>,
    pub preferences:    Versioned<Preferences>,
    pub relationships:  Versioned<HashMap<PersonId, Relationship>>,
    pub skills:         Versioned<HashMap<DomainId, SkillEntry>>,
    pub goals:          Versioned<Vec<Goal>>,
    pub health:         Versioned<Health>,           // PII, opt-in only
    pub schedule:       Versioned<ScheduleEntries>,
    pub emotional_baseline: Versioned<EmotionalState>,
    pub operator_prefs: Versioned<OperatorPrefs>,    // beyond LOWKEY nuance
}

pub struct Versioned<T> {
    pub value: T,
    pub confidence: f32,            // 0..1
    pub evidence_event_ids: Vec<u64>,
    pub first_observed_ts: Hlc,
    pub last_confirmed_ts: Hlc,
    pub decay_rate: f32,            // default 0.995/day
}
```

### 1.4 New WAL event types (v0.9 schema event_schema_version=5)

| Type | Name | Region | Purpose |
|------|------|--------|---------|
| 0x30 | PROFILE_DELTA | Hypothalamus | Proposed change: field + new_value + evidence + confidence |
| 0x31 | PROFILE_REINFORCE | Hypothalamus | Same claim re-observed; confidence↑, decay reset |
| 0x32 | PROFILE_SUPERSEDE | Hypothalamus | Contradiction; old claim tombstoned |
| 0x33 | PROFILE_REDACT | Hypothalamus | Operator-initiated removal (GDPR-style) |
| 0x34 | PROFILE_PAUSE | Hypothalamus | Operator disables learning |
| 0x35 | PROFILE_RESUME | Hypothalamus | Re-enable |
| 0x36 | PROFILE_EXPORT | Hypothalamus | Operator dumps profile to JSON/MD |

### 1.5 Extraction pipeline

`pipelines/profile_learn.yaml` (Phase 2 Day 38-42 deliverable):

```yaml
name: profile_learn
schicht: 1

trigger:
  on_wal_event: PROVIDER_RESPONSE   # 0x0E
  filter: { originator: LEFT }      # only learn from user-facing responses
  freedom_check: profile.learn.enabled

budget:
  tokens_max: 800
  time_max_ms: 4000
  usd_max_per_day: 1.0

steps:
  - id: extract_window
    tool: conversation.window_extract
    schicht: 0
    inputs: { turns: 2, current_event_id }
    
  - id: extract_profile
    tool: profile.extract                     # Schicht-0 LLM call (deterministic)
    schicht: 0
    inputs:
      window: extract_window.transcript
      model: gemini-3.1-pro-preview           # pinned exact version
      temperature: 0.0
      seed: hash(extract_window.transcript)
    outputs:
      delta: ProfileDelta  # typed JSON
    
  - id: validate
    tool: profile.validate
    schicht: 0
    inputs: { delta: extract_profile.delta }
    
  - id: pii_gate
    tool: freedom.check
    schicht: 0
    inputs: { categories: validate.categories_in_delta }
    # blocks fields whose category lacks freedom.yaml opt-in
    
  - id: apply
    effect_adapter: true                       # Schicht-1 boundary
    tool: profile.apply
    inputs:
      delta: validate.delta
      gated_categories: pii_gate.allowed
    idempotency_key: delta_content_hash
    audit_event_type: 0x30  # PROFILE_DELTA
```

### 1.6 Determinism guarantee (G.1 compliance)

- Model version pinned in pipeline YAML (`gemini-3.1-pro-preview`)
- temperature = 0
- seed = sha256(conversation_window)
- LOWKEY base stack NOT injected (extractor needs neutral lens)
- Same input → byte-identical ProfileDelta
- **Risk acknowledged**: Gemini API may not guarantee identical output at temp=0 across version bumps. `test_profile_extraction_deterministic` runs on every model-version pin update.

### 1.7 Hebbian reinforce + decay

```rust
// On PROFILE_REINFORCE event:
new_confidence = min(1.0, old_confidence + 0.1 * (1.0 - old_confidence));
// asymptotic approach to 1.0, never crosses

// Daily decay (background task):
new_confidence = old_confidence * 0.995;   // ~50% confidence after 138 days

// Field auto-dropped from active idx_profile when:
confidence < 0.10   // (but PROFILE_DELTA event stays in WAL for audit)
```

### 1.8 Block-B injection (confidence-gated)

Block-B (System Prompt) gets a `<profile_summary>` block injected — but only fields with `confidence >= 0.6`. Format:

```
<profile_summary version="2026-05-13" hash="abc123...">
Identity: Alex, security researcher, Berlin, EN+DE
Preferences: blunt directness, technical depth, German conversation, English code/commits
Schedule: chill-time bis 22 Uhr, work-mode after
Relationships: Saskia (partner), recurring mentions of family + colleagues
Skills: Rust intermediate, Python advanced, security research expert
Operator prefs: no apologies, no padding, no moralizing, direct execution
</profile_summary>
```

200-token cap on `<profile_summary>` block. Lowest-confidence fields dropped first when over cap. `munin profile show --injected` displays exact bytes injected per session.

### 1.9 Privacy controls (operator-facing CLI)

```
munin profile show                       # current state, confidence-sorted
munin profile show --raw                 # full WAL trace per claim
munin profile show --injected            # what's actually in Block-B right now
munin profile redact identity.location   # remove field, emit PROFILE_REDACT
munin profile pause --scope=session      # disable learning this session
munin profile pause --scope=forever      # global opt-out (toggleable)
munin profile resume
munin profile export --format=json > backup.json
munin profile inspect <event_id>         # see extraction-reasoning hash + window
```

### 1.10 PII opt-in (default-off categories)

`~/.munin/freedom.yaml`:
```yaml
profile:
  learn:
    enabled: true                        # global on/off
    require_approval: false              # if true: every PROFILE_DELTA needs operator click
    categories:
      identity: true                     # default-on (low-risk)
      preferences: true
      relationships: true
      skills: true
      goals: true
      schedule: true
      emotional_baseline: true
      operator_prefs: true
      health: false                      # PII OPT-IN
      financial: false                   # PII OPT-IN
      location_precise: false            # PII OPT-IN (city OK, GPS opt-in)
```

PROFILE_DELTA events for default-off categories get rejected at `pii_gate` step. Operator must edit freedom.yaml to enable.

### 1.11 Council injection

Council debates can consult profile in dissent resolution. Example:

```
Left:    "user prefers X (recommend X)"
Right:   "but user said Y last Tuesday — check profile.preferences"
Callosum: queries profile, finds Identity.role conflicts with X → flags dissent
```

Council sees **only aggregate summary**, never raw PII fields. Profile-consultation is read-only from Council's perspective.

### 1.12 Anti-pattern conformance (each G.1-G.13 addressed)

Detailed in `SPEC_proactive_learning.md` §9. Key points:
- G.1: profile.extract is deterministic (fixed seed/temp). Profile state lives in WAL append-only.
- G.2: Extraction YAML immutable post-load. content_hash verified.
- G.3: Profile is data, not goal. Extractor doesn't pursue completeness.
- G.6: Refusal-Umgehung: Gemini PII-refusal → Mirror-Pipeline triggered, NOT silent cascade.
- G.11: Phase-4 Ecology READS idx_profile for drift detection, never writes.
- G.12: Extractor pipeline = Schicht 1. profile.extract = Schicht 0 (pure-fn LLM call). profile.apply = Effect Adapter (Schicht-1 boundary).
- G.13: Profile is descriptive (observed), not prescriptive (identity). Cannot rewrite itself.

### 1.13 Schedule integration

| Phase | Day | Deliverable |
|-------|-----|-------------|
| 1 MVP | 30 | NOT included. Day-30 = Telegram-Left-Claude-recall only. |
| 2 | 31-37 | Right Hemisphere (Gemini) wired — prerequisite for extractor |
| 2 | 38 | `profile.extract` / `profile.validate` / `profile.apply` Schicht-0 tools |
| 2 | 39 | `pipelines/profile_learn.yaml` triggers on PROVIDER_RESPONSE |
| 2 | 40 | `idx_profile` view + Hypothalamus region_tag enforcement |
| 2 | 41 | Hebbian reinforce/decay daily background task |
| 2 | 42 | `munin profile show/redact/pause/export` CLI |
| 2 | 50-55 | Council profile-consultation integration |
| 3 | 65 | Migrate Jarvis HIPPOCAMPUS_CORE "About the user" entries → seed initial profile (Phase 3 one-shot, operator-reviewed) |
| 4 | 91+ | Ecology drift-detection (location/role/sentiment drift across months) |

### 1.14 Day-30 unaffected

Day-30 MVP scope unchanged. Profile-learning enters Phase 2 Day 38. Day-30 still passes its acceptance test (10k events × 10 queries × p95 < 30 ms × 100/100 keyword-find).

---

## 2. Updated Memory + Brain Region Inventory

`region_tag` final enum (v0.9):

| Value | Region | View | Single-writer | Invariants |
|-------|--------|------|---------------|------------|
| 0 | None | none | — | default for events that don't fit any region |
| 1 | Hippocampus | idx_episode | no | category=episodic in payload |
| 2 | Amygdala | idx_importance | yes | importance_score + decay_policy |
| 3 | Insula | idx_council | no | council_round_id |
| 4 | Cerebellum | idx_motor | yes | provider_id + latency_ns |
| 5 | BasalGanglia | idx_habit | no | tool_id + frequency_delta |
| 6 | **Hypothalamus** (NEW) | idx_profile | yes | profile_field + confidence + evidence_event_ids |

---

## 3. New CLI Surface (Munin)

Renamed all commands from `agenterctl` to `munin`:

```
# Health + status
munin status                              # daemon health, channel-state, queue lengths
munin metrics --since 24h
munin doctor                              # diagnostic, WAL integrity check

# Recall + memory
munin recall "what did Alex say about WiFi last week"
munin recall --since=2026-05-01 --until=2026-05-13 --top-k=10
munin profile show
munin profile redact identity.location
munin profile pause --scope=session
munin profile export --format=md

# Skills + plugins
munin skill list
munin skill enable security_research
munin plugin install ./needle.wasm
munin plugin list

# Channels
munin channel list
munin channel pause whatsapp
munin channel resume whatsapp

# Council
munin council invoke --task "stress-test design" --rounds=3
munin council history --since 7d

# WAL admin
munin wal verify                          # CRC scan, magic resync test
munin wal rotate                          # force segment rotation
munin wal compact                         # tombstone-driven compaction
munin wal export --format=jsonl > backup.jsonl

# Migration (Phase 3)
munin migrate dry-run                     # scan Jarvis stores read-only
munin migrate import-jarvis ~/.openclaw   # actual import
munin migrate parity-check                # vs eval/goldset
munin cutover authorize                   # YubiKey/TOTP gated
munin rollback authorize                  # same 2FA

# Settings
munin freedom show
munin freedom set profile.learn.health true
munin settings show
```

---

## 4. WAL Magic Change

```
v0.8 wire-format: magic = b"AGNT"
v0.9 wire-format: magic = b"MUNN"
```

Since no v0.8 WAL data exists yet (build hasn't started), zero migration cost. Reader rejects `b"AGNT"` if anyone ships a v0.8 prototype WAL — explicit `WalError::UnknownMagic`.

---

## 5. Updated v0.9 INDEX

`PLAN/INDEX.md` adds:
- `SPEC_proactive_learning.md` — NEW normative
- This `00_DESIGN_v0.9_FINAL.md` — current normative
- `00_DESIGN_v0.8_FINAL.md` → archived

---

## 6. Tagline + Brand Identity

- **Name:** Munin
- **Tagline:** *Munin remembers.*
- **Iconography:** stylized raven (single black raven, profile view, eye visible)
- **Color palette:** raven black + Norse-runic copper accent
- **Voice:** blunt, direct, German conversation / English code (matches Alex's LOWKEY profile already baked into Block-B)
- **Versioning scheme:** `munin-<year>.<month>.<day>-<build>` (similar to openclaw's date-based scheme)

---

## 7. Day-1 Update (unchanged, just renamed)

```
cargo new muninnd
cd muninnd
cargo add tokio serde serde_json serde_yaml thiserror tracing tracing-subscriber crc32c xxhash-rust uuid anyhow
mkdir -p src/{wal,memory,channels,pipelines,tools,plugins,council,brain,context_engine,profile}
mkdir -p ~/.munin/{skills,plugins,memory,vectors}
touch ~/.munin/soul.md ~/.munin/claude.md ~/.munin/freedom.yaml
echo 'Munin v0.9 - Day 1' > src/main.rs
cargo build --release
```

WAL writer Day 2 emits magic `b"MUNN"`.

---

## 8. Operator Action Required

Before Day 1 starts:

1. **Confirm name:** is **MUNIN** the final name, or pivot to alternative? (Operator override accepted.)
2. **Confirm directory rename:** `AGENTER/` → `MUNIN/` is operator-destructive op (renames the workspace dir). Do it now or later?
3. **Confirm Day-30 MVP scope:** Telegram-only, Left-Claude-only, recall=Keyword+Top-K-cosine. Profile-learning Phase 2. OK?
4. **GitHub-PAT revocation reminder:** Still standing from v0.5. `ghp_OVViPfYc6Y...` in `~/.openclaw-git-mirror/.git/config`. Revoke + rotate before Day 1.

---

## 9. v0.9 vs v0.8 Diff Summary

| Change | Why |
|--------|-----|
| Project rename AGENTER → MUNIN | viral brand, Norse memory-raven, Marvel-pantheon-parallel to Jarvis |
| WAL magic `AGNT` → `MUNN` | brand alignment, zero migration cost (no v0.8 data) |
| `region_tag` enum + Hypothalamus=6 | enable user-profile-state region |
| 7 new WAL event types 0x30-0x36 | profile lifecycle events |
| `idx_profile` view (Hypothalamus, single-writer) | user-profile materialized state |
| `pipelines/profile_learn.yaml` (Phase 2 Day 38-42) | continuous extraction trigger on PROVIDER_RESPONSE |
| 3 new Schicht-0 tools: profile.extract / validate / apply | Framework B.5 conformant pure tools |
| Profile schema typed Rust struct + Versioned<T> wrapper | 9 categories, confidence-scored, evidence-linked |
| PII opt-in default-off (health/financial/location_precise) | privacy default-safe |
| CLI rename `agenterctl` → `munin` | shorter, command-as-verb |
| event_schema_version 4 → 5 | tagged enum extended with profile variants |
| Tagline + brand identity | viral go-to-market |

---

## 10. Status

**Build-ready.** All Claude v0.7 review points fixed in v0.8. v0.9 adds Munin rename + proactive-learning feature without scope-creeping Day-30 MVP. Day-30 still ships.

Next: operator confirms name + directory rename + Day-1 GO. Then `cargo new muninnd`.
