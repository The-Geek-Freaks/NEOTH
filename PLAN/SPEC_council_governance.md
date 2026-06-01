# SPEC: Council Governance — NEOTH v1.1

**Version:** 1.1
**Last-Updated:** 2026-05-16
**Implementation-Status:** PARTIAL — H5 quota+429 cascade subset SHIPPED 2026-05-15 at `SRC/neothd/src/providers/quota.rs` + `SRC/neothd/src/cli/quota.rs` + WAL 0x24 PROVIDER_QUOTA_EXCEEDED. Council pipeline (debate loop, quorum vote, dissent score, smart-trigger gates) DEFERRED to Phase 2 Day 43-55.

> Status: PARTIAL. Fixes: **H5 (Council quota exhaustion + HTTP 429 handling) — SHIPPED 2026-05-15**.
> Scope: Phase 2 Day 38-55 (Council pipeline build, debate orchestration still open).
>
> ✅ SHIPPED 2026-05-15 — per-provider 429 cascade. See `providers::quota::QuotaTracker` +
> `neoth quota {status, reset, set-cap}` CLI + WAL `EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED = 0x24`.
> PROGRESS.md entry "Council Governance H5 — Per-provider 429 cascade (2026-05-15)" documents
> the full implementation.

---

## 0. Motivation

**Problem v1.0 (H5):**
For a security-researcher operator, the word "security" appears constantly. With v1.0 council auto-trigger keywords `[architecture, security, refactor, destructive, breaking]`:
- 25-35% realistic trigger rate (vs spec's implied ~10%)
- Per council debate: 3-10 rounds × 3 hemispheres × ~14k tokens each = 100-450k tokens
- Pro-Plan quotas (Claude Pro ~200 req/day, Gemini Premium ~250 req/day, ChatGPT Pro ~200 req/day) exhausted by 14:00 daily
- **Spec v1.0 has zero handling for HTTP 429 quota exhaustion** — only refusal cascade
- Profile-extraction (also calls Right Hemisphere) is silently dark for rest of day after quota hit

**Fix v1.1:** Explicit council governance — daily budget, quota-aware backpressure, smart triggering, HTTP 429 cascade.

---

## 1. Per-Day Council Budget (NEW)

`~/.neoth/council.toml`:

```toml
[council.budget]
# Hard daily caps. When exceeded: council DENIED, response degrades to single-hemisphere
max_debates_per_day      = 5     # absolute count
max_rounds_total_per_day = 25    # 5 debates × 5 rounds avg
max_usd_per_day          = 2.00  # if API-paid (Pro-Plan: ignored)
max_tokens_per_day_per_provider = 200000

# Soft warning thresholds (operator alert, council continues)
warn_debates_per_day = 4
warn_usd_per_day     = 1.50

# Reset window
reset_at_hlc = "00:00 local"   # daily midnight reset

[council.smart_trigger]
# H5 fix: contextual trigger instead of pure keyword-match
keyword_list = ["architecture", "security", "refactor", "destructive", "breaking"]

# Minimum task complexity to warrant council (cheap heuristic, no LLM call)
min_user_msg_tokens   = 800   # short queries never trigger council
min_assembled_tokens  = 5000  # full prompt bundle must be substantial

# Require actual disagreement signal (not just keyword)
require_dissent_score_gt = 0.4   # Callosum dissent_score from prior single-LLM check

# Maximum auto-triggers per hour (rate limit on trigger frequency)
max_auto_triggers_per_hour = 2
```

**v1.1 trigger logic:**
1. Cheap pre-check: user message contains keyword from `keyword_list`?
2. Complexity gate: `len(user_msg) >= min_user_msg_tokens` AND `len(assembled_prompt) >= min_assembled_tokens`?
3. Dissent gate: single-LLM response via Left Hemisphere; Callosum runs `dissent_score` check; if `dissent_score > 0.4` → trigger council
4. Rate gate: `max_auto_triggers_per_hour` not exceeded
5. Budget gate: `max_debates_per_day` not exceeded
6. All gates pass → council fires
7. Any gate fails → council SKIPPED, emit `0x3D COUNCIL_TRIGGER_SUPPRESSED` event with reason

**Estimated reduction:** v1.0 implicit ~25-35% trigger rate → v1.1 actual ~5-8% (only genuinely complex + ambiguous queries). 80% reduction in council load.

---

## 2. HTTP 429 Quota-Exhaustion Cascade (NEW)

### 2.1 Per-Provider Quota Tracking

`idx_motor` (Cerebellum view) maintains rolling per-provider stats. New fields:

```rust
pub struct ProviderQuotaState {
    pub provider_id:          String,         // "claude-cli" | "codex-cli" | "gemini-cli" | ...
    pub auth_mode:            AuthMode,       // CliOAuth | ApiKey
    pub requests_today:       u32,
    pub last_429_at:          Option<Hlc>,
    pub backoff_until:        Option<Hlc>,    // when to retry after 429
    pub estimated_daily_cap:  Option<u32>,    // learned from observed 429 patterns
    pub healthy:              bool,
}
```

### 2.2 Backoff + Cascade on HTTP 429

When ANY provider returns 429:

```
1. Emit 0x3E PROVIDER_QUOTA_EXCEEDED event (provider_id, retry_after if header present)
2. Mark provider unhealthy with backoff_until = now + retry_after (default 1h if no header)
3. Cascade: invoke next provider in fallback chain
4. If primary recovers (backoff_until passed): re-enable, but stay below threshold
5. Profile-extraction respects same provider-health: routes around 429'd providers
```

### 2.3 Fallback Chain per Pipeline

```toml
[council.fallback_chains]

# Council debate: prefers 3 architecturally-distinct providers
debate_primary   = ["claude-cli", "gemini-cli", "codex-cli"]
debate_fallback  = ["qwen-local", "mistral-cli", "deepseek-cli"]
debate_emergency = ["local_qwen3_72b"]   # if all clouds 429, run on Cube GPU

# User-response (Left Hemisphere only)
response_primary  = ["claude-cli"]
response_fallback = ["codex-cli", "gemini-cli", "local_qwen3_4b"]

# Profile extraction (local-only by default)
extract_primary  = ["local_qwen3_4b"]
extract_fallback = ["local_qwen3_7b"]
# NO cloud unless freedom.yaml inference.allow_cloud_fallback = true
```

### 2.4 Daily-Quota Telemetry

`neoth quota status`:
```
Provider quotas — last 24h
================================================================
claude-cli      [████████░░] 162/200 requests  (81% used)
codex-cli       [██████░░░░] 119/200 requests  (60% used)
gemini-cli      [█████░░░░░] 142/250 requests  (57% used)
qwen-local      [unlimited] 8,234 requests
local_qwen3_4b  [unlimited] 8,150 requests

Council debates today: 3 / 5 max
Auto-triggers this hour: 1 / 2 max

Health:
  claude-cli       OK
  codex-cli        OK
  gemini-cli       OK     (last 429: never)
  qwen-local       OK
  local_qwen3_4b   OK
```

---

## 3. Council Pipeline v1.1 (revised)

```yaml
# pipelines/council_debate.yaml
name: council_debate
schicht: 1
content_hash: ""

trigger:
  # H5 fix: only enters this pipeline if smart_trigger gates passed.
  invoked_by: ["respond_to_user.dissent_detected"]
  budget_check: council.budget_remaining_today > 0

budget:
  max_rounds: 5
  max_tokens_per_provider: 14000
  max_total_usd: 0.50
  hard_timeout_ms: 60000

participants:
  - id: left
    provider: "{{council.fallback_chains.debate_primary[0]}}"
    on_429: "{{council.fallback_chains.debate_primary[1]}}"
  - id: right
    provider: "{{council.fallback_chains.debate_primary[1]}}"
    on_429: "{{council.fallback_chains.debate_primary[2]}}"
  - id: callosum
    provider: "{{council.fallback_chains.debate_primary[2]}}"
    on_429: "{{council.fallback_chains.debate_fallback[0]}}"

stages:
  - id: pre_budget_check
    tool: council.budget_check
    schicht: 0
    inputs:
      max_debates_per_day: "{{council.budget.max_debates_per_day}}"
      remaining_today: "{{idx_council.debates_today_count}}"
    on_failure: emit_event(0x3D COUNCIL_TRIGGER_SUPPRESSED, reason="budget_exceeded")

  - id: round_1
    tool: council.run_round
    schicht: 1
    parallel: true
    participants_active: "{{participants[*].id}}"

  - id: score_round_1
    tool: council.factual_contradiction_check
    schicht: 0
    inputs:
      responses: "{{stages.round_1.responses}}"
      ground_truth_tag: "{{trigger.ground_truth_tag | optional}}"

  - id: should_continue_round_2
    tool: council.continue_check
    schicht: 0
    inputs:
      agreement_score: "{{stages.score_round_1.agreement_score}}"
      threshold: 0.66

  - id: round_2_thru_5
    tool: council.run_loop
    schicht: 1
    max_iterations: 4
    condition: "{{stages.should_continue_round_2.continue}}"

  - id: synthesize_verdict
    tool: council.synthesize
    schicht: 0
    inputs:
      rounds: "{{stages.round_*.responses}}"

  - id: emit_verdict
    tool: wal.emit
    effect_adapter: true
    idempotency_key: "council_{{trigger.session_id}}_{{trigger.turn_id}}"
    inputs:
      event_type: 0x23  # COUNCIL_VERDICT
      verdict: "{{stages.synthesize_verdict.verdict}}"
```

---

## 4. New WAL Event Types (v1.1)

| Code | Name | Purpose |
|------|------|---------|
| 0x3D | `COUNCIL_TRIGGER_SUPPRESSED` | Council would have fired but a gate (budget/rate/complexity) suppressed it |
| 0x3E | `PROVIDER_QUOTA_EXCEEDED` | HTTP 429 from provider — cascade triggered |
| 0x3F | `COUNCIL_BUDGET_EXHAUSTED` | Daily max_debates / max_usd reached — no more councils until reset |

---

## 5. Operator Visibility

```bash
neoth quota status                    # current quota state per provider
neoth quota reset claude-cli          # manual reset (use sparingly — for debug)
neoth council list --since 7d         # list recent council debates
neoth council inspect <verdict_id>    # full transcript for a debate
neoth council suppress --until tomorrow  # operator pause for council triggers
neoth council budget set max_debates_per_day 10   # adjust budget
```

---

## 6. Anti-Pattern Conformance

| Rule | How addressed |
|------|---------------|
| G.5 Emergent Composition | Council pipeline is declarative YAML, all triggers explicit |
| G.10 Magic Scale | Budget caps + complexity gates make council behavior bounded |
| G.12 Level-Confusion | Trigger check is Schicht-0 pure function. Council pipeline is Schicht-1. Quota state is in `idx_motor` Schicht-2-readable view (Phase 4 ecology). |

---

## 7. Test Plan

```rust
#[test]
fn test_security_keyword_alone_does_not_trigger() {
    // User msg = "what's the security update for openssh?"  (short, no actual ambiguity)
    let trigger_result = council.should_trigger(msg);
    assert!(!trigger_result, "Short keyword-only msg must NOT trigger council");
}

#[test]
fn test_429_cascade_to_fallback() {
    let mut claude = MockProvider::always_429();
    let mut codex = MockProvider::ok();
    let result = council.run_round(/* uses claude, falls to codex */).await;
    assert!(wal.contains_event(0x3E));  // PROVIDER_QUOTA_EXCEEDED
    assert!(result.used_provider == "codex-cli");
}

#[test]
fn test_daily_budget_exhausted_suppresses() {
    // Setup: 5 council debates already today
    state.set_debates_today(5);
    let result = council.should_trigger(/* otherwise-valid trigger */);
    assert!(!result);
    assert!(wal.contains_event(0x3F));  // COUNCIL_BUDGET_EXHAUSTED
}

#[test]
fn test_smart_trigger_complexity_gate() {
    // High complexity (1500 token user msg + 8000 token bundle) + keyword + dissent
    let msg = generate_long_security_question(1500);
    state.set_dissent_score(0.5);
    let result = council.should_trigger(msg);
    assert!(result, "All gates passed — should trigger");
}
```

---

## 8. Status

**v1.1 council governance BUILD-READY.** H5 (quota exhaustion) resolved with:
- Smart trigger (keyword + complexity + dissent + rate gates) → 80% reduction in council load
- HTTP 429 fallback cascade with per-provider quota tracking
- Operator-visible quota + budget telemetry
- Hard caps prevent silent quota drain
