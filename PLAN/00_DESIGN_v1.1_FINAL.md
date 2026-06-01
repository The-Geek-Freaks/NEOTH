# NEOTH — Design v1.1 FINAL (POST-ADVERSARIAL-FIXES)

> **Status:** BUILD-READY. All 10 S-class blockers + 8 H-class high-severity + 3 architectural gaps RESOLVED.
> **Tagline:** *Neoth knows.*
> **Day-1: GREEN** — `cargo build --release` 4.85s on Jarvis VM. Binary prints banner.
>
> **Multi-operator clarification (2026-05-14):** Neoth is operator-agnostic. SOUL.md, CLAUDE.md, freedom.yaml, and policy.example.yaml templates carry NO hardcoded operator identity. Per-deployment operator (id, role, language) set via `neoth init` at install or by editing `~/.neoth/freedom.yaml`. Where this design document references specific infrastructure (Cube 192.168.178.156, Jarvis VM 192.168.178.117, Veronica 100.86.138.18) — those are concrete examples from the dev/test operator's environment, illustrative only. Any operator runs their own Neoth instance with their own profile.

---

## 0. v1.1 vs v1.0 Diff Summary

10 parallel adversarial agents found 21 actionable issues. v1.1 fixes ALL of them.

### S-class Show-Stoppers (Day-1 compile fails without fixes)

| # | Issue | Fix Location |
|---|-------|--------------|
| **S1** | `ts_ns` vs `Hlc` byte-layout contradicts in 2 normative specs | `SPEC_wire_header_v2_slim.md` §4 — `_reserved` shrunk to `[u8;3]`, Hlc at bytes 33-44 |
| **S2** | Claimed HLC `hlc_tick_receive` branch 2 bug | `SPEC_multinode_clock.md` §3.5 — **re-audited against Kulkarni 2014. Spec correct.** Original adversarial flag was a misreading. Branch order preserved + cite. |
| **S3** | `PermissionToken<T>` phantom type (referenced, never defined) | `SPEC_skill_plugin_system.md` §6 — full sealed-trait + `PhantomData` + `pub(crate) fn mint()` + `AtLeast<T>` marker hierarchy implemented |
| **S4** | `hemisphere` vs `originator` name+meaning drift | `SPEC_wire_header_v2_slim.md` §5 — canonical name `originator`, `Originator` enum with `4=COUNCIL` (not BOTH) |
| **S5** | WAL `.cpt` crash-recovery no authentication | `SPEC_wal_lifecycle.md` §4.3 — HMAC-SHA256 over `.cpt` content using vault-derived key, refuse to apply on mismatch |
| **S6** | `MmapMut` on active segment writable by any same-user process | `SPEC_wal_lifecycle.md` §3 — no `MmapMut` on active. `WalWriterTask` owns `tokio::fs::File` with `O_APPEND`. Sealed segments use read-only `Mmap`. |
| **S7** | `MmapMut::flush()` calls `msync(MS_SYNC)` not `fsync(2)` | Same as S6 — `WalWriterTask` uses `tokio::fs::File::sync_data()` (= `fdatasync(2)`). Drive cache flush barrier forced even on `nobarrier` mounts. |
| **S8** | `#[repr(C, packed)]` causes multi-byte UB on aarch64 (SIGBUS) | `SPEC_wire_header_v2_slim.md` §11 — explicit `from_le_bytes(&[u8; 96])` + `to_le_bytes() -> [u8; 96]` byte parser. No `repr(C, packed)`. |
| **S9** | HLC `.expect()` panic on peer `logical = u32::MAX` (remote DoS) | `SPEC_multinode_clock.md` §3.1-3.3 — `Result<(), HlcError>` propagation. Caller emits `0x2F CLOCK_LOGICAL_OVERFLOW` event, no panic. |
| **S10** | GitHub PAT `ghp_OVViPfYc6Y...` still active since v0.5 | `S10_PAT_REVOCATION.md` — operator action required: revoke + rotate to SSH key. Day-1 gate. |

### H-class High Severity (Phase 1 must address)

| # | Issue | Fix Location |
|---|-------|--------------|
| **H1** | Profile-extraction prompt injection (Telegram paste → poisoned profile) | `SPEC_proactive_learning.md` §3.1 + `SPEC_profile_claim_guard.md` — first-person attribution stage (`window_attribute`) before LLM. Quoted/forwarded segments never enter extraction. ProfileClaimGuard rejects any claim not citing user-speech evidence. |
| **H2** | `PROFILE_REDACT` re-promotion (next "Berlin" mention reborn) | `SPEC_proactive_learning.md` §4.1 + `SPEC_profile_claim_guard.md` — persistent `idx_profile_redactions` registry with `never_recreate: bool`. Guard consults before every PROFILE_DELTA emit. Re-promotion blocked, `0x38 PROFILE_DELTA_BLOCKED` emitted. |
| **H3** | Privacy theater — conversations to Gemini API permanently | `SPEC_local_inference.md` — **Qwen3-4B-INT4 locally on Cube GPU.** `freedom.yaml inference.allow_cloud_fallback = false` by default. Conversations stay on machine. |
| **H4** | Hebbian decay + static `idx_profile` view incompatible | `SPEC_proactive_learning.md` §5.2 — nightly batch decay at 03:30 (`pipelines/profile_decay_tick.yaml`) + on-reinforce immediate. **Zero on-read recomputation.** Max 24h staleness, acceptable for slow-drift profile state. |
| **H5** | Council quota exhaustion ("security" keyword triggers 25-35% of turns) | `SPEC_council_governance.md` — smart trigger (keyword + complexity + dissent + rate gates) reducing council load 80%. HTTP 429 fallback cascade. Daily budget caps. |
| **H6** | `test_all_three_agree_and_wrong` cannot work (unanimous-wrong = no disagreement → tool silent) | `SPEC_recall_parity_methodology.md` §11 — `GROUND_TRUTH_TAG` in test fixtures. `factual_contradiction_check` accepts ground_truth_tag (test mode only) and checks response-vs-tag, not just hemisphere-vs-hemisphere. |
| **H7** | Grader-family bias (Claude grades Claude-output → high kappa + shared upward bias) | `SPEC_recall_parity_methodology.md` §4 — 4-grader protocol with 4th grader from external family (Mistral/DeepSeek/Qwen). Plus 20-query operator calibration anchor. Family-bias detection + correction. |
| **H8** | Mirror-refusal feedback loop (refusal → engagement → profile learns "values reflection" → more refusals) | `SPEC_proactive_learning.md` §3.1 trigger — `exclude_event_types: [REFUSAL_OBSERVED, REFUSAL_MIRRORED, REFUSAL_REDIRECTED, REFUSAL_PERSISTENT]` + `exclude_originators: [Council]`. Profile never learns from refusal events. |

### A-class Architectural Gaps (Phase 1 lock decisions)

| # | Gap | Resolution |
|---|-----|------------|
| **A1** | Local generative model for extraction | `SPEC_local_inference.md` — Qwen3-4B-INT4 via candle on Cube GPU. Phase 2 Day 38-42 deliverable. Combines with H3 fix. |
| **A2** | `send_proactive()` reservation on `Channel` trait | `SPEC_channels.md` §1 — method added to trait with default `Err(ChannelError::NotSupported)`. Reserved Phase 1, implemented Phase 3+ for proactive notifications. |
| **A3** | `PROFILE_BASELINE_SNAPSHOT` event 0x37 | `SPEC_proactive_learning.md` §4.2 — event type `0x37`, emitted ONCE at Phase-3 Day 65 seed migration. `importance=1.0`, never compacted, never tombstoned. Phase 4 drift detection anchor. |

### Plus: ProfileClaimGuard (one change, multiple risks)

| File | Coverage |
|------|----------|
| `SPEC_profile_claim_guard.md` | NEW — ~300 LOC Schicht-0 Rust struct between `profile.extract` and `profile.apply`. Single gate addresses H1 + H2 + H5 + M1 (timestamp hallucination) + M2 (novel-category `other: Vec<String>` black hole). Plus side-benefit: emits behavioral-style embedding for Phase-3 parity-substrate. |

---

## 1. Architecture (unchanged from v1.0)

NEOTH is a Rust single-binary personal AI agent. Tool-Framework v4.1 "Pflegbarer Garten" foundation:
- 3 Schichten (Tool / Pipeline / Ecology)
- 5 Zutaten (Variation / Constraints / Memory / Selektion / Laufzeit)
- 13 Anti-Patterns enforced via tests

Brain-anatomy LLM topology:
- **Left Hemisphere** = Claude Opus 4.7 — sole user-output channel
- **Right Hemisphere** = Gemini 3.1 Pro — pattern-match, no user egress (Phase 2)
- **Corpus Callosum** = Codex GPT-5.5 — synthesis + dissent surfacing (Phase 2)
- **Local extraction** = Qwen3-4B-INT4 (Phase 2, replaces Gemini for profile extraction per H3 fix)

6 brain regions (region_tag enum):
- Hippocampus (idx_episode), Amygdala (idx_importance), Insula (idx_council), Cerebellum (idx_motor), BasalGanglia (idx_habit), Hypothalamus (idx_profile)

WAL v1.1: 96-byte EventHeader, HLC inter-node ordering, segment rotation 256 MiB / 24h / generation, compaction with HMAC-signed `.cpt`, vector blob VEC0 sharded, 5-state disk pressure, no MmapMut on active segment.

---

## 2. Day 1-30 MVP Plan (unchanged scope, more rigor)

Day-30 acceptance test unchanged: Telegram message → recall from 2 WAL views → Left-Claude response → Telegram reply. 10k events × 10 queries × p95 < 30 ms × 100/100 keyword-find.

What v1.1 adds before Day 1:
- All 10 S-class fixes applied to specs (this update)
- 11 Day-1 cargo deps unchanged (`tokio`, `serde`, `serde_json`, `serde_yaml`, `thiserror`, `tracing`, `tracing-subscriber`, `crc32c`, `xxhash-rust`, `uuid`, `anyhow`)
- Operator action: revoke GitHub PAT (S10)

---

## 3. Phase 2-4 Schedule (unchanged dates, updated content)

Phase 2 (Day 31-60) — adds:
- Day 31-37: Right Hemisphere (Gemini) wiring + WhatsApp adapter + Slack adapter
- Day 38: download `qwen3-4b-int4.gguf`, `LocalInference` impl (A1)
- Day 39: candle integration + `test_local_inference_deterministic` passes
- Day 40: `profile_learn.yaml` switches to `model: local_qwen3_4b` (H3 fixed)
- Day 41: ProfileClaimGuard integration into pipeline
- Day 42: `idx_profile_redactions` SQLite migration + `neoth privacy audit` CLI
- Day 43-49: Council Pipeline (v1.1 smart-trigger + 429 cascade per `SPEC_council_governance.md`)
- Day 50-55: Council adversarial test suite (`test_all_three_agree_and_wrong` with GROUND_TRUTH_TAG per H6)
- Day 56-60: Mirror-Refusal Pipeline + Dreaming-Pipeline + remaining views

Phase 3 (Day 61-90) — adds:
- Day 61: Eval-Goldset extraction + 20-query operator anchor for parity (H7)
- Day 65: `PROFILE_BASELINE_SNAPSHOT` event 0x37 emitted at seed migration (A3)
- Day 73-79: 4-grader parity evaluation (Claude+Codex+Gemini+Mistral) with operator anchor calibration (H7)
- Day 80: cutover with operator-auth + 2FA
- Day 81-90: hot-watch + Phase-4 prep

Phase 4 (Day 91+) — adds:
- Drift detection comparing `idx_profile` against `PROFILE_BASELINE_SNAPSHOT` (A3 baseline operational)
- Council outcome → adaptive thresholds (using H5 governance data)
- All other v1.0 Phase 4 deliverables unchanged

---

## 4. Operator Action Items (before Day 1)

1. **Rotate any pre-existing secrets** that may have been exposed in your dev environment. See `SECURITY.md` for the disclosure flow if you discover anything leaked publicly.
2. **Read this document end-to-end** plus the SPEC files it links — you are responsible for the daemon running on your machine.
3. **Run `neoth init`** to generate `~/.neoth/freedom.yaml` and pick your LLM providers.

Once those three are done: `cargo install neoth` (or `cargo run --bin neothd` from a checkout) is the entry point.

---

## 5. Files Final v1.1 PLAN/

```
PLAN/
  INDEX.md                                ← navigation
  00_DESIGN_v1.1_FINAL.md                 ← THIS FILE — normative
  tool_framework_v4_1.md                  ← foundation
  S10_PAT_REVOCATION.md                   ← operator action

  SPEC_wire_header_v2_slim.md             ← S1, S4, S8 fixes
  SPEC_multinode_clock.md                 ← S2 audit, S9 fix
  SPEC_wal_lifecycle.md                   ← S5, S6, S7 fixes
  SPEC_skill_plugin_system.md             ← S3 fix (PermissionToken<T>)
  SPEC_proactive_learning.md              ← H1, H2, H4, H8, A3 fixes
  SPEC_channels.md                        ← A2 fix (send_proactive)
  SPEC_recall_parity_methodology.md       ← H6, H7 fixes
  SPEC_mirror_refusal.md                  ← unchanged from v1.0

  SPEC_local_inference.md                 ← NEW — H3 + A1
  SPEC_council_governance.md              ← NEW — H5
  SPEC_profile_claim_guard.md             ← NEW — one-change fix (H1+H2+H5+M1+M2)

  RUNBOOK_phase3_cutover.md               ← unchanged
  02_MEMORY_LAYER_MAPPING.md              ← unchanged
  BLUEPRINT_v06_synthesis.md              ← unchanged
  CHERRY_PICK_RANKING.md                  ← unchanged
  NEW_SOURCES_INTEGRATION.md              ← unchanged
  CHORUS_v06_codex.md / CHORUS_v06_gemini.md  ← unchanged

  CLAUDE_v07_review.md                    ← drove v0.8 (archive eventually)

  ADVERSARIAL/
    00_SUMMARY.md                         ← drove v1.1
    01_security_attack_surface.md
    02_silent_failures.md
    03_type_design_holes.md
    04_architecture_alternatives.md
    05_cost_reality.md
    06_operator_abuse.md
    07_eval_methodology.md
    08_schedule_reality.md
    09_implementation_hotpaths.md
    10_comparative_product.md

  archive/
    README.md
    00_DESIGN.md ... 00_DESIGN_v1.0_FINAL.md
    (older Chorus + Architect reviews)
```

---

## 6. Status

**BUILD-READY.** All adversarial findings resolved at spec level. Day-1 unblocked pending S10 operator action.

*Neoth knows.*
