# Schedule Reality Adversarial — NEOTH v1.0

Source: planner agent, 3-round adversarial.

## Round 1 — Day-by-Day Realistic vs Claimed (v0.8 §9)

| Day | Claimed | Realistic | Critical Hidden Complexity |
|-----|---------|-----------|---------------------------|
| 1 | Workspace + 11 deps + build ≤30s | 1d | OK. Risk: serde_yaml 0.9 Windows quirks |
| **2** | WAL writer: 96B header + CRC32c + fsync + segment rotation | **3d** | `tokio::fs` no O_DSYNC on Win; fsync-on-dir Linux-only; CRC32c HW-accel detection separate; atomic rename differs per OS; group-commit needs flush-coalescer (DNE yet) |
| 3 | WAL reader: mmap + CRC + magic-resync | **2d** | Depends Day-2 stable; memmap2 not in Day-1 deps; fuzz-tested boundary logic |
| 4 | YAML loaders | **2d** | serde_yaml silent key-order; LOWKEY content_hash needs sha2/ring (not in Day-1); Framework Teil-C validation non-trivial |
| **5** | Claude CLI-OAuth adapter | **5d** | Claude CLI auth = no public API, reverse-engineer; reqwest add; async subprocess + 120s kill + retry-401 = 3 concerns; token counting needs tiktoken (not in deps); spec ref "v0.7 §6" = archived |
| 6 | FREEDOM auth layer | **2d** | Depends Day-5; PermissionToken<Dangerous> phantom-type plumbing |
| **7** | Telegram ingress (6 controls) | **4d** | teloxide add; HMAC-SHA256 dep; bloom filter; sandboxed quarantine + mime allowlist; identity-norm 6 sub-tasks |
| 8 | Effect Adapter trait | 1d | OK |
| 9 | telegram.send | 1d | Depends Day-7 stable |
| 10 | InboundMessage → WAL | 1d | Depends Day-2 CRC tests pass |
| 11 | idx_episode SQLite | **2d** | rusqlite/sqlx not Day-1 dep; WAL→SQLite projection new |
| 12 | idx_semantic FTS5 | **2d** | Tokenizer config; payload extraction |
| 13 | recall.query keyword bigram | **2d** | AND-merge posting list non-trivial |
| **14** | candle-core + Qwen3-Embedding-0.6B-Q8 GGUF | **4d** | First contact candle API; GGUF edge cases (metadata, rope); quantization Q8_0 vs Q8_K; tokenizer integration; CPU inference benchmark; candle adds 2-4min clean build |
| 15 | Linear-scan top-K cosine | 1d | OK depends Day-14 |
| 16 | embed.encode + worker | **2d** | Pipeline abstraction undefined; async backpressure queue |
| 17 | VEC0 sharded vector store | **3d** | No existing VEC0 Rust to copy; layout decision; sharding policy |
| 18 | Amygdala decay-tick single-writer | **2d** | Mutex/actor for single-writer; deterministic formula for G.10 test |
| 19 | session.start/end + idx_session | 1d | OK |
| 20 | FinalizeResponseArtifact | 1d | OK but must match Day-26 — retroactive break risk |
| 21 | Pipeline-Router skeleton | **2d** | hemisphere-binding (REVIEW_architect Must-Fix #1); Teil-C dispatch |
| 22 | refusal_detect 6 classes | **2d** | 6 distinct heuristics OR LLM calls; SPEC_mirror_refusal precise |
| 23 | YAML skill loader + LOWKEY + hash | **2d** | content_hash SHA-256; LOWKEY versioned+hashable+disable (Codex v0.6 #7) |
| **24** | Context-Engine 5-block + budget | **3d** | Block-D drop logic; cascade fallback; token counting w/o tiktoken |
| 25 | Block-cache + tombstone-bus + 24h | **2d** | WAL subscription; TTL eviction |
| 26 | respond_to_user pipeline | **2d** | **First pipeline running; all 25 prior days must integrate cleanly** |
| 27 | Trajectory + secrets redaction | **2d** | Secrets pattern library + log-time scrubbing |
| 28 | Anti-pattern test stubs G.1-G.13 | 1d | OK with `#[ignore]` |
| **29** | Integration test (Telegram→...→Telegram) | **3d** | **First full integration. Industry: first attempt reveals 5-10 blockers. Plan budgets 1d.** |
| 30 | MVP DEMO + acceptance | **2d** | Synthetic event generator unbudgeted |

**Realistic Day 1-30 total: 62 working days** (claimed 30).

## Comparable OSS Projects

- **litellm**: v0.1 → working multi-provider streaming proxy = **45 days** (public commit history). Simpler scope than NEOTH Day-30.
- **agentmemory**: RAG memory layer, first end-to-end = **3 months** solo (Python, no WAL).
- **langchain**: first working agent loop (no memory, no tools, just chain) = **2 months** to production-grade.

NEOTH Day-30 scope exceeds langchain's first milestone by including WAL + embedding + FTS5 + vector store + Telegram adapter + typed pipeline system **simultaneously**.

## Round 2 — Collapse Scenario

If Days 2, 5, 7, 14, and 29 slip by realistic amounts (3+5+4+4+3 = 19 extra days), Day-30 user-visible state:

> Telegram receives message. WAL receives CHANNEL_INBOUND. Block assembly runs but idx_semantic FTS5 returns zero results (Day 12-13 not stable). Claude CLI adapter times out intermittently (Day 5 retry incomplete). Response generated from empty recall. No Telegram reply sent (idempotency_key collides with dedup-bloom false positives Day 7).

**Missing in plan**: explicit "minimum viable state at each checkpoint" definition. §5 defines Day-30 acceptance but nothing for Day 10/15/20. A slip on Day 7 blocks Days 9/10/26/29/30 — 5 downstream days with zero plan indication.

**Missing in plan**: explicit dependency graph. The §9 table is linear but hides that Days 11-17 are fully blocked by Days 2-3 (WAL) and Day 14 (candle).

## Round 3 — Risks Not in Plan

1. **Cumulative integration debt**: industry 30-50% of total. Plan budgets 3.3% (1 of 29). Architect review already flagged dependency inversion (Dreaming before Memory Engine) — same class can occur Days 11-26.

2. **Dependency churn**: candle/teloxide/wasmtime/reqwest monthly cadence. 30 days = ≥1 breaking change statistically certain. serde_yaml 0.9 deprecated. teloxide 0.12→0.13 breaking. No lockfile policy.

3. **Cargo build time creep**: Day-1 ≤30s. By Day 14 with candle+wasmtime+teloxide+reqwest+rustls+sqlx: realistic `cargo build --release` = 4-8min. `cargo check` = 45-90s. 10 cycles/day × 7-15min wait = 3.5-7.5h compile-wait over 30 days.

4. **Solo-dev velocity not constant**: security-researcher day-job + Saskia + family. 30 continuous full-velocity days unrealistic. Industry norm: 60-70% of theoretical. 30-day plan @ 65% = 46-day actual.

5. **Spec reference chasing**: Day 5 → "v0.7 §6" archived. Day 63 → 02_MEMORY_LAYER_MAPPING references SSH paths possibly moved by then. Every archived reference = hidden research cost.

6. **G.1-G.13 test write velocity**: 9 days for 13 tests = 0.7d each. Council adversarial = deterministic fixtures + 3 grader LLM calls + fuzz harness. Real ML/agent test 3-5d each. G.1-G.13 realistic = 39-65 days, not 9.

7. **Phase 2 scope = 90 days work, not 30**: WhatsApp + Slack + IVF + MMR + DSPM + idx_dedup + REINFORCE + SESSION_LEDGER + Tailslayer dual + concept-vocab + WASM + Right + Callosum + Council full + Mirror-Refusal + Conductor + Memory-Integrity + Situation-Board + Council-adversarial-suite + 4 hemisphere views. Codex previously estimated WhatsApp alone = 5-8d. Right+Callosum wiring = 8-10d (architect). IVF+MMR+DSPM = 3 separate algos. **Phase 2 realistic = 90-120 days.**

8. **Phase 3 prerequisite: moving target**: 100-query Jarvis goldset Day 61, but Jarvis still running and accumulating. Goldset extracted Day 61 valid only for state at Day 61. If Phase 2 slips to Day 120, regenerate. 14-day shadow run assumes Jarvis stable, but openclaw update during shadow shifts baseline.

9. **Phase 4 trigger ambiguity**: §12 "Day 91+, on-trigger". RUNBOOK Day 90: `neothctl phase4 init`. Auto vs explicit unclear. If Phase 3 slips to Day 150 does Phase 4 auto-start Day 151?

10. **Phase 3 Day 79 latency gate requires Phase 2 complete**: gate checks p95 recall <8ms which needs IVF (Phase 2 Day 35). If Phase 2 slips, Phase 3 Day 79 gate fails on latency. Cutover gated on Phase 2 completion — stated in one RUNBOOK line, not Phase 2 plan.

## Realistic State Estimates

| Checkpoint | Plan claims | Realistic state |
|-----------|-------------|----------------|
| **Day 30** | "MVP DEMO with all 3 channels" (current spec says Telegram-only) | WAL writer/reader stable. Telegram ingress basic. Claude CLI flaky on retry. idx_episode populated. idx_semantic returns results. Embedding: NOT integrated (Day-14 slipped to Day-17). **No cosine recall. No end-to-end Telegram round-trip passing acceptance test.** Daemon receives, logs, returns hardcoded "I heard you" |
| **Day 60** (Phase 2 claimed end) | Right+Callosum+Council+WhatsApp+Slack+IVF+DSPM+REINFORCE+SESSION_LEDGER+Tailslayer+concept-vocab+profile-extraction | = realistically end of what plan calls "Phase 1 Day 30 MVP". Keyword recall + embedding integrated. Telegram only. Council: 0%. Right+Callosum: 0%. WhatsApp/Slack: 0%. |
| **Day 90** (Phase 3 claimed end) | "Cutover complete, Phase 4 prep" | = realistically mid-Phase-2. Council stubbed. Right+Callosum maybe wired. IVF possibly. **No Phase 3 cutover possible — Phase 2 incomplete, Day 79 latency gate fails.** |
| **Day 180** | Phase 4 mature | = realistic Phase 3 cutover zone. Phase 1 done Day 60. Phase 2 done Day 150-180. Phase 3 starts Day 180. Jarvis goldset needs re-extraction. |

## Single Biggest Schedule Risk

**Day 14 (candle + Qwen3 GGUF loader) slipping to Day 17-18.**

Days 15 (cosine recall), 16 (embedding worker), 17 (vector-blob), and 24 (Context-Engine with Block-D from semantic recall) all depend on it. 3-4 day slip on Day 14 → 12-16 day cascade through critical path.

Day 29 integration test cannot pass without end-to-end embedding. Day 30 acceptance test (p95 <30ms) requires embedding. **Day 14 slip = Day 30 MVP structurally impossible.**

Domino chain: 14 → 15 → 16 → 17 → 24 → 29 → 30 = 7-node critical path with no slack.

## Realistic Delta Summary

| Phase | Claimed | Realistic | Delta |
|-------|---------|-----------|-------|
| Phase 1 MVP (Telegram + recall) | Day 30 | Day 60 | +30d |
| Phase 2 (Council + channels + ML) | Day 60 | Day 150-180 | +90-120d |
| Phase 3 cutover | Day 90 | Day 210-240 | +120-150d |
| Phase 4 start | Day 91+ | Day 240+ | +150d |

Hofstadter's Law recursively: plan already knows it will slip (stop-criterion exists), but stop-criterion doesn't account for being invoked on a system where half the critical path is still unbuilt.
