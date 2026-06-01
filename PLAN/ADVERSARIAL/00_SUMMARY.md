# Adversarial Review Synthesis — NEOTH v1.0

> **Reference document.** Captures analysis or synthesis at a specific point in time.
> The normative current state lives in `00_DESIGN_v1.1_FINAL.md` plus the `SPEC_*.md`
> files. Use this for context; not build instructions.

10 parallel agents × 3 rounds adversarial each. Files in this directory.

## Show-Stoppers (fix before any Day-1 code)

| # | Finding | Source | Spec to fix |
|---|---------|--------|------------|
| **S1** | **`ts_ns` vs `Hlc` byte-layout contradiction in 2 normative specs** — `SPEC_wire_header_v2_slim.md §3` says `ts_ns: u64` at bytes 29-36 + `_reserved: [u8; 7]`. `SPEC_multinode_clock.md §4` says `Hlc` at offset 37 = 12 bytes. **`static_assert(size==96)` fails on Day-1 compile.** Fix: shrink `_reserved` to `[u8; 3]`. | 03 type-design | SPEC_wire_header_v2_slim.md + SPEC_multinode_clock.md |
| S2 | **HLC `hlc_tick_receive` branch 2 bug** — sets `logical = current.logical + 1`, discards `peer.logical`. Will produce causality violations in Phase 3 multi-node gossip. Fix: `logical = max(current.logical, peer.logical) + 1`. | 04 architecture | SPEC_multinode_clock.md |
| S3 | **`PermissionToken<T>` is a phantom type** — referenced in SPEC_skill_plugin_system.md §10 as compile-time enforcement, NEVER defined anywhere. Vault security claim is theater. | 03 type-design | SPEC_skill_plugin_system.md |
| S4 | **`hemisphere: u8` vs `originator: u8` name+meaning drift** — 2 specs say different field names AND different meaning for value 4 (BOTH vs COUNCIL). Misrouting. | 03 type-design | SPEC_wire_header_v2_slim.md + 00_DESIGN_v0.8 |
| S5 | **WAL `.cpt` crash-recovery has no authentication** — pre-place crafted `.cpt` file with valid CRC32c (non-crypto), full WAL history rewrite on next restart. | 01 security | SPEC_wal_lifecycle.md |
| S6 | **WAL mmap active segment writable by same-user processes** — `MmapMut` allows overwrite of `importance = 0.0f32` at any event's header offset → silent erasure on next compaction. | 01 security | SPEC_wal_lifecycle.md |
| S7 | **MmapMut ≠ fsync** — `MmapMut::flush()` calls `msync(MS_SYNC)`. On XFS nobarrier (NVMe default), no drive cache flush barrier. Power loss between flush+platter write drops WAL frames silently — no CRC detection (frames absent, not corrupt). | 09 hot-paths | SPEC_wal_lifecycle.md |
| S8 | **`repr(C, packed)` UB on every multi-byte field access** — invisible on x86, SIGBUS on aarch64, blocks `cargo miri test`. `bytemuck` incompatible. | 09 hot-paths | SPEC_wire_header_v2_slim.md |
| S9 | **HLC `.expect()` in async task** — peer gossip with `logical = u32::MAX` panics the tokio task. Single-packet remote DoS. | 01 security + 09 hot-paths | SPEC_multinode_clock.md |
| S10 | **GitHub PAT `ghp_OVViPfYc6Y...` still in `~/.openclaw-git-mirror/.git/config` on Jarvis VM** — acknowledged since v0.5, not revoked. Exploitability: 5. | 01 security | operator action |

## High-Severity (fix before Phase 1 demo)

| # | Finding | Source |
|---|---------|--------|
| H1 | **Profile-extraction prompt injection** — Telegram paste of Reddit comment containing prompt-injection passes `profile.validate` (schema-valid), enters `idx_profile` with `require_approval=false`, Hebbian-amplifies to 0.95 confidence, poisons every Block-B injection forever. Self-amplifying via reinforcement. | 01 sec, 06 abuse |
| H2 | **PROFILE_REDACT re-promotion** — `neoth profile redact identity.location` removes from `idx_profile` but `profile.apply` consults only current state, not redaction history. Next "Berlin" mention reborn with no memory of deletion. | 06 abuse |
| H3 | **Profile-extraction-via-Gemini = privacy hole in 2 cloud providers** — `freedom.yaml profile.learn.health=false` prevents NEOTH storing health, but doesn't prevent sending health-containing conversation to Gemini API for analysis. Privacy table "Profile to outbound providers: Never" is technically true, operationally false. | 04 arch, 05 cost, 10 comparative |
| H4 | **Time-dependent confidence + static `idx_profile` incompatible** — Hebbian decay 0.995/day means same WAL produces different `idx_profile` over time. Lazy on-read recomputation = latency on every Block-B assembly (critical path of every LLM call). | 02 silent, 04 arch |
| H5 | **`council.should_trigger` keyword "security" exhausts quota by 14:00** — for a security-researcher operator this word appears constantly. 25-35% trigger rate × 9 LLM calls/council × 3 providers in parallel. Spec has zero handling for HTTP 429 quota exhaustion (only refusal). Profile-extraction silently dark for the rest of day. | 05 cost |
| H6 | **`council_test1_unfalsifiable`** — `factual_contradiction_check` fires on hemisphere disagreement. Unanimous wrong = no disagreement = tool silent = test passes with NEOTH shipping wrong answer. Test as-specified cannot work. | 07 eval |
| H7 | **Grader-family bias** — Claude grades Claude, Gemini grades Gemini, Codex grades Codex. All share stylistic priors. High kappa + shared upward bias = confidently wrong evaluation. | 07 eval |
| H8 | **Mirror-refusal feedback loop** — every refusal triggers mirror pipeline → operator engages positively → "operator values limitation-reflection" climbs in profile → Block-B primes Left toward hedged responses → more refusals → death spiral. | 06 abuse |
| H9 | **Skill template semantic injection** — `SkillSandboxViolation` checks template functions, not template text. Keyword-conditional injected instruction passes `test_render` with benign input, activates when relevant topic appears. Code sandbox ≠ semantic sandbox. | 06 abuse |
| H10 | **Channel-Ingress dedup-bloom false-positive** — legit user message dropped (bloom always has FP at scale), no error returned, user sees silence. | 02 silent |

## Architectural Gaps (decide before Phase 2)

| # | Finding | Source |
|---|---------|--------|
| A1 | **No local generative model for extraction** — must lock `model:` abstraction in pipeline YAML in Phase 1. Retrofit = pipeline schema change + new inference runtime. Operator's Cube has 3 GPUs. Qwen3-4B INT4 fits ~3GB. | 04 arch |
| A2 | **No `send_proactive()` on Channel trait** — reserve method signature now. Trait-lock without this = breaking change to all adapters when proactive output added. Kumpel-brand requires this. | 04 arch |
| A3 | **No `PROFILE_BASELINE_SNAPSHOT` event** — must be emitted at Phase 3 Day 65 seed migration. Miss that window = no drift comparison possible Phase 4. One event type (0x37), importance=1.0, never compacted. | 04 arch |
| A4 | **Custom WAL is reimplementing SQLite/fjall** — importance-weighted GC is the ONLY thing justifying custom. Could be a SQLite trigger. Saves ~2000 LOC + months of WAL correctness work. | 04 arch |
| A5 | **VEC0 + O(N) cosine without HNSW** — fine for MVP, blows up beyond 50K events. Qdrant embedded or sqlite-vec eliminates custom VEC0 + crash recovery + shard format. | 04 arch |

## Schedule Reality (planner's verdict)

| Phase | Claimed | Realistic | Delta |
|-------|---------|-----------|-------|
| Phase 1 MVP | Day 30 | **Day 60** | +30d |
| Phase 2 | Day 60 | **Day 150-180** | +90-120d |
| Phase 3 cutover | Day 90 | **Day 210-240** | +120-150d |
| Phase 4 start | Day 91+ | **Day 240+** | +150d |

**Single biggest schedule risk:** Day 14 (candle + Qwen3 GGUF) slipping 3-4 days. Cascades Day 15→16→17→24→29→30 (7-node critical path, no slack). **Day 30 MVP structurally impossible if Day 14 slips.**

## Cost Reality

- **Subscriptions:** $320/month floor (Claude MAX $100 + ChatGPT Pro $200 + Gemini Premium $20). No circuit breaker, regardless of usage.
- **API overage on quota walls:** $0-272/month additional.
- **Operator-hours:** 900-1,050 hours total build = **€72k-€135k opportunity cost** at researcher rate.
- **RAM lock:** 1 GB Tailslayer hugepages permanent.

## Cross-Cutting Themes (5 most damaging)

1. **Privacy theater**: local redaction controls (idx_profile zero-fill, PROFILE_REDACT, freedom.yaml gates) are technically correct but operationally moot because profile.extract sends source conversations to Gemini cloud API permanently. **Must decide local-extraction Phase 1 or document as known trade-off.**

2. **Specs contradict each other**: `ts_ns` vs `Hlc` byte layout (S1), `hemisphere` vs `originator` field name+meaning (S4), `PermissionToken<T>` referenced but undefined (S3). Day-1 compile fails on S1.

3. **Profile-self-amplification loops**: H1 (prompt injection), H2 (REDACT re-promotion), H8 (mirror-refusal feedback). Each creates a self-reinforcing drift cycle no audit catches. Spec lacks "ProfileClaimGuard" between extract and apply.

4. **Eval is theater**: council_test1 cannot work (H6), grader-family bias unaddressed (H7), no prompt-injection eval corpus, parity ≥0.85 anchors against Jarvis with no validated absolute baseline.

5. **Schedule is fantasy**: realistic Day-30 = Day-60. Phase 2 90-120d not 30d. Day 14 candle integration is sole show-stopper. Solo-dev velocity 60-70% theoretical assumed-100%.

## One Change That Addresses Most Risks

**`ProfileClaimGuard` Rust struct between `profile_extract` output and WAL write** (~300 LOC, non-LLM): 
- Normalizes timestamps before LLM sees them (M1 protection — timestamp hallucination)
- Routes novel categories to typed extension registry (not `other: Vec<String>`)
- Maintains redaction registry — PROFILE_REDACT blocks re-promotion of same key
- Generates behavioral-style embedding per turn (parity-scoring substrate)
- Global LLM-call count cap before council fires (cost-spiral prevention)

Combined with **local Qwen3-4B for extraction** (decision A1) eliminates the privacy theater + the largest class of cost/operator-abuse failures.

## Files in this directory

```
00_SUMMARY.md                       ← this file
01_security_attack_surface.md       ← 30 attack vectors, 10 severity-ranked
02_silent_failures.md               ← 19 failure modes, top-7 ranked
03_type_design_holes.md             ← 15 type holes, 8 refactors, top-5 ranked
04_architecture_alternatives.md     ← 8 decisions challenged, 5 missing features
05_cost_reality.md                  ← $320-600/month, 900-1050 operator-hours
06_operator_abuse.md                ← 5 self-pwn vectors, prompt-injection priority
07_eval_methodology.md              ← 5 eval gaps, single regression_anchor test
08_schedule_reality.md              ← Day-by-day realistic vs claimed, +30 to +150d
09_implementation_hotpaths.md       ← 8 hot-paths, Mmap/UB/HLC fixes, WalWriterTask
10_comparative_product.md           ← 5 failure modes from peer products, ProfileClaimGuard
```

## Recommendation to operator

**Do NOT start coding Day 1 against v1.0 as written.** At minimum fix:
1. S1 (ts_ns/Hlc byte contradiction) — 30 min spec edit
2. S2 (HLC tick_receive bug) — 1 line code change in future implementation, spec correction now
3. S3 (define PermissionToken<T>) — 4 hours spec + sample code
4. S5/S6/S7 (WAL .cpt auth + MmapMut writability + msync vs fsync) — SPEC_wal_lifecycle.md amendment
5. S8 (drop repr(C,packed), parse [u8;96] explicitly) — SPEC_wire_header_v2_slim.md amendment
6. A1 + A2 (local model + send_proactive) — Phase 1 architectural lock

**Time to v1.1 with all S-class fixed: 1-2 days of spec editing.**

Then start Day 1.
