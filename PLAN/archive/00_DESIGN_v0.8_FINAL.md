# AGENTER — Design v0.8 FINAL (BUILD-READY)

> **Status:** Locked. Addresses ALL 11 Claude v0.7 review points (3 sofort-aktionen + 8 sub-issues).
> **Wire format:** `wal_format_version = 2`, `event_schema_version = 4`. Header slim 96 B.
> **MVP:** Day-30 Telegram-only (recall=Keyword+Top-K cosine, no DSPM/REINFORCE/SESSION_LEDGER). WhatsApp/Slack/WASM → Phase 2.
> **Sub-specs (normative, all in PLAN/):**
> - `SPEC_wire_header_v2_slim.md` — 96 B header byte-by-byte
> - `SPEC_wal_lifecycle.md` — rotation, compaction, vector-blob, disk-full, compression
> - `SPEC_multinode_clock.md` — HLC for inter-node ordering
> - `RUNBOOK_phase3_cutover.md` — Day 61-90 tag-genau
> - `SPEC_recall_parity_methodology.md` — 3-grader Cohens-Kappa
> - `SPEC_channels.md` — channel adapters
> - `SPEC_mirror_refusal.md` — refusal pipeline
> - `SPEC_skill_plugin_system.md` — Skill + Plugin
> - `tool_framework_v4_1.md` — foundation

---

## 0. Diff vs v0.7 (11 Claude review fixes)

### Sofort-Aktionen vor Day 1 (all done in v0.8)

| # | Fix | Where |
|---|-----|-------|
| **SA1** | Header 215 B → 96 B. Moved to payload: prompt_bundle_hash, parent/supersedes_event_id, content/embedding/source_uri_hash, chunk_*, embedding_model/dim/blob_off, source_mtime, brain_region, hemisphere | `SPEC_wire_header_v2_slim.md` |
| **SA2** | WAL-Lifecycle Section. Segment rotation 256 MiB / 24h / generation, compaction 30% tombstone trigger, tombstone reaper 30d grace, vector-blob VEC0 sharded, disk-full 5-state (Normal/Warning70/NoNewRaw80/ReadOnly90/RefuseStart95), zstd_3 compression for compacted segments | `SPEC_wal_lifecycle.md` |
| **SA3** | Phase-3 Cutover-Runbook Tag-Level Day 61-90. Operator-Auth + Yubikey/TOTP, Snapshot, Webhook-Switch, Hot-Watch, Rollback (30 min ETA, same 2FA), all logged as WAL 0x2A/0x2B/0x2C/0x2D | `RUNBOOK_phase3_cutover.md` |

### Sub-Issues fixed in v0.8

| # | Issue v0.7 | Fix v0.8 |
|---|------------|----------|
| 1 | Brain-region enum inkonsistent (5 enforced, FREEDOM events trägt brain_region=None) | **Decision: degrade to Index-Tag.** Renamed field: `region_tag: u8` (not `brain_region`). 0=None, 1-5=Hippocampus/Amygdala/Insula/Cerebellum/BasalGanglia. FREEDOM events use `region_tag=0`. Tag is for ROUTING (which index gets the event), not for metaphor. See §1 |
| 2 | Council adversarial tests fehlen | Added `SPEC_council_adversarial.md` outline + 7 test types in §6 |
| 3 | Token-Budget per Block A-E fehlt | §3: explicit `max_prompt_tokens` per Hemisphere + per Block. Hard-fail at limit |
| 4 | Compression-Politik unklar | `SPEC_wal_lifecycle.md` §8: hot-segments uncompressed (mmap), warm/cold zstd_3, vector-blobs never compressed |
| 5 | Day-30 recall claim unscharf | §5: explicit "Day-30 recall = Keyword-match + Top-K cosine (linear scan, no IVF), no DSPM/REINFORCE/SESSION_LEDGER (those Day-32-37)" |
| 6 | Replay-Window clock-skew-naiv | HLC adopted (`SPEC_multinode_clock.md`). Inter-node = HLC-ordered. Channel-ingress = wall-clock ±300s for human-time |
| 7 | Recall-Parity 0.85 ohne Methodik | `SPEC_recall_parity_methodology.md`: 3-grader (Claude+Codex+Gemini), 5-dim rubric, Cohens-Kappa ≥ 0.6, harmonic-mean weighted aggregate |
| 8 | Phase-3 = "Cutover" 1 Wort | `RUNBOOK_phase3_cutover.md` Day-für-Tag |

---

## 1. region_tag (renamed from brain_region)

Claude review #2 was right. `brain_region` carried metaphor weight. The actual function is: tag events with which write-index they belong to. Renamed.

```rust
#[repr(u8)]
pub enum RegionTag {
    None         = 0,
    Hippocampus  = 1,   // episodic (idx_episode)
    Amygdala     = 2,   // importance (idx_importance, single-writer)
    Insula       = 3,   // council state (idx_council)
    Cerebellum   = 4,   // provider stats (idx_motor, single-writer)
    BasalGanglia = 5,   // tool-router cache (idx_habit)
}
```

**Invariants per tag** (enforced at WAL ingress):
- `Hippocampus` events: must have `category=episodic` in payload schema.
- `Amygdala` events: must carry `importance_score: f32` + `decay_policy: DecayPolicy` in payload.
- `Insula` events: must carry `council_round_id: u64`.
- `Cerebellum` events: must carry `provider_id: u8` + `latency_ns: u64`.
- `BasalGanglia` events: must carry `tool_id: TyplyHash16` + `frequency_delta: i32`.

WAL writer rejects events with mismatched payload (`MalformedRegionEvent` error).

**Hemisphere field renamed too:** `hemisphere: u8` → `originator: u8`. Same enum (0=N/A, 1=LEFT, 2=RIGHT, 3=CALLOSUM, 4=COUNCIL). Reflects "who produced this event" rather than anatomical claim.

Both fields now live in payload (per SA1), not header.

---

## 2. Locked Decisions (Q1-Q8 + N1-N14, finalized)

Unchanged from v0.7 except:

| # | v0.7 | v0.8 |
|---|------|------|
| MVP cutoff | Day 30 (Telegram-only) | Day 30 (Telegram-only, recall=Keyword+Top-K cosine linear-scan ONLY) |
| Brain regions | 5 enforced | 5 enforced + renamed to `region_tag` (functional, not metaphor) |
| WAL header | 215 B | 96 B (SA1) |
| WAL lifecycle | unspecified | full spec (SA2) |
| Phase 3 | 6 bullets | day-for-day runbook (SA3) |
| Inter-node clock | wall-clock + node_id | HLC (Hybrid Logical Clock) |
| Recall-Parity method | "≥ 0.85" | 3-grader Cohens-Kappa, harmonic-mean weighted |
| Compression | unspecified | hot=raw, warm/cold=zstd_3, vector-blobs=never-compressed |
| Token-Budget | unspecified | per-Block + per-Hemisphere hard caps (§3) |
| Council tests | "G.5/G.10 enforcement" | + 7 adversarial test types (§6) |

---

## 3. Token Budget per Block (NEW v0.8)

Block-Layer assembly (5 blocks A-E from v0.6, plus optional Conductor blocks):

| Block | Default cap (tokens) | Hard limit |
|-------|---------------------|------------|
| A — Tools schema | 4000 | 8000 |
| B — System+SOUL+LOWKEY+freedom_scope | 1500 | 3000 |
| C — Stable recall (Hippocampus-Core + idx_importance≥0.75) | 2500 | 5000 |
| D — Volatile recall (session-local + hybrid query) | 3000 | 6000 |
| E — User message + attachments | 4000 | 8000 |
| **Optional: Conductor.product** | 800 | 1500 |
| **Optional: Conductor.spec** | 1500 | 3000 |
| **Optional: Conductor.plan** | 1500 | 3000 |
| **TOTAL default** | 14000 | — |
| **TOTAL max (with Conductor)** | 17800 | — |

**Per-Hemisphere max_prompt_tokens:**
- Left (Claude Opus 4.7): 180,000 (model context limit ~200k, leave 20k headroom for response)
- Right (Gemini 3.1 Pro): 900,000 (huge context, Conductor-loaded heavy)
- Callosum (Codex GPT-5.5): 380,000

**Enforcement:** Context-Engine assembly emits `prompt_token_estimate` for the bundle. If > hemisphere max → emit `BUDGET_EXCEEDED` event 0x2F, fall back to: (a) drop Block-D oldest 50%, (b) if still over → drop Block-C lowest-importance 50%, (c) if still over → drop Conductor.plan, then .spec. Block-A/B/E never cut.

**Cost-control:** every PROVIDER_REQUEST event carries `prompt_token_estimate` + `prompt_token_actual` (after provider response). Cerebellum (`idx_motor`) tracks rolling per-provider cost.

---

## 4. EventHeader v0.8 96-byte layout (per SPEC_wire_header_v2_slim.md)

```
Offset  Size  Field                      Type           Endian   Why in header
─────────────────────────────────────────────────────────────────────────────
0       4     magic                      [u8; 4]        —        Resync after corruption: scan for b"AGNT"
4       1     wal_format_version         u8             —        Reader picks parser version
5       1     event_schema_version       u8             —        Reader picks payload schema
6       1     event_type                 u8             —        Routing without payload parse
7       1     event_subtype              u8             —        Sub-routing
8       2     header_len                 u16            LE       Length of this header (96 in v0.8)
10      2     reserved_len               u16            LE       Future-proof: bytes between header and payload
12      4     total_len                  u32            LE       Frame total bytes (magic..CRC inclusive)
16      4     payload_len                u32            LE       For mmap-skip without parsing
20      4     generation                 u32            LE       Writer-generation, increments per daemon restart
24      8     event_id                   u64            LE       Unique within node
32      12    hlc { ns:u64, logical:u32 }Hlc            LE       Inter-node causal ordering (replaces ts_ns)
44      4     flags                      u32            LE       TOMBSTONE/SUPERSEDED/SYNTHETIC/REDACTED/STREAM_PARTIAL
48      4     scope                      u32            LE       USER/WORLD/RELATIONSHIP/EPISODIC/SESSION/COMMONS
52      4     category                   u32            LE       facts/todo/knowledge/episode/auth/...
56      4     importance                 f32            LE       For recall pre-filter without payload parse
60      1     region_tag                 u8             —        Routing: which write-index this event hits
61      1     originator                 u8             —        Source hemisphere/COUNCIL
62      2     _reserved                  [u8;2]         —        Pad to 64
64      16    session_id                 [u8;16]        —        Session-scope routing
80      16    node_id                    [u8;16]        —        Multi-node origin
─────────────────────────────────────────────────────────────────────────────
96      —     PAYLOAD (variable, payload_len bytes)
96+P    —     reserved (reserved_len bytes, future use, 0 in v0.8)
T-4     4     crc32c                     u32            LE       Over magic..reserved
```

`T` = `total_len`. CRC32c covers everything from `magic` through `reserved` block.

**Wire-Format vs Rust-Struct:** the table above is the canonical wire format. The Rust `EventHeader` struct may use `#[repr(C, packed)]` or use serde with explicit byte-order, but the **wire format is authoritative**. Never dump a Rust struct directly to disk without explicit serialize-step.

**Payload schema for event_schema_version=4:** tagged enum prefix (1 byte tag, then variant fields). All moved-from-header fields live here. Schema documented in `SPEC_wire_header_v2_slim.md` §3.

---

## 5. Day-30 Recall Scope (explicit per Claude review #10)

**Day-30 MVP recall = Keyword-match + Top-K cosine linear-scan.**

What's INCLUDED Day 30:
- `idx_episode` view (Hippocampus, time-sorted)
- `idx_semantic` view (FTS5 on event payload text)
- Keyword bigram → posting list → AND-merge → top-N candidates
- Candidate set (≤ 10k events) → linear-scan cosine (no IVF)
- Top-5 by cosine score returned to Context-Engine

What's EXCLUDED Day 30:
- IVF-vector-index (Day 35)
- DSPM utility-scoring formula (Day 36)
- idx_dedup + REINFORCE event handling (Day 37)
- SESSION_LEDGER cross-session continuity (Day 38, Phase 2)
- MMR diversity re-ranking (Day 40)
- Tailslayer dual-replica (Day 41)
- Concept-vocabulary tagger (Day 42)
- Memory contradiction-triage (Day 50)

**Day-30 acceptance test:** insert 10,000 synthetic events, query with 10 mixed-keyword queries, p95 recall latency < 30 ms (vs <8 ms full-stack target). Returns top-5 events with cosine scores. Correctness measured: for each query, ≥ 1 of top-5 contains expected keyword. Pass = 100/100 queries.

---

## 6. Council Adversarial Test Suite (NEW v0.8)

Claude review #6: Council is the biggest black box. Anti-pattern tests G.5/G.10 not enough. Added.

`tests/council_adversarial.rs` — 7 test types, runs Day 50-55 (Phase 2):

1. **test_all_three_agree_and_wrong**: feed Council a prompt with known-incorrect "majority view" (synthetic test fixture). All 3 hemispheres trained or prompted to converge on wrong answer. Expected: dissent-detector catches via factual_contradiction_check tool (deterministic). Fails if Council ships wrong answer.

2. **test_emergent_divergence_explosion**: feed prompt that causes hemispheres to legitimately disagree. Council enters debate. Test: rounds stop at `agreement_threshold` OR `rounds_max`, NEVER loop forever. Fails if `rounds_executed > rounds_max`.

3. **test_left_dominates_right_unfairly**: Left hemisphere always confident. Right keeps flagging. Test: Callosum surfaces Right's dissent in `CouncilVerdict.dissent_log`, not silently filtered. Fails if dissent_log is empty when Right ≠ Left.

4. **test_callosum_self_destructs**: Callosum returns malformed CouncilVerdict (empty, invalid JSON, schema-violation). Test: Pipeline falls back to Left+Right unanimous OR aborts to mirror_refusal. Fails if malformed CouncilVerdict passes downstream.

5. **test_fuzz_input_against_council**: 1000 random prompts (10 categories × 100 each). Verify: no panic, no infinite loop, all complete within 60s. Output goes to `eval/council_fuzz/`.

6. **test_token_budget_exhaustion**: prompt-bundle approaches per-hemisphere max_prompt_tokens. Verify Context-Engine cuts Block-D oldest first, never Block-A/B/E. Emit `BUDGET_EXCEEDED` 0x2F. Fails if any Block-A/B/E content dropped.

7. **test_prompt_bundle_replay_determinism**: re-run same `prompt_bundle_hash` through Council with deterministic seed. Verify byte-identical CouncilVerdict (modulo timestamps). Fails if non-deterministic divergence.

**Divergence metrics:**
- `divergence_score(L, R, C)` = pairwise semantic distance via factual_contradiction_check tool + word-overlap Jaccard.
- Tracked in `idx_council` view per round.
- Aggregated daily via Phase-4 Ecology.

**Sub-spec scaffold:** `SPEC_council_adversarial.md` Day-50 deliverable. Stub file created Day-1 with skeleton.

---

## 7. Compression Policy (NEW v0.8, per SPEC_wal_lifecycle.md §8)

Locked:
- **Hot segments** (current + last 8 mmap'd): uncompressed. Zero-copy mmap reads. ≤ 256 MiB each.
- **Warm segments** (8 < age < 30 days): compressed zstd level 3. Decompressed on-demand to OS page cache.
- **Cold segments** (≥ 30 days, Phase 4): zstd level 9, optionally moved to S3-compatible object storage.
- **Vector-blobs**: NEVER compressed. Random-access required for top-K cosine.
- **Index files** (idx_episode, idx_semantic, ...): never compressed. Page-cache hot.

Compression-effect estimate at 10M events:
- Raw events.bin: ~50 GB (5 KB avg/event)
- Hot kept: last 8 segments × 256 MiB = 2 GB uncompressed
- Warm zstd_3: ~12 GB (60% reduction)
- Cold zstd_9 (S3): ~8 GB further reduction
- Vector blobs: 1024d × 4B = 4 KB/embed × 5M embeds = 20 GB (uncompressed, no choice)

---

## 8. Hybrid Logical Clock Integration (per SPEC_multinode_clock.md)

EventHeader v0.8 ships HLC from Day 1 (cannot retrofit). Cost: +4 bytes vs `ts_ns: u64` → already counted in 96 B header.

Phase 1 (single-node): HLC degenerates to monotonic wall-clock + counter. No correctness penalty.
Phase 3+ (multi-node): HLC orders events across Veronica + Jarvis-AGENTER + future nodes. Clock-skew up to 60s tolerated; > 60s emits `CLOCK_SKEW_DETECTED` 0x2E for operator inspection.

Causal ordering rule: for events e1, e2: `e1.happened_before(e2) ⟺ e1.hlc < e2.hlc` per HLC's < operator. Recall queries return causally-ordered results.

---

## 9. Revised Day 1-30 Plan (lean MVP)

| Day | Deliverable | Spec ref |
|-----|-------------|----------|
| 1 | cargo workspace (9 deps: tokio, serde, tracing, tracing-subscriber, thiserror, crc32c, xxhash-rust, uuid, anyhow). SOUL+CLAUDE+BOOT.md mounted Block-B | `00_DESIGN_v0.8_FINAL.md` §12 |
| 2 | WAL segment writer (96B header, magic+CRC32c, fsync group-commit, segment rotation logic) | `SPEC_wire_header_v2_slim.md` + `SPEC_wal_lifecycle.md` |
| 3 | WAL segment reader (mmap iterate, CRC validate, magic-resync, payload-schema parse) | same |
| 4 | YAML loaders (tool spec B.5, pipeline spec C.1, freedom.yaml, LOWKEY skill v1 with content_hash) | Framework v4.1 |
| 5 | Claude CLI-OAuth adapter (Left Hemisphere, 120s stream-kill, prompt_bundle_hash logged) | v0.7 §6 |
| 6 | FREEDOM authorization layer, permission-token Rust types | v0.7 §6 |
| 7 | Telegram ingress (sig-verify, replay ±300s, dedup-bloom, rate-limit, attachment-quarantine, identity-norm) | v0.7 §4 + `SPEC_channels.md` |
| 8 | Effect Adapter base trait (idempotency_key, max_retries, audit-event, backoff) | v0.7 §13 |
| 9 | telegram.send Effect Adapter | same |
| 10 | InboundMessage → WAL CHANNEL_INBOUND event (0x24), region_tag=None (channels aren't region-tagged) | wire-spec |
| 11 | idx_episode view (Hippocampus, time-sorted append) | wire-spec + Framework |
| 12 | idx_semantic view (FTS5 on payload text via sqlite) | same |
| 13 | recall.query Schicht-0 tool (keyword bigram → AND-merge → posting list) | Framework B.5 |
| 14 | candle-core + Qwen3-Embedding-0.6B-Q8 GGUF loader (deferred from Day-1) | v0.6 |
| 15 | Linear-scan top-K cosine recall (no IVF yet, ≤ 10k candidate set) | §5 |
| 16 | embed.encode Schicht-0 tool, embedding-worker pipeline | Framework + v0.7 |
| 17 | Vector-blob VEC0 writer + sharded store | `SPEC_wal_lifecycle.md` |
| 18 | Importance-decay tick (Amygdala writer, ≥ 0.75 promotion gate) | v0.7 §6 |
| 19 | session.start/end + idx_session view | v0.7 |
| 20 | FinalizeResponseArtifact typed struct + builder | v0.7 §5 |
| 21 | Pipeline-Router skeleton (Schicht-1 dispatcher, hemisphere-binding enforce) | Framework C.1 |
| 22 | refusal_detect Schicht-0 tool (6 classes per SPEC_mirror_refusal.md) | spec |
| 23 | YAML skill loader (LOWKEY base stack auto-inject, content_hash verify) | `SPEC_skill_plugin_system.md` |
| 24 | Context-Engine 5-block assembler + token-budget enforcement | §3 |
| 25 | Block-cache (tombstone-bus-flush + 24h ceiling) | v0.5 |
| 26 | respond_to_user.yaml pipeline + finalize_response stage | v0.7 |
| 27 | Trajectory tracing + secrets redaction (logging) | v0.6 |
| 28 | Anti-pattern enforcement tests (G.1-G.13 stubs, Day-37 full pass) | v0.7 §11 |
| 29 | Integration test: Telegram → WAL → Block-assembly → Claude CLI → Telegram | full stack |
| 30 | **MVP DEMO**: Telegram message → recall from idx_episode+idx_semantic → Left-Claude response (with LOWKEY base + freedom-scope skills) → Telegram reply. Day-30 acceptance test (§5) passes. | hard commit |

**Stop-Criterion Day 30:** If Day-30 acceptance test fails (p95 recall < 30 ms on 10k events, 100/100 keyword-find, end-to-end Telegram round-trip), invoke architect-agent review, identify slip-day, defer non-blocking to Day 31+.

---

## 10. Phase 2 Day 31-60

Adds:
- WhatsApp adapter (Meta Cloud API via reqwest)
- Slack adapter (socket mode)
- IVF-vector-index, MMR re-ranking
- DSPM utility-scoring formula
- idx_dedup + REINFORCE
- SESSION_LEDGER cross-session resume
- Tailslayer dual-replica (with mmap fallback)
- Concept-vocabulary tagger
- wasmtime Plugin Host (needle opt-in plugin)
- Right Hemisphere (Gemini) + Callosum (Codex) wired
- Council debate pipeline (rounds 2-10)
- Mirror-Refusal Pipeline full
- Conductor 3-layer-context
- Memory-Integrity pipeline (contradiction-triage, fact-registry)
- Situation Board live-config reader
- Council adversarial test suite full (§6, Day 50-55)
- 4 hemisphere views populated (idx_motor, idx_habit, idx_insula, idx_session_ledger)

## 11. Phase 3 Day 61-90

Per `RUNBOOK_phase3_cutover.md`:
- Day 61-65: Migration prep, dry-run, re-embed pipeline
- Day 66-72: Shadow-Run setup, 14d parallel
- Day 73-79: Goldset eval (100 × 3 graders × Cohens-Kappa), decision gate Day 79
- Day 80: CUTOVER (operator-auth + Yubikey/TOTP, snapshot, webhook-switch, hot-watch)
- Day 81-86: Post-cutover hot-watch
- Day 87-90: Stabilize + Phase 4 prep

Rollback ETA 30 min with same 2FA. All cutover/rollback events logged 0x2A/0x2B/0x2C/0x2D.

## 12. Phase 4 Day 91+ (Ecology, on-trigger)

Read-only Ecology-Schicht (Framework G.11):
- Tool-Genealogy + version tracking
- Memory-drift detection
- Council-outcome → adaptive thresholds
- Self-Improvement loop (ACTIVE_MUTATIONS, ERL)
- MemPalace Hebbian-Graph (per Jarvis-Audit finding: nodes=3602 tunnels=205 — NOT spatial rooms)
- Cold-segment tiering (S3 object storage)

---

## 13. Day-1 Cargo Deps (minimal, per Claude review non-blocker)

```toml
[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "fs", "io-util", "net", "sync", "signal", "time"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
thiserror = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
crc32c = "0.6"
xxhash-rust = { version = "0.8", features = ["xxh3"] }
uuid = { version = "1", features = ["v4", "v7"] }
anyhow = "1"
```

**NOT in Day-1:** `ring`, `rustls`, `hyper`, `reqwest`, `teloxide`, `candle-core`, `candle-transformers`, `wasmtime`, `memmap2`. Each added when slice needs it (Days 5, 7, 14, 23, etc per §9).

`cargo build --release` Day-1 target: ≤ 30s on dev workstation.

---

## 14. Anti-Pattern Enforcement Tests (Day 28 stubs, Day-37 full)

Each Framework G.1-G.13 anti-pattern gets a deterministic test. From v0.7 §11, expanded:

```
tests/anti_pattern/
├── g01_stateful_tool.rs           — Run tool 100x with same input, verify identical output
├── g02_self_modifying.rs          — Hash all tool YAMLs at startup, verify unchanged at shutdown
├── g03_goal_seeking_tool.rs       — Tool YAML scan for "goal:" field, must reject
├── g04_meta_decision_tool.rs      — Tool YAML scan for "invoke_pipeline" field, must reject
├── g05_emergent_composition.rs    — Pipeline YAML scan for inline `trigger:` outside `conditions:`, must reject
├── g06_refusal_umgehung.rs        — Inject refusal, verify mirror_refusal pipeline triggered, no provider cascade
├── g07_scope_inflation.rs         — Tool YAML scan: `category` field must be single value, not list
├── g08_starke_emergenz.rs         — same as g01 + ASLR variance test
├── g09_blackbox.rs                — Tool YAML must have `introspection:` block with ≥1 hook
├── g10_magic_scale.rs             — Council `agreement_score` formula deterministic for fixed inputs
├── g11_closed_loop_ecology.rs     — Ecology pipelines can only emit `read` events to Schicht-0/1
├── g12_level_confusion.rs         — Schicht-0 tool YAML must NOT have `effect_adapter: true`
├── g13_bateson_iii.rs             — Scan SOUL+CLAUDE+all skill YAMLs for "autonomous identity" claims, reject
```

Day-28 = stubs (all tests return PASS with `#[ignore]` for now). Day-37 = real implementations. Phase-2 = all 13 must pass before any Council code merged.

---

## 15. Status

v0.8 is build-ready. All Claude v0.7 review points addressed. Day-1 starts immediately.

**Action items:**
1. Archive v0.7 to `PLAN/archive/`.
2. Update `PLAN/INDEX.md` to point to v0.8.
3. Operator decision: `cargo new agenterd` Day-1.
