# ADR-004 — R-02 Phase 3 embedding model selection

**Status**: Accepted (2026-05-29 Session 28c — the `embed()` surface that
gated this decision is shipped: `providers/embed.rs` defines the
`EmbedProvider` trait + `l2_normalize`/`cosine`; `providers/local_qwen.rs`
ships `ensure_embed_loaded` + `run_embed` (mean-pool across the sequence
dim, then L2-normalise) + `impl EmbedProvider for LocalQwenAdapter::embed`
with an L2-norm contract assertion + tests. The `[[neoth-d14b-status-correction]]`
"Qwen path is stubbed" note is itself now stale. HO-04 stub registered
2026-05-27 Session 28).

## Context

R-02 Phase 3 dream-composition needs embeddings to cluster the
operator's episodes by theme. Two candidate models surfaced in the
Session 21 architect-panel discussion:

1. **Qwen3-Q8 (4B local)** — runs entirely on the operator's device
   via the candle-rs forward-pass already shipping for local
   inference. ~3 GB model file + ~5 GB peak VRAM/RAM during embed.
   Embedding dim 4096.
2. **BGE-small-en (33M local)** — much smaller (~130 MB),
   English-only out of the box, ~512 dim embeddings. The de-facto
   small-embedding baseline cited by every retrieval benchmark in
   late 2026-Q2.

The choice affects:
- AIO cross-platform invariant: both ship in-binary (model files
  bundled or first-run-downloaded headlessly). Qwen3-Q8 adds ~3 GB
  to the wizard's bandwidth ask; BGE-small adds ~130 MB.
- Privacy: both are local, so neither sends episode text to a
  cloud API. The privacy story is equivalent.
- Multilingual: Alex's operator profile mixes German + English
  freely. Qwen3 handles both natively; BGE-small-en is English-only
  (operator would see degraded clustering on German episodes
  without a multilingual swap-in like BGE-M3).
- Compute: Qwen3-Q8 embed at ~50 episodes/sec on CPU; BGE-small at
  ~500/sec on CPU. For a typical day's 100-500 episodes the
  difference is 2-10 seconds vs <1 second per nightly pass.
- Dim size: 4096-dim embeddings cost more in clustering compute +
  vector storage (whether mmap'd flat array or future tailslayer
  ReplicatedBuffer per [[neoth-d101-d102-d103-verdicts]] D-103
  follow-on).

## Decision

**Accepted — Qwen3-Q8 (local) as the default + primary embedding model.**
The `embed()` surface this decision gated on is now shipped (see Status),
so the decision is ratified rather than pending. Three downstreams can now
consume it: skill-router Stage-2, council dissent, R-02 dreaming — that
consumer wiring is tracked under SPEC-12 (v0.9), not this ADR.

The accepted shape per architect-panel direction:

- **Default + primary:** Qwen3-Q8. Multilingual + same model
  family as the chat path → no second model to download + manage.
  Operator's bandwidth ask is "one model file" rather than
  "chat model + embed model".
- **Fallback opt-in:** BGE-M3 (the multilingual sibling of
  BGE-small) for operators on memory-constrained devices where
  Qwen3-Q8 won't fit. `freedom.yaml::embed.model = "bge_m3"`.
- **English-only operators (none currently — Alex is bilingual)**
  could opt into BGE-small-en for speed, but no default operator
  profile justifies this branch.

This pairs with the Day-14b open work: once the `qwen2_embed.rs`
fork lands (per [[neoth-d14b-status-correction]]), the embed surface
exists + this ADR can flip to Accepted.

## Consequences

**Positive (Qwen3-Q8 default)**
- One model file to download + cache + auto-update — matches the
  AIO cross-platform invariant + the operator-never-opens-npm-or-
  hf rule.
- German + English clustering both work without a multilingual
  swap-in.
- Same forward-pass + sampling-loop infra serves chat + embed —
  one acceleration backend (CUDA / Metal / OpenVINO / CPU per the
  Day-14b accelerator-detect) to maintain.

**Negative**
- Operator bandwidth ask is large (~3 GB) — the wizard step needs
  to flag this clearly + offer download-resume.
- VRAM/RAM peak during embed (~5 GB) excludes operators on
  ≤8 GB systems; the BGE-M3 fallback covers this.
- Higher per-episode compute cost vs BGE-small means the nightly
  cron (if opted-in per [[ADR-003]]) takes ~10 seconds on a
  500-episode day instead of <1 second. Negligible operator
  impact for an opt-in nightly pass.

**Operator-facing**
- Default install: Qwen3-Q8 fetched at first `neoth dream now`
  invocation (or first cron tick if opted-in).
- Toggle: `freedom.yaml::embed.model = "qwen3_q8" | "bge_m3"` +
  GUI settings parity. Wizard step explains the trade-off.

## Alternatives considered

- **BGE-small-en as default** — rejected because Alex's profile is
  bilingual; English-only embeddings would degrade German episode
  clustering without operator-visible warning.
- **Cloud embedding (OpenAI text-embedding-3-small etc.)** —
  rejected outright. R-02 Phase 3 privacy is explicitly local-only
  per [[ADR-005]] and the no-ambient-cloud-default policy.

## Open questions

- First-run download UX: how does the wizard surface "we need
  3 GB for the embed model" without scaring the operator? Probably
  a wizard step toggle gated to dream-now opt-in.
- Auto-update cadence: model file hash check on every dream pass
  vs weekly cron. Probably hash-check-on-pass (zero ambient
  background download), align with the auto-update memory
  ([[neoth-arch-extensions]]).

## References

- Memory: [[neoth-d14b-status-correction]] — embed() surface is
  the gating implementation work.
- Memory: [[neoth-d101-d102-d103-verdicts]] — D-103 wasmtime +
  forward-pass baseline.
- Memory: [[open-decisions-verdicts]] — Session 21 ratification
  list (R-02 Phase 3 model remained "operator pick").
- `PLAN/HANDOFF_2026-05-22.md` §"Operator decisions pending" #3.
- `PLAN/PROGRESS_v1_0.md` SPEC-12 (R-02 Phase 3 implementation).
- HO-04 stub set: [[ADR-002]] / [[ADR-003]] / **[[ADR-004]]** /
  [[ADR-005]].
