# ADR-007 — chat_turn_pipeline module boundary

- **Status:** Accepted (2026-06-08, Session 45)
- **Relates to:** GOLD plan `PLAN/ROAD_TO_1_0_GOLD.md`; operator directive 2026-06-08

## Context

`cli/chat.rs::run_chat_with` (lines 128–1981, ~1853 executable lines within the function) is the CLI's per-turn entry point. It mirrors the channel-side pipeline that was just decomposed by GOLD-ARCH-01 (`refactor(serve): extract the inbound pipeline into cli/serve_pipeline`, commit `11bf9d4`). The serve decomposition moved `build_pipeline_handler` and its captured helpers into `cli/serve_pipeline.rs` (1865 LOC), leaving `cli/serve.rs` at 3388 LOC.

`cli/chat.rs` is 5692 LOC today. `run_chat_with` alone spans lines 128–1981 and executes at least 14 distinct phases, all inlined as comment-banners within a single async fn:

- line 164: `resolve_prompt` (extracted helper, called by value)
- line 269: RAW_TEXT WAL write (inlined)
- line 316–413: `PROVIDER_REQUEST` WAL write + `enforce_budget` pre-flight (inlined; `crate::tokens::budget::enforce_budget` called at line 380)
- line 436–570: skill registry load + ARCH-07 pinned-hash gate (inlined)
- line 609–708: mode/skill routing + Stage-2 embedding re-rank (inlined)
- line 711–737: MCP catalogue assembly (inlined)
- line 762–778: `pipeline::build_enriched_request` call (extracted — pure helper in `pipeline/enriched_request.rs`)
- line 780–842: autonomy gate / cost preview (inlined)
- line 844–866: provider quota pre-flight (inlined)
- line 931–978: TOML hook stages PrePipeline + PreProviderCall (helper `run_hook_stage` at line 2009)
- line 980–1439: provider dispatch — stream/council/MCP-loop/single branches (inlined; `dispatch_council_with_recovery` at line 3343, `run_mcp_dispatch_loop` at line 3719 are extracted but called inline)
- line 1487–1506: PostProviderCall hook (calls extracted `run_hook_stage`)
- line 1508–1530: PROVIDER_RESPONSE WAL write (inlined)
- line 1532–1687: refusal detect + recovery (inlined logic; `security::refusal_detect` / `security::refusal_recovery::try_recover_multi` called inline)
- line 1689–1721: ADR extraction (inlined)
- line 1704–1721: SESSION_ARCHIVE (inlined)
- line 1723–1909: profile pipeline post-reply (inlined, 186 LOC)
- line 1911–1961: two-stage review gate (inlined)
- line 1963–1976: hindsight card save (inlined)

The parallel precedent is clear: `cli/serve.rs` was growing the same way (`cli/serve_pipeline.rs` extracted the handler). `cli/chat.rs` has no corresponding extraction yet. Every new chat-turn feature (GOLD-WIRE-*, HON-*, COR-*) added since Session 1 has been inlined directly into `run_chat_with` because there is no declared boundary to land in. GOLD-ARCH-02 in `PLAN/ROAD_TO_1_0_GOLD.md` line 334 names the execution task, but does not yet constitute an architectural decision record — it is a backlog ticket, not a stable boundary contract that forces new code to comply.

The `pipeline/mod.rs` already holds one extracted primitive (`build_enriched_request`), with its doc comment explicitly stating what does NOT live there (provider call execution, WAL framing). That commentary is the closest existing module-boundary statement for the chat path; it is insufficient to guide new-feature placement.

## Decision

A future module `cli/chat_turn_pipeline.rs` is declared as the canonical home for all per-turn pipeline logic that is currently inlined in `run_chat_with` (`cli/chat.rs:128–1981`). The split mirrors the GOLD-ARCH-01 decomposition of `cli/serve.rs` into `cli/serve_pipeline.rs`.

The target module boundary defines four named phase functions:

1. **`build_prompt_bundle`** — everything from prompt resolution through skill routing, MCP catalogue assembly, `pipeline::build_enriched_request`, and the token-budget pre-flight. Corresponds to the inlined blocks at `cli/chat.rs:164–778`. Inputs: `ChatArgs`, `FreedomConfig`, `&dyn Provider` (for embedding provider). Output: a `PromptBundle` struct carrying `prompt`, `combined_system`, `prompt_bundle_hash`, `prompt_token_estimate`, `used_skill_id`, `skill_tool_allowlist`.

2. **`enforce_preflight`** — the autonomy gate, cost-preview WAL emit, and provider quota check. Corresponds to `cli/chat.rs:780–866`. Inputs: `PromptBundle`, `FreedomConfig`, `&dyn Provider`, `&WalWriterHandle`. Output: `Result<()>` (bails on denial; writes `COST_ESTIMATE_SHOWN` and checks `QuotaTracker`).

3. **`dispatch_provider`** — TOML hook stages, the stream/council/MCP-loop/single-provider dispatch tree, and the PostProviderCall hook. Corresponds to `cli/chat.rs:931–1506`. Inputs: assembled `Request`, `FreedomConfig`, `&dyn Provider`, `&WalWriterHandle`. Output: `(response_text: String, input_tokens: Option<u32>, output_tokens: Option<u32>, model_used: String)`. The already-extracted helpers `dispatch_council_with_recovery` (`cli/chat.rs:3343`) and `run_mcp_dispatch_loop` (`cli/chat.rs:3719`) remain in `cli/chat.rs` (or move together) — they are already named functions and do not violate this rule.

4. **`run_post_reply_pipelines`** — the ordered post-reply sequence: PROVIDER_RESPONSE WAL write, refusal detection + recovery, ADR extraction, SESSION_ARCHIVE, profile pipeline, two-stage review gate, hindsight card save. Corresponds to `cli/chat.rs:1508–1976`. Inputs: `response_text`, `PromptBundle` (for prompt/hash/ids), `FreedomConfig`, `&dyn Provider` (for recovery retries), `&WalWriterHandle`. Output: `Result<String>` (final `response_text` after any mutation by recovery).

**Enforcement rule:** Any new per-turn logic added to the chat path MUST be placed inside one of these four named phase functions (or a named sub-helper it calls), never inlined directly into `run_chat_with`. `run_chat_with` SHALL remain a sequencing shell: WAL writer init → `build_prompt_bundle` → `enforce_preflight` → `dispatch_provider` → `run_post_reply_pipelines` → WAL writer teardown.

The extraction itself (moving the bodies into `cli/chat_turn_pipeline.rs`) is deferred to GOLD-ARCH-02 (`PLAN/ROAD_TO_1_0_GOLD.md:334`). This ADR does not require that refactor today; it records the module boundary so the constraint is machine-checkable from the date of acceptance.

## Consequences

**Positive:**
- New features (GOLD-WIRE-*, HON-*, COR-* additions) have a forced landing zone. A reviewer can reject a PR that inlines into `run_chat_with` rather than into a named phase function, without needing to re-read 1800 lines of context.
- The four phase functions correspond 1-to-1 with the unit-test contract stated in GOLD-ARCH-02: each phase function takes typed inputs and returns typed outputs, making isolated test harnesses possible without mocking the full provider chain.
- The `PromptBundle` output type of `build_prompt_bundle` makes the current implicit coupling between prompt construction and audit framing explicit — the hash and token estimate computed in phase 1 flow into phases 2–4 by value, not via shared mutable state.
- Mirrors the GOLD-ARCH-01 precedent exactly, so contributors already familiar with `cli/serve_pipeline.rs` can orient in `cli/chat_turn_pipeline.rs` without a new mental model.

**Negative / revisit triggers:**
- The four-phase split is slightly coarser than the 14 comment-banner sections currently in `run_chat_with`. Some sub-steps (e.g. the conversational-recall short-circuit at line 303, the coding-intent auto-dispatch at line 194) happen before the WAL writer is even spawned, so they logically precede `build_prompt_bundle`. If a fifth pre-WAL phase (e.g. `route_early_exits`) is warranted, this ADR should be amended.
- Until GOLD-ARCH-02 executes the extraction, the constraint is advisory and enforced only at review time. CI will not reject a direct inline until a lint or architecture test is added.
- The `PromptBundle` intermediate type does not yet exist. Its shape is defined here conceptually; the real struct must be designed when GOLD-ARCH-02 runs. If the fields diverge significantly from what is listed here, this ADR should be updated.

**Operator-facing:** no behaviour change. This is a code organisation decision; the runtime pipeline sequence and all WAL events remain identical.

## Alternatives considered

- **Do nothing / let GOLD-ARCH-02 define the boundary when it executes.** Rejected: GOLD-ARCH-02 is a backlog refactor ticket, not an architectural contract. Without a recorded decision, every new feature author defaults to inlining into `run_chat_with`, which is exactly the accumulation pattern that made `cli/serve.rs` unreadable before GOLD-ARCH-01.

- **Extract immediately (do the refactor in this ADR's PR).** Rejected: the operator's explicit requirement is to record the decision and set the boundary without performing the refactor now. The GOLD-ARCH-02 task carries the execution work. Conflating ADR authorship with execution would make the boundary record conditional on the refactor being correct on the first attempt.

- **Put the phase functions in `pipeline/mod.rs` (alongside `build_enriched_request`).** Rejected: `pipeline/mod.rs:23–26` explicitly states that provider call execution and WAL framing do NOT live there (those are the bodies of `dispatch_provider` and `run_post_reply_pipelines`). Adding them would contradict the existing doc contract and make `pipeline/` a grab-bag module rather than the focused enrichment-composition layer it currently is.

- **Use a single extracted function `run_chat_turn_pipeline(PromptBundle, ...) -> Result<String>` instead of four phase functions.** Rejected: a single function restores the monolith one level up. The four-phase split is the minimum decomposition that gives each stage its own test entry-point, matching the test contract in GOLD-ARCH-02 ("each phase function has unit tests").

## Compliance audit (as of HEAD `7c9df23`, 2026-06-08)

**What already complies:**

- `resolve_prompt` (`cli/chat.rs:2174`) is already an extracted helper called by `run_chat_with` at line 164. It would live inside `build_prompt_bundle` after GOLD-ARCH-02.
- `pipeline::build_enriched_request` (`pipeline/enriched_request.rs`, called at `cli/chat.rs:763`) is already extracted. It is the only phase-1 step that currently lives outside `run_chat_with`.
- `dispatch_council_with_recovery` (`cli/chat.rs:3343`, `pub(crate)`) is already a named function. It satisfies the "named phase fn" rule for the council dispatch sub-path.
- `run_mcp_dispatch_loop` (`cli/chat.rs:3719`, `pub(crate)`) is already a named function. Same as above for the MCP dispatch sub-path.
- `run_hook_stage` (`cli/chat.rs:2009`) is already an extracted async helper used at lines 949, 964, 1492.
- `maybe_repo_context_block` (`cli/chat.rs:2743`, `pub(crate)`) is extracted and testable.

**What violates the decision (inlined logic that must become a named phase fn before or during GOLD-ARCH-02):**

- **`enforce_budget` block** (`cli/chat.rs:358–413`): 55-line inline block building `BlockItem` vec and calling `crate::tokens::budget::enforce_budget`. Must become part of `enforce_preflight` or a named sub-helper `build_prompt_bundle` calls.
- **Skill registry load + ARCH-07 pinned-hash gate** (`cli/chat.rs:458–606`): 148 inline lines. Must move into `build_prompt_bundle`.
- **Mode/skill routing + Stage-2 embedding re-rank** (`cli/chat.rs:608–708`): 100 inline lines. Must move into `build_prompt_bundle`.
- **MCP catalogue assembly** (`cli/chat.rs:711–737`): 26 inline lines. Must move into `build_prompt_bundle`.
- **Autonomy gate + cost preview WAL emit** (`cli/chat.rs:787–842`): 56 inline lines calling `permissions::Gate::check`. Must become `enforce_preflight`.
- **Provider quota pre-flight** (`cli/chat.rs:844–866`): 23 inline lines using `QuotaTracker`. Must become `enforce_preflight`.
- **Entire provider-dispatch branch tree** (`cli/chat.rs:931–1439`): 508 inline lines (hook stages + stream/council/MCP-loop/single-provider arms). Must become `dispatch_provider`.
- **Refusal detect + recovery** (`cli/chat.rs:1532–1687`): 156 inline lines. Must become part of `run_post_reply_pipelines`.
- **ADR extraction** (`cli/chat.rs:1689–1702`): 14 inline lines. Must become part of `run_post_reply_pipelines`.
- **SESSION_ARCHIVE** (`cli/chat.rs:1704–1721`): 18 inline lines. Must become part of `run_post_reply_pipelines`.
- **Profile pipeline post-reply** (`cli/chat.rs:1723–1909`): 186 inline lines. Must become part of `run_post_reply_pipelines`.
- **Two-stage review gate** (`cli/chat.rs:1911–1961`): 50 inline lines. Must become part of `run_post_reply_pipelines`.
- **Hindsight card save** (`cli/chat.rs:1963–1976`): 14 inline lines. Must become part of `run_post_reply_pipelines`.

**New logic added after this ADR is accepted** must not be inlined into `run_chat_with`; it must be placed inside one of the four named phase functions or a named sub-helper those functions call.

## References

- neothd/src/cli/chat.rs:128 — run_chat_with start
- neothd/src/cli/chat.rs:1981 — run_chat_with end
- neothd/src/cli/chat.rs:164 — resolve_prompt call
- neothd/src/cli/chat.rs:380 — enforce_budget call (inlined phase)
- neothd/src/cli/chat.rs:763 — pipeline::build_enriched_request call (extracted)
- neothd/src/cli/chat.rs:836 — permissions::Gate::check (inlined enforce_preflight)
- neothd/src/cli/chat.rs:949 — run_hook_stage PrePipeline (extracted helper)
- neothd/src/cli/chat.rs:1308 — dispatch_council_with_recovery call (extracted)
- neothd/src/cli/chat.rs:1332 — run_mcp_dispatch_loop call (extracted)
- neothd/src/cli/chat.rs:1539 — refusal_detect::classify (inlined post-reply)
- neothd/src/cli/chat.rs:1836 — profile::run_pipeline call (inlined post-reply)
- neothd/src/cli/chat.rs:2009 — run_hook_stage helper definition
- neothd/src/cli/chat.rs:3343 — dispatch_council_with_recovery definition
- neothd/src/cli/chat.rs:3719 — run_mcp_dispatch_loop definition
- neothd/src/cli/serve_pipeline.rs:1 — GOLD-ARCH-01 extraction (structural precedent)
- neothd/src/pipeline/mod.rs:1 — enriched_request extraction (partial precedent)
- PLAN/ROAD_TO_1_0_GOLD.md:334 — GOLD-ARCH-02 execution task
- ADR-006
