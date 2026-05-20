request changes

Top-5 must-fix issues ranked:

1. **Brain metaphor is currently under-specified and leaks into data model**
   Section refs: `2.1`, `2.3`, `2.4`, Framework `G.10`, `G.12`, `G.13`.

   The metaphor is useful only as UI/architecture vocabulary for separation of roles: input relay, private analysis, synthesis, final output. It becomes magical thinking once `brain_region` and `hemisphere` are made first-class WAL header fields without enforceable runtime semantics.

   `brain_region=Amygdala` does not currently constrain behavior beyond what `importance`, `decay`, `source`, `event_type`, and `pipeline_id` already express. If it is only a label, it is taxonomy theater. If it changes routing/retention/recall, those rules must be explicit and testable.

   Fix: demote anatomy terms to docs/display names, or define hard invariants per region, e.g. `Amygdala` events must carry `importance_score`, `decay_policy`, and can only be emitted by `importance.score` or `recall.rank`.

2. **Left-only output channel does not buy much reliability by itself**
   Section refs: `1.3.4`, `2.1`, `2.2`, `4`.

   One final speaker avoids contradictory user-facing messages, but that is already achievable with a normal response-synthesis pipeline. The design does not prove that "left hemisphere only" is more reliable than "single final synthesizer".

   Worse: right-side findings can be silently lost because `left_hemisphere_generate.final` is what gets emitted, while `corpus_callosum_check` only appears after the left draft. If callosum finds dissent, the pipeline triggers council, but the final emitted text still references `left_hemisphere_generate.final`.

   Fix: make the final response depend on a post-check artifact, e.g. `finalize_response` consumes left draft, right findings, callosum verdict, and optional council verdict. Then only that final artifact may reach `telegram.send`.

3. **Tool layer violates Framework locality/state rules**
   Section refs: `3`, Framework `A.1`, `B.5`, Anti-Patterns `G.1`, `G.4`, `G.7`, `G.9`, `G.12`.

   `telegram.send`, `http.fetch`, `oauth.refresh`, `vault.write`, `wal.emit`, and `embed.encode` are called "Tools", but Framework `A.1` says Tool-Schicht forbids filesystem/network/environment/global state. The artifact marks `telegram.send` as `network: yes`, `side_effects: yes`, and still `schicht: 0`.

   That is a direct Schicht mismatch. These are not pure stateless deterministic tools in the Framework sense; they are adapters/effects. Calling them Tool-Schicht without a separate effect boundary violates `G.12 Level-Confusion`.

   Fix: split `Tool` into pure operation specs and `Effect Adapter` specs, or explicitly extend Framework v4.1 for external-effect tools with idempotency keys, retry semantics, audit events, and deterministic wrappers.

4. **Phase-1 plan is not credible for solo dev in <60 days**
   Section refs: `6`, `8`, Live Truth `1`, `7`, `8`.

   The plan tries to build: Rust workspace, YAML loaders, WAL v2, three CLI OAuth adapters, 20 tool variants, 5 pipelines, 13 views, Tailslayer integration, Qwen/candle GGUF embedding, context engine, council engine, Telegram channel, migration, eval, and 14-day shadow run in 55 days.

   Realistic solo estimate to first end-to-end Telegram response:
   - Minimal path without full memory migration/council: **10-20 days**.
   - With Qwen embedding and one WAL-backed recall path: **20-35 days**.
   - With Tailslayer default-on, 13 views, council, migration/eval, shadow cutover: **75-120 days**.

   The current 11-step plan is too parallel in dependencies. `Memory Engine`, `Embedding`, `Context-Engine`, `Council`, and `Migration` are each large enough to slip the schedule alone.

   Fix: define Phase 1 as one golden path: Telegram in, WAL append, one recall index, one LLM response, Telegram out. Everything else behind feature flags.

5. **Tailslayer default-on is operationally brittle**
   Section refs: `6`, review focus `6`.

   Default-on low-latency hugepage vectors are a bad default for the observed deployment reality. It will hurt on:
   - dev machines with <16 GB RAM,
   - virtualized hosts where hugepages are disabled/restricted,
   - systems without preallocated hugepages,
   - containers/LXC where memory locking or hugepage mounts are constrained,
   - first-run installs where failure mode should be boring.

   Also the prompt mentions "users without 1 GiB hugepages", while the design says 2 MiB hugepages. That mismatch needs clarification. If Tailslayer requires only 2 MiB pages, say so and document fallback behavior.

   Fix: make Tailslayer `auto` default, not `on`: probe hugepage availability, memory budget, cgroup limits, and fallback to mmap/SQLite/LanceDB-compatible vector store. Keep `low-latency` as opt-in profile.

Other Framework v4.1 violations / weak spots:

- **G.10 Magic Scale Assumption:** native council 2-10 rounds is treated as quality gain without eval criteria. Cosine similarity of response embeddings is not a valid agreement metric for correctness.
- **G.11 Closed-Loop Ecology risk:** `Council-Outcome-Tracking`, `Provider-Score`, and `Tool-Genealogie` are okay as reports, but must not auto-adjust provider routing/tool selection unless human-approved.
- **G.5 Emergent Tool Composition:** `Provider-Cascade`, `Council-Auto-Trigger Keywords`, and `if_dissent_score > 0.4 trigger council` need explicit pipeline semantics. Otherwise runtime behavior becomes magic orchestration.
- **G.9 Black Box without Introspection:** CLI OAuth providers need captured prompts, stderr/stdout, token/cost estimates, model IDs, and timeout traces. "CLI-first" is otherwise hard to debug.
- **G.12 Level Confusion:** `Brain Stem = daemon-lifecycle`, `Pineal = scheduler`, `Thalamus = Context-Engine`, and `Mirror Neurons = refusal-handler` mix runtime services, pipelines, and views under the same "memory region" table.

Council-as-Pipeline verdict:

Council-as-Pipeline is more Framework-conform than runtime decoration. It belongs in Schicht 1 because it is multi-step, budget-bound, declarative orchestration. But the current design still needs one correction: the council result must produce a typed artifact consumed by finalization, not decorate the response path after the left model has already produced the final answer.

Verdict: **request changes**. The architecture is directionally better than v0.3 because it adopts Tool/Pipeline/Ecology separation and pushes Ecology out of Phase 1. But v0.4 still overcommits, turns metaphor into schema before proving semantic value, and misclassifies effectful adapters as deterministic tools. The fix is not a rewrite: strip Phase 1 down to the golden path, make brain labels enforceable or cosmetic, and put all output through a final typed synthesis step.

## DONE
