# CRG Adoption Analysis — `code-review-graph` vs NEOTH `code_map`

**Date:** 2026-07-20. **Question:** should NEOTH adopt capabilities from
`tirth8205/code-review-graph` (CRG)? **Method:** deep-read of both codebases
(CRG Python source at `~/.crg-venv/.../code_review_graph/`; NEOTH
`SRC/neothd/src/code_map/` + `cli/code_intel.rs` + `mcp/codegraph_server.rs`),
claims verified per-item against the actual source.

## Verdict (headline)

**NEOTH already has ~60% of CRG's substance, in superior Rust form — do NOT
adopt wholesale, and never add the Python dep.** NEOTH is genuinely BETTER at
three things CRG lacks entirely: **risk scoring** (`code_map/risk.rs`, logistic
ownership+churn → pre-edit gate), **co-change hidden coupling**
(`code_map/co_change.rs`, git-log pair counts), **ownership/bus-factor**
(`code_map/ownership.rs`). Port only the four concepts below (to Rust), and —
the single highest-value action — **wire NEOTH's existing `code_map` into the
coding hemisphere, which today ignores it entirely.**

### Verified ground-truth (2026-07-20)
- **Coding hemisphere does NOT consume `code_map`** — `git grep code_map|codegraph`
  under `SRC/neothd/src/coding/` returns **0**. Confirmed. The only consumer today
  is `mcp/codegraph_server.rs`.
- **NEOTH graph is thin** — `code_map/graph.rs::EdgeKind` = `Calls` + `References`
  (References is Phase-2-**reserved**, not emitted). No `Imports`, no `TESTED_BY`,
  no impact traversal. (The research agent mislabeled this as "Calls+Imports";
  actual is thinner.)
- **`codegraph_server.rs` exposes 6 tools** — `relevant_files`, `callers`,
  `callees`, `outline`, `extract_identifiers`, `path_keywords`. No impact tool.
  Confirmed.
- **Tree-sitter is NOT in NEOTH yet** — `code_map/symbols.rs:28` uses per-language
  regex (~85% coverage) and defers tree-sitter to "Phase-2b when it becomes worth
  the build cost." CRG uses `tree_sitter_language_pack` (~40+ langs, true AST).

## Backlog — adopt these (ranked), all ADOPT-NATIVE (port to Rust)

- [ ] **CRG-01 — Wire `code_map` into the coding hemisphere. (S, do first)**
  Not a CRG feature — the enabling gap. Feed `recall.rs::relevant_files_for_prompt`
  + `codegraph callers/callees` into the decomposer's prompt bundle. This is what
  converts NEOTH from "has a code-map CLI" to "uses code-map while coding," and
  delivers CRG's headline benefit (fewer grep round-trips, better first-pass
  decomposition) using NEOTH's own (better) infra. Integration: `SRC/neothd/src/coding/`
  decomposer + `code_map/recall.rs`.

- [ ] **CRG-02 — Structural blast-radius tool. (S)** Port CRG `graph.py:742
  get_impact_radius` (BFS outward over CALLS from changed nodes, N hops → affected
  set). NEOTH already has the halves: `codegraph_server.rs` `callers_inner`
  (~:402) + `callees_inner` (~:428). Add `code_map/graph.rs::impact_radius(roots,
  depth)` + 7th tool `codegraph_impact_radius`.

- [ ] **CRG-03 — git diff → function-level node mapping. (M)** Port CRG
  `changes.py:33 parse_git_diff_ranges` (`git diff --unified=0` hunk headers →
  `{file: [(start,end)]}`), intersect with per-symbol `line_start/line_end`
  (already persisted in `code_map_symbols.line`). Makes CRG-02 function-level
  precise instead of file-level noisy. New `code_map/diff.rs` +
  `graph.rs::nodes_in_line_range`. Also backs a future `neoth code-intel --diff`.

- [ ] **CRG-04 — `TESTED_BY` edge + test-gap detection. (M)** Add `TestedBy` to
  `EdgeKind`; mark symbols in `*_test.rs`/`test_*.py`/`*.test.ts` as test nodes
  (`symbols.rs`); emit a heuristic TestedBy when a test file references a
  production symbol by name. New tool `codegraph_test_gaps`. Consumers: coding
  hemisphere ("no test covers this path") + pre-edit risk gate (no-tests +
  high-risk = double warning). Ref: CRG `graph.py:423 get_transitive_tests`.

- [ ] **CRG-05 — PreToolUse hook injection. (S, high UX/effort)** Port CRG
  `enrich.py` pattern: a PreToolUse hook that reads `tool_input.pattern`/`path`,
  queries codegraph for callers/callees/tests, returns them as
  `hookSpecificOutput` — every Grep/Read gets structural context free. Zero new
  Rust: a hook script calling `neoth mcp codegraph-serve` or reading
  `~/.neoth/code_map.db`. Integration: NEOTH hooks config.

## Reference-only / skip

- **Tree-sitter AST parsing → GROUND-TRUTH.** CRG `parser.py` (node-type mapping
  tables ~:696-960, edge-emission) is the reference impl for NEOTH's planned
  Phase-2b. When the build cost is accepted, port those tables to the Rust
  `tree-sitter` crate + per-language grammar crates. **Never** add
  `tree_sitter_language_pack` (Python).
- **Token-savings metric → SKIP.** CRG's "~99%" is a 30-line `chars/4` reporting
  wrapper (`context_savings.py`) comparing graph output vs dumping whole files —
  real number, unfair baseline. NEOTH already has the same `CHARS_PER_TOKEN=4`
  math in `repo_map.rs`. No intelligence to steal; the real win is CRG-01..03
  (fewer tool calls), not reporting a percentage.
- **Leiden community detection → SKIP** (no NEOTH consumer yet; revisit for
  multi-agent module-boundary reasoning).
- **Flow/entry-point BFS → SKIP for now** (needs accurate parse; defer to Phase-2b).
- **Cross-repo registry, docs/wiki tools → SKIP** (single-operator daemon; wrong
  product surface).

## MCP note

CRG is also now installed + wired as an MCP server for Claude Code (`.mcp.json`,
`uvx code-review-graph serve`, gitignored) — usable as an external review tool
independent of any NEOTH port. The port above is about NEOTH's *own* coding
intelligence, not replacing that.

## Authoritative disposition (2026-07-25)

Evidence verified by grepping `SRC/neothd/src/` at HEAD (2026-07-25). No builds run.

| Item | Proposal | Disposition | Evidence owner |
|------|----------|-------------|----------------|
| CRG-01 | Wire `code_map` into coding hemisphere | **RETAINED-PARTIAL** | `SRC/neothd/src/coding/decomposer.rs` (call-site absent) + `SRC/neothd/src/code_map/recall.rs` (`relevant_files_for_prompt` exists, uncalled from decomposer) |
| CRG-02 | Structural blast-radius tool (`codegraph_impact_radius`) | **DEFERRED-v1.1** | `SRC/neothd/src/code_map/graph.rs` (no `impact_radius` fn) + `SRC/neothd/src/mcp/codegraph_server.rs` (tool list capped at 6) |
| CRG-03 | git diff → function-level node mapping | **DEFERRED-v1.1** | `SRC/neothd/src/code_map/` directory (`diff.rs` absent; no `nodes_in_line_range`) |
| CRG-04 | `TestedBy` edge + test-gap detection | **DEFERRED-v1.1** | `SRC/neothd/src/code_map/graph.rs:43` (`EdgeKind` enum: only `Calls` + `References`; no `TestedBy` variant, no test-node marking) |
| CRG-05 | PreToolUse hook injection (enrich.py port) | **DEFERRED-v1.1** | NEOTH hooks config (no codegraph enrich script; no `hookSpecificOutput` wiring) |

### Per-item evidence detail

**CRG-01 (RETAINED-PARTIAL):** R3-13 shipped the containment/index half —
`persist.rs:760` `root_index_generation`, `persist.rs:782` `is_index_stale`,
`codegraph_server.rs:334` MCP `index_generation` propagation. The MCP tool
`codegraph_relevant_files` (`codegraph_server.rs:65`) also exists. What is absent:
`coding/decomposer.rs` has zero calls to `recall.rs::relevant_files_for_prompt`
or to codegraph callers/callees; the coding hemisphere's prompt bundle is
un-enriched (confirmed by `grep -r "recall\|relevant_files\|codegraph" SRC/neothd/src/coding/`
returning only incidental mentions — no decomposer integration).

**CRG-02 (DEFERRED-v1.1):** Building blocks exist — `codegraph_server.rs:417`
`callers_inner`, `:443` `callees_inner`. Missing: no `impact_radius()` in
`code_map/graph.rs`; only 6 MCP tools registered (confirmed by test
`codegraph_server.rs:785`). Requires a new graph traversal fn + 7th tool stub.
Unblocked by CRG-01 but outside R3 scope.

**CRG-03 (DEFERRED-v1.1):** `code_map_symbols.line` persists line ranges in the
DB (the intersect substrate exists), but `code_map/diff.rs` does not exist and
no `nodes_in_line_range()` fn is present anywhere in `code_map/`. Depends on
CRG-02 to be actionable; defer together.

**CRG-04 (DEFERRED-v1.1):** `EdgeKind` enum (`graph.rs:43`) has exactly two
variants: `Calls` and `References`. No `TestedBy`, no test-node flag in
`symbols.rs`, no `codegraph_test_gaps` tool. Requires an edge-schema extension
and a DB migration; defer to v1.1.

**CRG-05 (DEFERRED-v1.1):** Zero new Rust required (hook script only), but no
hook script implementing the `hookSpecificOutput`/enrich.py pattern exists in
NEOTH's hooks config. Logically depends on CRG-01 being wired first so the
codegraph path is exercised end-to-end; defer to v1.1 with CRG-01 completion.

**Summary:** 1 RETAINED-PARTIAL (CRG-01), 4 DEFERRED-v1.1 (CRG-02..05). The
GOLD-R3-16 umbrella checkbox is ready for re-audit once the four DEFERRED-v1.1
items are formally acknowledged as v1.1 scope and CRG-01's decomposer-wiring
gap is either closed or moved to v1.1.
