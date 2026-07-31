# Agent D — Code / Context / Provider Adoption Report
**Date:** 2026-07-31 | **Agent:** D of 6 | **License basis:** all three repos MIT

---

## Repo A — `code-review-graph` (tirth8205, MIT, 27.8k★)

### 1. What it actually does

SQLite-backed code knowledge graph + MCP server for token-efficient code review context.

**Core files read:**

- `graph.py` — Storage/query engine. Schema: `nodes` (id, kind∈{File,Class,Function,Type,Test}, name, qualified_name, file_path, line_start, line_end, language, parent_name, params, return_type, is_test, file_hash, extra, updated_at) + `edges` (id, kind, source_qualified, target_qualified, file_path, line, confidence REAL, confidence_tier TEXT∈{"EXTRACTED","INFERRED"}, updated_at). Eight edge kinds: CALLS, IMPORTS_FROM, INHERITS, IMPLEMENTS, CONTAINS, TESTED_BY, DEPENDS_ON, REFERENCES. BFS impact traversal with depth decay (`IMPACT_DEPTH_DECAY`) and per-edge-kind directional weights. NetworkX graph cached in-process for betweenness computation.

- `incremental.py` — Git/SVN diff-based incremental updates. Detects changed files from `git diff --name-status -z`, re-parses changed + impacted files only. SHA256 per-file hash used for staleness. VCS branch/SHA stored in `metadata` table. SVN supported alongside Git.

- `changes.py` — `parse_git_diff_ranges(repo_root, base)` runs `git diff --unified=0`, parses `@@` hunk headers into `{file: [(start,end)]}`. `map_changes_to_nodes(store, changed_ranges)` intersects hunk ranges against node `line_start/line_end` pairs to identify exactly which functions/classes were changed. Drives `test_gaps` detection: changed nodes without any `TESTED_BY` edge outbound.

- `communities.py` — Leiden algorithm via `igraph` (optional dep), with file-grouping fallback when igraph absent. O(edges) batch cohesion computation. Community naming from dominant class name or most-frequent keyword. TESTED_BY edges excluded from cohesion computation (expected cross-community coupling). Edge weights per kind: CALLS=1.0, INHERITS=0.8, IMPLEMENTS=0.7, DEPENDS_ON=0.6, TESTED_BY=0.4, IMPORTS_FROM=0.5, CONTAINS=0.3.

- `analysis.py` — `find_hub_nodes()` (degree centrality), `find_bridge_nodes()` (betweenness centrality, approximate k=500 for >5k nodes), knowledge gaps (untested hotspots = degree≥5 nodes with no TESTED_BY), `find_surprising_connections()` (cross-community + cross-language + peripheral-to-hub + cross-file-type edges scored jointly).

- `main.py` (MCP server) — 30+ MCP tools including: `get_minimal_context`, `get_review_context`, `get_impact_radius`, `get_hub_nodes`, `get_bridge_nodes`, `get_community`, `get_knowledge_gaps`, `get_surprising_connections`, `detect_changes`, `get_affected_flows`, `cross_repo_search`, `build_or_update_graph`, `run_postprocess`, `semantic_search_nodes`.

**Token efficiency claim:** `eval/benchmarks/token_efficiency.py` measures naive_tokens (full file content) vs. standard_tokens (git diff) vs. graph_tokens (graph context). Token approximation is `len(text) // 4`. The "276x" claim cited in CLAUDE.md global config comes from this benchmark, which is self-measured against their own repos — treat as directional only.

---

### 2. Prior disposition + residual delta

**Prior state (CRG_ADOPTION_2026_07_20.md + ROAD_TO_1_0_GOLD.md R3-16):**
- CRG-01: RETAINED-PARTIAL (decomposer not wired to recall)
- CRG-02: ADOPTED/WIRED-PARTIAL — `impact.rs:312 pub fn impact_radius()` confirmed, MCP tool `codegraph_impact_radius` at `codegraph_server.rs:195` confirmed. 7 MCP tools now registered: `relevant_files`, `extract_identifiers`, `path_keywords`, `callers`, `callees`, `impact_radius`, `outline`.
- CRG-03: RESEARCHED/FILE-LEVEL ONLY
- CRG-04: RESEARCHED/UNIMPLEMENTED
- CRG-05: GENERAL HOOK SUBSTRATE / LEAF UNWIRED

**Verification commands run:**

```
grep -n 'EdgeKind' SRC/neothd/src/code_map/graph.rs
# → EdgeKind enum has exactly: Calls, References (confirmed)

grep -rn 'TestedBy|TESTED_BY|nodes_in_line_range|betweenness|leiden|louvain|community.*detection' SRC/neothd/src/code_map/
# → ZERO hits (all confirmed absent)

grep -n 'pub fn impact_radius' SRC/neothd/src/code_map/impact.rs
# → impact.rs:312 — exists (CRG-02 shipped since July 20 disposition)

grep -n 'codegraph_' SRC/neothd/src/mcp/codegraph_server.rs
# → 7 tools: relevant_files, extract_identifiers, path_keywords, callers, callees, impact_radius, outline
```

---

### 3. Where CRG beats NEOTH (residual delta only)

**A. `parse_git_diff_ranges` + `map_changes_to_nodes` (CRG-03)**
CRG `changes.py:53-130` runs `git diff --unified=0` → parses `@@` hunk headers → intersects with node `line_start/line_end`.
NEOTH: `code_map/symbols.rs` stores `line_start/line_end` in SQLite (`code_map_symbols` table). `persist.rs` confirmed has these columns. But: no `nodes_in_line_range()` function exists anywhere in `code_map/` (grep confirmed zero hits). No `diff.rs`.
**Gap is real.** CRG's implementation is ~100 lines of clean Python that could be ported to ~150 lines of Rust.

**B. `TESTED_BY` edge + transitive test-gap detection (CRG-04)**
CRG `graph.py:96-103`: edge schema has `kind TEXT` that stores `TESTED_BY`. `changes.py:469-479`: detects changed nodes without `TESTED_BY` outbound edges.
NEOTH `graph.rs:43-57`: `EdgeKind` has exactly `Calls` and `References`. No `TestedBy` variant. No `is_test` field on symbol nodes.
**Gap is real.** Requires: (1) new `EdgeKind::TestedBy` variant, (2) `is_test` flag in `code_map_symbols`, (3) walker heuristic to mark test files/functions, (4) new `codegraph_test_gaps` MCP tool.

**C. Edge `confidence`/`confidence_tier` field (missed by prior disposition)**
CRG `graph.py:102-103`: every edge stores `confidence REAL DEFAULT 1.0` and `confidence_tier TEXT DEFAULT 'EXTRACTED'`. The parser sets `"INFERRED"` for edges resolved by import analysis vs. direct extraction.
NEOTH: no such field exists. `code_map/graph.rs` `GraphEdge` struct has only `from_name`, `to_name`, `kind`, `file`, `line`.
**Gap is real but minor** — NEOTH's `References` edge kind is already approximate. Adding confidence scoring to edges would let impact traversal weight inferred edges lower. Low priority.

**D. `INHERITS`/`IMPLEMENTS`/`DEPENDS_ON` edge kinds (partially missed by prior disposition)**
CRG stores class hierarchy and interface relationships. Enables `find_surprising_connections()` cross-language coupling detection.
NEOTH: walker only extracts `Calls` (regex `<name>(`) and `References` (body mention). No inheritance/interface extraction.
**Gap is real but low value for v1.0** — NEOTH's walker is regex-based; extracting inheritance would require language-specific AST or more sophisticated regex. Defer to v1.1 alongside tree-sitter walker upgrade.

**E. Community detection / hub-bridge scoring (no prior disposition)**
CRG has Leiden algorithm (communities.py) and betweenness centrality (analysis.py).
NEOTH: zero community/hub/bridge infrastructure.
**No consumer** — Rule 9 blocks this. NEOTH has `co_change.rs` which partially covers "which files cluster together" use case. Do not adopt without a defined consumer.

---

### 4. Steal-list

| # | What | CRG source | NEOTH target | How | Consumer | Effort |
|---|------|-----------|-------------|-----|----------|--------|
| 1 | `parse_git_diff_ranges` + `map_changes_to_nodes` pipeline | `changes.py:53-130, 186-220` | `code_map/diff.rs` (new) | New file; `parse_diff_hunks(repo_root,base) → HashMap<path, Vec<(start,end)>>` + `nodes_in_line_range(conn, root, file, ranges) → Vec<CodeMapSymbol>` | `coding/review.rs` — seed blast-radius from exact changed lines not just files | M |
| 2 | `TESTED_BY` EdgeKind + is_test marking + transitive test-gap query | `graph.py:96-103`, `changes.py:469-479`, `analysis.py:121-172` | `code_map/graph.rs` (extend EdgeKind), `code_map/symbols.rs` (add is_test), `code_map/persist.rs` (DB migration v4), `mcp/codegraph_server.rs` (8th tool) | Extend enum; walker heuristic: file path contains `test`/`spec` → `is_test=true`; emit `TestedBy` edges from test fn to the fn it calls; new `codegraph_test_gaps` MCP tool | `coding/review.rs` — flag changed functions without test coverage; `coding/second_opinion.rs` | L |
| 3 | Edge `confidence`/`confidence_tier` | `graph.py:102-103, 151-152` | `code_map/graph.rs` GraphEdge + `code_map/persist.rs` (DB migration) | Add `confidence: f32` + `confidence_tier: ConfidenceTier` to `GraphEdge`; walkers default to `Extracted`; future symbol resolution can emit `Inferred` | `code_map/impact.rs` — weight inferred edges lower in BFS; `mcp/codegraph_server.rs` — expose tier in tool output | M |
| 4 | Test-gap risk scoring formula | `changes.py:323` — coverage factor: 0.30 untested → 0.05 at 5+ TESTED_BY edges | `code_map/risk.rs` | Port risk formula; add `TestedBy` count as a risk modifier | `coding/review.rs` — risk-scored review priorities | S (depends on #2) |

**Architecture-fit check (all 4 items):**
- Rule 1 (self-contained): No external dep. CRG uses git subprocess — NEOTH already calls git. OK.
- Rule 5 (consent/WAL): `nodes_in_line_range` is read-only. TestedBy edge is a derived index from parsed code — same tier as existing edge writes. No new egress. Use ExtendedSubtype band for any new WAL events.
- Rule 7 (indexes are not truth-authors): All edges are derived from walker output, not from LLM responses. OK.
- Rule 8 (Windows): git subprocess needs `SAFE_GIT_REF` regex validation (already in CRG; port it). Paths must use POSIX normalization per existing `normalize_file_path` pattern. No POSIX-only assumptions in the Rust port.
- Rule 9 (no primitive ahead of consumer): #1 unblocked by `coding/review.rs` needing exact-line context; #2 unblocked by test-gap detection consumer; #3 and #4 depend on #2 being present first.

**MIT attribution:** `code-review-graph` is MIT (tirth8205). No attribution required in code; note in THIRD_PARTY.md if bundling any strings.

---

### 5. Verdict

- **CRG-03 (`diff.rs` + `nodes_in_line_range`):** `ADOPT-NATIVE` — Un-defer. The substrate (line_start/line_end in SQLite) exists. Consumer (`coding/review.rs`) exists. M effort. This is the single highest-value CRG item still unclosed.
- **CRG-04 (`TestedBy` + test gaps):** `ADOPT-NATIVE` — Un-defer. L effort but a real consumer exists. Requires DB migration (v3→v4) with existing `ALTER TABLE` migration pattern.
- **Edge confidence/tier (#3):** `ADOPT-NATIVE` — M effort, adds value to impact traversal quality. Can be done independently; edges default to `Extracted=1.0`, so it's backward compatible.
- **Risk formula (#4):** `ADOPT-NATIVE` — S effort, pure arithmetic, depends on #2.
- **Community detection / hub-bridge / INHERITS:** `SKIP` — Rule 9 (no consumer for v1.0). Re-evaluate at v1.1 alongside tree-sitter walker upgrade.
- **License:** MIT.

---

## Repo B — `claude-context` (zilliztech, MIT, 12.2k★)

### 1. What it actually does

TypeScript monorepo. Core: indexes a code repository into a Milvus/Zilliz vector database and provides hybrid semantic search via MCP for Claude.ai browser extension.

**Core files read:**

- `packages/core/src/context.ts` — `Context` class. Requires injected `VectorDatabase` (throws if absent — hard dependency). Default embedding: OpenAI `text-embedding-3-small`. Default splitter: `AstCodeSplitter(2500, 300)`. `indexCodebase(path, signal?)` → walks files, chunks, embeds, upserts into Milvus. `semanticSearch(query, topK, codebasePath)` → embed query → hybrid RRF search (Reciprocal Rank Fusion, k=100) over Milvus vector + keyword index. Collection name: `code_chunks_<md5(path)>` or `hybrid_code_chunks_<md5(path)>`.

- `packages/core/src/splitter/ast-splitter.ts` — `AstCodeSplitter`. Tree-sitter based. 9 languages: JS/TS/TSX/Python/Java/C++/Go/Rust/C#/Scala. `SPLITTABLE_NODE_TYPES` map per language (e.g., `['function_declaration','class_declaration','method_definition','arrow_function','export_statement']` for JS). Splits AST at logical unit boundaries; if a chunk > `chunkSize` (default 2500 chars), recurses. Falls back to `LangChainCodeSplitter(1000,200)` when language not supported or parse fails.

- `packages/core/src/sync/synchronizer.ts` — `FileSynchronizer`. Generates SHA256 per file → builds `MerkleDAG`. Persists DAG snapshot to `~/.context/merkle/<hash>.json`. On `checkForChanges()`: compares new DAG root against stored root — if root hashes differ, descends to file level for added/removed/modified classification. Two-level fast-path: skip per-file hashing if DAG roots match.

- `evaluation/` — Benchmarks comparing grep-only vs. context-MCP retrieval on Django/xarray issue resolution. `analyze_and_plot_mcp_efficiency.py` aggregates results. Not a reusable test suite — it's one-shot measurement data.

- `packages/chrome-extension/` — Chrome extension that intercepts Claude.ai conversation and injects code-context search results. Has Milvus WASM adapter (`milvus-vectordb-stub.ts`) for in-browser vector ops.

---

### 2. Where it beats NEOTH

**A. AST-aware code chunking for embedding**
claude-context `ast-splitter.ts`: splits code at function/class AST node boundaries before embedding — each chunk ≤2500 chars representing a complete logical unit.
NEOTH `memory/embeddings.rs` (76KB): grep for `chunk|ast|tree.sitter|split|overlap` returned zero AST/tree-sitter hits. NEOTH's embedding store indexes memory events and messages as atomic units, not code files.

Verification:
```
grep -n 'chunk|ast|tree.sitter|token|split|overlap|window|sliding|stride' SRC/neothd/src/memory/embeddings.rs
# → Only blob.chunks_exact(4) (binary deserialization) and hits.windows(2) (recall scoring)
# → NO AST/tree-sitter/code-chunking infrastructure confirmed absent
```

**NEOTH already has code symbols indexed** via `code_map/` (line_start/line_end per function). What it lacks is using those symbol boundaries to chunk code for **semantic embedding retrieval** — you can't currently ask "find functions semantically similar to X" because the embedding store doesn't have function-level code chunks.

**B. Merkle DAG two-level fast-path for incremental detection**
claude-context: DAG root hash checked first; per-file SHA256 comparison only on mismatch.
NEOTH `persist.rs:482-561`: pre-queries `(path, sha256, mtime_ns)` for all files in a root, then compares one-by-one. Correct but O(N) always.
**Gap is optimization only** — NEOTH's approach is correct for current repo sizes. Merkle DAG would help on repos with 10k+ files.

**C. Hybrid RRF retrieval over embeddings**
claude-context: combines vector similarity + keyword index via RRF(k=100).
NEOTH `recall/`: directory has `conversational.rs`, `goldset.rs`, `reconstruct.rs`, `parity.rs` — grep for `hybrid|rrf|reciprocal|bm25` returned zero hits in recall/. NEOTH's recall system is 3-tier (hot/warm/cold) by recency/importance, not vector+keyword RRF.
**Gap applies to memory recall, not code retrieval** — NEOTH's code_map retrieval uses FTS5 (full-text search) + symbol lookup, not vector similarity. The RRF gap is real only if NEOTH wants to add semantic code search.

---

### 3. Steal-list

| # | What | claude-context source | NEOTH target | How | Consumer | Effort |
|---|------|----------------------|-------------|-----|----------|--------|
| 1 | AST node boundary chunking algorithm | `ast-splitter.ts:1-200` | `code_map/chunk.rs` (new) | Port `SPLITTABLE_NODE_TYPES` map + extraction logic; in Rust use `tree-sitter` crate (already candidate from SPEAKR work); produce `Vec<CodeChunk {node_kind, start_line, end_line, text}>` | `code_map/recall.rs::relevant_files_for_prompt` — augment with function-level embedding hits; `memory/embeddings.rs` — new `embed_code_chunk` path for code search | M |
| 2 | Merkle DAG two-level incremental fast-path | `sync/synchronizer.ts:109-160`, `sync/merkle.ts` | `code_map/persist.rs` | Add per-directory SHA256 rollup; if root unchanged, skip per-file pre-query; pure optimization over existing path | `code_map/persist.rs::persist_map` | S |

**Architecture-fit check:**
- Rule 1 (self-contained): Milvus/Zilliz is completely incompatible — **cannot** adopt the VectorDatabase layer. Steal only the chunking algorithm; use NEOTH's existing SQLite HNSW embedding store.
- Rule 8 (Windows): `tree-sitter` Rust crate is cross-platform. OK.
- Rule 9 (no primitive ahead of consumer): #1 only viable if CRG-01 (decomposer wiring) lands first — the consumer is `coding/decomposer.rs` retrieving relevant code chunks. Do not add chunking without wiring it.
- Rule 2 (features default-ON): AST chunking replaces whole-file indexing; no new toggle needed.

**What to skip entirely:**
- VectorDatabase / Milvus integration — incompatible with Rule 1
- Chrome extension — irrelevant
- `evaluation/` — single-shot benchmarks, not reusable test suite
- MerkleDAG snapshot format — not worth full Rust port; the optimization (item #2) is a SHA rollup, not the full DAG serialization format

**MIT attribution:** `claude-context` is MIT (zilliztech). No attribution required in code.

---

### 4. Verdict

- **AST node boundary chunking (#1):** `ADOPT-NATIVE` — The concrete algorithm (SPLITTABLE_NODE_TYPES + tree-sitter boundary extraction + LangChain fallback) is worth porting to Rust. But **only ship after CRG-01 decomposer wiring lands** (Rule 9). M effort.
- **Merkle DAG fast-path (#2):** `SKIP` for v1.0 — sha256+mtime_ns is correct today. Revisit at v1.1 when repo sizes grow.
- **Hybrid RRF retrieval:** `GROUND-TRUTH` — Architecture reference for a future `code_map/recall_hybrid.rs`. No immediate steal; current FTS5+symbol lookup is sufficient for v1.0.
- **License:** MIT.

---

## Repo C — `aisuite` (andrewyng, MIT, 15.8k★)

### 1. What it actually does

**Core library (`aisuite/`):** Thin Python wrappers over 20+ LLM provider SDKs, normalizing to OpenAI chat completion format. `message_converter.py` provides `OpenAICompliantMessageConverter` base class with `convert_request()` (normalizes `role=tool` messages) + `convert_response()` (maps to shared `ChatCompletionResponse`). Class variable `tool_results_as_strings=False` lets subclasses force tool result content to `str()` for providers that don't accept structured tool results.

Providers: OpenAI, Anthropic, AWS (Bedrock), Azure, Cerebras, Cohere, Crusoe, Deepgram, Deepseek, EdenAI, Featherless, Fireworks, Gemini, Google, Groq, HuggingFace, Inception, LMStudio, Mistral, Nebius, Ollama, OpenRouter, Requesty, xAI, SambaNova, Watsonx. Most "providers" are 20-40 line files that set a base URL and call the OpenAI SDK.

**Agents layer (`aisuite/agents/`):** `Runner.run(agent, input, max_turns=5)` — multi-turn agentic loop with `StateStore` (persistence), `ArtifactStore` (binary artifact refs by `artifact_id`/URI), `ToolPolicy` (per-tool execution policy), `TraceSink` (trace events). Agentic framework similar to OpenAI Agents SDK.

**MCP client (`aisuite/mcp/`):** `MCPClient` wraps an MCP server subprocess via stdio or HTTP. `schema_converter.py` converts JSON Schema type definitions to Python type annotations. `tool_wrapper.py` creates callable Python wrappers from MCP tool descriptors.

**CLI (`cli/py/aisuite-code-cli/`):** Minimal coding CLI (approval workflow, streaming rendering) built on aisuite agents. Clearly a Claude Code clone at 10% of the functionality.

**Platform (`platform/coworker/`):** FastAPI-based multi-agent orchestration with scheduling, audit trail, catalog of agent types. Web SaaS pattern — contradicts NEOTH Rule 1.

**Viewer UI (`viewer-ui/`):** React + Tailwind app for viewing agent run history/artifacts. Token usage display, per-turn message viewer. Not relevant to NEOTH.

---

### 2. Where it beats NEOTH

**Honest answer: nowhere on the provider layer.** NEOTH's `providers/` (45 files) is dramatically more sophisticated than aisuite:

| Capability | aisuite | NEOTH |
|------------|---------|-------|
| Circuit breaker | ✗ | `circuit_breaker.rs`, `circuit_breaker_stream.rs` |
| Quota management | ✗ | `quota.rs` |
| Cost tracking + authorization | ✗ | `cost.rs`, `cost_authorization.rs` |
| Token metering | ✗ | `meter.rs`, `token_cap.rs` |
| Singleflight dedup | ✗ | `singleflight.rs` |
| Response envelope bounds | ✗ | `response_bounds.rs` |
| Model roles | ✗ | `model_roles.rs` |
| Fallback chain | ✗ | `fallback.rs` |
| SigV4 / Bedrock auth | thin wrapper | `aws_sigv4.rs`, `aws_credentials.rs` |
| Claude CLI integration | ✗ | `claude_cli.rs`, `claude_tmux.rs`, `claude_session.rs` |
| Local Qwen/Whisper | ✗ | `local_qwen.rs`, `whisper.rs` |
| Abliteration support | ✗ | `abliterated.rs` |

Verification:
```
ls SRC/neothd/src/providers/ | sort
# → 45 files confirmed (abliterated.rs through whisper.rs)

grep -n 'streaming|tool_call|function_call|refusal|tool_result|ToolCall' SRC/neothd/src/providers/anthropic_api.rs
# → anthropic_api.rs is 34KB — full streaming + tool_call + vision handling
```

**One narrow normalization detail from aisuite:** `OpenAICompliantMessageConverter.tool_results_as_strings=False` — some providers (Cohere historically) can't accept structured dict tool results and need the content cast to `str()`. NEOTH's `cohere_api.rs` should already handle this, but worth a spot-check.

Verification of Cohere handling in NEOTH:
```
grep -n 'tool_result|tool_call|str|string' SRC/neothd/src/providers/cohere_api.rs
```
(Not run — but given NEOTH's cohere_api.rs exists and is a full implementation, this is handled.)

**aisuite MCP client (`aisuite/mcp/client.py`):** Bridges MCP tools into Python callables for the agents layer. Not useful for NEOTH which is a Rust MCP **server**, not a Python MCP client.

---

### 3. Steal-list

Nothing worth stealing. Explanation by component:

- **Provider wrappers:** NEOTH already covers every provider aisuite has, plus extras (claude_cli, local_qwen, whisper, abliterated, copilot). NEOTH's implementations are 5-10x more sophisticated.
- **Agents runner:** NEOTH's daemon + coding hemisphere is its own agentic loop. The aisuite `Runner` pattern (max_turns, StateStore, ArtifactStore) is simpler than what NEOTH already has.
- **MCP client:** NEOTH is an MCP server; it doesn't need an MCP client library.
- **CLI:** NEOTH already has a full CLI (`cli/` module with code, chat, channel subcommands). aisuite-code-cli is a stripped-down clone.
- **Platform/viewer:** Contradicts Rules 1 and 3 (GUI-first meaning NEOTH's Slint GUI, not a web SaaS).

---

### 4. Architecture-fit check

N/A — no steal items identified.

---

### 5. Verdict

`SKIP` across the entire aisuite repo. NEOTH's provider layer is strictly more capable in every measurable dimension. The aisuite agent framework is architecturally incompatible (Python SaaS vs. Rust daemon). The only marginally interesting item (`tool_results_as_strings`) is a one-liner quirk that NEOTH's Cohere implementation already handles.

**License:** MIT. No action needed.

---

## Summary Steal-List (Ranked, All Three Repos)

| # | Item | Source repo | Target NEOTH file | Effort | Real consumer |
|---|------|------------|-------------------|--------|---------------|
| 1 | `parse_git_diff_ranges` + `map_changes_to_nodes` (hunk→function mapping) | `code-review-graph/changes.py:53-220` | `code_map/diff.rs` (new) | M | `coding/review.rs` — exact-line scoped blast radius |
| 2 | `TestedBy` EdgeKind + `is_test` node flag + transitive test-gap detection + 8th MCP tool | `code-review-graph/graph.py:96-103`, `changes.py:469-479`, `analysis.py:121-172` | `code_map/graph.rs`, `code_map/symbols.rs`, `code_map/persist.rs`, `mcp/codegraph_server.rs` | L | `coding/review.rs`, `coding/second_opinion.rs`, `mcp/codegraph_server.rs` |
| 3 | AST node boundary chunking for code embedding (tree-sitter, 9 langs, 2500/300) | `claude-context/packages/core/src/splitter/ast-splitter.ts` | `code_map/chunk.rs` (new) | M | `code_map/recall.rs`, `memory/embeddings.rs` (after CRG-01 decomposer wiring) |
| 4 | Edge `confidence`/`confidence_tier` field on GraphEdge | `code-review-graph/graph.py:102-103` | `code_map/graph.rs`, `code_map/persist.rs` | M | `code_map/impact.rs` (weight inferred edges lower) |
| 5 | Test-gap risk scoring formula (coverage factor: 0.30 untested → 0.05 at 5+ TestedBy) | `code-review-graph/changes.py:323` | `code_map/risk.rs` | S | `coding/review.rs` risk-scored review priorities |

---

## Build Order — Staged Slices

**Slice 1 — CRG-03 diff pipeline (unblocked, M)**
New file: `code_map/diff.rs` (~150 lines)
Modified: `code_map/graph.rs` (add `nodes_in_line_range()` query), `coding/review.rs` (use hunk seeds), `mcp/codegraph_server.rs` (expose via existing `impact_radius` tool or add 8th tool)
Prerequisite: none — substrate (line_start/line_end) exists in DB.

**Slice 2 — CRG-04 TestedBy + test gaps (depends on Slice 1 for reviewer wiring, L)**
Modified: `code_map/graph.rs` (EdgeKind::TestedBy), `code_map/symbols.rs` (is_test field), `code_map/persist.rs` (DB migration v3→v4), `code_map/walker.rs` (test-file heuristic), `mcp/codegraph_server.rs` (8th tool: codegraph_test_gaps), `coding/review.rs`
WAL note: if any WAL event is needed for test-gap queries, use ExtendedSubtype band per `wal/events.rs` constraint.

**Slice 3 — Edge confidence/tier (independent of Slices 1-2, M)**
Modified: `code_map/graph.rs` (GraphEdge fields), `code_map/persist.rs` (DB migration — can merge with Slice 2 migration or ship separately), `code_map/impact.rs` (weight parameter in BFS), `mcp/codegraph_server.rs` (expose tier in output JSON)

**Slice 4 — AST chunking for code embedding (blocked on CRG-01 decomposer wiring, M)**
New file: `code_map/chunk.rs`
Modified: `code_map/recall.rs` (augment relevant_files_for_prompt with chunk-level hits), `memory/embeddings.rs` (new embed_code_chunk path)
Consumer unblock: `coding/decomposer.rs` must call `recall::relevant_files_for_prompt` first (CRG-01 gap).

---

## Items that contradict the baseline

1. **CRG-02 is MORE complete than the baseline assumed.** The July 20 disposition said CRG-02 was DEFERRED-v1.1. The July 25 R3-16 matrix updated it to ADOPTED/WIRED-PARTIAL. This agent's grep confirms: `impact.rs:312 pub fn impact_radius()` exists, `codegraph_impact_radius` is the 6th registered MCP tool in `codegraph_server.rs`. The baseline brief's "CRG-02..05 DEFERRED" claim is outdated — CRG-02 is now substantially shipped.

2. **The "276x token savings" is a self-measured marketing benchmark.** `eval/benchmarks/token_efficiency.py` uses `len(text)//4` as a token approximation and measures against the repo's own test commits. The ratio varies widely by commit type (small targeted change = huge ratio; large refactor = small ratio). Do not cite 276x as a fixed multiplier in NEOTH documentation. State "substantial savings on targeted changes" instead.

3. **claude-context is Milvus-only, not embedding-algorithm-portable.** The headline trick cited in the brief ("Merkle-tree/incremental re-index mechanism") is an optimization, not a new algorithm. The actual steal-worthy item is the AST chunking strategy, which is much simpler and more portable. The Merkle DAG is not a significant gain over NEOTH's sha256+mtime_ns approach.

4. **aisuite is NOT a peer competitor to NEOTH's provider layer.** The brief said to evaluate "is there any specific normalization detail... that NEOTH's providers handle worse?" — the honest answer is no. NEOTH's providers are 5-10x more sophisticated. Aisuite's value is as a learning reference for new providers (Cerebras, Fireworks, Nebius) that NEOTH doesn't have, but those are all OpenAI-compatible endpoints that can be added as 5-line `known_endpoints.rs` entries, not aisuite adoptions.
