# QUELLEN Adoption Report — codegraph → NEOTH
_Date: 2026-05-21 | Analyst: Claude Sonnet 4.6 (codex-agent)_

---

## 1. What Is codegraph?

`@colbymchenry/codegraph` v0.9.2 — a TypeScript/Node MCP server that
pre-indexes a codebase into a **directed multi-edge SQLite graph** and
exposes it to AI coding agents (Claude Code, Cursor, Codex CLI, Hermes)
via 8 MCP tools. MIT license, 100% local, zero-config.

---

## 2. What Graph Model It Builds

### 2a. Node kinds (22 types)
`file | module | class | struct | interface | trait | protocol |
function | method | property | field | variable | constant | enum |
enum_member | type_alias | namespace | parameter | import | export |
route | component`

### 2b. Edge kinds — the full set

| EdgeKind | Semantics |
|---|---|
| `contains` | parent→child in containment tree (file→class→method) |
| `calls` | function/method → called function/method (call-graph) |
| `imports` | file → source file (import-graph) |
| `exports` | file → exported symbol |
| `extends` | class/interface → parent (type-hierarchy) |
| `implements` | class → interface (type-hierarchy) |
| `references` | generic reference to another symbol |
| `type_of` | variable/param → its type node |
| `returns` | function → return type |
| `instantiates` | call site → class being constructed |
| `overrides` | method → parent method being overridden |
| `decorates` | decorator → decorated symbol |

**NEOTH today tracks: zero edges.** It stores `(symbol_name, kind,
file, line)` but no relationships at all. Every edge kind above is
absent from `code_map_symbols` schema.

### 2c. Graph operations exposed
- **callers(fn)** — incoming `calls` edges, recursive BFS up the call
  tree to configurable depth
- **callees(fn)** — outgoing `calls` edges
- **impact(symbol)** — multi-edge BFS outward: everything reachable
  from a symbol across all edge kinds (impact radius for change analysis)
- **context(symbol)** — ancestors + children + type edges + import edges
  around a focal node
- **findCircularDependencies()** — DFS cycle detection over import graph
- **getFileDependencies / getDependents** — import-graph traversal

---

## 3. How It Indexes

**Engine**: `web-tree-sitter` WASM (not native, no bindgen). Grammars
ship as `.wasm` blobs; the four non-standard ones (Lua, Luau, Pascal,
Scala) are bundled in `src/extraction/wasm/`. All other languages use
`tree-sitter-wasms ^0.1.11`.

**Process**:
1. Gitignore-aware file walker (uses `ignore` npm package, same
   semantics as git)
2. Per-language tree-sitter query extracts nodes + edges from AST
3. Post-extraction resolution pass: unresolved references resolved by
   name-matching and path-alias lookup
4. SQLite + FTS5 (node `name`, `qualified_name`, `docstring`,
   `signature`)
5. OS file-watcher (native events) → incremental re-index on save

**Languages supported**: TypeScript/JS/JSX/TSX, Python, Go, Rust,
Java, C#, PHP, Ruby, C, C++, Swift, Kotlin, Scala, Dart, Svelte, Vue,
Liquid, Pascal/Delphi, Lua, Luau (22 total).

---

## 4. Operator-Facing UX

| Surface | Detail |
|---|---|
| CLI | `codegraph init` / `codegraph sync` / `codegraph status` / `codegraph install` |
| MCP server | 8 tools: `codegraph_search`, `codegraph_context`, `codegraph_callers`, `codegraph_callees`, `codegraph_impact`, `codegraph_node`, `codegraph_files`, `codegraph_status` |
| Installer targets | Claude Code, Cursor, Codex CLI, opencode, Hermes Agent |
| Storage | `.codegraph/codegraph.db` per project, WAL mode, node's built-in `node:sqlite` |

---

## 5. Feature Map Against NEOTH K-Repo-Map

### 5a. SKIP-DUPLICATE — NEOTH already has this

| Feature | NEOTH path |
|---|---|
| Gitignore-respecting file walker | `SRC/neothd/src/code_map/walker.rs` — walker uses `ignore` crate (same semantics) |
| Per-language symbol extraction (function/class/method/struct/enum/trait/interface) | `SRC/neothd/src/code_map/symbols.rs` — regex-based, covers Rust/Python/TS/JS/Go/Java/Kotlin/Swift/C/C++/C# |
| SQLite persistence with FTS5 fuzzy search | `SRC/neothd/src/code_map/persist.rs` — `code_map_symbols` + FTS5 index |
| `relevant_files_for_prompt` context assembly | `SRC/neothd/src/code_map/recall.rs` — identifier extraction + path-keyword scoring + composite rank |
| 1 MB file-size skip | `walker.rs` (has oversize_skipped counter in ScanReport) |

### 5b. SKIP-OUT-OF-SCOPE

| Feature | Reason |
|---|---|
| `web-tree-sitter` WASM runtime (Node.js) | NEOTH is a Rust binary; cannot embed a Node runtime. The WASM grammar approach is TypeScript/Node-specific. |
| MCP server process model | NEOTH exposes tools via its own CLI/GUI skill system, not a separate MCP server process. |
| OS file-watcher auto-sync | Phase-3 scope for NEOTH; not a current gap. |
| Svelte/Vue/Liquid/Luau/Twig extractors | Not in NEOTH's target language set today. |
| Framework-specific extractors (NestJS, Drupal route/hook detection) | Out of scope for current NEOTH operator use cases. |

### 5c. **ADOPT-AS-CORE** — gaps in NEOTH that codegraph fills

All five items below are absent from NEOTH's `code_map` entirely.

---

#### [HIGH] CG-1: Call-graph edge extraction

**What codegraph does**: For every `call_expression` in the AST,
emits a `calls` edge `(caller_node_id → callee_node_id)` after
name resolution. Rust extractor uses `callTypes: ['call_expression']`.

**What NEOTH has**: `code_map_symbols` has no `edges` table. Zero call
relationships stored.

**NEOTH gap**: `relevant_files_for_prompt` can surface the file where
`auth_middleware` is defined; it cannot answer "what calls
`auth_middleware`?" or "what does `auth_middleware` call?" That context
is essential for impact analysis when the operator asks the agent to
modify a function.

**Proposed path**: `SRC/neothd/src/code_map/edges.rs`

**Schema addition** (migration on top of current `code_map.db` v1):
```sql
CREATE TABLE code_map_edges (
    id      INTEGER PRIMARY KEY,
    kind    TEXT NOT NULL,  -- 'calls' | 'imports' | 'extends' | 'implements'
    src_sym INTEGER NOT NULL REFERENCES code_map_symbols(id) ON DELETE CASCADE,
    dst_sym INTEGER REFERENCES code_map_symbols(id) ON DELETE SET NULL,
    dst_name TEXT NOT NULL,   -- unresolved name (fallback)
    dst_file TEXT,            -- resolved file path (nullable until resolve pass)
    line    INTEGER NOT NULL
);
CREATE INDEX idx_edges_kind_src ON code_map_edges(kind, src_sym);
CREATE INDEX idx_edges_kind_dst ON code_map_edges(kind, dst_sym);
```

**Implementation note**: NEOTH's extractor is regex-based, not AST.
Call-site extraction via regex is feasible for Rust (`ident(` patterns)
and Go/Python at ~80% precision — good enough for recall ranking. Use
the same regex-pass approach as `symbols.rs` for Phase 1; flag Phase 2b
for tree-sitter upgrade when the WASM build cost is accepted.

---

#### [HIGH] CG-2: Import-graph edge extraction

**What codegraph does**: For every `use_declaration` (Rust),
`import`/`require` (TS/JS), `import` (Python), emits an `imports` edge
`(file_node → imported_file_node)`. After resolution, enables
`getFileDependencies` and `getDependents`.

**NEOTH gap**: NEOTH knows which files exist; it does NOT know which
files depend on which. The context assembler in `recall.rs` ranks by
symbol name overlap only — it cannot boost a file because the already-
selected file imports it.

**Proposed path**: `SRC/neothd/src/code_map/edges.rs` (same module as CG-1)

**Minimum viable**: Rust `use ` lines + Python `import ` / `from `
lines + TS/JS `import ` statements. Regex extraction, store as
`kind='imports'` rows. Wire into `recall.rs` scoring: if file A is
selected as relevant and file B is imported by A, boost B's score by
`+0.5` to pull its context in automatically.

---

#### [HIGH] CG-3: Type-hierarchy edges (`extends` / `implements`)

**What codegraph does**: Emits `extends` and `implements` edges by
detecting inheritance syntax per language (Rust trait bounds, Java
`extends`/`implements`, TS interface extension, etc.).

**NEOTH gap**: A user query "how does `UserService` work?" today
surfaces the file and the symbol, but not the interface it implements
or the base class it extends. The agent must grep separately.

**Proposed path**: `SRC/neothd/src/code_map/edges.rs` (same module)

---

#### [MEDIUM] CG-4: Qualified names + containment hierarchy

**What codegraph does**: Stores `qualified_name` as the full path
`src/auth/mod.rs::AuthService.check_token`. The `contains` edge models
`file→class→method` so callers/callees can be restricted to one class
or module.

**What NEOTH has**: `code_map_symbols` stores `name` only (e.g.,
`check_token`). Two methods with the same name in different structs are
indistinguishable in FTS queries — returns both, no disambiguation.

**Proposed path**: Extend `Symbol` struct in
`SRC/neothd/src/code_map/symbols.rs` to add `qualified_name: String`
(e.g. `"AuthService::check_token"` for Rust, `"AuthService.check_token"`
for Python/TS). Store in `code_map_symbols.qualified_name TEXT`. Extend
FTS index to cover it.

**Impact**: Fixes false positives in `relevant_files_for_prompt` when
`name` collides across files.

---

#### [LOW] CG-5: BFS caller/callee traversal queries

**What codegraph does**: `getCallers(nodeId, maxDepth)` — recursive
incoming-`calls` BFS. `getCallees` — outgoing. `getImpact` — multi-
edge BFS across all edge kinds up to radius N.

**NEOTH gap**: No edges → no traversal. Blocked on CG-1/CG-2/CG-3.

**Proposed path**: `SRC/neothd/src/code_map/graph.rs` — implement
after `edges.rs` is shipped. Expose as:
- `callers(conn, sym_id, max_depth) -> Vec<Symbol>`
- `callees(conn, sym_id, max_depth) -> Vec<Symbol>`
- `import_chain(conn, file_path, direction) -> Vec<String>`

Wire into `recall.rs::relevant_files_for_prompt` as a graph-expansion
step: after finding seed files by name, BFS 1-hop callers + importers
and add them to the candidate set with a `graph_boost` score.

---

## 6. Implementation Priority

```
CG-1 (call edges) + CG-2 (import edges)    ← one combined PR, same table
CG-3 (type-hierarchy edges)                ← same PR or +1 day
CG-4 (qualified names)                     ← schema migration, ~0.5 day
CG-5 (BFS traversal + recall integration)  ← blocked on CG-1..CG-3
```

Estimated total: 4–6 engineering days in Rust. No new crate deps needed
(all regex, same `rusqlite` + `regex` already in lockfile). Tree-sitter
upgrade deferred to Phase 2b — regex gets 80% of the value at 0 build-
time cost.

---

## 7. What NOT to Port

- The Node.js / WASM runtime and all TypeScript extraction code — NEOTH
  is a Rust binary.
- The MCP server process — NEOTH exposes graph queries through its own
  skill/slash-command layer.
- The framework-detection layer (NestJS, Drupal, SvelteKit routes) —
  NEOTH is not a web-framework code assistant.
- The installer / Claude-MD template writer — NEOTH has its own wizard.
- The OS file-watcher auto-sync — defer to a later phase.

---

## 8. Reference Paths

| Subject | Path |
|---|---|
| NEOTH walker | `SRC/neothd/src/code_map/walker.rs` |
| NEOTH symbol extractor | `SRC/neothd/src/code_map/symbols.rs` |
| NEOTH SQLite persistence | `SRC/neothd/src/code_map/persist.rs` |
| NEOTH recall / context assembly | `SRC/neothd/src/code_map/recall.rs` |
| Codegraph schema (reference) | `QUELLEN/codegraph/src/db/schema.sql` |
| Codegraph edge traversal (reference) | `QUELLEN/codegraph/src/graph/traversal.ts` |
| Codegraph graph queries (reference) | `QUELLEN/codegraph/src/graph/queries.ts` |
| Codegraph Rust extractor (reference) | `QUELLEN/codegraph/src/extraction/languages/rust.ts` |
| Codegraph types/EdgeKind (reference) | `QUELLEN/codegraph/src/types.ts` |
