# SmallCode Audit — 2026-05-21

Source tree audited: `QUELLEN/smallcode/` (~24 MB, 101 source/doc files)
Reference: `QUELLEN/smallcode/README.md`, `COMPARISON.md`, `PLAN.md`,
`CHANGELOG.md`, `BONESCRIPT_INTEGRATION.md`, plus key runtime sources.

---

## §1 What SmallCode Is

SmallCode is a terminal-native AI coding agent (Node.js) designed from the
ground up to extract useful work from small local LLMs (7B–20B parameters,
4k–32k context windows). Its central thesis: frontier-model harnesses assume
large context and reliable JSON output; SmallCode compensates with aggressive
token budgeting, forgiving tool-call parsing, per-model capability profiles,
and an improvement loop (generate → lint/compile → retry → decompose → cloud
escalation) that makes tiny models competitive on single-file tasks. A dual
architecture splits a MarrowScript declarative cognition layer (compiled to a
deterministic runtime) from hand-written JS for TUI, tool implementations, and
session management. BoneScript integration collapses multi-file backend
generation into a single declarative `.bone` file.

---

## §2 Architecture Summary

The agent loop lives in `bin/smallcode.js` + `bin/model_client.js`. A user
turn triggers a four-stage pipeline: (1) heuristic complexity classification
(`src/model/router.js::estimateComplexity`) routes the call to fast/default/
strong/escalation model tiers; (2) a 2-stage tool router
(`src/tools/two_stage_router.js`) either shows all tool schemas (>16k context)
or presents a tiny `select_category` tool first and injects only the matching
category's schemas on the second turn (≤16k context, ~50% schema-token
reduction); (3) the tool executor validates, runs, and feeds results back with
output truncation; (4) an `EarlyStopDetector` (`src/governor/early_stop.js`)
scans the streaming buffer for repetition loops, patch spirals, and greeting
regression, injecting correction prompts or escalating to a full-file rewrite.
The context budget engine (`marrow/src/context/budget.ms`) enforces a 70%-of-
context ceiling on tool results, auto-summarises file contents to function
signatures when tight, and evicts history in priority order (old tool results
→ old assistant messages → system prompt sections). A per-edit undo stack
(`src/session/undo.js`) records before/after for every file write and patch,
allowing surgical per-edit rollback. The MarrowScript cognition layer
(`marrow/smallcode_cognition.marrow`) compiles deterministic routing, typed
prompts with retry/repair, cost policies, and self-critique capabilities from
a declarative source rather than hand-rolling these per feature.

---

## §3 Notable Patterns

All file references are relative to `QUELLEN/smallcode/`.

- **2-stage tool router** (`src/tools/two_stage_router.js`): category selector
  tool exposes only ~200 token description; full schemas inject on the second
  turn. Auto-selects mode based on `contextWindow <= 16384`. Env-override via
  `SMALLCODE_TOOL_ROUTING=direct|two_stage`. No equivalent in NEOTH today —
  Cerebellum currently sends full tool schemas on every dispatch.

- **Model profiles** (`src/model/profiles.js`): per-model TOML (or auto-
  detected by fuzzy name match) records `context_length`, `max_output`,
  `supports_tool_calling`, `tool_format` (native/hermes/json/xml/text),
  `strengths`, `weaknesses`. The router uses this to pick chat template +
  context budget cap + routing mode automatically. NEOTH has hemisphere
  provider binding (`cli/hemispheres.rs`) but no equivalent per-model profile
  struct that shapes prompt engineering decisions.

- **EarlyStopDetector** (`src/governor/early_stop.js`): three concrete
  degenerate-behaviour detections — repetition loop (O(tail) scan, 3× 50-char
  pattern), patch spiral (4 failures OR 6 total attempts on same file →
  force full-file rewrite), greeting regression (model loses context and
  outputs a greeting mid-task). On trigger: injects a corrective system message
  rather than aborting, so the model recovers without losing the turn. NEOTH
  has no equivalent; a stuck worker just becomes `Blocked`.

- **Forgiving tool-call parser** (`bin/smallcode.js` governor integration):
  tries JSON → YAML → regex extraction → natural language parse in sequence.
  On malformed call: shows 1-line error + correct schema, retries once. The
  `extensions/tmpl_repair_tool.ts` extension point drives a dedicated tiny-
  model repair pass. NEOTH workers currently receive well-formed API responses
  only (claude_cli via tmux + pane scraping); malformed output causes a failure
  rather than a repair attempt.

- **Complexity-driven model dispatch** (`src/model/router.js`): regex + length
  heuristics classify `fast | default | strong` before any LLM call. Configures
  three local model tiers + cloud escalation in `smallcode.toml`. NEOTH has
  `coding::classifier.rs` with a `Complexity` enum but the dispatcher does not
  yet route different model tiers — both hemispheres hit the same provider.

- **Context budget eviction order** (`marrow/src/context/budget.ms`): strict
  eviction priority (old tool results → old assistant msgs → system sections).
  Prevents context overflow silently corrupting the conversation. Known bug
  found + fixed in CHANGELOG 0.6.15: `midEst` was a `const`, so the eviction
  loop either evicted everything or nothing. NEOTH has no mid-session eviction
  mechanism; the WAL is append-only but in-memory conversation context sent to
  LLMs has no budgeting layer.

- **Per-edit undo stack** (`src/session/undo.js`): records full `before`/
  `after` content for every write + patch. `undoById(id)` allows surgical
  rollback of any specific edit, not just `git checkout -- .`. Stack is
  bounded at 50 entries. NEOTH stores patch files on disk per task
  (`worker.rs::WorkerOutcome.patch_path`) but no undo stack with per-edit
  granularity.

- **LSP integration** (`src/lsp/client.js`): auto-detects language server
  (typescript-language-server, pyright, rust-analyzer, gopls) from project
  files, sends `didOpen`/`didChange`, collects `publishDiagnostics`. Closes
  documents after reading diagnostics to prevent TS server OOM. Replaces
  shelling out to `tsc --noEmit`. NEOTH runs `cargo check` / `cargo test` via
  subprocess; no LSP client exists.

- **Secret redaction in tool output** (`src/security/sanitize.js`): pure-
  function recursive redaction of objects + strings before persistence.
  Pattern-based API key detection, `ALWAYS_REDACT_KEYS` set, ANSI/control-
  char stripping. Used in session persistence, trace recorder, MCP client,
  share/export, git context. NEOTH has WAL encryption + `WebhookVerifier`
  HMAC (`channels/webhook_verify.rs`) but no centralised tool-output redaction
  module.

- **edit_with_approval flow** (`marrow/features_1_6.marrow`): MarrowScript
  `flow edit_with_approval` pauses before applying any write, shows a diff
  preview, waits for `approve/reject/edit` with 5-minute timeout, executes
  backward compensation (`rollback_edit`) on reject. NEOTH's autonomy/consent
  system (`permissions::evaluate`) exists but is not wired into the coding
  worker write path.

---

## §4 Profile System Comparison vs NEOTH Autonomy Levels

SmallCode's "profiles" (`src/model/profiles.js`) are **model capability
profiles**, not permission/autonomy levels. They describe what a given LLM
can do (context window, tool call format, strengths/weaknesses) to drive
prompt engineering decisions. They are orthogonal to NEOTH's concept.

NEOTH's **autonomy levels** (strict/standard/elevated/full/custom from
`SPEC_user_adaptation.md` + `neoth_autonomy.md`) control what actions the
operator permits NEOTH to take without explicit consent. SmallCode has no
equivalent — it is single-operator, always-trusted.

SmallCode does have an analogous permission surface in a different form: the
`edit_with_approval` flow checkpoint is a runtime consent gate for file
writes, comparable to NEOTH's `PermissionToken<L>` gate. But SmallCode
doesn't model escalation levels; it treats every operator as "standard".

**Adoption verdict:** SmallCode's model-capability profiles (§ above) are
directly adoptable as a complement to NEOTH's provider system — they shape
prompt formatting, not permissions. NEOTH's autonomy levels have no
counterpart to adopt from SmallCode. The `edit_with_approval` flow is worth
examining for wiring into NEOTH's coding worker write path (see §5 #2).

---

## §5 Top 5 Things NEOTH Should Port/Adapt

Priority-ranked: highest value / lowest disruption first.

### #1 — EarlyStopDetector (degenerate-loop recovery)

**SmallCode source:** `QUELLEN/smallcode/src/governor/early_stop.js`  
**What it does:** Three runtime guards — repetition loop (tail-scan, O(tail)),
patch spiral (failure + attempt counters per file per turn), greeting
regression (context-loss detection). On trigger: injects a corrective system
message + switches strategy (patch → rewrite); does NOT abort the task.  
**NEOTH integration site:** `SRC/neothd/src/coding/worker.rs` — add a
`DegenGuard` checked after each provider response in the `Worker::execute`
loop. When triggered, transition task to `Blocked` + write a
`KANBAN_TASK_COMMENT` WAL frame with the stop reason + corrective injection
for the operator.  
**Scope estimate:** ~150 LOC (struct + 3 detection methods + WAL emit +
unit tests). Self-contained, no external deps.  
**Why high priority:** NEOTH workers currently have no recovery path when a
provider gets stuck. A blocked task with a clear reason is a much better UX
than a silent `Blocked` status.

### #2 — Per-model capability profiles in `coding::provider_worker`

**SmallCode source:** `QUELLEN/smallcode/src/model/profiles.js`,
`QUELLEN/smallcode/src/model/router.js`  
**What it does:** Fuzzy name-match against a TOML-backed profile table to
derive `context_length`, `tool_format` (native/hermes/json/xml), `max_output`,
`strengths`, `weaknesses`. Router uses `strengths` to pick Left vs Right
hemisphere automatically beyond the current heuristic classifier.  
**NEOTH integration site:** `SRC/neothd/src/coding/provider_worker.rs` +
`SRC/neothd/src/coding/classifier.rs`. Add a `ModelProfile` struct loaded
from `freedom.yaml::providers.<id>.profile` (or auto-detected from the
provider's model name). The dispatcher uses `ModelProfile.strengths` to
override hemisphere assignment when the operator hasn't pinned one.  
**Scope estimate:** ~200 LOC (profile struct + TOML loader + fuzzy match +
classifier integration + tests). The profile data itself can start as a
`const` table matching smallcode's exact entries — Qwen3 → hermes,
Gemma → native, DeepSeek → json, etc.  
**Why high priority:** NEOTH currently sends identical prompts regardless of
whether the backend is Qwen3-hermes or Gemma-native. Wrong tool format =
silent JSON parse failure in the coding worker loop.

### #3 — 2-stage tool router for small-context providers

**SmallCode source:** `QUELLEN/smallcode/src/tools/two_stage_router.js`,
`QUELLEN/smallcode/extensions/tmpl_classify_category.ts`  
**What it does:** When provider context ≤16k, sends a `select_category` tool
(~200 tokens) first; on response, injects only that category's full schemas
(~50% schema-token reduction). Env-override to force mode.  
**NEOTH integration site:** `SRC/neothd/src/coding/dispatcher.rs` — when
building the tool-call payload for `ProviderWorker`, check
`ModelProfile.context_length`. If ≤16384, inject category selector first
and buffer until category response, then inject filtered schemas.  
**Scope estimate:** ~180 LOC (category map + selector tool builder + dispatch
branching + integration test). Depends on #2 (ModelProfile) for context-
length gating.  
**Why useful:** NEOTH's coding session will route tasks to local Qwen models
with 8k–16k effective context. Sending all tool schemas at once eats 1/3 of
the budget before the task description.

### #4 — Centralised tool-output redaction module

**SmallCode source:** `QUELLEN/smallcode/src/security/sanitize.js`  
**What it does:** Pure-function recursive redactor. Pattern-based API key /
secret detection, `ALWAYS_REDACT_KEYS` deny-list, ANSI control-char strip,
path traversal block. Used uniformly across session persistence, MCP, trace
recorder, git context, share/export.  
**NEOTH integration site:** New `SRC/neothd/src/security/redact.rs` module.
Wire into: (a) WAL frame serialiser before writing `CODING_TOOL_RESULT`
frames; (b) session persistence (`recall::store`); (c) MCP tool output path
once it lands. The `webhook_verify.rs` HMAC primitives stay separate —
this is about output content, not request authentication.  
**Scope estimate:** ~120 LOC (redact_string + redact_value recursive +
path_safe + shell_escape_arg + unit tests against the pattern table). Port
smallcode's pattern list directly; Rust regex crate makes this straightforward.  
**Why useful:** NEOTH already stores operator secrets in WAL events (API keys
set via wizard). A coding worker that reads `.env` files and writes output to
a WAL frame could leak keys. This is a security gap.

### #5 — Improvement loop: validate → fix → escalate

**SmallCode source:** `QUELLEN/smallcode/marrow/bounded_loops.marrow`,
`QUELLEN/smallcode/extensions/tmpl_repair_tool.ts`,
`QUELLEN/smallcode/CHANGELOG.md` (0.6.x improvement loop cap fixes)  
**What it does:** After every file write: run `node --check` / compile / lint.
On failure: re-inject file + errors → ask model to fix (max 2 attempts). On
repeated failure: escalate to stronger model tier. The loop caps injected
content at 15% of context window (max 8000 chars) to prevent unbounded growth.  
**NEOTH integration site:** `SRC/neothd/src/coding/review.rs` +
`SRC/neothd/src/coding/worker.rs`. The `review.rs` `check_auto_promotable`
function already gates on `TestSummary`; extend it with a `validate_patch`
step that runs `cargo check --message-format=json` on the patched files and
feeds errors back to the worker for one retry. Cap injected diagnostics at
8000 chars. On second failure, escalate task to `Right` hemisphere (stronger
model) via a new `WorkerOutcome::Escalate` variant.  
**Scope estimate:** ~250 LOC across `review.rs` + `worker.rs` + a new
`validate.rs` subprocess helper. Cap logic is 5 lines; the retry flow
touches the dispatcher's task state machine (`dispatcher.rs`).

---

## §6 Things to Explicitly NOT Copy

- **MarrowScript / `.marrow` compilation layer.** SmallCode's entire cognition
  layer is built on a proprietary DSL (`marrowc compile`) that generates
  TypeScript runtime. NEOTH is Rust; the equivalent would be a proc-macro or
  code-gen tool. The actual patterns (retry, repair, routing) are worth
  porting, but the DSL is not. Port the compiled output patterns, not the
  source.

- **BoneScript integration.** BoneScript generates Node.js/TypeScript Express
  backends from a `.bone` declarative file. NEOTH does not generate web
  backends; its coding workflow targets general software engineering tasks. The
  "reduce 8-15 tool calls to 1-2" insight is relevant (see #3 tool router) but
  BoneScript itself has zero portability to Rust.

- **LSP client** (`src/lsp/client.js`). The LSP wire protocol implementation
  is 150+ lines of Node.js `child_process` + Buffer parsing. NEOTH already
  shells out to `cargo check --message-format=json` which provides structured
  diagnostics without a long-running LSP process. An in-process LSP client in
  Rust (`tower-lsp` / `lsp-types`) is feasible but is a large dependency with
  marginal value over `cargo check` for the Rust-centric coding workflow.
  Revisit when NEOTH's coding worker targets TypeScript or Python files.

- **TUI fullscreen rendering** (`src/tui/fullscreen.js`). SmallCode's TUI is
  built for a terminal-only product. NEOTH's GUI is Slint (R-1 roadmap). Do
  not port the alternate-buffer TUI — the GUI surface already covers this.

- **Session ID formula fix** (CHANGELOG 0.6.x: `9999999999999 - Date.now()`
  overflow). This was a JS-specific integer overflow bug that doesn't exist in
  Rust's u64 arithmetic. Noting only to confirm it is not a cross-language
  concern.

- **Bayesian governor / tool scorer.** CHANGELOG references a Bayesian
  learning tool scorer in the governor. The actual runtime file
  (`bin/governor.js`) was found but the Bayesian scoring logic was not present
  in the shipped source — it may be planned/partial. Do not plan a port until
  smallcode ships a working implementation to evaluate.
