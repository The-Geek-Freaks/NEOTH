# W54–W57 verification

## Scope and evidence boundary

The independently approved 18-path W54–W57 composition is formatted and
admitted on published W50/W52/W53 commit
`4409ff6c1b36f1c3ad921f8fb7df476e6e1411ad`. Source admission is retained in
`work/gold-20260906/wave54-57-admission-01.json`; the fresh pre-docgen source
capture contains 259 inputs. Subsequent reviewed repairs add the shared GUI
controller and canonical MCP commitment owner, for 20 changed source/configuration
paths. Final native Clippy, test build, the 2,580-test selected runtime and all
746 contract tests, GUI Clippy and Python45 have passed. The final source union
contains 260 inputs and eight executable hashes. Release acceptance remains
separate. No roadmap-closure claim follows.

W54 adds bounded root/generation-bound aggregate provenance for stored helper
or fixture, generated, unsupported-language and duplicate-target declarations.
The aggregate uses persisted facts; it does not invent unstored classifications
or infer relevance to an individual node from a root-wide count.
W54 rejects both aggregate exclusion provenance and nodes whenever an impact
test-gap outcome is rejected input. The two checks are independent, so a parsed
receipt cannot retain one evidence class by clearing the other. Root and
generation binding, bounded aggregate budgets, and read-only Doctor queries
remain part of the existing W54 boundary.

W55 makes chat/channel context outcome visibility durable: a request begins
`Unclaimed`, can become `Pending`, and reaches `Durable` only through the
single acknowledged append owner. For outcomes requiring a context receipt, provider dispatch waits for `Durable`.
Cancelling a waiter does not acknowledge the write: `Pending` remains pending
until the single append owner reports `Durable` or `Failed`. Append failure
fails closed; `Disabled` retains its zero-I/O path.

W56 derives an immutable generated-child impact-policy descriptor before MCP
binding, real authorization/catalogue/spawn, and `tools/call`. It preserves the
original JSON tool arguments and W53 base-descriptor provenance. A policy
change is represented by a new child descriptor; stale policy relaxation is
rejected before a new child/session authority is created.

W57 adds a default-off, read-only Doctor readiness check for the existing
outline route. Disabled configuration returns before registry or SQLite work.
Enabled inspection accepts only the shared exact generated descriptor, uses
the bounded physical-root lifecycle view, reports unavailable or fresh
root/generation state, opens no child/provider/network path, and does not
claim that any request was enriched.

## Current gate results

| Evidence | Result |
| :-- | :-- |
| 18-path composed custody, W54/W55/W56/W57 approval chain | APPROVE; formatted source admitted |
| Actual source admission and formatted-source hashes | PASS: 18 paths, retained admission receipt and fresh 259-input capture |
| Native Clippy | PASS: attempt07, `-D warnings`, 3m07s, minimum free 224.17 GiB, peak build working set 7.21 GiB |
| Native test build | PASS: attempt03, 4m05s, minimum free 219.95 GiB, peak build working set 11.37 GiB |
| Native 19-filter selection | PASS: attempt03, 2580 passed / 0 failed / 0 ignored in 182.71s; catalog 14,689 tests |
| Required W53, W55, and W56 fixtures | PASS: real outline gate/one receipt, Channel cancellation/one durable receipt, and immutable descriptor N/N/N+1 real-child dispatch |
| Seven contracts, including W52 headless-controller targets | PASS: final attempt02, 746 passed / 0 failed / 0 ignored; 2m52s compilation, minimum free 223.37 GiB, peak build working set 7.74 GiB; all 259 source inputs unchanged |
| GUI Clippy | PASS: attempt01, 7m57s, minimum free 219.22 GiB, peak build working set 11.68 GiB; existing 13 GUI test dead-code warnings and vendor warning remain |
| Python integrity/release/cadence gates | PASS: 19 + 11 + 8 + 7 = 45; Windows/macOS CI matrix limits verified |
| CLI doc generation | PASS: 1 / 0 / 0 from the final admitted native test binary; generated reference unchanged |
| Source and executable evidence | 260 final inputs, eight executable hashes; strict staged/current/source/artifact checks bind the 26 publication paths |
| Slint source lint | Retained W50/W52 PASS; every Slint input is unchanged in this batch |
| GUI rendering/accessibility/runtime and live provider/transport last mile | Not exercised by this batch; no such claim follows |
| CI, roadmap and release disposition | Previous published-commit CI is recorded below; new exact-commit CI and release acceptance remain separate. Counts unchanged: 1324 / 1014 / 308 / 2, raw310/pre-tag309 |

The final machine-readable records are
`docs/verification/gold-wave54-57-source-manifest.json` and
`docs/verification/gold-wave54-57-test-matrix.json`. Their evidence binds the
final successful attempts, exact selected test names, source snapshots and
retained logs. Only `SRC/_gui_lint.ps1` uses the explicitly recorded Git CRLF/LF
representation exception; all other staged source bytes match the executed
worktree bytes exactly. The direct-main publication receipt is retained in
`work/gold-20260906/wave54-57-publication.json` after the push is verified.

## Integration repairs and published-commit CI

The first selected runtime run exposed seven failures. Root admitted four
independently reviewed repair files before the fresh Clippy06 capture:

- The canonical MCP request commitment now includes the complete effective
  launcher descriptor, rather than only its id. This makes different immutable
  policy trailers produce different commitments while preserving canonical map
  ordering and the original tool arguments. Authorization and PreToolUse consume
  the same commitment; the descriptor is hashed, not emitted in the receipt.
- CLI and Channel cancellation fixtures count exactly one semantic unavailable
  context receipt across the shared WAL, allowing unrelated legitimate frames.
  Pending/replay/ack assertions remain intact. The empty-selection fixture now
  queries a marker absent from its seeded graph.
- An exact positive test observation remains known alongside visible inferred
  ambiguity. Stale, partial and capped inputs retain their unsupported status;
  capped root exclusions already set the direct API's `partial_graph` flag.

The final selected runtime passes with these repairs. Their preimages and
formatted postimages are retained in
`work/gold-20260906/wave54-57-root-runtime-repair-01/admission.json`.

The second run reached a later assertion in the W56 fixture. Independent
review identified a test-scope mismatch: SmartApprove starts a server-scoped
catalogue child, whose startup marker is not a per-call authorization receipt.
The final test keeps that marker empty, checks the complete descriptors
observed by both real children, and reconstructs N/N/N+1 request commitments
from those descriptors and the unchanged wire arguments. It retains the
rejected stale-policy change and retained-client checks. No SmartApprove
production API was changed. This final fixture correction is retained in
`work/gold-20260906/wave54-57-root-runtime-repair-02/admission.json`.

Four failed native Clippy attempts are retained as diagnostics. The repairs
pass the accepted impact-policy snapshot through the Chat call, remove one
dead assignment, restrict two compatibility wrappers to tests, simplify one
Doctor string expression, and update the affected baseline test calls. The
cancelled-route assertion does not require a debug representation of prompt
contents. The real W56 dispatch test keeps its process-wide environment lock
outside a current-thread runtime's async block, preserving exclusion until
the fixture and its environment-restoration guard finish.

The published `4409ff6c` Linux workspace Clippy job also found three unused
GUI operation getters and one fence method used only by tests. The getters
are removed and the fence method is test-only. This adds one shared GUI
controller to the 18-path feature batch. That correction was written during
Clippy04 by a worker before root admission; the 259-input comparison detected
exactly one changed file. Attempt04 is therefore diagnostic-only. Root
retained the preimage, verified and formatted the exact correction, and ran
attempt05 against a fresh, unchanged source capture.

Security run [34912040045](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34912040045)
passed on published `4409ff6c` in attempt2. Its only new blocking alert, #494,
was independently assessed and checked against that exact commit: the flagged
CLI table sink prints only payload-free outcome/rejection enums and a bool.
The single alert was dismissed as a false positive with that rationale, then
only the failed gate job was rerun. No query or source safeguard was disabled.
This result belongs to the published commit, not to the uncommitted batch.

Full CI on the same published commit completed with a Windows success and
the known Linux GUI dead-code failure above. macOS again timed out in its
100-minute workspace compilation step; tests did not execute. The log has no
compiler error or memory-failure diagnosis. A fallback cache restored, but the
failed compile skipped the cache post-save. This is separate from the guarded
local Windows validation and does not establish cross-platform acceptance.

## Fixture proof boundary

The executed local fixtures prove specific in-process
boundaries: W54 persisted rejected-receipt validation; W55 terminal receipt
settlement before the notification future is polled; and W56 real dispatch
through catalogue, spawn, stdio handshake, N/N+1 child bindings, and unchanged
`tools/call` JSON. W57's Doctor fixture checks disabled, unavailable,
incomplete, and fresh lifecycle states without repair. Their exact selected
names and source hashes are retained in the test matrix. They do not prove
rendered GUI behavior, accessibility, live
provider/transport effects, or release readiness.

## Composition custody

The composition contains four W54 files, the W55 `chat.rs` and
`serve_pipeline.rs` receipt overlays joined with accepted W56 policy threading,
ten W56 files, and three W57 files. The W57 `codegraph_server.rs` overlay is
bound to the declared W56 composed base; its two Doctor files are distinct
additions. The composition checkpoint records no conflict markers and an
independent APPROVE custody review. Rebase or source admission requires a
fresh canonical-preimage check.
