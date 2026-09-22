# W234 — Actual native and GUI recovery

This is an evidence-driven repair batch, not a release acceptance claim.
Full CI35782661515 on74334d4b compiled both native platforms. Windows reported
17530passed/3failed/24skipped/1leaky; macOS reported17600passed/15failed/
25skipped. The actual per-case logs and digest-verified JUnit artifacts are
retained in the recovery workspace. W232 already repaired the three Windows
fixture issues. macOS shares two of those and has separate current failures.

## Admitted earlier behavior

Grouped34035791901843 on2ca988bb passed340/340 actual cases, all71 source
hashes plus matrix/lock/terminals checked. This includes all12 throughput cases.
Grouped34135792356371 onc20ed504 passed341/341, with the same exact binding
checks, including the actual W229 assignment RPC and gate-concurrency fixture.
Core35792359278 passed slim Clippy, test typecheck and CLI build/export; the
source/digest-verified generated reference is byte-identical to the checked-in
reference. These receipts do not cover subsequent source changes.

## Core repairs admitted to source review

- The retained-history rebind fixture now models v42 exactly instead of stamping
  v38 on a current schema containing v43 objects. It removes the precise v43
  objects and v44 additive field/index before exercising the real final rebind.
- Concurrent yearly receipt settlement recognizes the real AlreadyExists I/O
  error through the existing private-store error carrier's root cause. The
  existing bounded retained-directory read and exact byte comparison remain
  mandatory before AlreadyMatching; an error number alone never means success.
- The retained-child-CWD fixture canonicalizes both the observed directory and
  expected moved directory, accounting for macOS /var and /private/var aliases.
- The actual citation CLI integration fixture exports a canonical private home.
  Explicit redirected cache/home ancestors remain rejected by production.
  Separately, an absent canonical cache namespace now returns a read-only miss
  without creating the cache or lock; genuine path/read errors remain typed.

Independent focused source review passed these changes. Four exact cases are
added to the actual grouped selection, making398. One new universal cache case
makes843 native identities; the migration fixture is recorded only for Linux
and macOS. The process-level citation CLI contract still requires full native
CI; its behavior is not inferred from the new unit case.

## Actual Linux GUI evidence and workflow repair

GUI11635790648880 onb1ef0a66 is source-bound at105passed,8actual failures and
3discovery failures:113 cases actually executed. All17 GUI source bindings,
manifest, matrix, lock and individual result terminals were checked. This is
not a GUI pass. The errors reproduce in separate processes, so an earlier
failed test cannot explain later tests through shared process state.

Two canonical module names were wrong: the W184 reducer lives in
vault_mirror_gui_tests and the timeout guidance test in
chat_stream_phase::daemon_chat_presentation_tests. They are corrected without
removing either requirement. The third case is an integration harness already
specified by requiredGuiClassesByPlatform.Linux; the workflow now respects
that canonical override and builds/runs the exact --test target.

The reviewed workflow records each class and selector, retains exact discovery
and execution proof, verifies its own manifest entry, and applies one shared
75-minute budget plus90-second receipt reserve before every build/discovery/
execution command. An isolated compatible cache saves only fully compiled CLI
and GUI harness targets, including after behavior-test failures. It never
writes into the shared CI cache namespace.

Callback repairs in main.rs remain separate work pending review and Hosted
execution. Cancellation/WAL lifecycle repair is W235 and is excluded here.
No compiler, formatter, parser, test, product or GUI was executed locally.
Inventory535sources/843native/94GUI plus22Linux/22macOS extras/26macOS custom.
No Road checkbox is closed from these partial or source-only outcomes.
