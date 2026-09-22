# W233 — Buddy TaskDelegate assignment controls

The existing W229 CLI/RPC assignment boundary now has real Buddy controls for an
explicit authenticated Peeroxide key. Inspect accepts a strict optional receipt:
null means no stored assignment and effective default deny at CAS revision zero.
Allow and Deny/reset use the exact inspected key and full u64 revision. Deny is a
new durable revision, not deletion or a reset of the concurrency counter.

Mutation receipts must match the key, requested boolean and expected revision + 1
without overflow. A later fresh revision may describe a different writer. A lower
revision, equal-revision conflict or failed readback cannot invalidate a proven
commit: its receipt remains visible as last known, while further mutation is
blocked until a new valid inspection. Unresolved membership revocation also
blocks actions. Input edits invalidate only projection binding; they cannot
release the busy ownership of a still-running operation. A→B→A is generation
fenced. Worker-start errors release busy with an explicit failure.

Three behavior unit cases cover strict receipts, absent state and invalid object
projection. Four real fake-CLI GUI fixtures exercise the actual callbacks:

- w58_gui_callback_runtime_tests::w233_task_delegate_set_owns_busy_across_edits_and_fences_stale_completion
- w58_gui_callback_runtime_tests::w233_invalid_fresh_readback_keeps_committed_receipt_and_fences_mutation
- w58_gui_callback_runtime_tests::w233_task_delegate_callback_fixture_covers_conflict_receipt_and_newer_readback
- w58_gui_callback_runtime_tests::w233_task_delegate_inspect_null_projects_effective_default_deny

The fake CLI validates exact argv, requested boolean and expected revision. It
covers a blocked mutation, input replacement, wrong receipt boolean/revision,
backward/conflicting/later readback, readback failure, and null→first commit at
revision one followed by durable Deny/reset at revision two. Waits are bounded. Root corrected fixture logging/modes and a
zero-revision expectation before publication. A self-referential source-string
test was removed; existing native parity contracts verify the real handlers.

All four runtime cases are registered in Linux libtest and the explicit macOS
native harness, whose exact inventory/discovery verifier grows from26 to30.
The canonical GUI lane grows to97 universal +26 Linux cases =123. Windows retains
its universal source/reducer coverage; these shell fixtures are Unix-only.
Independent focused source/delta review passed; actual Hosted compile and GUI
execution remain pending. No local parser, formatter, compiler or test ran.

## Design and acceptance boundary

GUI AGENTS, PRODUCT, DESIGN, COMPONENT_API, lint_rules and AUDIT_CHECKLIST were
read. Controls reuse the existing line edit/buttons, Theme spacing/colors/fonts
and existing cluster card. Copy distinguishes absent, working, committed,
unconfirmed and failed states without relying on color. Source/text review does
not establish rendered layout, scaling, keyboard focus or screen-reader behavior;
those checklist rows and exact-head GUI gates remain incomplete. No full GUI or
release approval is claimed. GOLD-LF-P2-18 remains open for its wider parity scope.
