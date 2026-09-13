# Wave 7 — native accepted-patch approval

This batch completes the remaining native Settings/Buddy patch-approval path
for `GOLD-LF-P1-05`. The public GUI route requests interaction; only a private
live-run broker and exact one-use response can satisfy the final required Gate.

## Behavior

The GUI reads the complete immutable accepted patch from the current broker,
bound to UI revision, run, approval ID, canonical repository, task, patch digest
and request binding. Generic events and snapshots contain metadata only.
Reject, expiry, cancellation, shutdown and consumption remove the preview.
Delayed events or responses for patch A cannot replace or close patch B.

Cancellation fences the controller synchronously before spawning the Core
delivery. The dispatcher refreshes physical repository identity after waiting,
validates the private grant, and acknowledges the authenticated TrustDecision
before creating a worktree. A GUI route without a broker has no apply authority.
The CLI-only confirmation marker remains private. No patch artifact is reread
as authority for the effect.

The shared Slint dialog has a read-only scrollable diff, explicit Approve/Reject,
one-use submitting state, contained forward/reverse keyboard traversal, Escape
and scrim rejection, and bounded content with reachable actions. Ordinary
confirmation dialogs retain their complete body text and scroll when necessary.

## Verification

The source manifest is `verification/gold-wave7-source-manifest.json`; selected
results and binary identity are `verification/gold-wave7-test-matrix.json`.
The final local gates pass: 582 Coding, 200 permissions, 29 Coding CLI and 10
production GUI-controller tests (821 executions, zero failures); fresh library
test build, Core check, GUI check including test modules, strict Clippy and
workspace formatting. The matrix records commands, durations and identities.
The full daemon library, native GUI test executable and release artifacts are
not claimed from these selected gates. The GUI controller harness imports the
actual production controller; the isolated Slint probe imports the actual
production ConfirmDialog without linking the full desktop test executable.

The real-WAL accepted path independently recomputes canonical-root/task/patch/
origin binding, checks it in metadata and authenticated replay, pauses after
Gate admission while no worktree exists, then releases the effect. Other tests
cover missing broker, rejection, cancel-first, root replacement during approval,
publication/consumption ordering, exact preview, replay and expiry.

The seven probe frames under
`work/gold-20260906/dialog-probe-attempt7/` were inspected. Normal layout shows
the diff; wheel scrolling exposes the final synthetic line 120 without changing
the full preview bytes. Small-window content scrolls and both responses remain
inside the card. The ordinary body is complete. Forward/reverse keys, pointer
actions, disabled controls, one-use submission and background isolation passed.
This is Slint software-renderer evidence, not Winit/GPU, OS accessibility-tree,
screen-reader, full MainWindow, installer or live-provider acceptance.

## Diagnostic repairs

Earlier failures remain diagnostic only: the missing public `Key::Enter` variant
was replaced with `Key::Return`; the probe sizes its software window before its
first frame; real input caught modal Tab leakage; visual inspection caught a
collapsed preview and clipped ordinary body. An explicit zero-height preview
and then a conditional card/body height binding cycle were removed. The final
geometry uses independent window/preview constraints. Strict Clippy exposed two
predicate simplifications and three sibling-test visibility errors. One runtime
fixture expected unsorted paths despite intentional production sorting; only
its expected order changed. The final source received independent review.

## Boundary inventory and release scope

The current final-effect inventory is documented in
`trust-decision-boundaries.md`. Waves 4–6 retain their source-bound evidence for
the existing HTTP/MCP/Todo/self-activation, daemon/cluster and durable-egress
paths. Wave 7 supplies the remaining native GUI path. Policy displays, preview
reads, scheduling probes and pre-admission queue filters do not create duplicate
final decisions. There is no claim of exactly-once physical external delivery.

The broader Gold checklist and exact-candidate cross-platform CI, Security,
CodeQL and artifact acceptance remain separate release requirements.
