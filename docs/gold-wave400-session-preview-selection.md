# W400 - canonical session-preview acceptance selection

GOLD-LF-P1-20 already has the canonical source path: transcript_store reads
latest visible raw_turns without migration; panel_logic sanitizes and bounds
the preview; main.rs refreshes it on send/completion/reload and rejects stale
session-switch completions. No product or Slint change is part of this batch.

The earlier admitted Group780 and GUI135 selections did not execute this
parent's own named cases. The current matrix now selects four native store
cases and eight GUI cases, recorded under wave400SessionPreviewAcceptance.

Native coverage verifies read-only ordered/sanitized history, isolated latest
turns, empty/control-only tails and legacy stores without raw_turns.
Five panel tests cover redaction, whitespace/grapheme bounds, completion/delete,
reload/session isolation, legacy labels and corrupt-store error propagation.
Three chat_subprocess_tests cover send before probe, stale A/B/live generation
fences and the existing Rust/Slint read-only selection contract.

All twelve existing cases are ordinary test-only fixtures, with no per-OS or
feature restriction. Four join the grouped native lane; eight join the
universal GUI list. Linux now selects113 universal plus30 platform cases=143;
macOS lists113 universal plus26 platform cases=139. The separate native macOS
harness count is unchanged. Source SHA binding and exact one-test discovery
remain mandatory; no test or assertion is removed.

P1-20 remains open until its focused actual terminals are admitted. The
existing GUI135 package result is supporting evidence, not proof that these
newly selected cases ran. Broader release gates remain separate.
No local executable validation ran under the workstation BSOD hold.
