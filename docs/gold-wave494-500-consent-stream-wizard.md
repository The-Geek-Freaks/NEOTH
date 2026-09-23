# W494, W499 and W500 consent, stream and wizard follow-up

Group888 run35917416801 atc7b946f1 is fully admitted:888 executed,
885PASS/3FAIL/0missing,176 source/input bindings. The Buddy inventory guard now
passes. The remaining failures were the stale generated CLI reference, the CLI
Replace fixture reading the wrong output carrier, and actual GUI consent proof
validation. The generated reference from run35916213648 at3de1cfe was imported
only after source-head and SHA256 verification; its diff adds only the92 lines
for the new canonical Buddy task-delegate aliases.

## W500 actual consent boundary repair

The real ready and interactive consent producers mint a lowercase canonical
UUID, one dot and64 lowercase hexadecimal secret bytes. GUI protocol validation
incorrectly applied the unrelated opaque capability grammar, which excludes the
dot. Actual runtime.start admission therefore failed with opaque_token_shape.
The consent-proof validator now accepts only the exact minted grammar. Capability
validation stays unchanged. Two new regressions use actual ready/interactive
mints and reject malformed, noncanonical, oversized and deny-with-proof inputs.

## W499 CLI stream assertion repair

The deferred post-provider stream reaches the real CLI sink as StreamFrames.
The test incorrectly collected only ProviderDelta intermediate events. It now
decodes the actual frame block and requires one redacted delta at sequence1,
one content-free provider_done with exact hash/count, the final receipt and
Complete, secret suppression across every sink event, and no recovery call.
The Block fixture retains its opaque-error and drained HOOK_BLOCKED WAL proof.
No production streaming behavior was changed for this fixture correction.

## W494 real served wizard behavior

Two Linux/macOS GUI cases launch the actual hosted neoth binary with
serve --wizard-bootstrap. They invoke the registered production channel/Cancel
callbacks, require daemon acknowledgement, frozen controls, listener/child exit,
and no replay. A separate daemon-loss case terminates only its owned child,
waits for the real projection to freeze/unavailable, and refuses Finish replay.
The existing controller fixture now also verifies same-boot reconciliation and
rejects stale observations. Callback registration was extracted without changing
its behavior. Child polling, event pumps and failure cleanup are bounded.
The macOS native harness explicitly lists and dispatches both new cases.

P1-18 remains open until these composed behavior cases actually pass. No Slint,
visual tokens, layout, labels, focus or controls were changed. For the GUI design
lint/audit contract, those visual checks are N/A to this callback extraction;
implementation integrity was reviewed and runtime evidence remains pending.

## Already admitted Windows result

Run35917424314 atc7b946f1 passed all17 exact selected Windows cases. Root
verified25 artifact hashes, exact source/input blobs and all17 ordered terminals.
This includes both the explicit live-parent rename refusal and the independent
positive bound-parent publication with a writable decoy display path. It does
not claim a successful physical parent swap.

The next native selection is890 cases, with1185 universal native entries and
24Windows/33Linux/32macOS extras. GUI selection is148Linux and144macOS;
macOS custom harness33. W477 reviewed the source changes; hosted validation is
pending for the newly changed behavior. No local executable validation ran.
