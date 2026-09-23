# W554/W557: shared production Wizard callback and admitted GUI evidence

Run35929972686 at6146f6a4becf780a035e087aa4ac4f15d07284bf executed148GUI
fixtures:145passed,3failed,0missing. Root verified all three GitHub artifact
ZIP digests,28Git source/input bindings and148individual actual test terminals.
The selected plan, ordered receipts and totals reconcile. Permanent evidence:
[gold-wave557-gui148-terminals.json](verification/gold-wave557-gui148-terminals.json).
The crash-child test legitimately prints two `running 1 test` headers while
retaining exactly one parent result. Inline fixture Git output is distinguished
from the final test terminal; no status is inferred from result.json alone.

The cancellation fixture failed after real hosted daemon cancellation because
it registered only the wizard mutation callbacks and omitted Finish. The
production frozen Finish guard itself already correctly refused completion.
The daemon-loss fixture failed earlier: `discover` reads a retained descriptor;
a killed process can leave that descriptor on disk without being reachable.

The corrected implementation factors production Finish registration into
`register_wizard_finish_callback`. It runs the existing frozen guard/status
before invoking the unchanged normal completion body. Both fixtures install
that same registration with a counted normal body. After cancellation/loss,
they require no normal completion calls, no operation in flight and the exact
production reconciliation status. The loss case also requires the retained
controller's actual same-boot OpenOrResume request to fail. Existing mutation,
cancellation/drain and freeze assertions remain. Independent review approved.

The unrelated W480 consumer failed before provider start. W550 at a7019b9e
already enables the reviewed test provider's W41 effect-start capability; the
GUI6146 source predates that fix. Its passing rerun remains pending.

P1-18 remains open until both corrected criterion-specific GUI terminals pass.
The whole surrounding GUI job need not pass for independent P1-18 admission.
No new roadmap acceptance is claimed by source review. Road remains1044checked,
278open,2partial; WS-LF37done/81open. Inventory native1215,Group934+GChat4 and
GUI148Linux/144macOS is unchanged. No Slint or local executable validation.
