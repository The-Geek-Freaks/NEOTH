# Real producer delivery, Buddy assignment parity and grouped execution

W480 connects the existing three-chunk W458 producer regression to actual
desktop consumers. The core fixture is shared by its original native test and
the explicit `gui-bridge-test-support` feature. It runs the real daemon producer,
filesystem hooks, runtime sink, authenticated Main/Buddy attach streams and WAL
drain. Its typed protocol frames pass through the existing private bridge
mapper; the GUI replay adapter forwards only those captured events.
The subscriptions retain the actual initial attach cursors, and the adapter
checks their boot/turn/surface/generation before forwarding only events after
the requested cursor. The capture is a Main-origin turn with a real separate
Buddy subscription; it does not claim to exercise Buddy-origin admission.

The GUI test invokes the real Main and Buddy callbacks with a fresh pair of
surfaces for each operation. It requires actual attach and terminal progress.
Block must expose no provider text, completion or preview. Replace must render
exactly `first ordinary chunk; [REDACTED]; third ordinary chunk`, including the
Buddy recent-lines surface and a nonempty Local CLI preview. Both captures
require one provider invocation, three consumed source chunks and an observed
post-provider hook. The source secret is absent from the bridge events and all
inspected display text. The original native test retains accepted-body digest,
replay identity and the actual `HOOK_BLOCKED` WAL causation assertions.

The test is registered in the Linux/macOS selection and macOS native callback
harness. No Slint file or production event shape changes. Stream finalization
receipts, lifecycle receipts and response-feedback targets retain their existing
distinct meanings. P2-26a remains open until the new consumer test actually passes
with its relevant source binding.

## Buddy assignment commands

W485 exposes `neoth buddy cluster task-delegate` by reusing the canonical
`ClusterTaskDelegateAction` directly. The nested grammar includes unscoped,
scoped and outbound show/set/reset operations and outbound dispatch. Buddy
forwards the parsed action and output format to `cli::cluster::run_cluster`.
There is no second membership-store or RPC mutation implementation.

The focused cases cover lossless scope/account/priority/revision parsing and
entry into the canonical dispatcher. Existing authority, CAS, daemon ownership
and no-live-fallback behavior remain owned by the canonical cluster path.
P2-18 remains open: scoped/outbound GUI controls and receipt/readback presentation
are still missing from the current surface contract.

## Grouped hosted execution

The admitted Group885 log at d938 contains a first compilation of 7m59s and
1,769 subsequent Cargo completion messages totaling 822.12 seconds. W484 removes
those repeated Cargo invocations. The hosted job compiles the library test
target once with locked dependencies and selects exactly one matching test
artifact from Cargo's structured output. Missing or ambiguous artifacts stop
the run. The binary choice is retained as a receipt.

Each selected identity is still listed exactly and executed in a fresh process
from the same package directory Cargo uses. Exact selection, one test thread,
180-second per-test limit, ten-second forced termination grace, failure inventory,
source/input bindings and individual log markers remain. Parent-shell receipt
loading avoids losing the selected executable inside the logging pipeline.
Compiler failures retain raw JSON/stderr and bounded readable diagnostics.
The first hosted execution must establish the new workflow's actual result;
the measured removed overhead is not a claimed end-to-end speedup.

## Windows parent-substitution follow-up

Run `35911460507` at `9abb52d5` compiled and executed all 16 selected Windows
regressions: 15 passed and the same retained-parent fixture failed. The hook's
ordinary path rename now returned Win32 5 (access denied), whereas the previous
run returned Win32 32 (sharing violation). This is a changed failure, not proof
that the parent-substitution test passed or that its cause is fully resolved.

W486 changes only the fixture hook. It opens the directory through its retained
namespace and requests the same native, handle-relative POSIX rename facility
already used by the storage implementation. Replacement creation is also
capability-relative. The original assertions still require publication inside
the displaced bound parent while the replacement's marker remains untouched.
Production publication, authority handles and the test identity are unchanged.
The hosted rerun determines whether this exercises the intended Windows race.

## Verification boundary

The publication inventory is 734 source paths, 1,183 universal native identities,
888 grouped identities, 115 universal GUI identities plus 31 Linux/27 macOS
identities, and 31 macOS native callbacks. Road remains 1,039 complete, 283 open
and two partial. Local validation is restricted to text, hashes, JSON and Git
under the BSOD hold; compiler, formatting, contract and behavior execution run
only on GitHub.
