# W407 cluster operation inventory repair

## Finding

The nested-operation guard in SRC/neothd/src/cli/parity_drift.rs enumerates
the live Clap leaves below every capability represented in OPERATION_INVENTORY.
The cluster task-delegate inventory previously represented only:

- cluster task-delegate show
- cluster task-delegate set

The current ClusterTaskDelegateAction also contains these seven real leaves:

- cluster task-delegate scope-show
- cluster task-delegate scope-set
- cluster task-delegate scope-reset
- cluster task-delegate outbound-show
- cluster task-delegate outbound-set
- cluster task-delegate outbound-reset
- cluster task-delegate outbound-dispatch

That mismatch is the direct cause of
cli::parity_drift::operation_inventory_tracks_live_nested_cli_leaves failing.

## Repair

W407 adds one cfg(feature = "cluster") operation-inventory entry for each of
the seven leaves. Every added entry is Unwired with missing callback, handler,
dispatch token, receipt, and readback evidence.

The Buddy Config panel has verified coverage only for the unscoped peer
assignment through task-delegate show and set. Its deny/reset control acts on
that unscoped assignment. It does not expose:

- an exact skill/channel/account scoped authority projection or CAS editor;
- a scoped deny-tombstone reset;
- outbound route projection, allowed/priority/revision mutation, or reset; or
- live authenticated outbound task dispatch with operation/task/prompt input
  and receipt/readback.

The entries use buddyconfig as the truthful adjacent product surface so the
ledger displays the delivery gap. They do not claim that this panel implements
the respective CLI leaves.

## Scope and validation

The production repair changes only SRC/neothd/src/cli/parity_drift.rs. This
record and the required recovery log preserve its evidence boundary. The
repair neither changes cluster CLI behavior nor adds GUI/Buddy capability.

Static inspection confirmed the exact seven action variants in
SRC/neothd/src/cli/cluster.rs and the existing Buddy Config callbacks for only
the unscoped show/set path. No local parser, compiler, formatter, test,
runtime, browser, download, or network command was run; the BSOD hold remains
local-only.

Hosted validation is permitted now. Run the focused
cli::parity_drift::operation_inventory_tracks_live_nested_cli_leaves test in a
hosted build. Its acceptance condition is that the cluster inventory and live
Clap leaf set match while the seven unresolved GUI/Buddy gaps remain visible
as Unwired rather than being reported as verified parity.
