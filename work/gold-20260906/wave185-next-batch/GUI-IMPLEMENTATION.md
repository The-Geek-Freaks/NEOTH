# W185 GUI implementation receipt

## Wire boundary

Resources reads `neoth --output json models ollama status`. It strictly accepts schema version 1 and projects the core-owned endpoint, inventory, operation and readiness fields. The UI renders **Ready (probe verified)** only for the daemon `ready` readiness variant. TCP reachability, tags/ps, action exit, and a pull/update acknowledgement do not render Ready.

Each Pull, Update, Prune, Cancel, and Retry callback uses the exact model or operation identifier from the rendered row. The callback requires a typed `LocalModelActionAck`, validates its schema/action/operation id, strictly parses its nested snapshot, then runs a new `models ollama status` command. Both acknowledgement and fresh status must bind to the same operation, and the fresh observation timestamp must not predate the acknowledgement snapshot; only then is the new projection painted. Retry first binds its exact selected **failed** terminal receipt to the retained model and underlying action. Cancel requires the acknowledgement operation id to equal the selected active operation id. A RAII singleflight guard prevents duplicate GUI actions and every failure clears both visible in-flight state and stale model rows.

## Native fixture target

Implemented callback fixture, for the root-owned macOS harness registry and dispatcher:

`w58_gui_callback_runtime_tests::w185_local_model_callbacks_require_typed_ack_and_fresh_readback`

It stages exact `models ollama` status/action paths in `w116_stage_fake_neoth`, invokes generated Resources callbacks, and proves duplicate singleflight, withheld status readback before the action acknowledgement returns, progress projection, rejected false and stale/foreign acknowledgements, failed-child retry, and exact retry/cancel operation targeting. The actual core contract is retained: Cancel and Retry acknowledgements name the underlying Pull/Update/Prune action, rather than a synthetic `cancel` or `retry` action.

## Design scope

The Resources additions use only existing `Theme.*` colors, typography, radii and spacing. Existing hardware cards are retained. Model rows expose installed size, core-reported loaded total footprint, and VRAM usage when present. `loaded.size_bytes` is not misrepresented as RAM; RAM remains explicitly unknown without an authoritative measurement. Active pulls without an inventory row are synthesized from the core active operation so progress and Cancel remain visible. The model rows expose accessible Pull, Update, Prune, Cancel, and Retry actions with disabled states; interrupted-unknown state has no Retry because core refuses it.

## Validation boundary

No local validation was run: current BSOD containment permits text reads, edits, and hashes only. Cargo, Slint parsing, formatting, test fixtures, GUI/runtime, Git, and network operations remain intentionally unrun.
