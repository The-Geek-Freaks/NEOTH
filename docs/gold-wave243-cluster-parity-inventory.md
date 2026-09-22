# GOLD Wave 243 — Cluster CLI/GUI parity inventory

Scope: `cluster` feature leaf commands captured by `cli::parity_drift`. This is a source-only inventory produced during the BSOD validation hold; it does not claim executable validation.

| Leaf | GUI posture |
| --- | --- |
| configure, enable, disable | The settings UI uses a composite configuration transaction; the exact CLI leaves remain explicitly unwired. |
| confirm, discover, list, frontier, plan | No exact GUI CLI leaf callback. |
| conflicts, conflicts resolve | Mesh refresh observes conflicts, but no leaf-level receipt/resolve parity. |
| events, swarm, sync-state | Mesh refresh consumes these read models as a composite projection, not an exact leaf operation. |
| export-foreign, restore | CLI-only operational export/restore paths. |
| request-sync | The mesh UI invokes a selected-peer request, but the leaf is recorded as unwired until it has operation-level receipt/readback parity. |
| revoke, revoke-status | The GUI uses the distinct Buddy membership-revocation transaction. |
| status, topology | GUI projections exist, but the operation ledger has no leaf-level receipt parity. |
| task-delegate show, task-delegate set | Wired W233 GUI actions with typed receipt/projection/readback handling. Leaf paths intentionally omit positional arguments. |

The `parity_drift` guard compares these paths to Clap-derived leaf identities. Positional arguments and flags must not be part of `cli_path`.