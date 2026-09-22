# W226 — Operator task-delegation assignments for authenticated cluster peers

The existing cluster membership database now stores an explicit operator
assignment for inbound TaskDelegate requests. Pairing and peer-advertised Hello
capabilities do not grant task execution. A missing or denied assignment returns
the existing typed `Rejected` result with `operator_assignment_denied`.

Schema v5 adds an exact Peeroxide-key assignment with a monotonic revision.
Mutations require an active membership binding and an immediate SQLite
compare-and-set transaction. Membership identity, existing revocation effects,
provider consent and protected delegated-request assembly remain in force.

The inbound handler checks before autonomy/lease work and again after the
durable gate before queuing. The executor checks after dequeue and again after
request assembly and live consent, directly before its external-effect permit.
Lookup errors fail closed. The queued and final-boundary revocation regressions
require zero provider calls.

## Operator contract

- `neoth cluster task-delegate show <PEER_PK>` performs a read-only lookup and
  never upgrades the authority database, including an existing v4 database.
- `neoth cluster task-delegate set <PEER_PK> --allowed <true|false> --expected-revision <N>`
  requires the daemon to be stopped, takes the existing offline authority lock,
  commits the revision-bound assignment and verifies its exact readback.
- Existing paired peers default to denied until the operator assigns them.
  A stale revision cannot overwrite a concurrent accepted assignment.

This is the first P2-18 TaskDelegate slice. It does not implement daemon RPC
editing, skill assignment, channel/account bindings, outbound failover selection
or GUI/Buddy parity. P2-18 remains open. No live-network cluster execution or
external provider-delivery claim is made by the in-process fixtures.

## Validation

Seven new behavioral regressions cover v4 preservation/read-only lookup,
exact-key/default-deny/revisions, actual CLI set/show/conflict readback, inbound
denial and post-gate revocation, queued revocation and final-boundary revocation.
The grouped lane also selects fourteen existing affected handler/executor
cases, including successful completion, missing/dead WAL, protected prompt,
live consent, membership revoke and shutdown. This grows the complete selected
lane from 282 to 303 cases; exact identities are in the canonical test matrix.

Independent source review passed after correcting read-only migration behavior,
the final dispatch check and the initial structural-only CLI test. Hosted
compile/behavior and generated CLI-reference acceptance are pending. No local
compiler, parser, formatter, test, fixture or runtime executed under the BSOD
hold. Schema migration, command changes and effect checks are not release proof.
