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

## First Hosted result and fixture repairs, 2026-09-23

Grouped303 `35788592926` on `bbcb3c56` executed every selected case: 299 passed
and four failed. Source admission verified all 62 source-path hashes, matrix,
Cargo.lock and individual pass/fail terminals. Two new membership fixtures
supplied a different endpoint from their signed attestation. A custom in-flight
revocation fixture lacked the newly required explicit task assignment. The
shared job fixture tried revision 0 a second time in one home.

The fixtures now use the actual signed endpoint, explicitly seed the custom
allowed job, and initialize the shared assignment only when absent. Repeated
setup retains the existing revision and never silently re-enables a revoked
assignment. Production default denial and behavioral assertions are unchanged.
The repaired cases require another actual run.

Core `35788596014` passed slim Clippy, test typecheck, public CLI build and
reference export on `bbcb3c56`. The generated `docs/cli-commands.md` was imported
after verifying the artifact source-head and SHA-256. This does not turn the
four failed behavior tests into passes; their recheck joins Grouped328.
## Fixture repair accepted — 2026-09-23

Grouped328 run35790281385 on aca578a0 passed328/328 actual selected cases,
including all21 W226 cases. All68 source bindings, matrix, lock and individual
terminals were verified. The four Grouped303 setup repairs are accepted.
W229 live mutation changes are separate and not covered by this receipt.
