# W229 — Live operator-owned cluster delegation assignments

`cluster task-delegate set` now uses the existing authenticated daemon Audit
RPC when the daemon owns the home. Offline operation retains the established
membership authority lock. The server accepts one strict CAS request on
`/membership/task-delegate`; existing same-user and bearer checks remain in
force. A missing assignment still denies delegated work.

The response is the stable committed assignment receipt. A later concurrent
writer may advance that assignment; it must not retroactively turn this
successful commit into a false readback failure. Neither client nor CLI retries
an ambiguous mutation or silently switches to offline authority after RPC error.
The read-only show path remains a separate observation.

## Final provider boundary

The actual store CAS and the executor's final assignment check plus
`begin_external` share one short process-local authority gate. If revocation
commits first, the pending start sees deny and makes no provider call. If start
wins first, it already has the membership external-effect permit. This does
not claim cancellation of a transport that already started. No authority mutex
is held across the provider future. A typed admission error preserves the
operator-denial result separately from other authority failures.

The existing final-boundary test is strengthened and renamed. A real controller
setter owns the shared gate and pauses before its durable commit; the executor
announces its final gate attempt, then the setter commits deny. The executor
must return operator_assignment_denied and the provider counter remains zero.
Test-only observers do not enter production builds.

The existing real RPC roundtrip additionally checks unauthenticated401 with no
mutation, allow revision1, stale CAS422 with unchanged authority and deny
revision2. This is a real authenticated server-transport fixture; a full daemon
PID/sidecar CLI launch is not claimed. The selected RPC identity is added to
the native inventory; the strengthened race replaces its former exact name.

## Review and verification state

Independent source and delta reviews passed. Native inventory becomes842 and
the focused grouped selection341; source inventory stays535, universal GUI94,
Linux/macOS extras22 each and macOS custom26. P2-18 remains open for node skill
assignments, channel/account bindings, conflict/failover and GUI/Buddy parity.

Formatting, core typecheck and actual behavior require GitHub-hosted execution.
No local compiler, formatter, parser, test, fixture or GUI ran under the BSOD
hold. Previous Grouped328 evidence proves the preceding W226 implementation;
it does not certify these newly changed sources.
