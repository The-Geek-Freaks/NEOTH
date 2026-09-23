# W392 outbound scoped task delegation

W392 adds the daemon-owned master-side half of scoped cluster task delegation.
An operator creates an exact `(Noise peer, skill, channel, account)` outbound
assignment. Optional channel and account values are canonical empty components,
not wildcards. Candidate selection considers only active current memberships and
orders eligible peers by `priority`, then authenticated Noise key.

Dispatch is available only through the same-user authenticated audit RPC while
the daemon owns an authenticated peer runtime. It persists `prepared` before a
frame enters a peer queue. Unknown, closed, full, or revoked queues may advance
to the next authorized candidate only before acceptance. After an accepted
queue operation, no timeout, disconnect, caller retry, or missing result can
replay the task.

Startup converts unresolved `prepared` records to `indeterminate`. A TaskResult
settles an operation only when its authenticated Noise sender and task id match
the persisted selected peer. The accepted/result transition is monotonic, so a
late local acceptance cannot overwrite a result.

The runtime removes dispatch admission before carrier teardown and serializes
that removal with in-flight dispatch admission. P2-19 distributed budget
consensus and GUI/Buddy parity remain outside this slice.

Runtime queue fixtures capture the current clock for finite 300-second grants;
pure membership model fixtures retain deterministic historical timestamps.
The real send path revalidates expiry against the current clock, unchanged.

Hosted Preflighted979 run35866308924 produced a ten-path rustfmt-only patch.
Root verified the exact source head, artifact digests and every before/after
Git blob before importing it. This is format evidence, not compiler or behavior
acceptance. Coreed97935866308409 supplies the pending current-source compiler
gate. The earlier Core9fd35864804945 passed all four gates and its exported
CLI reference54491B95 matches the committed pre-outbound reference.
