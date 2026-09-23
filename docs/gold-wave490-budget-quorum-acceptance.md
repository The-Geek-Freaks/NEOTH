# Cluster BudgetToken functional acceptance

GOLD-LF-P2-19 is accepted against
`9abb52d52604710b838967ecb92b0d89919e35dd`. Hosted Group886 run
`35911456591` passed all 38 selected BudgetToken identities. Root verified all
886 actual test terminals and 176 source/input bindings in the complete group.
The two unrelated Chat fixture failures remain failures; they are not erased by
this scoped acceptance.

The last missing regression starts two different live followers of three real
OpenRaft/SQLite replicas behind a barrier. Each reserves the entire shared cap.
Exactly one request obtains a committed grant and the other receives
`CapExceeded`. Only the winner obtains the move-only provider permit. The losing
request remains rejected on replay and after its follower restarts.

The other 37 passing identities cover reserve/claim/settle behavior, conservative
accounting, minority partitions, leader changes, lost claim acknowledgements,
permit non-reuse, durable snapshot/restart recovery, authenticated membership and
transport, and the actual paid-provider leaf. Quorum loss stops that leaf before
provider dispatch; a reconciled or repeated claim cannot mint another permit.

The exact selection, individual results, source hashes and group-admission hash
are in [`verification/gold-wave490-p219-acceptance.json`](verification/gold-wave490-p219-acceptance.json).
W482's verified hosted formatting is the only subsequent change to the budget
service/concurrent-test sources through `3de1cfe2`. W480/W487 do not alter the
BudgetRaft or paid-provider behavior. This accepts the functional Road contract,
not an unrun current-source full release or installed-package gate.

All executable checks ran on GitHub. No local compiler, formatter, test or
product runtime ran under the BSOD hold.
