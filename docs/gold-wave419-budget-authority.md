# W419 budget authority core

W419 implements the deterministic, durable domain half of P2-19. It does not
close P2-19: the OpenRaft runtime, SQLite store, authenticated carrier, and
provider-admission seam still have to be wired together and exercised in the
three-node fixture described by [W416](../work/gold-20260906/W416-budget-consensus-design.md).

The ledger accepts a frozen configuration of exactly three unique
`StableNodeId -> TransportIdentity` voters. Its scope hash is recomputed from a
domain-separated, length-prefixed canonical encoding of cluster id, membership
epoch, ordered voter bindings, cap, and UTC window. Recovery validates that
binding before admitting any command.

Each reserve records its original committed term/index permanently. Its reserve
fence binds cluster id, scope hash, epoch, original log position, grant, intent,
fingerprint, bound, and window. A dispatch fence additionally binds the original
reserve position/fence and the committed claim position, owner, attempt, and
intent. Settlement and release receipts have their own terminal fence, binding
the complete terminal command and its original log position. Replaying an
identical reserve or claim returns the stored receipt with the original position;
it cannot create a replacement fence or a second permit.

`ReservedGrant` and `ClaimReceipt` are persisted receipts, not provider permits.
The future provider seam may mint a private, move-only `NewDispatchPermit` only
for the invocation that receives the first committed `NewClaimed` result. All
later BeginDispatch replies are reconcile-only durable information.

The hard window ceiling sums every original reservation. A release before a
claim, a known under-spend, or an unknown result does not create new headroom.
Unknown cost settles at the full bound. An overrun is stored as a durable
reconciliation state, returns `Overrun`, remains unreleasable, and rejects a
changed retry. Terminal settlement and release retries are accepted only when
their full immutable command matches the original terminal command.
