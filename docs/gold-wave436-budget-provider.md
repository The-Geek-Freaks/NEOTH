# W436 - Quorum admission at the actual provider leaf

The optional fixed-voter cluster budget is installed only on the runtime-owned
cluster provider authorizer. Each actual remote provider leaf derives its bound
from the reviewed price and concrete request/output ceiling. Unknown price,
unbounded output or missing delegated task identity refuses admission before
provider transport. Existing permissions, daily/operation budgets and durable
provider-intent WAL gates remain in force.

After the intent is durable, Reserve and the first majority-committed
BeginDispatch must succeed. A private move-only permit is transferred with its
accounting ticket into the existing raw-call guard without another await.
Responses contain receipts only. Replays, lost acknowledgements and restart do
not mint another permit; unknown outcomes retain the full bound. Terminal
settlement records actual or unknown cost without turning a paid call into a
retry after an accounting failure. Standalone builds do not name cluster types.

The focused fixtures exercise the real three-voter OpenRaft/SQLite service and
normal AuthorizedProvider boundary: one paid call through a follower, zero raw
calls under lost quorum, and zero raw calls for unknown pricing. Domain, durable
store, transport cancellation and membership fixtures cover their separate
contracts. These are source changes awaiting hosted compilation and behavior;
GOLD-LF-P2-19 remains open. No local executable validation ran.
