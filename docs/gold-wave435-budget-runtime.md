# W435 — budget Raft runtime and durable membership boundary

This batch adds the default-disabled `cluster.budget_raft` policy and the
runtime ownership boundary for P2-19. Enabling it requires an explicit positive
cap and UTC window, one membership epoch, and exactly three distinct canonical
`StableNodeId -> Peeroxide public key` voter bindings. Iroh is rejected because
it does not yet expose the equivalent authenticated request/reply carrier.

The runtime derives `BudgetClusterConfig` from one current
`MembershipStore::full_snapshot()` on the blocking pool. It rejects pending
authority work, a changed authority epoch, inactive/tombstoned/revoked members,
expired or non-Peeroxide bindings, and any mismatch between the frozen policy,
the local stable identity, and the local Noise public key. The cluster id is
the resolved cluster identity name, so all correctly configured voters derive
the same immutable scope. Every inbound Raft
peer and each local provider-admission claim performs the same fresh durable
read; a wire tuple or old `MembershipGrant` does not authorize a voter.

Recovery opens the existing `budget-raft.db` only after that proof. No config,
cap, window, epoch, or binding change resets or migrates the durable ledger: the
runtime remains unavailable until a matching recoverable store and authenticated
three-voter carrier exist. During startup, the Peeroxide carrier is constructed
without a service target, the durable service is recovered, the swarm starts,
the exact fixed voter map is bootstrapped once, then the carrier receives only a
weak service reference and provider dispatch is published. Any failure unwinds
the partial runtime.

On shutdown and reload, budget ingress stops before OpenRaft, gossip, Peeroxide,
and executor teardown. Runtime policy equality includes the whole budget policy,
so a cap/window/epoch/voter change restarts the generation rather than leaving a
previous authority live. Hosted focused checks still need to compile and exercise
the jointly integrated carrier, service, provider-admission, and three-node
fixture. This documentation is source-scope evidence only and does not close
`GOLD-LF-P2-19`.
