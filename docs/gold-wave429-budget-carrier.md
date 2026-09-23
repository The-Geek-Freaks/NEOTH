# GOLD-W429 — authenticated Peeroxide Budget-Raft carrier

`BudgetPeerCarrier` carries OpenRaft AppendEntries, Vote, InstallSnapshot, and
the follower-to-selected-leader `BudgetCommand` lane only through a current
`PeerStreamRegistry` session. Command replies are `BudgetReply` domain data;
the carrier never serializes a `NewDispatchPermit`. It does not dial,
self-route, retry through another voter, or fall back to a local counter.

Each `BudgetRaftEnvelope` has an independent envelope version, a non-zero
request ID, frozen cluster ID, membership epoch, scope hash, asserted stable
sender, exact request/reply kind, and a payload capped at 512 KiB before nested
OpenRaft CBOR decoding.  The outer heartbeat protocol moves to v7, so a v6
peer cannot complete the Hello handshake and receive a budget frame.

Outbound routing derives a `BudgetSession` solely from the live sender selected
by the frozen `BudgetPeerRoute`.  The registry checks the exact Peeroxide
transport, stable voter, frozen epoch, current `MembershipGrant`, and sender
generation.  Sending rechecks that same generation and acquires the existing
membership external-effect guard.  A revoked, replaced, missing, full, or
closed session fails the RPC; it cannot choose another route.

The carrier keeps at most 64 pending replies.  Every entry is bound to request
ID plus expected transport identity, stable voter, generation, and response
kind.  Timeout, session cancellation, runtime stop, sender failure, and normal
completion remove the entry.  An inbound response may wake a caller only after
all of those values match the current authenticated session.

Shutdown uses `watch::Sender::send_replace(true)`, so new request
subscriptions observe stopped even if no request was active at shutdown. A
drop cleanup guard removes the pending entry if OpenRaft cancels an awaiting
carrier future before it receives a reply.

Inbound envelopes are intercepted in the authenticated Peeroxide connection
loop after membership revalidation.  The loop builds a context for its own
registered generation, compares the asserted sender/config fields to the
Noise-bound grant, and gives the carrier the envelope.  Responses correlate
immediately.  Requests are admitted behind a bounded semaphore and handled in
a spawned task, so waiting for Raft never blocks the stream reader from
receiving the corresponding response.  The response is sent only with the
retained inbound session generation.

Runtime owns the strong objects: create with
`BudgetPeerCarrier::new(Arc::downgrade(&peer_streams), config, local_stable)`,
recover the service with the carrier as `BudgetRaftCarrier`, then call
`carrier.bind_service(Arc::downgrade(&service))`.  Pass `Some(carrier)` to
`spawn_discovery_with_wal`; shutdown calls `carrier.stop()` before tearing down
the swarm/service.  The service owns its carrier for outbound Raft, while the
carrier holds only weak references back to the service and peer registry, so
stop does not depend on an Arc cycle.
