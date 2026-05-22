# SPEC — R-2 Phase 3+ (DHT UDP dialer + NOISE-IK + Hypercore replication)

**Status**: scope acknowledged. Multi-week effort across THREE
sub-phases — each is its own 1-2 week single-session-impossible
ship. Phase 1 (crypto primitives) + Phase 2 (DHT bootstrap +
announce-packet shape) already in tree.

**Parent**: R-2 Hyperswarm port for Keet channel. SPEC_cluster_
auto_discovery shares the crypto anchor but is a parallel
deliverable (cluster discovers NEOTH-to-NEOTH; R-2 discovers
NEOTH ↔ Keet-on-phone).

## Phase 3 — DHT UDP dialer

**Estimate**: 2-3 weeks.

The hyperdht protocol's transport layer is UDP-based with a
custom QUIC-like reliability layer (UDX). We need:

1. **`tokio::net::UdpSocket` wrapper** with the hyperdht packet
   framing (length-prefix + protocol-version byte + payload).
2. **DHT bucket walker**: from the bootstrap list (Phase 2),
   query progressively closer DHT nodes to the discovery key.
   Kademlia-style XOR distance — well-documented, but the
   wire details follow hyperdht's own conventions, not
   classical Kad.
3. **Announce + Lookup state machine**: each operation is a
   multi-round trip — announce sends 5+ packets to the node
   responsible for the discovery key, lookup does the same to
   collect peer-list responses from N closest nodes. Retry +
   timeout per packet.
4. **NAT traversal**: hyperdht peers behind home routers need
   simultaneous UDP holepunch (the reference impl has its own
   "punch" subprotocol). 1-2 weeks of careful work to
   reproduce.

## Phase 4 — NOISE-IK handshake

**Estimate**: 1-2 weeks.

Once two peers know each other's DHT-discovered addresses, they
establish a NOISE-IK session over UDX. NOISE-IK is well-
documented but the implementation choices Holepunch made for
Keet aren't perfectly aligned with the standard library
(`snow` crate) — partial-fork or careful spec mapping.

- **Static key**: derived from `keet_crypto::entropy()` (Phase 1
  shipped). Crate: ed25519-dalek for the curve ops + custom
  signature material.
- **Ephemeral key**: per-session, generated via `rand::rngs::OsRng`.
- **Replay defense**: 12-byte nonce per direction; Phase 6 of
  Hypercore replication uses the same envelope.
- **MITM defense**: pinned identity hash check after handshake
  — operator's Keet phone displays the same hash so the operator
  visually confirms.

## Phase 5 — Hypercore replication

**Estimate**: 3-4 weeks.

After the NOISE session, the two peers run Hypercore's
replication protocol. Hypercore is an append-only Merkle log;
replication is "tell me which signed blocks I'm missing", with
the Merkle tree allowing efficient O(log n) proof of
inclusion.

- **Block-level proofs**: each block has a SHA-256 hash; tree
  root signed by the writer's ed25519 keypair. Replication
  walks the operator's known set + asks the peer for missing
  blocks by index, validates each against the signed tree.
- **Bitfield exchange**: peers swap compact bitfields of which
  block indices they have. Naive run-length-encoded; the JS
  impl uses a more compact variant.
- **Streaming**: Keet's chat works because every message is a
  Hypercore block; the replication channel pushes new blocks
  as they're written. Real-time UX requires sub-100ms
  replication latency, which is achievable once the dialer +
  handshake bottlenecks are out of the way.

## Why all three are multi-week

Each phase is a multi-thousand-line protocol port from a
JS reference impl that lives in a non-trivial maintenance
ecosystem (Holepunch's `hyperdht`, `udx`, `hypercore` packages
all have ongoing development + breaking changes per minor
version). Mature Rust ports don't exist yet — `hypercore`
crate (different team, separate from Holepunch) implements an
older spec that doesn't interop with Keet.

The closest production-grade pattern is to either:

1. **Port-as-you-go**: every session lands one sub-phase
   primitive + interop-tests against the JS reference. ~12
   weeks total if focused.
2. **Embed a node subprocess**: spawn a small Node.js process
   bundled with `hyperdht` + IPC over stdin/stdout. Operator
   pays the Node-install friction (NOOB-UX-6 conflict) but
   the Keet interop arrives in ~2 weeks. Backward step from
   the AIO hard rule.

## Decision deferred

Operator (Alex) to ratify the port-as-you-go vs Node-subprocess
trade-off before R-2 Phase 3 starts. Default leans port-as-you-go
to stay AIO; revisit if the timeline matters more than the
zero-extra-dep guarantee.
