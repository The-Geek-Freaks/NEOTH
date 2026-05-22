# SPEC — Cluster Phase 5 (Hysteria-shared relay)

**Status**: scope acknowledged. Multi-week effort — single-session
ship structurally impossible.

**Parent SPEC**: `PLAN/SPEC_cluster_auto_discovery_2026-05-22.md`
Phase 5 (Hysteria-shared lookup).

## Use case

Two NEOTH operators (Alex on home server + Alex on travelling
laptop) both connect outbound through the same Hysteria QUIC
server. Phase 2 mDNS doesn't reach across NATs; Tailscale isn't
installed on the home-server side. They want to pair anyway.

Solution: the Hysteria server itself relays peer-discovery
announces between authenticated tunnel clients. NEOTH instances
register with the relay on connect; the relay returns the list
of other instances connected with the same `cluster_key` proof.

## Why this is multi-week

1. **Hysteria server-side support**: the upstream Hysteria binary
   has no concept of "peer registry" — it terminates QUIC + forwards
   payloads. NEOTH would need either:
   - A separate relay daemon co-located with Hysteria that listens
     on a known port AND requires every NEOTH instance to dial
     it on each connect (~2 weeks of relay code + auth + ops doc)
   - OR a Hysteria fork that injects the registry endpoint into the
     proxy itself (~4-6 weeks + maintenance burden of carrying a
     fork)
2. **Operator-side Hysteria config change**: every operator needs
   to update their Hysteria server config to expose the relay
   port + open firewall. Cross-version migration is messy.
3. **HMAC-over-QUIC handshake**: the cluster_key authenticator
   already shipped in Phase 1 works for one-shot mDNS broadcasts;
   over a long-lived relay connection we'd need a session-bound
   variant that resists replay across reconnects.

## Phase 5.1 (1 session) — RELAY-PROTOCOL SPEC

Single-session deliverable: write the relay-protocol spec
covering wire frames + handshake sequence + state machine. No
implementation. Operators wanting Phase 5 functionality today
either (a) install Tailscale (covered by Phase 3) OR (b) wait
for the actual relay impl.

## Phase 5.2 (multi-week) — RELAY DAEMON

Standalone Rust binary `neoth-relay` shipped alongside
`neothd`. Sits behind the operator's Hysteria server on the
relay port. NEOTH clients dial it after the QUIC tunnel comes
up; relay maintains the per-cluster_key peer set in memory.

## Phase 5.3 (multi-week) — NEOTH CLIENT-SIDE WIRE-UP

`cluster::hysteria_relay` module. When `freedom.yaml::cluster
.hysteria_relay.url` is set + the operator's Hysteria
supervisor is up, the relay client connects + announces the
local peer + subscribes to incoming peer updates.

## Open questions

1. Co-locate the relay daemon with Hysteria (operator runs both)
   or ship as a standalone service operators can host
   independently?
2. Relay-side rate limit: how many peers per cluster_key
   before the relay starts rejecting? (Defends against an
   operator with a compromised cluster_key flooding the relay
   with synthetic peers.)
3. Federation: should multiple relays form a mesh so an
   operator running Hysteria on Server A + an operator running
   Hysteria on Server B can still pair? Probably yes, but
   adds Phase 5.4.
