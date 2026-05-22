# SPEC — NEOTH cluster auto-discovery + pairing

**Status**: design phase. Logic-Diskussion open, primitive scaffolded.
**Source**: Alex operator-request 2026-05-22 Session 20 ("NEOTH-Instanzen
im gleichen Netz — LAN / Hysteria / Tailscale — sollen sich gegenseitig
erkennen und als Cluster pairen").

## Use case

A solo operator running NEOTH on multiple devices (laptop + home server
+ phone-tethered tablet) wants those instances to behave as one logical
unit: shared memory, shared usage budget, shared kanban, shared chat
scrollback. Today each instance is isolated; the operator has to ssh
between them or copy `~/.neoth/` by hand.

## Discovery dimensions

Three independent transport surfaces — auto-discovery has to work
across each because operators rotate between them:

1. **LAN** (home wifi, office subnet) — peers reachable via local
   broadcast or mDNS. Bandwidth: high (gigabit). Latency: <1ms.
2. **Tailscale / WireGuard mesh** — peers reachable via MagicDNS
   hostname or the assigned `100.x.y.z` CGNAT range. Bandwidth:
   ~10-100 Mbps depending on relay path. Latency: 10-50ms.
3. **Hysteria QUIC tunnel** — operator's NEOTH already speaks
   SOCKS5 via Hysteria for outbound HTTP; peer-to-peer over the
   same tunnel is a v2 ask (Hysteria itself is client-server, not
   mesh — would need a separate side-channel).

## Proposed discovery primitive

Each NEOTH instance broadcasts a `ClusterAnnounce` packet on a
configurable cadence (default 60s). Three emitters in parallel:

- **mDNS service** `_neoth._udp.local.` carrying the operator's
  pub key + instance label + listen port. Standard zeroconf —
  every OS already runs an mDNS resolver.
- **Tailscale Magic DNS scan**: enumerate hosts in the operator's
  tailnet (`tailscale status --json`) + try the well-known NEOTH
  port on each.
- **Hysteria-shared lookup**: operators using the same Hysteria
  server can discover each other via a small in-tunnel relay
  registered with the Hysteria proxy (multi-week — needs operator-
  side Hysteria config change).

Discovery returns a list of `ClusterPeer { pub_key, instance_label,
addr, discovered_via: { Mdns, Tailscale, HysteriaRelay } }`.

## Pairing

Two-step gate:

1. **Shared cluster secret**: operator picks a 24-word phrase OR
   reuses their Keet seed. SHA-256 of the canonical phrase yields
   a 32-byte `cluster_key`. Discovery packets are HMAC-signed
   with this key — instances with a different cluster_key see
   each other's packets but reject the HMAC, so a hostile peer
   on the same LAN can't impersonate.

2. **Per-peer consent**: even with a matching cluster_key, the
   operator confirms each new peer via a doctor warn / wizard
   step (default autonomy: Standard → confirm; Full → auto-
   approve). Confirmed peers land in `~/.neoth/cluster.yaml`;
   subsequent restarts re-pair silently.

## Cluster state sync

Out of scope for the discovery primitive. Multi-week follow-up:

- WAL frame replication via gossip protocol (per-event vector
  clock + last-writer-wins for non-conflicting frames).
- Memory tier sync (`idx_episode` / `idx_consolidated` /
  `idx_longterm`) via the same gossip channel.
- Kanban + usage_log + dream JSONLs are append-only so easy.
- Council debate budget shared across cluster — needs a leader
  election or distributed-token (Pick #8 BudgetToken extension).

## Phases

- **Phase 1** (single session): SPEC + types + cluster_key derivation
  (reuses keet_crypto). **THIS SHIP** lands the types module.
- **Phase 2**: mDNS announcer + listener. Cross-platform via
  `mdns-sd` crate (already maintained, pure-Rust). Operator runs
  `neoth cluster discover` + sees peer list. 1-2 sessions.
- **Phase 3**: Tailscale magic-DNS scan via shelling to
  `tailscale status --json`. 1 session.
- **Phase 4**: Consent gate + cluster.yaml persistence + doctor
  surface. 1-2 sessions.
- **Phase 5**: Hysteria-shared lookup (needs operator-side
  Hysteria config + relay-side support). Multi-week.
- **Phase 6**: State-sync gossip protocol. Multi-week.

## Open questions (Alex to ratify)

1. Should cluster_key be derived from the operator's Keet seed
   (one-secret-everywhere) OR a separate phrase (defense in depth)?
2. mDNS broadcasts the operator's pub key in plaintext. Risk
   profile acceptable on home LAN; on shared office network the
   operator might prefer an opaque ID instead.
3. Default cluster mode = strict (require operator consent for
   every peer) vs trusting (auto-pair anyone with a matching
   cluster_key). Memory `neoth_autonomy` suggests strict by default.
4. Should cluster discovery be enabled by default in the wizard
   or opt-in?
