# SPEC — NEOTH cluster auto-discovery + pairing

**Status**: design phase. Logic-Diskussion open, primitive scaffolded.
**Source**: operator-request 2026-05-22 Session 20 ("NEOTH-Instanzen
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

## Open questions (operator to ratify) — RATIFIED 2026-05-22

4-agent audit (security-auditor + security-auditor + architect +
planner) ran 2026-05-22 Session 20. Verdicts:

### Q1 — Phrase reuse: **ALLOW REUSE** with warning

Single phrase, derive both Keet topic + cluster keys via
domain-separated SHA-256. Domain separation + SHA-256 avalanche
makes the two 32-byte outputs cryptographically uncorrelated;
requiring a second phrase adds zero security against the
opportunistic-observer threat model.

Would change if: threat model expands to include compromised-
device (malware reading `SecretString` from mlocked memory). Then
expose `--separate-phrases` flag in advanced setup but keep
single-phrase as the wizard default.

### Q2 — mDNS pub_key: **KEEP RAW** + add `announce_on_untrusted_wifi: false` flag

Pseudonym design buys nothing against a static-cluster_key
operator (HMAC-derived pseudonym is just as linkable as the raw
pub_key). The actual mitigation for the cross-network linkability
threat is operational: suppress mDNS broadcasts on untrusted
networks. Default `freedom.yaml::cluster.announce_on_untrusted_wifi
= false`. Operator-named trusted SSID list OR Tailscale-only
opt-in.

Auditor also flagged three code issues in the Phase-1 primitives
(now fixed in 248f6XX series):
  - HMAC key construction: namespace moved from key-side into
    data-side per RFC 2104 idiom
  - Variable-length fields (addr_str, instance_label) now
    length-prefixed (LE u32) before HMAC input — defends the
    canonicalisation-collision corner case
  - `ClusterKey` no longer `Copy`; Drop impl writes volatile
    zeroes byte-by-byte

Instance labels in mDNS broadcasts: same suppress-on-untrusted-
wifi treatment. Optional defense-in-depth: render label as
`HMAC(cluster_key, hostname)[:8]` hex in the broadcast TXT
record; full label only in `cluster.yaml`.

### Q3 — Trust model: **REQUIRE-CONSENT default, autonomy-mapped**

Map to `permissions::AutonomyLevel`:

| AutonomyLevel | ClusterPeerPairing Decision |
|---|---|
| Strict | Deny (cluster makes no autonomous topology changes) |
| Standard | Confirm |
| Elevated | Confirm (topology-change is material per Chorus Q1a precedent) |
| Full | Allow (HMAC check is the gate) |
| Custom | Delegate to Standard until per-category map ships |

Reject the LAN-auto-pair / Tailscale-consent split — transport
provenance isn't reliable (Tailscale is layer-3 overlay; an
attacker on the tailnet has the same transport privileges as a
legitimate peer).

CLI surface:
  - `neoth cluster discover` — read-only peer enumeration
  - `neoth cluster confirm <pub_key_prefix>` — operator-initiated
    consent; writes to `~/.neoth/cluster.yaml`, emits WAL 0xE0
  - `neoth cluster revoke <pub_key_prefix>` — removes peer +
    emits WAL 0xE2; revoked peer rediscovers as PENDING_CONSENT
  - `neoth doctor cluster` — surfaces pending peers as WARN

Confirm-prompt text (TTY): `[cluster] Peer '<label>'
(<pub_key_prefix>) wants to join your cluster via <transport>.
This grants it read/write access to your memory and WAL.
Approve? [y/N]`

WAL audit frame on consent records `pub_key`, `instance_label`,
`discovered_via`, `autonomy_level` so `neoth doctor cluster
--history` traces every admission.

### Q4 — Wizard default: **Design B** (Default ON + explanatory step + opt-out checkbox)

New wizard step inserts between Channels (current step 7) and
Keys, becoming step 8 of 9. Checkbox is unchecked by default;
discovery stays ON unless operator explicitly disables.

Wizard copy:

> **Network buddy discovery**
>
> NEOTH can automatically find your other devices on this network
> and connect them into one team — shared memory, shared chat,
> shared task board. It uses a lightweight mDNS broadcast (same
> technology as Airplay and Chromecast) to announce itself every
> 60 seconds. On a home or office LAN this is completely safe;
> on a shared or public network it reveals your instance label
> and public key to other devices on the subnet. If you only
> ever run one NEOTH instance, you can turn this off — you can
> always re-enable it later with `neoth cluster enable`.
>
> [ ] **Disable buddy discovery on this device** *(recommended:
> leave unchecked if you run NEOTH on more than one device)*

Post-install CLI: `neoth cluster {enable,disable,status}`
toggles `freedom.yaml::cluster.mdns.enabled`.
