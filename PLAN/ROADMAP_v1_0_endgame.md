# NEOTH v1.0 — Endgame Roadmap

> Synthesised 2026-06-01 from a 4-lens senior panel that **verified the real
> remaining scope of every named 1.0 blocker against the code** (not the plan
> estimates). Grounded findings — many "open" items are partly shipped.

## Verified ground truth (corrects the estimates)

- **SPEC-09 cluster is fully shipped** — `cluster/` (hyperswarm receive-half +
  heartbeat CBOR + registry + mdns/tailscale + `cli/cluster.rs` discover/confirm/
  revoke/list/status + WAL 0xE0/0xE2). The `[x]` is accurate. The genuinely-open
  cluster piece is **live transport send-path + the slave shim**, not discovery.
- **A recurring prerequisite blocks several lanes: WAL event-code band resolution.**
  Multiple items reserve codes in comments that aren't defined OR collide:
  SL-01a leases (0xA4/A5/A6 — verify the 0xA0–0xAF band), SL-01b gossip
  (0xE8 is already `CLUSTER_ROLE_CHANGED`, **not** `WAL_SYNC_SENT` → use a free
  cluster-band slot), HO-07 monitor (free slots above 0x3F), ARCH-05 cutover
  (0x2A taken). **Resolving the band map first is a cheap unblock for 4 items.**
- **GU-01 is the biggest honest-1.0 gap**: 6/10 GUI settings tabs are explicit
  "Coming in v0.2" stubs, while `docs/release-notes-v1.0.md` claims GUI parity —
  a claimed-but-not-true guarantee (the SC-04b class).
- **"signed export / signed proof" doc language** (KF-03) describes a capability
  whose signing half isn't built — false until KF-03 ships + the keypair lands.

## Lanes

| Lane | Items | State |
| :-- | :-- | :-- |
| **0 · Foundation** | WAL band resolution → **SL-01a Capability Lease** | READY |
| **1 · Agent quality** | G-03 self-correction · PC-01 OS-tool surface | READY |
| **2 · GUI parity + brand** | GU-01 settings parity → GU-02 cyber-brand → GU-03 adaptive depth | GU-01 READY |
| **3 · Cluster live-transport** | SL-01 slave shim → SL-01b gossip sender → SL-02 topology → SL-03 resources → SL-01c hostname | NEEDS-PREREQ (SL-01a + send loop) |
| **4 · Launch + proof** | KF-03 unsigned export (READY) → **[sign: keypair]** → MAR-01 (README + CLI shots) → MAR-02 **[keypair]** | mixed |
| **5 · Migration hardening** | ARCH-05 `neoth-migrate apply` + data-loss guard → SPEC-08 recall-parity goldset | MULTI-DAY |

## Dependency-ordered build sequence

1. **WAL band resolution** (≤0.5d) — audit `events.rs`, assign free slots for
   lease (0xA0-band) / gossip / monitor / cutover, record in PROGRESS sequencing.
   *Unblocks SL-01a, SL-01b, HO-07, ARCH-05.*
2. **SL-01a Capability Lease** (~1d, READY) — `permissions/lease.rs`
   `CapabilityLease { lease_id (UUIDv7), granted_to, action, expires_unix }` +
   LEASE_GRANTED/EXPIRED/REVOKED WAL events + pure grant/check/revoke +
   `neoth lease grant/revoke/list`. *Unblocks G-01 bounded write + SL-01 delegation.*
3. **G-03 Self-correction loop** (~1d, READY) — subscribe to
   `DomainEvent::ProviderResponded`; detect a follow-up correction/feedback turn;
   emit a new feedback WAL frame; feed the self-dev proposal path.
4. **PC-01 OS-tool surface** (~1.5d, READY) — `Action::OsFileRead/OsFileWrite` +
   `FreedomConfig::tools.allowed_paths` (default empty = deny-all) + consent-gated
   file read first (write later).
5. **GU-01 settings parity** (start, READY) — replace the 6 stub tabs with real
   panels sourced from the existing CLI/config surface; Channels toggle list first.
6. **KF-03 unsigned export slice** (READY) — `neoth wal export --window <a>..<b>`
   → `.neoth-proof` JSON of the HMAC-chained frames. `--sign` waits on the keypair.
7. **SL-01 slave shim** → SL-01b gossip-sender → SL-02 topology (after 1+2).
8. **ARCH-05** `neoth-migrate apply` (Markdown reader) + `dedup_key` + data-loss guard.

## 1.0 cut-line (deferred to post-1.0)

SPEC-11 (cross-channel identity), SPEC-12 (LLM clustering Phase 3), PC-02
(Chrome DevTools MCP — needs operator license decision), HO-07 (monitor sidecar),
SC-02 open half (named-restore), GR-03 (Trust Ledger — needs operator lane call).

## Blocked on the operator (one action unblocks 3 items)

- **minisign release keypair** → unblocks **KF-03 signing**, **MAR-02** signed
  release, **MV-01b** CI auto-update signing. Action: `minisign -G` (or
  `rsign generate`) locally, add `NEOTH_RELEASE_MINISIGN_SECRET` (+ public) as
  GitHub Actions secrets. The CI + verify code is already built.
- **PC-02**: confirm the Chrome DevTools MCP license is acceptable for inclusion.
- **GR-03**: confirm post-1.0 deferral (or assign a lane).

## Immediate honesty fixes (cheap, on-wedge — do alongside)

- Qualify the GUI-parity claim in `docs/release-notes-v1.0.md` (6/10 tabs are
  stubs) until GU-01 lands.
- Qualify "signed export / signed proof" doc language until KF-03 + keypair ship.
