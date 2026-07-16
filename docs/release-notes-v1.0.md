# NEOTH 1.0 Release Notes

> **Release-candidate target: stable `1.0.0`.** The source tree carries that
> version, but it is not Gold/tag-ready and no public artifacts have been
> published. The open v1 contracts below must close before the `v1.0.0` tag.

NEOTH 1.0 is the first public release intended for real personal use: one
operator, one private memory, many approved surfaces, local-first defaults, and
operator-readable proof.

## Open v1.0 release blockers

These are unfinished v1 contracts, not accepted post-1.0 limitations:

- **Integration/adoption lifecycle:** the capability DAG, durable job store,
  lifecycle state machine, progress events and contract-bound Ready-evidence primitives
  are a contract foundation. A production daemon owner, permission/WAL
  orchestrator, artifact adapters, supervisor/retention policy, IPC/SSE,
  CLI/GUI/Buddy/Doctor consumers, production receipt issuer and an explicit
  `AwaitingUser` state for QR/OAuth/device/signing work are not wired yet.
- **Channel completion and OpenClaw parity:** IRC, BlueBubbles, Mattermost,
  Google Chat, Matrix and Nostr fail closed on their named inbound identity
  policies. Discord, Slack, WhatsApp Business, Signal and LINE now require an
  exact immutable sender identity, refuse open inbound startup, and gate every
  decoded message before the pipeline with metadata-only WAL rejection
  evidence. Twitch still authenticates only the transport/bot and needs a
  mandatory typed audience/mention policy before release. Five advanced settings are still file-only
  (`line_webhook_port`, `irc_port`, `irc_tls`, `irc_allowed_nick`,
  `matrix_store_path`). Durable cross-store credential recovery, persisted
  multi-account identity, descriptor-rendered forms and OpenClaw
  apply/status/rollback plus runtime-behaviour parity remain open.
- **Zero-friction retained adoptions:** models, Obsidian preload, n8n,
  Paperless, WhatsApp/managed Node, Keet and the other retained integrations do
  not yet share a proved acquire -> verify -> configure -> supervise ->
  authenticated Ready -> repair/update/uninstall path on every clean target.
- **Release proof:** exact-head CI, Security and CodeQL, signed native-installer
  execution, clean-machine install/upgrade/repair/uninstall and complete
  release-feature packaging must be green before tagging.
- **Adaptive communication, Mobile and Cluster:** default-on local communication
  adaptation still needs subject isolation, non-diagnostic evidence/decay and
  prompt parity on every answer path. The current phone pairing preview has no
  installable Android/iOS client or durable device session. Cluster gossip and
  replay are durable, but master-side delegated-task/result coordination and
  full GUI/Buddy control are incomplete. These are v1.0 Gold work, not
  post-release promises.
- **Breaking OpenClaw import correction:** provider-only `import-config`
  conversion is retired. The compatibility command now requires a complete
  `openclaw.json`, uses the same read-only source-set/inventory-bound inspector
  as `import-openclaw`, and reports `apply_available=false`. Its former
  provider-only flags fail closed.

## Implemented boundaries and operational limitations

These limits describe implemented surfaces honestly; they do not close or
defer the release blockers above:

- **GUI settings depth (GU-01):** all 10 post-onboarding settings tabs are now real
  panels (GU-01 closed in the Session-37 GUI batch — see the GUI honest-status note
  below). The Channels tab now drives the canonical 15-adapter CLI registry for
  refresh, add/reconfigure, read-only live test, and confirmed removal. A few other
  panels stay intentionally thin — the Chat tab is a launch-point for the composer,
  Hemispheres/Plugins/Memory are read-only views, and not every individual
  `freedom.yaml` flag has its own toggle yet. In particular, the five advanced
  Channel fields named above currently require a direct configuration-file
  edit; they have no first-class CLI or GUI control.
  (GUI rendering is compile-verified; visual QA is a manual step.)
- **Migration shadow-run (ARCH-05):** the deterministic recall-parity GATE +
  runbook ship; the 14-day shadow-run, grading, and cutover are
  operator-operational steps you perform, not code that runs itself.
- **Signed release artifacts:** `neoth wal export --sign` / `verify-proof` /
  `wal proof-key` (including fail-closed, dual-signed `proof-key rotate`) work
  today for the OPERATOR proof key. The separate MAR-02 release keypair is
  provisioned in CI and its public half is committed in
  `NEOTH_RELEASE_MINISIGN_PUBKEY.txt`; a release tag fails closed unless the
  configured public key matches that repository pin and every archive receives
  a verified `.minisig`, checksum, and cosign bundle. The remaining limitation
  is operational: no `v1.0.0` tag or resulting public artifact exists yet.

## What is implemented today

Implementation in this table does not imply that every related adoption has
the zero-friction lifecycle or clean-machine proof required by the blockers
above.

| Area | Status |
| :-- | :-- |
| GUI/CLI first run | Bare `neoth` presents one accessible GUI/CLI choice on a graphical session, persists it in the authoritative instance home, and never opens a popup in SSH/CI/headless sessions. Either surface provides a real switch to the other. |
| CLI | Chat, recall, profile, privacy audit, Doctor, providers, channels, plugins, cluster, coding, credential-safe-by-default backup, WAL verification. |
| Memory | Five-tier local memory + vault ingest, with profile facts, evidence, confidence, redaction, recall, and consolidation. |
| Privacy | Fail-closed profile extraction, explicit destinations, provider audit, WAL verification, plugin hostcall audit. |
| Local models | Qwen profile path, optional local thinking-model path and model-cache diagnostics. Unified visible acquire/materialize progress and the complete managed adoption lifecycle remain open. |
| Providers | Configured cloud providers, provider status, usage caps, circuit breakers, flapping detection. |
| Channels | CLI and the post-onboarding GUI share one 15-adapter registry and the same add/reconfigure, test, remove and refresh contracts. Six named inbound identity policies fail closed; six other adapters still need the common operator/sender/conversation gate and therefore are not Gold-ready for untrusted audiences. Status never masquerades as reachability, and Test returns the adapter's typed live or unavailable verdict. Five advanced fields, persisted multi-account identity, cross-store recovery and OpenClaw apply/runtime parity remain open. Desktop archives also ship the repository-owned, full-duplex `neoth-keet-bridge` for private Keet-identity Pear/Hyperswarm topics; it deliberately does not claim interoperability with existing Keet app rooms. |
| Coding buddy | Planning, canvas/Kanban, repo memory, cargo/check loop, review promotion, recall of decisions. |
| Release self-knowledge | Every archive and native installer carries a pinned-Graphify map of the exact tag. Runtime verification binds version, source HEAD, closed file set, and canonical payload digest; upgrade/uninstall preserve operator-owned `User Overlays`. |
| Automation | Local cron plus a default-off, loopback-only n8n ingress API with bearer scopes, endpoint-specific consent/cost gates and typed request/downstream audit events. Zero-friction post-install n8n coupling and the shared adoption lifecycle remain open. |
| Plugins | Skills and WASM plugins with capabilities, signatures, revocation, hostcall WAL events. |
| Private mesh | Authenticated peeroxide/iroh carriers share durable per-peer pending frames, exact cursor-bound ACKs, restart replay, and transactional receive/materialization for canonical memory and ground-truth snapshots. Raw ingress remains default-off and the mesh is intentionally scoped to typed NEOTH content rather than arbitrary device files. |
| Doctor | Setup diagnostics for config, secrets, models, channels, plugins, providers, disk, WAL, and cluster discovery. |
| Docs | Quickstart, privacy proof, install, CLI, providers, local models, channels, plugins, compare pages, security policy. |

Native desktop releases contain both Peeroxide and Iroh; the static headless
musl server contains Peeroxide only. GUI and CLI persist cluster settings as one
complete typed transaction with an optional stdin-only shared passphrase.
Enabled lifecycle changes return `restart_required: true`: they are durable,
but the current daemon does not hot-switch transport, mDNS or gossip and must
be restarted before the change is active. Disabled plus stopped is already
inert and returns `false`.

> **GUI settings coverage (honest status):** the post-onboarding settings window has
> 10 tabs and — since the Session-37 GU-01 batch — all 10 are real panels (Privacy,
> Cluster, Code Sessions, Config, Chat, Hemispheres, Channels, Skills, Plugins, Memory).
> Channels is no longer one of the thin panels: it refreshes the canonical registry
> and drives add/reconfigure, typed live Test, and confirmed Remove through the same
> CLI contracts. Chat remains a launch-point for the composer, and
> Hemispheres/Plugins/Memory are read-only views (rebind/enable still flow through the
> CLI); not every single `freedom.yaml` flag has a dedicated toggle yet. The five
> advanced Channel fields named above are currently file-only, so they are not
> covered by first-class CLI/GUI controls. GUI rendering is compile-verified,
> not yet visually QA'd. This note exists so the
> GUI claim is never read as more than it is.

## Deliberate post-1.0 boundaries

Only the areas in this table are deliberate post-1.0 boundaries. The open v1
release blockers above are not moved into this table.

| Area | 1.0 boundary |
| :-- | :-- |
| Multi-tenant SaaS | NEOTH 1.0 is single-operator/private-cluster first. No hosted account control plane is required or promised. |
| Enterprise admin console | Policy is local and operator-owned; fleet admin UX belongs after the personal product is stable. |
| Public plugin marketplace trust at scale | 1.0 supports capability gates and audits; large ecosystem moderation is later work. |
| General-purpose device/file replication | Durable v1 mesh sync is scoped to canonical NEOTH memory, ground-truth, and policy-approved WAL classes. It is not a filesystem, account, or arbitrary application-data sync service. |
| Perfect deletion from third-party providers | NEOTH can redact local memory and stop re-promotion; it cannot erase data already sent to a provider by approved policy. |
| Arbitrary untrusted autonomous control | Autonomy is policy-gated and auditable. NEOTH is not a "give it root and pray" product. |
| Team collaboration | Project/team modes can build on the runtime later; 1.0 optimizes for one loyal assistant. |

## Verification command set

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
neoth doctor
neoth privacy audit --last 30d
```

The release workflow publishes checksums, minisign signatures, cosign bundles,
and the pinned public key beside the archives. A clean-install `neoth doctor`
run is separate launch-verification evidence; it is not embedded in an archive.
