# NEOTH Privacy Model

NEOTH's privacy model is simple: local-first, explicit destinations,
fail-closed profile extraction, auditable actions.

This document is the proof surface for users who do not want to trust the
README.

<img src="../.github/assets/neoth-readme-trust-stack.svg" alt="NEOTH trust stack — WAL evidence, local learning, permissioned memory, and capability gates under operator control" width="100%">

## The contract

| Rule | Meaning |
| :-- | :-- |
| Local-first memory | Durable profile facts, recall indexes, WAL, and operator data live in the NEOTH home by default. |
| Explicit provider routing | Model calls go to configured providers only; profile extraction does not silently fall back to cloud. |
| Fail-closed sensitive work | If a required local/private path is unavailable, NEOTH reports the problem instead of using a less private path. |
| Evidence before belief | Durable profile facts carry source evidence, confidence, and review state. |
| Redaction sticks | Redacted profile facts must not be re-promoted from old evidence without review. |
| Plugins have caps | Extensions get declared capabilities, not ambient filesystem or network power. |
| Governed core actions leave typed trails | Provider calls, profile promotions, plugin hostcalls, outbound channel actions, and selected automation calls have typed audit events. Coverage is surface-specific; the threat model names best-effort and log-only exceptions. |

## Verify it locally

```bash
neoth privacy audit --last 30d
neoth profile show --evidence
neoth profile pending
neoth verify
neoth plugin ledger
neoth doctor
```

## Forget and physical erasure

`neoth memory --forget <topic>` is a read-only preview. Re-run it with
`--confirm` to install the anti-resurrection tombstone and erase matching
recall, transcript, profile, graph, embedding, peer-ledger, and people-index
state. The `TOMBSTONE_REQUESTED` intent is fsynced before mutation; if that
audit write fails, erasure does not start. The derived HNSW cache is invalidated
before reconstruction, so a rebuild failure cannot leave forgotten vectors
searchable; recall falls back to the erased SQLite truth.

The tamper-evident WAL retains historical payload bytes by default. Add
`--physical` when those payload bytes must also be redacted. Any refused or
failed segment makes the command fail loudly instead of reporting a complete
physical erase.

## What stays local

| Data | Default location |
| :-- | :-- |
| Operator config | `~/.neoth/freedom.yaml` |
| Secrets | `~/.neoth/credentials.yaml` |
| WAL audit trail | `~/.neoth/wal/` |
| Read-side indexes | `~/.neoth/views.db` |
| Profile facts | SQLite views backed by WAL events |
| Local model cache | `~/.neoth/models/` (download libraries may also use their transfer cache) |
| Skills and plugins | `~/.neoth/skills/`, plugin registry, capability ledger |
| Backups | `~/.neoth/backups/` unless configured otherwise; `credentials.yaml` is excluded by default |

## What may leave the machine

Configured destinations include the following. Optional integrations add their
own explicitly configured endpoints; consult their guide and the threat model
before enabling them rather than treating this overview as exhaustive.

| Destination | When it is used | How to inspect |
| :-- | :-- | :-- |
| LLM provider | You configure a cloud model for chat/reasoning. | `neoth provider list`, `neoth privacy audit --last 30d` |
| Chat platform | You connect Telegram, WhatsApp, Slack, Discord, or another channel. | `neoth channel list`, `neoth privacy audit --last 30d` |
| Cloud TTS | You select Edge, ElevenLabs, Azure, or ViitorVoice and explicitly set `media.cloud_tts_enabled: true`. | `neoth tts status`, `neoth wal show --type tts_synthesized` |
| Public search/API | You run web search, arXiv, or another explicitly configured integration. | Command status/output and the surface-specific audit contract |
| Hugging Face | An allowed explicit model pull or an uncached Qwen/Ouro first use downloads weights. | `updater.allow_huggingface_downloads`, `neoth wal show --type model_download_start` |
| IMAP/OAuth | A source build enables IMAP and you explicitly run fetch or enable the default-off poller. | Email status, CLI triage frames, or daemon logs for the documented cron exception |
| Release host | You run self-update/staging against the pinned GitHub release repository. | Update status plus signed-update WAL metadata |
| n8n | You enable the loopback ingress API; n8n itself stays local, but scoped workflows can request provider/channel effects. | `neoth n8n status`, `neoth wal show --type n8n_request`, downstream event types |
| Cloud archive | You configure a sync folder or remote backend. | `neoth doctor --explain "cloud archive"` |
| Private mesh peer | You pair a node and approve discovery/transport. | `neoth cluster status`, `neoth doctor --explain "cluster mDNS announcer"` |

`neoth verify` proves the integrity of frames that exist. It does not by itself
prove that every possible external side effect emitted a frame. See the
[network and audit matrix](security/threat-model.md) for exact gates, audit
semantics, and known limitations.

## Fail-closed examples

| Situation | Expected behavior |
| :-- | :-- |
| Local profile model is missing | Doctor reports model cache/readiness; profile extraction does not silently switch to cloud. |
| Provider token is expired | Provider call fails or circuit-breaks; NEOTH does not use another provider unless policy allows it. |
| Plugin asks for a blocked hostcall | Plugin invocation is denied and audited. |
| Channel token is half-configured | Doctor reports configured-not-started state instead of pretending the channel is live. |
| Current Wi-Fi is not trusted | mDNS announcer stays quiet unless policy allows untrusted networks. |
| Redacted fact appears in old evidence | Fact stays redacted unless the operator explicitly re-approves. |

## Fully local preset

```bash
neoth preset activate fully-local
neoth preset apply fully-local
neoth doctor
neoth privacy audit --last 30d
```

Use this when the local machine is the trust boundary.

## Threat boundaries

NEOTH is designed for a single operator or trusted private cluster first.

| In scope | Not a 1.0 promise |
| :-- | :-- |
| Local user privacy from accidental cloud/provider exposure. | Multi-tenant SaaS isolation. |
| Tamper-evident action history. | Protection from an attacker with full OS/admin control. |
| Plugin capability gates and audit. | Trusting arbitrary unreviewed plugins blindly. |
| Private mesh pairing and transport policy. | Public internet control plane by default. |
| Redaction and evidence semantics. | Perfect deletion from third-party providers already called by policy. |

## Cross-channel identity (SPEC-11)

When you reach NEOTH from more than one channel (Telegram, Slack, WhatsApp, …),
it can link those channel-native aliases under one stable `human_uuid` so it
treats "you on Telegram" and "you on Slack" as the same person. This is useful —
but a unified identity is also a **tracking amplifier**, so it is bounded:

- **Auto-link is per-channel-alias, never cross-channel.** The inbound resolver
  mints a `human_uuid` per `(channel, sender_id, chat_id)` triple. NEOTH does
  **not** guess that two *different* channel aliases are the same person.
- **Linking two aliases is operator-controlled, explicit, and auditable.** Only
  `neoth identity merge <keep> <fold>` joins two identities. Every merge writes a
  `0x9B IDENTITY_MERGED` WAL frame carrying the full before-state (the reassigned
  aliases), so the link is reviewable in the audit chain (`neoth wal show --type
  identity_merged`).
- **Merge is reversible by design.** The folded identity is *tombstoned*
  (`merged_into` set), not deleted — the row + the audit frame retain enough to
  reconstruct a future `identity split`. No attribution history is destroyed.
- **The identity map never leaves the machine.** It lives in the local
  `views.db` like the rest of memory; it is not shared with providers or peers.

The `human_uuid` you receive an encrypted memory transfer under is your X25519
receiving key (`neoth identity pubkey`); it is unrelated to the channel-identity
map above and is auto-managed locally.

## OMI conversation and native media ingest (OMI-MULTIMODAL-01)

OMI can contain everyday speech, still images, and video-call frames. It is off
by default and every data/effect boundary is separately controlled.

- **Four explicit modes.** `developer_api` imports through OMI's official
  conversation list/detail API, `native_ingest` accepts authenticated live-call
  events, `both` also exports completed native transcripts through OMI's official
  segment API, and `legacy_memories` preserves the old local feed. A public OMI
  HTTPS endpoint is accepted only with `omi.allow_cloud_api: true`; legacy mode
  remains local-only. Native wildcard/public binds are always rejected.
- **Dedicated credentials.** Developer import/export requires an `omi_dev_*`
  key. Native ingest requires a separate bearer token of at least 32 bytes even
  on loopback. File and keychain backends share the same effective load path;
  status surfaces only presence, never secret values. Desktop writes use the
  bounded-stdin `neoth omi set-credentials` path, so secrets never enter argv
  and encrypted/keychain storage plus unrelated credential fields are preserved.
- **Independent consent controls.** Audio, images, video frames, raw transcript
  retention, summaries, task creation, ground-truth seeding, OMI cloud API use,
  and provider-backed cloud summaries are independent. Media byte and connection
  caps are enforced before buffering or decode. Raw audio/image bytes never enter
  the journal, WAL, or `views.db`.
- **SC-18 is fail-closed and durable.** Every external OMI text field, native
  caption, STT result, and vision result passes the stream sanitizer before
  journal persistence and before any summary, OMI export, memory promotion, or
  task creation. A quarantine performs
  none of those effects and persists `sanitizer_halted` across restarts. Only an
  explicit `neoth omi resume --review-note ...` clears it while retaining review
  evidence and the finding set.
- **Transactional, idempotent projection.** Conversation revisions, aligned
  segment hashes/optional text, media metadata, ground-truth, and task mappings
  reconcile in one transaction. Replayed revisions are no-ops; native event IDs
  are bound to the exact payload and semantic headers. Terminal calls are evicted
  from memory and reduced to bounded idempotency receipts. Audit records contain
  SHA-256 metadata, not transcript text. Both-mode export uses a stable upstream
  session id; an upstream `discarded: true` result is audited and completed
  locally instead of becoming a permanent retry/pending loop. Cancelled or failed
  calls never promote caller-supplied partial summaries/actions into summary,
  task, or ground-truth projections.
- **Opt-outs scrub immediately and monotonically.** Startup/reload applies the
  active controls before starting a candidate: disabled transcript/media/
  summary/ground-truth/action projections are deleted from `views.db`, and the
  same private fields are removed from native recovery journals. A shorter
  retention window is enforced immediately. If later readiness fails, NEOTH
  keeps the scrubbed state and does not restore a weaker runtime that would
  re-enable the revoked capture or retention boundary.
- **Bounded retention with anti-resurrection.** `retention_days` defaults to 30.
  Expiry and `neoth omi purge <id> --yes` remove the transactional database
  derivatives and native recovery receipt, then leave a tombstone so a later
  remote poll cannot silently restore it. Native purge requires a stopped daemon
  so active private state cannot survive in memory. Re-import requires the separate confirmed
  `neoth omi allow-reimport <id> --yes` action; native re-import also removes any
  stale receipt and reconciliation state before clearing the tombstone. The
  retention worker remains active after ingest is disabled, so already accepted
  records still expire on schedule.
- **Audited operator mutations.** Every offline OMI mutation has a dedicated,
  metadata-only operator WAL segment. Resume/re-import intents are fail-closed
  before lowering a safety boundary. Purge/retention follow the explicit
  `privacy_deletion_wins` contract: privacy deletion commits even if its audit
  sink fails, and the CLI reports that incomplete audit instead of hiding it.
  New frames use `extended/omi_lifecycle_audit`; historical `0x9C` promotion
  frames keep their original meaning for backward-compatible inspection.
- **Truthful operations.** `neoth omi status` and `neoth doctor` expose config,
  credential presence, ledger counts, pending reconciliation, sanitizer/
  retention errors, and PID-verified runtime posture without transcript
  content. Native readiness is acknowledged only after recovery and bind;
  ordinary failed candidates roll back to the last known-good runtime, while a
  failed privacy-reducing candidate leaves the weaker runtime stopped and a
  visible failed state. `neoth omi probe` tests local endpoint/listener
  reachability without making an unaudited public API call.

The complete setup, native event contract, storage model, and incident procedure
are in [runbook_omi_privacy.md](runbook_omi_privacy.md).

For vulnerability reporting, see [../SECURITY.md](../SECURITY.md).
