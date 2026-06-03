# NEOTH Privacy Model

NEOTH's privacy model is simple: local-first, explicit destinations,
fail-closed profile extraction, auditable actions.

This document is the proof surface for users who do not want to trust the
README.

## The contract

| Rule | Meaning |
| :-- | :-- |
| Local-first memory | Durable profile facts, recall indexes, WAL, and operator data live in the NEOTH home by default. |
| Explicit provider routing | Model calls go to configured providers only; profile extraction does not silently fall back to cloud. |
| Fail-closed sensitive work | If a required local/private path is unavailable, NEOTH reports the problem instead of using a less private path. |
| Evidence before belief | Durable profile facts carry source evidence, confidence, and review state. |
| Redaction sticks | Redacted profile facts must not be re-promoted from old evidence without review. |
| Plugins have caps | Extensions get declared capabilities, not ambient filesystem or network power. |
| Every sensitive action leaves a trail | Provider calls, profile promotions, plugin hostcalls, outbound channel actions, and automation calls are auditable. |

## Verify it locally

```bash
neoth privacy audit --last 30d
neoth privacy audit --destinations
neoth profile show --evidence
neoth profile pending
neoth wal verify
neoth plugin ledger
neoth doctor
```

## What stays local

| Data | Default location |
| :-- | :-- |
| Operator config | `~/.neoth/freedom.yaml` |
| Secrets | `~/.neoth/credentials.yaml` |
| WAL audit trail | `~/.neoth/wal/` |
| Read-side indexes | `~/.neoth/views.db` |
| Profile facts | SQLite views backed by WAL events |
| Local model cache | HuggingFace cache / configured model cache |
| Skills and plugins | `~/.neoth/skills/`, plugin registry, capability ledger |
| Backups | `~/.neoth/backups/` unless configured otherwise |

## What may leave the machine

Only configured destinations:

| Destination | When it is used | How to inspect |
| :-- | :-- | :-- |
| LLM provider | You configure a cloud model for chat/reasoning. | `neoth provider show`, `neoth privacy audit --destinations` |
| Chat platform | You connect Telegram, WhatsApp, Slack, Discord, or another channel. | `neoth connect`, `neoth privacy audit --last 30d` |
| n8n | You enable localhost workflow calls. | `neoth n8n status`, WAL audit events |
| Cloud archive | You configure a sync folder or remote backend. | `neoth doctor --explain "cloud archive"` |
| Private mesh peer | You pair a node and approve discovery/transport. | `neoth cluster status`, `neoth doctor --explain "cluster mDNS announcer"` |

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

## OMI transcript ingest (OM-01)

OMI ingest is the **single most sensitive** surface in NEOTH: it passively reads
transcripts (potentially your everyday conversation) and feeds the high-confidence
ones into long-term memory. It is therefore the most tightly bounded surface, and
it is **off unless you turn it on**.

- **Default off.** `omi.enabled` is `false` on every fresh install. With it off,
  the ingest task never spawns and no transcript is ever read. Its state is
  visible at a glance as the `omi_ingest` safe-mode rail (`neoth security
  safe-mode`) and in `neoth trust`.
- **Local-only endpoint — a cloud endpoint is refused at startup.** When you
  enable it, the daemon polls `omi.endpoint` (default `http://127.0.0.1:8002`).
  An **SC-14 startup gate refuses to boot** if `omi.endpoint` resolves to a
  non-local host (e.g. `api.omi.me`) — so transcripts are pulled from *your*
  self-hosted backend and never sent to, or fetched from, an OMI cloud service.
  NEOTH itself opens no outbound connection except to that one local endpoint
  (enforced by the `no_outbound_network` build guard).
- **Every transcript passes the sanitizer first.** Each item is run through the
  `StreamBatchSanitizer` (SC-18) before anything else. A quarantined chunk
  (prompt-injection markers, control sequences) is **dropped** — it is never
  promoted to memory and never reaches a provider.
- **Only high-confidence items are promoted.** A surviving transcript is
  promoted to ground-truth **only** when its confidence is at or above
  `omi.confidence_threshold` (default `0.75`). Below the threshold it is
  discarded. Action items detected in the text become kanban tasks.
- **Raw transcript text is NOT stored in the audit trail.** The promotion emits
  a `0x9C OMI_ACTION_PROMOTED` WAL frame that carries **metadata only** — a text
  hash + the confidence, never the verbatim transcript. The promoted *statement*
  itself lives in the local ground-truth store (`views.db`) like the rest of
  memory; it never leaves the machine.
- **Delete / export controls.** A promoted statement is ordinary local memory:
  inspect it with `neoth recall`, export the full audit trail with `neoth wal
  export --sign`, and remove items through the standard memory-decay / forget
  path — there is no separate OMI silo. Turning `omi.enabled` back off stops all
  future ingest immediately; nothing already promoted is re-fetched.

For vulnerability reporting, see [../SECURITY.md](../SECURITY.md).
