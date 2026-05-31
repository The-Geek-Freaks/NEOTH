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
| LLM provider | You configure a cloud model for chat/reasoning. | `neoth providers status`, `neoth privacy audit --destinations` |
| Chat platform | You connect Telegram, WhatsApp, Slack, Discord, or another channel. | `neoth channels list`, `neoth privacy audit --last 30d` |
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

For vulnerability reporting, see [../SECURITY.md](../SECURITY.md).
