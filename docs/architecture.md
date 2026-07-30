# Architecture

NEOTH is a Rust-first, local-first operator runtime. The visible product is a loyal AI buddy; the machinery underneath is a memory, policy, provider, channel, coding, and automation control plane.

## System map

<img src="../.github/assets/neoth-readme-system.svg" alt="NEOTH 1.0 control plane — governed routes cross trust gates and emit typed events into the WAL-backed memory core" width="100%">

```text
Operator
  |
  | GUI / CLI / canonical 15-channel registry / CalDAV / optional IMAP
  v
Channel + Surface Adapters
  |
  v
Ingress Sanitizer + Identity + Allowlist
  |
  v
Pipeline Router
  |---- Recall
  |---- Profile claims
  |---- Skills
  |---- MCP/tool catalog
  |---- Coding canvas / Kanban state
  |---- Policy and autonomy context
  v
Provider Router
  |---- Fast role
  |---- Deep role
  |---- Council / dissent
  |---- Local Qwen / Ouro / CLIP / Whisper
  v
Response + Action Gate
  |
  |---- channel send
  |---- tool call
  |---- plugin hook
  |---- memory proposal
  |---- workflow action
  v
WAL + SQLite Views + Obsidian Mirror
```

Governed sensitive paths are designed to cross an explicit trust boundary:
policy or a dedicated opt-in, permission where the action engine applies, and
an operator-visible audit event where the path has WAL coverage. The exact
per-surface controls and documented best-effort/log-only exceptions are in the
[threat model](security/threat-model.md).

## Core components

| Component | Job |
| :-- | :-- |
| **Surface adapters** | Normalize GUI, CLI, the canonical messaging registry (Telegram, Slack, both WhatsApp transports, Keet-identity private topics, Discord, Signal, iMessage/BlueBubbles, Matrix, LINE, IRC, Mattermost, Twitch, Nostr, and Google Chat), CalDAV, source-build IMAP triage, n8n, cron, and coding sessions into shared governed request shapes. |
| **Ingress sanitizer** | Blocks prompt-injection surfaces, quoted content, hostile markup, and unsafe inbound payloads before memory or profile learning. |
| **Pipeline router** | Builds the enriched request: profile, recall, skills, tools, operator rules, channel context, and active task state. |
| **Provider router** | Picks cloud/local providers by role, cost, latency, privacy, model capability, and circuit-breaker state. |
| **Council** | Triggers multi-model dissent when risk, complexity, contradiction, or explicit policy warrants it. |
| **WAL** | Durable source of truth for memory and for the governed caller lifecycles that emit provider, plugin, channel, recovery, and audit events. Exact coverage and documented best-effort/log-only exceptions are listed in the threat model. |
| **SQLite views** | Queryable projections over the WAL: episodes, importance, council, motor state, habits, profile, embeddings. |
| **Babel-Index observer** | Async, content-free collapse scoring over the WAL stream: seven variables per rolling window, pre-registered failure labels, early warning before degradation ([babel-index.md](babel-index.md)). |
| **Obsidian mirror** | Human-readable knowledge layer for decisions, notes, reflections, project memory, and operator inspection. |
| **Plugin runtime** | Skills as data, WASM plugins as sandboxed code with capability gates. |
| **Private mesh** | Candidate discovery plus authority-gated cluster nodes over LAN/mDNS, Tailscale, Hysteria, and peeroxide/Hyperswarm. This cluster protocol is distinct from the separately shipped Keet-identity channel companion; neither path claims access to existing Keet app rooms. |

## WAL source of truth

The WAL is the durable event chain under NEOTH. Views can be rebuilt; the WAL is authoritative.

Rotating namespaces publish each successor atomically with an authenticated
cross-segment link and immediate HMAC marker. The link binds the canonical
predecessor/successor identities and final predecessor lengths/digest; scanners
validate the complete relevant chain before yielding frames to authority
consumers. Marker-bearing or linked segments currently refuse physical payload
redaction before mutation until the v1 signed, crash-recoverable rewrite
transaction is complete. This preserves chain truth while logical forget
remains available; it is not yet a complete physical-erasure implementation.

Its typed event families record core activity including:

- inbound and outbound messages
- governed provider-call intents, destinations, and results where the caller
  lifecycle has mandatory WAL coverage
- memory/profile changes
- approval/decline events
- plugin and skill activity
- automation actions
- channel sends
- recovery and verification events
- cluster and capability lease events

This list describes event families, not a proof that every external side effect
successfully appended a frame. `neoth verify` proves integrity of recorded
frames; coverage and fail-closed versus best-effort behavior are surface-specific.

Why this matters:

| Property | Result |
| :-- | :-- |
| Append-first | NEOTH can audit what happened even after failures. |
| Rebuildable views | SQLite projections are convenient, not irreplaceable. |
| Checks and authentication | Corruption and tamper paths become visible. |
| Redaction semantics | Sensitive values can be removed while preserving integrity events. |
| Operator commands | `neoth verify`, `neoth privacy audit`, and profile evidence views have real backing data. |

## Memory regions

NEOTH uses brain-region names as pragmatic memory analogies. They are not claims about consciousness; they are a way to keep different memory jobs separate.

| Region | View | Purpose |
| :-- | :-- | :-- |
| **Hippocampus** | `idx_episode` | Events, conversations, timelines, and time-anchored recall. |
| **Amygdala** | `idx_importance` | Salience, urgency, priority, and risk signals. |
| **Insula** | `idx_council` | Debate logs, dissent, verdicts, and reasoning traces. |
| **Cerebellum** | `idx_motor` | Tool outcomes, provider quotas, execution state, and action traces. |
| **Basal Ganglia** | `idx_habit` | Repeated patterns, skills, triggers, and routines. |
| **Hypothalamus** | `idx_profile` | Operator profile, preferences, evidence, redactions, and approval state. |
| **Visual/Semantic index** | `idx_embedding` | CLIP/Whisper/text vectors and multimodal similarity search. |

## Memory layers

| Layer | Job |
| :-- | :-- |
| **L1 Hot working set** | Active chat, current task, canvas, and volatile tool results. |
| **L2 Warm cache** | Recent recall, active project facts, and high-use context. |
| **L3 Episodic memory** | Conversations, events, decisions, and timelines. |
| **L4 Semantic memory** | Embeddings, files, images, audio, video, documents, and concepts. |
| **L5 Skills and habits** | Routines, trigger patterns, tool success, provider habits, learned workflows. |
| **L6 Vault mirror** | Obsidian-readable long-term archive owned by the operator. |

## Multimodal pipeline

```text
File / attachment / voice / image / video / document
  |
  v
Bounded admission + immutable snapshot
  |---- count, kind, byte and expansion ceilings
  |---- no-follow regular-file / reparse-point checks for local paths
  v
Media router
  |---- PDF text/forms
  |---- Image decode + CLIP embedding
  |---- Audio decode + Whisper transcript
  |---- Video audio + thumbnail/frame extraction
  |---- Paperless OCR import
  v
Bounded extraction record
  |
  |---- canonical untrusted attachment data (Block D)
  |---- WAL lifecycle / metadata
  |---- optional reviewed embedding/index update
  v
Exact operator caption (Block E) + answer
```

Attachment bytes, filenames, extracted text, email bodies, web pages, and
Paperless content remain untrusted data. They do not become system instructions
after parsing. Chat and channel ingress preserve the exact operator caption
separately, serialize attachment content through one bounded typed envelope, and
fail visibly if required content cannot fit the effective provider budget.

Parser and decoder work has modality-specific input, allocation, expansion,
duration, output, and diagnostic ceilings. Subprocess-backed extraction uses
private scratch storage plus bounded termination and reap; cloud transcription
requires a concrete request-bound authorization and durable intent before
egress. Ingest commands may promote reviewed extraction records into memory, but
that does not change their prompt trust class.

## Provider routing

NEOTH can route by role:

| Role | Typical provider |
| :-- | :-- |
| Fast answer | Low-latency cloud or local model. |
| Deep reasoning | Stronger cloud or local reasoning model. |
| Local profile extraction | Qwen/Ouro path. |
| Vision | CLIP/image-capable provider path. |
| Audio | Whisper path. |
| Council | Multiple role-bound providers with budget and dissent handling. |

Governed provider callers bind the final provider/model request before
authorization and record destination plus circuit-breaker state through their
caller lifecycle. Coverage is not inferred from a transport adapter alone; the
exact mandatory and best-effort paths are listed in the
[threat model](security/threat-model.md).

## Coding architecture

The coding buddy is not a separate product bolted on top. It is another surface over the same memory and policy core.

```text
Prompt
  |
  v
Canvas plan -> Kanban split -> role dispatch -> patch/test/review
  |
  v
Review findings + decisions + test outcomes
  |
  v
Project memory + Obsidian handoff + future recall
```

The important design point: code decisions survive the session.

## Private mesh

NEOTH can run as one node or as a consent-gated private mesh.

| Transport | Purpose |
| :-- | :-- |
| LAN/mDNS | Local candidate discovery at home or office; announcements never grant membership. |
| Tailscale/WireGuard | Private cross-device mesh. |
| Hysteria | Restricted-network relay path. |
| peeroxide/Hyperswarm | Optional transport for NEOTH's own authenticated cluster protocol; separate from the `neoth-keet-bridge` channel companion and not an adapter for existing Keet app rooms. |
| Cluster policy | Stable identity, authoritative enrollment/revoke, capability leases, topology view, health and resource state. |

The shared passphrase derives a `ClusterKey` used only for rendezvous/bootstrap
HMAC proof. It is not an authorization database. Each node instead owns a
passphrase-independent `LocalNodeIdentity`; its signing key derives the stable
node ID and its carrier identity persists across normal daemon restarts.
The mDNS v2 record combines those layers without conflating them: the HMAC
filters the rendezvous domain, while a signed `EndpointAttestation`
authenticates the candidate's stable identity and exact Peeroxide endpoint.
Neither check grants membership.

`cluster-membership.db` is the authority boundary. Discovery produces
candidates only. Enrollment follows
`authority invite -> exact carrier-bound signed EndpointAttestation -> confirm`,
then carrier admission returns an epoch-bound `MembershipGrant`. Revocation is
fail-closed and ordered: close the process-local admission gate; durably write
a `Pending` UUIDv7 request bound to the exact snapshot/digest/authority/member
generation; publish cancellation; tear down, drain, and classify every captured
external carrier effect; persist `Indeterminate` for any uncertain remote
outcome; only then commit the tombstone plus outbox. An orphaned `Pending`
request recovers durably as `Indeterminate`, never silently as `Completed`.
`cluster.yaml` is imported only as legacy `Pending` state and never authorizes a
session or effect. Revocation intent reason/source/status metadata are plaintext
in local SQLite (never secrets); OS file permissions are the storage boundary.

## Context assembly

Before an LLM call, NEOTH assembles bounded context blocks:

| Block | Content |
| :-- | :-- |
| A | Operator-explicit system text and trusted protocols. Protected from independent degradation. |
| B | Active skill and discipline instructions. Never dropped. |
| C | Approved profile/operator claims. Lowest-importance entries degrade first. |
| D | Recall plus typed untrusted tool, repository, channel, web, and attachment data. Optional entries may degrade; required attachment data fails closed instead. |
| E | The exact current operator message/caption. Exactly one is required and it is never dropped. |
| Conductor | Orchestration plan/spec metadata. Bounded by truncation rather than silent removal. |

The model does not receive raw WAL or an attachment-prepended synthetic user
message. It receives selected, policy-filtered blocks with trusted instructions
and untrusted data kept structurally separate.

## Tool-Framework lineage

NEOTH follows the Tool-Framework v4.1 split:

| Layer | Responsibility |
| :-- | :-- |
| Tool | Bounded, testable capability. |
| Pipeline | Orchestration and context flow. |
| Ecology | Memory, adaptation, scoring, runtime behavior. |

State lives in the WAL and views. Tools stay small. Pipelines make behavior inspectable.
