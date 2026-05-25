# Architecture

NEOTH is a Rust-first, local-first operator runtime. The visible product is a loyal AI buddy; the machinery underneath is a memory, policy, provider, channel, coding, and automation control plane.

## System map

```text
Operator
  |
  | GUI / CLI / Telegram / WhatsApp / Slack / Discord / Keet / email / calendar
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

Every sensitive path is designed to cross the same trust boundary: policy, permission, WAL event, and operator-visible audit.

## Core components

| Component | Job |
| :-- | :-- |
| **Surface adapters** | Normalize GUI, CLI, chat apps, email, calendar, n8n, cron, and coding sessions into a shared request shape. |
| **Ingress sanitizer** | Blocks prompt-injection surfaces, quoted content, hostile markup, and unsafe inbound payloads before memory or profile learning. |
| **Pipeline router** | Builds the enriched request: profile, recall, skills, tools, operator rules, channel context, and active task state. |
| **Provider router** | Picks cloud/local providers by role, cost, latency, privacy, model capability, and circuit-breaker state. |
| **Council** | Triggers multi-model dissent when risk, complexity, contradiction, or explicit policy warrants it. |
| **WAL** | Durable source of truth for memory, provider calls, plugin actions, channel sends, recovery, and audit. |
| **SQLite views** | Queryable projections over the WAL: episodes, importance, council, motor state, habits, profile, embeddings. |
| **Obsidian mirror** | Human-readable knowledge layer for decisions, notes, reflections, project memory, and operator inspection. |
| **Plugin runtime** | Skills as data, WASM plugins as sandboxed code with capability gates. |
| **Private mesh** | LAN/mDNS, Tailscale, Hysteria, Keet, and consent-gated cluster nodes. |

## WAL source of truth

The WAL is the durable event chain under NEOTH. Views can be rebuilt; the WAL is authoritative.

It records:

- inbound and outbound messages
- provider calls and destinations
- memory/profile changes
- approval/decline events
- plugin and skill activity
- automation actions
- channel sends
- recovery and verification events
- cluster and capability lease events

Why this matters:

| Property | Result |
| :-- | :-- |
| Append-first | NEOTH can audit what happened even after failures. |
| Rebuildable views | SQLite projections are convenient, not irreplaceable. |
| Checks and authentication | Corruption and tamper paths become visible. |
| Redaction semantics | Sensitive values can be removed while preserving integrity events. |
| Operator commands | `neoth wal verify`, `neoth privacy audit`, and profile evidence views have real backing data. |

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
Media router
  |---- PDF text/forms
  |---- Image decode + CLIP embedding
  |---- Audio decode + Whisper transcript
  |---- Video audio + thumbnail/frame extraction
  |---- Paperless OCR import
  v
Extraction record
  |
  |---- WAL event
  |---- embedding/index update
  |---- profile-safe recall material
  v
Recall + answer + optional Obsidian mirror
```

Large files, untrusted documents, email bodies, and Paperless ingest pass through sanitizer and prompt-injection checks before becoming trusted context.

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

Provider calls are audited by destination and circuit-breaker state.

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
| LAN/mDNS | Local discovery at home or office. |
| Tailscale/WireGuard | Private cross-device mesh. |
| Hysteria | Restricted-network relay path. |
| Keet | P2P channel and future swarm direction. |
| Cluster policy | Node pairing, capability leases, topology view, health and resource state. |

Keys identify peers; operator approval grants membership and capabilities.

## Context assembly

Before an LLM call, NEOTH assembles bounded context blocks:

| Block | Content |
| :-- | :-- |
| A | System identity, operator rules, current autonomy level. |
| B | Approved profile facts, evidence summary, redaction constraints. |
| C | Relevant recall from episodes, files, documents, and project memory. |
| D | Active skills, tool catalog, channel state, coding canvas, Kanban state. |
| E | Per-request volatile outputs and safety constraints. |

The model does not receive raw WAL. It receives selected, policy-filtered context.

## Tool-Framework lineage

NEOTH follows the Tool-Framework v4.1 split:

| Layer | Responsibility |
| :-- | :-- |
| Tool | Bounded, testable capability. |
| Pipeline | Orchestration and context flow. |
| Ecology | Memory, adaptation, scoring, runtime behavior. |

State lives in the WAL and views. Tools stay small. Pipelines make behavior inspectable.
