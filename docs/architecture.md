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

## Shared chat turn engine

The direct CLI adapter prepares and admits the request before opening its
home-bound WAL writer. It then calls `cli::chat_turn_pipeline` with the selected
provider, configuration, writer, segment path, cancellation gate, and typed
output sink. The engine borrows these resources; it does not parse CLI options,
read a GUI launch envelope, or create and drain a writer.

The caller owns completion. The CLI closes the turn's cancellation gate after
the engine returns, drops its writer handle, and awaits the writer's completion
result before publishing deferred done output and the success terminal. A
writer finalization failure suppresses that success presentation. The accepted
configuration path also remains available to existing lower-level helpers, so
a local action uses the selected custom configuration.

Another in-process owner can supply the same admitted resources and its own
output sink. This seam does not itself provide daemon RPC, job persistence,
replay, or GUI ownership. The focused verification and its limits are recorded
in [the Waves 35–38 receipt](gold-wave35-38-verification.md).

## Proposed daemon chat and native CLI probe boundaries

Waves 39 and 40 are published at `e4b4a117f258df401467b5c10c17e6ef1d266b2c`.
Its full CI `34857514849` completed with Linux 16,174/5, Windows 16,111/1, and
macOS 16,164/5 from the same updater causes; it is not green acceptance evidence.
The daemon
plain-chat route accepts only a sealed same-user request. It rejects command
forms before capacity admission and before provider, configuration, local
action, or WAL work. The daemon keeps all turn resources and the CLI only falls
back when an RPC failure occurs before a write begins. Completion guards and
bounded response writes prevent a client from stalling shutdown.

The native CLI version probe is a separate, authority-bound update lane. It
binds the accepted descriptor, recaptures it immediately before contained
execution, uses a fixed version-only command, and records durable intent and
terminal receipts. Cancellation or timeout stops later component admission and
reaps the contained child before its terminal classification. It deliberately
does not cover npm, Git, OSV, installers, or automatic SelfApply. Unsupported
wrappers are reported by typed outcomes rather than guessed or launched. The
reviewed fixture-only repairs correct the earlier diagnostics and native-cancel
writer-join hang. Local validation is complete; publication and a new-head full
CI remain pending.

Neither boundary establishes daemon replay/status/cancel APIs, native GUI
behavior, live-provider behavior, or cross-platform acceptance.

## W41 Main and Buddy daemon chat

Wave 42 typed channel health is published at
`cb717ee54e40f9e27583a8534b8bc25130e773e4`. Its v5 proactive health reader
keeps exact channel references distinct even where Telegram/default and
Slack/default account-id text is equal, without changing outbound behavior.
That publication leaves P1-14 and P1-16 open and P1-17 partial.

W41 routes both the Main chat surface and Buddy through one
daemon-owned stream. The GUI is a presentation consumer: it cannot mint a
capability, consent proof, route, endpoint, or transport identity. The daemon
owns admission, provider/configuration selection, turn/WAL custody, and the
authority that converts a request-bound decision into an effect.

The preflight presents either Ready or a bounded safe-route
ConfirmationRequired prompt. Main and Buddy retain the three visible outcomes
Deny, AllowOnce, and AllowAlways; prompt text, attachment paths/names,
capabilities, grants, and bearers stay out of that prompt. Deny clears staged
state before provider effect. Stream frames carry bounded lifecycle/content
updates with per-handoff generations; Stop addresses the current handoff, and
reopen settles only the still-current Main/Buddy projection so an older detached
Buddy error cannot clear a newer Main turn.

Attachments remain typed untrusted data in the existing bounded envelope. The
operator caption stays separate, and required attachment material fails visibly
when it cannot fit the effective provider budget. Native validation now covers
the selected daemon core (2,108 passing tests) and six contract targets (29
passing tests). Python19+11+8, final GUIClippy02 and the Wasm feature check passed.
The public source and test receipts retain 230 inputs and seven executable hashes.
Exactly three GUI implementation modules are outside the core unit snapshot
(227 inputs) and covered by the final GUI snapshot (230 inputs); core-embedded
GUI parity text remains unchanged. This proves the recorded local admission,
effect-start, cancellation and lifecycle fixtures. Native GUI interaction,
live-provider delivery and full cross-platform CI acceptance remain separate
gates; no parent roadmap item closes from this batch alone.

## W43–47 coding-graph composition boundary

W43/W45 composed01 is approved across 19 paths. W47 repair06 is approved across
three target overlays. W46 repair06 is approved across 13 paths. The independently
reviewed 31-path composition is admitted and awaiting native gates. Its MCP, provider and
direct-CLI coverage is a bounded boundary, not a claim that every native surface
has a consumer. CRG-04 now has an implementation kernel, but its test evidence
is pending; CRG-03 and CRG-05 remain open. No runtime validation or roadmap leaf
closure follows until root-owned gates are green.

W46 adds the `pre_tool_use` hook boundary for configured MCP calls emitted by a
provider or requested through direct CLI MCP use. It validates bounded typed
metadata before invocation; each permit binds the same arguments, and invocation
still requires authorization. Incognito disables configured hook evaluation
while admission, cancellation and deadline checks remain active. Only bounded
allow, result-enrichment, and block outcomes are accepted; unsupported actions
fail closed and cannot rewrite tool arguments. This does not extend hook
coverage to every native surface.

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
