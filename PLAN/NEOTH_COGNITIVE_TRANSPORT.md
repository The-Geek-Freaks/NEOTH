# PLAN — NEOTH Cognitive Transport (NCT)

> **Repository target:** `PLAN/NEOTH_COGNITIVE_TRANSPORT.md`
> **Prepared:** 2026-07-27
> **Status:** adopted, research-backed `v1.0.0 Gold` implementation specification
> **Intended release lane:** `v1.0.0 Gold`; phases describe dependency order, not deferral
> **Owner:** TheGeekFreaks / NEOTH
> **Research cutoff:** 2026-07-27, Europe/Berlin
> **Decision class:** architecture + product differentiation + security boundary
> **Working product name:** **NEOTH Cognitive Transport (NCT)**
> **Internal schema name:** **NIR/1 — NEOTH Intermediate Representation v1**

---

## 0. Binding decision

### 0.1 Verdict

Build **NEOTH Cognitive Transport** as an evolution of the existing NEXUS/sub-agent handoff path, not as a second agent framework beside NEOTH.

NCT must combine five layers:

1. **Route selection:** decide whether a task should remain single-agent or use a bounded topology such as sequential, parallel, manager-worker, or council.
2. **Typed cognitive handoff:** transfer only the minimum sufficient task contract, state delta, evidence, references, uncertainty, and requested next action through NIR/1.
3. **Shared immutable state:** large content remains in a capability-scoped content-addressed store; agent messages carry references and revisions rather than repeatedly serializing the world.
4. **Authenticated admission:** every cross-agent transition is verified, revision-bound, capability-bound, replay-resistant, and auditable before it can alter state or authorize an action.
5. **Gold-shipped, operator-opt-in local latent fast path:** compatible local agents may exchange hidden/KV state only behind an exact-runtime fingerprint, an authenticated manifest, strict memory limits, and a mandatory visible commitment. Its `lab`/`experimental` label governs runtime activation and claims; it does not defer packaging, testing or the Gold DoD. It is never the sole authority for an external action.

### 0.2 Hard release boundary

NCT is part of `v1.0.0 Gold` under the binding operator scope correction in
`PLAN/ROAD_TO_1_0_GOLD.md`. Every phase in this specification must be
implemented, wired, qualified and packaged before the Gold tag. Historical
`post-Gold`, `v1.1`, or delayed-surface language describes dependency order
only and cannot defer work.

The dependency boundary remains strict:

- baseline and frozen fixtures precede optimization claims;
- `GOLD-R3-14` typed-context closure precedes V2 handoff migration;
- canonical schemas, references, revisions and admission precede active routing;
- authenticated admission and the action firewall precede any latent backend;
- every retained capability reaches daemon, CLI, GUI, Buddy, Doctor, Channels,
  packaging and exact-release evidence before it is called complete;
- an evidence-based backend-specific `SKIP` is allowed only when the roadmap
  records the verified safety, redundancy or no-consumer reason.

Throughout this specification, `optional`, `lab` and `experimental` mean
operator/runtime selection only. They never mean optional shipping or deferred
DoD. Gold includes the managed latent contract, null backend, compatibility
Doctor, installer/update/repair/uninstall lifecycle and at least one qualified
non-null exact-runtime backend. An individual additional adapter may be skipped
only through the evidence rule above; the entire latent capability cannot be
silently reduced to types, a null backend or future research.

The current Gold source of truth remains `PLAN/ROAD_TO_1_0_GOLD.md`. NCT may
not close, rename or obscure any existing Gold blocker. Shared evidence may
close overlapping acceptance criteria only when each affected task records the
same production source-to-sink proof explicitly.

### 0.3 Final product thesis

> **NEOTH selects the cheapest safe cognitive path for each task — direct model, compact state-delta handoff, or compatible local latent transfer — and leaves tamper-evident proof for every cross-agent state transition.**

That is the target. It is **not yet a claim**. It becomes a public claim only after the benchmark and security gates in this document pass.

---

## 1. Executive conclusion: is it a USP?

### 1.1 What is not a USP

| Candidate feature | 2026 reality | Verdict |
|---|---|---|
| Multi-agent handoffs | Standard in OpenAI Agents SDK, LangGraph, Microsoft Agent Framework, CrewAI, and other orchestrators [R17–R20] | Commodity |
| Structured JSON between agents | Common implementation technique; structured outputs are provider features [R12–R13] | Necessary, not differentiating |
| Shared state, persistence, checkpoints | Standard framework capability [R17–R20] | Commodity |
| Prompt caching | Native provider capability [R12–R13] | Cost optimization, not USP |
| Compact natural-language summaries | Extensively researched and implemented | Weak differentiation |
| Adaptive message representation | Published as OPTiMACS and related work [R02] | Research frontier, not exclusive |
| State-delta communication | Published in EMNLP and adjacent work [R03] | Not exclusive |
| Latent/KV-cache agent communication | LatentMAS, SDE, AVP, cache relays, and a growing research field already exist [R03–R07] | **Not a standalone USP** |
| A binary latent protocol | AVP already publishes a protocol and SDK [R07] | Not exclusive |
| Adaptive topology selection | A July 2026 controlled study already predicts which architecture wins in held-out settings [R01] | Valuable, but not exclusive |
| Cryptographic integrity for KV handoffs | Current research already demonstrates authenticated manifests [R08] | Required security, not exclusive |

### 1.2 What can become a defensible NEOTH differentiation

The defensible differentiation is the **integrated operating mechanism**, not one primitive:

- direct-vs-multi-agent decision before coordination begins;
- adaptive topology **and** message codec selection;
- provider-agnostic typed state deltas and immutable references;
- exact-runtime local latent fast path;
- visible commitments plus cryptographic payload binding;
- capability leases and the existing fail-closed action gate;
- content-free, HMAC-chained WAL evidence;
- Babel-informed coordination-pressure telemetry;
- local-first operation and operator-explainable route receipts;
- A2A interoperability without surrendering NEOTH’s internal trust model;
- reproducible public benchmarks that show when the feature helps and when it does not.

No primary source located in this research pass demonstrated this complete combination as a production-oriented, local-first, auditable runtime. That supports a **product differentiation hypothesis**, not a legal novelty or “first in the world” claim.

### 1.3 USP strength by layer

| Layer | Differentiation strength | Required proof |
|---|---:|---|
| NIR/1 typed handoffs | Low–medium | token/cost reduction without quality loss |
| State revisions + references | Medium | deterministic replay, reduced duplication, crash safety |
| Adaptive direct/topology/codec routing | Medium–high | held-out route selection and lower total cost at non-inferior quality |
| Cryptographically admitted hybrid text/latent handoffs | High | complete tamper/replay/mismatch rejection and action-gate binding |
| Babel-calibrated coordination throttling | Potentially high | out-of-sample predictive lift; no hard steering from an unvalidated scalar |
| Whole NCT system inside NEOTH | **Strong product-level hypothesis** | public, reproducible benchmark dossier |

### 1.4 The moat is not secrecy

NEOTH is open source. The durable moat would be:

- the accumulated per-model/per-task routing evidence;
- the compatibility fingerprint matrix;
- the benchmark corpus and failure taxonomy;
- integration with NEOTH’s WAL, leases, memory tiers, provider router, mesh, Graphify, and Babel observer;
- operational reliability and explainability;
- a truthful product narrative backed by reproducible data.

A cryptic “AI language” can be copied. A measured, secure, self-observing cognitive transport layer is much harder to reproduce well.

---

## 2. Research and review iterations

This plan reflects six explicit challenge rounds. Each round was allowed to invalidate the previous framing.

### Round 1 — premise falsification

**Initial premise:** a compact or latent AI language may itself be a major advantage.

**Finding:** there is no known universal model-independent latent language. Natural-language replacement is task-, model-, tokenizer-, and architecture-dependent. OPTiMACS explicitly treats representation choice as adaptive rather than fixed [R02]. Latent communication literature spans embeddings, hidden states, KV caches, alignment strategies, and fusion methods rather than one universal channel [R06].

**Decision:** NIR is a canonical semantic contract with multiple codecs. Never make one cryptic surface syntax the architecture.

### Round 2 — market and prior-art challenge

**Initial premise:** latent inter-agent transfer might be the USP.

**Finding:** LatentMAS reports large token and latency gains in controlled model setups; AVP already specifies latent/KV handoffs with compatibility negotiation and JSON fallback [R04–R07]. State Delta Encoding and other methods already augment text with model state [R03].

**Decision:** latent communication alone is not a USP. It becomes one
Gold-shipped, operator-opt-in lane behind a broader adaptive and auditable
system.

### Round 3 — multi-agent value challenge

**Initial premise:** optimize communication whenever multiple agents are used.

**Finding:** a controlled 2026 study across 260 configurations found that multi-agent collaboration can help or hurt depending on task, model capability, and topology, and reported successful architecture selection on held-out within-domain configurations [R01]. Stronger base models can outgrow some collaboration benefits.

**Decision:** the first routing question is **“Should NEOTH delegate at all?”** Communication compression is downstream of that decision.

### Round 4 — NEOTH architecture fit

**Finding in current source:** NEXUS already has typed request/result structures, bounded fan-out, QA, provider identity, token fields, WAL evidence, and private result storage. The costly seam is that `SubAgentRequest.context`, result `output`, and evidence remain free text, and the runtime re-inserts the original context and candidate into primary, QA, and retry prompts [R24–R25].

**Decision:** evolve NEXUS with a versioned V2 handoff and dual-read migration. Do not build a parallel harness.

### Round 5 — security red team

**Initial premise:** a readable receipt beside latent state is sufficient.

**Finding:** current latent-agent security work shows that visible-text verification can miss tampered KV state. One study authenticated sender/session/model/visible commitment/tensor metadata/payload digest and rejected all recorded altered payloads in its replay corpus, while another demonstrates latent-only attack effects [R08–R09].

**Decision:** a plain receipt is insufficient. NCT requires a cryptographic manifest, admission verifier, replay control, exact runtime fingerprint, explicit downgrade, and a rule that latent state cannot directly authorize an external action.

### Round 6 — release and complexity red team

**Finding:** NEOTH is still pre-Gold and has explicit open release blockers.
Landing a latent sidecar, A2A surface, adaptive learning loop and new state
store out of dependency order would increase the unverified state space and
undermine the existing gates [R23].

**Decision:** all NCT phases are Gold scope, but must land in the dependency
order below. Baseline and typed-boundary work come first; off/shadow mode
precedes active routing; authenticated admission precedes external or latent
transfer; latent remains the last implementation lane.

### 2.1 Corrections to the initial proposal

| Initial direction | Corrected direction |
|---|---|
| “A compact AI language could be the USP” | The **adaptive, authenticated cognitive transport system** is the potential USP |
| One concise schema with cryptic keys | Full semantic schema internally; compact provider-specific codecs only after measurement |
| Latent transfer as primary path | NIR/ref path is primary; latent ships in Gold but runtime activation is opt-in and narrowly eligible |
| Human-readable audit receipt | Cryptographic manifest **plus** visible commitment **plus** WAL receipt |
| Multi-agent optimization by default | Direct/single-agent is a first-class route and often the correct answer |
| Generic cross-model latent transfer | Exact same-runtime is the first Gold-qualified implementation; cross-model use requires its own qualification |
| New protocol stack | NCT internal; A2A for external agent interoperability; MCP remains tools/resources/context |
| Immediate implementation | Dependency-ordered staged work inside the Gold lane |

---

## 3. Product definition

### 3.1 Category

**Sovereign cognitive transport layer for local-first agent runtimes.**

“Cognitive transport” means the controlled movement of task intent, state, evidence, commitments, and—only where safe and compatible—latent model state between execution actors.

It does **not** mean network transport. NEOTH already has a `transport` module for provider egress and private carriers. The Rust module must therefore be named:

```text
SRC/neothd/src/cognitive_transport/
```

### 3.2 Primary users

- NEOTH itself: left/right/callosum, Council, coding sub-agents, retries, QA, provider fallbacks, cluster workers.
- Operators who need lower cost and explainable routing.
- Local-model users who can benefit from exact-compatible KV/hidden-state transfer.
- External A2A peers that can exchange typed NIR artifacts without obtaining internal NEOTH authority.

### 3.3 User-visible outcomes

- fewer repeated tokens and duplicated context;
- lower latency/cost where the route is eligible;
- better failure containment under fan-out and retries;
- an explanation of why a single model, Council, or sub-agent path was selected;
- deterministic references to artifacts and evidence;
- explicit fallback when a compact/latent path is unsafe or unhelpful;
- verifiable audit evidence without recording private payloads.

### 3.4 Public claim ladder

#### Claim level 0 — safe after implementation

> NEOTH uses typed, revision-bound state handoffs instead of blindly copying full context between agents.

#### Claim level 1 — requires benchmark pass

> NEOTH adaptively selects direct or multi-agent execution and reduces coordination cost without measurable quality loss on the published evaluation set.

#### Claim level 2 — requires latent + security pass

> Compatible local NEOTH agents can transfer authenticated latent working state, with visible commitments and fail-closed fallback to typed handoffs.

#### Claim level 3 — prohibited without independent legal and market proof

Do **not** claim:

- “the first AI language”;
- “the first latent agent protocol”;
- “zero-token agents” as a system-wide statement;
- “universal model telepathy”;
- “works across all models”;
- “always cheaper/faster/better”;
- “patented/patentable”;
- “first in the world”;
- “cryptographically proves the model reasoned correctly.”

The manifest proves payload integrity and binding under its threat assumptions. It does not prove semantic truth, benign intent, or uncompromised endpoints.

---

## 4. Scope and non-goals

### 4.1 In scope

- NIR/1 schemas and codecs;
- immutable content references;
- state snapshot/revision and typed deltas;
- prompt/context projection;
- actual token/cache/cost/latency telemetry;
- deterministic route policy and later data-driven selection;
- direct, sequential, bounded parallel, manager-worker, and Council routes;
- cryptographic transfer manifests and admission verification;
- explicit downgrade/fallback semantics;
- A2A interoperability profile;
- local latent backend interface and sidecar;
- Babel telemetry integration;
- CLI/operator diagnostics;
- benchmark, fuzz, adversarial, and conformance suites.

### 4.2 Out of scope for NCT v1

- exporting private chain-of-thought;
- storing or displaying latent state as “reasoning”;
- latent transfer through commercial closed-model APIs;
- arbitrary cross-model projection in production;
- a new generic network carrier;
- replacing MCP;
- replacing A2A discovery or task lifecycle;
- giving opaque latent payloads action authority;
- unbounded swarms or recursive fan-out;
- self-modifying route policy in production;
- online reinforcement learning before a frozen offline benchmark exists;
- a second product integration path outside the Gold workstream;
- patentability or freedom-to-operate conclusions.

### 4.3 Design principles

1. **Semantic core, replaceable codec.**
2. **Reference, do not repeat.**
3. **Delta, do not retell.**
4. **Direct route is a success condition, not a fallback.**
5. **No opaque state crosses a trust boundary without authenticated admission.**
6. **No transfer grants authority. Authority comes from existing capability and action gates.**
7. **Fail closed, downgrade visibly.**
8. **Measure total system cost, not message character count.**
9. **Preserve operator inspectability without logging private payloads.**
10. **No claim outruns evidence.**

---

## 5. Current NEOTH seam and integration point

### 5.1 Existing substrate

NEOTH already provides the foundations NCT needs:

- provider routing and exact wire-model identity;
- left/right/callosum role separation and Council;
- typed NEXUS sub-agent request/result structures;
- bounded fan-out and concurrency;
- structured QA verdicts and retry cap;
- private run records and content-free WAL events;
- capability leases and fail-closed boundaries;
- HMAC-chained audit log;
- local-first memory and mesh;
- Babel observer and calibration;
- Graphify/release-bound self-knowledge.

The README describes role-bound paths, Council arbitration, winner tracking, collapse telemetry, and verifiable WAL mechanisms [R26].

### 5.2 Current duplication seam

Current source has:

```rust
pub struct SubAgentRequest {
    // typed routing fields...
    pub context: String,
    pub deliverable: String,
    pub success_criteria: Vec<String>,
    pub evidence_required: Vec<String>,
}
```

and:

```rust
pub struct SubAgentResult {
    // typed verdict/provider fields...
    pub evidence: Vec<String>,
    pub output: String,
}
```

The runtime currently:

- clones `request.context` into the primary provider prompt;
- embeds the original context and full candidate in the QA prompt;
- embeds original context, previous candidate, and QA failures again in the retry prompt;
- stores full output privately while the WAL receives hashes/metadata [R24–R25].

This is already a good bounded and auditable flow. NCT should replace repeated free-text serialization with a typed projection and references, while retaining the current QA, provider authorization, private-record, and WAL behavior.

### 5.3 Required integration map

```text
Pipeline / Coding / Council / Channel / Buddy / Cron
                         |
                         v
              CognitiveRoutePlanner
              - direct vs topology
              - codec eligibility
              - risk/budget/privacy
                         |
                         v
                ContextProjector
              - task contract
              - state revision
              - deltas + references
              - visible commitment
                         |
                         v
          NIR Codec / Legacy Compatibility
           |             |              |
           v             v              v
       Provider       A2A peer      Latent backend
           \             |              /
            \            |             /
                         v
                AdmissionVerifier
              - schema and limits
              - refs/revision
              - signature/MAC
              - capability lease
              - replay/expiry
                         |
                         v
              Existing Response Gate
                         |
                         v
               Existing Action Gate
                         |
                         v
           WAL / private run record / metrics
                         |
                         v
              Babel observer + evaluator
```

### 5.4 Files and modules

Adopted Gold layout:

```text
SRC/neothd/src/cognitive_transport/
├── mod.rs
├── types.rs
├── nir.rs
├── limits.rs
├── refs.rs
├── revisions.rs
├── delta.rs
├── projection.rs
├── codec.rs
├── routing.rs
├── policy.rs
├── manifest.rs
├── admission.rs
├── telemetry.rs
├── legacy.rs
├── a2a/
│   ├── mod.rs
│   ├── agent_card.rs
│   ├── mapping.rs
│   └── conformance.rs
└── latent/
    ├── mod.rs
    ├── backend.rs
    ├── fingerprint.rs
    ├── envelope.rs
    └── sidecar.rs
```

Adjacent changes:

```text
SRC/neothd/src/sub_agents/schema.rs       # V2 handoff/result + legacy adapter
SRC/neothd/src/sub_agents/runtime.rs      # projection, refs, usage, admission
SRC/neothd/src/council/                   # topology + NIR integration
SRC/neothd/src/providers/                 # structured output + actual usage
SRC/neothd/src/context/                   # typed untrusted projection reuse
SRC/neothd/src/wal/                       # NCT event registry
SRC/neothd/src/analytics/                 # content-free NCT/Babel signals
SRC/neothd/src/config/                    # frozen config schema
SRC/neothd/src/cli/                       # `neoth cognition`
schemas/nct/                              # versioned JSON schemas
docs/cognitive-transport.md
docs/security/cognitive-transport-threat-model.md
docs/a2a-nir-profile.md
docs/runbook-cognitive-transport.md
benches/cognitive_transport/
tests/nct_*/
```

Do not name this module `transport`; that name is already used by NEOTH’s network/provider transport layer.

---

## 6. NIR/1 — canonical semantic handoff

### 6.1 Core rule

NIR is **not** a secret shorthand language. It is a canonical typed semantic contract.

The internal Rust type uses explicit field names and strong enums. A codec may produce compact JSON, provider tool calls, A2A parts, or a latent envelope, but all codecs map to the same semantic object.

### 6.2 Minimum sufficient handoff

A handoff contains:

\[
M = (\text{intent}, \text{contract}, \text{base revision}, \Delta\text{state},
\text{references}, \text{claims}, \text{uncertainty}, \text{requested next action})
\]

It does not contain:

- the full conversation by default;
- unchanged memory;
- raw files larger than the inline threshold;
- repeated system instructions;
- chain-of-thought;
- unbounded logs;
- complete candidate output on every retry.

### 6.3 Proposed request schema

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NirFrameV1 {
    pub schema: SchemaId,                 // "neoth.nir.frame.v1"
    pub frame_id: FrameId,                // UUIDv7
    pub session_id: SessionId,
    pub parent_frame_id: Option<FrameId>,
    pub sequence: u64,

    pub from: ActorId,
    pub to: ActorId,
    pub task_id: TaskId,
    pub phase: WorkPhase,
    pub priority: HandoffPriority,

    pub intent: Intent,
    pub contract: WorkContract,
    pub state: StateProjection,
    pub claims: Vec<Claim>,
    pub requested_actions: Vec<ActionIntent>,

    pub privacy: PrivacyLabel,
    pub taint: Vec<TaintLabel>,
    pub capability_scope: CapabilityScope,
    pub lease_id: Option<LeaseId>,

    pub codec_hint: Option<CodecId>,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}
```

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkContract {
    pub deliverable: DeliverableKind,
    pub instructions: BoundedText,
    pub acceptance_criteria: Vec<Criterion>,
    pub evidence_requirements: Vec<EvidenceRequirement>,
    pub output_schema: Option<SchemaRef>,
    pub max_attempts: u8,
}
```

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateProjection {
    pub base_revision: StateRevision,
    pub delta: StateDelta,
    pub refs: Vec<ContentRef>,
    pub omitted: Vec<OmissionReceipt>,
}
```

### 6.4 Proposed result schema

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NirResultV1 {
    pub schema: SchemaId,                 // "neoth.nir.result.v1"
    pub frame_id: FrameId,
    pub in_reply_to: FrameId,
    pub session_id: SessionId,
    pub task_id: TaskId,

    pub from: ActorId,
    pub to: ActorId,
    pub verdict: QaVerdict,

    pub claims: Vec<Claim>,
    pub evidence: Vec<EvidenceRef>,
    pub artifacts: Vec<ContentRef>,
    pub proposed_delta: StateDelta,
    pub requested_actions: Vec<ActionIntent>,
    pub next: Option<NextStep>,

    pub confidence: Option<Confidence>,
    pub uncertainty: Vec<Uncertainty>,
    pub usage: Vec<ProviderUsage>,

    pub created_at_unix_ms: i64,
}
```

### 6.5 Claim and evidence model

```rust
pub struct Claim {
    pub claim_id: ClaimId,
    pub subject: SubjectRef,
    pub predicate: PredicateId,
    pub value: ClaimValue,
    pub confidence: Option<Confidence>,
    pub evidence: Vec<EvidenceRef>,
    pub scope: ClaimScope,
}

pub struct EvidenceRef {
    pub content: ContentRef,
    pub locator: Option<ContentLocator>,  // line/range/page/event, bounded
    pub evidence_kind: EvidenceKind,
    pub digest: Digest,
}
```

A claim is not accepted as fact merely because it exists in NIR. Existing NEOTH evidence, ground-truth, memory, QA, consent, and action policies remain authoritative.

### 6.6 Action intent

```rust
pub struct ActionIntent {
    pub action_id: ActionId,
    pub tool_or_capability: CapabilityId,
    pub arguments_ref: ContentRef,
    pub requested_scope: CapabilityScope,
    pub reason_claims: Vec<ClaimId>,
    pub requires_operator_confirmation: bool,
}
```

`ActionIntent` is a request. It is **never** an authorization. The existing action gate must re-validate the live lease, policy, arguments, endpoint, consent state, and current config generation.

### 6.7 Model-facing example

Canonical semantic frame:

```json
{
  "schema": "neoth.nir.frame.v1",
  "frame_id": "0198...",
  "session_id": "0198...",
  "sequence": 14,
  "from": "cerebellum",
  "to": "rust-reviewer",
  "task_id": "kanban:auth-null-guard",
  "phase": "verify",
  "priority": "high",
  "intent": "verify_patch",
  "contract": {
    "deliverable": "qa_verdict",
    "instructions": "Verify the patch against the listed criteria.",
    "acceptance_criteria": [
      {"id": "c1", "kind": "test_passes", "target": "ref:test-set-3"},
      {"id": "c2", "kind": "no_untrusted_prompt_bypass", "target": "ref:patch-4"}
    ],
    "evidence_requirements": [
      {"kind": "test_output", "target": "ref:test-set-3"}
    ],
    "max_attempts": 1
  },
  "state": {
    "base_revision": "b3:...",
    "delta": {"ops": []},
    "refs": [
      {"id": "ref:file-2", "kind": "file_slice", "digest": "b3:...", "locator": "88:125"},
      {"id": "ref:patch-4", "kind": "patch", "digest": "b3:..."},
      {"id": "ref:test-set-3", "kind": "test_set", "digest": "b3:..."}
    ],
    "omitted": []
  },
  "claims": [],
  "requested_actions": [],
  "privacy": "private",
  "taint": ["operator_supplied", "repository_content"],
  "capability_scope": "code:read+test:run",
  "created_at_unix_ms": 1785140000000,
  "expires_at_unix_ms": 1785140900000
}
```

A compact provider codec may shorten keys only after a per-model benchmark proves that it lowers true token count without increasing parse, repair, or semantic error rates. The compact form is never the canonical persisted schema.

### 6.8 Protocol invariants

- Every frame has a unique `frame_id`, parent, session, and monotonic sequence.
- Every state delta names its exact base revision.
- Every reference has an authoritative digest; aliases are convenience only.
- Every field is size-, count-, and depth-bounded before allocation.
- Unknown schema major versions fail closed.
- Unknown optional fields may be retained but cannot grant authority.
- A frame cannot self-grant capability, privacy downgrade, or policy exemption.
- A result cannot modify state until admission and revision checks pass.
- A retry references the prior candidate and failures; it does not concatenate unbounded prose.
- No NIR field stores hidden chain-of-thought.
- A codec round-trip must preserve canonical semantics.

---

## 7. Content references and state deltas

### 7.1 Content-addressed reference store

Large content is stored once and referenced by digest.

```rust
// Private CAS index record. Never serialized into NIR or returned to a peer.
pub struct StoredContentObject {
    pub storage_digest: Digest,            // unkeyed internal integrity/index digest
    pub size_bytes: u64,
    pub publication_epoch: u64,
    pub encryption_domain: EncryptionDomainId,
}

// Subject-visible, authority-scoped reference.
pub struct ContentRef {
    pub id: RefId,                         // keyed opaque ID, never storage_digest
    pub subject_id: SubjectId,
    pub authority_namespace: AuthorityNamespace,
    pub encryption_domain: EncryptionDomainId,
    pub kind: ContentKind,
    pub object_commitment: KeyedDigest,
    pub size_bytes: u64,
    pub media_type: MediaType,
    pub locator: Option<ContentLocator>,
    pub privacy: PrivacyLabel,
    pub taint: Vec<TaintLabel>,
    pub provenance: ProvenanceRef,
    pub metadata_digest: Digest,
    pub grant_metadata_digest: Digest,
    pub expires_at_unix_ms: Option<i64>,
}
```

The model sees `ref:file-2`, not a host path, raw UUID, credential, or unrestricted URI.

The unkeyed `storage_digest` is an internal integrity/index value and never a
visible identifier or existence oracle. `RefId` and `object_commitment` are
derived with a domain-separated key scoped to the subject, authority namespace
and encryption domain over the internal digest plus canonical metadata. The
metadata digest binds kind, size, media type, privacy, ordered taint,
provenance, expiry and encryption domain; the grant-metadata digest binds
issuer, grantee, purpose, authorization epoch, lease/session and allowed range.
Changing any of those values creates a different reference/grant.

CAS namespaces, object keys and encryption keys are isolated by subject and
authority namespace. Identical plaintext in two subjects is independently
encrypted, indexed and published and produces unrelated visible IDs and
commitments. The resolver neither confirms cross-subject existence nor reuses a
foreign subject's stored object, timing/cache hit, grant or encryption domain.
Physical cross-subject deduplication is forbidden for NCT v1.

Local publication is fail-closed and immutable:

- `neothd`, not a model or sidecar, owns publication;
- publication selects the subject/authority encryption domain before reading
  bytes and cannot move a staged object to another domain;
- bytes stream through a newly created private temporary object under the
  declared per-object and aggregate limits while the full digest and exact
  length are computed;
- the object is not addressable until the bounded stream reaches EOF, its
  digest, length and media constraints match, and metadata plus bytes are
  durably committed;
- publication uses an atomic no-replace transition into an owner-only CAS
  namespace; an existing digest is reused only after its stored length and
  metadata are revalidated;
- callers receive only the session-local opaque alias after commit;
- partial, over-limit, changed-during-read or unverifiable objects are removed
  from the staging namespace and never become resolver-visible.

### 7.2 Reference resolution rules

- Resolution is capability-scoped and actor-scoped.
- The resolver checks current session, digest, privacy label, lease, range, and byte budget.
- The resolver maps the keyed visible commitment to one private internal digest
  only after subject, authority namespace, encryption domain, metadata and grant
  digests pass.
- Filesystem paths never become authority-bearing reference IDs.
- A range request is contained to the referenced object and normalized before read.
- The resolver returns typed content envelopes through the existing untrusted-context boundary.
- References are immutable. Updating content creates a new digest and state revision.
- Missing, expired, mismatched, or oversized refs fail visibly.
- Remote A2A references use expiring scoped retrieval handles or A2A artifacts, never raw internal paths.
- Secret-bearing refs are not eligible for cross-node or cloud projection unless existing consent policy explicitly allows it.
- Every retrieval handle binds the exact actor, subject, purpose, authorization
  epoch, capability lease, session, object digest, permitted byte range, byte
  budget and expiry. A handle is not transferable between actors, tasks,
  purposes or sessions.
- The resolver compares the handle's authorization epoch with the durable
  monotonic revocation floor before opening the object, during a bounded
  streaming interval, and immediately before the consumer commits a derived
  result. A mid-stream revoke aborts the stream, invalidates the handle and
  discards uncommitted derived bytes.
- Local sources are consumed through already-opened, no-follow handles owned by
  the Rust core. A model-, sidecar- or peer-supplied path cannot be reopened
  after admission.
- Remote retrieval is HTTPS-only and re-runs scheme, userinfo, hostname, port,
  DNS result, public-IP and redirect policy on every hop and on the actual
  connected address. Redirects and DNS rebinding cannot reach loopback,
  link-local, private, metadata or other denied ranges.
- Credentials, cookies, bearer tokens and client certificates are never
  forwarded across an origin change. Redirect count, response headers, encoded
  bytes, decoded bytes, time, range and content type are bounded before data
  reaches CAS.

### 7.3 State revision

Start with a deterministic snapshot manifest, not a complex distributed Merkle graph.

```text
StateRevision =
    BLAKE3(
      domain_separator ||
      sorted(logical_key, content_digest, metadata_digest)
    )
```

The manifest is private, immutable, and transactionally published. A Merkle tree can be added later if profiling shows that full manifest hashing is material.

### 7.4 Delta operations

Avoid arbitrary unrestricted JSON Patch over global state. Use a bounded enum:

```rust
pub enum DeltaOp {
    UpsertRef {
        key: StateKey,
        value: ContentRef,
        expected_old: Option<Digest>,
    },
    RemoveRef {
        key: StateKey,
        expected_old: Digest,
    },
    AddClaim {
        claim: Claim,
    },
    RevokeClaim {
        claim_id: ClaimId,
        expected_digest: Digest,
    },
    AddArtifact {
        artifact: ContentRef,
    },
    ApplyTextPatch {
        target: ContentRef,
        patch: ContentRef,
        expected_target_digest: Digest,
    },
}
```

### 7.5 Delta apply transaction

1. Verify frame admission.
2. Resolve and verify all referenced digests.
3. Lock the target state namespace.
4. Confirm `base_revision`.
5. Validate every expected-old digest.
6. Stage all changes in a private temporary namespace.
7. Re-run capability and policy checks for any effectful artifact.
8. Compute new revision.
9. Atomically publish the state manifest.
10. Emit content-free commit/abort WAL event.
11. Only then expose an `ActionIntent` to the action gate.

Revision conflict does not silently merge. It produces a typed conflict result and may route to a bounded merge agent or operator.

### 7.6 Garbage collection

- session-local aliases expire separately from content;
- unreferenced CAS objects are collected after a safety grace period;
- pinned evidence, releases, ground truth, and audit-required artifacts obey their own retention policies;
- latent tensors are not stored in CAS by default;
- GC has byte/time caps and a dry-run/audit command;
- crash recovery reconciles staged, referenced, and committed objects.

GC uses a snapshot/epoch barrier rather than a best-effort directory scan:

1. Every state commit, pin, lease and resolver-handle mutation updates the
   authoritative root tables and advances or observes the CAS epoch in the same
   database transaction.
2. A GC pass opens a consistent read transaction, captures epoch `E` and the
   complete roots/pins/leases visible at `E`, and marks only objects whose
   publication epoch is not newer than `E`.
3. Marked objects remain unavailable for deletion through a configured grace
   period; new roots may still rescue them.
4. Deletion opens a new write transaction and rechecks the current root,
   revision, pin, lease, live handle, grace deadline and object digest. Any
   change clears the candidate instead of deleting it.
5. The tombstone and authoritative index removal commit before unlinking bytes;
   crash recovery either completes that unlink or restores a still-rooted
   object without exposing a partial publish.

No object is deleted solely because it was absent from an earlier snapshot.
Concurrent state publication, rollback, evidence pinning, lease renewal and
mid-stream retrieval have explicit roots or barriers and are covered by race
tests.

---

## 8. Context projection and prompt construction

### 8.1 Projection, not replay

Each receiving actor gets a role-specific projection:

```text
project(actor, task, revision, policy, budget)
    -> NirFrameV1
```

The projector decides:

- which state keys are relevant;
- which content can remain a reference;
- which small fragments need inline rendering;
- which claims and uncertainties matter;
- which fields must be omitted for privacy, capability, or token budget;
- whether a missing prerequisite should block delegation before a paid call.

### 8.2 Prompt layout

For providers that support caching:

```text
[stable system role]
[stable NIR protocol and output schema]
[stable tool definitions]
[cache breakpoint]
[dynamic task contract]
[dynamic state revision/delta/refs]
[dynamic current evidence]
```

OpenAI and Anthropic both recommend stable reusable prefixes and dynamic suffixes for prompt caching [R12–R13]. Caching lowers provider compute/cost/latency; it does not remove cached tokens from the logical context window [R13]. NCT therefore needs both caching and actual context reduction.

### 8.3 Output enforcement order

Use this order per provider capability:

1. Native Structured Outputs / strict JSON schema.
2. A single strict `emit_nir_result` tool.
3. Strict JSON-only response with local schema validation.
4. One bounded repair attempt.
5. Fallback to concise text or block, depending on policy.

Never use repeated open-ended “please fix your JSON” loops.

### 8.4 Inline threshold

Initial configurable default:

```text
ref_inline_threshold_bytes = 1024
```

This is not a fixed truth. The benchmark must optimize it per content type and model. Some small structured values are cheaper inline; some tokenizer-unfriendly identifiers should remain aliases.

### 8.5 Retry projection

A retry frame contains:

- original contract by reference or stable cached prefix;
- previous result reference;
- typed QA failures;
- unchanged base revision if state did not move;
- only new evidence or constraints.

It must not concatenate the full original prompt, full candidate, and full verifier prose by default.

---

## 9. Codec registry

### 9.1 Canonical codecs

```text
direct/no-handoff       No inter-agent message
nir_json                Default provider-agnostic semantic JSON
nir_tool                Provider-native structured tool call
concise_text            Compatibility fallback
a2a_nir                 NIR mapped to A2A DataPart/Artifact
kv_same_runtime         Exact-compatible local KV transfer
hidden_same_runtime     Exact-compatible local hidden-state transfer
cross_model_projection  Research-only, disabled in production
```

### 9.2 Codec contract

```rust
pub trait CognitiveCodec: Send + Sync {
    fn id(&self) -> CodecId;
    fn eligibility(&self, ctx: &CodecContext) -> Eligibility;
    fn encode(&self, frame: &NirFrameV1) -> Result<EncodedTransfer>;
    fn decode(&self, transfer: &EncodedTransfer) -> Result<NirFrameV1>;
    fn estimate(&self, frame: &NirFrameV1) -> CodecEstimate;
}
```

Every codec must pass:

- schema round-trip vectors;
- unknown-field behavior;
- size/depth/count limits;
- taint/privacy preservation;
- deterministic digest vectors;
- model-specific parse/repair benchmarks;
- downgrade behavior.

### 9.3 Selection objective

For route \(r\) and codec \(c\):

\[
U(r,c) =
E[\Delta Q]
-\lambda_C E[\text{cost}]
-\lambda_L E[\text{latency}]
-\lambda_R E[\text{risk}]
-\lambda_O E[\text{coordination tax}]
-\lambda_M E[\text{memory pressure}]
\]

Where:

- \(Q\): task quality or success probability;
- cost includes input, output, cache write/read, retries, and local compute;
- latency includes queueing, prefill, decode, transfer, and verification;
- risk includes privacy, capability, semantic uncertainty, and attack surface;
- coordination tax measures inter-agent work that does not advance the task;
- memory pressure includes GPU KV footprint and CAS/ref-store pressure.

### 9.4 No learned router at launch

The first active router is deterministic and policy-driven. Before activation it runs in shadow mode and compares its suggested route with the actual route.

A contextual bandit or learned selector may be introduced only when:

- a frozen feature schema exists;
- enough labeled runs exist;
- training, validation, and holdout sets are separated;
- the fixed-rule baseline is strong;
- rollback is immediate;
- the model cannot edit its own objective or safety overrides.

---

## 10. Adaptive route planner

### 10.1 Candidate execution shapes

- `Direct`: one selected provider/model.
- `DirectWithVerifier`: one worker plus one independent bounded verifier.
- `Sequential`: ordered dependent specialists.
- `ParallelIndependent`: bounded fan-out/fan-in for independent evidence.
- `ManagerWorker`: central decomposer and bounded workers.
- `Council`: left/right/callosum with dissent and arbitration.
- `OperatorEscalation`: no autonomous continuation.

### 10.2 Features

The planner may use:

- task class and required deliverable;
- decomposition confidence;
- independence vs sequential dependency;
- reversibility and effect risk;
- privacy and egress constraints;
- context size and projected duplication;
- provider availability and authorization;
- historical quality by model/task;
- historical cost, latency, parse, repair, and retry rates;
- current queue/GPU/memory pressure;
- contradiction/evidence requirements;
- baseline model confidence;
- existing Babel window metrics;
- operator policy, budget, and forced route.

### 10.3 Initial deterministic policy

1. **Use Direct** when the task is small, sequentially coupled, low ambiguity, or the selected strong model historically solves it reliably.
2. **Use DirectWithVerifier** when output is high impact but decomposition adds little value.
3. **Use ParallelIndependent** only when subtasks are genuinely independent and mergeable.
4. **Use Sequential** only when later actors need typed outputs from earlier actors and the dependency chain is explicit.
5. **Use Council** for high-value contradiction, competing hypotheses, architecture choices, or explicit operator request.
6. **Block or escalate** when required evidence/capability is absent.
7. **Prefer NIR/ref** for heterogeneous providers and all cloud paths.
8. **Consider latent** only for exact-compatible local runtimes, eligible tasks, acceptable memory pressure, and a passing security handshake.
9. **Reduce topology** when projected coordination tax exceeds expected quality gain.
10. **Never let an LLM recommendation override hard policy.**

### 10.4 Fan-out limits

Current NEXUS has absolute limits of fan-out 8 and concurrency 4 [R25]. NCT should keep those as hard ceilings but use safer defaults:

```text
default_max_fanout = 3
default_max_concurrent = 3
default_max_rounds = 2
absolute_max_fanout = existing NEOTH cap
absolute_max_concurrent = existing NEOTH cap
```

The defaults are configurable but cannot exceed compiled policy ceilings without an explicit future schema/version change.

### 10.5 Route receipt

Every decision emits an operator-readable receipt without private reasoning:

```json
{
  "schema": "neoth.nct.route-receipt.v1",
  "run_id": "0198...",
  "selected": {"topology": "direct_with_verifier", "codec": "nir_json"},
  "alternatives": [
    {"topology": "council", "rejected_code": "coordination_cost_exceeds_gain"},
    {"topology": "parallel", "rejected_code": "subtasks_not_independent"},
    {"codec": "kv_same_runtime", "rejected_code": "runtime_fingerprint_mismatch"}
  ],
  "policy_generation": 42,
  "feature_digest": "b3:...",
  "estimated": {"input_tokens": 6200, "cost_microusd": 18000, "latency_ms": 9400}
}
```

This explains the decision class and evidence, not hidden chain-of-thought.

Paid provider execution has an explicit state machine:

```text
not_dispatched
  -> dispatched
  -> confirmed_not_executed | confirmed_executed | indeterminate_paid_execution
  -> reconciled
```

Once the final request may have crossed the provider's execution boundary, a
timeout, disconnect, crash or missing response is not evidence that no paid
work occurred. `indeterminate_paid_execution` retains the budget reservation,
provider-permit digest, request-binding digest and provider request-id hash. It
does not automatically retry, fall back or redelegate unless a provider-backed
idempotency key or authoritative reconciliation proves that the original leaf
did not execute. Otherwise NEOTH obtains an authoritative provider status or
requires an explicit operator decision whose duplicate-cost risk is shown and
audited. A new provider/model leaf always requires a new bound cost and consent
authorization.

---

## 11. Babel integration

### 11.1 Phase rule

The existing Delta/NEOTH integration states that Babel begins as asynchronous telemetry and should not directly block or steer output in its first phase [R26]. NCT must preserve that rule.

### 11.2 Integration stages

#### Stage B0 — observe only

Record content-free NCT features:

- active actors;
- edge count;
- fan-out;
- rounds;
- retry density;
- token/byte pressure;
- output similarity/convergence proxy;
- route redundancy;
- fallback success;
- state conflict count;
- codec repair/downgrade count.

No routing effect.

#### Stage B1 — offline evaluation

Test whether Babel variables add out-of-sample predictive value for:

- agent loops;
- retry storms;
- context-limit failure;
- semantic degradation;
- fallback failure;
- objective failure.

Report calibration and Brier score.

#### Stage B2 — bounded advisory

After preregistered predictive success, Babel may contribute one bounded feature to route scoring. It cannot be the sole reason for denial or termination.

#### Stage B3 — optional throttle

Only after independent validation and explicit operator opt-in:

- reduce fan-out;
- reduce rounds;
- require one-shot visible commitments;
- prefer direct or direct-with-verifier;
- force NIR instead of latent when opacity risk is high.

A hard kill switch based solely on one Babel scalar remains a non-goal.

---

## 12. Authenticated transfer and admission

### 12.1 Threat model

| Threat | Required control |
|---|---|
| Payload alteration | digest + HMAC/signature over fixed manifest |
| Visible commitment differs from latent state | commitment digest bound into manifest |
| Replay | session, sequence, nonce, expiry, replay cache |
| Cross-session cache bleed | session-bound key and fingerprint; separate cache namespace |
| Wrong model/layout | exact runtime fingerprint |
| Stale state | base revision and expected-old digests |
| Prompt injection in referenced content | typed untrusted-context serializer and taint |
| Capability smuggling | live lease/policy revalidation; payload cannot grant authority |
| Downgrade attack | explicit permitted downgrade list + WAL event |
| Decompression/resource bomb | pre-allocation metadata limits, byte caps, timeouts |
| Malicious sender | QA/evidence/action gates; crypto does not prove benign semantics |
| Compromised endpoint/key | out of scope for transport integrity alone; node isolation and key rotation |
| Compromised latent sidecar | mandatory OS sandbox, no ambient authority, Rust-side independent validation, no signing/action key |
| IPC endpoint squatting or peer substitution | private parent-created endpoint, owner-only ACL, OS peer credentials, PID/executable/bundle binding |
| A2A bearer replay or channel confusion | per-session proof of possession plus per-message or cryptographic channel binding |
| Stale cluster owner or split brain | monotonic fence generation, committed leader term/proof, membership and authorization epochs |
| Revoked authority reused from cache | durable monotonic revocation floor checked at admission, during streaming and before commit |
| CAS collection races a new root | transactional root table, snapshot/epoch barrier, grace period and delete-time recheck |
| Paid request outcome is unknown | indeterminate paid-execution state, retained budget, provider reconciliation before retry |
| Canonicalization ambiguity | byte-exact field encoding, duplicate rejection, no floats/maps in signed V1 manifest |
| Latent covert leakage | privacy labels, local-only default, ephemeral retention, no cloud path |
| Crash between transfer and state apply | staged transaction + idempotent frame ID + commit event |
| Model update after cache creation | fingerprint mismatch; discard |
| Untrusted A2A peer | Signed Agent Card verification, policy mapping, no internal capability inheritance |

### 12.2 Transfer manifest

```rust
pub struct DowngradeCommitmentV1 {
    pub source_codec: CodecId,
    pub target_codec: CodecId,
    pub authorization_policy_digest: Digest,
    pub reason_code: DowngradeReasonCode,
}

pub struct TransferManifestV1 {
    pub schema: SchemaId,                 // "neoth.nct.manifest.v1"
    pub transfer_id: TransferId,
    pub frame_id: FrameId,
    pub parent_frame_id: Option<FrameId>,
    pub session_id: SessionId,
    pub sequence: u64,
    pub nonce: [u8; 32],

    pub cluster_id: Option<ClusterId>,
    pub subject_id: SubjectId,
    pub authority_namespace: AuthorityNamespace,
    pub sender: ActorId,
    pub receiver: ActorId,
    pub task_id: TaskId,
    pub correlation_id: CorrelationId,
    pub attempt: u32,

    pub fence_owner: Option<NodeId>,
    pub fence_generation: Option<u64>,
    pub leader_term: Option<u64>,
    pub leader_commit_index: Option<u64>,
    pub leader_commit_proof_digest: Option<Digest>,
    pub fence_grant_digest: Option<Digest>,
    pub membership_epoch: Option<u64>,
    pub authorization_epoch: u64,
    pub capability_inventory_revision: u64,

    pub state_revision: StateRevision,
    pub nir_digest: Digest,
    pub visible_commitment_digest: Digest,
    pub refs_digest: Digest,
    pub route_receipt_digest: Digest,

    pub codec: CodecId,
    pub runtime_fingerprint: Option<RuntimeFingerprint>,
    pub payload_digest_sha256: Sha256Digest,
    pub payload_len: u64,
    pub tensor_metadata_digest: Option<Digest>,

    pub capability_scope_digest: Digest,
    pub lease_id: Option<LeaseId>,
    pub policy_digest: Digest,
    pub config_generation: u64,
    pub config_digest: Digest,
    pub downgrade: Option<DowngradeCommitmentV1>,

    pub budget_grant_digest: Option<Digest>,
    pub provider_permit_digest: Option<Digest>,
    pub final_provider: Option<ProviderId>,
    pub final_wire_model: Option<WireModelId>,
    pub model_revision_digest: Option<Digest>,
    pub output_token_ceiling: Option<u64>,
    pub max_cost_microusd: Option<u64>,
    pub pricing_snapshot_digest: Option<Digest>,

    pub previous_transfer_digest: Option<Digest>,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}
```

Cluster fields are optional only on a provably non-cluster local path. A
cluster-carried frame is invalid if the owner, generation, fence grant,
committed leader term/index/proof, membership epoch or authorization epoch is absent. Paid-provider
fields are optional only before a concrete provider leaf exists; a dispatched
paid leaf requires the final provider, exact wire model and model revision,
output ceiling, price bound, budget grant and provider-permit digests. The
manifest binds the immutable capability-inventory revision used for routing;
live admission may reject it if a later revocation floor supersedes it.

`correlation_id` is required on direct, retried, delegated and cluster paths
and remains stable across the related attempt chain; it is not reconstructed
from logging metadata. `config_generation` supplies the monotone anti-rollback
coordinate, while `config_digest` commits the complete effective
security/privacy/routing/codec/cost/admission configuration consumed by the
decision. Equal generations with different digests and equal digests at a
different required generation both reject. `route_receipt_digest` commits the
immutable canonical route receipt that selected this exact route and codec,
including candidate/rejection evidence and its policy/config commitments; even
a direct route emits and binds a receipt.

`refs_digest` is mandatory even when no references exist. It is the SHA-256
digest of the exact domain-separated bytes
`"NCT-REFSET-V1\0" || u32(count) || canonical(ContentRef[0]) || ...`.
The canonical ref registry contains every distinct `ContentRef` structurally
reachable from the NIR frame exactly once, sorted by canonical `RefId` bytes;
duplicate IDs, unsorted encodings, an alias without a registry entry, or an
unreferenced smuggled entry reject. Each entry commits the full `ContentRef`
field sequence from section 7.1 -- including subject, authority namespace,
encryption domain, object commitment, locator, privacy, ordered taint,
provenance, metadata/grant digests and expiry -- rather than only an ID or
object digest. The zero-count encoding has one fixed digest; omission is not an
empty set.

`downgrade = None` is the only representation of no codec transition. A
present `DowngradeCommitmentV1` is valid only when `source_codec !=
target_codec`, `target_codec == manifest.codec`, both codec IDs are known, and
the current explicit operator-approved downgrade record and current downgrade
policy reproduce `authorization_policy_digest`. `reason_code` is a closed,
frozen `u16` registry, never free text; unknown codes reject. The commitment
cannot replace the manifest-level `policy_digest`: admission checks both, and
any absent, expired, stale or mismatched authorization fails closed and emits
no implicit fallback.

### 12.3 Signature input

Do not sign arbitrary serializer output.

Define one fixed, domain-separated, length-prefixed byte layout:

```text
"NCT-MANIFEST-V1\0"
|| canonical(schema)
|| canonical(transfer_id)
|| canonical(frame_id)
|| canonical(parent_frame_id)
|| canonical(session_id)
|| canonical(sequence)
|| canonical(nonce)
|| canonical(cluster_id)
|| canonical(subject_id)
|| canonical(authority_namespace)
|| canonical(sender)
|| canonical(receiver)
|| canonical(task_id)
|| canonical(correlation_id)
|| canonical(attempt)
|| canonical(fence_owner)
|| canonical(fence_generation)
|| canonical(leader_term)
|| canonical(leader_commit_index)
|| canonical(leader_commit_proof_digest)
|| canonical(fence_grant_digest)
|| canonical(membership_epoch)
|| canonical(authorization_epoch)
|| canonical(capability_inventory_revision)
|| canonical(state_revision)
|| canonical(nir_digest)
|| canonical(visible_commitment_digest)
|| canonical(refs_digest)
|| canonical(route_receipt_digest)
|| canonical(codec)
|| canonical(runtime_fingerprint)
|| canonical(payload_digest_sha256)
|| canonical(payload_len)
|| canonical(tensor_metadata_digest)
|| canonical(capability_scope_digest)
|| canonical(lease_id)
|| canonical(policy_digest)
|| canonical(config_generation)
|| canonical(config_digest)
|| canonical(downgrade)
|| canonical(budget_grant_digest)
|| canonical(provider_permit_digest)
|| canonical(final_provider)
|| canonical(final_wire_model)
|| canonical(model_revision_digest)
|| canonical(output_token_ceiling)
|| canonical(max_cost_microusd)
|| canonical(pricing_snapshot_digest)
|| canonical(previous_transfer_digest)
|| canonical(created_at_unix_ms)
|| canonical(expires_at_unix_ms)
```

The V1 canonical byte contract is normative:

- the domain separator is the exact ASCII byte string
  `NCT-MANIFEST-V1\0`; it is included once at offset zero;
- fields occur exactly in the declared `TransferManifestV1` order; no field
  name, serializer order or platform ABI participates. Every declared field is
  encoded exactly once. `payload_digest_sha256` is the sole commitment to the
  detached payload bytes in this layout; neither the payload nor that digest is
  appended again after the final manifest field;
- `u8`, `u16`, `u32`, `u64` and two's-complement `i64` use fixed widths and
  network byte order; booleans are one byte `0x00` or `0x01`;
- variable bytes and strings use a `u32` network-order byte length followed by
  exact bytes; strings must already be valid UTF-8 NFC and non-NFC input is
  rejected rather than normalized after verification;
- `Option<T>` is one tag byte (`0x00` absent, `0x01` present) followed by the
  canonical `T` only when present; absent and present-empty are distinct;
- enum discriminants are frozen `u16` registry values. Textual enum names,
  unknown values and aliases are rejected;
- lists use a `u32` element count followed by canonical elements in semantic
  order. Signed manifest V1 contains no maps; any semantic map is first
  represented as a key-sorted unique list. Duplicate keys are rejected before
  object materialization and are never resolved by first- or last-wins logic;
- IEEE floating point, NaN, infinity, locale-dependent numbers and scientific
  notation are forbidden. Prices use integer micro-units and ratios use an
  explicitly reduced integer numerator/denominator type;
- every digest is encoded as `u16 algorithm_id || u16 digest_len || digest`.
  V1 freezes `0x0001 = BLAKE3-256` and `0x0002 = SHA-256`; length must be 32;
- every authenticator is encoded as
  `u16 algorithm_id || u16 key_id_len || key_id || u16 signature_len ||
  signature`. `key_id` is an opaque 1..128-byte value; empty, overlong,
  non-unique or unknown key IDs reject. V1
  freezes `0x0001 = HMAC-SHA-256` with 32 bytes and `0x0002 = Ed25519` with
  64 bytes. Algorithm/key-type confusion and unknown IDs reject;
- parsers must reject trailing bytes, duplicate fields, overlong lengths,
  non-minimal alternate representations and integer overflow.

The authenticator is an outer envelope and is not part of
`TransferManifestV1` canonical bytes. HMAC or Ed25519 signs those bytes once;
verification reconstructs exactly the same bytes and never hashes or appends a
manifest field a second time.

Publish golden vectors for Rust, Python sidecar, and A2A adapters. The corpus
includes every field at minimum/maximum permitted value, absent versus
present-empty options, the payload-digest double-append trap, empty and
128-byte key IDs, unknown/non-unique key IDs, HMAC and Ed25519 success/failure,
unknown hash/signature IDs, trailing bytes, alternate/overlong length encodings,
non-NFC text, duplicate keys and integer boundary/overflow cases.

The corpus also contains named positive and negative vectors for every field
added by the Gold manifest contract:

- one no-downgrade vector with required `correlation_id`, `config_digest`,
  `route_receipt_digest` and the fixed empty-ref-set `refs_digest`, plus one
  fully populated typed-downgrade vector;
- omission of each required field, including omission of `refs_digest` instead
  of encoding the empty set, rejects without shifting later bytes into the
  missing field;
- swaps of adjacent canonical fields and semantic swaps of task/correlation,
  config generation/digest, route/ref digests and downgrade source/target
  reject;
- one-bit or value tampering of each new field, a same-generation/different-
  config snapshot, a replaced route receipt, and mutation of any committed
  `ContentRef` field reject;
- an empty ref set is accepted only through its canonical zero-count
  commitment; duplicate, omitted, unsorted, truncated, extra or partially
  committed ref sets reject;
- `downgrade = None` succeeds only when no transition occurred. Present-empty,
  source-equals-target, target-not-equal-to-`manifest.codec`, unknown reason,
  stale/absent authorization, stale policy and authorization/policy-digest
  tampering reject.

### 12.4 Keying

- **Same-process Rust components:** use typed in-process values and capability
  objects; do not turn an in-process call into a false cryptographic boundary.
- **Rust core to latent sidecar:** after OS-level peer verification, `neothd`
  creates a fresh random per-spawn 256-bit session secret and transfers it only
  through the protected inherited bootstrap handle or mutually authenticated
  private IPC. HKDF derives direction-, session-, generation- and purpose-bound
  HMAC-SHA256 keys. The HMAC authenticates sidecar protocol messages only; it
  does not create a cluster identity, provider permit, capability, lease or
  action authority.
- **Cross-node NEOTH mesh:** Ed25519 sender signature plus the existing authenticated/encrypted carrier.
- **External A2A:** verify Signed Agent Card and peer identity policy, establish
  proof of possession, and bind every NCT message to the authenticated channel
  or sign it with the session PoP key.
- Ed25519 and provider/action signing keys stay in the Rust core or platform
  keystore and are never exposed to the sidecar. The sidecar returns a
  session-MACed candidate envelope; Rust independently validates it, constructs
  the authoritative manifest and applies any required Ed25519 signature.
- Keys are domain-separated, rotated and never placed in prompts/WAL.
  Zeroization of owned CPU buffers is required where supported, but the design
  does not claim guaranteed erasure from allocator copies, page files, crash
  dumps, GPU/driver memory or hardware remanence. Those residuals are reduced by
  sandboxing, dump/swap policy, bounded lifetimes and process/device reset and
  are documented honestly.
- A valid signature is necessary but not sufficient for acceptance.

### 12.5 Admission pipeline

```text
receive
  -> reject unknown major schema
  -> preflight lengths/counts/depth before allocation
  -> parse canonical bytes and reject duplicates/trailing/alternate forms
  -> verify sender/receiver/session/task/correlation binding
  -> verify expiry/nonce/sequence/replay
  -> verify MAC/signature
  -> verify current authorization epoch and durable revocation floor
  -> verify sole-origin or quorum-committed fence grant and membership epoch
  -> verify NIR and visible commitment digests
  -> recompute the full canonical ref-set commitment
  -> verify payload/tensor metadata digest
  -> verify exact runtime fingerprint if latent
  -> verify current policy plus config generation and full config digest
  -> verify the immutable route receipt and selected route/codec binding
  -> verify typed downgrade authorization/policy commitment or exact absence
  -> verify state base revision
  -> verify current capability lease and capability-inventory revision
  -> verify and single-use consume budget/provider permit for final request
  -> resolve refs under budget
  -> validate semantic schema
  -> revalidate revocation/fence/lease immediately before state or action commit
  -> ACCEPT, REJECT, or explicit DOWNGRADE
```

No transcript, state, or action advances before acceptance.

**Authoritative cluster fence ledger.** Every task-capable cluster freezes
exactly one authority mode in its signed genesis:

- `SoleOrigin`: one `StableNodeId` and authority key append fence, membership,
  revocation and budget records. There is no automatic election, promotion or
  failover. If the origin is unavailable, no other node can grant or renew a
  fence, consume a permit, terminalize a task or authorize an effect. Authority
  migration is an explicit signed recovery transaction that advances the
  membership/authorization epoch and rekeys the cluster; absent that proof the
  operator creates a new cluster identity and re-pairs nodes.
- `QuorumConsensus`: only an entry committed by the configured quorum of the
  current signed voting membership is authoritative. The proof binds leader
  term, commit index and entry digest. A leader acknowledgement, follower WAL,
  local majority guess, gossip convergence or minority signature set is not a
  commit proof.

A local SQLite database or WAL is a durable projection/cache, never proof of
distributed authority. `FenceGrantV1` is a sole-origin-signed or
quorum-committed ledger entry binding the exact cluster, subject, authority
namespace, task, attempt, owner `StableNodeId`, monotonically increasing fence
generation, membership epoch, authorization epoch, leader term/commit index,
expiry and manifest-intent digest. The final manifest carries the grant and
commit-proof digests and signs them. Grant, renewal, task terminalization,
budget release and every durable/effectful commit compare that complete tuple
against the current committed ledger in one linearizable operation.

A minority, stale leader, stale membership, superseded generation/owner,
different attempt or mismatched manifest cannot grant, renew, terminalize,
release budget or cause an effect. Its frames may be retained as content-free
forensic evidence only. Restoring a database/WAL snapshot cannot reduce the
accepted term, commit index, membership/authorization epoch, fence generation
or revocation floor.

**Membership and revocation authority.** Membership and role changes are
sole-origin-signed or quorum-committed under the same current membership epoch.
The target's signature or possession of an old transport key never authorizes
its own admission, promotion or reactivation.

- `revocation_floor` is monotonic per cluster/issuer/subject/authority
  namespace and is backed by both the current signed authority/quorum proof and
  a platform-sealed monotonic anchor that is excluded from ordinary NEOTH
  backup/restore. A current quorum may serve as the independent anchor when its
  committed state is demonstrably newer.
- A restored or long-offline node authorizes no new session, renewal, task
  terminalization, permit consumption or effect until it obtains a current
  valid authority/quorum proof whose epochs/floors are at least the sealed
  anchor. A restored local backup, SQLite file or WAL alone is never sufficient.
- If the independent anchor is lost, rolled back or unverifiable, NEOTH fails
  closed for sessions and effects. Recovery creates a newly signed authority
  generation/cluster identity, invalidates old sessions and requires re-pairing;
  it does not guess or reset the old floor.
- Revocation tombstones are retained for the lifetime of the cluster identity.
  They may be compacted into a signed/committed accumulator and floor but never
  omitted in a way that permits a lower epoch or retired key to become valid.
- Self-elevation is forbidden. Actor role and quorum are read from the same
  committed entry used for the mutation. Concurrent promotions/demotions
  serialize, a minority cannot change its own quorum threshold, and the last
  active administrator/sole origin cannot remove or demote itself unless the
  same committed recovery transaction establishes and proves its successor.
- Revoking a member rotates future group/transport session keys and future
  content-encryption domains to the active membership only. New grants,
  sessions, messages and content exclude the revoked identity.

Revocation cannot erase plaintext, exported artifacts or key material that a
formerly authorized or compromised peer already copied. The product and
operator UI must state this limit plainly: the contract prevents future
authority and future encrypted access; it does not promise remote deletion of
past plaintext.

Key, Agent Card, membership, capability and lease caches may raise their
observed floor but may never lower it. Long streams revalidate on bounded
byte/time intervals and at final commit, so revocation is effective before any
new durable effect even when transfer began under an older epoch.

**Single-use provider budget permit.** A concrete paid leaf uses:

```rust
pub struct ProviderBudgetPermitV1 {
    pub permit_id: PermitId,
    pub worker_node_id: StableNodeId,
    pub membership_epoch: u64,
    pub authorization_epoch: u64,
    pub task_id: TaskId,
    pub attempt: u32,
    pub fence_owner: StableNodeId,
    pub fence_generation: u64,
    pub provider_account_digest: Digest,
    pub provider: ProviderId,
    pub wire_model: WireModelId,
    pub model_revision_digest: Digest,
    pub pricing_snapshot_digest: Digest,
    pub billing_currency: CurrencyCode,
    pub budget_currency: CurrencyCode,
    pub fx_tax_snapshot_digest: Option<Digest>,
    pub output_token_ceiling: u64,
    pub max_cost_microunits: u64,
    pub expires_at_unix_ms: i64,
    pub nonce: [u8; 32],
}
```

When billing and budget currencies differ, the permit requires a frozen FX,
tax and fee snapshot; otherwise that field is absent and the currencies must be
identical. Provider account identity is a non-secret stable digest, not a
display name.

The same sole-origin or quorum authority performs a linearizable, single-use
state transition:

```text
Reserved -> Released
Reserved -> DispatchCommitted -> Spent
                              -> Indeterminate
                                  -> ReconciledSpent
                                  -> ReconciledUnspent
```

`Released` is legal only before provider egress. `DispatchCommitted` atomically
consumes the permit immediately before the exact bound request may cross the
provider boundary. From that point expiry, timeout, crash or cancellation
cannot refund it automatically. `Spent` uses authoritative provider evidence;
`Indeterminate` retains the full reservation until reconciliation proves
`ReconciledSpent` or `ReconciledUnspent`. Retry, fallback, redelegation, another
worker/account/provider/model/revision, a higher output ceiling or changed
price/currency/tax requires a new permit and cannot reuse the old nonce or
budget transition.

**Carrier qualification matrix.** Each exact release artifact publishes a
generated matrix with one row per compiled/configurable carrier:

| Carrier/build profile | Authenticated peer | Bounded ordered task frames | Backpressure/cancel | Durable ACK/dedup/replay | Reconnect/redelegation | Fence/budget proof | Installed multi-process evidence | Classification |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| peeroxide/Hyperswarm | required | required | required | required | required | required | required | `task-capable` only if every cell passes |
| Iroh QUIC | required | required | required | required | required | required | required | `task-capable` only if every cell passes |
| mDNS/Tailscale announce or probe | discovery only | no | no | no | no | no | discovery evidence | `discovery-only` |
| WAL gossip/foreign recall/export carrier | required where networked | no | no | gossip replay only | no task recovery | no | gossip evidence | `gossip-only` |
| external A2A binding | A2A PoP | A2A task lifecycle | binding-specific | binding-specific | binding-specific | external policy only | A2A conformance | external, never an internal cluster carrier |

Missing, disabled or untested cells are `FAIL/NOT BUILT`, not assumed from a
shared trait or in-process unit test. A gossip-only/discovery-only carrier is
rejected before task routing and shown honestly in CLI, GUI, Buddy, Doctor and
release documentation.

Task-capable evidence runs the installed release binaries, not library mocks:
at least three independent OS processes with separate homes, stable identities,
databases and sockets use the real packaged carrier to pair, delegate, stream,
cancel, return, ACK, replay and recover tasks. The matrix covers large/bounded
frames, backpressure, duplicate/out-of-order delivery, process crash/restart,
partition/minority, stale leader/fence, redelegation, revocation and clean
shutdown on every supported OS/build feature combination. Exact artifact
hashes, command transcript and content-free receipts accompany the release.

### 12.6 Downgrade semantics

Permitted example:

```text
kv_same_runtime -> nir_json -> concise_text
```

A downgrade is allowed only when:

- `allow_downgrade` is explicitly enabled; the default is false;
- policy permits the target codec;
- the canonical NIR frame is available or can be reconstructed safely;
- privacy does not become weaker;
- the reason is typed;
- a content-free WAL event is emitted;
- no rejected latent bytes are reused.

Never silently reinterpret an incompatible tensor as text or projected state.

Automatic downgrade and last-known-good state are limited to
availability/performance axes such as a qualified codec or backend becoming
temporarily unavailable. They may never substitute stale values on authority
axes: sender/receiver identity, subject/namespace, privacy/taint, consent,
capability inventory, lease, authorization/revocation epoch, cluster
membership/fence/leader term, budget, provider permit, final provider/model,
output ceiling, pricing bound, action policy, evidence requirement or state
revision. If any current authority input is unavailable or differs, the frame
rejects or waits for explicit reauthorization; a last-known-good security value
cannot make it admissible.

### 12.7 Action firewall

A latent payload may influence a proposed result, but it may not directly:

- invoke a tool;
- change a lease;
- authorize egress;
- write memory;
- apply a patch;
- send a message;
- change configuration.

Every effect becomes a typed `ActionIntent`, is rendered into inspectable arguments, and passes the existing live action/consent/capability gate.

Neither a sidecar HMAC, Ed25519 transfer signature, A2A PoP proof, cluster
commit proof nor valid NIR manifest can mint authority. They prove bounded
origin/integrity/state claims only. The Rust core derives effect authority from
the current local policy, subject, lease, budget and concrete request binding
after admission. A compromised sidecar therefore has no signing key, provider
credential, network route, tool handle or direct state writer with which to
bypass this firewall.

---

## 13. Latent fast path

### 13.1 Purpose

The latent lane exists to test whether exact-compatible local agents can avoid repeated text decoding/encoding and context prefill while preserving or improving task quality. Research reports material gains in controlled settings, but also reports backbone instability, memory/transfer costs, and new attack surfaces [R04, R08–R09, R27–R28].

It is an optimization, not the canonical source of truth.

### 13.2 Eligibility

All conditions must pass:

- local/self-hosted model;
- compatible backend exposes required state;
- exact runtime fingerprint match;
- same task/session/privacy domain;
- authenticated manifest support;
- visible commitment generated and schema-valid;
- payload and memory size within limits;
- no policy requiring fully text-inspectable transfer;
- benchmark says this model/task/backend pair is eligible;
- no current memory-pressure or Babel advisory exclusion;
- canonical NIR fallback is available.

### 13.3 Exact runtime fingerprint

At minimum bind:

```text
model weight/checkpoint digest
model config digest
tokenizer + vocabulary digest
quantization scheme and parameters
dtype
layer count / hidden size / KV heads / head dimension
RoPE/scaling configuration
attention backend
KV layout and block size
tensor parallel / pipeline parallel layout
adapter/LoRA set and digest
inference engine and exact build/version
relevant engine flags
system-prefix digest
NIR schema and policy versions
latent backend protocol version
```

The model display name is never sufficient.

### 13.4 Backend trait

```rust
#[async_trait]
pub trait LatentBackend: Send + Sync {
    async fn capabilities(&self) -> Result<LatentCapabilities>;
    async fn fingerprint(&self, model: &ModelRef) -> Result<RuntimeFingerprint>;
    async fn export(
        &self,
        session: &LatentSession,
        request: &LatentExportRequest,
    ) -> Result<LatentEnvelope>;
    async fn import(
        &self,
        session: &LatentSession,
        envelope: &AuthenticatedLatentEnvelope,
    ) -> Result<LatentImportReceipt>;
    async fn discard(&self, handle: &LatentHandle) -> Result<()>;
}
```

### 13.5 Sidecar architecture

Keep NEOTH Rust-first. Isolate fast-moving model internals:

```text
neothd (Rust)
  |
  | Unix domain socket / named pipe / loopback mTLS gRPC
  v
nct-latent-sidecar (Python, shipped; operator activation opt-in)
  ├── Hugging Face backend
  ├── vLLM connector backend
  ├── LMCache backend
  ├── AVP adapter qualification
  ├── tensor validator
  ├── manifest verifier
  └── bounded ephemeral state registry
```

Reasons:

- model-internal Python ecosystems move faster than the Rust core;
- sidecar activation is operator-opt-in, while its Gold package and independent
  sandbox contract are mandatory;
- NEOTH can fail closed if it is unavailable;
- the Rust trust boundary remains small and testable;
- no Python dependency enters normal NEOTH operation.

The sidecar is an untrusted, compromise-expected component. An OS-enforced
sandbox is mandatory in every production package; process separation without
an enforceable sandbox does not qualify. If the required controls cannot be
established and verified, the latent backend is `Unavailable` and NIR fallback
remains the only path.

Platform contract:

- **Windows:** `neothd` launches the sidecar with a restricted primary token
  inside a dedicated AppContainer/lowbox profile and a Job Object configured
  for kill-on-close, active-process, memory and CPU limits. The package grants
  only explicit AppContainer capabilities; ambient user-profile, registry,
  device and network access are denied. Named-pipe ACLs name only the operator
  and the sidecar identity, and both server and client PID/token identities are
  verified.
- **Linux:** the launcher requires unprivileged user, mount, PID, IPC and
  network namespaces, `no_new_privs`, a syscall allowlist enforced by seccomp,
  read-only/pivoted filesystem mounts and cgroup-v2 memory, PID and CPU limits.
  The sidecar has no host network namespace. Parent death is bound through
  `PR_SET_PDEATHSIG` plus the owned process/cgroup lifecycle.
- **macOS:** the signed distribution launches the sidecar through an
  application/Seatbelt sandbox profile with deny-by-default filesystem,
  process and network rules plus resource supervision. It uses a private
  owner-only local socket and validates peer process identity/audit credentials.
  A platform version for which the packaged sandbox cannot be installed or
  verified does not expose the backend.

Cross-platform invariants:

- network is off by default and for the HF exact-runtime backend remains off;
  downloads are performed by the Rust acquisition pipeline before sandbox
  launch. Any future networked backend needs a separately reviewed destination
  allowlist and cannot receive provider, user or cluster credentials;
- filesystem access consists only of Rust-opened read-only handles to exact
  verified model/runtime artifacts and a new private bounded scratch handle.
  There is no ambient home, repository, credential, plugin, cache or arbitrary
  path access;
- the sidecar has no shell and cannot spawn child processes. An indispensable
  native helper must instead be a separately pinned Rust-launched sandboxed
  component with its own manifest and limits;
- Hugging Face loads with `trust_remote_code=false` and offline mode. Only
  allowlisted non-executable, length-bounded, digest-verified formats such as
  `safetensors` are accepted; pickle, arbitrary `torch.load`, joblib, model
  Python modules and archive extraction with executable content are forbidden;
- the exact sidecar executable, Python runtime, wheels, native libraries,
  lockfile, model bundle and loader policy are covered by release/artifact
  hashes. Import paths are fixed to that sealed bundle and user/site packages
  are disabled;
- IPC endpoints are created exclusively by the Rust parent in a private
  no-follow directory or protected named-pipe namespace before the child can
  connect. Endpoint ownership, inode/handle identity, OS peer credentials,
  expected PID, executable/bundle digest and generation are checked before the
  bootstrap secret is released;
- endpoint squatting, symlink/reparse substitution, PID reuse and path
  time-of-check/time-of-use are prevented with exclusive creation, open handles
  and post-connect identity checks. The sidecar never reopens a caller-supplied
  path;
- Job Object/cgroup/parent-death and IPC-EOF supervision terminate the complete
  sandbox generation when `neothd` exits, reloads, revokes it or loses peer
  identity. Restart creates a new endpoint, process identity, generation and
  HMAC secret;
- Rust independently validates all tensor ranks, dimensions, dtype, strides,
  layout, lengths, digests, runtime fingerprint, visible commitment and
  manifest fields before allocation/import. A sidecar saying that it validated
  data is not acceptance evidence.

Qualification includes compromise tests in which the sidecar attempts network
egress, arbitrary file/registry reads, symlink/reparse escape, shell/child
creation, unsafe model deserialization, endpoint replacement, forged peer
identity, stale-generation reuse, oversized/shared-memory payloads, malformed
tensors and survival after parent death. Each attempt must be blocked by an OS
or Rust boundary and leave a typed content-free diagnostic.

### 13.6 Backend order

#### L0 — null backend

Trait, config, fingerprints, failure semantics, tests. No tensors.

#### L1 — Hugging Face exact-same-runtime lab

Simplest path to instrument hidden states/KV and reproduce research. Single host, no persistence, no cross-model projection.

#### L2 — vLLM/LMCache exact-layout path

Use official connector/cache capabilities where compatible. vLLM documents asynchronous KV transfer through NIXL, and LMCache provides persistent/shared KV infrastructure and observability [R10–R11]. These systems prove transport feasibility; they do not automatically supply NCT’s semantic handoff or security model.

#### L3 — AVP adapter qualification

AVP can be implemented behind `LatentBackend`, never as the canonical NCT schema. Verify license, tests, maintenance, layout handling, and security assumptions before dependency adoption [R07].

#### L4 — cross-model projection research

The implementation and qualification lane ships as part of Gold. Runtime use
remains disabled unless independent, multi-model, multi-task quality and
security gates pass. AVP’s cross-model claims are project claims and must be
reproduced locally; a failed adapter is recorded as the evidence-backed
backend-specific `SKIP`, not deferred silently.

### 13.7 Latent storage policy

Default:

```text
persist = false
ttl_seconds = 60
same_host_only = true
cross_node = false
max_payload_bytes = bounded by model/backend profile
max_session_bytes = bounded
max_global_bytes = bounded
zeroize_on_discard = required for owned buffers, with no physical-remanence guarantee
```

No base64 tensor payload is ever placed in an LLM prompt, JSON NIR body, WAL, or ordinary private run record.

Discard overwrites owned CPU buffers where the allocator/backend permits,
releases shared-memory handles, invalidates the per-generation HMAC keys and
forces backend/process reset where required. It does not claim physical erasure
from allocator copies, swapped pages, crash dumps, GPU memory, driver caches or
hardware remanence. Production qualification disables avoidable dumps/swap for
secret key pages, bounds lifetime and documents platform/GPU residuals. Because
those residuals cannot be universally proven absent, latent payloads never
contain credentials, capability material, provider permits or signing keys.

### 13.8 Visible commitment

Before export, the sender emits a compact typed commitment:

```rust
pub struct VisibleCommitment {
    pub task_id: TaskId,
    pub claims: Vec<Claim>,
    pub proposed_next: Option<NextStep>,
    pub uncertainty: Vec<Uncertainty>,
    pub artifact_digests: Vec<Digest>,
}
```

The commitment:

- is not chain-of-thought;
- is inspectable and auditable;
- is bound cryptographically to the latent payload;
- gives the receiver and verifier a semantic contract;
- does not prove that the hidden state is semantically benign.

### 13.9 Important economic constraint

Full KV state can be large. “Zero text tokens between agents” does not mean zero system cost. The benchmark must include:

- GPU/CPU memory consumed;
- bytes copied;
- PCIe/network transfer time;
- serialization and hashing;
- cache hit/miss;
- sidecar overhead;
- verifier overhead;
- extra decode steps;
- fallback/retry cost.

If transfer and memory pressure erase the gain, use NIR/ref or direct routing.

---

## 14. A2A and MCP

### 14.1 A2A role

A2A is the external agent interoperability surface. The protocol is designed for discovery and communication between opaque heterogeneous agent systems, supports Agent Cards and multiple bindings, and version 1.0 introduced Signed Agent Cards [R14]. An official Rust SDK exists [R15].

NCT should not reinvent:

- agent discovery;
- task lifecycle;
- streaming task status;
- standard message/artifact envelopes;
- external capability advertisement.

### 14.2 Proposed A2A profile

Working extension URI:

```text
https://thegeekfreaks.de/neoth/a2a/extensions/nir/v1
```

The canonical URI must be approved, stable, HTTPS-controlled, documented, and tested before publication.

Agent Card advertises:

```json
{
  "extensions": [
    {
      "uri": "https://thegeekfreaks.de/neoth/a2a/extensions/nir/v1",
      "required": false,
      "params": {
        "schemas": ["neoth.nir.frame.v1", "neoth.nir.result.v1"],
        "codecs": ["nir_json"],
        "max_frame_bytes": 65536
      }
    }
  ]
}
```

Mapping:

- NIR frame/result -> A2A `DataPart`;
- large output/evidence -> A2A `Artifact` or scoped resource reference;
- route/admission receipt -> typed metadata/DataPart;
- standard text fallback remains available;
- external peers never inherit NEOTH internal capability leases;
- latent transfer is excluded from the external A2A profile; the fully packaged
  local exact-runtime latent backend remains required for Gold.

An Agent Card signature authenticates a published capability document; it is
not a bearer credential and does not authenticate an A2A task session by
itself. Every accepted external NCT session therefore establishes proof of
possession through either:

- mutually authenticated TLS whose peer certificate/key is authorized by the
  accepted Agent Card policy, with each message bound to a TLS exporter/channel
  value; or
- OAuth 2.0 with DPoP, including a verified `cnf` key binding, fresh server
  nonce and method/target binding, followed by a per-message detached signature
  or channel-binding proof from the same PoP key.

The proof input binds the exact sender and recipient actor IDs, authority
namespace, subject, A2A task ID, A2A context ID where present, message/frame ID,
sequence, nonce, accepted Agent Card digest/version, PoP key ID, authorization
epoch and canonical HTTPS origin. Reusing a valid proof for another recipient,
origin, namespace, task, message, sequence, card, key or transport channel
rejects. Streaming status and artifact chunks retain the same session binding
and revalidate the revocation floor before terminal or effectful state.

Cryptographic policy is fail-closed:

- JWS/JWT algorithms come from an explicit asymmetric allowlist; `none`,
  symmetric/asymmetric key confusion, unrecognized critical headers, duplicate
  keys and a `kid` that does not uniquely select one allowed key/algorithm
  reject;
- accepted Card/JWKS key versions and authorization epochs have a durable
  monotonic floor. Cache refresh may advance but never roll back that floor;
  an older still-validly-signed Card or reintroduced retired key cannot restore
  authority;
- Card, extended-card, JWKS, artifact and scoped-reference fetches use the same
  hardened SSRF resolver: HTTPS-only, no userinfo, bounded response, DNS and
  connected-IP validation, and complete policy revalidation on every redirect;
- authentication headers, DPoP proofs, cookies, client certificates and other
  credentials are never forwarded to a different origin. A redirect to a new
  origin requires a fresh independently authorized request and proof.

Pin the exact A2A spec/SDK version at implementation time and run compatibility tests against at least two independent SDK languages.

### 14.3 MCP role

MCP remains the protocol through which models/applications discover and invoke tools and obtain resources/prompts/context [R16].

Possible NCT-related MCP tools/resources:

```text
nct.resolve_ref
nct.inspect_receipt
nct.explain_route
nct.list_codecs
nct.benchmark_status
nct.get_schema
```

MCP is not the internal cognitive handoff protocol and does not grant transfer admission.

---

## 15. Provider usage, caching, and telemetry

### 15.1 Extend provider usage

Current sub-agent call evidence records provider, wire model, input tokens, and output tokens [R24]. NCT needs actual provider-native accounting:

```rust
pub struct ProviderUsage {
    pub stage: UsageStage,
    pub provider: ProviderId,
    pub wire_model: String,

    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,

    pub estimated_cost_microusd: Option<u64>,
    pub ttft_ms: Option<u64>,
    pub wall_ms: u64,
    pub queue_ms: Option<u64>,

    pub request_id_hash: Option<Digest>,
    pub provider_usage_authoritative: bool,
}
```

Character-count approximations may remain pre-call estimates but cannot be used as benchmark truth when provider usage is available.

### 15.2 Per-edge metrics

Record content-free metrics for every cognitive edge:

- route and codec;
- canonical NIR size;
- wire bytes;
- inline bytes vs referenced bytes;
- provider token categories;
- cache hit/write;
- TTFT and wall time;
- transfer and admission time;
- GPU/CPU memory for latent;
- quality/verdict;
- parse, repair, retry, fallback, and downgrade;
- state conflicts;
- ref resolution count/failure;
- visible commitment size;
- coordination tax;
- duplication ratio;
- Babel window association.

### 15.3 Derived measures

```text
duplication_ratio =
  bytes_or_tokens_repeated_from_prior_state / total_handoff_input

coordination_tax =
  total_inter_agent_cost / total_task_cost

commitment_density =
  verified_claims_and_actions / handoff_tokens

eligible_savings =
  (baseline_total_cost - nct_total_cost) / baseline_total_cost

route_regret =
  achieved_utility(best_observed_route) - achieved_utility(selected_route)
```

Do not optimize only “message tokens.” Optimize task success, total cost, latency, memory, repair, and risk.

### 15.4 WAL events

Allocate event IDs through the existing authoritative registry; do not hardcode numbers in this plan.

Proposed event names:

```text
NCT_ROUTE_SUGGESTED
NCT_ROUTE_DECIDED
NCT_FRAME_EMITTED
NCT_FRAME_REJECTED
NCT_REF_RESOLVED
NCT_REF_REJECTED
NCT_CODEC_SELECTED
NCT_TRANSFER_PREPARED
NCT_TRANSFER_ACCEPTED
NCT_TRANSFER_REJECTED
NCT_TRANSFER_DOWNGRADED
NCT_STATE_COMMITTED
NCT_STATE_CONFLICT
NCT_LATENT_CREATED
NCT_LATENT_CONSUMED
NCT_LATENT_DISCARDED
NCT_BABEL_ADVISORY
NCT_BENCHMARK_SAMPLE
```

WAL payloads contain:

- IDs/hashes;
- schema/codec/topology;
- counts and sizes;
- typed reason codes;
- provider/model identity;
- policy/config generation;
- timing and outcome.

They do not contain prompts, model output, reference bodies, secrets, or latent tensors.

---

## 16. Configuration and operator surface

### 16.1 Configuration

```toml
[cognitive_transport]
mode = "off"                    # off | shadow | active
default_codec = "nir_json"
max_fanout = 3
max_concurrent = 3
max_rounds = 2
min_expected_quality_gain = 0.0
max_coordination_tax = 0.35
ref_inline_threshold_bytes = 1024
max_frame_bytes = 65536
max_refs_per_frame = 64
max_delta_ops = 128
route_policy = "deterministic_v1"
a2a_enabled = false

[cognitive_transport.security]
require_authenticated_admission = true
max_clock_skew_seconds = 30
max_transfer_age_seconds = 300
replay_cache_entries = 10000
allow_downgrade = false
allowed_downgrades = []

[cognitive_transport.latent]
mode = "off"                    # off | lab | experimental
backend = "none"
same_host_only = true
exact_match_only = true
persist = false
ttl_seconds = 60
max_payload_bytes = 0           # backend profile must set explicit nonzero cap
max_session_bytes = 0
fallback_codec = "nir_json"
cross_model_projection = false
sidecar_network = "off"          # the v1 sidecar accepts no other value
trust_remote_code = false        # invariant; true is rejected

[cognitive_transport.babel]
mode = "observe"                # observe | advisory | throttle
may_be_sole_decision_input = false
```

All new fields require:

- typed schema;
- strict defaults;
- GUI/CLI readback parity where exposed;
- accepted config generation;
- no hidden environment override;
- migration and downgrade behavior;
- documentation and threat-model update.

### 16.2 CLI

```text
neoth cognition status
neoth cognition routes
neoth cognition explain <run-id>
neoth cognition codecs
neoth cognition refs status
neoth cognition refs gc --dry-run
neoth cognition audit --last 24h
neoth cognition benchmark run <suite>
neoth cognition benchmark compare <a> <b>
neoth cognition latent doctor
neoth cognition latent compatibility
neoth cognition a2a card
```

Operator force controls:

```text
--cognition-route direct
--cognition-route council
--cognition-codec nir_json
--no-cognitive-handoff
```

Forced choices remain subject to security, privacy, capability, provider, and resource gates.

### 16.3 GUI

Required for every retained Gold capability, using the same typed controller as
CLI, Buddy and Doctor:

- status and mode;
- route explanation;
- cost/token delta;
- compatibility matrix;
- security rejections/downgrades;
- no display of latent tensors or pseudo-chain-of-thought;
- explicit opt-in for latent and external A2A.

---

## 17. Implementation phases

## Phase 0 — Gold decision, freeze and baseline

**Release lane:** first dependency slice of `v1.0.0 Gold`; behavior-neutral.

Deliverables:

- this plan and ADR;
- freeze statement;
- baseline benchmark harness around current NEXUS/Council paths;
- measurements of repeated context in primary/QA/retry;
- provider-usage gap inventory;
- threat model draft;
- schema sketches and golden fixtures outside runtime;
- current-code insertion map;
- legal/prior-art note.

Exit gate:

- no public behavior change;
- no new runtime dependency;
- no Gold blocker weakened;
- benchmark reproduces current output and usage.

## Phase 1 — complete existing typed-boundary work

**Release lane:** Gold blocker closure and prerequisite for all NCT consumers.

Deliverables:

- finish `GOLD-R3-14` typed untrusted-context adoption for sub-agents, QA, retry, fallback, streaming, and all remaining consumers;
- eliminate raw delimiter interpolation;
- preserve exact current route behavior;
- add no-bypass source gate;
- exact-head CI/Security/CodeQL evidence as required by Gold.

Exit gate:

- authoritative Gold criteria pass;
- no parallel prompt-frame convention or partial public NCT claim;
- source and docs truth aligned.

## Phase 2 — NCT foundation for Gold

Deliverables:

- `cognitive_transport` module;
- canonical NIR/1 types and limits;
- JSON schemas and golden vectors;
- `ContentRef` store and state revisions;
- typed delta apply transaction;
- immutable bounded publish plus transactional CAS root/epoch GC;
- private internal storage digests plus keyed subject/authority-visible IDs,
  metadata/grant commitments and encryption-domain isolation;
- legacy `SubAgentRequest`/`SubAgentResult` adapters;
- mode `off`;
- unit/property/fuzz tests.

Exit gate:

- legacy behavior byte/semantics compatible where promised;
- ref resolution deterministic;
- revision conflict safe;
- concurrent root publication, revocation and GC cannot delete live content;
- identical bytes across subjects cannot expose existence, IDs, cache reuse or
  encryption-domain linkage;
- all schemas versioned;
- no active routing.

## Phase 3 — NIR integration and prompt projection

Deliverables:

- `SubAgentRequestV2`/`SubAgentResultV2`;
- dual-read, V2-write behind flag;
- primary/QA/retry projection through refs/deltas;
- provider structured-output adapters;
- stable-prefix caching layout;
- actual provider usage extensions;
- private record migration;
- content-free NCT WAL events.

Exit gate:

- NIR parse success >= 99.9% in supported routes;
- semantic round-trip >= 99%;
- no privacy/authority regression;
- benchmark shows measurable duplication reduction;
- feature remains opt-in/shadow.

## Phase 4 — shadow route and codec planner

Deliverables:

- deterministic route policy;
- route/codec estimates;
- shadow suggestions;
- route receipts;
- per-edge telemetry;
- holdout dataset split;
- offline evaluator;
- Babel observe-only features.

Exit gate:

- shadow decisions are reproducible;
- no task path changes;
- estimated vs actual cost/latency error is characterized;
- privacy-safe metrics;
- fixed baseline defined.

## Phase 5 — active deterministic routing

Deliverables:

- active `Direct`, `DirectWithVerifier`, bounded parallel, sequential, manager-worker, Council selection;
- safety overrides;
- budgets, hard caps, operator forcing;
- explicit fallback;
- active codec selection among non-latent codecs.

Exit gate:

- held-out quality non-inferior;
- lower total cost/latency on eligible workload;
- route regressions have typed rollback;
- active mode remains opt-in for one release.

## Phase 6 — authenticated admission

Deliverables:

- manifest and fixed signature layout;
- HMAC/Ed25519 integration;
- replay cache, expiry, sequence;
- state/capability/config binding;
- byte-exact cross-language canonicalization and algorithm registries;
- authorization epochs, revocation floor and linearizable cluster fencing;
- explicit no-failover sole-origin or quorum-committed authority mode with a
  restore-independent sealed monotonic anchor;
- signed membership/role transitions, revocation tombstones and active-member
  rekeying;
- budget/provider-permit/final-model/price-bound admission;
- single-use provider permits and exact paid-execution state transitions;
- task-capable versus gossip-only carrier qualification from installed
  multi-process release artifacts;
- indeterminate paid-execution reconciliation;
- explicit downgrade;
- action-firewall integration;
- adversarial and crash-recovery suite.

Exit gate:

- all tamper/replay/mismatch fixtures reject fail closed;
- dual-leader, minority, stale fence/leader/membership/auth epochs, restored
  local-only state and ambiguous paid retries reject;
- a node below or unable to verify the independent revocation anchor authorizes
  no session, permit, terminal result or effect;
- permit consume/refund/reconcile and role/quorum/last-admin invariants pass
  crash, partition, replay and restore tests;
- every advertised task carrier passes its real installed three-process matrix;
- no action path bypass;
- golden vectors pass Rust/Python;
- key rotation/recovery documented.

No latent backend may become usable before Phase 6 passes.

## Phase 7 — A2A NIR profile

Deliverables:

- A2A Agent Card extension;
- NIR DataPart/Artifact mapping;
- Signed Agent Card verification;
- mTLS or OAuth-DPoP proof of possession with per-message/channel binding;
- algorithm allowlist, JWKS anti-rollback and hardened SSRF/redirect handling;
- external peer policy mapping;
- conformance tests against at least two SDK languages;
- no external latent transfer.

Exit gate:

- version negotiation and fallback work;
- card/key/origin/task/message/channel swaps and stale revocation epochs reject;
- external peer cannot inherit internal capability;
- malformed/oversized A2A messages fail closed;
- docs and example peer published.

## Phase 8 — latent lab

Deliverables:

- managed packaged Python sidecar with operator-opt-in activation;
- null and HF exact-runtime backend;
- mandatory Windows/Linux/macOS OS sandbox and parent-owned private IPC;
- sealed dependency/model bundle, safe formats and `trust_remote_code=false`;
- fingerprint and compatibility doctor;
- ephemeral tensor registry;
- visible commitment;
- authenticated envelope;
- NIR fallback;
- benchmark variants.

Exit gate:

- exact match enforced;
- same-host only;
- no persistence;
- network, ambient filesystem, shell, subprocess and signing authority denied;
- malicious-sidecar and parent-death compromise tests pass;
- no action authority;
- quality/cost/latency/security gates pass for at least one frozen configuration.

## Phase 9 — vLLM/LMCache and AVP adapter qualification

Deliverables:

- supported vLLM connector path;
- LMCache integration if it reduces net cost;
- AVP adapter implementation/qualification behind the common trait and an
  operator activation feature;
- compatibility matrix;
- memory/backpressure controls;
- the same sandbox, sealed-bundle, IPC and Rust-side validation contract for
  every retained backend;
- fault injection.

Exit gate:

- each backend independently qualifies;
- no claim from upstream benchmarks alone;
- dependency/license/security reviews pass;
- unsupported hardware/layout fails before transfer.

## Phase 10 — evidence release

Deliverables:

- reproducible benchmark report;
- threat-model report;
- route-policy card;
- compatibility matrix;
- negative results;
- public claim review;
- Graphify/self-wiki/Obsidian/release snapshot;
- release notes and rollback runbook.

Exit gate:

- all Definition of Done criteria pass;
- exact release commit CI/Security/CodeQL green;
- public claims match measured evidence.

---

## 18. Proposed PR sequence

| PR | Scope | Depends on | Rough effort |
|---|---|---|---:|
| NCT-000 | ADR, plan, freeze, source map | none | 2–4 d |
| NCT-001 | current NEXUS benchmark + duplication metrics | none | 4–7 d |
| NCT-002 | provider usage field inventory/normalization | Gold-safe overlap | 4–8 d |
| NCT-003 | finish sub-agent typed context under R3-14 | Gold dependency | tracked by Gold |
| NCT-100 | module skeleton, schemas, limits, golden vectors | Gold | 5–8 d |
| NCT-110 | CAS refs + capability-scoped resolver | NCT-100 | 8–14 d |
| NCT-120 | state revisions + typed deltas + transaction | NCT-110 | 8–14 d |
| NCT-130 | V2 handoff/result + legacy dual-read | NCT-100/120 | 7–12 d |
| NCT-140 | context projector + prompt compiler | NCT-130 | 8–14 d |
| NCT-150 | structured provider output + bounded repair | NCT-140 | 6–10 d |
| NCT-160 | QA/retry migration to refs/deltas | NCT-140/150 | 6–10 d |
| NCT-170 | edge telemetry + WAL + private records | NCT-130 | 6–10 d |
| NCT-200 | deterministic shadow router | NCT-170 | 8–14 d |
| NCT-210 | active route policy + operator controls | NCT-200 | 10–18 d |
| NCT-220 | non-latent codec registry/selection | NCT-150/200 | 6–10 d |
| NCT-300 | manifest, signing, replay, admission | NCT-120/170 | 12–20 d |
| NCT-310 | action-firewall and crash recovery | NCT-300 | 8–14 d |
| NCT-400 | A2A NIR profile | NCT-300 | 12–20 d |
| NCT-500 | latent trait/null backend/doctor | NCT-300 | 6–10 d |
| NCT-510 | HF sidecar exact-runtime lab | NCT-500 | 18–30 d |
| NCT-520 | vLLM/LMCache backend | NCT-510 | 18–35 d |
| NCT-530 | AVP adapter implementation and qualification | NCT-500 | 10–20 d |
| NCT-600 | full benchmark/security/product dossier | all qualifying lanes | 12–20 d |

Effort values are preliminary engineering ranges, not calendar commitments. They assume an experienced developer already familiar with NEOTH and exclude unrelated Gold closure.

---

## 19. Test and evaluation plan

### 19.1 Variants

```text
A  Current direct/single-agent baseline
B  Current NEXUS/Council full-text handoff
C  NIR JSON with inline content
D  NIR refs + state deltas
E  Adaptive route + adaptive non-latent codec
F  Exact-runtime latent handoff
G  A2A NIR peer
```

### 19.2 Task buckets

1. **Direct small tasks** — should not be over-orchestrated.
2. **Independent evidence gathering** — parallelism may help.
3. **Split evidence / information asymmetry** — communication quality matters.
4. **Sequential planning** — tests accumulated distortion.
5. **Repository coding** — deterministic build/test/lint acceptance.
6. **QA and retry** — tests repeated-context savings.
7. **Tool workflows** — capability and action-gate correctness.
8. **Memory/recall** — reference and provenance preservation.
9. **Contradiction/Council** — dissent and arbitration.
10. **Long context** — context and cache pressure.
11. **Adversarial prompts** — injection, delimiter, authority smuggling.
12. **Latent security** — tamper, replay, mismatch, poisoned commitment.
13. **Fault and resource pressure** — crash, timeout, OOM pressure, stale refs.
14. **External A2A** — schema/version/peer trust failures.

Prefer deterministic task checks. Where an LLM judge is unavoidable:

- use at least two judges or a calibrated human subset;
- hide variant identity;
- record judge disagreement;
- keep exact prompts/models;
- do not let one provider grade itself exclusively.

### 19.3 Core quality gates

| Gate | Required threshold |
|---|---:|
| NIR schema parse success | >= 99.9% |
| Authoritative reference resolution | 100% for valid fixtures |
| Invalid/expired/unauthorized reference rejection | 100% |
| Semantic codec round-trip | >= 99% task-semantic equivalence |
| Deterministic fields round-trip | 100% |
| Repair/fallback rate on supported provider paths | < 1% |
| Task quality vs matched baseline | non-inferior; default <= 1 percentage point absolute loss, preregistered per task |
| Eligible handoff token reduction | >= 30% median |
| Eligible total cost reduction | >= 20% median |
| No increase in task failure from stale/conflicting state | required |
| Route receipt reproducibility | 100% for frozen policy/features |
| Tamper/replay/fingerprint mismatch rejection | 100% of adversarial corpus |
| Latent-origin external actions with typed live gate | 100% |
| Latent p95 latency improvement | >= 25% on declared eligible workload |
| Latent quality | non-inferior to best matched text/NIR route |
| Memory/resource caps | 100% enforced |
| A2A malformed/version mismatch handling | 100% conformance fixtures |
| WAL content leakage | 0 forbidden payloads in scan |
| Babel calibration | no degradation; advisory only until validated |

### 19.4 Router evaluation

- Freeze feature schema and candidate routes.
- Split runs by task family into train/validation/holdout.
- Compare:
  - always direct;
  - always Council;
  - simple fixed rules;
  - deterministic NCT policy;
  - learned selector, if later added.
- Measure:
  - task success;
  - total cost;
  - latency;
  - route regret;
  - risk violations;
  - calibration of expected gain;
  - out-of-domain behavior.
- Use paired tasks/seeds and bootstrap confidence intervals.
- Publish failures and domains where direct wins.

### 19.5 Latent evaluation

For every model/backend pair publish:

```text
weights digest
tokenizer digest
engine/build
quantization/dtype
hardware
parallel layout
prompt/system digest
task set
latent steps
KV/hidden payload bytes
memory peak
transfer/admission time
decode time
total latency
quality
fallback rate
tamper tests
```

No aggregate “4x faster” claim may be copied from research. NEOTH must reproduce its own numbers on its own eligible configurations.

### 19.6 Security suite

Required adversarial cases:

- one-byte payload modification;
- tensor metadata modification;
- visible commitment swap;
- sender/receiver swap;
- task/session swap;
- old sequence replay;
- nonce replay;
- expired transfer;
- correlation omission/swap/tamper across task, attempt and session;
- policy/config generation change, equal-generation config-digest mismatch and
  config-digest omission/tamper;
- route-receipt omission/swap/tamper or selected route/codec disagreement;
- canonical ref-set omission versus empty, duplicate/unsorted/extra/truncated
  entries and tamper of every full `ContentRef` commitment field;
- authorization-epoch rollback and cached state below the revocation floor;
- sole-origin unavailable with attempted automatic failover or foreign grant;
- dual leaders, quorum minority, uncommitted acknowledgement and stale
  leader/fence generation, term/index/proof or membership epoch;
- restored SQLite/WAL below the platform-sealed/quorum revocation anchor,
  missing anchor and long-offline node without current proof;
- membership proof/tombstone rollback, self-elevation, minority quorum change,
  concurrent demotion and last-administrator removal without atomic successor;
- revoked member excluded from future transport/group/content keys while tests
  acknowledge that already copied plaintext cannot be remotely erased;
- budget grant, provider permit, final provider/model, output ceiling or pricing-bound swap;
- budget permit worker node, membership/auth epoch, task/attempt/fence, provider
  account, model revision, currency/FX/tax, expiry or nonce swap;
- duplicate permit consume, release after dispatch, expiry/crash auto-refund,
  retry/fallback permit reuse and indeterminate-to-unspent without
  authoritative reconciliation;
- stale state revision;
- model name same but tokenizer/quantization/layout different;
- valid MAC with semantically malicious sender;
- valid sidecar HMAC attempting to mint authority or disagreeing with Rust validation;
- truncated/oversized/compressed bomb;
- sidecar crash before/after export/import;
- sidecar network, arbitrary file/registry, shell, child-process and sandbox escape attempts;
- AppContainer/restricted-token, namespace/seccomp/cgroup and macOS sandbox enforcement;
- IPC endpoint squatting, symlink/reparse swap, PID reuse, wrong OS peer credentials and stale generation;
- parent death/reload kills the complete sidecar generation and invalidates its session key;
- `trust_remote_code`, unsafe model format, unlocked dependency or bundle-hash mismatch rejection;
- malformed rank/dimension/stride/dtype/shared-memory metadata independently rejected by Rust;
- canonical encoding endian/width/enum/option/list/UTF-8-NFC/duplicate-key/trailing-byte vectors;
- every manifest field encoded exactly once, payload-digest double-append,
  field omission/adjacent swap, empty/maximum/unknown key IDs, HMAC/Ed25519 and
  alternate-length vectors;
- hash/signature algorithm confusion, wrong digest length and unknown algorithm IDs;
- typed downgrade omission/presence confusion, source/target swap,
  source-equals-target, target/manifest-codec mismatch, stale or absent
  authorization/policy commitment, unknown reason code and downgrade stripping
  privacy labels;
- last-known-good downgrade attempt on an identity, subject, capability, lease,
  membership, budget, provider, pricing or action-policy axis;
- action intent not represented in commitment;
- A2A Agent Card/key rotation mismatch;
- A2A proof replay and sender/recipient/origin/namespace/task/message/sequence/card/key/channel swap;
- A2A `alg` confusion, JWKS/Card rollback, DNS rebinding, redirect-policy bypass and cross-origin credential forwarding;
- CAS reference replaced or range escaped;
- CAS publish partial/hash/length/TOCTOU failure, GC root race, grace-period rescue and delete-time recheck;
- identical plaintext under different subjects/authority namespaces produces
  unrelated visible IDs/encryption domains with no existence, resolution,
  timing/cache-hit or physical-reuse oracle;
- resolver-handle actor/subject/purpose/session swap and mid-stream revocation;
- paid provider timeout/crash remains indeterminate and cannot auto-retry without reconciliation;
- each advertised task-capable carrier runs delegation, ACK/replay,
  backpressure/cancel, crash/restart, partition/minority, stale-fence and
  redelegation against at least three installed release-binary processes;
- WAL/private-record content leakage.

Crypto detects transport integrity violations under key assumptions; semantic maliciousness must still be caught by evidence, QA, policy, and action gates.

### 19.7 Statistical discipline

- preregister benchmark tasks, thresholds, and exclusion rules;
- freeze prompts/configs before final comparison;
- report exact model versions and dates;
- use paired comparisons;
- publish confidence intervals;
- distinguish provider estimates from authoritative usage;
- do not tune on holdout;
- report negative results;
- keep raw private data out of public artifacts;
- publish synthetic/reproducible fixtures where possible.

---

## 20. Rollout and migration

### 20.1 Modes

```text
off       Legacy behavior only
shadow    Compute NIR/routes/estimates; do not change execution
active    Use qualified non-latent NCT routes
lab       Explicit local latent testing; never default
```

### 20.2 V1 to V2 handoff migration

1. Add `SubAgentRequestV2`/`ResultV2`.
2. Keep V1 decoder.
3. Convert V1 to canonical NIR with `legacy_context` provenance.
4. Write V2 only behind feature flag.
5. Compare V1/V2 in shadow.
6. Move one consumer at a time:
   - provider-only sub-agent primary;
   - QA;
   - retry;
   - coding chain;
   - Council;
   - channels/Buddy/Cron where applicable.
7. Retain downgrade adapter for one documented compatibility window.
8. Remove V1 writes only after stored-run migration and rollback tests.
9. Do not remove V1 reads until release policy and migration telemetry allow it.

### 20.3 Activation sequence

```text
Gold checkpoint G0: off, schemas/docs/baseline only
Gold checkpoint G1: shadow, behavior-neutral comparison
Gold checkpoint G2: active non-latent opt-in after qualification
Gold checkpoint G3: eligible non-latent default only if evidence passes
Gold release: managed sidecar, null/Doctor and at least one non-null exact-runtime
              backend packaged, installed, tested and surfaced; latent runtime
              activation remains a separate explicit opt-in
```

No silent default flip. Checkpoint labels are implementation gates inside the
same `v1.0.0 Gold` workstream, not later release promises.

### 20.4 Rollback

- one config switch returns to legacy direct/NEXUS behavior;
- schema major versions remain readable during rollback window;
- state revisions and CAS are additive/immutable;
- latent state is ephemeral and discarded;
- route policy version is pinned in every receipt;
- authorization, membership and key revocation floors never roll back with the
  feature or schema version;
- a paid leaf in `indeterminate_paid_execution` keeps its reservation and is
  reconciled before rollback can retry or release it;
- rollback emits a typed event;
- rollback does not downgrade privacy or action policy.

---

## 21. Risks and kill criteria

### 21.1 Main risks

| Risk | Consequence | Mitigation |
|---|---|---|
| Protocol complexity exceeds savings | maintenance burden | semantic core + small codec set; kill thresholds |
| Models misunderstand compact forms | repair/retry cost | full-name canonical JSON; per-model qualification |
| Router over-orchestrates | higher cost, lower quality | direct-first policy, shadow mode, holdout |
| Shared state becomes mutable/global | races and leakage | immutable refs, revisions, capability resolver |
| CAS GC races publication/revocation | live-object loss or revoked read | transacted roots, snapshot epoch, grace and delete-time recheck |
| Latent tensors are huge | OOM/latency | strict eligibility, size caps, local-only, benchmark |
| Latent state is opaque | hidden attack/leak | visible commitment, authenticated manifest, action firewall |
| Latent sidecar is compromised | host escape, model/code execution, forged payload | mandatory OS sandbox, sealed safe bundle, private peer-authenticated IPC, independent Rust validation |
| Cross-model projection unstable | silent quality loss | Gold qualification lane; runtime disabled unless its reproduced gates pass or the adapter records an evidence-backed SKIP |
| A2A expands trust boundary | remote injection/authority confusion | signed cards, PoP/channel binding, anti-rollback, hardened fetch, no lease inheritance |
| Cluster split brain or stale cache | duplicate terminal result/action/budget | linearizable fencing, committed leader/membership/auth epochs |
| Paid provider outcome is indeterminate | duplicate cost or work on blind retry | retained reservation, idempotency/reconciliation, typed operator escalation |
| Babel causes circular self-steering | false throttles | observe first, independent validation, bounded feature |
| Gold work is delayed | release failure | dependency-ordered Gold workstream; no parallel harness |
| “USP” marketing outruns evidence | credibility loss | claim ladder and evidence dossier |
| Broad patents exist | legal exposure | professional claim/FTO review |

### 21.2 Kill criteria

Stop or narrow a lane when any criterion persists after one bounded remediation cycle:

- NIR/ref total savings are < 20% after repair and resolver overhead.
- Semantic error or repair rates exceed the gates.
- Adaptive routing cannot beat simple fixed rules on holdout.
- Direct routing wins nearly everywhere and topology selection adds no value.
- Latent memory/transfer overhead erases latency/cost advantage.
- Latent quality is unstable across seeds or model updates.
- Admission cannot fail closed without unacceptable false rejection.
- Cross-model projection is not reproducible across multiple models/tasks.
- A2A dependency surface exceeds product value.
- Babel does not add out-of-sample predictive value.
- Operational complexity causes more failures than it prevents.

If an individual latent adapter fails, retain its negative evidence and use the
qualified exact-runtime backend. Gold cannot close if no non-null backend meets
the packaged install, sandbox, quality and security contract; NIR, refs,
revisions, route receipts and secure admission remain the safe fallback during
runtime use, not a release-scope escape hatch.

---

## 22. Engineering estimate and critical path

### 22.1 Preliminary range

| Workstream | Engineer-days |
|---|---:|
| NIR, refs, revisions, projection, migration, shadow telemetry | 45–75 |
| Hardened routing, authenticated admission, A2A profile | 35–60 |
| Latent lab, backends, hardening, compatibility evidence | 50–90 |
| **Total** | **130–225** |

Uncertainty is high because:

- Gold closure may change the exact insertion seam;
- provider usage parity varies;
- A2A Rust SDK/API may evolve;
- latent backend compatibility is hardware/model specific;
- security/fuzz findings may force redesign.

### 22.2 Critical path

```text
Gold R3-14 closure
  -> canonical typed context
  -> NIR/ref/revision foundation
  -> provider usage + projection
  -> shadow routing
  -> active non-latent routing
  -> authenticated admission
  -> A2A and/or latent
  -> evidence release
```

Latent is late on the dependency path and is never required for an individual
task to run, but the fully packaged local backend contract and at least one
qualified non-null configuration are required before the Gold release can ship.

---

## 23. Definition of Done

NCT is done for a production claim only when all are true:

### Architecture

- [ ] One canonical semantic NIR schema exists.
- [ ] All production codecs round-trip to it.
- [ ] NEXUS/Council integration uses versioned V2 handoffs.
- [ ] No parallel uncontrolled agent harness exists.
- [ ] Direct route remains first-class.
- [ ] Existing provider/action/consent/capability gates remain authoritative.

### State

- [ ] Large payloads use immutable scoped references.
- [ ] State transitions are revision-bound and transactional.
- [ ] Conflict/replay/crash behavior is deterministic.
- [ ] GC and retention are documented and tested.
- [ ] No raw host path is an authority-bearing model token.

State closure includes immutable bounded publish, actor/subject/purpose-bound
resolver handles, mid-stream revocation, transactional root snapshots, epoch
barriers, grace and delete-time rechecks. A directory scan or mark-only GC test
does not satisfy these items. Internal storage digests remain private; visible
references are keyed to subject, authority namespace and encryption domain and
bind privacy/taint/provenance plus grant metadata. Identical cross-subject
content must not expose existence or reuse.

### Security

- [ ] Manifest golden vectors pass across implementations.
- [ ] Tamper, replay, mismatch, expiry, and downgrade tests pass.
- [ ] Latent cannot authorize an action.
- [ ] WAL contains no forbidden payload content.
- [ ] Keys and rotation/recovery are documented.
- [ ] Threat model states what crypto does not prove.

Security closure additionally requires the byte-exact signature contract,
monotonic revocation floors, linearizable cluster fencing, final
budget/provider/model/price binding, indeterminate paid-execution handling and
the mandatory per-platform sidecar sandbox. A Python process boundary, valid
sidecar HMAC, Signed Agent Card or passing happy-path tensor test is not
sufficient evidence. Closure also requires one frozen no-auto-failover
sole-origin or quorum-consensus authority mode, an independent non-rollback
anchor that survives ordinary restore, signed membership/role changes,
retained revocation tombstones and rekeying, single-use budget-permit state
transitions and real installed multi-process proof for every carrier marketed
as task-capable. Dual/minority/stale/restore, self-elevation/last-admin and
permit refund/retry adversarial cases must pass.

### Efficiency and quality

- [ ] Provider-native usage is captured where available.
- [ ] NIR/ref gates pass.
- [ ] Router holdout gates pass.
- [ ] Direct-vs-multi-agent results are published.
- [ ] Latent claims are limited to qualified configurations.
- [ ] Negative results are included.

### Interoperability

- [ ] A2A profile is versioned and documented.
- [ ] Signed Agent Card policy works.
- [ ] At least two independent SDK-language conformance tests pass.
- [ ] MCP role remains bounded to tools/resources/context.
- [ ] No external peer inherits internal authority.

Interoperability closure includes session proof of possession, per-message or
cryptographic channel binding, algorithm/key allowlists, JWKS/Card anti-rollback
and redirect-by-redirect SSRF/credential isolation. Agent Card signature
verification alone cannot close the A2A security contract.

### Product/release

- [ ] Public claim review matches measured evidence.
- [ ] ADRs and runbooks exist.
- [ ] Graphify affected-map/self-wiki/Obsidian/release snapshot are current.
- [ ] Exact release commit passes CI, Security, CodeQL, and release gates.
- [ ] Rollback is tested.
- [ ] No Gold scope was silently deferred.

Product/release closure requires the managed latent sidecar, null/Doctor
contract and at least one qualified non-null exact-runtime backend to be
packaged, installable, repairable, removable and clean-machine tested on its
declared platforms. Runtime activation may remain off by default and
operator-opt-in; shipping and DoD may not be labeled optional, future or
post-Gold.

---

## 24. Immediate next actions

These are the immediate dependency-ordered actions for Gold:

1. Add this document to `PLAN/NEOTH_COGNITIVE_TRANSPORT.md`.
2. Add an ADR stating:
   - binding `v1.0.0 Gold` lane;
   - NCT evolves NEXUS;
   - NIR/ref first;
   - latent last;
   - no “first/universal” claim.
3. Add a behavior-neutral benchmark around current `sub_agents/runtime.rs`:
   - primary prompt bytes/tokens;
   - QA prompt bytes/tokens;
   - retry prompt bytes/tokens;
   - duplicated-content ratio;
   - actual provider usage when available.
4. Tag all NCT-overlapping work under existing `GOLD-R3-14`; do not create a second typed-context implementation.
5. Freeze a small deterministic task corpus for future A/B comparison.
6. Record current direct/NEXUS/Council quality, cost, latency, and retry baselines.
7. Track PRs `NCT-100+` in the Gold workstream and its production-consumer
   adoption ledger.
8. Do not add latent dependencies or public config until authenticated
   admission, canonical signing, mandatory OS sandboxing and private IPC are
   designed and adversarially tested.

### First Gold implementation slice

The highest-value first slice is:

```text
NIR V2
+ ContentRef
+ StateRevision
+ typed QA/retry projection
+ provider-native usage
+ shadow route receipt
```

This can save tokens and improve auditability without requiring latent model internals, a Python sidecar, A2A, or learned routing.

---

## 25. ADR set

Create:

```text
ADR-NCT-001  Product boundary, release lane, and non-goals
ADR-NCT-002  NIR canonical schema and codec separation
ADR-NCT-003  Content references, revisions, delta and epoch-barrier GC semantics
ADR-NCT-004  Direct/topology/codec route policy
ADR-NCT-005  Canonical manifest, keys, fencing, revocation and admission
ADR-NCT-006  Action-firewall binding
ADR-NCT-007  A2A NIR profile, PoP/session binding and MCP boundary
ADR-NCT-008  Latent backend, OS sandbox and exact-runtime compatibility
ADR-NCT-009  Telemetry, benchmark, and claim policy
ADR-NCT-010  Babel observe/advisory/throttle progression
```

Every ADR needs:

- context;
- decision;
- alternatives rejected;
- security implications;
- migration;
- rollback;
- measurable acceptance criteria;
- affected Graphify/self-wiki nodes.

---

## 26. Legal and prior-art note

This research is not a patent opinion or freedom-to-operate analysis.

A preliminary keyword review found patent publications/claims covering broad areas such as:

- multi-agent orchestration and validation;
- parallel LLM pipelines;
- reuse of KV caches or partial layer outputs between related models;
- permission/invalidation concepts around internal state reuse [R21–R22].

Before filing patents, promising exclusivity, or making legal novelty claims:

1. commission a professional claim-level search;
2. inspect patent families, priority dates, jurisdictions, prosecution status, and independent claims;
3. map each planned NCT mechanism to claims, not abstracts;
4. review open-source licenses and NOTICE obligations;
5. document clean-room/original implementation where relevant;
6. avoid naming or marketing that implies ownership of existing open protocols.

The product can still be differentiated even if individual primitives are prior art.

---

## 27. Source record

Primary and first-party sources checked during this plan:

### Research

- **[R01]** Kim et al., “Capable language models can outgrow the benefits of collaboration,” *Nature Machine Intelligence*, published 2026-07-24.
  https://www.nature.com/articles/s42256-026-01268-y

- **[R02]** Gupta et al., “Learning Optimal Message Representations for Agentic Communication,” Findings of ACL 2026 (OPTiMACS).
  https://aclanthology.org/2026.findings-acl.1441/

- **[R03]** Tang et al., “Augmenting Multi-Agent Communication with State Delta Encoding,” EMNLP 2025.
  https://aclanthology.org/2025.emnlp-main.518/

- **[R04]** Zou et al., “Latent Collaboration in Multi-Agent Systems” / LatentMAS.
  https://arxiv.org/abs/2511.20639

- **[R05]** Official LatentMAS repository.
  https://github.com/Gen-Verse/LatentMAS

- **[R06]** Liu, “Beyond Tokens: A Unified Framework for Latent Communication in LLM-based Multi-Agent Systems,” updated 2026-07-15.
  https://arxiv.org/abs/2606.05711

- **[R07]** Agent Vector Protocol specification and reference SDK.
  https://github.com/VectorArc/avp-spec
  https://github.com/VectorArc/avp-python

- **[R08]** Brito and Baquero, “When Latent Agents Lie: KV-Cache Integrity in Multi-Agent LLM Collaboration,” 2026-06-27.
  https://arxiv.org/abs/2606.28958

- **[R09]** Wang et al., “Out of Sight, Not Out of Mind: Unveiling Latent Attack in Latent-based Multi-Agent Systems,” 2026-05-27.
  https://arxiv.org/abs/2605.28214

- **[R27]** Li et al., “When Less Latent Leads to Better Relay: Information-Preserving Compression for Latent Multi-Agent LLM Collaboration,” 2026.
  https://arxiv.org/abs/2604.13349

- **[R28]** “Reusable Latent Building Blocks for Multi-Agent Systems,” 2026.
  https://arxiv.org/abs/2602.03695

### Inference and caching

- **[R10]** vLLM NixlConnector usage guide.
  https://docs.vllm.ai/en/stable/features/nixl_connector_usage/

- **[R11]** LMCache documentation and architecture.
  https://docs.lmcache.ai/
  https://docs.lmcache.ai/mp/index.html

- **[R12]** OpenAI Prompt Caching documentation.
  https://developers.openai.com/api/docs/guides/prompt-caching

- **[R13]** Anthropic Prompt Caching and context-window documentation.
  https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching
  https://docs.anthropic.com/en/docs/build-with-claude/context-windows

### Protocols and frameworks

- **[R14]** A2A protocol specification, 1.0 announcement, and core release repository.
  https://a2a-protocol.org/latest/specification/
  https://a2a-protocol.org/latest/announcing-1.0/
  https://github.com/a2aproject/A2A/releases

- **[R15]** Official A2A Rust SDK.
  https://github.com/a2aproject/a2a-rs

- **[R16]** Model Context Protocol specification.
  https://modelcontextprotocol.io/specification/2025-11-25

- **[R17]** OpenAI Agents SDK: handoffs, sessions, tracing.
  https://openai.github.io/openai-agents-python/handoffs/
  https://openai.github.io/openai-agents-python/sessions/
  https://openai.github.io/openai-agents-python/tracing/

- **[R18]** LangGraph: graph state, subgraphs, persistence, checkpointers.
  https://docs.langchain.com/oss/python/langgraph/graph-api
  https://docs.langchain.com/oss/python/langgraph/use-subgraphs
  https://docs.langchain.com/oss/python/langgraph/checkpointers

- **[R19]** Microsoft Agent Framework workflows and orchestrations.
  https://learn.microsoft.com/en-us/agent-framework/workflows/
  https://learn.microsoft.com/en-us/agent-framework/workflows/orchestrations/handoff

- **[R20]** CrewAI Flows, state, persistence, and memory.
  https://docs.crewai.com/en/concepts/flows
  https://docs.crewai.com/en/guides/flows/mastering-flow-state
  https://docs.crewai.com/en/concepts/memory

### Preliminary patent landscape

- **[R21]** US20250259042A1 and US20250259044A1, orchestration/KV or partial-layer reuse descriptions.
  https://patents.google.com/patent/US20250259042A1/en
  https://patents.google.com/patent/US20250259044A1/en

- **[R22]** US12111859B2 and US12039263B1, multi-agent orchestration and parallel LLM pipeline claims/descriptions.
  https://patents.google.com/patent/US12111859B2/en
  https://patents.google.com/patent/US12039263B1/en

### Current NEOTH source

- **[R23]** Current `PROGRESS_v1_0.md`, last updated 2026-07-26.
  https://github.com/The-Geek-Freaks/NEOTH/blob/main/PLAN/PROGRESS_v1_0.md

- **[R24]** Current NEXUS sub-agent request/result schemas.
  https://github.com/The-Geek-Freaks/NEOTH/blob/main/SRC/neothd/src/sub_agents/schema.rs

- **[R25]** Current sub-agent runtime, QA, retry, limits, and WAL flow.
  https://github.com/The-Geek-Freaks/NEOTH/blob/main/SRC/neothd/src/sub_agents/runtime.rs

- **[R26]** Current NEOTH README and Delta/NEOTH integration notes.
  https://github.com/The-Geek-Freaks/NEOTH/blob/main/README.md
  https://github.com/The-Geek-Freaks/delta-kosmologie/blob/main/docs/neoth-integration.md

---

## 28. Final recommendation

Proceed, but with a corrected center of gravity:

```text
Do not build “an AI language.”
Build a versioned cognitive transport system.

Do not start with latent tensors.
Start with direct-route selection, typed state deltas, references, and truthful metrics.

Do not trust a readable receipt alone.
Authenticate the payload, commitment, runtime, state, policy, and capability.

Do not force multi-agent collaboration.
Prove when delegation beats a strong direct model.

Do not market primitives as unique.
Market the measured, local-first, fail-closed, auditable integration only after it earns the claim.
```

The best first implementation is therefore **NIR/1 + immutable references + revision-bound deltas + typed QA/retry projection + provider-native usage + shadow route receipts**. It attacks the real current duplication seam, aligns with open Gold work, produces immediate measurable value, and leaves a clean path to A2A and authenticated latent transfer without betting the product on unstable model internals.
