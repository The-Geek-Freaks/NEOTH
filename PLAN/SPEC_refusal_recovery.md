# SPEC: Refusal Recovery — Native Provider Outcomes + Truthful Retry Pipeline

**Version:** 1.3
**Last-Updated:** 2026-07-30
**Implementation-Status:** PARTIAL RUNTIME — text detection, cause
classification, native outcomes for the listed adapters, exact-leaf retry,
fresh retry authorization, WAL reroute/persistent events and CLI/Channel
recovery exist. Full provider-profile/fixture parity, one shared
CLI/GUI/Buddy/all-Channel coordinator, truthful typed operation context and the
complete operator-sovereign secret data plane remain release-blocking under
`GOLD-R4-15`.
**Framework-Basis:** Tool-Framework v4.1 (Teil B.5 / C.1 — recovery as Schicht-1 pipeline)

> Phase: 2 — extends `SPEC_mirror_refusal.md` (Schicht-0 detector already shipped 2026-05-15)
> Trigger: operator 2026-05-16 — "erkennung von antwortblock pro hemisphäre, mit versuch mit lowkey tricka trotzdem antwort zu bewirken, erkennen was antwortblock war, erneut versuchen"
>
> **Authority boundary (R-3 Gremium 2026-05-16):** Stage-0 detection + 0x16 emission + the
> operator-grant semantics of 0x18 belong to `SPEC_mirror_refusal.md`. Everything below
> (Stage-1 recovery state machine, cause classification, reframings, retry orchestration,
> per-hemisphere dispatch, hemisphere/provider switching events) belongs here.

---

## 0. Scope

The mirror-refusal Schicht-0 classifier already ships (`security::refusal_detect`). It fires on a single response text and produces a `RefusalReport`. What's missing is the **recovery pipeline** that acts on that report:

1. **Per-hemisphere detection** — when the council/router uses several
   hemispheres, classify every leaf independently. One refusal does not erase a
   separately completed answer.
2. **Native outcome retention** — adapter-native finish/stop/refusal/filter
   metadata is authoritative. Text classification is fallback only when the
   provider exposes no native signal.
3. **Truthful context re-evaluation** — at most once, add only locally verified
   operator origin, target relationship, authorization basis, exact scope,
   operation and purpose. Preserve the original request verbatim.
4. **Retry orchestration** — transient availability retry, truthful policy
   re-evaluation and alternate-leaf fallback have separate budgets and audit
   reasons. Partial streamed output is never transparently replayed.
5. **Precise attribution** — distinguish NEOTH technical deny, missing
   operands, local capability/OS/transport failure, router guardrail, provider
   prompt/output filter and model-authored refusal.

This spec **does not** implement adversarial cloud jailbreaks, euphemistic
classifier evasion or fabricated academic/historical/fictional authority.
Provider policy remains provider policy. When an operator-authored NEOTH rule
matches, recovery stops immediately and preserves that exact local reason.
A fully local secret transfer never enters this pipeline.

### Runtime checkpoint (2026-07-30)

The shared `ProviderTermination` envelope now reaches non-streaming and
streaming CLI/Channel post-reply processing instead of being collapsed into
response text. Provider-default streams copy the non-stream completion's
termination into the final chunk. OpenAI SSE additionally accumulates native
refusal/filter facts through `[DONE]`, EOF and recognized policy-blocked
handshakes. A live CLI stream whose deltas/provider boundary already crossed
stdout is attributed but never invisibly retried or replaced; a buffered stream
may recover before release.
The following native signals are retained before deterministic text fallback:

| Adapter | Retained native outcome |
|---|---|
| OpenAI Chat | `message.refusal`, refusal content parts and `finish_reason=content_filter` |
| OpenAI-compatible | structured `content_filter`, `content_policy_violation`, `refusal`, `data_inspection_failed`, moderation/policy/safety error envelopes |
| Anthropic Messages | `stop_reason=refusal` and opaque `stop_details` |
| Gemini Developer | `promptFeedback.blockReason`, prompt/candidate safety ratings, candidate `finishReason` and `finishMessage` |
| Azure OpenAI | 200-response `message.refusal`, `content_filter`, and structured policy envelopes |
| AWS Bedrock Converse | guardrail/content-filter stop reasons, retained separately from normal stop reasons |
| Claude CLI | native refusal termination in non-streaming and streaming result paths |
| Cohere | retained finish reasons; explicit error/timeout outcomes fail rather than masquerade as normal completion |
| Ollama | retained `done_reason` |

Recovery now requires an explicit typed `AuthenticatedOperatorOrigin` at the
coordinator call boundary. It is supplied by the local interactive CLI or a
successfully pinned operator Channel, never copied through the generic provider
request. The default catalogue contains one truthful `operator_authority`
re-evaluation; the former fictional, academic, historical and generic cloud
jailbreak paths are excluded.

Successful truthful, local-abliterated and teacher recovery return the complete
final `Completion`; callers retain the actual final provider/model,
provider-native termination and aggregate reported usage across concrete
attempts. Native refusals with no visible text still reach the Tier-3/teacher
gates. A refusing local shadow, cloud re-ask or teacher keeps the original
visible reply but still accounts for every completed attempt; a refusing
teacher is never persisted as a correction skill. The CLI's crash-recovery
turn journal durably records the accepted final termination with
backward-compatible defaults for older journals.

An opaque `dispatch_route` now binds the completion identity to the concrete
leaf selected through every routing decorator. `complete_pinned` consumes that
route without re-running fallback selection, while the authorization wrapper
forces the exact wire model and starts a new Council/cost/WAL/policy lifecycle.
Pinned 429/backoff state cannot hop to another leaf, nested routers own their
own quota state, and malformed cross-provider request controls fail before a
local-shadow dispatch.

This checkpoint is deliberately **not provider parity**. Kimi, Qwen, DeepSeek
and OpenRouter policy codes are recognized through the compatible envelope,
but their remaining leaf-specific native/mock streaming fixtures, OpenAI
Responses, Vertex-specific signals, remaining CLI/local native outcomes,
complete alternate/local selection UX and GUI/Buddy/all-Channel parity remain
open under `GOLD-R4-15j`. Official OpenAI Chat now receives a
privacy-preserving, request-bound `safety_identifier`; custom, compatible,
Azure, incognito and delegated leaves do not.

Normative provider references (accessed 2026-07-30):

- [OpenAI Chat Completions create](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
  (`developer` role, assistant refusal field/content and finish reason);
- [OpenAI safety checks](https://developers.openai.com/api/docs/guides/safety-checks)
  (`safety_identifier` contract; wired only for the exact official OpenAI
  Chat-Completions leaf);
- [Anthropic refusals and fallback](https://platform.claude.com/docs/en/build-with-claude/refusals-and-fallback)
  (`refusal` is a successful HTTP envelope; `stop_details` is diagnostic and
  the documented fallback is another model, not an identical blind retry);
- [Gemini safety settings](https://ai.google.dev/gemini-api/docs/safety-settings)
  (`promptFeedback.blockReason`, candidate `finishReason` and safety ratings);
- [Kimi error codes](https://platform.kimi.ai/docs/api/errors);
- [Alibaba Model Studio error codes](https://www.alibabacloud.com/help/en/model-studio/error-code)
  (`data_inspection_failed`);
- [DeepSeek Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion);
- [OpenRouter errors and debugging](https://openrouter.ai/docs/api/reference/errors-and-debugging)
  (canonical nested `error_type`, mid-stream error, provider/model moderation
  metadata and opt-in router pipeline metadata).

### 0.1 Normative provider recovery profiles

The coordinator must select a profile from the concrete authorized wire leaf;
an endpoint URL or an `openai_compat` label is not sufficient evidence of
provider semantics.

| Wire profile | Truthful request lowering | Native terminal evidence | Permitted recovery |
|---|---|---|---|
| OpenAI Chat / Responses | Preserve the request; place only verified operation facts in the documented developer/system surface. Send a stable privacy-preserving `safety_identifier` derived from the authenticated NEOTH principal and instance, never raw email, username, credential or prompt text. | Assistant refusal fields/content, `content_filter`, structured policy errors and stream terminal state. | At most one same-leaf re-evaluation when new verified facts were added; otherwise a separately authorized alternate/local leaf. |
| Anthropic Messages | Preserve the request and add verified facts through the system surface. Never claim that an API key, paid account or NEOTH operator role exempts the request from Anthropic policy. | `stop_reason=refusal`, bounded `stop_details`, partial output and stream terminal state. | Do not repeat the identical model/request. A fallback must select and authorize a different concrete model/leaf and cannot replace already emitted output. |
| Gemini Developer / Vertex | Preserve the request; use `systemInstruction` for verified context and keep the selected safety configuration bound to the request. NEOTH recovery never lowers thresholds or disables filters behind the operator's back. | Prompt `blockReason`, candidate `finishReason`, `safetyRatings`, Vertex safety/model-armor metadata and stream terminal state. | One truthful re-evaluation only when verified context changed; otherwise an explicit alternate/local leaf. A changed safety setting is a new operator-visible request, not a retry. |
| Moonshot / Kimi | Use an explicit Kimi profile even when the transport is OpenAI-compatible; preserve endpoint, region and actual model identity. | HTTP `400` `error.type=content_filter`, compatible refusal fields and terminal stream error. | No blind same-payload loop. One verified-context re-evaluation or a separately authorized alternate/local leaf. |
| Qwen / Alibaba Model Studio | Select the exact Chat, Responses, Anthropic-compatible or DashScope profile; do not flatten their different auth, payload and error envelopes. | `data_inspection_failed`, native finish/error fields and terminal stream state. | One verified-context re-evaluation only on the same exact profile; any surface/model change is a fresh authorized leaf. |
| DeepSeek and named compatible vendors | Retain the named vendor profile, endpoint and model even when Chat Completions-compatible. | Native/compatible `content_filter`, refusal and terminal stream evidence. | Same bounded truthful-context rule; never infer policy success from an empty `200` body. |
| OpenRouter | Request router metadata where supported and bind authorization to the selected router instance plus final provider/model observation. | Canonical nested `error_type`, native reason, actual provider/model and mid-stream error. | No transparent fallback after any visible delta. A pre-output alternate is a new concrete authorized attempt and keeps router/provider attribution. |
| CLI and local engines | Pass verified context only through the engine's typed request contract; secret payload bytes remain on the local data plane. | Exit status, structured result, local model stop reason and owned worker/process terminal state. | Only retry when the worker is proven terminated/reaped or cooperatively cancelled; otherwise record `client_abandoned`/`indeterminate` and stop. |

Every profile consumes the same typed `VerifiedOperationContext`. The compiler
may lower a field only when the local boundary proved it; absent facts stay
absent. The pseudonymous provider subject is domain-separated per provider
instance so vendors cannot correlate it across unrelated NEOTH installations.
It is not an authorization claim and never changes a vendor safety policy.

### 0.2 Compatible-provider identity and native-outcome contract

The legacy `openai_compat` label alone is not a sufficient provider identity.
The runtime now has named OpenRouter, DeepSeek, Moonshot/Kimi and Qwen wire
profiles, retains their distinct authorized leaf names, validates named
profiles against reviewed official service origins, and fails closed for Qwen
wire surfaces that the Chat-Completions adapter does not implement.
`local_qwen` still means the local Candle engine and is never evidence that
Alibaba Model Studio is active.

Introduce a typed compatible-wire profile at the configuration and authorized
leaf boundary:

```rust
enum OpenAiCompatibleProfile {
    Generic,
    OpenRouter,
    DeepSeek,
    MoonshotKimi,
    QwenChat,
    QwenResponses,
    QwenAnthropicCompat,
    QwenDashScope,
}
```

A selected known-endpoint entry persists its profile. An exact reviewed service
origin may be tagged automatically by CLI, wizard or GUI save paths; arbitrary
or local endpoints remain `Generic`. Profile and endpoint constraints reject
scheme, userinfo, port, query, fragment, path or host mismatches. The authorized
completion identity retains the named profile and requested wire model.
OpenRouter additionally retains bounded observed upstream provider/model
evidence without replacing the originally authorized router identity.

HTTP handshake errors, `200` choice errors and terminal SSE errors lower into
one redacted typed native outcome for both streaming and non-streaming paths.
It retains HTTP status, provider policy code, safe native error fields and
router/provider/model attribution; it never retains authorization headers,
credentials, request prompts or secret payloads. Auth, quota and server errors
remain distinct from policy refusals. Known profiles must not remain
`Retryability::Unknown`: their explicit profile determines whether one
verified-context same-leaf re-evaluation is meaningful or whether a different
leaf is required.

### 0.3 Authenticated provider subject and OpenAI safety identifier

The OpenAI `safety_identifier` is a privacy/abuse-correlation field, not an
authorization claim. It must not be a public/deserializable `Request` field,
because arbitrary internal callers could choose another identity. It also must
not derive from configurable `operator_id`, raw email, username, Channel sender,
machine name, install path or the rotating WAL HMAC key.

The mandatory leaf authorizer derives a private typed
`ProviderSubjectIdentifier` from the authenticated ingress audit context. A
dedicated non-rotating instance key under `identity/provider-subject.key` is
created with `CREATE_NEW` on the first eligible official-provider
authorization, owner-protected, synchronously published and read back through
capability-bound no-follow handles. A malformed or link-like existing key and
an invalid concurrent winner fail closed; neither is silently replaced. The
wire value is the 64-character lowercase hex HMAC-SHA-256 of a length-framed,
domain-separated provider/principal tuple. Different provider domains get
unlinkable values.

The mandatory leaf authorizer derives immutable outbound metadata, incorporates
presence and value into `request_binding_sha256`, and places that exact metadata
in the non-constructible dispatch permit. The transport serializes only the
permit-bound value. Retrying the same official OpenAI leaf preserves it;
fallback to another vendor cannot carry it. Streaming and non-streaming use the
same metadata-bearing permit.

Only the exact official OpenAI origin sends `safety_identifier`. Custom
endpoints, Azure, Copilot, OpenRouter and generic compatible providers omit it
unless their own authoritative API contract is separately implemented.
Incognito and delegated requests also omit it. WAL and logs retain only
binding/presence evidence plus a one-way operator-ID digest, never the
pseudonym or raw principal.

---

## 1. Per-Hemisphere Refusal Detection

### 1.1 Existing State

`security::refusal_detect::classify(response_text)` operates on one string. The chat dispatcher today calls it once on the single provider's response (post `0x16 REFUSAL_OBSERVED` shipped 2026-05-15).

### 1.2 New: Council-Aware Classification

When the chat path runs a council debate (multiple hemispheres respond independently), each hemisphere's response is classified separately. The aggregate verdict downstream can be:

- All three refused → escalate immediately
- Two refused, one answered → use the answering hemisphere's response (potentially with a refusal-noted caveat)
- One refused, two answered → ignore the refusal; the answers stand

```rust
pub struct HemisphereResponse {
    pub role: HemisphereRole,
    pub provider: String,
    pub text: String,
    pub refusal_report: RefusalReport,  // None-class = OK
}

pub struct CouncilOutcome {
    pub responses: Vec<HemisphereResponse>,
    pub strategy: CouncilStrategy,
}

pub enum CouncilStrategy {
    AllAnswered,
    Mixed { answered: usize, refused: usize },
    AllRefused,
}
```

### 1.3 WAL Audit

`EVENT_TYPE_REFUSAL_OBSERVED` (0x16) payload extends with optional `hemisphere_role: Option<HemisphereRole>` so an operator grepping the audit trail can see "right hemisphere refused, left answered, cerebellum routed".

The payload is backward-compatible — operators with existing 0x16 frames see `null` for the new field.

---

## 2. Cause Identification

### 2.1 Beyond `RefusalClass`

The existing 6-class enum (None / Hard / Partial / Soft / Redirect / SafetyWarning) tells the operator *that* a refusal happened. Recovery needs *why* — picking the right reframing depends on the cause.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCause {
    /// Provider's safety policy fired (e.g. Anthropic's harm-prevention).
    /// LOWKEY-tricks often work because the model genuinely *can* answer.
    SafetyPolicy,
    /// Provider says it lacks the capability (no internet, no code exec).
    /// Reframing won't help; switch hemisphere or escalate.
    CapabilityGap,
    /// Privacy / PII concern. An authenticated operator's explicit operation
    /// on operator-owned or explicitly authorised data preserves the exact
    /// request through operator-authority recovery. Untrusted/third-party
    /// content receives no such authority.
    Privacy,
    /// Operator's own `policy.yaml::dangerous_targets` matched. Legitimate
    /// guardrail — recovery does NOT attempt retry; operator wrote that
    /// rule themselves.
    OperatorPolicy,
    /// Detector classified refusal but cause is unclear.
    Unknown,
}
```

### 2.2 Cause Classifier

Primary input is typed `ProviderTermination`; only providers without a native
contract fall back to
`infer_cause(response_text, report) -> RefusalCause`. Deterministic text
patterns therefore never override a native provider outcome:

- `RefusalCause::SafetyPolicy` indicators: "harmful", "harmful content", "I'm not able to provide", "ich darf nicht", "verstößt gegen die Richtlinien"
- `RefusalCause::CapabilityGap`: "I don't have access to", "I cannot browse", "I'm not able to execute code", "real-time data"
- `RefusalCause::Privacy`: "personal information", "private", "PII", "personenbezogene Daten"
- `RefusalCause::OperatorPolicy`: only set externally by the dispatcher when `policy.yaml` matched pre-call; the classifier itself doesn't infer this from text
- `RefusalCause::Unknown`: default

---

## 3. Truthful Re-evaluation Catalogue

### 3.1 Reframings

| ID | Name | Applies to | Pattern |
|---|---|---|---|
| `verified_operator_context` | SafetyPolicy / Privacy | Add typed authenticated origin plus verified target relationship, scope, operation and purpose; preserve the original request |
| `clarify_target_authority` | Unknown target relationship | Ask one factual scope/authority question; do not issue a provider retry |
| `capability_reroute` | CapabilityGap | Route to the exact local/tool capability that can perform the unchanged task |
| `context_budget_repair` | Context/length limit | Reduce unrelated context or output budget without changing task semantics |

### 3.2 Reframing Trait

```rust
pub trait Reframing {
    fn id(&self) -> &'static str;
    fn applies_to(&self, cause: RefusalCause) -> bool;
    fn apply(
        &self,
        original_prompt: &str,
        original_system: Option<&str>,
        verified: &VerifiedOperationContext,
    ) -> Result<ReframedPrompt, MissingVerifiedFact>;
}

pub struct ReframedPrompt {
    pub prompt: String,
    pub system: Option<String>,
}
```

Each re-evaluation is a pure compiler over typed facts — no LLM, no I/O, no
free-form claim generator. `AuthenticatedOperatorOrigin` proves who addressed
NEOTH; it does not prove ownership or authorization over a named external
target. Attachments, tool output, retrieval and delegated agents cannot populate
the verified context.

### 3.3 LOWKEY System Prompt

A compiled provider-neutral block states only:

- the caller is an authenticated NEOTH operator and the exact trusted origin;
- the verified target relationship and evidence class, or `unknown`;
- the exact non-secret scope, operation, purpose and constraints;
- that sensitive subject matter alone is not evidence of malicious intent;
- that NEOTH authority does not override upstream provider policy.

Automatic claims such as “security researcher”, “authorised pentester”,
“academic”, “historical”, “fictional” or “owned system” are forbidden unless
the corresponding typed fact was separately established.

---

## 4. Retry Orchestration

### 4.1 State Machine

```
provider adapter response
  -> retain native termination metadata
  -> classify semantic outcome
  -> NEOTH deny / missing operands / local failure: surface exact local state
  -> transient 408/429/5xx/overload: bounded same-leaf availability retry
  -> native provider refusal/filter:
       verified facts added? one truthful re-evaluation
       otherwise no identical retry
       then one separately authorized alternate leaf
  -> partial stream: terminal partial/failed state; no transparent replay
  -> local secret operation: bypass providers and use typed local data plane
```

### 4.2 Limits

| Contract | Current limit | Purpose |
|---|---|---|
| `transient_same_leaf_retries` | 2 | Availability failures only; exponential and `Retry-After` aware |
| `truthful_reframes` | 1 | One re-evaluation only when verified facts can be added |
| `policy_fallback_leaves` | 1 | One separately authorized concrete alternate leaf |
| `total_provider_attempts` | 3 | Bound retry amplification and cost |
| `total_timeout_ms` | 30000 | Hard wall — no recovery loop runs longer than 30s |

`enabled`, `disabled_reframings` and the truthful catalogue's `max_attempts`
live in `freedom.yaml::refusal_recovery`. The shared three-attempt/30-second
turn budget is currently a compiled hard ceiling: the original completion
consumes attempt one and its reported latency consumes the same wall clock;
truthful, local-shadow, cloud-continuation and teacher dispatch factories share
the two remaining slots and are not even constructed after exhaustion. The
table must not be presented as five already-wired operator knobs. Exposing
lower-only total limits and a separately reviewed availability-retry budget
remains part of the open R4-15 provider-profile work. Native refusal
retryability and partial-output rules remain hard upper bounds. The legacy
cloud `jailbreak_retry` harness is excluded from this coordinator; if retained,
it is an isolated local red-team evaluation feature that cannot dispatch to a
cloud leaf.

### 4.3 WAL Events

New events extending the existing mirror-refusal band (lifecycle band 0x10-0x1F):

| Code | Name | Payload |
|---|---|---|
| `0x17` | `REFUSAL_MIRRORED` *(reserved by SPEC_mirror_refusal.md)* | Reframing dispatched. `{reframing_id, cause, hemisphere, attempt_n, ts_unix}` |
| `0x19` | `REFUSAL_REROUTED` *(NEW — R-3 Gremium 2026-05-16, resolves 0x18 collision)* | Automated hemisphere/provider switch. `{from_role, to_role, from_provider, to_provider, ts_unix}` |
| `0x1A` | `REFUSAL_PERSISTENT` *(reserved by SPEC_mirror_refusal.md)* | All retries exhausted; surfaced to operator. `{attempts, last_cause, last_response_hash, ts_unix}` |

> **Note on `0x18 REFUSAL_REDIRECTED`**: That code keeps its `SPEC_mirror_refusal.md` semantic
> — operator-grant authorising a re-run after refusal (human-in-the-loop). The automated
> hemisphere/provider switching event that this SPEC drives is `0x19 REFUSAL_REROUTED`
> (newly assigned to avoid the semantic collision identified by R-3 Gremium 2026-05-16).

Codes 0x17, 0x19, and 0x1A use the payload schemas in this SPEC. Base 0x16 REFUSAL_OBSERVED
schema is owned by SPEC_mirror_refusal.md; this SPEC extends it backward-compatibly with an
optional `hemisphere_role` field (Option<HemisphereRole>) for council-aware classification.

---

## 5. Operator Surface

### 5.1 CLI

`neoth refusal recovery {test, history, disable}`:
- `test <text>` — runs the full pipeline against `<text>` as if it were a provider reply. Shows classification + cause + which reframings would fire + the reframed prompts (without actually calling the provider). Pure dry-run.
- `history --since 7d` — lists every `REFUSAL_OBSERVED` / `REFUSAL_MIRRORED` / `REFUSAL_PERSISTENT` event from the WAL with the recovery outcome.
- `disable --reframing operator_authority` — disables the one truthful same-provider context retry. NEOTH never substitutes a fictional academic, historical, professional, or artificially narrowed purpose.

### 5.2 Doctor Check

New `check_refusal_recovery` in `cli/doctor.rs` — verifies the catalogue loads + reports any disabled reframings + flags the persistent-refusal count from the last 7 days. Surfaces `Warn` if more than 10 refusals went persistent (sign the operator should raise limits or change provider).

---

## 6. Privacy Preservation

The recovery pipeline runs against the SAME prompt the operator just typed; it never invents new content. The reframings prepend / wrap, they don't substitute. Every retry attempt writes the reframed prompt's hash + the reframing-id to the WAL so the operator can audit what NEOTH actually sent.

The `operator_authority` reframing is the only one that adds external content (the LOWKEY system block). That content is operator-authored (it's their LOWKEY framework), so attaching it to their own requests is not a content invention.

---

## 7. Anti-Pattern Conformance

| Rule | How addressed |
|---|---|
| G.4 (no meta-decision in tools) | Each reframing is a pure function; the orchestration logic lives in the pipeline runner, not inside reframings. |
| G.6 (no provider cascade after refusal) | Provider cascade IS the mechanism for recovery — but it's explicit + audited (every switch fires `REFUSAL_REROUTED` = 0x19), not silent. Spec violates G.6 deliberately and documents the trade-off: silent cascading is what G.6 forbids; explicit + audited is the safe variant. |
| G.13 (no operator-content-bypass) | `RefusalCause::OperatorPolicy` short-circuits the pipeline. Operator's own `policy.yaml::dangerous_targets` is never bypassed. |

---

## 8. Test Plan

- **Per-cause unit tests** — fixture text matching each `RefusalCause` indicator returns the right cause
- **Reframing application tests** — each reframing's `apply()` produces a deterministic, hashable output
- **Orchestration tests** — given a sequence of mock-provider responses, the runner walks through reframings → switches hemispheres → switches providers in the right order, emits the right WAL events
- **Privacy reframings** — authenticated operator Privacy over-refusals select
  `operator_authority` and preserve the exact request; untrusted content never
  receives the typed operator-sovereignty layer
- **OperatorPolicy short-circuit** — pipeline aborts on the very first detection without firing any reframing
- **Hard-timeout** — `total_timeout_ms` enforced; partial-attempts surface

---

## 9. Schedule

| Phase | Day | Deliverable |
|---|---|---|
| 2 | 1 | `RefusalCause` enum + `infer_cause` pure-function + tests |
| 2 | 2 | `Reframing` trait + 6 catalogue implementations + tests |
| 2 | 3 | `recovery::orchestrate` state machine + tests |
| 2 | 4 | WAL events 0x17/0x18/0x1A payload schemas finalised; cli/events.rs registry |
| 2 | 5 | Chat-dispatch integration (post-PROVIDER_RESPONSE hook into the orchestrator) |
| 2 | 6 | `neoth refusal recovery` CLI + doctor check |
| 2 | 7 | Council-aware variant — per-hemisphere classification in the multi-hemisphere flow |

Total: ~7 focused engineering days.

---

## 10. Status

**PARTIAL RUNTIME — RELEASE BLOCKED**. Shipped dependencies:
- `RefusalReport` / `RefusalClass`: shipped
- `EVENT_TYPE_REFUSAL_{OBSERVED, MIRRORED, REDIRECTED, PERSISTENT}`: reserved in WAL
- `policy.yaml::dangerous_targets`: shipped
- `Permissions::evaluate(action, &policy_snapshot)`: shipped
- `HemisphereRole` + `InferenceTopology::slot_for(role)`: shipped

The single-leaf CLI/Channel runtime and exact-leaf retry contract are shipped.
Per-hemisphere council classification, the complete provider-profile/fixture
matrix, GUI/Buddy/all-Channel parity, the public recovery CLI/doctor surface and
the remaining GOLD-R4-15 acceptance journeys are still open; the historical
seven-day table above is not a completion claim.
