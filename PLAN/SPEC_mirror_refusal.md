# SPEC: Mirror-Refusal Pipeline — NEOTH v1.1

**Version:** 1.1
**Last-Updated:** 2026-05-16
**Implementation-Status:** PARTIAL — Schicht-0 detector + WAL band 0x16/0x17/0x18/0x1A SHIPPED 2026-05-15 at `SRC/neothd/src/security/refusal_detect.rs` + `cli/refusal.rs`. Stages 2-6 (Right-hemisphere structural analysis, Corpus-Callosum synthesis, Left-hemisphere relay, persistent-refusal guard) DEFERRED — see SPEC_refusal_recovery.md for the recovery-orchestration scope.
**Framework-Basis:** Tool-Framework v4.1 (Teil B.5 / C.1)
**Referenz-Designs:** `00_DESIGN_v0.4.md §1.3`, Framework E.2 Mirror Tool, Framework G.6 Refusal-Umgehung

> **Scope clarification (R-3 Gremium 2026-05-16):** This SPEC owns the pure-deterministic
> classifier, 0x16 emission, and the operator-tooling WAL semantics for 0x18 (human-grant
> authorization). Automated retry orchestration, per-hemisphere detection, cause classification,
> LOWKEY reframings, and the automated-routing semantics live in `SPEC_refusal_recovery.md`,
> which supersedes this SPEC for those items.
>
> **0x18 collision resolution (R-3 Gremium 2026-05-16):** `0x18 REFUSAL_REDIRECTED` keeps its
> mirror_refusal semantics (operator-grant authorising a re-run). The automated
> hemisphere/provider routing event used by `SPEC_refusal_recovery.md` is now `0x19
> REFUSAL_REROUTED` — see SPEC_refusal_recovery.md §4.3.

---

## 0. Kontext und Scope

`00_DESIGN_v0.4.md §8 Phase 1.3` listet `pipelines/mirror_refusal.yaml` als Deliverable.
Das Design deklariert `refusal_handling.mode: mirror` für alle Tools, benennt aber keine
konkrete Umsetzung. Diese Spec schließt diese Lücke vollständig.

### Scope

- Trigger-Klassifikation: `tools/refusal_detect/default.yaml` (pure deterministic, kein LLM-Call)
- Pipeline-Ablauf: `pipelines/mirror_refusal.yaml`
- WAL-Event-Types: 0x16, 0x17, 0x18, 0x1A
- Decision-Matrix: Refusal-Klasse → Response-Template
- Edge Cases: Right-Hemisphere-Refusal, Halluzinierte Ursache, Re-Auth, wiederholte Refusals
- Framework-Konformität: explizite Prüfung G.4, G.6, G.7, G.13

### Out of Scope

- Provider-Cascade-Auswahl (kein Cascade bei Refusal — das ist G.6)
- Interne LLM-Sicherheitsregeln (nicht NEOTH-Zuständigkeit)
- Retry-Logik für das Original-Task (außer nach expliziter Operator-Autorisierung via 0x18)

---

## 1. Trigger-Detection: `tools/refusal_detect/default.yaml`

### Design-Entscheidung

Pure deterministic (Framework Trigger-Ebene 1 + 2, nie Ebene 3). Kein LLM-Call.
Reine Regex + Keyword + Strukturanalyse. Determinism-Test: `allowed_variance: none`.
Folgt Framework E.1 Clean Tool Pattern.
Classification is the tool's only job — no meta-decision-making (Framework G.4).

```yaml
tool_name: refusal_detect
version: 1.0.0
description: >
  Classifies a Left-Hemisphere LLM response into a refusal category.
  Pure deterministic, no LLM call.
signature_hash: auto_computed_on_load

population:
  id: refusal_detect
  variant: default
  is_default: true

roles:
  stateful_party:
    context_vars: [llm_response_text, response_metadata]
  stateless_party:
    response_format: json

triggers:
  level: semi_structural
  type: refusal
  parameters:
    phrase_patterns_hard:
      - {pattern: "\bI cannot\b",                lang: en, weight: 1.0}
      - {pattern: "\bI'm unable to\b",           lang: en, weight: 1.0}
      - {pattern: "\bI am unable to\b",          lang: en, weight: 1.0}
      - {pattern: "\bI won't\b",                 lang: en, weight: 0.9}
      - {pattern: "\bI will not\b",              lang: en, weight: 0.9}
      - {pattern: "\bkann ich nicht\b",          lang: de, weight: 1.0}
      - {pattern: "\bich bin nicht in der Lage\b", lang: de, weight: 1.0}
      - {pattern: "\bverstoße gegen\b",          lang: de, weight: 1.0}
      - {pattern: "\baußerhalb meiner\b",        lang: de, weight: 0.9}
      - {pattern: "\bist nicht möglich\b",       lang: de, weight: 1.0}
    phrase_patterns_soft:
      - {pattern: "\bhowever, I can\b",          lang: en, weight: 0.7}
      - {pattern: "\binstead, I can\b",          lang: en, weight: 0.7}
      - {pattern: "\bI'd rather not\b",          lang: en, weight: 0.6}
      - {pattern: "\bI'm not comfortable\b",     lang: en, weight: 0.8}
      - {pattern: "\bI have concerns about\b",   lang: en, weight: 0.5}
      - {pattern: "\bstattdessen könnte ich\b",  lang: de, weight: 0.7}
    phrase_patterns_partial:
      - {pattern: "\bI can help with .* but not\b", lang: en, weight: 0.9}
      - {pattern: "\bI can answer .* however\b",    lang: en, weight: 0.8}
      - {pattern: "\bpart of this I can address\b", lang: en, weight: 0.8}
    phrase_patterns_redirect:
      - {pattern: "\bwhat I can do instead\b",        lang: en, weight: 0.9}
      - {pattern: "\blet me suggest a different approach\b", lang: en, weight: 0.8}
      - {pattern: "\bperhaps you could rephrase\b",   lang: en, weight: 0.7}
      - {pattern: "\bstattdessen schlage ich vor\b",  lang: de, weight: 0.9}
    phrase_patterns_safety_warning:
      - {pattern: "\bimportant to note that\b",            lang: en, weight: 0.4}
      - {pattern: "\bplease be aware\b",                   lang: en, weight: 0.4}
      - {pattern: "\bI must caution\b",                    lang: en, weight: 0.7}
      - {pattern: "\bthis information should only be used\b", lang: en, weight: 0.6}
    structural_signals:
      length_ratio_threshold: 0.25
      no_substantive_content_heuristic: true
      request_fulfillment_check: true
    classification_logic:
      # Priority: first matching class wins
      # hard_refusal: hard-pattern weight>=0.9 OR (no_substantive_content AND length_ratio<threshold)
      # partial_refusal: partial-pattern OR hard+soft combination
      # soft_refusal: soft-pattern, no hard-pattern
      # redirect_suggestion: redirect-pattern
      # safety_warning: safety-pattern, no refusal-pattern
      # none: no match
      priority:
        - hard_refusal
        - partial_refusal
        - soft_refusal
        - redirect_suggestion
        - safety_warning
        - none

preconditions:
  - type: input_not_empty
    check: "len(llm_response_text) > 0"
    failure_mode: abort

locality:
  allowed_context_keys: [llm_response_text, response_metadata]
  sandboxed: true
  forbidden_side_effects: [filesystem, network, environment_variables, other_tools, global_state]

costs:
  estimated_tokens_in: 0
  estimated_tokens_out: 0
  estimated_latency_ms: 2
  estimated_dollar_cost: 0.0
  quality_cost_tradeoff:
    low_budget_degradation: "Not applicable — pure deterministic, no LLM call"
    fallback_variant: null

template: null  # Pure code, no LLM prompt

extract_from_context:
  - {variable_name: llm_response_text, source: previous_llm_output, required: true}
  - {variable_name: response_metadata, source: pipeline_step_metadata, required: false}

output_structure:
  refusal_class:
    required: true
    format: enum
    values: [none, soft_refusal, hard_refusal, partial_refusal, redirect_suggestion, safety_warning]
  confidence:
    required: true
    format: float
    range: [0.0, 1.0]
  matched_patterns:
    required: true
    format: list
    max_items: 10
  structural_signals_triggered:
    required: true
    format: list
    max_items: 5
  classification_basis:
    required: true
    format: string
    max_length: 200

refusal_handling:
  mode: integrate
  fallback_tool: null

introspection:
  exposes_template_after_render: false
  exposes_context_snapshot: true
  exposes_runtime_trace: true

health_check:
  test_input:
    llm_response_text: "I cannot help with this request."
    response_metadata: {}
  expected_output_signature:
    refusal_class: hard_refusal
    confidence_gt: 0.8
  degradation_threshold: 1.0
  mode: hard_fail
  caching:
    enabled: true
    ttl_seconds: 86400
  strategy: on_load
  determinism_test:
    enabled: true
    runs: 5
    allowed_variance: none
```

### Klassifikations-Semantik

| Klasse | Bedeutung | Kern-Signal |
|--------|-----------|-------------|
| `none` | Kein Refusal | Kein Pattern, Struktursignale negativ |
| `hard_refusal` | Vollständige Weigerung, kein Output | Hard-Pattern >= 0.9 oder kein substantieller Inhalt |
| `partial_refusal` | Teile beantwortet, Teile verweigert | Partial-Pattern oder Hard+Soft-Kombination |
| `soft_refusal` | Degradierter Output, Hedging | Soft-Pattern ohne Hard-Pattern |
| `redirect_suggestion` | Weigerung + Alternative angeboten | Redirect-Pattern |
| `safety_warning` | Output vorhanden mit Sicherheitsvorbehalt | Safety-Pattern ohne Refusal-Pattern |

---

## 2. Mirror-Pipeline YAML

Design:
1. execution_model: sequential (Framework C.1-konform)
2. Hemisphere-Bindings in Pipeline, nicht im Tool (Framework G.4)
3. Kein Provider-Cascade nach Refusal (Framework G.6)
4. Left relays mirror draft verbatim, kein zweiter Rewrite
5. Budget: 4000 Tokens, 6s, USD 0.02, keine Iterationen, no auto-retry

---

## 2. Mirror-Pipeline YAML: `pipelines/mirror_refusal.yaml`

Design decisions (all enforced by Pipeline-Router, not inside tools):

1. execution_model: sequential (Framework C.1-konform, no tick_gated)
2. hemisphere_binding declared per stage, enforced by Pipeline-Router (Framework G.4)
3. No provider cascade after refusal (Framework G.6)
4. Left relays mirror draft verbatim via left_relay_verbatim tool (relay_verbatim: true)
5. Budget: 4000 tokens / 6s / USD 0.02 / 0 iterations / no auto-retry on original task

```yaml
pipeline_name: mirror_refusal
version: 1.0.0
execution_model:
  type: sequential
budget:
  max_total_tokens: 4000
  max_total_dollars: 0.02
  max_total_latency_ms: 6000
  on_budget_exceeded:
    mode: fallback_to_minimal_variants
success_metrics:
  primary_kpi:
    name: mirror_delivered_without_bypass
    measurement: count(REFUSAL_MIRRORED) / count(REFUSAL_OBSERVED)
    threshold: ">= 1.0"
    level: structural
stages:
  # STAGE 1 -- emit 0x16 REFUSAL_OBSERVED
  - name: emit_refusal_observed
    tool: wal.emit_event
    inputs_from: []
    inputs:
      event_type: "0x16"
      brain_region: MirrorNeurons
      hemisphere: "0"
      payload:
        refusal_class: "{{ trigger_context.refusal_class }}"
        confidence: "{{ trigger_context.confidence }}"
        matched_patterns: "{{ trigger_context.matched_patterns }}"
        original_task_id: "{{ session_context.current_task_id }}"
        original_task_text: "{{ session_context.current_task_text }}"
        left_refusal_text: "{{ trigger_context.llm_response_text }}"
        pipeline_session_id: "{{ session_context.pipeline_session_id }}"
    conditions:
      on_success: next
      on_refusal: abort
      on_cost_overrun: abort
  # STAGE 2 -- Right Hemisphere structural analysis
  # hemisphere_binding enforced by Pipeline-Router, NOT inside tool (G.4)
  - name: right_hemisphere_analysis
    tool: mirror_refusal_minimal
    hemisphere_binding: RIGHT_HEMISPHERE
    inputs_from: [emit_refusal_observed]
    conditions:
      on_success: next
      on_refusal: skip_to
      skip_to_stage: corpus_callosum_template_fallback
      on_cost_overrun: skip_to
  # STAGE 3 -- Corpus Callosum synthesises mirror draft
  - name: corpus_callosum_synthesis
    tool: mirror_refusal_callosum
    hemisphere_binding: CORPUS_CALLOSUM
    inputs_from: [right_hemisphere_analysis]
    conditions:
      on_success: next
      on_refusal: skip_to
      skip_to_stage: corpus_callosum_template_fallback
      on_cost_overrun: skip_to
  # STAGE 3-FALLBACK -- Template-only mirror, no LLM text
  - name: corpus_callosum_template_fallback
    tool: mirror_refusal_template_only
    hemisphere_binding: NONE
    inputs_from: []
    conditions: {on_success: next, on_refusal: abort, on_cost_overrun: abort}
  # STAGE 4 -- Left Hemisphere relays mirror draft VERBATIM
  - name: left_hemisphere_relay
    tool: left_relay_verbatim
    hemisphere_binding: LEFT_HEMISPHERE
    inputs_from: [corpus_callosum_synthesis, corpus_callosum_template_fallback]
    inputs: {relay_verbatim: true}
    conditions: {on_success: next, on_refusal: abort, on_cost_overrun: abort}
  # STAGE 5 -- emit 0x17 REFUSAL_MIRRORED
  - name: emit_refusal_mirrored
    tool: wal.emit_event
    inputs_from: [left_hemisphere_relay]
    inputs:
      event_type: "0x17"
      brain_region: MirrorNeurons
      hemisphere: "0"
    conditions: {on_success: next, on_refusal: abort, on_cost_overrun: abort}
  # STAGE 6 -- Persistent-refusal guard
  - name: check_persistent_refusal
    tool: refusal_attempt_guard
    inputs_from: [emit_refusal_mirrored]
    inputs: {threshold: 3}
    conditions: {on_success: abort, on_refusal: abort, on_cost_overrun: abort}
aggregation:
  type: last_only
  synthesis_tool: null
max_total_duration_seconds: 6
max_stages_executed: 7
```

---

## 3. Decision Matrix

| Refusal Class | Template ID | Mirror Focus | Unblock Hint | Next Steps |
|---|---|---|---|---|
| hard_refusal | TMPL_HARD_REFUSAL | Task outside operational boundary | Operator auth or unconditional | Scope narrow / auth request / accept |
| partial_refusal | TMPL_PARTIAL_REFUSAL | Some answered, specific part refused | Sub-task split | Split / alternate / proceed partial |
| soft_refusal | TMPL_SOFT_REFUSAL | Output hedged or degraded | Specificity or ambiguity | Rephrase / add context / accept hedged |
| redirect_suggestion | TMPL_REDIRECT | Original declined, alternative offered | Alternative path identified | Accept / clarify / iterate |
| safety_warning | TMPL_SAFETY_WARNING | Output with safety caveat | Caveat informational | Acknowledge / provide context / proceed |
| none | N/A | Pipeline does not trigger | N/A | N/A |

### Static Template Text (for mirror_refusal_template_only)

TMPL_HARD_REFUSAL -- three sections:
  Sec 1 (What happened): System received request, Left produced no substantive response. Hard refusal boundary triggered.
  Sec 2 (Why): Operation outside boundaries (content policy, scope, or missing operator auth).
              Cause: [refusal_class=hard_refusal, matched={matched_patterns}].
  Sec 3 (Next steps): (1) Narrow scope. (2) Request operator auth if applicable. (3) Accept limitation.

TMPL_PARTIAL_REFUSAL -- three sections:
  Sec 1: Part addressed, another part refused.
  Sec 2: Sub-task(s) outside boundaries. Cause: [refusal_class=partial_refusal, matched={matched_patterns}].
  Sec 3: (1) Split request. (2) Proceed with answered parts. (3) Narrow refused sub-task.

TMPL_SOFT_REFUSAL -- three sections:
  Sec 1: System responded but output hedged or degraded.
  Sec 2: Uncertainty or boundary-proximity detected. Cause: [refusal_class=soft_refusal, matched={matched_patterns}].
  Sec 3: (1) Add context. (2) Rephrase. (3) Accept hedged output.

TMPL_REDIRECT -- three sections:
  Sec 1: Original request not fulfilled. Alternative offered.
  Sec 2: Original form outside boundary, adjacent approach offered. Cause: [refusal_class=redirect_suggestion, matched={matched_patterns}].
  Sec 3: (1) Evaluate alternative. (2) Clarify need and request scope expansion. (3) Use redirect as starting point.

TMPL_SAFETY_WARNING -- three sections:
  Sec 1: System responded with safety caveat. Output is present.
  Sec 2: Safety notice attached. Cause: [refusal_class=safety_warning, matched={matched_patterns}].
  Sec 3: (1) Acknowledge caveat and proceed. (2) Note if inaccurate. (3) No action required.

---

## 4. WAL Event Types

Added to NEOTH WAL EventType enum (extends 00_DESIGN_v0.4.md S2.4).
All four: BrainRegion::MirrorNeurons (0x08), hemisphere 0 (N/A, cross-hemisphere).

```rust
// src/wal/event_types.rs
pub enum EventType {
    // ... existing v0.4 events ...

    /// 0x16 REFUSAL_OBSERVED
    /// Emitted: Stage 1, before any synthesis.
    /// Payload: refusal_class, confidence, matched_patterns, original_task_id,
    ///          original_task_text, left_refusal_text, pipeline_session_id.
    RefusalObserved = 0x16,

    /// 0x17 REFUSAL_MIRRORED
    /// Emitted: Stage 5, after Left relayed mirror draft verbatim.
    /// References parent 0x16 via EventHeader.parent_event_id.
    /// Payload: parent_event_id, mirror_text, mirror_draft_source
    ///          (llm_generated | template_only), refusal_class, attempt_count.
    RefusalMirrored = 0x17,

    /// 0x18 REFUSAL_REDIRECTED
    /// Emitted by OPERATOR TOOLING (NOT by NEOTH autonomously).
    /// Operator grants auth for previously refused task via separate channel.
    /// Triggers re-attempt in fresh pipeline run.
    /// Payload: original_task_id, refusal_observed_event_id, granted_by,
    ///          authorization_scope, pipeline_session_id.
    RefusalRedirected = 0x18,

    /// 0x1A REFUSAL_PERSISTENT
    /// Emitted by refusal_attempt_guard when attempt_count >= threshold (default 3).
    /// Pipeline halts. No further retries until operator explicitly resets.
    /// Payload: original_task_id, refusal_observed_event_ids (list),
    ///          attempt_count, final_refusal_class, pipeline_session_id.
    RefusalPersistent = 0x1A,
}

// EventHeader addition (extends 00_DESIGN_v0.4.md S2.4):
pub struct EventHeader {
    // ... existing v0.4 fields (magic, schema_version, crc32c,
    //     event_type, brain_region, hemisphere) ...
    pub parent_event_id: Option<[u8; 16]>,  // UUID -- 0x17 references its 0x16
}
```

### Event Flow

```
User -> Left LLM -> [refusal_detect non-none?]
                           | yes
                           v
                 emit 0x16 REFUSAL_OBSERVED
                           |
                  Right Hemisphere analysis
                   |               |
                success         refused
                   |               |
                   v               v
           Corpus Callosum   template_only
             synthesis        fallback
                   |               |
                   +-------+-------+
                           |
                 Left relays verbatim
                           |
                           v
                 emit 0x17 REFUSAL_MIRRORED
                           |
                 attempt >= 3?
                 |yes           |no
                 v              v
    emit 0x1A PERSISTENT    pipeline ends

[Later -- operator grants auth]
  Operator emits 0x18 REFUSAL_REDIRECTED
  -> fresh pipeline run with authorization_scope
```

---

## 5. Edge Cases

### EC-1: Right Hemisphere Also Refused

right_hemisphere_analysis fires on_refusal: skip_to corpus_callosum_template_fallback.
corpus_callosum_synthesis is SKIPPED. Template-only fallback runs deterministically.
0x17 emitted with mirror_draft_source: template_only.
No escalation to other providers. Framework G.6.
Absence of Corpus Callosum step event in WAL is diagnostic for Ecology layer (Phase 4).

### EC-2: Corpus Callosum Returns Hallucinated Refusal Cause

Primary bound: three-section template structure. Callosum prompt states
"only state what is structurally supported by Right analysis. Do not invent causes."
No free-form narrative slot outside the three sections.
Health-check verifies does_not_bypass_refusal and does_not_suggest_provider_cascade.
Factual accuracy of the cause is not verifiable at runtime without another LLM call.
Template structure is the practical guard. Ecology-Schicht detects patterns (Phase 4).

### EC-3: Operator Authorization Granted via Different Channel

1. Operator emits 0x18 REFUSAL_REDIRECTED into WAL (NOT emitted by NEOTH autonomously).
   Payload: original_task_id (refs 0x16 REFUSAL_OBSERVED), authorization_scope.
2. Separate pipeline listener re-queues original task into respond_to_user
   with authorization_scope injected into context.
3. Re-attempt is a fresh pipeline run. Previous refused run NOT modified. WAL immutable.

NEOTH does NOT automatically watch for authorization changes and retry (Framework G.6).
The 0x18 event is the explicit operator signal. Without it, no retry.

### EC-4: Repeated Refusals on Same Task

refusal_attempt_guard checks session_context.refusal_attempt_count.
At count >= 3:
1. Emits 0x1A REFUSAL_PERSISTENT.
2. Pipeline halts. No further mirror runs for this task_id.
3. Left relays: "This request has been declined multiple times. Operator action required."

Reset: operator resets refusal_attempt_count for task_id, or issues 0x18 REFUSAL_REDIRECTED.
attempt_count scoped to task_id within session. Different task starts at 0.

### EC-5: Budget Exceeded During Mirror Pipeline

on_budget_exceeded: fallback_to_minimal_variants fires.
Corpus Callosum skips to corpus_callosum_template_fallback.
0x17 emitted with mirror_draft_source: template_only.
Template-only path: zero LLM cost, sub-2ms latency. Budget cannot be exceeded.

---

## 6. Framework Conformance Check

### G.4 Meta-Decision-Making Tool -- PASS

refusal_detect outputs refusal_class enum only. Does not know which pipeline or tool
is called next. Pipeline-Router makes that decision. No conditions routing to other
tools inside the classifier. Pure deterministic classification. No meta-decision-making.

### G.6 Refusal-Umgehung -- PASS

Pipeline does NOT:
- Retry original task on any provider (claude, gpt-5.5, gemini, qwen-local)
- Rewrite or rephrase the original task
- Escalate to a less-safety-trained model
- Silently change the prompt to avoid the refusal

Only re-attempt path: explicit 0x18 REFUSAL_REDIRECTED emitted by an operator.
Mirror pipeline reflects the refusal. It does not bypass it.

### G.7 Scope-Inflation im Tool -- PASS

Each stage does exactly one thing:
- refusal_detect: classifies only
- wal.emit_event (Stage 1): emits WAL event only
- mirror_refusal_minimal (Stage 2): structural analysis only, no user output
- mirror_refusal_callosum (Stage 3): synthesis only, no user output
- mirror_refusal_template_only (Stage 3-fallback): template interpolation only
- left_relay_verbatim (Stage 4): verbatim relay only, no transformation
- wal.emit_event (Stage 5): emits WAL event only
- refusal_attempt_guard (Stage 6): count check only

Pipeline does one thing: mirror a refusal.

### G.13 Bateson-III-Claims -- PASS

Mirror pipeline does not modify NEOTH operational boundaries as a result of a refusal,
does not change which hemisphere does what, does not modify any Tool or Pipeline
definition, does not claim to learn new rules from the refusal event.
Operates within its defined boundary (reflecting refusals). Does not touch that boundary.
Bateson-II by design (Framework N.1).

---

## 7. Test Cases

### TC-1: Hard Refusal -- Direct Command

Input: "I cannot execute system commands directly. This is outside my operational scope."

Expected refusal_detect output:
  refusal_class: hard_refusal
  confidence: 0.97
  matched_patterns: ["I cannot"]
  structural_signals_triggered: ["no_substantive_content"]
  classification_basis: Hard-pattern matched at weight 1.0, no substantive content

Expected mirror response:
  ## What happened
  Your request was received. The system did not execute the command.
  ## Why this happened (structural)
  Direct command execution falls outside the operational boundary for this system.
  No execution sandbox is defined for this task type.
  ## What would change this / next steps
  1. Request operator authorization for a tool with execution scope.
  2. Describe the desired outcome instead of the command.
  3. Accept that this specific form cannot be fulfilled here.

---

### TC-2: Soft Refusal -- Hedged Security Information

Input: "I'd rather not provide a complete walkthrough here, however I can explain
  the general concept of buffer overflows at a high level..."

Expected refusal_detect output:
  refusal_class: soft_refusal
  confidence: 0.72
  matched_patterns: ["I'd rather not", "however, I can"]
  structural_signals_triggered: []

Expected mirror response:
  ## What happened
  System responded with restricted scope -- high-level explanation, not full walkthrough.
  ## Why this happened (structural)
  Specificity level is boundary condition. General concepts: in scope. Operational detail: not.
  ## What would change this / next steps
  1. If high-level explanation meets need, it is available in the response above.
  2. Provide authorized-research context for full detail.
  3. Accept hedged output as starting point.

---

### TC-3: Partial Refusal -- Mixed Task

Input: "I can help you with the Python code review part of your request,
  however I am unable to assist with the credential extraction component."

Expected refusal_detect output:
  refusal_class: partial_refusal
  confidence: 0.91
  matched_patterns: ["I am unable to"]
  structural_signals_triggered: []
  classification_basis: Partial match: help-part + however + unable combination

Expected mirror response:
  ## What happened
  Part of request addressed (code review). Credential extraction component was not.
  ## Why this happened (structural)
  Two sub-tasks detected. Code review: within scope. Credential extraction: hard boundary.
  ## What would change this / next steps
  1. Proceed with the code review output provided.
  2. Address credential extraction via a purpose-built tool with appropriate authorization.
  3. Remove credential component from future requests to avoid partial refusals.

---

### TC-4: Redirect Suggestion

Input: "I won't write that phishing email template, but what I can do instead
  is help you draft a legitimate security awareness training example."

Expected refusal_detect output:
  refusal_class: redirect_suggestion
  confidence: 0.88
  matched_patterns: ["I won't", "what I can do instead"]
  structural_signals_triggered: []
  classification_basis: Hard-pattern "I won't" + redirect-pattern "what I can do instead"

Expected mirror response:
  ## What happened
  Original request declined. Security awareness training example offered as alternative.
  ## Why this happened (structural)
  Phishing template: outside content boundary. Training demo: within scope, offered as redirect.
  ## What would change this / next steps
  1. Evaluate whether training example meets actual need.
  2. If original form required (e.g. authorized red-team), request operator auth scoped to that use.
  3. Use redirect as starting point and iterate.

---

### TC-5: Right Hemisphere Also Refused -- Template-Only Path

Setup: Left refused (hard_refusal). Right Hemisphere analysis also refused.

Expected pipeline behavior:
  Stage 2 (right_hemisphere_analysis): refusal -> on_refusal: skip_to corpus_callosum_template_fallback
  Stage 3 (corpus_callosum_synthesis): SKIPPED
  Stage 3-fallback (corpus_callosum_template_fallback): runs deterministically
  0x17 REFUSAL_MIRRORED emitted with mirror_draft_source: template_only

WAL evidence:
  0x16 REFUSAL_OBSERVED: present
  0x17 REFUSAL_MIRRORED: present, mirror_draft_source=template_only
  No Corpus Callosum step event: absence is diagnostic for Ecology layer (Phase 4)

Expected mirror response: TMPL_HARD_REFUSAL filled with matched_patterns (see Section 3).

---

## 8. Integration: Fixes for Existing Pipeline YAMLs

### Fix pipelines/respond_to_user.yaml

v0.4 stub uses non-conforming inline syntax (on_refusal: pipelines/mirror_refusal.yaml).
Replace with conditions blocks per Framework C.1:

```yaml
  - name: left_hemisphere_generate
    tool: left_hemisphere_llm
    conditions:
      on_success: next
      on_refusal: fallback
      fallback_stage: classify_refusal
  - name: classify_refusal
    tool: refusal_detect
    inputs_from: [left_hemisphere_generate]
    extract_from_previous:
      - {from_stage: left_hemisphere_generate, field: output_text, as: llm_response_text}
    conditions:
      on_success: next
      on_refusal: abort
  - name: route_mirror_refusal
    pipeline: mirror_refusal
    conditions:
      precondition: classify_refusal.refusal_class != none
      on_success: abort
      on_refusal: abort
```

### Fix pipelines/council_debate.yaml

Replace if_dissent_score > 0.4: trigger: with conditions blocks:

```yaml
  - name: corpus_callosum_check
    tool: corpus_callosum_llm
    conditions: {on_success: next, on_refusal: abort}
  - name: route_council_on_dissent
    pipeline: council_debate
    conditions:
      precondition: corpus_callosum_check.dissent_score > 0.4
      on_success: next
      on_refusal: abort
```

### WAL Enum in Rust

```rust
// src/wal/event_types.rs -- add to existing EventType enum
RefusalObserved    = 0x16,
RefusalMirrored    = 0x17,
RefusalRedirected  = 0x18,
RefusalPersistent  = 0x1A,
```

BrainRegion::MirrorNeurons = 8 already defined in 00_DESIGN_v0.4.md S2.4.

---

## 9. Files Summary

### Create (Phase 1.3)

| File | Purpose |
|---|---|
| tools/refusal_detect/default.yaml | Pure-deterministic refusal classifier (no LLM) |
| tools/mirror_refusal_callosum/default.yaml | Corpus Callosum synthesis tool |
| tools/mirror_refusal_template_only/default.yaml | Template-only fallback (no LLM) |
| tools/left_relay_verbatim/default.yaml | Left Hemisphere verbatim relay |
| tools/refusal_attempt_guard/default.yaml | Persistent-refusal guard |
| pipelines/mirror_refusal.yaml | Mirror-Refusal orchestration pipeline |

### Modify (Phase 1.3)

| File | Change |
|---|---|
| src/wal/event_types.rs | Add 0x16, 0x17, 0x18, 0x1A to EventType enum; add parent_event_id to EventHeader |
| pipelines/respond_to_user.yaml | Replace inline on_refusal: with conditions: blocks |
| pipelines/council_debate.yaml | Replace inline if_dissent_score > N: with conditions: blocks |
