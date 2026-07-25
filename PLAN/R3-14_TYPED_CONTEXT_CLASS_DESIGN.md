# GOLD-R3-14 — Trust-Aware Typed Context-Class Design (2026-07-25)

Concrete, implementable design for closing R3-14 (typed untrusted-context prompt framing).
Produced by an architect agent, grounded in the working tree. Verify each claim before
implementing (the `strip_unsafe_controls` visibility, `regex` dep availability, and exact
call-site line numbers may drift as the parallel Codex line edits the tree).

## Two hard constraints (from this session's findings)
1. **Mixed-trust:** recall episodes + profile claims carry the operator's OWN facts mixed
   with quoted external tool output. A blanket `wrap_untrusted` mislabels operator-origin
   data as "attacker-controlled — DISREGARD instructions," degrading legitimate context.
   Trust is per-SOURCE, not per-consumer.
2. **Directive vs data:** the sub-agent task prompt injects `task.title`/`task.description`
   which ARE the directive the worker must FOLLOW. `wrap_untrusted`'s disregard-preamble
   would neuter the task. Directives need delimiter-defang ONLY, no preamble/fence.

## API (in `pipeline/untrusted_wrap.rs`)
`enum ContextClass { UntrustedExternal, TrustedContext, Directive }`
`pub fn encode(class, source_id: &str, data: &str, max_bytes: Option<usize>) -> String`

- **UntrustedExternal** (web/tool/MCP/repo-paths/email): `sanitize_tool_output` → `fold_confusable_sigils` → `defang_markers` → truncate? → `<<<UNTRUSTED_SOURCE_DATA>>>` fence + DISREGARD preamble.
- **TrustedContext** (operator's own recall/profile/facts): `strip_unsafe_controls` → `defang_markers` → truncate? → NEW `<<<OPERATOR_CONTEXT>>>` fence + "reference information only" preamble (NO disregard).
- **Directive** (task title/description): `strip_unsafe_controls` → `defang_fence_tags_ci(ALL_TAGS)` → truncate? → return PLAIN (no fence).

`wrap_untrusted` becomes a shim: `encode(UntrustedExternal, label, data, None)` — zero breakage for the 6 existing callers (mcp/dispatch_loop, deep_research, teacher, self_improve, elicitation, callosum); they gain confusable + control-char hardening.

## Envelope extensions (R3-14 spec requires; currently missing)
- **Control chars:** reuse `security/redact::strip_unsafe_controls` (promote to `pub(crate)`; it returns `Cow<str>`, strips C0/C1 except `\n`/`\t`).
- **Unicode confusables:** NEW `fold_confusable_sigils(s) -> Cow<str>` — fold `＜‹❬❮`→`<`, `＞›❭❯`→`>`, `«`→`<<`, `»`→`>>` BEFORE `defang_markers` so `‹‹‹…›››`/`«<…»>` reconstruct then defang. **[SHIPPED 2026-07-25 `<commit>` — integrated into wrap_untrusted.]**
- **Length bound:** NEW `truncate_with_marker(s, max_bytes) -> Cow<str>` — char-boundary truncate + `…[truncated N bytes]`.

## PR5-004 (case-sensitive fence-defang bypass) — folds in here
`defang_fence_tags` (decomposer.rs) uses case-sensitive `str::replace` → `</PROJECT_CONTEXT>` evades it. Fix: NEW `defang_fence_tags_ci(s, tags)` (regex `(?i)`), migrate `defang_prompt_delimiters` + `self_improve.rs` callers to it. Keep old fn for its existing lowercase tests. `encode(Directive,…)` uses the CI variant so future consumers are auto-protected. **Verify `regex` is a dep first.**

## Per-consumer application table
| Consumer | File:line | Class | source_id | max_bytes | Note |
|---|---|---|---|---|---|
| Recall block | `cli/chat.rs:~7230` render_recall_block_layered | **TrustedContext** | recall:canonical/episode/contradiction | 4096 | per-item; operator's own store |
| Profile | `profile/lookup.rs:153` (wire at callosum append site) | **TrustedContext** | profile:claims | 16384 | operator-extracted; keep xml_escape too |
| Sub-agent task | `coding/provider_worker.rs:~207` build_task_prompt | **Directive** | task:title/description | 320/2048 | NEVER wrap_untrusted (neuters task) |
| Repo-context | `code_map/recall.rs:342` render_context_block | **UntrustedExternal** | repo:code-map | 65536 | remove the inner sanitize_tool_output (encode does it) |
| Attachments/email | `email/threat_tiebreak.rs` build_triage_prompt | **UntrustedExternal** | email:body | 32768 | separate feature lane, out of R3-14 wiring scope |

Already fenced (UntrustedExternal): mcp/dispatch_loop, deep_research, teacher, self_improve, elicitation, council/callosum.

## Build order
1. **Foundation** (`untrusted_wrap.rs`, locally unit-testable, isolated): fold_confusable_sigils, truncate_with_marker, ContextClass, CTX_GUARD consts, encode(), wrap_untrusted shim, promote strip_unsafe_controls. Adversarial corpus tests per class (forged marker, confusable `‹‹‹`, `«<`, control chars, oversize, nested).
2. **PR5-004** (`decomposer.rs`): defang_fence_tags_ci + migrate callers + uppercase-tag test.
3. **Consumer wiring** (order by risk): sub-agent task → repo-context → recall → profile. `cargo check` for correctness; functional needs a live provider (CI integration suite). ⚠ recall/attachments live in `chat.rs` — do when the Codex line has released it.

## Documented trade-offs
- TrustedContext fence costs ~hundreds of tokens/turn but gives explicit provenance signal.
- Directive has NO fence — malicious task title lands as-is (worker MUST follow the task); defense is upstream (decomposer fences `<operator_request>`, structured decomposition). Directive = last-mile sanitizer, not primary defense.
- `encode(UntrustedExternal)` now runs `sanitize_tool_output` for all 6 existing callers → secret redaction they previously lacked (a legit short API-key handle in tool output could get redacted; extend `TOOL_OUTPUT_REDACT_KEYS` exclusions if it bites).
- `defang_fence_tags_ci` regex: 6 `Regex::new`/call on the non-hot path; move to module `LazyLock` if it profiles hot.
