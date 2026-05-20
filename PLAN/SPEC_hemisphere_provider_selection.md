# SPEC: Per-Hemisphere Provider Selection — Wizard + Switching

> Status: BUILD-READY (planning)
> Phase: 2 (extends `config/inference.rs::InferenceTopology` which already supports per-hemisphere config)
> Trigger: Alex 2026-05-16 — "Llm auswahl peovider pro hemisphäre (3 stück - auswahl ausgängigen providern)"

---

## 0. Scope

NEOTH already has the data model for per-hemisphere provider selection. `InferenceTopology::{left, right, cerebellum}: HemisphereSlot` exists; `HemisphereSlot::{provider, model, key, endpoint}` exists. What's missing is the operator UX to set them — the wizard only fills `default_slot` today.

This spec closes that gap with:
1. **Wizard step 5d** — three sequential provider pickers (left/right/cerebellum), each surfacing the 8 available `InferenceProvider` variants with their description.
2. **`neoth hemispheres` CLI** — show current per-hemisphere assignment + reassign without re-running the full wizard.
3. **GUI screen** — Slint panel mirroring the wizard step for post-onboarding edits.

---

## 1. Hemisphere Role Semantics

Existing semantics (from `config/inference.rs` docstring):
- **Left hemisphere** — analytic / structured reasoning. Code review, math, deductive arguments.
- **Right hemisphere** — creative / freeform generation. Drafting, brainstorming, mirror-refusal reframings.
- **Cerebellum** — fast pattern matching for routing + summaries. Skill routing (Stage-2 router), short Acks, context-block summarisation.

This spec adopts those roles verbatim — no semantic change.

---

## 2. Available Backends per Role

The wizard surfaces the same 8 `InferenceProvider` variants for all three roles, but with **per-role recommendations** based on what each role needs:

| Role | Recommended primary | Recommended fallback | Reasoning |
|------|---------------------|----------------------|-----------|
| Left | `claude_cli` | `openai_api` | Strong structured reasoning + tool use |
| Right | `gemini_api` | `claude_cli` | Strong creative + multilingual freeform |
| Cerebellum | `local_qwen` (or `openai_compat` → LM Studio) | `openai_api` | Fast + cheap; perfect-quality not required for routing |

Recommendations are *displayed* in the wizard but **never enforced** — operator can pick any provider for any role.

---

## 3. Wizard Step 5d

```
┌──────────────────────────────────────────────┐
│ Step 5d — Hemisphere Providers              │
├──────────────────────────────────────────────┤
│ NEOTH routes different tasks to different    │
│ LLMs. Pick a provider for each role:        │
│                                              │
│ ── Left hemisphere (analytic) ──             │
│   ⊙ claude_cli  (recommended)               │
│   ○ anthropic_api                            │
│   ○ openai_api                               │
│   ○ openai_compat                            │
│   ○ gemini_api                               │
│   ○ local_qwen                               │
│   ○ hermes [stub]                            │
│   ○ openclaw [stub]                          │
│                                              │
│ ── Right hemisphere (creative) ──            │
│   ⊙ gemini_api  (recommended)               │
│   ○ ... (same list)                          │
│                                              │
│ ── Cerebellum (router) ──                    │
│   ⊙ local_qwen  (recommended)               │
│   ○ ... (same list)                          │
│                                              │
│  [Use same provider for all three (Single)]  │
│                                              │
│             [ Back ]   [ Next ]              │
└──────────────────────────────────────────────┘
```

A "Use same provider for all three" toggle at the bottom collapses to the existing Single mode — operators who don't care about hemisphere differentiation skip per-role complexity.

When a per-role provider needs an API key or endpoint, the wizard chains a credentials sub-prompt (re-using `wizard::secret_prompt` from existing step5).

---

## 4. CLI: `neoth hemispheres`

```
neoth hemispheres show
  Left:        claude_cli  model=claude-opus-4-7
  Right:       gemini_api  model=gemini-2.5-pro
  Cerebellum:  local_qwen  model=Qwen/Qwen2.5-3B-Instruct

neoth hemispheres set --role left --provider openai_api --model gpt-4o --key-env OPENAI_API_KEY
  ✓ Updated freedom.yaml::inference.left
  ✓ Audit frame written (0x1F LEVEL_PROVIDER_REBOUND)

neoth hemispheres test --role cerebellum
  ✓ Provider local_qwen reachable; round-trip 234ms; produced 12 tokens
```

`set` is atomic — writes to `<freedom>.tmp` + rename + chmod 0600, same as `cli::init` paths.

`test` runs a one-shot "ping" prompt through the configured provider for that role and reports latency + bytes. Useful sanity check after a rebind.

---

## 5. Routing Today vs After

**Today** (`InferenceTopology::slot_for(role)`): returns `default_slot` in Single mode; in Triplet/Custom it returns the per-slot override or falls back to default. Already wired in `providers::from_config_for_role`.

**After this spec**: same routing function; the *config inputs* are richer because the wizard actually populates them. Zero code change in the dispatcher — pure UX shipment.

---

## 6. Hemisphere-Aware Provider Construction

`providers::from_config` already builds a single provider. For per-hemisphere routing the daemon needs `providers::from_config_for_role(config, role)` — already a `pub fn` skeleton in mod.rs but currently delegates to the single path.

This spec finalises that:

```rust
pub async fn from_config_for_role(
    config: &FreedomConfig,
    role: HemisphereRole,
) -> Result<Box<dyn Provider>> {
    let slot = config.inference.slot_for(role);
    match slot.provider {
        Some(InferenceProvider::ClaudeCli) => ...,
        Some(InferenceProvider::OpenAi) => ...,
        ...
        None => from_config(config).await,  // fall back to single-mode provider
    }
}
```

Chat dispatch, council runner, and the skill router all migrate to call `from_config_for_role` with their respective roles. Today they all call `from_config` and get the default slot.

---

## 7. Test Plan

- `wizard step5d` selects per-role providers + persists to a tempfile freedom.yaml; reload round-trips
- `wizard step5d` with the "single provider" toggle collapses to `mode = Single` + leaves `left/right/cerebellum` empty
- `neoth hemispheres show` against a Single-mode config shows all three roles using the same provider with "(default)" annotation
- `neoth hemispheres set --role right --provider gemini_api` mutates only the right slot; left + cerebellum unchanged
- `from_config_for_role` returns the correct adapter for each role
- `neoth hemispheres test --role <X>` against a misconfigured provider surfaces the actionable error (missing key, bad endpoint)

---

## 8. WAL Audit

New lifecycle event:

| Code | Name | Payload |
|------|------|---------|
| `0x1F` | `HEMISPHERE_REBOUND` | `{role, prior_provider, new_provider, source, ts_unix}` |

(0x1F is the last slot in the lifecycle band — fully fills it.)

---

## 9. Schedule

| Phase | Day | Deliverable |
|-------|-----|-------------|
| 2 | 1 | `neoth hemispheres {show, set, test}` CLI + WAL event 0x1F |
| 2 | 2 | `providers::from_config_for_role` real per-role construction (audit ~3 existing call sites) |
| 2 | 3 | Wizard step 5d implementation + integration test |
| 2 | 4 | Slint sidebar panel (post-wizard switcher) |

Total: ~4 focused engineering days.

---

## 10. Status

**BUILD-READY**. All data structures exist; `from_config_for_role` skeleton exists; wizard framework + secret-prompt helpers exist. Spec is purely additive UX.
