# NEOTH — Gremium Execution Backlog (Phase 2)

**Date:** 2026-05-20  
**Purpose:** Convert the prior superreview into implementation-ready work packages with objective acceptance checks.

---

## 1) Short answer to “Ist das schon alles?”

Nein. Die vorherige Lieferung war **Audit + Strategie**.  
Diese Datei ist die fehlende **Execution-Ebene**: konkrete Arbeitspakete, Reihenfolge, Messkriterien, und Done-Definition.

---

## 2) P0: Safety & Reliability (must ship first)

### P0-1 Webhook ingress resilience hardening
- **Scope:** `SRC/neothd/src/channels/webhook_listener.rs`
- **Work items:**
  1. Add bounded concurrency gate (Semaphore) for per-connection handler.
  2. Add explicit 429/503 behavior when queue saturated.
  3. Add request timing + outcome counters (accepted/rejected/verify_failed).
- **Acceptance:**
  - Synthetic burst test (>=1k requests) yields no OOM/no unbounded task growth.
  - Over-capacity traffic receives deterministic failure status.

### P0-2 Verify-path anti-fragility tests
- **Scope:** `SRC/neothd/src/channels/webhook_verify.rs`, router/listener tests.
- **Work items:**
  1. Add property/fuzz-style tests for signature canonicalization and timestamp windows.
  2. Add regression fixtures for malformed/multi-value headers.
- **Acceptance:**
  - Test suite catches known malformed header patterns.
  - No false-positive verification in fixture corpus.

### P0-3 WASM host guardrails verification
- **Scope:** `SRC/neothd/src/wasm_plugin/*`, config plumbing.
- **Work items:**
  1. Add explicit startup log of enforced limits (fuel/memory/timeouts).
  2. Add integration tests proving limits are active under feature flag.
- **Acceptance:**
  - A deliberately misbehaving plugin is terminated by limits.
  - Tests fail if limits are disabled/ignored.

---

## 3) P1: Product quality and operator trust

### P1-1 Unified “safe mode” status surface
- **Scope:** `SRC/neothd-gui/ui/main.slint`, daemon status endpoint/event.
- **Work items:**
  1. Add single source of truth for active safety rails.
  2. Surface concise reason strings (policy lock, degraded network, plugin blocked).
- **Acceptance:**
  - GUI reflects daemon safety state within 1s.
  - Operator can explain “why action blocked” without logs.

### P1-2 Error taxonomy normalization
- **Scope:** daemon + GUI notification bridge.
- **Work items:**
  1. Define stable error codes (security, policy, transport, runtime).
  2. Map raw backend errors to user-grade messages.
- **Acceptance:**
  - 90%+ top recurring failures mapped to deterministic code+message.

---

## 4) P2: UX leap toward “12/10” consistency

### P2-1 Jobs-style interaction contract (coherence first)
- **Scope:** `SRC/neothd-gui/ui/*.slint`
- **Work items:**
  1. Define spacing/type/elevation tokens with strict reuse.
  2. One primary action per screen; destructive actions require second-step confirmation.
  3. Keyboard-first navigation and focus-ring consistency.
- **Acceptance:**
  - Token-usage audit finds no one-off spacing/font hacks in core screens.
  - Keyboard-only completion path for top 5 user journeys.

### P2-2 Accessibility baseline gate
- **Scope:** GUI lint/tests + CI check.
- **Work items:**
  1. Contrast checks for text/button states.
  2. Focus-order test fixtures for major dialogs.
- **Acceptance:**
  - CI blocks on contrast/focus regressions in touched screens.

---

## 5) P3: Differentiation vs OpenClaw/Hermes/OpenHuman

1. **Trust Ledger:** user-visible, append-only timeline of key autonomous actions.
2. **Autonomy Gradients:** per-skill/policy trust dial, not binary global mode.
3. **Recovery-first UX:** one-click rollback for major agent operations.

**Success metric:** Operator confidence + lower intervention cost (measure “manual correction events/week”).

---

## 6) 30/60/90 implementation cut

### Day 0–30
- Ship P0-1, P0-2.
- Add dashboards for webhook/error safety metrics.

### Day 31–60
- Ship P0-3 and P1-1.
- Freeze initial error taxonomy.

### Day 61–90
- Ship P1-2 + P2-1 baseline.
- Add CI accessibility gate (P2-2).

---

## 7) Definition of Done (global)

A work package is Done only when all are true:
1. Code merged with tests.
2. Observable metric added (counter/log/dashboard panel).
3. Runbook note updated for operators.
4. One rollback path documented and tested.

---

## 8) Suggested tracking format

For each item, track:
- `Owner`
- `ETA`
- `Risk`
- `Test command`
- `Rollback command`
- `Evidence link` (test output / screenshot / log snippet)

This prevents strategy docs from stalling and forces execution proof.
