# ADR-006 — HO-08: no separate `council/adaptation.rs`; the adaptation callback already exists

- **Status:** Accepted (2026-06-05, Session 39)
- **Supersedes / relates to:** HO-08 in `PLAN/PROGRESS_v1_0.md`; the Ecology layer (CH-13, `DESIGN_CH13_ecology_schicht_2026-05-23.md`)

## Context

HO-08 proposed a 3-step Ecology pickup procedure plus "2 new file targets", one of
which was a `council/adaptation.rs` module to host council-side callback hooks for
ecology-driven adaptation proposals.

A senior-dev design gremium (Session 39) verified the actual code against this
proposal:

- The Ecology auto-scheduler's ONLY council-side action is staging self-dev
  proposals — `ecology/scheduler.rs::stage_self_dev_proposals` calls
  `crate::cli::self_dev::propose_and_store` (`ecology/scheduler.rs:108`).
- `propose_and_store` (`cli/self_dev.rs:279`) IS the adaptation callback: it reads
  the behavioural snapshot, runs `propose_adjustments` against the council's Lowkey
  baseline, de-duplicates against the persisted store, and emits the `0x1C`
  audit frames — the whole pipeline review-gated per the DESIGN_CH13 **P2 hard
  constraint** ("Council-Fitness darf nicht heimlich Council-Policy umschreiben").
- The `council/` module (`council/mod.rs`) exposes `run_debate` / dissent scoring /
  budget / callosum / trigger. None of these is a natural sink for a
  scheduler-triggered policy-adaptation summary, and there is no second council-side
  callback that would add real value today.

## Decision

**Do NOT create `council/adaptation.rs`.** Creating it now would produce a placeholder
module with no real consumer — a violation of the project's no-stubs / no-speculative-
features rule. The adaptation callback the Ecology layer needs already exists as
`cli::self_dev::propose_and_store`, reached via `ecology/scheduler.rs:108`.

HO-08's scope therefore reduces to this ADR. The 3-step operator pickup procedure is
already satisfiable with shipped surfaces:

1. Enable Ecology in `freedom.yaml` (`ecology.enabled = true`) and confirm the
   read-only fitness scan finds winner records (`ecology::correlation_detector::scan_winner_records`).
2. Confirm `ecology::scheduler::spawn_ecology_cron_loop` is wired into the daemon
   (`cli/serve.rs`) — it returns `None` when disabled, so opt-out operators carry no idle task.
3. Confirm staged proposals surface via `neoth self-dev list` / `accept` / `decline`,
   each audited (`0x4C ECOLOGY_SCHEDULER_FIRED` on every fire; `0x1C` per proposal).

## Consequences

- **Positive:** no dead module; the genealogy concept already lives at
  `ecology/genealogy.rs` (the `skills/genealogy.rs` target in the original HO-08 note
  is superseded — it would have been a duplicate). The P2 constraint stays enforced by
  the single shared staging path, not a second council-side path that could drift out of
  sync.
- **Negative / revisit trigger:** if a future slice gives the council a genuine
  adaptation sink that the scheduler must call IN ADDITION to `propose_and_store`
  (e.g. a council-policy-version bump the scheduler records), revisit this ADR and add a
  real, wired module at that point — not a placeholder.

## Alternatives considered

- **Create `council/adaptation.rs` as a stub now (HO-08 as written).** Rejected: a
  placeholder module with `// TODO` headers is exactly the speculative scaffolding the
  coding rules forbid, and it would mislead future readers into thinking a council-side
  adaptation hook exists when the real one is `propose_and_store`.
- **Create `skills/genealogy.rs`.** Rejected: superseded by the shipped
  `ecology/genealogy.rs` (tool-usage genealogy); a second file would duplicate the concept.
