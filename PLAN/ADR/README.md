# Architectural Decision Records

Numbered, immutable decisions that shape NEOTH's architecture. Each
ADR captures *why* a path was chosen so future contributors don't
relitigate settled questions or accidentally drift away from a
constraint that originally drove the call.

## When to write an ADR

Open an ADR when:
- A choice between two viable approaches affects the shape of the
  codebase (framework, transport, dep family, persistence layer).
- The decision is hard to reverse — replacing the GUI framework or
  the WAL format costs weeks.
- A constraint isn't obvious from reading the code (e.g. "we use
  hyper 1.x http1-only because the operator's reverse proxy terminates
  TLS upstream").

Skip ADRs for:
- Settled idioms (use anyhow, use thiserror for libraries).
- Bugfixes / refactors that don't change the architecture.
- Decisions a single PR can reverse in under a day.

## Format

Each ADR is a Markdown file:

```
NNN-short-kebab-title.md
```

Body sections:
- **Status** — `Proposed` / `Accepted` / `Superseded by NNN` / `Deprecated`.
- **Context** — what problem prompted the decision; what constraints applied.
- **Decision** — what was chosen, in one paragraph.
- **Consequences** — positive, negative, and operator-facing trade-offs.
- **Alternatives considered** — every viable option that was rejected,
  with a one-line "why not".
- **References** — links to issues, specs, research notes, related ADRs.

## Index

- [ADR-001 — Slint as the GUI framework](001-slint-gui-framework.md) — Accepted.
- [ADR-002 — R-2 Keet/Hyperswarm port strategy](002-r2-port-strategy.md) — Accepted (port-as-you-go, no Node subprocess).
- [ADR-003 — R-02 Phase 3 dream-composition cadence](003-r02-phase3-dream-cadence.md) — Proposed (opt-in `neoth dream now` default + opt-in nightly cron, pending Day-14b).
- [ADR-004 — R-02 Phase 3 embedding model selection](004-r02-phase3-embedding-model.md) — Proposed (Qwen3-Q8 default + BGE-M3 opt-in fallback, gated on Day-14b `embed()` surface).
- [ADR-005 — R-02 Phase 3 channel-ingress privacy boundary](005-r02-phase3-privacy-boundary.md) — Accepted (episodes-only, no counterparty-leak via clustering).
- [ADR-006 — HO-08: no separate `council/adaptation.rs`](006-ho08-ecology-council-adaptation-hook.md) — Accepted (the adaptation callback is `cli::self_dev::propose_and_store`; no placeholder module).
