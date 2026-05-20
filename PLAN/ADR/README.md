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

- [ADR-001 — Slint as the GUI framework](001-slint-gui-framework.md)
