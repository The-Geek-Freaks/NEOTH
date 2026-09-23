# W300 — Coding role-origin binding

## Scope

W300 binds only coding call paths that already select a concrete
HemisphereRole before creating their provider authorizer. It adds no new route,
no user-selectable role, and no model-derived role selection.

- SRC/neothd/src/cli/code.rs: build_worker_set selects Left, Right, and
  Cerebellum. Each worker now retains that loop role in its authorized provider.
- SRC/neothd/src/coding/service.rs: build_dispatch_plan applies the same
  binding for the service-owned Left/Right/Cerebellum worker set.
- SRC/neothd/src/coding/service.rs: build_audited_worker constructs the
  Cerebellum decomposer and now binds Cerebellum before the one-shot wrapper.

The binding identity is resolved from config.inference.slot_for(role), with the
established legacy top-level provider fallback. Each binding retains
Arc::new(config.clone()), so these standalone/service construction paths retain
their existing fixed snapshot. No ReloadController is introduced.

## Regression evidence encoded in source

- cli/code.rs has a counted Right worker transport test: the allowed selected
  role reaches one mock leaf; a configured provider mismatch reaches zero.
- coding/service.rs has a counted Cerebellum decomposer test: the allowed
  wrapper reaches one mock leaf, drains a provider lifecycle WAL containing the
  Cerebellum role identity, and a configured provider mismatch reaches zero.
- The production wrappers remain the sole provider boundaries. Worker dispatch,
  default-wire-model resolution, retry behavior, and one-shot finalization are
  unchanged.

## Validation boundary

No executables, Cargo commands, formatter, parser, tests, or runtime checks
were run during the active BSOD hold. The source and focused regressions require
the GitHub-hosted Rust typecheck/test gate before acceptance.
