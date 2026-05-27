# ADR-002 — R-2 Keet/Hyperswarm port strategy

**Status**: Accepted (backfilled 2026-05-27 from Session 21 [[open-decisions-verdicts]]
verdict — 4 architect agents ratified port-as-you-go in Session 21
2026-05-23). HO-04 (Round-3 v0.4 stub-register item) closes by recording
this rationale so the implementation lane is unblocked from "operator
decision pending" status.

## Context

R-2 is the Keet messenger adapter; its substrate is Hyperswarm (a Node
DHT). NEOTH's daemon is pure Rust. Two strategies presented themselves
in late 2026-Q2 research:

1. **Node-subprocess** — ship a small Node bootstrapper alongside
   `neothd` that hosts Hyperswarm + Keet primitives, communicate over
   stdio/JSON-RPC. Fast to MVP because the Pears reference impl is
   Node-native.
2. **Port-as-you-go** — port the subset of Hyperswarm + Keet we actually
   need into Rust, starting with the minimal swarm + topic-resolver
   slice and expanding lane-by-lane as channel features mature.

The choice affects:
- AIO cross-platform invariant ([[neoth-aio-cross-platform]]): every
  runtime dep must ship in-binary or auto-install headless. A Node
  subprocess is a third-party runtime to bundle + heal.
- Build-pipeline drag: NEOTH's release workflow is pure Rust + cargo-
  dist; introducing Node would force a parallel npm install + bundle
  step on every release host.
- Long-term maintenance: each Hyperswarm upstream bump would force a
  npm-package re-pin + integration-test churn on the subprocess.

## Decision

**Port-as-you-go.** No Node subprocess in the shipped `neothd` binary.

We port the Hyperswarm + Keet primitives we need into Rust incrementally,
beginning with the minimal subset that K-2 (Pears HTTP bridge —
[[neoth-d101-d102-d103-verdicts]]) already validated end-to-end. The
HTTP bridge is the transitional path: it lets us iterate the Keet UX
without freezing the port estimate at "12 weeks until parity". As more
of the Hyperswarm surface lands in Rust, the bridge shrinks to a
thinner facade until it can be retired.

Estimated full-port effort: ~12 weeks across Phase 3+ (per Session 21
operator-decisions list).

## Consequences

**Positive**
- `neothd` stays a single binary on every supported OS — matches the
  AIO cross-platform hard rule + the operator-never-opens-npm rule
  ([[neoth-aio-cross-platform]]).
- Release workflow stays pure Rust; cargo-dist + the cross-compile
  matrix in `.github/workflows/release.yml` need no Node-side
  additions.
- Each ported subset lands with its own test surface in Rust, joining
  the existing test family (no JS test harness to maintain).

**Negative**
- Initial channel-feature velocity is slower than the Node-subprocess
  path would have been. The K-2 HTTP bridge cushions this — Keet
  ships before the full port lands.
- Two transports coexist during the port window (HTTP bridge for
  unmigrated paths, native Rust Hyperswarm for migrated). Operators
  notice nothing; contributors see a temporarily dual code path.

**Operator-facing**
- The wizard installs only one binary; no Node prompt + no `npm
  install` step at any phase of onboarding.
- Disk footprint stays small (no node_modules dir).

## Alternatives considered

- **Node-subprocess** — rejected for the AIO cross-platform reasons
  above; the operator-never-opens-npm constraint was the deciding
  factor.
- **WebAssembly Hyperswarm fork** — rejected because Hyperswarm's
  socket layer + DHT primitives don't map cleanly to wasi networking
  in the current wasmtime release we target ([[neoth-d101-d102-d103-verdicts]]
  D-103 covers the wasmtime baseline).

## References

- Memory: [[open-decisions-verdicts]] — Session 21 ratification.
- Memory: [[neoth-d101-d102-d103-verdicts]] — K-2 HTTP-bridge baseline.
- Memory: [[neoth-aio-cross-platform]] — operator-never-opens-npm rule.
- `PLAN/HANDOFF_2026-05-22.md` §"Operator decisions pending" #1.
- `PLAN/PROGRESS_v1_0.md` HO-04 (this ADR closes the register half).
