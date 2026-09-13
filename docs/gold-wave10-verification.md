# Gold Wave 10 — authenticated local transcript ingress

Accepted for Stage 3b of `GOLD-LF-P1-08` on 2026-09-13.
The implementation is restricted to AGENTER, from source baseline
`22ac400e2d8c665fd066d905d83e24f463e3e68d`. The sixteen changed compiled
inputs are recorded in `verification/gold-wave10-source-manifest.json`.
P1-08 remains open: this component does not complete the candidate export,
operator labeling, shadow execution, live graders or release report workflow.

## Implemented boundary

Fresh local operator turns can explicitly opt into one finite mining window.
The private ingress creates the operator row and exact RAW_TEXT plan, obtains
authenticated physical WAL readback, then creates and independently delivers
the canonical metadata-only Bound frame. Delivered plus active plus lease
release is one SQLite transaction. Agent turns, legacy rows, imports and
Incognito do not acquire that capability.

Unknown outcomes retain the original immutable descriptor and a durable
delivery lease. Recovery authenticates exact bytes, including after an HMAC
key rotation. Deletion fails busy during owned or unknown delivery. Expired
RAW, absent expired Bound, late Bound acknowledgement and already-active
expiry each have a monotonic terminal path. Revocation uses the delivered
Bound and immutable local terminal receipt independently of damaged raw-plan
bookkeeping.

Ordinary SQLite connections default to denying receipt and lifecycle
attestation. The private connection grants one closed operation against exact
lease and descriptor identities. Mining reads reconstruct the canonical row
binding and authenticate both WAL frames and their frame/location receipts;
mutable status fields cannot grant authority. The historical V37 table
definition is preserved; the additive V38 migration invents no old proof.

Signed HMAC rotation audits can establish a complete authenticated prefix
only for their exact named, complete single-frame evidence and trusted proof
key chain. Transition discovery uses retained-directory reads with physical,
logical, aggregate and transition-count limits. Physical identities are
pinned between discovery, authentication and callback passes.

The behavior and command contract is [local transcript provenance](transcript-provenance-v1.md).

## Acceptance gates

| Final gate | Result |
| --- | --- |
| `_gui_check.bat test -p neoth --lib --no-run --locked --offline -j1` | PASS, 3m03s |
| `_gui_check.bat check -p neoth --lib --locked --offline -j1` | PASS, 1m46s |
| `_gui_check.bat clippy -p neoth --lib --tests --locked --offline -j1 --no-deps -- -D warnings` | PASS, 4m26s |
| `_gui_check.bat fmt --all -- --check` | PASS |
| Selected library behavior tests, one test thread | 242 passed, zero failed/ignored, 32.66s |
| Parent-owned cross-process child | 1 passed, counted separately |
| Independent source and final delta review | CLEAR |
| Roadmap release-gate tests | 11 passed |
| Lost-feature integrity tests | 19 passed |

The final test binary is `SRC/target/debug/deps/neothd-b3c2385f8afc9114.exe`,
SHA-256 `2582A4939D23B13E4C3BB023A20E063F0FBF54A7BF782114483A1FCE63CF841E`.
It lists 14,231 tests; this receipt covers the selected 242 and the child
invocation, not the entire library. Exact selection and executable identity
are retained in `verification/gold-wave10-test-matrix.json`. The existing
`peeroxide-dht` dependency dead-code warning does not fail the no-deps gate.

Compilation uses one job, debug info zero, Idle priority and four logical
CPUs (affinity 61440). The owned process tree is monitored and stops if free
physical or virtual memory falls below 32 GiB. This is a measured load limit,
not a guarantee against workstation hardware or driver failure. The final
test build peaked at 10.11 GiB with at least 218.44 GiB RAM free. Strict
Clippy peaked at 10.25 GiB with at least 218.38 GiB free; Core check peaked
at 6.34 GiB with at least 222.13 GiB free.

The selected suite covers local chat opt-in/default/Incognito, exact RAW and
Bound retry, cancellation and expiry, ordinary SQL mutation denial, raw
deletion, damaged bookkeeping, real HMAC rotation, historical migration,
existing store/WAL/signing behavior and CLI documentation consistency. The
cross-process child fixture is exercised by its owning parent; the standalone
child invocation and optional WAL latency benchmark are not selected.

Diagnostic runs caught a private RAW admission mismatch, historical V37 DDL
contamination, receipt mutation through ordinary SQL and an unbounded signing
discovery pass. These were repaired and independently reviewed before final
acceptance. The existing CLI regression was updated to its actual schema-1
provider Gate audit and skipped-Council semantics while retaining the full
request/response and no-refusal checks.

This receipt does not claim a complete library/workspace run,
live provider acceptance, a native GUI/installer, cross-platform behavior or
a release candidate. The roadmap still has 1,324 items: 1,009 complete,
313 open and two partial, with 315 raw and 314 pre-tag blockers.
