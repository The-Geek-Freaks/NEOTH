# GOLD Wave 5 verification

**Status date:** 2026-09-07
**Scope:** bounded daemon and cluster admission checkpoint.
**Validation:** bounded local gates pass on six unchanged compiled inputs.
This checkpoint does not close GOLD-LF-P1-05 or a release gate.

## Source and runtime provenance

The changed compiled inputs are `cli/serve_pipeline.rs`, `cli/serve_tasks.rs`,
`cli/serve.rs`, `cli/obsidian.rs`, `cluster/hyperswarm.rs` and
`permissions/gate.rs`, relative to
`SRC/neothd/src`, against base `479df2e0a3bacc2f74045c21859d62a3340037dc`.
The frozen input hashes are recorded in the
[source manifest](verification/gold-wave5-source-manifest.json). Post-gate
readback at 2026-09-07T10:30:21.5835889Z confirmed all six input hashes and
both executable hashes without mismatches. Detailed gate results are in the
[test matrix](verification/gold-wave5-test-matrix.json).
Publication targets GitHub `main`.

The fresh library test executable contains **14,147 tests**. Its SHA-256 is
`7D1F3C332A30F34AF21FE79D5568B76346A66C6B0B8520204B133760441527FE`
(271,215,104 bytes). Test compilation passed in 3m39s, strict Clippy in 3m44s
and the core package check in 42.10s.

The public CLI build passed in 2m30s. `SRC/target/debug/neoth.exe` reports
`neoth 1.0.0` and has SHA-256
`2F0A929D77A4D7AEE18B21C38C2E0EB5B24F47C7359580E07F9760F6700A4322`
(181,801,472 bytes). All five version/help probes passed: version, serve,
Obsidian, Obsidian preload and permissions audit. They prove startup and CLI
registration; the behavior evidence below comes from the focused tests.

Workspace formatting and the GUI static guard pass. Locked metadata resolves
five packages and five workspace members. The roadmap contract passes 11 tests
and lost-feature integrity passes 19 tests. Code, Rust and security review are
clear; the final instance-DB repair also received narrow code and Rust review.

## Selected behavior evidence

| Test filter | Passed | Failed | Ignored parent entries |
| --- | ---: | ---: | ---: |
| `cli::serve_pipeline::` | 40 | 0 | 0 |
| `cli::serve_tasks::` | 64 | 0 | 0 |
| `cluster::` | 472 | 0 | 0 |
| `permissions::` | 194 | 0 | 0 |
| `daemon::audit_rpc::` | 56 | 0 | 1 |
| `wal::writer::` | 86 | 0 | 1 |
| `obsidian::` | 101 | 0 | 0 |
| **Total** | **1,013** | **0** | **2** |

All seven groups execute tests and pass. The existing audit-RPC child helper
is exercised by its parent test; its separate ignored harness entry is not an
extra pass in this count. The other ignored entry is an optional WAL latency
benchmark. These are selected parent-harness executions, not the whole library
suite or a count of independent product requirements.

## Implemented boundaries

The upstream channel-reply Gate requires the daemon's authenticated Writer
audit and retains the platform-verified inbound sender as its lease and ledger
subject. Denial or unavailable audit suppresses the ordinary reply release
and prevents the live provider stream from opening. This is not the later
durable outbox's local-subject recipient/body admission.

Configured Obsidian preload awaits its required local decision before task
creation, lifecycle intent, vault copy, preload-state persistence or database
ingestion. Disabled or incomplete configuration still skips without a decision.
Strict refusal and a dead writer start no preload task. The success fixture
uses a real manifest, Markdown file, isolated NEOTH home and authenticated WAL.
Primary and knowledge-template ingestion explicitly use that same instance
home's `views.db`. Neither async fixture changes the process-global home.
The shared vault guard checks existing linked ancestors before creating a
target parent and reports rejected targets as an unsuccessful preload outcome
while allowing safe files to continue.

Cluster TaskDelegate admission preserves parsing, static-denial, pairing,
membership and lease prefilters. It reserves executor capacity before the final
Gate. That Gate uses the authenticated Noise peer as subject and a digest of
the exact peer/task/prompt descriptor. A missing writer prevents admission.
Membership revalidation follows the authenticated Allow and precedes queueing;
the accepted cluster event follows the queue effect. Expiry and revocation
tests exercise the boundary through test-only hooks in the production path.
The explicit decision-clock helper exists only in test builds; production
continues to use the live Gate clock. A final fallible enqueue handles receiver
closure or a capacity race after audit. Those no-effect outcomes retain the
already-authenticated admission while emitting no accepted cluster event.

## Review repairs retained in the checkpoint

Review caught the receiver-close race in an infallible reserved send. The final
fallible enqueue now exposes that failure and prevents a false accepted event.
The lease-expiry fixture also moved from a one-second wall-clock assumption to
an explicit test-only decision clock. Code, Rust and security re-reviews of
those repairs are clear.

The first test compile found an incorrect non-reexported error-type path and a
missing teardown argument in the revocation fixture. Both received narrow
repairs and code/Rust re-review before the second frozen input manifest.
The first runtime matrix then exposed a fresh-vault Windows path mismatch and
an incorrect live-WAL completeness expectation. The preload repair compares
consistent canonical roots, rejects malformed subdirectories before admission,
and checks existing linked ancestors before creating a target outside the
vault. The cluster test distinguishes its authenticated live prefix from the
complete history after writer shutdown. Intermediate diagnostics are retained
under `work/gold-20260906`.
Strict Clippy then rejected two test environment locks held across `await`.
Binding both production ingestion calls to the supplied instance home removed
the global environment overrides and also fixed multi-instance DB selection.

## Evidence limits

The corresponding contract is [required trust decisions](trust-decision-boundaries.md).
Focused local tests are not live peer-network/provider acceptance or full
workspace, GUI, package, installer or unchanged-candidate release qualification.
Repeated remote task IDs are not deduplicated by this admission boundary.
Durable proactive/webhook admission and unknown-append reconciliation remain
open under P1-05. The separate GUI apply-confirmation flow remains open.
