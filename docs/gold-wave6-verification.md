# GOLD Wave 6 verification

**Status date:** 2026-09-07
**Scope:** bounded durable proactive/webhook trust admission and reconciliation.
**Validation:** bounded local gates pass on the frozen 17-input source set,
including all nine selected runtime groups and the affected feature check.
This checkpoint does not close GOLD-LF-P1-05 or a release gate.

## Source and runtime provenance

The base is `3fb7082ce06b6f86f0ffab1d1e9e727a5ebf014f`. The changed compiled
inputs cover the trust descriptor/Gate, WAL writer, local audit RPC, proactive
egress/dispatcher, webhook listener, accepted-config reload and serve wiring,
plus the proactive source contract. The final changed-input inventory is in
[the source manifest](verification/gold-wave6-source-manifest.json); selected
results are in [the test matrix](verification/gold-wave6-test-matrix.json).
Publication targets GitHub `main`.

The fresh library test executable contains **14,180 tests**. Its SHA-256 is
`0762490F0AF83B9446FD3D9AE77BAAB1491717D0E287DABEDDFB89945E667BD9`
(273,219,072 bytes). Test compilation passed in 3m40s, strict Clippy in 2m52s,
and the default core package check in 1m58s. These gates used rustc/cargo 1.95.0,
Windows x64 MSVC, one Cargo job, one test thread and offline dependencies.

The public CLI build passed in 4m58s. `SRC/target/debug/neoth.exe` reports
`neoth 1.0.0` and has SHA-256
`E3025B3BD5BC297D4A247D5B21B12CCAA75321DB241D4B402C58911E383E8A18`
(182,257,664 bytes). All five version/help probes pass: version, serve,
permissions audit, proactive list and reload. They prove startup and command
registration; the focused tests above and below prove bounded behavior.
Workspace formatting, the GUI static guard and locked workspace metadata
pass. The metadata resolves five packages and five workspace members.
After the final PLAN annotations, roadmap and lost-feature contracts pass
11 and 19 tests respectively. The proof documents are not embedded runtime
inputs; those documentation edits do not invalidate the frozen binaries.

The affected `matrix-channel,gchat-channel` production/test type check passes
in 9m24s. It verifies the optional dispatcher branches, not live providers.
The standalone proactive source integration contract was freshly rebuilt and
passes 19/19. Final readback at 2026-09-07T12:50:13.2707004Z confirms all
17 source hashes and both executable hashes with zero mismatches.

## Selected behavior evidence

| Test filter | Passed | Failed | Ignored parent entries |
| --- | ---: | ---: | ---: |
| `permissions::` | 200 | 0 | 0 |
| `wal::writer::` | 94 | 0 | 2 |
| `daemon::audit_rpc::` | 62 | 0 | 1 |
| `daemon::proactive_egress::` | 43 | 0 | 0 |
| `daemon::proactive_dispatcher::` | 27 | 0 | 0 |
| `channels::webhook_listener::` | 47 | 0 | 0 |
| `config::reload::` | 46 | 0 | 0 |
| `cli::serve_tasks::` | 64 | 0 | 0 |
| `cluster::` | 472 | 0 | 0 |
| **Total** | **1,055** | **0** | **3** |

Every group executes tests and passes. The writer cross-process helper and
audit-RPC child helper are exercised by their parent tests; their separate
ignored entries are not additional passes. The remaining ignored entry is
the optional D008 latency benchmark. Counts use each process's final parent
summary, excluding nested child summaries. Cluster is regression coverage of
shared permission behavior; no cluster source changes belong to this batch.

## Implemented boundaries

A strict immutable descriptor binds the local subject, exact operation/action,
effective request, policy fingerprint and decision provenance. The typed WAL
schema-2 decision is distinct from compatibility schema 1. Generic append
routes cannot mint schema-2 admission. Durable Confirm requires a covering
live capability lease; an editable source label, CLI flag or unrelated
upstream receipt cannot confer durable authority.

The writer once transaction holds home-bound process and OS file authority
across authenticated lookup and append. It seals only its own open HMAC
window before lookup and forces a marker before acknowledging a new receipt.
Existing exact receipts are reused. Conflict, duplicate and indeterminate
results remain distinct; malformed, foreign or unauthenticated tails do not
prove absence. Cancellation of the requester does not abandon an already
owned writer operation.

The mandatory local RPC uses the existing same-user authenticated endpoint
and canonical home identity. Its strict request/response types preserve once
outcomes without automatic retry. A dropped HTTP response after durable
append can be reconciled to ExistingExact with one authenticated decision.
The optional public audit-route switch does not disable this internal route.

Proactive claims v3 and webhook outboxes v2 persist their descriptors before
submission and require authenticated reconciliation before transport. A
copied receipt must still match the actual immutable effect. The accepted
ReloadController snapshot supplies both policy and the effect lease. Reload
retires old admissions and drains leased effects before publishing a new
snapshot. The dispatcher uses a coherent config/credential pair from the
actual serve configuration path, including custom paths.

Proactive ownership retains generation authority through terminal Result
acknowledgement; the provider task separately retains it through actual I/O
teardown. Cancellation cannot release an active effect or leave reload
dependent on a later recovery tick. Suppressed operations retain truthful
Intent/Result history without Armed or provider invocation. Legacy Armed
uncertainty remains CrashUnknown without resend.

Webhook delivery owns a stable per-record process/OS lock, reloads the record
under that lock, and owns generation authority through HTTP, result audit and
durable settlement even if the initiating caller is cancelled. Overlapping
foreground/recovery calls cannot independently send the same record. Retries
and restart reuse the receipt when the accepted policy fingerprint matches;
process-local epochs are not persisted authorization. Legacy attempts remain
explicit future-only continuation, never retrospective approval.
DeliveredPendingAudit stays audit-only.

## Repairs and review

Independent code, Rust and security reviews are clear. Review corrections
retain exact generation ownership during cancellation, descriptor/effect
binding and typed RPC failure propagation without source-label authority.

The earlier attempt-6 runtime matrix had 11 failures and is diagnostic only.
The final fixtures use a Tokio runtime for the re-executed writer lifecycle,
await writer readiness before no-write RPC baselines, distinguish JSON outbox
records from stable lock siblings, and release old DELETE-capable handles
before simulating restart. Windows namespace-replacement cases require exact
identity refusal while preserving both the public sentinel and displaced
original bytes. The dispatcher no-effect fixture states its intended
autonomy. Those repairs received narrow code/Rust/security review before the
fresh passing attempt-7 build; no attempt-6 runtime result substitutes for it.

## Evidence limits

The corresponding contract is [required trust decisions](trust-decision-boundaries.md).
This is selected local behavior, not the complete 14,180-test library suite,
live provider/peer acceptance, interactive GUI, installer/package validation,
or unchanged-candidate CI/Security/CodeQL release qualification. Exactly once
describes the authenticated TrustDecision, not physical provider delivery.
The native GUI/Buddy apply-confirmation flow and completion of the overall
boundary inventory remain open under P1-05. No roadmap checkbox closes here.
