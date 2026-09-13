# Gold Wave 14 — first account identity

**Receipt status:** local component accepted. The first P1-16 account-identity
slice has fresh build and runtime evidence. Complete multi-account behavior
and cross-platform acceptance remain open.

## Implemented contract

Every singleton startup captures a canonical `ChannelRef`. Inbound messages
whose channel disagrees with that binding stop before provider or WAL work.
Sender-supplied human UUIDs do not become identity authority. V39 introduces
account-qualified v2 aliases; v1 aliases remain unbound historical records.
Resolution uses an immediate transaction and rechecks the binding under its
writer lock. Only an opaque token minted at authenticated legacy Telegram
startup can claim an exact default-account alias whose sender and pinned
operator UUID match. The claim and new alias commit atomically.

Explicit identity merge is transactional across v1/v2 aliases and its tombstone.
It preserves the original claim UUID/time as immutable provenance. Migration
tests preserve v1 history, leave new identity tables empty, verify idempotence,
and force a second-table DDL failure to prove version/schema/data rollback.

Account binding reaches sender hashes, conversation/profile scopes, transcript
and archive keys, media-source references, rate-limit buckets and channel WAL
receipts. Both ChannelSend and MCP gates use the same canonical account/sender
lease subject. Bare historical sender leases authorize neither account A nor
B; `neoth lease channel-subject` supplies the exact value for deliberate regrant.
The helper is pure and the CLI reference is regenerated from the executable's
command tree.

## Final local evidence

| Gate | Result |
| --- | --- |
| TestBuild04 | PASS, 1m44s; minimum 200.49 GiB free / peak 9.51 GiB |
| Selected03 | 327 passed / 0 failed / 0 ignored, 18.02s |
| AccountContracts02 | 81 passed / 0 failed / 0 ignored across 10 targets; build 1m08s; minimum 203.47 GiB free / peak 5.98 GiB |
| Clippy05 | PASS, 3m07s; minimum 203.23 GiB free / peak 6.45 GiB |
| Core01 | PASS, 1m52s; minimum 203.20 GiB free / peak 7.48 GiB |
| Formatting and GUI lint/self-test | PASS; final Rust source is formatted |
| Python documentation/inventory checks | PASS: lost-feature integrity 19; roadmap release gate 11 |
| Independent account source and regression review | APPROVE |

The selected binary catalogue contains 14,290 tests. Its SHA-256 is
`EF240748AFBE4F02C77858288439B2933956089DBA41849877A2F284647E106E`.
`verification/gold-wave14-source-manifest.json` records 74 changed/relevant
inputs, including direct integration-contract source dependencies;
`verification/gold-wave14-test-matrix.json` records exact selected names and
all ten integration executable hashes. The selected modules cover identity,
rate limits, channel pipeline/startup, CLI identity/leases/history/recall/parity,
doc generation, migrations/store, permission gates/leases and cost authorization.

Earlier failed passes are retained locally: two obsolete rusqlite API calls,
two lint errors, six stale helper test calls, five stale WAL/receipt assertions,
and a constant schema assertion. The final schema assertion tests the actual
database value. Two final formatting corrections were followed by a fresh
test build, selected run, strict Clippy and integration run. Core01 preceded
those formatting-only test changes; production behavior did not change.

## Published CI boundary and remaining work

Full CI `34762817827` on base `7064930cf4a83ce8f180accad8f25421ef108b19`
is terminal: Windows workspace nextest passed; macOS ran 15,535 tests with
15,518 passes and 17 failures (23 skipped); Linux failed an unused `Context`
import that this batch now gates to Windows. Preflight `34762795412` and code
quality `34762795622` passed. No current-head cross-platform green claim is made.

The macOS failures include the physical SQLite reopen path for recall, stale
migration fixtures, and specific symlink/WAL test expectations. Reviewed repair
proposals are prepared for the next batch. P1-16 remains OPEN for configuration,
credential ownership, outbound routing, pairing/queues/health and remaining
surfaces. Roadmap counts stay 1,324 total / 1,010 complete / 312 open / 2 partial
(314 raw blockers; 313 pre-tag blockers).

All compiler gates ran serially with one Cargo job, Idle priority, four logical
CPUs and a monitored 32 GiB physical/virtual free-memory floor. No GUI monolith
was linked locally.
