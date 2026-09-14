# Gold Waves 29 and 31 — mapped DM pairing and macOS recall diagnosis

**Receipt status:** **LOCALLY VALIDATED.**
Fifteen source files and a regenerated 179-input / 14-executable evidence set
are admitted on published `d2ae7b4b`. Publication identity is the Git commit
containing this receipt; no current-head GitHub CI result is claimed.

## W29 — mapped Telegram direct-message pairing

DM pairing is an explicit per-account policy opt-in through `channel account
set-dm-pairing telegram --account <id> --enabled`. Operators administer the
exact account's requests with `channel pairing list`, `approve --code`, and
`dismiss --request-id`.

Only a private, non-pinned DM may create a request. Pending state is bound to
the selected `ChannelRef` and its current binding tag, holds no pairing code,
expires after one hour, and allows at most three pending requests. Pinned
operator groups and the existing ConfirmBus path retain their behavior. Edited
Telegram messages cannot create or refresh pending requests. Rotation isolates
account A's state from account B. A mapped terminal without its authenticated
receipt is visible as an ingress failure and never enters the chat pipeline.

`DmPairingStore` uses a private bound directory and SQLite custody; synchronous
work is performed under an owned async-worker permit. This does not claim
pairing migration, physical-provider live acceptance, or full multi-account
readiness.

## Local runtime evidence

| Evidence | Result |
| --- | --- |
| Final selection | **PASS** — 741 pass / 0 fail / 0 ignored; 18 filters; catalogue 14,427; 29.55s |
| Binary | SHA-256 `17E881808E0AA46EA58D1A9162F3F28F9EC7F8EA76DA5B103DB8C8ADC85F85DC`; 282,038,272 bytes |
| Clippy08 | **PASS** — 3m03s; 209.02 GiB minimum free; 6.68 GiB peak |
| TestBuild04 | **PASS** — 4m12s; 204.11 GiB minimum free; 10.99 GiB peak |
| AccountConfigContracts | **PASS** — 157 tests across 13 executables; build 2m27s; 207.70 GiB minimum free; 7.40 GiB peak |
| Formatting and CLI docgen | **PASS** |
| Final GUI check | **PASS** — 1m40s; 208.24 GiB minimum free; 6.62 GiB peak; no GUI link |
| Python integrity checks | **PASS** — lost-feature integrity 19 (1.136s), roadmap 11 (0.112s), release gate 8 (0.001s), self-knowledge 19 (151.460s) |

Selected01 exposed a Windows fresh-SQLite `DELETE`-sharing conflict; the repair
uses the private SQLite handle. Selected02 exposed a fixture that aborted its
wrapper while the real writer remained live; the fixture completion repair does
not change production behavior. The final selection follows both repairs.

The verified evidence JSON records 179 source inputs, 14 physical executables,
741 unit tests, and 157 integration tests.

The Weak<dyn Channel> repair gives each once-bound reply an acyclic lifecycle:
releasing the adapter leaves no strong cycle. A real bundle-graph regression
covers that ownership boundary, and a retired send fails before WAL or
transport.

## W31 — macOS session-start-recall diagnostics

W31 records diagnostics for the two failures from macOS job `103806563594`:
`checked_query_error_never_becomes_empty` and
`missing_home_is_no_data_and_never_births_sqlite_or_wal`. It makes no deadline
change and claims no repair. No W30 or W32 implementation is part of this wave.

## Limits

P1-16 and P1-17 remain open. Counts remain 1,324 total / 1,011 complete / 311
open / 2 partial (313 raw; 312 pre-tag blockers). This receipt does not claim
native-GUI acceptance, a physical-provider result, or cross-platform CI.
