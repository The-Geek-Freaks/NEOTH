# Gold Wave 16 — account-bound proactive routing and delivery

**Receipt status:** **LOCALLY ACCEPTED; EXACT-HEAD FULL CI OUTSTANDING.**
Sixteen production files plus one adapted source gate have exact admitted hashes.
Foundation, delivery, test, and final source-gate reviews are **APPROVE**. This
does not establish cross-platform acceptance and makes no live Telegram,
GUI-link, or macOS-runtime claim.

## Admitted contract

`neoth proactive route --default --channel telegram --account <account-id>`
records an explicit mapped
Telegram account on new route/queue work. That stored binding survives later
route/default changes. During physical delivery, the account-bound path holds
`DeliveryLock` and immediately before durable `Prepared` reloads a fresh
coherent config/credential pair. It checks the accepted public configuration,
resolves the exact stored account, and derives both owning adapter and recipient
only from the returned authenticated bundle.

A credential or policy update completed before this fresh admission therefore
applies to the attempt. This contract makes no retroactive cancellation promise
after pair admission. Map-active missing, unknown, removed, partial, mismatched,
or legacy-unbound account state settles without a send and never falls back from
A to B. Historical unbound Telegram delivery stays available through the legacy
flat path while the effective account map is empty.

New account-bound durable claims and intent/result/projection evidence use a v4
typed `ChannelRef` with domain-separated binding. Existing unbound queue JSON,
v1-v3 claims, WAL records, hashes, and recovery behavior remain compatible.

P1-16 remains **OPEN**: this is Telegram-only and does not claim other
transports, pairing, GUI/Buddy/importer, account health, migration UI, complete
outbound routing, or live Telegram I/O.

## Current local evidence

| Gate | Result |
| --- | --- |
| TestBuild02 | **PASS** — 4m05s; 202.95 GiB minimum free; 10.42 GiB peak |
| SelectedFINAL | **PASS** — 221/0/0 in 10.44s; catalogue 14,340 |
| Fresh binary | 278,616,576 bytes; SHA-256 `FF78DE3802E0DB29D56C7DB706E5FE525F87F3941E9B26B424E3E8068EAD64E9` |
| Formatting, GUI lint, GUI self-test | **PASS** |
| Python integrity/release checks | Earlier **PASS** — 19 + 11 + 8 |

Clippy03 **PASS**: 3m50s, 205.89 GiB minimum free, 8.59 GiB peak. It predates
the final two test-fixture changes; Clippy04 below verifies the final test state.

## Retained failure history

Clippy01 found private-interface visibility and a dead helper; Clippy02 found
an Armed fixture referring to a nonexistent field. Both were corrected, with
the latter checking v4 authenticated hashes. Selected01 ran 218/3: one stale
Cron text fixture; one exact-B-only credential/reload-authorization fixture
because `Credentials::write` preserved A; and one Armed fixture missing the
trust receipt. The fixtures now assert the actual behavior, including
`ensure_trust_admission_receipt` with `TrustOutcome::Allowed`; the production
behavior did not change. All fixes were
independently reviewed **APPROVE**.

## Final local validation

| Gate | State |
| --- | --- |
| Clippy04, after final fixture changes | **PASS** — 3m04s; 205.10 GiB minimum free; 6.48 GiB peak |
| Unit behaviors | **PASS** — 221/0/0, plus one real cross-process child validated separately by child completion and outer terminal result |
| AccountConfigContracts (13 targets) | **PASS** — 157/0/0 |
| Formatting, GUI lint, GUI self-test | **PASS** |
| Python integrity/release checks | **PASS** — 19 + 11 + 8 |

The integration proof used two invocations. The initial first ten targets
passed; the 58-test network target took 100.34s. The initial 13-target compile
took 4m27s (203.15 GiB minimum free; 9.27 GiB peak), but target 11's source-gate
run had 18/2 failed assertions: a formatted method chain and old v2/v3
fingerprints. It is not recorded as a pass. The reviewed source-gate repair
retains its invariants. A final tail run of the source gate and the previously
unrun transcript/untrusted targets passed; compile time was 6.89s, minimum free
211.96 GiB, peak 0.25 GiB. The first ten executable hashes were verified
unchanged, so they were not rerun.

The exact 101-input, 14-executable receipts are
[`gold-wave16-source-manifest.json`](verification/gold-wave16-source-manifest.json)
and [`gold-wave16-test-matrix.json`](verification/gold-wave16-test-matrix.json).
They match the final local source and evidence.

## Remaining publication and CI boundary

Wave 16 exact-head full CI remains outstanding. Wave 15 exact CI `ea0d9c3e`
remains pending. These receipts record local verification; Git history records
publication. No cross-platform or live-runtime result follows.
Roadmap counts remain 1,324 total / 1,010 complete / 312 open / 2 partial
(314 raw; 313 pre-tag blockers).
