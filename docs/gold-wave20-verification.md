# Gold Wave 20 — account transport evidence and Doctor flapping

**Receipt status:** **LOCALLY VERIFIED.** Nine source
files are admitted on published W18-19 `f946f132`, including the Doctor count
pins and mapped live-auth repair. Local Rust gates, Python checks, formatting,
and GUI lint/self-test pass. Publication identity is the Git commit containing
this receipt; no current-head full CI or cross-platform acceptance is claimed.
The receipt makes no physical
delivery, authorization, retry, or runtime-health claim.

## Admitted boundary

The slice records optional account metadata on a live egress intent only when a
validated, nonlegacy mapped `TelegramAccountBundle` supplies the private
provenance. It keeps generic/default bindings, legacy Telegram, other channels,
webhooks, probes, and outboxes unbound. The result joins that immutable intent;
existing unbound formats remain compatible.

One read-only complete authenticated home-WAL scan feeds the strict proactive
v4 collector first and passes only nonproactive frames to the bound-live
collector. Both collectors finish validation before a 24-hour account counter
is calculated. A partial, unavailable, malformed, replaced, or unauthenticated
scan returns an error and no counters. Historical `ChannelRef` evidence is never
rebound against current configuration, credentials, runtime state, or routes.

The Doctor account-flapping check consumes those counters. Its initial warning
threshold is at least five completed attempts and at least 20% failures.
Unknown-after-armed and unsettled-live-intent are visible inconclusive counts;
they do not enter the completed rate. Zero evidence passes, while reader failure
is unavailable with no partial account rows.

P1-14, P1-16, and P1-17 remain open. This does not add physical exactly-once
delivery, remote or human receipts, account authority, routing, credentials,
or retries.

## Mapped live-auth repair

Existing opaque capability gates bind the intent and terminal through the
existing `append_authenticated` path. A `CHANNEL_SEND` audit record is appended
before the terminal marker on both success and failure. Unbound payload and
ordering behavior remain unchanged. The focused tests cover `LiveDelivery`
reader success and failure while the writer remains running, plus the case
where a live unsigned writer can acknowledge an ordinary payload but refuses a
mapped payload before the mock send.

## Local verification evidence and repaired regression

| Evidence | State |
| --- | --- |
| TestBuild01 | **PASS** — 7m29s; 182.78 GiB minimum free; 15.1 GiB peak |
| Four real authenticated-WAL tests | **PASS** |
| Unknown-outcome sanitizer review | **PASS** |
| Formatting | **PASS** |
| TestBuild02 | **PASS** — 4m07s; 183.27 GiB minimum free; 11.07 GiB peak |
| Selected02 | **PASS** — 394/0/0 in 27.57s; this ran before the live-auth repair |
| Python checks (19 + 11 + 8) | **PASS** |
| Clippy03 (final source) | **PASS** — 3m12s; 205.12 GiB minimum free; 7.31 GiB peak |
| TestBuild03 | **PASS** — 3m49s; 202.66 GiB minimum free; 10.65 GiB peak |
| Final selected run | **PASS** — 397/0/0 in 26.48s; catalogue 14,389 |
| 13 integration targets | **PASS** — 157/0/0; build 4m27s; 205.11 GiB minimum free; 10.82 GiB peak |
| Final formatting, GUI lint, and GUI self-test | **PASS** |

Selected01 initially returned **391/3/0**. Its three failures exposed one real
production defect and two new Doctor count pins. The production defect was a
legacy JSON byte-order regression. The writer now restores the former `json!`
value plus optional-reference shape; the raw-byte assertion remains unchanged.
The Doctor all-check documentation count changed from 59 to 60, while
`run_all_checks` changed from 58 to 59 runtime outcomes. The fixture
corrections do not add authority, retry, or delivery behavior.

## Receipt artifacts and publication boundary

The final binary is 279,900,672 bytes with SHA-256
`6B53DF7714F73FBEA15C1C093D1B82201550C21C1E14FDA9D50480C41D5FAE4E`.
The local receipts record 153 source inputs and 14 executables:
[source manifest](verification/gold-wave20-source-manifest.json) and
[test matrix](verification/gold-wave20-test-matrix.json).

The live producer/authenticated-reader integration coverage includes rotation
writer negative behavior. It verifies the admitted local behavior; it does not
assert physical delivery or a remote receipt.

Publication identity is the Git commit containing this receipt. There is no
current W20 full-CI or cross-platform acceptance claim. Wave 17 CI is terminal
**FAILED**: Linux and Windows passed;
macOS has 13 failures (11 session-start recall and 2 chat) involving SQLite
`NOFOLLOW` temporary fixture paths; its terminal report records `1550/15633`.
The approved W23 repair awaits admission.
The current W18 exact-head Preflight `34780142255` and Code Quality
`34780141999` passed, but those historical results do not validate W20.
