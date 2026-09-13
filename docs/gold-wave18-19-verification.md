# Gold Waves 18–19 — GUI and connect account consumers

**Status: LOCALLY VERIFIED; full CI pending.** Six source files extend published Wave17
`ad4c4826640b05b9b049afd35727afef02a10c90`. Each consumer received an independent
source review. They share the compile round because both consume Wave17's
canonical account-status contract.

## Behavior

Settings → Channels renders nested Telegram account rows with separate static
readiness and optional runtime observation. Its account-test action constructs
the exact selected `channel test telegram --account <id> --output json` command,
retains the existing environment scrub and hidden-window behavior, and accepts
only a matching account result. The headless test target imports the actual GUI
parser/action modules and serializes a real core result across their boundary.

`neoth connect` retains canonical account rows instead of dropping them. A map
overview never invents a selected default or an unqualified test command.
Explicit configured `default` is an ordinary account id. Invalid maps stay a
repair-only view, and legacy single-channel JSON preserves its five-key shape.

The initial connect candidate failed independent review because it confused an
invalid map's empty account list with legacy mode and added a legacy JSON field.
Both were corrected with focused regressions before admission. The initial
format check requested only Rust formatting in connect and the GUI callback;
those edits were applied and the format check then passed.

## Local verification

| Gate | Result |
| --- | --- |
| Core TestBuild01 | **PASS** — 5m26; minimum free 189.98 GiB; peak 12.52 GiB |
| Core selected cases | **PASS** — 175/0/0 in 1.87s; fresh catalogue 14,362 |
| Full GUI test-source check02 | **PASS** — 1m47; minimum free 195.19 GiB; peak 6.67 GiB |
| Actual GUI parser/action harness, final source | **PASS** — 350/0/0 in 1.13s; rebuild 11.26s; minimum free 200.91 GiB; peak 1.99 GiB |
| Strict core Clippy02, including headless target | **PASS** — 2m45; minimum free 193.00 GiB; peak 8.25 GiB |
| Formatting, GUI lint/self-test, generated CLI reference | **PASS** |
| Python integrity, roadmap-release and release-gate contracts | **PASS** — 19 + 11 + 8 |

All compiler/test gates ran serially with one Cargo job, Idle priority, CPU mask
61440, debug info off and the 32 GiB free-memory guard. The GUI check compiles
Slint and test types without linking the GUI test monolith. Its 13 warnings are
in the unchanged Windows test-only `trusted_probe_supervisor` surface; no new
consumer warning remains. The vendored peeroxide warning is also unchanged.

The first GUI check passed in 7m54 but identified an unused connect guard
variable. Replacing its unused binding with `_` preserves behavior; check02
verifies the final production source. The first headless run passed all 350
tests in 1.22s but omitted desktop callers of `operator_diagnostic` from that
test crate. Clippy01 then found that the harness's public module import exposes
the desktop-private `KanbanSelection` as public API. Independent review approved
two narrow `#[expect(...)]` annotations on the harness imports. These contain
only the synthetic visibility/liveness conditions, alert if no longer needed,
and leave production visibility and behavior unchanged. Clippy02 and the final
350-test run verify that exact harness state.

The 149-input and two-executable receipts are
[`gold-wave18-19-source-manifest.json`](verification/gold-wave18-19-source-manifest.json)
and [`gold-wave18-19-test-matrix.json`](verification/gold-wave18-19-test-matrix.json).
The core executable SHA-256 is
`C1BD2D11B96DB1DA0E180E747EB342A920FB1FFE5FE51138189BE396A1F0C39D`;
the final headless executable SHA-256 is
`B92F4176B56824C870F4F92635C14A5EDA30EDBC28A3A468AD4BAB9A6B3DB71A`.
The receipts compare current input bytes, exact selected/terminal test names,
counts and executable hashes. The scoped commit requires an exact index check.

This batch does not implement account creation, pairing, migration UI or new
physical delivery. Native rendering, keyboard/accessibility acceptance and
cross-platform execution remain separate. P1-16 is OPEN and counts stay at
1,324 total / 1,010 complete / 312 open / 2 partial (313 pre-tag blockers).

Wave17 full CI [34777552729](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34777552729)
is running against its own exact published commit. That result cannot serve as
an exact-commit verdict for this subsequent consumer batch.
