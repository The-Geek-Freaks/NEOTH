# Gold Wave 15 — account maps and recovery

**Receipt status:** **Locally accepted.** Sixteen source files implement the
Wave 15 P1-16 slice; Rust, documentation and inventory checks pass.
This is not a full-CI, cross-platform, GUI-link, or macOS-runtime acceptance.

## Implemented contract

Telegram configuration and credentials use matching account maps. Migration is
explicit, keychain-aware, and supports cleanup recovery. Per-account fleet and
reload paths own the resulting adapters. Flat Telegram outbound paths and CLI
legacy mutations are guarded while maps are active. The macOS recall repair
derives display home from the bound physical parent and retains `NOFOLLOW`;
fixture and scan repairs accompany it. P1-16 remains **OPEN** for its remaining
account configuration, credential, routing, and outbound-delivery surfaces.

## Final Rust evidence

| Gate | Result |
| --- | --- |
| TestBuild02 | **PASS** — 3m56s; 195.89 GiB minimum free; 10.40 GiB peak |
| SelectedFINAL | **PASS** — 1,119/0/0 in 40.34s; catalogue 14,324 |
| AccountConfigContracts (13 targets) | **PASS** — 156/0/0; build 5m14s; 196.16 GiB minimum free; 10.80 GiB peak |
| Clippy03, post delta | **PASS** — 3m01s; 199.45 GiB minimum free; 6.49 GiB peak |
| Formatting, GUI lint, GUI self-test | **PASS** |
| Python integrity / roadmap release gate / release evidence contract | **PASS** — 19 / 11 / 8 tests |

Fresh binary SHA-256:
`092543A364567956CC48C8255E3FEAC4C255F2DEC603DF40A201FA1958FBD805`.

The 89-input source and 14-executable test receipts are
[`gold-wave15-source-manifest.json`](verification/gold-wave15-source-manifest.json)
and [`gold-wave15-test-matrix.json`](verification/gold-wave15-test-matrix.json).
They were built from fresh logs. Every selected test name matches the fresh
catalogue and has a verified terminal result; CLI stdout may interleave without
changing those terminal results.

## Review and retained history

Independent account/migration review is **APPROVE**. The macOS repair review,
corrected Linux three-site delta, and test-fix review are **CLEAR**. The final
delta retains `AuditEndpointV2` all-test re-export cfg, GUI wrapper cfg(test),
and an inline closure after an earlier proposal wrongly removed test-used
surfaces.

Core02's earlier **PASS** (1m43s; 201.10 GiB minimum free; 7.44 GiB peak)
preceded the test-only fixture correction and final Linux/GUI delta; TestBuild02
and Clippy03 provide the later evidence. Selected01 initially found three new
flat-guard fixture defects: `emptyCredentials` expected an omitted file and
`to_string` hid a context cause. The narrow repair preserves the Discord
sentinel file/byte guard and complete `anyhow` chain with exact guard text.

## Remaining gates

Current-head full CI has not run. The older Wave 14 CI `34766600264` retains
three Linux lint failures repaired in this batch.
Windows `103748563885` succeeded on full-workspace nextest; macOS
`103748563923` remains running. A replacement manual CI is deferred until that
macOS evidence is terminal. No full-CI-green claim follows.

Roadmap counts remain 1,324 total / 1,010 complete / 312 open / 2 partial
(314 raw; 313 pre-tag blockers).
