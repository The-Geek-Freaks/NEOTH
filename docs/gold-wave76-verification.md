# W76 - CI fixture repair and remote Windows preview

Status on 2026-09-16: **focused review and lightweight validation passed;
repaired-source GitHub compilation and behavior gates are pending**.

The first full [W72-W75 CI run](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35065955859)
used exact commit `669e38c0bcee4a57e0b4961909ec3b0b4cdf6fda`. Linux quality failed
on three private GUI enum paths, a private test-only controller constructor,
two fallback-fixture mutex-guard scopes and one compressed adjacent `if`.
The beta job also found the GUI visibility errors. Ten independent jobs had
passed while Windows and macOS test compilation was still running. An uploaded
cached test report is not accepted when its producing test step did not run.

## Changes

- GUI fixtures now use public `cli::init::ProviderKind`; the injected controller
  constructor remains `cfg(test)` and only becomes `pub(crate)`.
- Chat and Channel fallback assertions end mutex guards in lexical blocks
  before WAL drain awaits. The channel scan has readable independent event
  conditions. Request, binding, body-hash and delivery-order assertions and the
  three-call provider cap remain intact.
- The previously reviewed Windows installer smoke checks the actual installed
  code-map lifecycle, paths containing spaces, separate roots and corrupt
  refresh behavior. Its process helper drains both streams and bounds waits.
  This commit adds source-level coverage; it does not claim an installed pass.
- A manual GitHub-hosted Windows x64 workflow builds the locked desktop CLI,
  GUI, migration, relay and Keet payload with one Cargo job. It stages only new
  contained outputs, adds full commit provenance and SHA-256 inventories, then
  uploads an unsigned portable ZIP and checksum for seven days. It creates no
  tag, release, installer or fabricated self-knowledge snapshot. Push preflight
  invokes its lightweight contract through the explicit command allowlist.

## Evidence and remaining gates

The [source manifest](verification/gold-wave76-source-manifest.json) records
281 inputs. The [test matrix](verification/gold-wave76-test-matrix.json)
binds all 42 native and 5 GUI required identities to the repaired sources,
review hashes, original failed CI log and fresh lightweight checks.

| Check | Result |
| --- | --- |
| Independent four-file Rust repair review | APPROVE, static scope |
| Preview workflow and installed-CLI source reviews | APPROVE, static scope |
| Python/source contracts | 54 passed, 0 failed |
| Focused rustfmt | Four changed Rust files passed; no compilation |
| GUI source lint | PASS; runtime/visual acceptance remains separate |
| Installed smoke PowerShell parser | PASS; no installer executed |
| Repaired native/GUI compile, Clippy and tests | Pending fresh GitHub CI |
| Portable preview build and downloaded-binary acceptance | Pending |
| Installed-product and visual/accessibility acceptance | Not established |

The original preflight contract correctly rejected an unlisted new preview
check. Adding that exact stdlib-only command to the existing allowlist made
the paired seven-test cadence contract pass; the compiler-denial guard remains.

Heavy Rust compilation on this workstation remains suspended after repeated
unexpected restarts. No new local Cargo build, test compilation, Clippy or
linker ran for W76. Release readiness is false. ROAD counts remain
1324 total / 1015 checked / 307 open / 2 partial (raw309, pre-tag308).
