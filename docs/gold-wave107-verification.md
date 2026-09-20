# W107 — repair observed CI and portable-preview regressions

This batch continues the reviewed W105 source at
`6a37557357b8758f5f826a9f7e655ddca0823110`. Its exact Preflight
[`35117162317`](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35117162317)
and Code Quality
[`35117157860`](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35117157860)
passed. Those static results do not establish native runtime or package acceptance.

## Actual remote failures

The completed full CI
[`35113128375`](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35113128375)
ran the earlier `5e353a168db45234383cfbf735c7835a9ef17300` source:

- macOS executed 16810 tests: 16805 passed, five failed; 23 were skipped.
  The failures were the W95 direct-CLI selected read, W97 negative selected read,
  configured-selector validation, W95 isolated provider loop, and the shared GUI
  impact/lifecycle identity fixture.
- Windows exhausted the 50-minute test-compilation step. It saved an interrupted
  target cache and never ran Nextest. There is no new Windows runtime result.
- Linux failed strict lint on three test-only wrappers already corrected by W103.
  Its uploaded cached JUnit is rejected because this job did not execute Nextest.

The earlier-source Windows preview
[`35113132073`](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35113132073)
completed all native builds, the Keet companion and ZIP staging. Actual lifecycle
acceptance then rejected the initial absent-status response: stdout began with
the tracing startup banner before the JSON document. Diff-impact acceptance and
the public preview-artifact upload were skipped. Receipt upload is not acceptance.

## Changes and regression boundaries

Both text and structured tracing now use stderr. Command results stay on stdout;
the portable helper continues to require a complete JSON document and does not
strip or ignore diagnostic lines. The real-binary regression
`w107_json_status_preserves_stdout_with_text_and_json_diagnostics` runs `neoth`
and compatibility `neothd` with default text logging and all three structured
format names (`json`, `jsonl`, `ndjson`). It requires valid absent-status JSON,
observable diagnostics on stderr, valid structured log lines, and no code-map
database creation.

The two direct-CLI tests had attempted to start the Rust test executable with
production `mcp codegraph-serve` arguments. They now use the existing real
codegraph NDJSON child at their already injected spawn boundary. They preserve
the exact selected/trusted snapshot, actual SQLite map, ordinary-result and
sidecar assertions. The isolated provider-loop test uses the existing external
NDJSON fixture for its selected server, while keeping the separate trusted
descriptor in the same snapshot. Its child counter must observe exactly one
call. The Python fixture is a CI dependency only; packaged NEOTH gains no Python
runtime requirement.

Configured-selector semantic bounds are checked through the production public
configuration parser. Raw Serde alone is not the semantic validation boundary.
The valid selector and invalid key/kind/path/duplicate/identifier/count/byte
cases remain required; production configuration validation is unchanged.

The shared GUI fixture now supplies the redacted `root_identity_sha256` used by
the actual lifecycle display. It additionally rejects the raw physical identity;
wrong-identity and wrong-root rejection remain required. Production identity
checks are unchanged.

Windows CI keeps one compiler worker, one test thread, locked workspace coverage
and the separate 30-minute execution window. Compilation receives 80 minutes
after the observed 50-minute timeout; the containing job receives 120 minutes
including a 10-minute setup/cache margin. Cache restoration is build input only.
The existing workflow-contract test checks the updated bounds.

## Evidence status

W107 was published as `08531fa33a2b85733ee3d5fb3d9bba5084dae838` after independent
source review. Code Quality `35532704376` passed. Preflight `35532704971`
requested only assertion layout changes in the configuration and shared GUI test
files; its exact Rustfmt output is applied in the follow-up without local
formatting or semantic changes.

The resulting commit `3922ee4b7c221028e7b101685d2423f27b109040` passed
[Preflight 35532847982](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35532847982)
and [Code Quality 35532847770](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35532847770).
[Full CI 35532960640](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35532960640)
and [Windows preview 35532961776](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35532961776)
were dispatched on that exact commit. Nine component jobs passed, including
actual-binary Gold smoke. Linux, Windows and beta GUI compilation failed on
undefined `Theme.surface-raised` and `Theme.space-2xs`; the SSH feature job
reported test-only `E0382` and `E0373` in `cli/mcp.rs`. Both runs are confirmed
cancelled after those failures. The remaining platform/portable result is not
acceptance. W109 corrects the four diagnosed source sites alongside W108;
that combined source needs fresh static, compile, native and portable gates.

W107 strict lint, compilation, native regressions and portable acceptance still
require fresh GitHub-hosted results. No local compiler, formatter,
parser, test, Git fixture, product binary or GUI was executed on the workstation.
The source manifest and required-test matrix retain separate source and execution
states. The selector test identity is corrected to the actual
`config::code_map_config_tests` module observed in the macOS run.

No roadmap checkbox closes. Counts remain **1324 total / 1015 checked / 307 open /
2 partial** (309 raw unchecked, 308 before the tag gate). Four obsolete W105 source
mirrors were deleted only after matching their published hashes and canonical
source; the formatting report, reviews and publication receipts remain available.
