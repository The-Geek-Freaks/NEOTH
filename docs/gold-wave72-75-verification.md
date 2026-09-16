# W72-W75 - reviewed consumer and CI batch

Update: the first full remote run on `669e38c0` failed in Linux Clippy and
GUI test compilation. The four-file repair, original errors and renewed
validation boundary are documented in [W76](gold-wave76-verification.md).
The W72-W75 manifest and matrix below remain the original source snapshot;
their pending status is historical, not a later passing result.

Status on 2026-09-16: **static review and lightweight checks passed; GitHub-hosted
compilation and runtime acceptance pending**. No local heavy Rust build was
started for this batch after the repeated host crashes.

## Implemented source changes

- Self-improvement QA uses private versioned JSON data for candidate diff,
  verification output and typed analysis. The sub-agent runtime supplies the
  sole outer prompt boundary.
- macOS CI records bounded memory, swap and compiler-process diagnostics and
  uploads them on failure while preserving Cargo's exit status, time limits
  and full test graph. The exact paired cadence contract passes seven tests.
- Buddy callbacks use the real CodingService with source channel `buddy`.
  Cancellation publishes failure activity; queued terminal callbacks must
  still own the current UI revision before changing presentation.
- Chat and Channel create one canonical retained code-map binding before the
  provider and reuse it for final-result provenance without a later database
  reread to infer the accepted request.
- The fallback acceptance seam is crate-private, per-call and `cfg(test)` only.
  Production uses its normal loader. Tests assert actual request counts/context,
  retained/final binding, final-body hash/length and receipt/terminal/egress
  ordering through real consumers with injected capturing providers. They do
  not establish live external-model success.

The provider cap remains **three calls total including the initial call**.
Chat tests initial refusal, truthful retry and local-shadow final: no dispatch
budget remains for cloud continuation. Channel disables reframing and tests
initial refusal, local shadow and cloud continuation. Independent review
rejected the earlier impossible four-call expectation; no production guard
was relaxed to make these tests reachable.

## Current evidence

Nine manual owners and two documentation updates were prepared from W70/W71
commit `c1f34a27f53fc75530620a50d61fc9b0aa20e759`. Original source, raw proposal,
formatted result and independent review hashes were checked before copying.
W75 retains five original actual anchors separately from three W74 upstream
proposal anchors. The paired Python contract was normalized to LF while its
approved raw mirror was retained.

The [source manifest](verification/gold-wave72-75-source-manifest.json) covers
279 scoped inputs. The [test matrix](verification/gold-wave72-75-test-matrix.json)
records 42 required native identities and 5 GUI identities as **pending**.
Inherited W70 runtime passes belong to that prior source, not this new batch.

| Check | Outcome |
| --- | --- |
| Independent source reviews | APPROVE for all nine owners |
| Focused rustfmt | PASS, seven Rust files, no compilation |
| Python contracts | 45 passed, including seven paired CI tests |
| Windows/macOS CI matrix | PASS |
| GUI source lint | PASS; no runtime or visual claim |
| Native/GUI compile, behavior and Clippy | Pending GitHub-hosted CI |
| Installed package, visual/accessibility and delivery | Not established |

The full [CI workflow](https://github.com/The-Geek-Freaks/NEOTH/actions/workflows/ci.yml)
validates the reviewed `main` commit, including W70's remaining GUI/full-platform
gates. Its exact run and commit are recorded in the local publication receipt
when dispatched. Release readiness stays false until required remote and
artifact acceptance gates actually pass.

Roadmap counts remain 1324 total / 1015 checked / 307 open / 2 partial
(raw unchecked 309, pre-tag open 308). No acceptance box closes on this handoff.
