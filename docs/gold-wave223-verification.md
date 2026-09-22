# W223 — Hosted slim-core Clippy corrections

Full CI35782661515 on74334d4b passed formatting but stopped its Linux quality
job106931734757 at `cargo clippy -p neoth --lib --bins --no-default-features
--locked --no-deps -- -D warnings` with nine diagnostics. Other native jobs
continue; they are not cancelled or credited with the later changes.

The correction is limited to four existing source files:

- Credentials: three redundant `then` closures become direct `open_store`
  function references. The custody inspection helper is compiled for tests,
  its only callers.
- Counterparty receipts: the local/channel convenience parsing wrappers are
  compiled for tests. Production retains the canonical `parse_origin_receipt`
  dispatch and strict typed receipt parsers it uses.
- Embeddings: the unused Episode wrapper scope and scoped test entrypoint are
  compiled for tests together with their match/control branches. Production
  consumers use the retained MediaModel scope. Existing production local
  generation-bound embedding APIs remain intact.
- Consent ceremony: the Grant match arm returns its `Ok(reservation)` value
  directly after commit.

No lint level is relaxed; no production dead-code allowance is introduced.
The callsite search and scoped diff check are static evidence. Hosted slim
Clippy, full workspace compilation and tests remain required for current source.
No compiler, formatter, code parser, test or product runtime ran locally.

## Existing validated behavior

Grouped272 run35782455869 on35c410a8 passed all272 exact tests. Admission checked
56 source identities, matrix and Cargo.lock against Git objects, selected and
executed names, one successful result terminal per case and empty failed-case
receipt. The production aggregate rollback regression is therefore behaviorally
confirmed. This evidence does not cover later W220/W222 fixtures or W221 denial
receipt work. Canonical Road counts remain1015 checked/307 open/2 partial.

Independent bounded source/callsite review PASS; fresh Hosted slim-Clippy
acceptance remains pending.

The existing CLI-reference Hosted workflow now accepts optional
slim_clippy=true and runs the exact full-CI slim production command before
its normal typecheck/build/export. This gives W223 a focused recheck while
native Windows/macOS continue. It is not a release-CI substitute. Independent
text review passed; no local workflow parser or compiler ran.

Focused slim run35784699877 on48c08050 reached one E0282 after the test-only
Episode arm was gated out: the remaining MediaModel tuple needed an explicit
Option type. None::<&str> now matches the Episode branch generation.id() type.
Source correction only; the exact Hosted slim command must be rerun.

## Hosted acceptance 2026-09-22

Run `35785793542` on `c42038984897887c435c82536dd5557ed65dc0a8`
passed the exact slim-core production Clippy command, core test-target typecheck,
public CLI build and reference export. The generated reference artifact's
source-head and SHA-256 are verified; its bytes match the committed
`docs/cli-commands.md` snapshot. This confirms the W223 repairs including the
explicit `None::<&str>` type. The still-running native full CI on `74334d4b`
remains an independent older-source Windows/macOS evidence boundary.