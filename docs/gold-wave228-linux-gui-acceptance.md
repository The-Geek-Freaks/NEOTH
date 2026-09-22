# W228 — Focused, exact Linux GUI fixture execution

The existing full native CI compiles the complete workspace, including the
large core test harness, before GUI acceptance. The new manually dispatched
`gui-linux-fixtures.yml` provides a focused Linux receipt for the GUI cases
already required by the canonical matrix. It neither replaces release CI nor
cancels the Windows/macOS jobs in the existing full CI run.

The lane binds `requiredGuiClass` to `neothd-gui::bin/neothd-gui`, validates all
94 universal and 22 Linux test identities as unique exact names, verifies the
declared GUI source closure and source-manifest hash, and records the resolved
commit, matrix, Cargo.lock and GUI Cargo manifest. Source, log and receipt
artifacts retain these bindings with the dispatched source SHA.

The genuine `neoth` CLI and GUI binary test harness are built once with a
single Cargo build job. GUI dependencies and Xvfb follow existing Linux CI.
The core library is built as a dependency; the separate `neoth --lib` test
harness is not requested. Existing test-local staged CLI behavior is preserved.
Every selected case is discovered exactly once and then executed serially
under Xvfb. Success requires its actual one-test pass terminal with zero failed
and zero ignored tests.

The job retains a 90-minute limit with a shorter internal deadline and bounded
commands. Durable started/completed/executed/passed/failed checkpoints preserve
honest partial evidence. A complete receipt requires each ordered test list to
equal the exact selection and no failures. Missing, ignored, undiscovered,
interrupted or unexecuted cases cannot produce a green acceptance receipt.

Independent static review passed after correcting cold-build placement,
per-test terminal verification, receipt-error propagation and partial evidence.
Hosted execution remains pending. No local compiler, parser, formatter, test,
fixture, product or GUI execution ran under the BSOD hold. No Road checkbox
closes merely because this validation lane exists.
