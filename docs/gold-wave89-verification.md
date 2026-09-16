# W89 - native macOS callback test entry and W88 Git fixture correction

The five generated-Slint callback fixtures need a native macOS process main
thread. Ordinary libtest runs test functions on test threads. W89 adds a
feature-selected custom Cargo test target using the existing GUI source, with
an explicit entry that implements the
[Nextest custom-harness protocol](https://nexte.st/docs/design/custom-test-harnesses/).
Each selected fixture retains its real generated window, registered callbacks,
loopback provider, CodingService, event loop and provenance/cancellation checks.
No testing-backend substitution or dependency/lockfile change is introduced.

The custom entry and helpers are test-only. The feature cannot import development
dependencies into the normal application. The custom executable also intercepts
non-macOS invocations, including an all-features build, so it cannot fall through
to application startup. Windows and Linux retain their ordinary five fixture
registrations; the sixth controller fixture remains in its original GUI and core
integration-test targets.

Only macOS CI enables `neothd-gui/macos-native-gui-test` for compile, discovery and
execution. Structured Nextest discovery binds the five names to their custom
binary and preserves the ordinary controller copies. Missing or duplicate
ownership must fail before execution. Fresh macOS JUnit must then prove actual
execution under the custom binary's identity; listing alone is not acceptance.

The [source manifest](verification/gold-wave89-source-manifest.json) retains the
prior committed source bindings and records the changed/new inputs, 291 total.
The [test matrix](verification/gold-wave89-test-matrix.json) requires 49 native
and 6 GUI identities, with five explicit macOS custom-target class overrides.

This batch also corrects the W88 history fixture's initial fast-import parent to
`{head_ref}^0`, as specified by the
[Git fast-import reference](https://git-scm.com/docs/git-fast-import). A bounded
Git-only probe in two isolated WORK repositories reproduced the former self-parent
failure (exit 128), then confirmed the corrected 201-commit chain, author counts
67/67/66 plus the baseline, and a clean checkout. Both probes together took
2,671 ms. The subsequent 199 mark references and production risk-receipt behavior
are unchanged; this does not substitute for the Rust fixture's remote execution.

Following the further confirmed restart at 14:31 local time, all local validation
is suspended, including rustfmt, Python/PowerShell tests, Git fixtures and product
or GUI probes. The Git-only result above predates that restart and is not permission
to repeat it. A recovered independent source review approved all five hash-bound
W89 files without running local validation. The next immutable GitHub source must
pass formatting, contracts, compilation and the complete test matrix before
runtime claims. The updated host restriction is recorded in the build cadence.
No roadmap checkbox closes: 1324 total / 1015 checked / 307 open / 2 partial,
raw309 / pre-tag308. The older W86 portable preview remains a separate snapshot.
