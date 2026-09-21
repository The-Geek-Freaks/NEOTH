# W172 — exact Hosted test-compilation and lint repairs

GitHub CI 35653174520 on 61eaa58fc060d211e73e1535caf3dcd04b80d7f0
exposed two distinct failures before the complete native suites could run.

- The channel-adapters job 106510251649 reported four E0308 errors in the
  existing throughput producer test. W168 made the control token optional so
  daemon-GUI events can share the producer. The CLI test now explicitly passes
  `Some(token)` to its four calls, preserving its token-bound frame assertions.
  Production call sites already pass the optional token.
- Linux quality job 106510251267 passed workspace formatting and slim-core
  Clippy, then rejected an unfulfilled `expect(dead_code)` on the public
  `gui_action` module imported by the impact-controller integration test.
  The obsolete expectation is removed. No lint is suppressed or disabled.

The source-bound logs and independent review are retained under
`work/gold-20260906/wave172-hosted-repair/`. These changes require fresh
GitHub compilation and test execution. They do not establish native, GUI,
portable, or release acceptance and close no Road item.

The unaffected Windows preview 35653179383 remains a separate source-bound
run. The small cadence-only correction 9c2a4215 passed Preflight 35653959335
and Code Quality 35653958110 before these Rust test repairs.

No local compiler, formatter, tests, fixtures, or product execution ran.

## Follow-up on 6c69ce79

The channel-adapter lane in CI 35655045794 passed after the four token fixes.
Linux quality reached a different headless target, `gui_channel_status`, whose
import of the desktop `gui_action` module leaves four production Q8 executor
symbols unused. A `dead_code` allowance is limited to that test-only import
and explains the absent desktop consumer. Product GUI linting is unchanged.

The beta workspace build also exposed four actual E0277 errors in the new
recall-chip projection: a `Vec<SharedString>` does not implement conversion to
Slint's `ModelRc`. The two clearing and two populated Main/Buddy assignments
now construct the existing `VecModel`/`ModelRc` representation. Recall
lifecycle fences, line content and callback ordering remain unchanged.

Full CI 35655045794 and Windows preview 35653179383 are confirmed cancelled.
The preview's GUI source was byte-equivalent in Git to the compiler-failing
source before cancellation. Both require fresh execution after publication.
Retained logs, source freezes and root integration review are in the same W172
evidence directory. No result from these failed/cancelled runs closes a Road
item or establishes release acceptance.

## GUI test compilation follow-up on cc0af938

The beta workspace job 106526765152 in CI 35658155763 now reaches GUI
test compilation and reports eight errors: two missing clear-helper imports,
four ModelRc emptiness checks and two ModelRc indexed reads. The production
recall-chip assignments are no longer the reported failure. A narrow test-only
repair imports both helpers and uses Model::row_count/row_data; explicit row
existence and all original content/state assertions are preserved.
The retained job log is fullci-cc0a-beta.log in the W172 evidence directory,
SHA-256 7E5F94BD1010323FF0F588B7C930A65B296E18AC0D14A40594F68D4BC71445C9.
Linux stopped on the six formatting hunks already fixed by fc3767f3; Windows
and macOS compilation and the separate Windows preview remain in progress.
