# W379 macOS GUI fixture repair

FullCI954 exposed two macOS-native GUI fixture defects in
`w58_gui_callback_runtime_tests`.

`w164_response_feedback_callback_requires_post_done_target_and_verified_readback`
uses an intentional macOS containment-refusal branch. That branch never
permits the response-feedback action, but the shared trailing assertion still
required the two-surface success-path CLI call counts. The fixture now asserts
that this refusal emits no response-feedback CLI action. The non-macOS-native
path retains every existing exact mutation/readback count, including its
post-done target, session, revision, single-flight, and foreign-target denial
checks.

`w155_citation_callbacks_bind_cache_and_live_consent_receipts` reached its
approved final lookup with `--gui-approval-stdin`, but the staged shell helper
used a `grep` option sequence to decide whether to copy private stdin to its
test marker. The helper now uses POSIX shell `case` matching for that argv
marker. It still records no proof in argv, accepts it only from stdin, and
retains the cache binding, preflight/decision receipt, historical read-only,
bounded-child-output, and stale-child-cancellation assertions.

This is static fixture evidence only. The two identities require a hosted
macOS FullCI rerun for runtime confirmation.
