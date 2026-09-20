# W113 — observed MCP and GUI fixture recovery

GitHub CI `35534405981`, source `7909081e`, macOS job `106140714937`
completed 16821 tests: 16818 passed (one reported leaky), three failed and 23
were skipped. This batch addresses the two observed fixture defects; generated
CLI-reference drift is handled by importing real source-bound binary output.

## MCP provider loop

The scripted first response contained literal backslash-n bytes around its
MCP fence. The real extractor therefore found no tool call and the loop exited
after one provider iteration. The fixture now emits actual newlines. Expected
two iterations, one actual selected external tools/call, its counter, normal
provider result, selected snapshot and exactly one untrusted sidecar assertions
remain in place. Production parsing, tool authorization and dispatch do not change.

Required identity:
`mcp::dispatch_loop::tests::w95_configured_read_path_provider_loop_uses_same_loaded_server_snapshot`.

## Native Buddy callback

The fixture intentionally writes invalid YAML to exercise unavailable readiness.
Its next real lifecycle write previously inherited that invalid file, correctly
failed before mutation, and could never produce the expected disabled status.
After the unavailable assertion, the test now restores its initial serialized
default configuration before the next real transaction. The unavailable case,
selected-root checks, actual callbacks, clear sentinels, revision fences and late
queued result checks remain intact. No production callback or config writer changes.

Required macOS identity:
`neothd-gui::neothd-gui-macos-native w58_gui_callback_runtime_tests::w58_buddy_status_callback_publishes_selected_root_readiness`.

## Evidence boundary

The exact observed failures and source changes are retained under
`work/gold-20260906/wave113-ci-regressions/`. Independent review approved both frozen source files.
The cumulative matrix already requires both identities; new execution must use
the repaired source. No local validation ran. No roadmap checkbox closes.
