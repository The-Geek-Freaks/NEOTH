# W120 — observed Linux MCP and Buddy completion regressions

Linux job 106152819746 in CI 35538895227 tested source 78a4229f. Strict
Clippy and doctests passed. Nextest executed 16850 tests: 16848 passed,
two failed and 20 were skipped. Those results do not validate the later
W115–W119 source. The two failures were retained and diagnosed separately.

The configured ReadPath provider-loop fixture reached the second provider
turn with a successful real tool call. Its ordinary-result assertion expected
raw inner JSON, while the actual untrusted-context prompt serializes that
content with escaped quotes. The corrected assertion requires the entire
contiguous escaped fixture-result payload. The two turns, exact server/tool,
ordinary result and single provenance sidecar assertions remain required.

The Buddy failure exposed a product race. A fast provider could complete and
release controller ownership before the queued start callback displayed its
Run ID. The correctly accepted terminal callback still displayed completion,
leaving the visible ID empty. The terminal callback now publishes that same
accepted Run ID behind its existing completed-run and current-UI-revision
checks. The initial callback's ownership fence and the original failing
identity/provenance assertions remain intact.

Required existing remote regression identities:

- mcp::dispatch_loop::tests::w95_configured_read_path_provider_loop_uses_same_loaded_server_snapshot
- w58_gui_callback_runtime_tests::w73_buddy_start_reaches_real_provider_worker_and_commits_terminal_provenance
- w58_gui_callback_runtime_tests::w73_queued_late_terminal_bridge_callback_executes_and_revision_gate_rejects_it

Independent source review approved both repairs. Fresh GitHub execution remains required.
No local compiler, formatter, parser, tests or product execution ran. No
roadmap or release acceptance is inferred from the repair source.
