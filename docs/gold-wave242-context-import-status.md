# W242 — Context Import status CLI

`neoth context import status` now uses the existing authenticated Connector-Control
RPC route `/cc/accounts/status`. It sends an empty request body and returns the
daemon-owned content-free account contract: connector identifier, lifecycle,
policy revision and lifecycle revision.

The slice adds no RPC transport, no daemon route, no Context Evidence read path,
and no local configuration fallback. A missing or unauthenticated Connector-Control
daemon remains an error. The command is available on the same Windows-only client
surface as `neoth context import plan` and `apply`.

The focused regression fixtures are:

- `cli::context::route_tests::context_import_status_parses_and_uses_the_existing_content_free_status_route`
- `cli::context::windows_tests::windows_context_cli_client_status_plan_apply_reopen_and_shutdown_are_bound_to_live_daemon` (`cfg(windows)`)

The current local BSOD hold prohibits local Rust formatting, compilation and test
execution. This source slice therefore remains pending the hosted Windows execution
receipt; it does not close `GOLD-CC-04` or add pause, resume, erase, GUI, or Buddy
coverage.
