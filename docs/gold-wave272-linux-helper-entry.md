# W272: Linux containment helper entry

The Linux manager-owned containment fixtures run their transient service with the
built `neothd-gui` product binary as `MainPID`. The test harness is never used as
the service helper because libtest runs fixture bodies from harness-managed
threads.

`LinuxChatUnitSetup::configure` has two deliberately separate helper resolution
paths:

- Production resolves and validates `current_exe()` as before.
- Linux test builds require `NEOTH_GUI_TEST_SYSTEMD_HELPER`. The value must name
a nonempty executable that passes `validate_linux_executable`; a missing,
empty, malformed, or non-executable value is returned through the existing
containment-availability error path. Required hosted fixtures therefore fail,
while optional local fixtures retain their existing capability-unavailable
policy.

Both paths pass the same private launch frame to `systemd-run` and invoke the
helper with only `--neoth-internal-chat-service-v1`. The production binary
intercepts that flag in `main.rs` before tracing, Slint, or GUI initialization,
then executes the unchanged `linux_manager_helper_main` containment sequence.
No test-only shell wrapper, libtest entrypoint, namespace setting, or systemd
unit property is introduced.

The hosted W228 lane builds the production `neothd-gui` binary once before its
selected test harnesses. It derives the canonical executable path from Cargo
JSON output, records source HEAD, path, SHA-256, and byte count in
`contained-gui-helper.json`, stores the path separately, and applies the
narrow temporary AppArmor profile to that exact executable. The exported helper
path is shared by both binary and public-API harness executions.
Implementation and independent static review are complete; hosted fixture
validation remains pending. No local executable validation ran under the BSOD hold.
