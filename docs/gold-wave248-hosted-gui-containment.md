# W248 — Hosted Linux GUI containment recovery

GUI123, run `35800209653` at source `a7f3e225a73744639367b2e7a4f5bd73bef8fe4c`,
executed 123 exact GUI fixtures. 121 passed; W153 and W164 failed. This is a
hosted-runtime recovery note, not an acceptance claim.

W153's bounded fixture diagnostic reports
`NEOTH_GUI_CONTAINMENT_SYSTEMD_USER_MANAGER_UNAVAILABLE` before its fake shell
writes `shell-entry`. W164 reports
`NEOTH_GUI_CONTAINMENT_SERVICE_FAILED` with `load=loaded, active=inactive,
sub=dead`, also before the fake provider starts. The first is a user-manager
availability failure. The second proves that a manager accepted a unit but not
why the request guardian terminated; it must be diagnosed from subsequent
manager and journal evidence.

The Linux child supervisor does not permit a process-group fallback. It invokes
trusted root-owned, non-group/world-writable `/usr/bin` or `/bin` systemd tools,
creates a `systemd-run --user` notify unit, verifies its cgroup and process
contract, then requires a guardian to enter user, cgroup, mount and PID
namespaces before it sends READY. The workflow first adopts a usable runner
session. When none exists, it starts the runner's system-managed
`user@UID.service`, which owns `/run/user/$UID`, the standard user D-Bus socket,
and the `systemd --user` manager. It does not create private background
servers or terminate runner-managed processes.
Its bounded preflight calls `systemd-run --user` with `DBUS_SESSION_BUS_ADDRESS`
removed, matching the supervisor's XDG-runtime-bus launch behavior, and probes
manager plus user/cgroup/mount/PID namespace capability. This is not complete
notify/guardian acceptance: the W153/W164 fixtures provide that proof. It sets
`NEOTH_GUI_REQUIRE_SYSTEMD_CONTAINMENT_TESTS=1` so unavailable containment is
fatal in the provisioned hosted lane.

On a fixture failure the lane records a bounded user-manager state, failed and
remaining `neoth-gui-chat-*` units, and the last 160 user-journal entries. The
next hosted run must show whether W164 reaches the fake shell or provide this
specific guardian/manager evidence. No source containment rule, fixture
assertion, or fallback was weakened.
