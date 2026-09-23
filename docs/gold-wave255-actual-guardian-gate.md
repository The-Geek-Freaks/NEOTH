# W255 — Hosted actual-guardian containment gate

GUI124D731, hosted run `35805521658`, loaded the W252 temporary AppArmor
profile without a matching AppArmor denial. Its util-linux proxy still failed
before compilation when writing `/proc/self/setgroups` with `EPERM`. That proxy
is not the product guardian: it implements its own user-namespace setup and
therefore adds a third synthetic implementation after the earlier root-map and
current-user-map probes.

The product guardian already provides the required acceptance path. It calls
raw `unshare` for user, cgroup, mount, and PID namespaces, writes `setgroups`,
then identity-preserving UID and GID maps, creates its PID guardian, and sends
systemd READY only after that guardian is ready. W153 and W164 are selected
mandatory fixtures for this Hosted lane. With
`NEOTH_GUI_REQUIRE_SYSTEMD_CONTAINMENT_TESTS=1`, containment unavailability is
fatal in that real path.

W255 retains the fatal manager readiness requirements: an owned standard user
runtime directory and D-Bus socket, a reachable user manager, trusted systemd
tools, and the existing cgroup/systemd session setup. It removes only the
synthetic util-linux namespace command as a prerequisite. After each exact
harness compiles, W252 still loads a temporary AppArmor profile for the exact
Cargo JSON-reported executable; the source resolves the helper with
`current_exe()`, so the manager-owned re-exec uses the same attachment.

Fixture failure now records bounded userns/AppArmor state before the existing
manager, unit, and journal snapshot. This preserves a direct diagnostic if the
actual guardian's `setgroups`, UID map, GID map, cgroup, mount, PID, or READY
steps fail. No production containment code, fixture selection, AppArmor global
policy, or sysctl is relaxed. A successful manager preflight remains only a
prerequisite; W153/W164 must pass before this lane can be accepted.
