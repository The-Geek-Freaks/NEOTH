# W250 — Hosted Linux user-namespace UID-map diagnosis

GUI124, hosted run `35803340455` at source
`ea43839c701cf334d43d546eb9b3a7124b0dd43e`, completed the W248 user-manager
setup: UID 1001 had a running user manager, a standard D-Bus socket, and an
owner-only `/run/user/1001`. No compilation, fixture discovery, or fixture
execution began because the containment preflight failed first.

The bounded preflight transient unit `run-u0.service` failed after
`/usr/bin/unshare --user --map-root-user ...` reported
`write failed /proc/self/uid_map: Operation not permitted`. This establishes a
UID-map failure at that probe. It does not establish its kernel or AppArmor
cause: the receipt did not yet contain the relevant sysctls, AppArmor state, or
kernel journal records.

The probe's `--map-root-user` mode was also not faithful to the GUI guardian.
The guardian calls `unshare` for user, cgroup, mount, and PID namespaces; it
denies setgroups, then writes a single identity-preserving map of
`UID UID 1` and `GID GID 1`. W250 requires util-linux support for
`--map-current-user`, records its hosted help output, uses that mode with
`--setgroups deny`, and prints the resulting `uid_map` and `gid_map`. The
transient service still uses the manager, `Delegate=no`, cgroup kill policy,
`NoNewPrivileges=yes`, and the standard XDG D-Bus route after the explicit D-Bus
variable is removed.

On readiness failure, W250 records bounded read-only values for the userns and
AppArmor sysctls, AppArmor status when available, and filtered kernel and system
journal records. It changes no sysctl or AppArmor policy. The probe remains
fatal, while W153 and W164 remain the required actual notify/guardian acceptance
proof; a successful preflight is not an acceptance claim.

If the next receipt specifically proves Ubuntu's AppArmor user-namespace
restriction, a later change may consider a temporary policy scoped to the real
compiled GUI fixture executables. The source resolves the helper through
`current_exe()`, so the binary fixture and any hashed integration-test executable
must be identified before such a policy could be justified. Broad host policy,
global AppArmor/sysctl changes, and a policy for `/usr/bin/unshare` are not
supported by this evidence.
