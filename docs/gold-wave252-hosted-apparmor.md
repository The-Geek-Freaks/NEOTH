# W252 — Hosted Linux AppArmor user-namespace remedy

GUI1243FC, hosted run `35803931022`, proved the W250 cause rather than only a
symptom. The runner has `kernel.unprivileged_userns_clone=1`, while
`kernel.apparmor_restrict_unprivileged_userns=1`. Its kernel journal records an
unconfined `/usr/bin/unshare` transitioning to `unprivileged_userns`, followed
by AppArmor denial of `cap_sys_admin`; the identity-preserving UID-map probe
then fails with `EPERM`. Compilation, discovery, and fixtures did not run.

W252 keeps the product namespace contract and the fatal readiness probe. It
loads temporary, complain-mode AppArmor profiles only for `/usr/bin/unshare`
during the readiness probe and for the exact Cargo JSON-reported fixture
executables after they compile. Each profile explicitly grants `userns` and
`cap_sys_admin`; complain mode preserves the runner's previous ordinary file
access only for that exact executable during this short, runner-only test
scope. The profile is attached by exact executable path, so the systemd helper
reaches the same profile when the supervisor re-execs its `current_exe()` as the
manager-owned helper. Actual fixtures remain required to prove the behavior.

The workflow removes every profile it loaded through an EXIT trap. It makes no
global AppArmor or sysctl change and does not create a policy for a directory,
Cargo, or arbitrary executable. The exact executable path is bound from Cargo's
`compiler-artifact` JSON for `neothd-gui` or
`gui_chat_bridge_public_api`; ambiguous or missing output fails the lane.

The next Hosted run must still pass the real W153/W164 fixtures. A passing
preflight or profile installation is only a prerequisite and is not a
notify/guardian acceptance claim.
