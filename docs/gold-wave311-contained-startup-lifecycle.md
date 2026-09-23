# Wave 311: hosted GUI contained-startup lifecycle repair

## Hosted failure boundary

Hosted run `35826461386` bound `424678f2b2dbcf5c4c7d6b671d27dcd5ec7ed07b` completed 128 planned GUI fixtures: 125 passed and three failed. The passing manager-stop fixture exercised the real request-owned systemd unit, private cgroup/PID/mount/user namespaces, provider capability clearing, public-cgroup mount attacks, and tree reaping. Wave 311 therefore does not weaken containment or reclassify the manager as unavailable.

The failed W153 and W164 GUI fixtures each showed a Main request that reached `Started` followed by a Buddy request that reached `reasoning-written` and then saw its transient unit as `loaded/inactive/dead`. The receipt journal records the second unit being stopped before its activation poll could accept it. W153 reused its fixture `release` and `started` files between loop cases, allowing the next provider to exit immediately. W164 advanced from the first surface as soon as its UI target was projected, while the prior manager-owned child could still be retained by the worker cleanup path.

## Repair

The fixture now resets the provider-lifetime markers, sealed envelope, and call log before every W153 case. Both W153 and W164 wait for the exact supervised child slot to be empty before beginning a subsequent lifecycle step. This preserves the production requirement that the child remains owned until the manager confirms the whole tree is empty; the repair changes only test sequencing and diagnostics.

## Validation boundary

The third failure, `linux_gui_crash_kills_complete_manager_unit`, remains
unresolved. Its nested parent-death fixture's unit stopped before readiness;
the current evidence does not establish the cause. This batch does not change
the supervisor or claim the crash-tree test is repaired.

The workstation is under the BSOD hold. This wave used text, Git, and source edits only; it intentionally did not run Cargo, Rust tooling, local tests, GUI code, or runtime processes. Hosted rerun evidence is required to close Wave 311.
