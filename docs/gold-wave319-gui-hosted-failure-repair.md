# Wave 319: GUI hosted failure repair

GUI129 source `d6da730098d792a758e1b01fb9ea7049aaad8564` ended with four failures: W153, W164, `linux_manager_stop_reaps_setsid_and_double_fork_tree`, and `linux_gui_crash_kills_complete_manager_unit`.

The W314 terminal diagnostics showed `load=loaded, active=inactive, sub=dead`, `result=success`, `exec_main_code=0`, `exec_main_status=0`, and an empty `status_text`. W153 additionally captured a later guardian-side `publish provider readiness: Broken pipe`; W164 and the direct containment fixtures had empty test-only `systemd-run` stderr. In the same receipt, the r12 parent-death unit reached `Started` before its fixture intentionally exited, whereas the ordinary r11 unit did not.

The supervisor had treated every loaded inactive snapshot as terminal before checking whether the main service process had ever started. This permits the initial queued `loaded/inactive/dead` observation to make activation call its own cleanup path; that stop closes the guardian readiness reader and explains the subsequent Broken Pipe without showing a containment failure.

The repair requests `ExecMainStartTimestampMonotonic` with the existing bounded systemd snapshot. A loaded inactive unit remains pending while that optional timestamp is zero or unavailable. A `failed` unit, or an inactive unit with a nonzero main-process start timestamp, remains terminal and preserves the detailed W314 error. `active/running` remains the only accepted state and still runs the existing exact unit/cgroup contract verification before acceptance. `systemd-run` exit and the existing timeout remain fail-closed.

The deterministic parser fixture now covers the state sequence initial inactive -> activating -> active/running, plus a started-then-inactive terminal unit and a failed unit. It also retains the legacy snapshot fallback. The W311 fixture marker reset and owned-child cleanup waits remain present; no new `main.rs` fixture change is required.

The supported fullCI750 cleanup removes the redundant `unsafe` around `libc::WEXITSTATUS` in the adversarial containment fixture. No local Cargo, compiler, formatter, parser, GUI, or runtime execution ran under the BSOD hold. Hosted validation remains required for the four GUI fixtures and the lint gate.