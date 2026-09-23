# W260 — Preserve hosted test-helper startup diagnostics

GUI124D99, hosted run `35806202796`, executed all 124 exact GUI fixtures: 122 passed and two failed.
W153 and W164 each created their manager-owned transient service, but the test
helper exited 125 before provider launch. The temporary AppArmor profile had
matching `ALLOWED` records and no matching denial. The unit journal retained
only the service start and exit status, so it did not contain the helper's
already-produced error message.

The Linux test helper maps every `linux_manager_helper_main` error to stderr
and exit 125. W260 preserves that existing diagnostic only after an
`OwnedChatChild::spawn` activation failure in Linux test builds: after the
existing kill/wait cleanup, it changes the already-owned `systemd-run` stderr
pipe to nonblocking mode, performs one read capped at 4096 bytes, restores its
flags, and appends the result to the fixture-visible error. `fcntl` and read
failures are reported as diagnostic text but never replace the original
containment error.

This is compiled only with `cfg(all(test, target_os = "linux"))`. Production
does not read that pipe at activation time, and provider startup, containment
properties, fixture selection, and cleanup behavior are unchanged. The next
Hosted W153/W164 failures will therefore either include the precise guardian
failure or explicitly show that no helper stderr was buffered; neither outcome
is an acceptance claim.
