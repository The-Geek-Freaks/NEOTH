# W184 — opt-in Git WAL backup mirror

The backup mirror now has one shared backend for the reload-aware daemon
cadence, `backup mirror`, Buddy, and the GUI status/repair action. It creates a
WAL-inclusive archive without credentials, writes through retained private
file/directory handles, and uses a contained Git child with a retained working
directory. Nightly and manual publication each require their own default-off
permission. See [operator behavior](vault-mirror.md).

Before any push, the exact commit intent is durably stored. An interrupted or
unknown push blocks new runs; repair checks the exact remote ref without
replaying a push. A non-push run stores a Prepared archive without starting Git.
A later run may replace that pre-effect preparation. A kernel-exclusive lock
on a permanent inode is released when its owning process crashes. Blocking
workers retain the lease until completion even if their async caller cancels.

Explicit retention creates a second ordinary commit and its own durable intent.
Only receipt-backed manifest leaves are removed. Unrelated children, remote
refs and Git history objects are retained. Cleanup records do not count as
backups; immediate completion and repair share the same state settlement.
Persisted states are bounded and validated before reading and writing.

The GUI requires a typed repair acknowledgement and a fresh matching status
before reporting success. Its real callback fixture is registered for Linux
and the macOS custom harness; Windows keeps the common parser/reducer checks
and its native retained-CWD fixture as separate evidence.

The independent review and source freeze are retained under
`work/gold-20260906/wave184-vault-mirror/`. This is source review, not runtime
acceptance. Required Hosted fixtures cover real bare-remote archive/push/repair,
multiple retention rounds, uncertain-push replay refusal, Prepared retries,
corrupt state, fetched symlinks, lock release, configuration, and GUI behavior.
GOLD-LF-P2-03 remains open until those exact-source checks pass.

This publication also repairs the two strict-Clippy diagnostics from CI
`35674687864` on `a666a2c9`: the explicit post-WAL terminal function has a
documented argument-count allowance, and the duplicate feedback-target guard
uses the equivalent let-chain. Neither diagnostic changes runtime behavior.
The same source passed core test typechecking and CLI build in `35674232090`;
the full CI and Windows preview retain their own original source identities.

No local compiler, parser, formatter, fixture, product runtime or test ran.
All executable verification remains on GitHub because of the workstation's
reported BSOD history. No Road checkbox is closed by this publication.
