# W363 nightly vault-backup caller acceptance

W363 closes one narrow test gap in the existing P2-03 vault-mirror source: the
real bare-remote fixture had exercised the durable core directly, while the
public nightly entrypoint itself had no matching hosted fixture.

`run_nightly` now delegates its existing default-off policy gates to one small
dispatcher. Production still passes no injected remote, so it retains the
validated configured-remote route through `run_impl`. The test-only helper
passes a local bare remote only after the same `enabled` and
`allow_nightly_push` decisions have admitted a run.

Focused hosted fixtures:

- `daemon::vault_mirror::tests::nightly_entrypoint_default_off_and_without_permission_create_no_mirror_state`
- `daemon::vault_mirror::tests::nightly_entrypoint_uses_durable_push_and_exact_head_verification`

The first proves both denied states leave a missing home absent. The second
creates a local bare remote, WAL fixture, and credentials sentinel, then
proves a verified receipt, the actual archived WAL bytes, the absence of a
`credentials.yaml` archive member, persisted settled state, and a receipt
commit bound to the exact remote branch head.

This does not alter nightly policy, production transport, retention, CLI,
Buddy, GUI, or roadmap state. It does not close P2-03: GitHub-hosted
compilation and the named fixtures remain required, together with the broader
P2-03 acceptance and release evidence.

No local compiler, parser, formatter, test, Git child, archive, or network
operation was run under the BSOD hold.
