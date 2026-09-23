# Gold Wave 317 - live egress wrapper lint repair

Hosted slim Core run `35831257004` failed with exactly two diagnostics under
`-D warnings`: `dead_code` for
`emit_account_bound_egress_intent` and
`emit_account_bound_egress_result` in `channels/send_gate.rs`.

W310 moved every production mapped-Telegram live-delivery call to the
session-aware `*_in` functions. The two parameter-only wrappers retain the
legacy `None` session mapping for direct send-gate fixtures, and a repository
caller search found they are used only in that module's tests. They are now
compiled only for tests. The contextual `*_in` production APIs and all
nonlegacy live-delivery callers remain unchanged.

No local compiler, formatter, parser, test, runtime, or fixture execution was
run under the BSOD hold. Hosted slim-Core validation remains required.
