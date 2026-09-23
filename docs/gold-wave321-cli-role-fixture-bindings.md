# Gold Wave 321 — CLI role fixture bindings

The W301 fixtures initially populated `inference.right` and `inference.left`
while retaining `InferenceTopology`'s default `single` mode. Production
`slot_for(role)` deliberately resolves every role to `default_slot` in that
mode, so the fixture's populated role slot was not the selected identity and
the direct role-binding helpers correctly returned their missing-provider
errors.

Each W301 fixture now selects `TopologyMode::Custom` before setting its role
slot. The tested provider identity is therefore the same identity production
`slot_for(Right)` or `slot_for(Left)` resolves: `LocalOllama` with the fixture
model. The model-mismatch deny cases retain zero raw calls and the profile
case retains zero `PROVIDER_REQUEST` WAL frames; production binding and its
fail-closed missing-identity behavior are unchanged.

The correction is source-only under the BSOD hold. Hosted test, formatting,
and lint gates remain the required verification.
