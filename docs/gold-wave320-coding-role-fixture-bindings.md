# Wave 320 coding-role fixture bindings

Date: 2026-09-23

## Scope

This repair changes only the two focused role-admission fixtures:

- `cli::code::tests::resume_worker_role_binding_allows_selected_right_and_denies_mismatch_before_transport`
- `coding::service::tests::cerebellum_decomposer_role_binding_allows_one_leaf_and_audits_then_denies_before_transport`

It does not alter the production role-authorizer, the role-policy decision, the
provider transport, or their assertions. No local executable validation was run
under the absolute workstation BSOD hold.

## Observed Hosted failure

The Group643750 log records both tests stopping at their setup
`unwrap()`, with respectively:

- "coding role `right` has no configured provider identity"
- "coding role `cerebellum` has no configured provider identity"

Each fixture set its per-role provider but inherited
`InferenceTopology::default().mode == Single`. In that mode,
`InferenceTopology::slot_for(role)` reads `default_slot` and intentionally
ignores `right` and `cerebellum`. The fixture therefore did not describe the
configured role it asserted about.

## Repair

Both fixtures now set `TopologyMode::Custom` before populating the per-role
slot and its closed role-policy rule:

- `SRC/neothd/src/cli/code.rs`: Right / LocalOllama / `w300-right`
- `SRC/neothd/src/coding/service.rs`: Cerebellum / LocalOllama / `w300-cerebellum`

This matches the current topology contract: per-role slots are consulted only
in `custom` or `triplet` mode. The allowed path still requires the selected
provider/model to match its rule, and the denied path still changes only the
policy rule to OpenAI and asserts denial before provider transport.

## Required Hosted follow-up

Re-run the two exact test identities above from the repaired source revision.
Acceptance requires the allowed calls and audit assertions to pass, while each
mismatched policy continues to deny with zero transport calls. The local BSOD
hold means this document is source/diagnostic evidence only.
