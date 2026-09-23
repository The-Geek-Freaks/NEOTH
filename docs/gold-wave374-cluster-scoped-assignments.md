# W374 — scoped cluster TaskDelegate assignments

`TaskDelegateBody.scope` is an optional canonical `(skill, channel, account)` selector. The requester remains the authenticated Peeroxide Noise key; payload fields cannot name or authorize a peer.

The existing membership authority now stores exact `(peeroxide key, skill, channel, account)` assignments with revision CAS. Scoped requests default to deny without a matching allowed record and also require the existing unscoped TaskDelegate assignment. Unscoped requests retain their previous semantics. The scope is checked before routing, before queueing, before request assembly, and within the final provider-start authority gate.

`neoth cluster task-delegate scope-show`, `scope-set`, and `scope-reset` provide read, CAS write, and revisioned deny reset. `scope-show` opens no write-capable DB and never migrates an older daemon-owned database. Scoped mutation remains offline-only: with a live daemon it refuses instead of claiming cross-process linearization until a matching authenticated daemon RPC request/receipt contract is added.

Schema v6 adds only the scoped assignment table. Existing v5 databases retain membership, unscoped assignments, and revocation health projections; read-only inspection uses the actual revocation-intent introduction version (v4), not the latest authority schema number. The v4 fixture removes both later assignment tables before migration.

New regression identities:

- `cluster::membership::tests::v5_to_v6_migration_preserves_unscoped_assignment_and_keeps_scopes_absent`
- `cluster::membership::tests::scoped_task_delegate_assignment_is_exact_revisioned_and_default_deny`
- `cluster::heartbeat::tests::validate_task_delegate_enforces_bounds`
- `cluster::executor::tests::scoped_assignment_revoked_after_queue_before_dispatch_makes_zero_provider_calls`
- `cluster::executor::tests::scoped_assignment_revoke_winning_final_authority_gate_makes_zero_provider_calls`
- `cli::cluster::tests::task_delegate_scope_cli_read_set_stale_cas_and_reset_preserve_exact_default_deny`

No local compiler, Cargo, formatter, test, or runtime validation ran under the BSOD hold. Hosted exact-head execution is required.
