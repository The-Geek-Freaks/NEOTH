# W198 — n8n session-start Skill registry

W198 extends the already admitted W136 metadata-only registry to the
authenticated n8n `/api/provider/call` surface. Each call captures one
`AcceptedConfigSnapshot`, uses its config and epoch, then requires the daemon's
process-wide `SkillRegistry` to belong to that API state's `home/skills` path
and exact `ReloadController` allocation. The identity check is `Arc::ptr_eq`:
matching paths or a matching numeric epoch cannot authorize a registry created
by another controller. The registry must return
`authority_bound_snapshot_for_epoch(epoch)` before any provider is constructed.
Missing, foreign-home, foreign-controller, or stale registries refuse the call
rather than turning a registry failure into an empty inventory.

The admitted snapshot is filtered by the existing evaluation and pinned-hash
rules before `SkillRouteResolver::session_registry_context` serializes it. The
result is one retained typed untrusted Block D value. n8n still performs no
skill selection: no skill body, tool catalogue, model routing, or cluster
context is added to the request.

Focused regression identities in `SRC/neothd/src/n8n_api/handlers.rs`:

- `n8n_provider_request_includes_exactly_one_guarded_registry_without_route_leaks`
- `n8n_registry_excludes_eval_and_pinned_hash_mismatch_skills`
- `n8n_registry_refuses_absent_foreign_or_stale_daemon_registry` (also covers
  same-home equal-epoch foreign controllers for both same and different source
  config paths)
- `n8n_provider_request_retains_registry_a_after_later_accepted_b`

The resolver's existing `session_registry_context_rejects_oversized_complete_inventory`
and `session_registry_context_rejects_json_escape_expansion_after_raw_bound`
remain the n8n renderer's exact oversized-inventory gates: n8n propagates their
error before provider dispatch. Hosted Rust formatting, compilation, and these
tests remain required. No local compiler, formatter, test, parser, or product
runtime was run under the BSOD hold. W198 supplies only this n8n entry point;
it does not close the wider P2-10 readiness/acceptance item or alter Road
counts.
