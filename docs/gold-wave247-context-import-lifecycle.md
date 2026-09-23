# W247 — Local Import lifecycle control

W247 adds the first authenticated, durable pause/resume control for the
existing Local Import vertical. It does not add background sync, erase,
credentials, GUI, Buddy, or a new persistence format.

## Operator contract

The Windows same-user client exposes:

```text
neoth context import pause --policy-revision <N> --lifecycle-revision <N>
neoth context import resume --policy-revision <N> --lifecycle-revision <N>
```

The calls map to `POST /cc/local-import/pause` and
`POST /cc/local-import/resume`. Their only request fields are the expected
policy and lifecycle revisions. The Local Import account is fixed by the
daemon to the accountless `local_import` instance; a client cannot select a
different account, subject, source, root, or policy.

Each successful response is content-free and returns the connector name,
lifecycle, unchanged policy revision, and incremented lifecycle revision.
Pause accepts only `active -> paused`; resume accepts only `paused -> active`.
Revoked accounts cannot be resumed. A stale policy or lifecycle revision,
wrong daemon subject, disabled control plane, concurrent transition, or an
invalid edge is rejected without a durable mutation.

## Durable ordering

The selected `neoth serve --config` path is passed into the Connector-Control
RPC state. It is never reconstructed from the home directory.

1. The control plane checks the daemon-authenticated subject and expected
   revisions, then creates the exact successor configuration with a checked
   lifecycle-revision increment.
2. `FreedomConfig::prepare_update_at` loads that selected file under its
   canonical configuration locks. It rejects a file whose
   `context_connectors` state differs from the daemon projection and produces
   an exact-source CAS-bound update.
3. The lifecycle-specific bounded transition closes new import admission and
   drains live operation leases for at most the Connector-Control work budget.
   A pre-publication timeout restores every captured gate; retained leases and
   the prior authority become live again.
4. `commit_durable_update` atomically publishes the exact prepared
   `freedom.yaml` successor and then installs its matching in-memory
   projection.

If preparation or the source CAS fails, the unpublished transition drops and
restores its captured gates. If installation fails after the durable publish,
the existing control-plane contract remains globally fail-closed; the newly
published file is retained and the operation is not reported as successful.
On daemon restart, the control plane is reconstructed from the persisted
lifecycle state.

## Validation added

- `connectors::control_plane::tests::authenticated_lifecycle_successor_is_revision_fenced_and_never_uses_import_admission`
- `connectors::control_plane::tests::lifecycle_transition_cas_failure_reopens_the_unpublished_active_authority`
- `connectors::control_plane::tests::lifecycle_drain_timeout_preserves_the_live_lease_and_prior_authority`
- `connectors::control_plane::tests::lifecycle_drain_commits_after_the_held_lease_releases`
- `connectors::control_plane::rpc::tests::lifecycle_request_requires_exact_revision_fields`
- `cli::context::route_tests::context_import_lifecycle_routes_bind_both_expected_revisions`
- `cli::context::windows_tests::windows_context_cli_client_status_plan_apply_reopen_and_shutdown_are_bound_to_live_daemon`

The Windows acceptance path covers active status, a persisted pause that
blocks planning, a revision-fenced resume, and recreation of the projection
from the persisted configuration. The local BSOD hold means these tests were
added but not executed locally.
