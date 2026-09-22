# Wave 202 n8n adoption verification boundary

The source implements `neoth n8n adopt --endpoint http://127.0.0.1:5678 --api-key-stdin`, durable job-backed status, literal loopback endpoint validation, byte- and time-bounded stdin, an authenticated `GET /api/v1/workflows?limit=1` probe, and prepared config-plus-secret publication with readback, compensation, and custody handling. The durable job is created before either pre-commit network request. Ctrl-C during either active pre-commit request acknowledges a terminal cancellation with no binding; Ctrl-C during the published post-commit probe rolls back the exact binding before acknowledgement.

`n8n status` performs no HTTP request and reports only the stored endpoint, secret presence, and durable job state. The adapter does not install, discover, launch, supervise, or claim ownership of n8n. The old bundled workflow listing remains separate from adoption evidence. The capability advertises the CLI surface only; Doctor has no adoption-evidence consumer in this wave.

`Ready` means that the post-commit authenticated n8n-compatible API contract succeeded and all four durable evidence bindings matched. It does not prove the n8n binary provenance, a product version, process ownership, workflow execution, or a persistent live-health guarantee. If custody cleanup after a durable Ready transition is interrupted, Ready remains valid and the retained private custody record is the repair boundary retried by the next owned adapter open; cleanup failure does not leak a raw filesystem or keychain error through the CLI.

No Rust parser, formatter, compiler, test, runtime, HTTP, or live-n8n command was run for this wave because the active BSOD hold prohibits those operations. The source was inspected with bounded text reads only. Therefore the following focused tests are present but **not executed**:

- `integrations::n8n::tests::parses_documented_workflows_shape_without_invented_identity_fields`
- `integrations::n8n::tests::rejects_non_documented_or_unbounded_workflows_shapes`
- `integrations::n8n::tests::descriptor_and_step_plan_are_stable_and_local_only`
- `integrations::n8n::tests::generic_200_workflows_envelope_without_key_rejection_is_not_adoption_evidence`
- `integrations::n8n::tests::adoption_requires_unauthenticated_rejection_then_persists_and_reports_ready_without_key`
- `integrations::n8n::tests::precommit_unauthorized_fails_durably_without_config_or_credential_write`
- `integrations::n8n::tests::postcommit_failure_restores_exact_preimage_and_never_reaches_ready`
- `integrations::n8n::tests::injected_cancellation_is_durable_and_never_publishes_a_binding`
- `integrations::n8n::tests::active_hanging_precommit_probe_is_cancelled_without_publishing`
- `integrations::n8n::tests::active_hanging_negative_control_is_cancelled_without_publishing`
- `cli::n8n::tests::stdin_key_line_accepts_exact_limit_with_lf_and_crlf`
- `cli::n8n::tests::stdin_key_line_rejects_oversize_invalid_utf8_and_controls`
- `integrations::n8n::tests::missing_input_is_a_terminal_required_input_job_without_config_mutation`
- `integrations::n8n::tests::restart_of_unowned_active_job_is_terminal_and_releases_the_capability_lock`
- `integrations::n8n::tests::read_only_status_of_absent_state_creates_no_config_or_job_database`

The configuration transaction tests supplied by the configuration slice also remain unexecuted under the same hold. A later authorized verification pass must run the narrow integrations/configuration/CLI test sets and a hermetic loopback mock before any claim of compiled or runtime validation.


**W203 durable Cron link / W202 format follow-up (2026-09-22):** Hosted
Grouped60 `35733913541` on `7f1070d9` executed all sixty exact identities;
59 passed. Its remaining failure exposed a production mismatch: the WAL
append receipt is a byte offset, while Cron persisted it as `fired_event_id`.
The shared event helper now preserves the generated header identity and returns
it only after durable append succeeds. Normal, failure and delivery consumers
share the corrected identity. The unchanged strict WAL-link test remains in
the selection, and independent source review passed. All sixty actual names
and source bindings were admitted from downloaded evidence. W202's first
Hosted Preflight exported formatting corrections for eight source files; the
exact patch, source HEAD and before/after Git blobs were verified on import.
No local formatter/test/compiler ran. Grouped83 and Core/CLI on `b704284d`
are still separate pending runs; Road checkboxes remain unchanged.


**W202 first Hosted behavior repair (2026-09-22):** Grouped83 `35735312775`
on `b704284d` executed every selected identity: 73 passed, ten failed. Eight
adoption paths stopped at the shared enqueue contract because the adapter
revision label was not canonical semver. Both producers now use the separate
adapter release `1.0.0`; artifact provenance remains `n8n-adoption-v1`, with
no n8n binary-version claim. Fresh-home status now returns unconfigured only
for two unchanged absent files after repeated pending-journal checks. The
remaining Cron link failure was already repaired in `2f189197`. Independent
source review passed, all 83 exact identities/source bindings were verified,
and no failing test was removed. Core test-target checking, public CLI build
and export `35735316615` passed; the hash-bound generated reference is imported
(SHA-256 `59b3d3c91f53d2b6cb9b3168377c22f5c0d64d8b8102a9436b91dfa0d1df0e4a`).
Three residual rustfmt hunks from Hosted `35736102874` are imported. Fresh
Hosted behavior/Preflight remain required; W204 remains uncommitted WIP and
Road counts remain unchanged. No local executable validation ran.
