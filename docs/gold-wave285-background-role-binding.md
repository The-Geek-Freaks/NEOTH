# W285 — background Left-role binding

The background worker’s production leaf now binds `HemisphereRole::Left` to the existing `ProviderCallAuthorizer` before `AuthorizedProvider::complete`. The binding uses the second, unchanged live configuration check immediately before authorizer creation. It resolves the configured Left provider identity and retains that accepted configuration for final model-role revalidation.

This preserves the queue snapshot, approval capability, consent checks, canary binding, cost/permission authorization, provider fallback construction, WAL lifecycle, and failed-job receipt behavior. The role binding does not select a new provider or model: fallback leaves remain subject to the same originating Left authority at their existing final permit/send boundaries.

Focused tests exercise the production `AuthorizedProvider::from_box` boundary used by
the worker, with a non-network counting leaf and a real fail-closed WAL authorizer:

- `w285_background_left_role_binding_admits_exact_leaf_once` proves an admitted
  Left provider/model reaches the raw leaf exactly once and emits its provider-request
  lifecycle event.
- `w285_background_left_role_binding_denies_disallowed_model_before_effect` proves a
  different final model is rejected by that same Left binding before the raw leaf is
  called and before any provider-request lifecycle event is written.

They use the same `background_role_authorizer` seam as production, the shared
`ProviderCallAuthorizer::with_role_dispatch`, and configured `RolePolicyConfig`.
The counting leaf implements the trait's test-double `complete` seam, reached only
after the outer authorizer has admitted the actual provider call. This covers
only the background P2-15 consumer. P2-15 remains open for normal dispatch/fallback,
broader retry consumers, sub-agents, adversarial proof, and CLI/GUI/Buddy parity.

BSOD hold: source/docs edits only. No local compiler, Cargo, formatter, parser,
test or runtime validation ran. GitHub-hosted compilation and execution remain
required before this batch is accepted.
