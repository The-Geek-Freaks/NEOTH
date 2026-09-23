# W329 research CLI acceptance

## Boundary

Only `SRC/neothd/src/cli/research.rs` and this document changed. No Cargo,
compiler, parser, formatter, test, runtime, PLAN/inventory, Git, CI-dispatch or
agent-dispatch operation ran under the active BSOD hold.

## Behavior-preserving execution seam

The public `run_research` still resolves the process home and production
provider exactly as before. It now delegates to private `run_research_at` and
passes no override. The common runner accepts an optional already-resolved
provider solely for hermetic tests; it still executes the same revision claim,
config-derived policy, `ProviderCallAuthorizer`, real home-bound standalone WAL
writer, `ExternalHttpAuthorizer`, `RunCallBudget`, `DurableControl`, and
`run_deep_research_controlled` producer. No global mutable test hook or
production bypass was added.

## Added fixtures

- `operator_lifecycle_dispatches_create_approve_run_pause_resume_cancel_show_and_list_with_exact_revisions`
  serializes a temporary `NEOTH_HOME` and drives public dispatch for create,
  show, list, stale and correct approval, run, pause, resume and cancel.
  The isolated no-provider run/resume cases assert real pre-effect failure;
  executor-side control observation completes the dispatched pause/cancel.

- `successful_lifecycle_dispatches_real_authorized_producer_and_decodes_wal_terminals_without_replay`
  drives the common dispatch path with a counted provider, an ephemeral
  Wiremock SearXNG endpoint returning a valid empty result set, full-autonomy
  config and a real authenticated home-WAL. The fixture saves and restores the
  provider, endpoint and language environment variables under the shared test
  lock, so it cannot inherit an external search endpoint. It decodes the WAL
  through `for_each_frame_at_home`, requiring the xxh3 hash of the exact
  fixture topic in both `DEEP_RESEARCH_STARTED` and
  `DEEP_RESEARCH_COMPLETED`, in that order. Completion must report one round
  and zero citations. It confirms the durable `Completed` audit state and
  proves a second dispatched run is refused before a further provider call.
  The empty response proves lifecycle custody only; it makes no source-evidence
  claim.

- `interrupted_lifecycle_decodes_started_wal_and_refuses_replay_after_terminal_failure`
  injects a provider which fails only at synthesis after the durable effect
  start. It asserts `Interrupted`, its audit event, a decoded start receipt
  bound to the exact fixture-topic hash without a false completion receipt,
  and a second dispatched run refusal before another provider call.

## Exact WAL-join-failure limit

The earlier `paused_or_cancelled_terminal_wal_failure_is_reported_without_mutation`
fixture remains the direct proof that a terminal WAL finalization failure leaves
an already committed terminal record unchanged. W329's new success/interruption
fixtures exercise the real writer and decode its records, but the writer's
short-lived join is constructed internally and exposes no existing failure
injection after the producer terminal event. Manufacturing that failure from a
fixture would require a second production seam for writer construction/join
ownership. It was not added because the accepted minimal seam was limited to
provider resolution. Therefore W329 proves terminal no-replay after a real
interruption, while the exact post-terminal writer-join failure remains covered
by the existing targeted fixture rather than a fabricated integration path.

No fixture has run locally; Hosted execution is required before any acceptance
claim.
