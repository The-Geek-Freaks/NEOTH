# Gold Wave 289: Cron role binding

## Scope

This wave adds an optional `execution.hemisphere_role` to Cron job execution
policy and binds every job-local Cron provider intent to that role at the
existing final `ProviderCallAuthorizer` boundary.

Relevant source paths:

- `SRC/neothd/src/cron/schema.rs`
- `SRC/neothd/src/cron/runner.rs`
- `SRC/neothd/src/cli/cron.rs`

## Authority behavior

When `inference.role_policy` is configured, a job that sets a primary provider,
model, fallback chain, or explicit role must set `execution.hemisphere_role`.
An omitted role is refused before the Cron runner constructs its raw provider
chain. A role-only job constructs the configured default topology and binds it
to that role.

The configured provider identity for that role and the configuration snapshot
used to construct the topology are passed into the existing role-dispatch
authorizer. It checks every primary and fallback leaf at the final permit/send
boundary. The originating role is retained across the already selected chain;
this wave does not select a replacement provider or reorder fallbacks.

When no role policy is configured, legacy Cron jobs retain their previous
unbound override behavior. The new field is optional and omitted from serialized
jobs when unset. The CLI continues to create jobs with no role field because it
does not add a new operator-facing flag in this wave.

## Focused test intent

The W289 tests use an in-process `local_ollama` counting provider and a
temporary WAL segment. They cover an exact allowed leaf, a disallowed final
model denied before the provider call and provider-request WAL event, missing
origin rejection for provider and model-only intent, and the accepted
role-policy reload fence between the durable request audit and raw send. The
selector assertions and the resolver fixture exercise the same provider-intent
branch used by Cron for model-only and role-only jobs. They make no network
calls. The daemon scheduler threads its existing accepted `ReloadController`
to the Cron authorizer; standalone calls retain a fixed per-invocation
snapshot.

## Acceptance boundary

No compiler, formatter, parser, tests, runtime, or Git operation was run
locally while the BSOD hold is active. A hosted build and the focused W289 tests
are required before acceptance. This wave supplies one Cron consumer binding;
it does not claim P2-15 is closed.
