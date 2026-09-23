# Gold Wave 322: Role Fixture Lifecycle Repair

## Hosted failure provenance

The grouped hosted lifecycle run recorded four fixture failures in
`work/gold-20260906/wave310311-publication/group643750/w190-research-lifecycle-log-750d162b075d01c9155f00291d207180dacc3341/cargo-research-lifecycle.log`:

- `cli::chat::tests::w292_daemon_compatibility_left_binding_rechecks_policy_enabled_after_admission` stopped while accepting the reload because its new Left rule selected `openai_api` although the retained Left slot is `claude_cli`.
- `sub_agents::runtime::tests::w296_left_policy_covers_429_fallback_leaf_lifecycles` returned a blocked result before the expected pass because both mock leaves shared the `openai_api` quota key. The primary's synthetic 429 placed that key in backoff, so the fallback leaf was skipped.
- The two W303 dissent-winner loop tests stopped at loop safety validation because their full-autonomy fixtures passed no `tool_call_budget`.

## Fixture corrections

- W292 reloads a `claude_cli` Left policy for `w292-left-model`. The reload is therefore admissible for the captured Left identity; after durable request acknowledgement, the changed policy identity is still rechecked and blocks raw transport.
- W296 gives the fallback mock its own provider identity, `w296-fallback-provider`. The configured Left role policy remains `openai_api` for `wire-model-v1`; only the fixture's quota-tracker key is separated so the simulated primary 429 can advance to the fallback leaf.
- Both W303 calls to `LoopConfig::for_dissent_invoke` use `Some(1)`. The loop remains a single round and now reaches the existing Right-role allow/deny boundary.

## Regression claims

- W292 proves a policy enabled after admission cannot authorize raw transport when its role-policy identity changes.
- W296 proves the primary 429 and fallback leaves for primary and QA carry the retained Left role lifecycle; the adjacent denied-fallback-model fixture still proves a rejected fallback model never reaches transport.
- W303 proves the configured Right winner reaches one loop leaf and writes a Right lifecycle decision, while a mismatched Right policy blocks before a provider-request WAL frame.

## Local validation boundary

The local BSOD hold remains in force. No Cargo command, compiler, Rust parser, formatter, test, runtime, model, or local CI was run for this repair. Validation is limited to text inspection, exact fixture searches, and scoped `git diff --check`; hosted execution remains required to confirm the regressions.
