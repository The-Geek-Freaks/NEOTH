# Gold wave 368 — Research fixture authorized budget

Group721 on `954f838afd1ddef8a7781913218cbb189f7659bd` exposed two fixture
configuration failures in the real Research lifecycle path.

Both lifecycle fixtures wrote `autonomy: full` but left the configuration input
cap at its zero default, and both persisted a `ResearchRunBudget` with
`max_provider_tokens: 0`. The real `CostAuthorizingProvider` therefore denied
the controlled request before raw provider dispatch: its conservative input
bound was 1919 against effective cap 0. The successful fixture consequently
failed during synthesis; the interrupted fixture never reached its intended
second controlled call and observed zero calls.

The two test-only homes now set `tokens.max_per_request: 4096` and persist the
same bounded `max_provider_tokens: 4096`. This authorizes the existing real
plan/synthesis path without relaxing any production cap. The successful
fixture still requires exactly two calls and refuses replay; the interruption
fixture still requires the real post-effect failure, terminal WAL behavior,
and replay refusal.

No local Cargo, compiler, parser, formatter, test, or runtime command ran
under the BSOD hold. Hosted rerun evidence remains required.