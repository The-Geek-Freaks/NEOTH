# Document distillation and scored self-review

`neoth skills --distill-doc guide.md --min-reflexion-score 80` is an explicit
provider-backed operation. The score is an operator-selected threshold from
0 through 100. The existing `--from-doc`, `--from-doc-chapter` and chapter-list
commands retain their provider-free review behavior.

The new command uses the existing bounded no-follow document admission and
extractor chain. It sends only defanged source text and sanitized fingerprints.
The source pathname and raw binary document are excluded from the prompt.

Before resolving the provider or requesting consent, the command prints and
flushes a token/cost preflight for both calls. The reflection input estimate
includes the entire 128 KiB candidate limit; it is a conservative upper bound,
not a prediction of typical use. The configured utility model is used, falling
back to the configured main model. An explicit resolved model is required so
the request and estimate name the same model. Known prices come from the
reviewed exact-model table. Local/free estimates are zero; unknown estimates
have `state: unknown` and null monetary fields. This receipt grants no spending
permission. Existing consent and request-bound cost authorization still apply.

The receipt uses the same effective utility configuration and endpoint/profile
classifier as the actual adapter. Custom OpenAI endpoints are identified as
`openai_api_custom` with unknown/null pricing; compatible vendor profiles keep
their actual leaf identity. A configured Claude CLI is refused before emitting
a bounded estimate because one CLI invocation may perform multiple internal
model calls and has no enforceable whole-invocation output cap. Configure a
token-bounded API or local `inference.utility_provider` for this operation.

With `--output json`, the preflight is emitted to stderr and the result remains
one JSON object on stdout. With `--output jsonl`, both are ordered stdout events.
The human-readable format prints the preflight before the candidate and score.
Failure to deliver the preflight stops before provider resolution.

The pipeline makes one candidate call (2048 output tokens maximum) and exactly
one scored review call (256 output tokens maximum). It never retries or refines.
Empty/oversized candidates stop before review. Provider errors, authoritative
refusals and token-limit truncation stop the pipeline. Review output must be a
strict JSON object with schema_version 1, a 0..100 integer score, accept/reject
verdict and bounded non-empty reasons. Invalid output stops. Scores below the
operator threshold and explicit rejection make the candidate ineligible.

The resulting candidate and reasons are defanged before display. The outcome
reports `eligible_for_b7_staging`; no proposal, installed skill, activation or
memory/wiki write is made. Audit writing uses the existing completion-aware
WAL drain before success is reported.

B5 source wiring and the CLI part of B6 are implemented. Hosted tests and an
independent review are pending at publication. B6's named proactive/GUI consumers
and B7's consent-gated staging remain separately open. No GUI completion or
model-quality guarantee is claimed by this change.
