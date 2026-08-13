# NCT-01 Current-Path Baseline Corpus Protocol

## Scope and non-claim

This protocol defines the first, deliberately partial, reproducible slice of
**GOLD-NCT-01**. It measures only the current NEXUS provider-backed sub-agent
path: one Primary call, one QA call, and, when the existing QA verdict is
retriable and retry is enabled, one correction followed by one QA call. It is
behavior-neutral: request construction, dispatch, authorization, model choice,
sampling, provider routing, retry eligibility, retry limit, WAL behavior, and
private run-record behavior are unchanged.

It is not evidence for the full GOLD-NCT-01 card. Direct, Council,
fallback/reroute, streaming, cluster-worker, real-provider, and cross-route
comparisons remain open.

## Frozen synthetic corpus

The manifest at
`SRC/neothd/tests/fixtures/nct_baseline/subagent_prompt_baseline_v1.json`
is the corpus authority. It records a deterministic recipe and fixed split IDs,
not raw prompt content:

- train: recipe tuning only;
- validation: implementation/regression selection only;
- holdout: final reported comparison only.

Synthetic generators must be deterministic, preserve the manifest seed and
recipe version, and emit ASCII-safe fixed-length segments. They must never
persist raw prompt text, candidate text, QA verdict text, provider request IDs,
new hashes, or unsalted content-derived identifiers.

## Captured current-path measurements

Every existing `SubAgentProviderCall` may carry an optional
`prompt_baseline`. It includes only:

- stage and B22-bound `provider` / `wire_model` identity already carried by the
  call;
- byte counts for the complete prompt plus system, context, candidate, and
  QA-failure construction segments;
- repeated-segment bytes: content carried again from an earlier current-path
  stage, never a fingerprint;
- explicitly conservative tokenizer-independent byte-based upper bounds for
  each segment and the complete request;
- optional native Completion input/output/cache-creation/cache-read token
  counts, preserving `None` distinctly from a provider-reported `Some(0)`;
- Completion request-to-last-token latency in milliseconds.

The runtime computes this from its internal `PromptSegments` before dispatch;
it does not recover segment data by parsing a completed or rendered prompt.
Baseline attachment happens after the existing Completion returns and does not
make an extra provider request.

No baseline record contains raw prompt/candidate/verdict data, new content
hashes, a provider request ID, route/decorator identity, a WAL/event record, or
an unsalted content identifier. Existing B22 completion provider/wire-model is
the sole identity.

## Cost and provider usage

Unknown native usage remains unknown. `None` must not be converted to zero,
estimated as a provider bill, or used to claim a cost saving. The local token
upper bounds are only conservative byte-based planning ceilings, not tokenizer
measurements and not billable-token estimates.

Any cost report must cite a reviewed price snapshot containing provider,
wire-model, effective date, source URL or archived review reference, currency,
input/output/cache pricing units, and explicit treatment of missing usage. A
snapshot is invalid for an unreviewed model alias, a changed price date, or a
call without usable native usage; such rows stay `cost_unknown`.

## Quality and failure corpus

For each split, retain content-free outcome aggregates: pass/fail/blocked,
attempt count, retriable-QA correction occurrence, malformed-QA occurrence,
provider-call error occurrence, and native-usage presence. Keep the raw quality
judgments only in the controlled evaluation environment, separately from this
manifest and baseline output. Do not promote synthetic QA agreement into a
real-provider quality claim.

## Route limits and reproducibility gates

The baseline uses the current runtime limits without relaxing them:

- one Primary and one QA request per attempt;
- at most one QA-triggered correction (`MAX_QA_RETRIES = 1`);
- current fan-out ceiling 8 and concurrency ceiling 4;
- current prompt/system/candidate byte limits and B22 authorization boundary.

For a reproducible run, record source revision, fixture manifest bytes/version,
provider and exact B22 wire model, runtime config fingerprint excluding secrets,
platform/runtime version, split ID, and whether any native usage is absent.
Do not replace these run-environment facts with a content identifier.

## Remaining GOLD-NCT-01 work

This baseline leaves the following explicitly open:

- Direct request path measurement;
- Council topology and synthesis measurement;
- provider fallback/reroute and error-recovery measurement;
- streaming request/chunk/final-usage measurement;
- cluster-worker and peer transport measurement;
- real-provider reproducibility, price-snapshot review, and cost settlement;
- frozen human-reviewed quality/failure corpus execution and train/validation/
  holdout reporting across every current path.

No efficiency, quality, price, or completion claim may generalize this NEXUS
slice to those paths until their own frozen corpus and behavior-neutral baseline
are implemented.
