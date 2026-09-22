# Gold Wave 188 — P2-06 capability quality observation

## Scope

This batch adds one read-only operator diagnostic, `neoth doctor`'s
`capability quality` row.  Its data path is a complete authenticated home-WAL
prefix, scanned through `for_each_authenticated_prefix_frame_at_home` with the
diagnostic's own 32 MiB physical / 64 MiB logical / 128-segment bound and the
underlying identity and authenticated-prefix checks. It retains at most 4,096
in-window samples across 128 identities; a limit breach is unavailable rather
than a partial summary. It does not consume `usage_log::aggregate`: that helper can repair its
JSONL projection and its current read path is not an acceptable read-only,
bounded provenance source for this diagnostic.

Only authenticated `EVENT_TYPE_PROVIDER_RESPONSE` and
`EVENT_TYPE_PROVIDER_ERROR` terminal frames with
`usage_projection_schema = neoth.provider-usage.v2` are eligible.  The reader
requires a canonical invocation id, provider, wire model, timestamp, latency,
terminal boolean and a closed audited `(call_scope, source, call_type)` triple.
The terminal boolean must agree with the authenticated response/error frame
type. Rows without a current closed workflow identity are counted as unattributed;
older projectionless terminal rows are separately counted as legacy. Neither is
silently assigned to current provider routing.

Provider and model labels are accepted only when non-empty, at most 128 bytes,
and free of control characters before Doctor renders them. The producer builds the terminal
payload at completion, including its timestamp, before appending it to WAL. Doctor shows at most four degrading
identity labels and an omitted count.

## Signal and limits

The report keeps provider + wire model + closed workflow identities separate.
It compares a recent 24-hour window against the preceding seven-day baseline.
Both windows need their own conservative floor (8 recent and 12 baseline
terminal outcomes). The only indicators are completed-call failure rate and
p90 terminal latency. A degradation requires a material failure-rate or
latency increase; recovery requires an independently sufficient current window
and a materially better rate or latency than the baseline.

The result is advisory. It never changes routing, availability, retry policy,
provider configuration, cache state or WAL/JSONL state. Terminal success is
adapter outcome evidence, not evidence of factuality, usefulness, safety or
reasoning quality. An incomplete authenticated prefix is refused and displayed
as unavailable rather than summarized.

## Regression identities to run hosted

- `daemon::capability_decay::tests::min_samples_keep_each_identity_inconclusive`
- `daemon::capability_decay::tests::regression_and_recovery_require_separate_conservative_windows`
- `daemon::capability_decay::tests::provider_and_capability_never_share_a_window`
- `daemon::capability_decay::tests::malformed_or_unattributed_terminal_payload_never_becomes_quality_evidence`
- `daemon::capability_decay::tests::authenticated_provider_terminal_producer_reaches_scanner_and_doctor`
- `daemon::capability_decay::tests::authenticated_terminal_history_refuses_a_later_incomplete_prefix`
- `cli::doctor::checks::capabilities::tests::capability_quality_doctor_home_is_read_only_when_history_is_absent`
- `cli::doctor::checks::capabilities::tests::capability_quality_limits_rendered_degradation_labels`

Hosted compilation and runtime acceptance remain required. This is the first
observation slice only: it deliberately does not claim the P2-06 persisted
quality-history contract is complete.

Integrated source review is complete; the terminal timestamp is sampled by the
existing producer during append. No provider authorization code changes were needed.
