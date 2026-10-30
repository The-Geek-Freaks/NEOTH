# Terminal cost provenance

New provider terminal records retain the effective static price row used by NEOTH, including the resolved provider/model, exact rate bits, fixed EUR/USD conversion, cache multipliers and calculation version. `pricing_basis.basis_id` identifies those inputs with SHA-256. This describes NEOTH's cost estimate; it is not a vendor invoice or proof of payment.

The same reviewed row feeds the amount calculation and its provenance. Unknown prices or a known price without sufficient measurements leave both the uncomputed amount and its basis unavailable. An explicitly free local result retains zero cost and a zero-rate basis. A cache-only measurement can retain its basis even when total cost is unknown.

Terminal WAL `neoth.provider-usage.v4` contains snapshot `neoth.provider-usage-snapshot.v2`. Both the outer terminal and snapshot metadata require `pricing_basis`, including an explicit `null` when unavailable. Recovery checks their equality, provider/model identity, canonical numeric encodings and basis digest, then restores the recorded amount bits. It never consults the current price table or performs another charge.

Historical v3/snapshot-v1 records keep their exact field set and amounts; a new basis field is rejected even when null. Older v2 records retain their documented current-rate reconstruction and receive no invented historical basis. Existing JSONL records remain readable. New priced JSONL events expose the basis beside the existing invocation identifier; general rollups still aggregate the existing amounts.

Implementation owners: `providers/cost.rs` selects and calculates the static rate; `providers/pricing_basis.rs` versions its effective inputs; `providers/cost_authorization.rs` writes the terminal; `daemon/usage_log.rs` serializes and repairs the same event. The versioned constants for algorithm v1 must remain frozen if another calculation policy is introduced.

A02 now carries optional `prompt_tax.components` for instrumented final bundles. Its seven origins are system, workflow, skill, retrieval, tool result, user and unattributed. Producers label origin independently of authority/degradation class and the five legacy prompt-tax counters. Only retained content contributes. Unlabelled content remains unattributed; rewrites that mix origins lose their label. The `utf8_byte_upper_bound_v1` estimator counts UTF-8 content bytes and the existing request envelope reserve. `envelope_residual` accounts for separators and framing in that same estimate domain. The seven counts plus residual equal `request_upper_bound`; none of these values are provider token measurements or allocated money. Saturated request bounds leave the component estimate unavailable.

The existing request binding carries this metadata into the same reservation/ticket. Changed prompt/system bytes clear it; a changed model/stop envelope clears the component estimate even if content stays identical. Request intents keep their original v2 shape. Terminals with components use WAL v5 and snapshot v3, including the same price basis and exact amount bits. Historical terminal v2/v3/v4 and snapshot v1/v2 reject the new component key, including null. Canonical v5 replay validates the component arithmetic and outer/snapshot equality without repricing, calling a provider or debiting again.

`neoth usage` and its JSON rollup show seven-category estimates, residual and observed-call coverage separately from reported token and money totals. Missing legacy or unbound measurements remain unavailable; observed zeros remain zeros. Tool-loop rewrites without retained typed provenance remain unavailable rather than being guessed from tool text. The retained-WAL inspection modes below expose recorded plans and acquisitions. Complete per-stage reservation history, model-specific tokenizer measurements, broader tool-loop origin propagation and dedicated GUI/mobile presentation remain open. This slice stores no prompt text and introduces no second ledger.

Authenticated capability observation and Doctor quality reporting accept terminal v2, v3, v4 and v5. The v3/v4/v5 paths first use the same canonical snapshot decoder as usage recovery, then retain their quality-specific identity, workflow, event-type and time checks. Invalid declared snapshots fail instead of becoming legacy observations. Unknown versions remain legacy and do not contribute quality evidence.

## Planned authorization prices

For a priced, bounded remote call, the existing `COST_ESTIMATE_SHOWN` event now includes `authorization_price_bound` beside its existing request SHA-256 binding. The closed `neoth.authorization-price-bound.v1` record freezes the effective price basis, input upper bound, output ceiling, nonempty-system condition and exact USD amount bits. Validation reconstructs the amount from those recorded rates and policy inputs without looking up today's price table. It preserves the existing arithmetic order, the minimum output ceiling of one, and the Anthropic cold-cache premium when a nonempty system message is present.

The operation, daily and cluster reservation plans consume the same frozen planned amount, retaining each budget owner's existing units and rounding. Missing prices remain unavailable rather than becoming zero. Local free calls retain their existing path; they do not gain a fabricated remote estimate event.

This record proves a planned authorization calculation, not acquisition of a reservation, provider execution, invoiced cost or payment. Daily admission, operation admission, durable provider intent and cluster claim still occur in their existing order. Historical acquisition evidence, including cancellation between these stages, remains a separate open requirement. An absent acquisition observation must not be interpreted as proof of no reservation. Existing terminal snapshots and usage recovery remain unchanged by this planning record.

## Observed budget acquisitions

New producer code emits the additive EXTENDED subtype `provider_budget_acquired` (0x3D), with payload schema `neoth.provider-budget-acquired.v1`, after the existing daily and operation admissions, durable provider intent and any cluster claim. It binds the invocation and request digest to the admitted daily amount in USD nanos, operation token and micro-USD amounts, and cluster USD-nano bound plus opaque grant identifier. A present zero is an observed acquisition; a null scope was not configured for that invocation. This record contains no prompt text, dispatch capability or new accounting authority.

The raw provider dispatch guard is returned only after this observation is durably acknowledged. Caller cancellation retains the owned append task and existing terminal owner. Daily pre-dispatch rollback remains with its original owner; operation quota remains charged. The cluster settlement owner is attached before the new await. Its existing failure policy settles unknown cost at the full reserved bound only after the terminal WAL append succeeds; a failed terminal write leaves the claim outstanding for reconciliation.

This is historical acquisition evidence at the recorded point, not a current balance, final charge, invoice or proof that the provider ran. Missing observations remain unknown: rejection, cancellation or failure may occur before this combined observation despite an earlier acquisition. The inspection modes below validate and compare retained records without changing their accounting owner. Complete per-stage history, GUI/mobile presentation and tokenizer measurements remain open. Terminal usage snapshots and replay do not consume this record or debit again.


## Inspect retained invocation evidence

The ordinary `neoth usage` command keeps its existing JSONL rollup. Two explicit modes read authenticated prefixes of the retained home WAL instead:

```console
neoth usage --acquisitions --days 7
neoth usage --provenance --days 7 --format json
neoth usage --provenance --since-unix 100 --until-unix 200
```

`--acquisitions` compares request and acquired-budget observations, preserving daily USD nanos, operation token/micro-USD reservations and cluster USD nanos/grant IDs. `--provenance` adds the planned authorization price and terminal usage for each invocation. The modes are mutually exclusive and reject `--currency`; recorded units and frozen USD amounts are preserved. Both accept `table` or `json` and the existing day/explicit timestamp window options.

The provenance JSON uses `neoth.provider-provenance-inspection.v1`. Each occurrence retains its recorded timestamp, segment identity, logical offset and `is_in_window` flag. An invocation is selected if any recognized record falls within the inclusive window; its other retained observations remain visible as context. Diagnostics are scan-wide because malformed records have no trusted timestamp.

An `observed_metadata_match` requires exactly one request, plan, acquisition and terminal with the same canonical request binding, provider and wire model. A terminal also needs the recognized lifecycle schema and a present binding. This is comparison of recorded metadata within the scanned home, not proof of causality, globally unique invocation IDs or complete history. `conflict`, `duplicate`, `unbound` and `incomplete` remain distinct. The group retains missing kinds, duplicate kinds and differing fields even when another status takes precedence.

Plans remain estimates, acquired scopes remain reservations, and terminal token counters remain reported observations. Terminal v3/v4/v5 preserve frozen computed amounts, exact amount bits, available historical price basis and prompt components. The read-only terminal-v2 path leaves cost and savings unknown; it does not invoke the older JSONL repair policy's current-rate reconstruction. A missing observation or amount is never converted to zero. UTF-8 upper bounds and envelope residuals remain estimates, with no fabricated model-tokenizer version.

Always inspect `scan.complete` and `observations.semantic_decode_complete`. Even when both are true, `full_history_complete` and `atomic_latest_snapshot` remain false: retention and concurrent writes limit what this read can establish. An empty retained WAL does not establish zero usage. Repeated or conflicting observations are all retained; they are not summed into an invoice, settlement or current balance.

The reader has shared limits of 20,000 recognized records, 8 MiB of recognized payload/segment-name input, 1,000 diagnostics and 16 MiB of serialized output. Limits or authentication/scan errors fail the read before buffered output is published. Provenance mode rejects duplicate JSON keys recursively. Neither mode creates missing WAL keys, repairs JSONL, calls a provider, replays an effect or performs another debit.

The W2640 source and hosted formatting/static gates are published. Its 115-case focused runtime and generated CLI reference remain a separate pending qualification; this documentation does not claim GUI/mobile or release acceptance.
