# Terminal cost provenance

New provider terminal records retain the effective static price row used by NEOTH, including the resolved provider/model, exact rate bits, fixed EUR/USD conversion, cache multipliers and calculation version. `pricing_basis.basis_id` identifies those inputs with SHA-256. This describes NEOTH's cost estimate; it is not a vendor invoice or proof of payment.

The same reviewed row feeds the amount calculation and its provenance. Unknown prices or a known price without sufficient measurements leave both the uncomputed amount and its basis unavailable. An explicitly free local result retains zero cost and a zero-rate basis. A cache-only measurement can retain its basis even when total cost is unknown.

Terminal WAL `neoth.provider-usage.v4` contains snapshot `neoth.provider-usage-snapshot.v2`. Both the outer terminal and snapshot metadata require `pricing_basis`, including an explicit `null` when unavailable. Recovery checks their equality, provider/model identity, canonical numeric encodings and basis digest, then restores the recorded amount bits. It never consults the current price table or performs another charge.

Historical v3/snapshot-v1 records keep their exact field set and amounts; a new basis field is rejected even when null. Older v2 records retain their documented current-rate reconstruction and receive no invented historical basis. Existing JSONL records remain readable. New priced JSONL events expose the basis beside the existing invocation identifier; general rollups still aggregate the existing amounts.

Implementation owners: `providers/cost.rs` selects and calculates the static rate; `providers/pricing_basis.rs` versions its effective inputs; `providers/cost_authorization.rs` writes the terminal; `daemon/usage_log.rs` serializes and repairs the same event. The versioned constants for algorithm v1 must remain frozen if another calculation policy is introduced.

A02 remains open for seven-category prompt attribution, tokenizer provenance, residual estimates, reservation-price history and dedicated operator presentation. This slice does not store prompt text and does not introduce a second ledger.
