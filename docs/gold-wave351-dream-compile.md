# Wave 351 Dream compile repair

The hosted slim-core Clippy run `35846287395` at commit `4ea5` reported only
the following Dream integration compile errors:

- `consolidate.rs`: the Dream Light source row declared six selected fields but
  decoded only five. The decoder now reads `trust` at column five.
- `dream_phases.rs`: the retained-warm `Statement` borrowed the transaction
  across both transaction commit paths. The statement and row collection now
  live in an inner scope, so the statement drops before either commit.

No local Rust command was run under the BSOD hold. GitHub must rerun the exact
hosted gate to establish compile and Clippy proof for the repaired head.
