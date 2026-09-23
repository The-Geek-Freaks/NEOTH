# Wave 354 Dream Clippy repair

The hosted slim-core Clippy run `35847289447` at commit `32bc` reported seven
Dream diagnostics. Four were `clippy::type_complexity` diagnostics:

- `dream_phases.rs` had the same eight-field source row type in the hot input
  selection and input revalidation, plus a nine-field retained warm-anchor row.
  Both row shapes now have descriptive private aliases.
- `consolidate.rs` had an unnamed seven-field aged warm-tier row. It now uses
  `AgedWarmRow`.

The other three were dead-code diagnostics. The unused `PhaseComplete` enum
variant, its `ALL` entry, and its label are removed from `cli/dreaming_task.rs`:
completion is already contained in the atomic `PhaseEffect` transaction. The
unused `transition_id`, `payload_sha256`, and `location_sha256` accessors are
removed from `wal/dream_receipts.rs`; receipt contents and the active
`frame_sha256` accessor remain unchanged.

No local Rust command was run under the BSOD hold. GitHub must rerun the exact
hosted gate before this repair is accepted.
