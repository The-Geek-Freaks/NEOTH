# Gold Wave 290 - retention hosted compile repair

Hosted run `35822418284` on the Wave 280 source reported one Clippy
`possible_missing_else` lint, `E0277` in the yearly-synthesis hygiene match,
and `E0282` for the journal and receipt inventories. The hosted formatter
patch already expanded the independent validation `if` statements, so this
repair preserves that formatting and makes the remaining source-only changes:

- compare the iterator's retained `&PeriodReflection` with
  `&record.reflection`;
- specify the concrete journal and receipt vector element types before sorting;
- retain an underlying `std::io::ErrorKind` when the read-only retention helper
  translates a contextual `anyhow` failure to `std::io::Error`.

The last change allows existing `NotFound` branches to remain reachable while
retaining the full contextual cause for permission, type, and data failures.
Existing coverage includes
`v2_receipt_owned_missing_note_still_quarantines_the_exact_archive` in
`reflection/retention_v2_tests.rs`; no additional fixture was needed.

No local compiler, formatter, parser, runtime, or fixture execution was run
under the BSOD hold. Hosted validation is still required.
