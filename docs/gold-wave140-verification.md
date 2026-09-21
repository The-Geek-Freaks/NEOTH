# W140 — observed type-hierarchy strict-lint repair

Full CI 35581691195 on 12048d6c reached the library but Linux quality job
106275797909 failed on four Clippy diagnostics in code_map/type_hierarchy.rs:
one needless borrow, two needless as_bytes calls, and filter_map_bool_then.

The repair removes the redundant reference, uses the equivalent string byte
length directly, and separates filter/map while preserving iteration order
and selected names. No lint was suppressed, no test was weakened and no
runtime contract changed. Root reviewed the complete four-hunk diff against
the complete saved hosted log after the independent source edit.

Source SHA-256: `AB6EDA837C6F3C08B1577653F6F1D88DC0E5E463B657B27FE80BAC7C0940EC45`.
Fresh hosted strict lint and tests are required. Other jobs in the preceding
run are tracked separately; their results do not prove this repair or W137.
No local compiler, formatter, parser, tests, fixtures, product or GUI ran.
Road counts and checkboxes are unchanged.
