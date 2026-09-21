# W129 — observed GUI fixture Clippy repair

Full CI `35567383561` on `f87e063432e73b6d86f12bcb87d8435ebd0c28bc`
reached strict Linux workspace Clippy and failed with `obfuscated_if_else` in
the shared `w122_inventory_json` native GUI fixture. The boolean
`then(...).unwrap_or_default()` account projection is replaced by an explicit
`if`/`else` returning the same Telegram rows or an empty vector. Product code,
fixture values, assertions and warning policy are unchanged.

The completed Linux job is `106231814849`; its log is retained under
`work/gold-20260906/wave129-ci-recovery/linux.log`. Other platform jobs in that
run were still active when this correction was prepared. This repair requires
fresh hosted Clippy and native tests. No local formatter, compiler or tests ran.
