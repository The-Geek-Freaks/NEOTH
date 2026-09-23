# Gold Wave 312 - hosted core fixture import repair

Hosted Core `d2` run `35829527494` ran `cargo check -p neoth --tests --locked
--keep-going` and stopped with five errors plus two NEOTH test-target warnings.

The errors are three missing `FreedomConfig` references in
`sub_agents/runtime.rs` (`E0412` twice and `E0433` once) and two missing
`Provider` trait imports for `AuthorizedProvider.complete(...)` in
`cli/loop_cmd.rs` (`E0599` twice). The test module now imports
`FreedomConfig`; the loop test module now imports `Provider`.

The two NEOTH test-target warnings were an unused `persist_edges` test import
in `code_map/recall.rs` and an unused `Provider as _` test import in
`cli/hemispheres.rs`; both were removed. The hosted run also displayed the
pre-existing multiple-GUI-target manifest warning and the vendored
`peeroxide-dht` dead-code warning. They are not part of this source repair.

No local compiler, formatter, parser, test, runtime, or fixture execution was
run under the BSOD hold. Hosted Core test-target validation remains required.
