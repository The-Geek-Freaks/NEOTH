# A130 Linux strict-Clippy repair

Full Linux CI `35677727994` at source `a130526e` failed the
`gui_code_map_impact_controller` integration target with five dead-code
diagnostics:

| Compile site | Diagnostics | Minimal repair |
| --- | --- | --- |
| Production `gui_action/ouro_q8.rs`, imported by the headless controller | `MAX_OBSERVATION`, `OuroQ8VerifyError::unobserved`, `run_ouro_q8_verify`, and `timeout_error` appear unused because this target does not import desktop `ouro_gui`, their real consumer. | Added a reasoned `dead_code` allowance only to the controller's `#[path] gui_action` harness module. Production `gui_action.rs` and `ouro_q8.rs` are unchanged. |
| `BuddyVaultMirrorReceiptWire.created_at_unix` in `panel_logic.rs` | Required wire field is deserialized but not displayed. | Kept strict deserialization with `#[serde(rename = "created_at_unix")]` and renamed the private storage field to `_created_at_unix`. |

The panel-logic edit is limited to the W184 Vault receipt wire field and
preserves its required JSON key under `deny_unknown_fields`; pending W185 work
is otherwise untouched.

| Artifact | SHA-256 |
| --- | --- |
| CI log `ci-a130-linux.log` | `DA65611D7E85CA1FA273F042466F7237D05E7A455CEAD846464B3F2A2A5390E2` |
| `SRC/neothd/tests/gui_code_map_impact_controller.rs` before | `BF42FFE24F8DF0201D880C5D3D81DF5B2C8992A99CACA73632D2FD910E93ABAD` |
| `SRC/neothd/tests/gui_code_map_impact_controller.rs` after | `9BC7701C2805E7D8A6D3155558FC262A1AA3E6578DD295BC13BC88566DD2B980` |
| `SRC/neothd-gui/src/panel_logic.rs` before | `F9285146C28DFC362502FE788FE728008B5D814767E1D90B11386B2A540DFCE7` |
| `SRC/neothd-gui/src/panel_logic.rs` after | `FFABCBCF4ECB6140C3D2E134433ED4A038EA1109D9D6CA4E99C4289FB34C7D74` |

Source-only repair. No local executable, compiler, parser, formatter, test,
runtime, Git, or network command was run. Hosted rerun remains required.
