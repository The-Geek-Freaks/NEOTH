# W100 - shared codegraph enrichment readiness in Doctor, GUI and Buddy

The Coding panel and Buddy expose a read-only enrichment readiness action for
the configured NEOTH home and managed roots. This result stays separate from
the existing selected-repository lifecycle status. It reports a typed disabled,
ready or unavailable state; a ready result describes prerequisites for a future
eligible call, not an executed selector, an enriched response or permission to
invoke a tool.

The core helper contains the existing Doctor readiness checks and wording.
Doctor preserves its Pass mapping for disabled/ready and Warn mapping for
unavailable. Configuration validation, the exact generated registration,
read-only physical-root inspection, the eight-root bound and matching complete
index/graph generations remain required. It does not open an MCP child, call a
provider, modify configuration or create, refresh or repair a map.

GUI diagnostics compare the registration to the CLI resolved by the existing
GUI resolver. This is necessary because the running GUI executable differs
from the registered CLI. The expected path never comes from the untrusted
registration itself. Runtime W53/W95 admission keeps its existing exact
current-process identity check; diagnostic classification grants no authority.
Disabled configuration is still reported as disabled if no CLI can be resolved.

Both the panel and Buddy invoke the same worker and Slint publication path.
Each publication is bound to its configuration revision and individual request
revision. A late response cannot replace a newer result, including when the
configuration has not changed. Lifecycle configuration load and successful
apply refresh the separate readiness display.

The added native regression identities are:

- `code_map::enrichment_readiness::tests::w100_missing_config_keeps_the_doctor_disabled_wording_without_opening_sqlite`
- `code_map::enrichment_readiness::tests::w100_invalid_config_stops_before_mcp_or_sqlite_inspection`
- `mcp::codegraph_server::tests::w100_diagnostic_identity_accepts_expected_cli_and_rejects_gui_lookalike`

The existing real W58 Buddy callback fixture now exercises disabled, invalid and
fresh-ready states, and queues the newer result before a late older response.
A test-only counter proves both queued callbacks were processed before the
retained result is asserted. This stays inside the existing macOS native
main-thread harness identity, while retaining its selected-root assertions.
An owned small CLI-path marker supplies a controlled fallback; it is never
executed and no large executable copy is needed.

All current-source formatting, strict lint, compilation and runtime evidence
remain pending GitHub-hosted gates. No local compiler, formatter, parser, test
or product execution is permitted on the affected workstation. The cumulative
[source manifest](verification/gold-wave95-96-source-manifest.json) and
[test matrix](verification/gold-wave95-96-test-matrix.json) bind the admitted
source and required test identities.

[Preflight 35116495298](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35116495298)
on `7d210ff8201efa59a10c6158ea139ef076ba9e41` requested formatting in four Rust
files. W105 applies only those emitted layouts and import ordering, after source
comparison. [Code Quality 35116495877](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35116495877)
passed the preceding source. The updated formatting/static gate is still required;
neither result establishes compilation or the 62 native / 7 GUI runtime identities.

This advances the CRG-05 GUI status/error and Buddy test controls. Selector
editing, Buddy enable/disable/explain controls, native Read/Grep/Glob/Bash
integration and final package/live-provider acceptance remain open. No roadmap
checkbox closes: **1324 total / 1015 checked / 307 open / 2 partial**.

User instructions are in [code-map lifecycle](code-map-lifecycle.md#check-enrichment-readiness)
and the [configuration reference](configuration.md).
