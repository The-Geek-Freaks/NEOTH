# W78 source-to-roadmap reconciliation

Date: 2026-09-16. Source inspected: `389b5038264562ccd0e438e8d0a6eed450784a0d`.
This is a documentation-only correction, with no new runtime or release claim.

The CRG-03 description still asserted that the diff parser, persisted exact
extents and downstream consumers were absent, despite completed kernel leaves
and later consumer work. CRG-04 did not distinguish implemented consumers from
remaining acceptance, and CRG-05 understated existing reload/Doctor support.
The ROAD now describes those boundaries explicitly. Its checkbox sequence is
unchanged: **1324 total / 1015 checked / 307 open / 2 partial**,
raw unchecked 309 / pre-tag 308.

| Scope | Current implementation | Remaining boundary |
| --- | --- | --- |
| CRG-03 diff impact | `code_map/diff.rs`, `diff_impact.rs` and persisted exact extents provide bounded acquisition, hunk/symbol seeds, canonical physical-root/generation binding and separate file fallback. `cli/code.rs`, `cli/review.rs`, `coding/dispatcher.rs` and `mcp/codegraph_server.rs` carry explicit Coding, Review, advisory Apply and CLI/MCP results/citations. | Current compiled/runtime proof; named structural-risk and GUI/Buddy/Doctor contracts; packaged acceptance. |
| CRG-04 test gaps | `code_map/test_coverage.rs` keeps `no_observed_test_is_not_absence` explicit. Coding/Review/Apply and CLI/MCP retain the same calibrated projection and citation identity. | Surface, lifecycle, remaining risk and package claims require their own scoped acceptance. |
| CRG-05 outline enrichment | `mcp/dispatch_loop.rs` and `cli/mcp.rs` admit the typed PreToolUse boundary before child execution. The exact built-in outline route validates registration, read-only source, root/generation and post-call freshness. `config/ops.rs`, `config/reload.rs` and Doctor integrations provide default-off policy/reload/status checks. | Generic native Read/Grep/Glob/Bash coverage and other codegraph selectors are not established. At this baseline, `invoke_authorized_with_audit_sink_effect_gate` still appends byte-identical configured and built-in sidecars twice. A separate reviewed change is needed. |

The inspection identifies existing chains; it does not establish universal tool
coverage or replace behavioral tests. In particular, Apply's structural data
is informational and does not grant approval or change the risk gate.

Validation remains GitHub-hosted: full CI `35070262418` targets W77 source
`389b5038`; unsigned portable preview `35069306601` targets the earlier
`e6f24af8` and cannot prove W77 Apply policy propagation. Both were still running
when this report was prepared. Local Cargo compilation, Clippy and linking
remain suspended after repeated host restarts. No release, installation or
visual acceptance is claimed.
