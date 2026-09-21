# W132 — persisted TypeHierarchy and bounded MCP traversal

Hosted format follow-up: Preflight `35578149373` on `a7b78704` reported
49 Rustfmt hunks across `persist.rs`, `snapshot.rs`, `type_hierarchy.rs` and
`codegraph_server.rs`. Those exact layouts were imported without a local
formatter. Code Quality `35578149332` passed on that source. Fresh hosted
format, compilation and runtime gates are still required after this import.

This slice extends the native code-map with explicit type declarations and
direct, conservative type relations. Rust uses the existing bounded `syn`
parser and retains only unambiguous local module relationships. Negative or
generic impls, aliases and unsupported scopes are omitted. Python supports
top-level simple local base classes, including bounded multiline headers and
trailing comments. Unsupported Unicode Rust names/scopes are omitted without
discarding an independent supported hierarchy. Missing relations remain unknown.

Known declarations are stored separately from relation edges, so an indexed
type with no known parents is distinguishable from an unknown type. Schema v12
adds a separate type generation; a legacy snapshot cannot claim a current empty
hierarchy. Full and delta publication bind declarations and edges to the same
root, index, call and import snapshot. Map-only publication invalidates types.

The read-only `codegraph_types` tool uses ancestor/descendant BFS with
hard source, declaration, edge, depth, node, work and text budgets. It must bind
the exact requested declaration to a complete, current, fresh snapshot before
emitting the existing context witness. A changed source, unknown endpoint,
truncated load or stale generation must produce an error without a witness.

Independent integrated review approved all five final source files after
corrections for Python headers, Unicode module names and persisted endpoint
inventory integrity. An edge cannot invent a declaration missing from the
authoritative table. Either load cap returns an empty truncated result that MCP
rejects. Sixteen new regressions cover full/delta replacement, known-empty and
unknown endpoints, missing inventory rows, stale generations, source/query caps
and actual stdio tools/call witness binding. Review receipt SHA-256:
077AEFE1E815F3B657CD3BA6D59CC9A6F41822DFE0748AF707BEB5CFC71E30B6.
Hosted compilation, native execution and release acceptance remain required.

W131's observed hosted follow-up failures are repaired within this integration:
the delta publication API exceeded Clippy's argument threshold, and its new
test used an incorrect root-identity module path plus a missing builder import.
The original failed run is CI 35575496939 on 85658d48, Linux 106256308815 and
optional-adapter 106256308937. The run was cancelled after test compilation was
known to fail; completed cancellation is confirmed. Preview 35575775478 on the
same source continues because those reported errors are confined to test code.

No local compiler, formatter, parser, test, fixture, product or GUI execution
is permitted. P2-11 and all Road counts remain open/unchanged pending integrated
native and release Graphify/self-knowledge regeneration evidence.

Format-import correction: Preflight 35579188796 caught an incomplete hunk in
the first import at 73f87a71. The tool-visible log had been truncated. The full
log contains 49 hunks and four files, not the initially recorded 39/three.
All four files were reconstructed from a7b78704 plus the complete hosted
layouts. This restores the endpoint-cap assertion and edge-cap call and includes
the omitted snapshot formatting. Fresh hosted verification remains required.
