# W131 — root-local ImportGraph and bounded MCP queries

The code-map now carries a separate ImportGraph alongside CallGraph. Conservative
Rust and Python extraction resolves only unambiguous files within the scanned
root. Aliases, macros, ambiguous module layouts and unsupported syntax do not
create guessed edges. File and corpus byte caps apply before parsing; edge,
node, depth and rendered-text limits bound graph construction and queries.

Schema v11 stores import edges and an independent import generation. Legacy
snapshots remain invalid until rebuilt. Full and delta publications replace
the complete import graph in the same transaction as the map and call graph;
map-only publication invalidates imports. Stored endpoints must be canonical
relative paths and current indexed members of the same root.

The read-only `codegraph_imports` MCP tool offers forward/reverse traversal.
It requires active-root identity, a complete current snapshot, matching
index/call/import generations, source freshness and a final unchanged-snapshot
check. Successful replies use the existing context-binding witness. Known
indexed leaves return bound empty results; unknown paths fail. Requested
runtime policy can reduce hard query budgets. The configured filesystem-read
enrichment selector remains `codegraph_outline`-only.

Python extraction reuses the shared comment/string neutralizer, now corrected
for escaped triple terminators, assignment strings, CRLF continuations and
unsupported short-string newlines without exposing string contents as code.

Twelve focused regressions cover resolution, ambiguity, lookalikes, cycles,
budgets, endpoint rejection, generation invalidation, actual delta removal,
actual stdio tools/call binding and stale rejection, and string neutralization.
Independent review approved the six exact source files; review receipt SHA-256:
BA5A762EF0BAAA831534BD486CE68657D32424F61FA2C810A410D27917088D41.

All execution remains GitHub-hosted. No local compiler, formatter, parser,
tests, fixture or product ran. P2-11 stays open for TypeHierarchy integration,
Graphify/self-knowledge consumers and fresh native evidence. Road counts are
unchanged at 1324 total / 1015 checked / 307 open / 2 partial.

Hosted format follow-up: W131 source f3b6a0ae received 76 exact Rustfmt hunks
across six files from Preflight 35575158268 (including W133 dispatcher layout).
They were imported without local formatter execution. Fresh hosted gates remain
required; no semantic change or Road checkbox closure is attributed to formatting.

CI 35575496939 on 85658d48 reached Linux strict Clippy and rejected the
nine-argument atomic delta-publish function (job 106256308815). This observed
follow-up is being repaired with the W132 integration. Other native jobs and
preview continue; a Linux runtime pass is not claimed.
