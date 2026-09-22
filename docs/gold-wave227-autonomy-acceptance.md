# W227 — Explicit per-skill autonomy acceptance selection

P2-12 has production implementations for typed Custom skill overrides,
restrictive per-action intersection, route-bound invocation authority, current
global policy at effect time, and CLI/GUI inspect/set/reset. This batch selects
the existing behavioral evidence instead of adding another implementation.

The universal native inventory already contains the relevant tests. However,
the actual Grouped303 workflow selects only its named wave `requiredTests`
blocks: none of the 24 W138 autonomy tests was part of that execution set.
Presence in `requiredNativeTests` does not mean a grouped run executed a test.

`wave227AutonomyAcceptance` explicitly adds those 24 existing identities plus
the existing W145 loop-to-MCP retained-cap denial regression. No native identity
is duplicated and no production source is changed. The total grouped selection
becomes 328. Coverage includes configuration limits and legacy behavior, CLI
commit/readback/reset, read-only inventories, restrictive policy intersection,
route reload, channel confirmation, live global tightening, SmartApprove
rejection, actual paid-provider pre-transport denial and the loop effect edge.

P2-12 remains open. Its core acceptance requires all 25 named cases to execute
and pass against matching source, matrix and lock hashes. The independently
selected GUI receipt contract and real inspect/set/reset callback also require
actual native execution. Registry-retention tests from W224 cannot substitute
for per-skill autonomy enforcement. Release/platform gates remain separate.

No local compiler, parser, formatter, test or runtime ran. Source review and
text/JSON inventory checks are preparation for GitHub-hosted verification.

## Hosted acceptance update — 2026-09-23

Grouped328 run35790281385 on aca578a0 passed all328 exact selected cases.
All68 source-path hashes, matrix, Cargo.lock and actual per-case terminals
were checked against the frozen Git source. This includes all25 W227 cases.
Independent literal-contract review found no remaining source/selection gap.
P2-12 stays open pending actual GUI116 acceptance, including the typed receipt
and real inspect/set/reset callback. No local executable validation ran.
