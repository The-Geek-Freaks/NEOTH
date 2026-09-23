# W433 — citation native and public-provider results

Run `35874789863` at `010d535c84b3966270877ae9bb808b51c8ea35e5` succeeded.
All 50 selected native cases were discovered and executed exactly once; each
has its actual successful test terminal, an exit-zero receipt and no timeout.
The previously misclassified stderr-interleaved CLI case now passes. Root
independently verified all nine source/input bindings and ordered terminals.

The ordinary CLI made three authorized public DOI requests from separate fresh
homes. Crossref and OpenAlex returned live records for `10.1038/nature12373`.
Root read their actual CLI JSON logs and independently recomputed the Rust
length-prefixed claim hash, record fingerprint and binding hash. Both match.
Semantic Scholar returned the typed `unavailable:rate_limited` outcome. That
is an observed provider terminal, but establishes no successful record coverage.
No rate limit was bypassed and no repeated provider request was made here.

The machine record is `docs/verification/gold-wave433-citation-results.json`.
This admits native50 and two live records only. P1-12 remains open pending its
remaining provider/presentation evidence; universal GUI reducers may carry only
after the relevant sources and actual terminals are checked. The macOS W155
callback remains a distinct native-presentation boundary. This record does not
claim all providers, rendered accessibility, all platforms or release readiness.

All execution took place on GitHub. Local work was bounded text/JSON/hash/Git.
