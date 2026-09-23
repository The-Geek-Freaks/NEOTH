# W342 — Windows FullCI fixture repair

Source: FullCI run `35833337095`, Windows job `107090834419`, source commit
`750d162b`.

The chat architecture fixture previously wrote the repository map and call
edges through separate compatibility publishers. Architecture recall accepts
only one complete current snapshot, including map, call graph, imports, and
type hierarchy generations. The fixture now uses the identity-bound atomic
publisher with its empty import and type-hierarchy witnesses, so it exercises
the same complete-snapshot condition as production.

The local-anchor revalidation fixture snapshots the parity run while its bound
run lock remains held. Windows can reject a read of that active
`.parity-harness.lock` with a sharing violation. Its test-only snapshot now
excludes exactly this advisory lockfile. Persisted run artifacts remain in the
snapshot and continue to prove that revoked local source is rejected without
mutating the run.

No local compiler, formatter, parser, test, or runtime probe was run under the
BSOD hold. Hosted formatting, compilation, and the two selected fixtures remain
required.
