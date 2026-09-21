# W133 — hosted compilation and adapter-fixture recovery

Full CI 35573074634 on 1f96e099 completed with failure. Linux job 106248712267
found three unused default-feature adapter parameters and a nine-argument
dispatcher helper. Windows 106248712180 and macOS 106248712361 both rejected
Slint string field access in the pairing approval button. Optional-adapter job
106248712415 passed its first five exact tests, then rejected the sixth test's
noncanonical home-bound WAL location; the seventh test was not reached.

The three-path repair adds a feature-guarded consume for the unused references,
groups the dispatcher helper's immutable dependencies in `LiveRouteContext`,
and gives all four new dispatcher fixtures the required `wal/000001.wal` path.
The Slint button now requires nonempty text; the existing Rust callback and
private-input envelope still validate exact code length and alphabet.

Preview 35573077459 on the same source was cancelled after the compile failure
was known; completed cancellation was confirmed. Neither that preview nor the
failed full CI establishes native or portable acceptance. Static Preflight
35572946068 and Code Quality 35572946388 passed on 1f96e099 before these repairs.

Focused independent review approved all three exact source hashes. Fresh hosted
gates remain required. Source
regression assertions remain intact. No local compiler, formatter, parser, test,
fixture, product binary or GUI ran. No Road checkbox or count is changed.
