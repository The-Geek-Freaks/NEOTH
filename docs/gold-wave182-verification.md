# W182: Earlier Hosted type checking of core tests

The old a72 full CI encountered the same three library-test compiler diagnostics
in optional-adapter, SSH and beta jobs while native builds were still compiling.
The binary-only CLI-reference build did not cover those `cfg(test)` paths.

The existing CLI-reference job now first runs
`cargo check -p neoth --tests --locked` with a 15-minute bound and its existing
single Cargo worker. It checks the default-feature core test targets without
test-binary linking or execution. The existing 25-minute CLI build, one-minute
reference export and source/hash-bound artifact remain. A 50-minute outer bound
leaves nine minutes for setup and upload beyond those bounded steps.

This early check does not prove behavior, platform-specific test paths, optional
features, GUI integration or release acceptance. Native and broader feature
gates remain required. No local execution is enabled by this change.

Independent review: `work/gold-20260906/wave182-core-test-preflight/REVIEW.md`,
SHA-256 `76217F5DA487CCE8EA7828B7FC74056BD5A4D2133059548ABF9F69B30EE530B4`.
Verdict: static approval; first Hosted result pending.

The preceding W177/W180 formatting and W179 alias-scope repair passed Preflight
`35670551761` and Code Quality `35670550997` on `97e2137a`. Its CLI build remains
separate from the new core-test check. No Road checkbox closes.
