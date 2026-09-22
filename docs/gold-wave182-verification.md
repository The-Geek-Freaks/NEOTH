# W182: Earlier Hosted type checking of core tests

The old a72 full CI encountered the same three library-test compiler diagnostics
in optional-adapter, SSH and beta jobs while native builds were still compiling.
The binary-only CLI-reference build did not cover those `cfg(test)` paths.

The existing CLI-reference job now first runs
`cargo check -p neoth --tests --locked --keep-going` with a 15-minute bound and its existing
single Cargo worker. It checks the default-feature core test targets without
test-binary linking or execution. The existing 25-minute CLI build, one-minute
reference export and source/hash-bound artifact remain. A 50-minute outer bound
leaves nine minutes for setup and upload beyond those bounded steps.

This early check does not prove behavior, platform-specific test paths, optional
features, GUI integration or release acceptance. Native and broader feature
gates remain required. No local execution is enabled by this change.

Independent review: `work/gold-20260906/wave182-core-test-preflight/REVIEW.md`,
SHA-256 `76217F5DA487CCE8EA7828B7FC74056BD5A4D2133059548ABF9F69B30EE530B4`.
Verdict: static approval. First Hosted run `35670885967` on `1e8beb99`
failed at the new core-test check after finding three E0063 diagnostics in
`council_adversarial.rs`. Its synthetic A/B/E budget fixtures omitted the new
optional `prompt_tax_source` field. All three now explicitly use `None`, as
these fixtures exercise retention rather than prompt-tax attribution. The
existing assertions remain unchanged; fresh Hosted compilation is required.

The retained failure log has SHA-256
`0BDCFA09A24F1D6375B2C22FB18CDBF05B1B73AE725DAB8FF9A81291ECEEA6BD`.
Repair receipt: `work/gold-20260906/wave182-core-test-preflight/CORE-TEST-REPAIR-01.md`,
SHA-256 `140398FBD8DBF7793E82F5B35A7CA1257E894D58099A573F22610548C5E5BCAB`.
The following documentation-only head `fbca7750` passed Preflight
`35671020802` and Code Quality `35671019947`; neither proves test compilation.

The second run `35671482575` on `850aad7e` reached the library-test target and
found three E0308 diagnostics: one missing `&Path` borrow in the chat feedback
fixture and two in the training-export fixtures. All three now borrow the
existing `home.join("views.db")`; their assertions and product code are unchanged.
The retained log SHA-256 is
`3345C5B82907209475C68E4C6B8B84CDA2D061C52EE9FDED3493C750C3DDB706`.
The check now uses `--keep-going` to report independent target errors together
within the unchanged one-worker/15-minute limits. It still fails if any target
fails. Fresh Hosted compilation remains required.

The preceding W177/W180 formatting and W179 alias-scope repair passed Preflight
`35670551761` and Code Quality `35670550997` on `97e2137a`. Its CLI build remains
separate from the new core-test check. No Road checkbox closes.
