# W82-W84 - configured GUI impact limits and CI runtime repairs

Reviewed source is admitted. Focused static validation is recorded in the
[test matrix](verification/gold-wave82-84-test-matrix.json); actual execution of
these Rust changes requires the next GitHub-hosted CI run. Local heavy Rust
compilation remains suspended after recurring workstation restarts.

W82 fixes a GUI parity defect: the Coding form and Buddy action previously used
default impact limits. Their shared start path now loads and validates the
accepted Freedom configuration, converts its policy once, and stores that exact
snapshot in the admitted operation. Invalid configuration produces a visible
error before admission. Index freshness and execution authority are unchanged.

The native integration fixture starts real indexed analysis with a one-node
limit, changes the caller's options, and proves that the admitted operation
retains its original cap. A later operation uses the wider cap. The generated
Buddy callback fixture also verifies narrow and wide results, root, digest,
generations and invalid-config rejection without an active worker or false
receipt. Review caught missed integration callers and weak count parsing in the
initial proposal; only corrected revision 02 was admitted.

The prior Linux job on `389b5038264562ccd0e438e8d0a6eed450784a0d`
([run 35070262418](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35070262418))
passed pinned Rust 1.91 strict Clippy and doctests. Its Nextest report contains
16,805 executed cases: **16,796 passed and 9 failed**. Nextest separately reported
20 skipped tests; the JUnit file's zero-skipped count does not mean that all
workspace tests ran. The report timestamp is bound to its completed producing
test step, and its XML SHA is recorded in the new matrix.

| Observed failures | Cause and reviewed correction |
| --- | --- |
| 3 retained-context retry/fallback fixtures | Initial operator requests already carry the authority directive. Fixtures now assert that current contract and use explicit native safety-policy refusal metadata to reach the intended existing recovery route. Request counts, retained context, untrusted local draft boundary, final-body hash and WAL ordering remain asserted. Production retry logic is unchanged. |
| 2 executions of one GUI digest fixture | The expectation serialized a JSON map in lexical key order; production hashes a struct in declared field order. The fixture now computes the accepted struct commitment using the same field order and serializer. Other provenance checks remain intact. |
| 4 generated GUI fixtures | The Ubuntu runner lacked the X11 library dynamically loaded by xkbcommon. CI now installs `libxkbcommon-x11-0` and retains the complete locked workspace run under Xvfb. |

W84 fixes the corresponding package dependency omission. Automatic ELF scanners
do not discover this dynamic load. DEB adds `libxkbcommon-x11-0`, and RPM adds
`Requires: libxkbcommon-x11`. Existing `dpkg-shlibdeps` and `AutoReqProv` processing
is preserved and protected by the package contract. The existing script joins
the offline push preflight with build-tool denial still active. It exercises
temporary fake products and validation paths; actual built-package metadata and
clean-machine launch remain release acceptance work.

The same prior-source CI run completed Windows Nextest with **16,731 passed /
7 failed**, plus 22 skipped tests and one leaky passing test. Five failures match
the retry/digest fixtures above. Two additional Buddy start/cancel fixture
failures are under separate investigation; this batch does not claim to fix
them. Their Linux behavior was previously masked by the missing X11 library.

Local checks pass: 38 Python contracts, formatting of the six changed Rust
owners, both shell syntax checks, GUI source lint and `git diff --check`.

The [source manifest](verification/gold-wave82-84-source-manifest.json) covers
290 inputs: the prior 288 plus the Linux builder and its existing contract. The
matrix carries 48 required native and 6 GUI identities, with explicit JUnit
classes. The GUI-controller fixture appears in both a native path-import target
and the GUI binary; these are separate test instances whose outcomes must both
be retained.

GUI changes follow the existing product, design and component rules. No visual
layout, tokens or motion changed in W82. Source lint is not rendered, keyboard,
screen-reader or installed-product acceptance. The earlier portable preview
source `e6f24af8` does not validate the changed GUI policy or W79/W80 behavior.

ROAD checkboxes remain unchanged: 1324 total / 1015 checked / 307 open /
2 partial, raw309 / pre-tag308. Earlier Linux CI failures and pending platform
and preview results remain explicit. This batch does not establish release
readiness.
