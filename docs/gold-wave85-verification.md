# W85 - Buddy source provenance and joined cancellation fixtures

The Windows job in [CI 35070262418](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35070262418)
completed 16,738 tests on source `389b5038`: 16,731 passed and 7 failed, with
22 further tests skipped and one passing test marked leaky. Five failures match
the W83 repairs. W85 repairs the two additional Buddy fixture defects exposed
by that run. Linux had stopped those fixtures earlier at its missing X11 library.

Buddy's source channel is carried by the real `CodingStartRequest` and persisted
in `idx_kanban_session.source_channel`. Provider envelopes do not export that
arbitrary display label. The start fixture now checks the persisted request
field instead of requiring the word `buddy` somewhere in provider JSON. Its
selected-root context, actual worker requests and terminal provenance assertions
are preserved.

The cancellation fixture created a circular wait: it withheld the simulated
plan-review response until after observing a terminal cancellation, although the
service joins its in-flight provider request before publishing that terminal
receipt. The fixture now releases the response after observing the UI's
cancellation fence and alert state, then waits for settlement. It still requires
the same run ID, a cancelled receipt, no running state, an error mood and joined
provider/service tasks. Late-success rejection is not disabled.

Independent review approved the exact one-file fixture change. Focused rustfmt
passes. No production callback, cancellation or authority code changes in W85;
the admitted W82 GUI policy change is preserved. Actual fixture execution remains
pending the next complete GitHub-hosted CI run.

The preceding W82-W84 commit `5deea77a` passed GitHub Preflight `35077814742`
and Code Quality `35077814791`. Its new Linux package contract actually executed
successfully on Ubuntu with build tools denied. This is a fixture-contract pass,
not built-package or installed-product acceptance.

The [source manifest](verification/gold-wave85-source-manifest.json) retains
290 inputs, and the [test matrix](verification/gold-wave85-test-matrix.json)
retains 48 native and 6 GUI required identities. ROAD/PROGRESS are updated
together without closing checkboxes: 1324 total / 1015 checked / 307 open /
2 partial, raw309 / pre-tag308. Local heavy compilation remains suspended.
