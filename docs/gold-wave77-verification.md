# W77 - Apply consumes the configured impact policy

Status: reviewed source and lightweight gates passed; fresh remote Rust gates
are pending. No local heavy compilation ran.

The real Apply dispatcher previously replaced the operator's validated impact
limits with `ImpactOptions::default()`. Both CodingService and CLI now capture
the accepted policy with the selected database and canonical physical root.
The existing advisory stores these limits unchanged. It does not authorize
Apply, change risk decisions, discover a different root or refresh the store.

Three new native fixtures cover default/maximum conversion, invalid-policy
rejection, and real Apply/WAL behavior with narrow and wide node limits. The
latter checks root/generations, truncation and raw-patch exclusion. Independent
review caught a missed CLI caller in the initial three-file proposal; the
approved four-file revision includes it. The original BLOCK report remains
retained. Root moved the unchanged policy test module to the end of its file.

The same batch fixes two Rust 1.91 `cmp_owned` findings in completed/cancelled
Buddy GUI test predicates. Full CI `35067941794` on `69d9c15b` failed Linux
quality on these two sites; its successful beta job did not substitute for the
pinned compiler. The two predicates retain their expected status strings.

The [manifest](verification/gold-wave77-source-manifest.json) now covers 288
inputs: the previous W76 281-file scope plus seven packaging/documentation
inputs recorded separately in its preview follow-up. The [matrix](verification/gold-wave77-test-matrix.json)
requires 45 native and 5 GUI identities. Earlier manifests retain their original
scope and are not relabeled as complete evidence for later source changes.

| Boundary | Result |
| --- | --- |
| Four-file policy review and GUI comparison repair review | APPROVE, static |
| Focused rustfmt | Five files passed |
| Python/source contracts | 55 passed, 0 failed |
| GUI source lint | PASS |
| Rust compile, Clippy and behavior | Pending fresh GitHub CI |
| Portable preview `35069306601` | Separate earlier `e6f24af8` snapshot |
| Installed, visual/accessibility and final release acceptance | Not established |

ROAD wording now reflects already-present review/decomposition/advisory Apply
consumers and validated policy reload instead of calling all of them absent.
No checkbox closes: 1324 total / 1015 checked / 307 open / 2 partial;
raw309 / pre-tag308. Heavy local Rust builds remain suspended.
