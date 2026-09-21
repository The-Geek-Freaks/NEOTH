# W160-W161 - hosted compiler and portable acceptance repairs

These are reviewed source repairs awaiting GitHub-hosted execution. They do not
close a Road item. The workstation runs no compiler, parser probe, formatter,
test, fixture, product, GUI, or model.

## W160: observed compiler and strict-lint failures

CI `35617862631` ran source `669f32db5d655295dd4069e737cb1d292c3cedf7`.
The Linux job `106393119516` reported two `collapsible_if` diagnostics, and
adapter job `106393119951` reported missing test-side `Debug` for
`LiveReasoningOwner`. The run was cancelled after those shared failures were
retained; cancellation is not a passing result.

`LiveReasoningOwner` now derives `Debug` only under `cfg(test)`. The owner
contains surface and generation metadata, not reasoning text. The two
let-chain changes retain the previous zeroization and provider output/error
paths. Independent source review approved all three bounded repairs.

Evidence under `work/gold-20260906/wave160-hosted-compile`:

- Linux log SHA-256: `C63F1D78BA679B51F9003D2F8954E95A47187158A2F8521338F8425D882DBA48`.
- Adapter log SHA-256: `EF3DA6D375EB9D06C779BF6046F5B7903CA1919BF4E24F88E023D845D6AB3ED9`.
- Review SHA-256: `27B4367E61685CEEA405BAE4CEAB8424F2E6E9030F030D57DB74519CDDDBA0EE`.

## W161: portable diff-impact root identity

Preview `35604567130`, job `106348413498`, ran older source
`ff146652e6ef230bd500206978f183e5040644d6`. Native CLI, GUI, relay and
migration builds passed. Portable lifecycle, including the hosted Windows
software GUI probe, also passed. Diff-impact acceptance then failed at its
first refresh-root assertion: `fixture refresh root was not bound to the
requested fixture root`.

The fixture now converts Windows verbatim local and UNC paths to their
equivalent Win32 spelling before the existing case-exact comparison. This
accounts for Rust canonicalization's `\\?\` prefix. Different roots and
different casing remain unequal. Production root identity, CLI arguments,
receipt schema and all acceptance assertions remain unchanged.

Evidence under `work/gold-20260906/wave161-preview-failure` includes the full
hosted log (SHA-256
`83F63CC8F0FF2775DB79B0BB3EDE7AE07B2F571CBDF5C4C08422EB8DBA6E0B03`),
individual lifecycle/diff-impact receipts, repair report and independent
source review. A fresh preview must pass the actual helper on the repaired
source; the older successful build does not validate subsequent W153/W155 work.

## Required next evidence

The formatting follow-up `b58ec47f87ed552d13b95310113e320ff3dc6b7e`
passed Preflight `35622231947` and Code Quality `35622233230`. Full CI
`35622258375` then reported `E0507` in the shared lib-test build, adapter job
`106407927790`: the attach fixture attempted to move `response.turn_id` from a
borrowed response. The narrow follow-up clones that existing typed ID, as the
adjacent session and capability fields already do. The adapter log is retained
with SHA-256 `14E27E89E1BE4778BDA0D1A3FF8FDA2A87AA1C58277429F4BA7151BE8E4C88F0`.
The failed-source CI is confirmed cancelled after retaining its diagnostics.
Windows preview `35622261449` continues because this test-only failure does not
invalidate its production build or W161 acceptance path.

Run the existing Preflight and Code Quality gates, full native/GUI CI, and
Windows preview on the newly published source. Keep W137 automatic routing
and W142 terminal refresh unresolved until their actual hosted diagnostics
identify and verify a repair. Citation integration remains a separate batch.
