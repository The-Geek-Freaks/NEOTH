# W378 — macOS FullCI954 managed-browser fixture recovery

## Provenance

The macOS FullCI954 log at
`work/gold-20260906/wave357-publication/fullci954/macos954-job.clean.log`
records these selected failures:

- `exact_marker_and_executable_resolve_and_revalidate`
- `retained_binding_detects_executable_replacement_and_symlink_parent`
- `missing_generation_fails_closed_without_ambient_fallback`

Its preserved source binding is
`work/gold-20260906/wave357-publication/group721954/source-bindings/SRC_neothd_src_tools_managed_browser.rs`,
with Git object `e4a14b62202693d2ab22462fedbdf5c322a48000`. The current file
object is `775434abbd17d4e872d84c7be23f59d7498dfff1` (W377's ZIP-writer
lifetime repair included).

## Exact/revalidation fixtures

The old source passed raw `tempfile::tempdir()` paths into the explicit-home
no-follow resolver. macOS surfaced those roots under `/var/folders/...`; `/var`
aliases `/private/var`, so the deliberately strict absolute capability walk
refused the alias before the fixture reached its marker, executable-identity,
or replacement assertions.

The current `fixture_home()` is the narrow fixture repair: it canonicalizes
`std::env::temp_dir()` and creates each retained `TempDir` beneath that physical
root. The exact-marker and retained-binding fixtures now use `fixture_home()`;
the latter also uses it for both hostile and link homes. Their meaningful
assertions remain intact: successful initial resolution/revalidation, rejection
after executable replacement, and rejection of a deliberate managed-root
symlink.

No change is appropriate in `open_absolute_bound_directory`,
`open_bound_real_child_dir`, or the production resolver. Accepting the `/var`
alias in the no-follow walk would weaken the intended boundary.

## Missing-generation fixture

The 954 failure asserted incidental helper text. W369 changed
`resolve_from_manifest` to attach the stable, resolver-owned context
`resolve managed-browser root beneath explicit home`, and the fixture now
asserts that context plus no creation of `managed-browser`. This is a distinct
failure-message contract repair, not the macOS path-alias repair.

## Current source and verification boundary

W347/W352 installation and CLI behavior remain preserved. W377's nested ZIP
writer scope remains preserved. This recovery adds no source mutation because
both actual macOS fixture causes are already represented in the current source.

Under the BSOD hold, no local compiler, formatter, parser, test, or runtime
command was run. Hosted macOS must execute the three named managed-browser
tests against the current source, followed by the selected hosted
format/compile gate.
