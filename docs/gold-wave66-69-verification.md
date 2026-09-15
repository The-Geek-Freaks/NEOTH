# W66/W67/W68/W69 verification — local Source09 validation

## Scope and evidence custody

Source09 contains eleven manual source paths plus reviewed generated `Cargo.lock`:
270 pre-docgen / **271** post-docgen inputs, **25** filters, **27** mandatory
fixtures and 19 commit paths. The evidence builder verified all 271 inputs and
2,920 selected tests. The source manifest and test matrix are
`docs/verification/gold-wave66-69-source-manifest.json` and
`docs/verification/gold-wave66-69-test-matrix.json`.

## Local validation

| Gate | Result |
| --- | --- |
| NativeClippy12 | PASS — 3m02s |
| TestBuild06 | PASS — 1.70s |
| selected06 | PASS — 2919 / 0 / 1 in 163.23s; 2,920 selected from a 14,744-test catalog; 25 filters and 27 mandatory fixtures |
| contracts05 | PASS — 750 / 0 / 0 |
| CLI docgen | PASS — 1 / 0 / 0 |
| GUI build05 | PASS — 20.68s |
| GUI05 full suite and catalog | PASS — 742 / 0 / 0 in 5.94s; 742-test catalog |
| GUI Clippy02 | PASS — 4m53s; minimum free 215.38 GiB; peak 6.85 GiB |
| Python45, CI matrix, fresh GUI lint | PASS |

The GUI evidence uses binary
`81A75F3BC560CFBB0D3A540348FDB796226023F8E474C6AA731E3DF504BD2DA9`.
The W67 route retains the real GUI→service→ProviderWorker selected-home context
binding, three HTTP calls, three completed usage rows, WAL-file presence and
context SHA/byte plus alternate-context assertions.

## Behavior boundary

The local source set covers W66 canonical session-sort card framing, W67
selected-home audit/usage and prepared-context binding, W68 canonical Council
recall, W69 Windows software-renderer CI coverage, and the orphaned code-map
refresh recovery regression. Earlier fixture failures remain diagnostic history.

This is local validation only. It does not claim full CI, installer acceptance,
visual or accessibility acceptance, external delivery, release publication, or
ROAD-leaf completion.

## Road boundary

No ROAD leaf changes. Counts remain **1324/1015/307/2** (raw309/pre-tag308).
W62 installed-CLI acceptance and W70/W71 result provenance remain separate.
