# W279 — native fs glob with indexed Codegraph sidecar

`neoth fs glob <absolute-root> <root-relative-pattern>` provides bounded file-name discovery through the existing OS allowlist. It has its own `OsDirectoryList` permission action: the operation opens the admitted root as a no-follow capability and enumerates only children from that handle. It never routes through `OsFileRead`, opens matching files, invokes a shell, or follows symlink/junction/reparse entries.

`--max-results` is 1..64 (20 by default); `--max-depth` is 0..16 (8 by default); traversal stops at 4096 entries. JSON paths are normalized root-relative `/` paths and sorted. Empty matches are successful and include `empty: true`.

`--codegraph-enrichment --repository-root <absolute-root>` is optional. When the master outline switch is on, the sidecar is based only on fresh complete `code_map_files` and `code_map_symbols` DB rows for returned paths. It includes bounded indexed names, kinds, and line ranges, plus the exact call/root/generation binding. No raw source and no provider data are returned. The sidecar is dropped if the indexed root, identity, completeness, freshness, or generations change before attachment.
## Verification boundary

The focused hosted lane selects thirteen cases: eleven new identities
(ten universal and one Unix-only symlink case), plus the existing exhaustive
ActionKind and IFC-clearance cases. These cover CLI bounds, rooted and
drive-relative pattern refusal, sorted and empty discovery, the actual
PreToolUse and indexed-sidecar callers, cancellation, required-audit refusal,
root replacement, stale snapshots and bounded symbol overflow.

Windows directory identity comes from FileIdInfo on the retained directory
HANDLE; Unix uses device/inode metadata. Both are rechecked before sidecar
publication. A discovery-entry budget overflow yields an explicit truncated
empty result; a result-count overflow returns the sorted bounded prefix.
Required audit completion precedes public output.

Source review is separate from hosted compilation and execution. No local
compiler, formatter, parser, test or product runtime was run under the BSOD
hold. The current CLI reference will be refreshed from the next exact-source
hosted export.
