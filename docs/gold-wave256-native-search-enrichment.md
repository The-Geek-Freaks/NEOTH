# Gold Wave 256: native literal file search

`neoth fs grep <path> <literal>` searches one allowlisted UTF-8 file through
the existing OS file-read gate. It is a literal search only: there is no shell,
regular-expression engine, recursive traversal, or glob expansion. The search
uses the descriptor retained by the allowlist/autonomy admission and therefore
does not reopen the selected path after PreToolUse.

The literal must be non-empty and at most 256 bytes. The default result cap is
20 lines and the command accepts at most 64. Each output line has a one-based
line number and a UTF-8-safe 512-byte total snippet cap, including ellipses.
When a line is clipped, its window includes the first matched literal. JSON reports `matches`,
`empty`, and `truncated`; truncation covers either the result cap or a clipped
line.

`--codegraph-enrichment --repository-root <absolute-root>` uses the same
default-off `code_map.outline_enrichment` master switch as `fs read`. It emits
one bounded, untrusted native `fs-grep` sidecar only after the selected file
has been read and the literal scan over those retained-descriptor bytes has
completed, and the existing root/index freshness checks still hold. The
sidecar is path-outline impact evidence for the selected indexed file; it does
not claim symbol-level extraction from individual matching lines, provider/MCP
coverage, or completion of CRG-05.
No matching line is an explicit no-op: `empty` is true and no hook or
codegraph enrichment is attached.

The typed PreToolUse origin is `DirectCliOsFileSearch`. Its bounded arguments
are the canonical selected path, literal, result cap, and canonical repository
root. A denial, cancellation, stale index, missing descriptor, or unavailable
sidecar cannot authorize or alter the underlying file-read result.

No local compiler, formatter, parser, test, fixture, or runtime command was
run under the BSOD hold. Hosted validation remains required.
The internal native-search admission keeps cancellation and its deadline together
as one bounded control value. This is a lint-only parameter grouping: the
existing cancellation-before-read and deadline-before-read behavior is unchanged.
