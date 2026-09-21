# W180: Preserve the failing portable impact result

Windows preview run `35658158597`, job `106526773696`, built the CLI and GUI at
`cc0af93882b885ded730b4b1b108c54b89db6fb6`. Its portable lifecycle receipt reports
twelve passed checks, including the Hosted software-backend GUI runtime probe.
This is an unsigned, uninstalled preview from that older source, not acceptance
of subsequent W175/W177/W178 changes or a final release.

The next portable diff-impact check failed: a fresh `callers` query had the exact
changed-symbol seed but lacked the expected concrete `caller_symbol` declaration.
The previous helper threw before preserving the successful command's graph
projection, so the result does not establish whether the edge was absent or
unresolved. The overall preview run failed and no release claim follows.

The helper now emits a bounded identity-only diagnostic before its unchanged
caller assertion: counts, truncation flags, up to sixteen impacted identities,
and separate retained/unresolved expected-edge indicators. A new native test
`code_map::diff_impact::tests::fresh_snapshot_diff_impact_retains_same_file_caller_declaration`
uses an actual fresh snapshot, the exact fixture body/diff, persisted graph,
endpoint resolution and caller traversal. These changes improve reproduction
and evidence; they are not a demonstrated repair of the underlying defect.

Root reviewed the two-file diff and the diagnostic field shapes against the
production impact DTO. PowerShell checkout bytes follow the existing CRLF
attribute. Hosted execution remains required. No local parser, helper, compiler,
formatter, fixture, test or product ran.

The failure and lifecycle transcripts are retained in
`work/gold-20260906/wave179-hosted-repair/cc0-preview-receipts` from artifact
`10670601827`; its GitHub-reported archive digest is
`sha256:30fe644e88396e2d59c493906d1f83d844952df3a76461c70c88b654b292076e`.
The W180 source receipt is in `wave180-portable-impact/SOURCE-REPAIR-02.json`.
No Road checkbox closes.
