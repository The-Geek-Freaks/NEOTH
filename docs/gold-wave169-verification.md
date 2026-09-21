# W169 — pinned channel schema extraction

Status: diagnostic extraction tooling is independently source-approved. The
custody schema fixture and importer integration require the actual hosted
artifact and remain pending. GOLD-LF-001-02 is not closed.

The manual GitHub workflow reads OpenClaw's generated bundled channel metadata
at commit 4c667aac8859114bd8f0a589ac6cd1de8bfe1474. Before decoding, the extractor
checks the exact 292905 bytes, SHA-256 and framed Git blob ID. It decodes the
static string-array payload with Python literal/JSON readers, without running
JavaScript, installing upstream dependencies or starting OpenClaw.

Expected channel IDs come from W166's hash-bound package inventory. Duplicate
IDs, missing schemas and a changed manifest set are explicit failures. The
walker inventories closed properties, account maps, arrays, compositions and
local references. Cycles, unbounded or unknown structural forms and semantic
siblings it cannot account for produce named blockers. An incomplete schema
cannot silently become a complete inventory.

The workflow runs focused regression tests first and retains extraction status,
partial inventory and source evidence on extraction failure. A test failure
before extraction is visible in workflow logs and may have no artifact. Output
contains schema structure and hashes, never an operator configuration or secret
value. The source review is retained in
work/gold-20260906/wave169-channel-schema/EXTRACTOR-ROOT-REVIEW.md.

The next gate is an actual source-bound GitHub artifact. Its observed coverage
and blockers determine the remaining extractor work before package-owned
schema validation and account/source-path ledger integration. No local parser,
test, fixture, compiler or product execution is permitted by this batch.
