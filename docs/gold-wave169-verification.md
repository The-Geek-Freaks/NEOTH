# W169 — pinned channel schema extraction

Status: diagnostic extraction passed GitHub run 35653170374 at source
61eaa58fc060d211e73e1535caf3dcd04b80d7f0. The custody schema fixture and importer
integration are in progress. GOLD-LF-001-02 is not closed.

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

Run 35652616234 verified both pinned inputs and observed all 26 expected IDs,
with 3230 typed paths and 22 explicit empty-schema blockers. JSON Schema `{}`
admits arbitrary JSON; the next extractor revision records these as opaque
subtrees requiring explicit leaf mapping. It does not infer any inner fields,
credential handling or adapter support from an unconstrained schema. Its
regression tests also run in the ordinary push preflight.

The workflow runs focused regression tests first and retains extraction status,
partial inventory and source evidence on extraction failure. A test failure
before extraction is visible in workflow logs and may have no artifact. Output
contains schema structure and hashes, never an operator configuration or secret
value. The source review is retained in
work/gold-20260906/wave169-channel-schema/EXTRACTOR-ROOT-REVIEW.md.

The successful rerun records 3252 schema rows across all 26 expected channels,
including 22 explicit opaque subtrees, with zero uncovered extraction blockers
and zero duplicate channel/path/type/scope identities. The opaque rows still
block migration; extraction success does not supply their missing mappings.
The package input is frozen byte-for-byte at SHA-256
A7E60AFBB1E0D013100EE8C30F5237307E6552923F34B55A39B2DC1263B0283F
(384625 bytes). Its source/evidence/status receipt is retained in
work/gold-20260906/wave169-channel-schema/HOSTED-FREEZE.json.

Preflight 35653170741 passed formatting and then rejected the newly added
extractor unit-test command because the exact cadence allowlist was not updated.
The matching test now admits that specific command in its existing order;
fresh hosted preflight is required. Full CI 35653174520 and Windows preview
35653179383 are running on the same published source. No local parser, test,
fixture, compiler or product execution is permitted by this batch.
