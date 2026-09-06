# Code-map evidence for coding plans

`neoth code` retains the code-map selection that informed a generated plan.
Inspect it with the existing session command:

```console
neoth --output json kanban show <session-id>
```

The response keeps its existing `session` and `tasks` fields and adds
`code_map_receipts`. Older sessions and sessions created without code-map
context return an empty receipt list. The table view shows a compact digest
and indicates whether the context was shortened.

## What a receipt establishes

Each `neoth.coding.code_map_receipt.v1` receipt is persisted on the session
before the corresponding decomposer call. It records prepared input, not
proof that a remote provider received it or completed a response. A failed
provider call can therefore leave a receipt without generated tasks.

The receipt binds the session and the attempt to:

- The canonical repository root display and its physical identity. The display
  and indexed names use the existing secret redaction boundary; a source with
  changed metadata explicitly reports `metadata_redacted: true`. Redacted
  names are display evidence and are not reversible identifiers. The exact
  physical identity stays in local inspection and does not enter plan-review
  prompts.
- Equal, positive index and graph generations, checked for freshness when
  the context was assembled.
- The selected source files and symbols, and the exact bounded caller list
  used by the renderer. A generic repo-map component records only file and
  symbol entries actually included by its summary renderer.
- SHA-256 commitments to the operator prompt, original assembled context,
  context passed to the typed prompt builder, and final logical prompt passed
  to `DecomposerLlm::complete`. These are hashes of exact UTF-8 bytes; they do
  not claim to describe subsequent provider-specific HTTP framing.

`sources` describes the selection **before the decomposer's input-budget
truncation**. `submitted_context_sha256`, `submitted_context_bytes` and
`context_truncated` describe what remained after that truncation. A receipt
with truncation does not claim that every originally selected symbol reached
the model. The logical provider-prompt hash also covers the typed untrusted
data envelope used for the request.

The receipt contains metadata and hashes, with no raw operator prompt,
assembled context or provider prompt. Existing session data has its own
retention rules; this does not change the session's pre-existing prompt field.
Path and symbol metadata are sanitized before persistence, with no raw backup
copy. The context hashes still commit the exact rendered bytes. A root identity
that would require redaction is rejected instead of changing its meaning.

## Repair, generation changes and failure behavior

A malformed response permits the existing single repair attempt. Attempt 2
must preserve the same operator, original selection, context bytes and
generation evidence as attempt 1. Its logical provider-prompt hash changes
because the repair prompt also contains the first response. A failed receipt
write, readback or validation stops that attempt before another provider call.

Targeted recall and a generic summary are combined only when their root,
physical identity and generations match. If the generic snapshot advanced
while context was being assembled, the coding path keeps the original
targeted component and its evidence. It does not relabel that context with the
new generation. Later reindexing does not rewrite historical plan receipts.

After response validation, all generated tasks are inserted in one SQLite
transaction. A later insert failure rolls back every task in that batch.
No database transaction remains open while awaiting a provider response.
The stored input receipt remains a record of the prepared request even if
task insertion subsequently fails.

## Storage and compatibility

The nullable `idx_kanban_session.code_map_receipts` column is added idempotently
when an older coding database is opened. Receipts survive session archival
and disappear with their owning session. They are not stored in the mutable
session summary. Corrupt receipt data causes explicit inspection and
recording errors; it is not rendered as an empty list. SQLite values must be
bounded TEXT or NULL: oversized TEXT and BLOB values are rejected before
conversion to an owned Rust string.

The stored representation retains the common source evidence once. The repair
record adds only its attempt number and logical provider-prompt digest, after
an exact comparison with the first attempt's complete context basis. Inspection
reconstructs the two logical receipts, so the public response remains easy to
compare without duplicating the source graph in SQLite. Both attempts share
one 128-KiB storage limit. Each of the at most two source records is limited to
56 KiB of serialized metadata, leaving space for both attempt commitments.

The existing plain decomposer API remains usable for callers without code-map
context. The coding CLI uses the typed context entry point. Plan review can
read the associated context digest and generation metadata from the same
session evidence.

## Context limits

The `code_map` configuration keeps Chat/Channel auto-context opt-in separate
from explicit coding requests:

```yaml
code_map:
  auto_context_max_files: 0
  coding_recall_max_files: 8
  coding_callers_per_symbol: 3
  coding_summary_token_budget: 2048
```

The coding file limit accepts 1–50, caller limit 0–20, and summary budget
128–12000. Zero callers disables caller enrichment. These settings are ceilings;
the final source selection also fits the shared 64-KiB rendered-context limit
and the serialized metadata limits. Targeted context takes precedence over the
generic summary. Any source selection shortened by those limits reports
`selection_truncated`, separately from the decomposer's later
`context_truncated` flag. There is no separate arbitrary cap of 128 symbols or
384 callers in the receipt validator.

The summary uses the existing four-UTF-8-bytes-per-token estimate as a strict
byte ceiling; it is not a tokenizer or billing measurement. The decomposer
still enforces its separate combined input ceiling. Invalid
values are rejected before configuration publication. The next `neoth code`
invocation reads new coding settings; accepted daemon reloads update
auto-context for subsequent messages. Explicit CLI/MCP inspection limits and
self-improve's private scope remain separate policies.
