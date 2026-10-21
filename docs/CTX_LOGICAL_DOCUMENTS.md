# Logical documents in ctx

Use explicit logical documents when a document needs a stable identity across
content revisions and indexed-path changes. Existing label-based indexing remains
available for unbound sources.

## Register a document

Read the current request epoch:

```text
neoth --output json ctx --logical-epoch
```

Create a UTF-8 JSON request file using the returned epoch. The example uses zero
only for a store that has not purged any sources:

```json
{
  "action": "register",
  "logical_document_id": "manual-1",
  "logical_event_id": "manual-1-register-1",
  "authorization_epoch": 0,
  "index": {
    "label": "Operator manual",
    "content": "The complete text to index.",
    "file_path": "manuals/operator.md",
    "content_type": "prose",
    "source_category": "manuals"
  }
}
```

Apply the file and inspect the current state:

```text
neoth --output json ctx --logical-request request.json
neoth --output json ctx --logical-status manual-1
```

A path exactly equal to "-" reads JSON from stdin. Requests are limited to 10 MiB,
indexed UTF-8 content to 8 MiB, and scalar request metadata to 8192 bytes.
Identifiers use 1-128 ASCII letters, digits, underscores, hyphens or periods.
Unknown request fields are rejected. Logical modes cannot be combined with
search, ordinary indexing, purge, CCR retrieval/savings or their modifiers.

The index object also accepts the existing optional source event ID and validated
document provenance. Without extraction provenance, the raw-container digest is
unknown; the result only proves the indexed text digest.

## Revise content or rename indexed metadata

Read the current status first. A revision uses action "revise", a new logical event
ID, the current epoch, an index object, and an expected object containing all three
current values:

```json
{
  "source_id": 42,
  "content_revision_id": "replace-with-the-returned-64-character-revision",
  "current_event_id": "manual-1-register-1"
}
```

The numbers and revision above are illustrative: use the exact returned values.
A stale source, revision or event is rejected. A revision replaces the physical
source and both search projections atomically while preserving the logical ID.

For a metadata rename, use action "metadata_rename" with the same guards,
new_label and optional new_file_path instead of an index object. This updates only
indexed metadata and the search paths; it does not move a file on disk or replace
its indexed content. Omitted or null new_file_path clears the stored path. The
receipt records the previous label/path.

## Replays and deletion

Repeating an event with identical normalized semantics returns its original
receipt without repeating the mutation. After later changes, that receipt has
replayed=true and is_current=false and names the current event. Its historical
source ID is not a promise that the old physical source still exists. Reusing an
event ID with different content or metadata fails.

A successful source, category or all-source purge removes logical ownership and
its receipts in the same transaction and advances the store-wide epoch. Pending
requests for any document must then use the current epoch. An empty purge leaves
the epoch unchanged. Replaying an old registration after deletion fails rather
than recreating the document.

The epoch and hashes detect stale or changed requests; they do not grant consent.
These commands operate within the caller's existing local-store access. They do
not add a watcher, provider request, automatic file move or approval bypass.

JSONL emits one object per successful command. An absent status is explicit:
{"logical_document_id":"manual-1","found":false}. Invalid requests and malformed
status identifiers fail before opening or migrating the store.
