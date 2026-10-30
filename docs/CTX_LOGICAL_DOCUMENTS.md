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


## Physical DOCX section-property ranges

The DOCX extractor's structure v2 additionally retains the complete XML byte range
of each supported Word section-property container. Intermediate containers under
body/p/pPr are labeled paragraph_properties; containers directly under body are
labeled body. The ranges address the exact uncompressed word/document.xml member
and share the existing source/container digests. They are property-element ranges,
not rendered pages, section-content extents, heading hierarchy, inherited layout,
or proof of valid Word layout. No implicit section is fabricated.

Nested, revised, foreign and unsupported-context containers are omitted whole.
The report retains bounded omission details and total omitted-container counts;
overflow or an interrupted scan cannot produce a complete structure. A metadata
limit summary can exist with zero omitted section containers when tables caused
the shared limit. Its complete flag still remains false.

Structure v1 stays readable and serializes without a section_properties field.
Version2 requires that field and its exact parser/scope contract; explicit null
and inconsistent ranges or completeness are rejected. The existing source
transaction and search output retain the projection with the document provenance.
This does not change logical identity, consent, file-move or purge authority.

W2641's seven new cases are included in the accepted document62 selection.
Run 41039038367 on producer a3e5b071 passed all 62 document and 115 cost/provenance
cases, both Clippy gates and the CLI build. Root verified the original artifacts,
case identities and producer source hashes. This proof covers the v2 section
projection; the newer v3 numbering extension below still awaits its own
document76/cost115 runtime qualification.


## Physical DOCX numbering properties

Structure v3 adds numbering_properties alongside the existing table and
section-property projections. It records only explicit numPr containers in
direct body paragraphs or paragraphs in flat table cells. Each record binds
the complete paragraph and property-container byte ranges to the same original
word/document.xml member and document digests.

num_id greater than zero is an unresolved numbering_reference. num_id zero
is numbering_removed; it does not refer to a numbering definition. An absent
ilvl remains null. Present levels are limited to the Word-supported range 0-8.
Numeric attributes use a bounded unsigned decimal digit representation after
XML entity decoding; other forms are omitted. The projection does not resolve
numbering.xml or styles.xml, infer inherited numbering, generate bullets or
ordinals, or assert that the document has valid Word layout.

Duplicate, nested, revised, foreign or unsupported properties cause the whole
outer paragraph to be omitted. Publication waits until that paragraph closes,
so later conflicting properties cannot leave a partial accepted record.
Numbering in nested paragraphs counts once against the containing outer
paragraph, independent of which properties occur first. Unsupported containers
outside paragraphs are omitted as complete observed containers.

At most 256 records and 64 omission details are retained. Counts include records
omitted by limits. An interrupted table scan also retracts prior numbering
records inside its unaccepted XML tail. The shared 256 KiB serialized metadata
limit covers tables, sections and numbering together; its summary may contain
zero omitted numbering paragraphs if another projection caused the limit.

Historical structure v1 and v2 continue to read and serialize without a
numbering_properties field. Version 3 requires that field and both its exact
parser/scope contract and the section_properties field. Explicit null, invalid
ranges, overlapping accepted/omitted paragraphs and inconsistent counts are
rejected. The existing source transaction remains the sole persistence owner:
reopen/search preserve the projection, failed replacement rolls back, successful
replacement clears stale metadata, and purge removes it with the source.

This adds explicit physical numbering provenance. Rendered list semantics,
headings, code-block structure and full A03 acceptance require their own evidence.
