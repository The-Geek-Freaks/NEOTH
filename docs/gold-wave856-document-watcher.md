# Local document-discovery watcher

## Purpose and status

ADOPT31-B8 adds an opt-in, local document-discovery poller to `neothd`. It
finds eligible revisions below operator-selected directories and creates
private, metadata-only notices for a later review decision. It is not an OS
filesystem event watcher, an extractor, a distiller, a staging path, a
provider call, an activation mechanism, or an outbound sender.

The current backend, daemon wiring, and connected CLI path have been approved
by static review only. Hosted CI still has to validate the merged
unit/integration paths before B8 is accepted as integrated. No local build,
formatter, parser, test, fixture, product runtime, or GUI validation was run
under the active BSOD hold. There is no GUI toggle: the `.slint` work remains
outside this backend slice.

## Enabling discovery

The feature is off by default. While `doc_ingest.enabled` is `false`, the
daemon does not construct the worker, resolve a root, open the NEOTH home,
read state, or inspect the filesystem.

Put an explicit top-level `doc_ingest` block in the live configuration and
reload the daemon through the normal configuration-reload path:

```yaml
doc_ingest:
  enabled: true
  watch_paths:
    - 'C:\Users\operator\Documents'
    - 'D:\Reference'
  max_per_day: 3

# Optional. When configured, this vault is an additional discovery root.
obsidian_vault: 'C:\Users\operator\Obsidian'
```

`watch_paths` entries must be non-empty absolute paths. An enabled
configuration needs at least one `watch_paths` entry or a configured
`obsidian_vault`. The vault counts as a root but is configured separately from
`doc_ingest`.

The limits are deliberately small and validated before an enabled worker can
scan:

| Setting | Default | Allowed value | Meaning |
| --- | ---: | --- | --- |
| `enabled` | `false` | `true` / `false` | Explicit operator opt-in. |
| `watch_paths` | `[]` | At most 32 roots together with `obsidian_vault` | Absolute directories selected by the operator. |
| `max_per_day` | `3` | 1–100 | Newly admitted pending notices in a rolling 24-hour period. |

An active configuration is resolved at runtime with no-follow directory
capabilities. A missing or unusable configured root refuses that scan instead
of silently widening its scope. Duplicate aliases are collapsed by opened
directory identity; overlapping roots discover a physical file once, with the
most-specific nested root taking ownership.

## What it scans

The worker polls every 60 seconds. Each pass recursively inventories the
selected roots, skips symbolic/link-like entries, and accepts regular files
only with these extensions:

| Extension group | Notice `source_kind` |
| --- | --- |
| `.pdf` | `pdf` |
| `.docx`, `.pptx`, `.xlsx`, `.odt`, `.ods`, `.odp`, `.epub`, `.rtf` | `office_or_book` |
| `.txt`, `.md`, `.markdown` | `plain_text` |

Scanning is bounded. A pass permits up to 32 roots, 2,048 directories, 4,096
entries per directory, 65,536 visited entries, 4,096 queued directories and
4,096 inventory candidates. It attempts at most 64 candidate hashes and reads
at most 256 MiB of source bytes in one pass. A single source must also fit the
existing 64 MiB document-source limit. The persisted rotating cursor avoids
starving later files; a file that does not fit the remaining aggregate byte
budget waits as the next candidate for a later pass.

For an accepted file, the worker hashes a freshly reopened bound snapshot and
rechecks its file identity and metadata. Its revision id binds the resolved
root identity, relative path, source kind, and source SHA-256. A changed file
therefore creates a distinct revision; earlier pending or deferred revisions
for that same root-relative path become superseded. A dismissed revision stays
dismissed until a materially different revision is discovered.

## Private notice state and quota behavior

The durable authority is the local private file
`<NEOTH_HOME>/doc_ingest_state.v1.json`, serialized by the adjacent private
lock file `doc_ingest_state.v1.lock`. The watcher has no WAL authority. State
contains only notice metadata, status, root-relative bookkeeping, quota
timestamps, and a scan cursor. It never stores document body text.

Each operator-visible notice contains:

- `revision_id` — the 64-character revision digest.
- `source_path` — the absolute local path, retained so an operator can review
  the exact file after a restart.
- `source_kind`, `source_bytes`, and `source_sha256`.
- `first_seen_unix`.

This absolute path is private local metadata, not document content. State is
limited to 4 MiB and 4,096 entries. Reads reject malformed, oversized, or
schema-invalid state without overwriting it. Writes use a bound private lock
and atomic replacement. On Windows, an unsupported parent-directory sync is
accepted only after exact live-byte and bound-parent verification; it is not a
power-loss-durability claim.

When the rolling 24-hour `max_per_day` quota is full, newly found revisions are
recorded as deferred rather than made reviewable. After quota expiry, a
deferred revision is promoted only after a fresh snapshot confirms that it is
still present in a currently selected root. A scan error retains the existing
state and is retried on a later poll.

## Operator review and dismissal

Use the dedicated proactive commands against the intended NEOTH home:

```text
neoth proactive documents
neoth proactive dismiss-document <revision-id>
```

`neoth proactive documents` prints JSON with `schema_version: 1` and a
`documents` array. Every array item has the notice under `document` plus this
argv-shaped review instruction:

```json
{
  "review_command": {
    "program": "neoth",
    "args": ["skills", "--from-doc", "<source-path>"]
  }
}
```

The watcher and the listing command do not execute that review command. The
operator may run the displayed `neoth skills --from-doc <source-path>` command
to perform the existing explicit, read-only document review. The emitted argv
contains no `--distill-doc`; discovery never starts extraction, a provider
call, or document staging.

`neoth proactive dismiss-document <revision-id>` changes only the exact
currently pending revision to `dismissed` and returns its id as JSON. Unknown,
deferred, superseded, or already dismissed revisions are left unchanged and
reported as not found. Dismissal never changes the source document.

Listing a missing NEOTH home returns an empty notice list and does not create a
home directory, state file, or lock.

## Reload, replacement, and cancellation

When enabled, `DocumentIngest` joins the existing cron fleet. Its worker
fingerprint includes the complete `doc_ingest` configuration and the optional
Obsidian vault root. A relevant configuration reload replaces the active
worker; disabling `doc_ingest.enabled` removes it from the desired fleet.

The poller performs blocking filesystem work through the existing async task
boundary. Retirement marks the scan cancelled and fences its short final
state-commit section. Cancellation is checked through inventory and hashing
and again immediately before commit, so task-join completion is the boundary
after which the retired scan cannot publish further notices.

## Source of truth

- `SRC/neothd/src/config/doc_ingest.rs` defines the public configuration and
  validation limits.
- `SRC/neothd/src/daemon/doc_ingest_cron.rs` owns bounded discovery, private
  state, notice lifecycle, and cancellation.
- `SRC/neothd/src/cli/serve_tasks.rs` and `SRC/neothd/src/cli/serve.rs` connect
  the worker to the cron fleet and reload fingerprint.
- `SRC/neothd/src/cli/proactive.rs` exposes the operator listing, review argv,
  and exact-revision dismissal commands.

The adjacent [document-staging guide](gold-wave848-document-staging.md) begins
only after a separate explicit review/staging decision. Discovery itself does
not create a proposal or write a destination.
