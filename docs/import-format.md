# NEOTH prior-assistant import contract

`neoth-migrate` brings operator-owned memory from OpenClaw, Hermes,
OpenHuman, Veronica, Obsidian and generic local exports into NEOTH's
`idx_groundtruth` view. Imported rows are candidates: they keep their source
provenance and do not become operator-verified facts merely because they were
present in another assistant.

The runnable 1.0 flow is:

```text
neoth-migrate detect --output import-manifest.yaml
neoth-migrate dry-run --manifest import-manifest.yaml
neoth-migrate apply --manifest import-manifest.yaml --confirm
neoth-migrate status
```

`detect` and `dry-run` are read-only. `apply` requires explicit `--confirm`,
preflights every declared source, writes all rows in one SQLite transaction,
and records a durable local audit lifecycle. A failed source aborts the whole
run; there is no default partial-import mode.

## Manifest

The input is YAML:

```yaml
sources:
  - name: openhuman-home
    path: ~/.openhuman
    kind: assistant_home
    hint: openhuman

  - name: operator-vault
    path: ~/Documents/Notes
    kind: markdown
    hint: scope:global
```

Each source has four fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique operator-readable name used in reports and audit events. |
| `path` | yes | Absolute path or a path beginning with `~/`, resolved against `--root`/the operator home. |
| `kind` | yes | Reader selected from the table below. |
| `hint` | no | Assistant family for `assistant_home`, SQLite provenance hint, or `scope:<scope>` override. |

Duplicate or empty source names are rejected on apply. Missing paths are
reported by dry-run and rejected by apply.

## Reader kinds

| `kind` | Input | Apply support |
| --- | --- | --- |
| `assistant_home` | Complete OpenClaw/Hermes/OpenHuman/Veronica home | yes; requires `hint: openclaw`, `hermes`, `openhuman`, or `veronica` |
| `markdown` | Recursive Markdown directory | yes |
| `markdown_file` | One Markdown file | yes |
| `json_dir` | Recursive `.json`/`.ajson` directory | yes |
| `json_file` | One JSON value/array/object | yes |
| `sqlite` | One SQLite file, or one directory containing a direct SQLite file | yes |
| `lance_arrow` | Lance dataset inventory | scan only |
| `git_tree` | Git repository inventory | scan only |
| `faiss_flat` | Flat-vector inventory | scan only |

An apply manifest containing a scan-only kind is rejected before any row is
written. This is deliberate: an inventory-only reader must not be silently
reported as a completed migration.

### Whole-home reader

`assistant_home` is what generated manifests use. It recursively discovers:

- Markdown (`.md`, `.markdown`), including nested workspace, memory, skill and
  vault notes;
- JSON and nested JSON containers (`.json`, `.ajson`);
- line-delimited JSON (`.jsonl`, `.ndjson`);
- every file with a real SQLite header and extension `.db`, `.sqlite`, or
  `.sqlite3`, not merely the first database in one hard-coded directory.

OpenHuman `profile_facts(subject, predicate, object, confidence)` rows are
preserved as complete triples, with the existing `confidence > 0.7` gate.
Other SQLite stores contribute non-empty text columns. JSON extraction follows
known content fields (`statement`, `text`, `content`, `body`, `message`,
`fact`, `claim`, `note`, `value`) through nested arrays/objects. Exact claims
are deterministically sorted and deduplicated before insertion.

The whole-home policy excludes credential/auth/secret/keychain/cookie/browser
stores, `.env`, cache/log/temp/build trees, and the complete NEOTH target tree.
Those exclusions prevent secrets or the target database itself from becoming
recall candidates. Provider config conversion is a separate explicit surface:

```text
neoth-migrate import-config --auth-profiles <path> --models-providers <path>
```

That command strips sensitive fields and emits reviewable `freedom.yaml`
provider stanzas; it never writes API keys into memory. Cron conversion is
similarly explicit and review-first:

```text
neoth-migrate import-crons --timer <unit.timer> --crontab <file>
```

It emits jobs for operator review rather than activating foreign automation
implicitly.

## Self-target and atomicity guarantees

Before mutation, apply rejects a source that:

- resolves to the target `views.db` path;
- is a symlink or hard-link alias of that file;
- lives inside the target workspace (normally `~/.neoth`);
- is the target workspace itself; or
- is an ambiguous `sqlite` directory containing the target database.

A recursive source may be an ancestor of the target (for example a manually
declared operator home), but the target workspace is pruned from its walk.
This makes whole-home discovery useful without permitting self-ingestion.

Every supported source is fully parsed before `BEGIN IMMEDIATE`. If preflight
fails, zero rows are inserted. Insertions then run in one transaction. Any
database error rolls it back. Re-running a successful migration is idempotent:
`INSERT OR IGNORE` relies on NEOTH's unique `(statement, scope)` index and
never resets the state of an existing fact.

The audit file is opened once and held for the complete operation. If a
terminal audit write nevertheless fails after SQLite has committed, the
command returns an explicit "rows committed" error and attempts a
`MIGRATION_FAILED` event with `rolled_back: false`; it never misreports that
committed data was rolled back.

## Persistence and provenance

Each imported claim is inserted with:

- `fact_state = candidate`;
- `confidence = 0.5`;
- `maturity = emerging`;
- source weight `{<source-tag>: 1}`;
- provenance tag `import:openclaw`, `import:hermes`, `import:openhuman`,
  `import:veronica`, `import:obsidian`, or `import:session`.

The default scope is `global`. A manual source can set `hint: scope:<value>`.
For OpenHuman profile triples the scope is `subject:<subject>` so facts about
different people do not collapse into one global identity.

## Audit and status

Real applies append fsynced JSONL events to:

```text
~/.neoth/neoth-migrate-audit.jsonl
```

On Unix the file is forced to mode `0600`. Audit intent must be writable before
mutation starts. Events are:

| Event | Meaning |
| --- | --- |
| `MIGRATION_STARTED` | Durable intent with operation id, source count, target path and atomicity flag. |
| `MIGRATION_BATCH` | One committed source result: claims seen, inserted, duplicate count. Emitted only after commit. |
| `MIGRATION_COMPLETE` | Successful terminal result; retains legacy `GROUNDTRUTH_IMPORTED` / `0x99` fields. |
| `MIGRATION_FAILED` | Failed preflight, transaction, or post-commit audit; stage, bounded error detail, and truthful rollback outcome. |

`neoth-migrate status` reads the latest lifecycle and reports
`never_started`, `in_progress`, `complete`, or `failed`; `--json` exposes the
same state for GUI/automation consumers.

The sidecar is not the daemon WAL. A standalone migrator must not violate the
daemon's single-writer invariant by opening its WAL concurrently.

## Operator verification

After a successful apply:

```text
neoth-migrate status --json
neoth groundtruth list --limit 50
```

Review candidates before promoting them. Keep the foreign assistant home
read-only during cutover and retain its backup until recall parity has been
checked.

## Compatibility

Unknown manifest fields are ignored by Serde's default map handling; existing
reader names remain stable. New reader variants may be added, but a scan-only
variant never becomes silently mutating inside an existing binary. A future
breaking manifest change requires a new major contract version and an explicit
converter.

## Changelog

- 2026-07-13 — Corrected the public contract to the shipped manifest/apply
  implementation; added complete assistant-home discovery, self-target
  refusal, fail-closed atomic preflight, durable failure audit and status.
- 2026-05-23 — Initial pre-implementation import proposal.
