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

`detect` is source-read-only (unless `--output` is requested). `dry-run` never
changes imported data, but it does persist an immutable private plan checkpoint
under `~/.neoth/migrations/plans/`. `apply` requires explicit `--confirm` and
accepts only the exact SHA-256 plan produced by dry-run. A source change creates
a different plan hash and fails closed before imported data is changed.

## OpenClaw channel configuration

`detect` reports an OpenClaw `openclaw.json` separately from memory sources and
prints the exact inspection command. The file is never parsed as conversation
history or inserted into ground truth:

```text
neoth-migrate import-openclaw --config ~/.openclaw/openclaw.json
neoth-migrate import-openclaw --config ~/.openclaw/openclaw.json --json
```

This command is a read-only migration plan. It accepts OpenClaw's JSON5 syntax,
resolves `$include` files only inside the canonical configuration directory,
and rejects traversal, symlink escapes, cycles, duplicate keys, excessive
depth, excessive file count and oversized inputs. Include paths are resolved
relative to the file that contains them.

Every effective configuration leaf after include/merge resolution is listed
exactly once without its value. The report marks a leaf as `mapped`,
`needs_secret`, `needs_relink`, `needs_runtime`,
`unsupported`, or `unknown`. Secret-shaped fields and OpenClaw secret
references are always redacted. `unknown`, `unsupported`, `needs_relink` and
`needs_runtime` are hard apply blockers; `needs_secret` blocks activation until
the credential is supplied through NEOTH's credential flow.

OpenClaw's `channels.whatsapp` is explicitly mapped to NEOTH's
`whatsapp_baileys` adapter, not the Meta Business adapter. Its Baileys auth
directory is device/session state and therefore requires a guided QR relink.
The current command does not write live channel configuration; its ledger is
the fail-closed contract for the subsequent consent-gated apply step.

Memory, Markdown and supported SQL text are preflighted and committed in one
SQLite transaction. Foreign config, cron, agent and skill definitions are not
activated: they are sanitised and staged under the plan-specific review
quarantine. Credential references become a checklist without values. Vector
sources with extractable text/metadata become NEOTH re-embedding queue entries;
raw dimension/model-specific vector bytes are never copied.

## Manifest

The input is YAML:

```yaml
acknowledge_unsupported: false

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

The top-level `acknowledge_unsupported` flag defaults to `false`. Leave it
false for the first dry-run. If the plan reports an inventory that NEOTH cannot
safely transform, apply remains blocked. Setting it to `true` after review
records an explicit, plan-bound skip; it never turns an unsupported artifact
into a successful import.

Each source has four fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique operator-readable name used in reports and audit events. |
| `path` | yes | Absolute path or a path beginning with `~/`, resolved against `--root`/the operator home. |
| `kind` | yes | Reader selected from the table below. |
| `hint` | no | Assistant family for `assistant_home`, SQLite provenance hint, or `scope:<scope>` override. |

Duplicate or empty source names are rejected. Missing paths are represented as
blocked artifacts in the plan and therefore block apply unless explicitly
acknowledged as unsupported.

## Reader kinds

| `kind` | Input | Apply support |
| --- | --- | --- |
| `assistant_home` | Complete OpenClaw/Hermes/OpenHuman/Veronica home | yes; requires `hint: openclaw`, `hermes`, `openhuman`, or `veronica` |
| `markdown` | Recursive Markdown directory | yes |
| `markdown_file` | One Markdown file | yes |
| `json_dir` | Recursive `.json`/`.ajson` directory | yes |
| `json_file` | One JSON value/array/object | yes |
| `sqlite` | One SQLite file, or one directory containing a direct SQLite file | yes |
| `lance_arrow` | Lance dataset plus text/metadata sidecars | review queue for NEOTH re-embedding; raw-only input is blocked |
| `git_tree` | Git repository inventory | unsupported; blocked unless explicitly acknowledged |
| `faiss_flat` | Flat-vector files plus text/metadata sidecars | review queue for NEOTH re-embedding; raw-only input is blocked |

Every declared kind is represented in the deterministic plan. Unsupported
artifacts are never silently dropped or reported as imported. Without explicit
acknowledgement they block apply before the memory transaction. With explicit
acknowledgement they remain visible in plan, review output and status as
`blocked_unsupported` / `explicitly_acknowledged_unsupported`, with
`applied: false`.

### Whole-home reader

`assistant_home` is what generated manifests use. It recursively discovers:

- Markdown (`.md`, `.markdown`), including nested workspace, memory and vault
  notes;
- JSON and nested JSON containers (`.json`, `.ajson`);
- line-delimited JSON (`.jsonl`, `.ndjson`);
- every file with a real SQLite header and extension `.db`, `.sqlite`, or
  `.sqlite3`, not merely the first database in one hard-coded directory.

A file with a SQLite extension but no valid SQLite header is emitted as an
explicit blocked artifact; it is never silently skipped or treated as an empty
database.

The same walk also identifies the OpenHuman runtime surfaces that are not
memory:

- `config.toml`;
- SQLite `cron_jobs`, including `expression`, `command`, schedule JSON,
  `job_type`, `prompt`, `name`, `session_target`, `model`, `enabled`, delivery,
  `delete_after_run` and `agent_id` when present;
- custom agent TOMLs below `<workspace>/agents` and `~/.openhuman/agents`;
- `SKILL.md`, `skill.json` and resources below `~/.openhuman/skills`,
  `~/.agents/skills`, `<workspace>/.openhuman/skills`,
  `<workspace>/.agents/skills` and legacy `<workspace>/skills`;
- credential key/path references; and
- vector stores and their extractable text/metadata sidecars.

`detect` adds `~/.agents` as a separate OpenHuman-family source when present,
because that user-global skill root is a sibling of `~/.openhuman`.

OpenHuman `profile_facts(subject, predicate, object, confidence)` rows are
preserved as complete triples, with the existing `confidence > 0.7` gate.
Other SQLite stores contribute non-empty text columns. JSON extraction follows
known content fields (`statement`, `text`, `content`, `body`, `message`,
`fact`, `claim`, `note`, `value`) through nested arrays/objects. Exact claims
are deterministically sorted and deduplicated before insertion.

The memory importer excludes config, cron/automation, agent, skill, vector,
credential/auth/secret/keychain/cookie/browser stores, `.env`,
cache/log/temp/build trees, and the complete NEOTH target tree. Those inputs
remain plan-visible but cannot become recall candidates or active runtime
configuration. Sensitive config keys and credential-like paths are reduced to
references such as `key:model.api_key` or `file:<path>`; the value bytes are not
serialised into the plan, checklist or review artifact.

The older focused converters remain available for standalone review exports:

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
implicitly. The complete `assistant_home` flow performs the same safety
boundary automatically inside its plan-bound quarantine.

## Deterministic plan and mutation binding

The plan is canonical JSON with stable source/artifact ordering. It includes:

- a semantic SHA-256 binding of the sorted manifest;
- one SHA-256 binding per recognized artifact;
- a source aggregate hash;
- category, disposition, byte count and source-relative path; and
- a final SHA-256 over the complete plan body.

For SQLite, the binding covers the database plus present `-wal` and `-shm`
sidecars so uncheckpointed rows cannot evade the mutation guard. Apply rebuilds
the plan before preflight and again immediately before `BEGIN IMMEDIATE`. The
exact immutable checkpoint must exist both times. Deleted, added or changed
recognized artifacts therefore stop the run.

Plan checkpoints are stored at:

```text
~/.neoth/migrations/plans/<plan-sha256>.json
```

## Self-target and atomicity guarantees

Before mutation, apply rejects a source that:

- resolves to the target `views.db` path;
- is a symlink or hard-link alias of that file;
- lives inside the target workspace (normally `~/.neoth`);
- is the target workspace itself; or
- is an ambiguous `sqlite` directory containing the target database.

Recursive plans also refuse symlinked source nodes. Declare the canonical
target explicitly so both the dry-run hash and apply read the same file tree.

A recursive source may be an ancestor of the target (for example a manually
declared operator home), but the target workspace is pruned from its walk.
This makes whole-home discovery useful without permitting self-ingestion.

Every transactional source is fully parsed before `BEGIN IMMEDIATE`. If
preflight fails, zero rows are inserted. Insertions then run in one transaction.
Any database error rolls it back. Re-running a successful migration is
idempotent: `INSERT OR IGNORE` relies on NEOTH's unique `(statement, scope)`
index and never resets the state of an existing fact.

After the memory commit, append-only per-artifact markers record review staging
progress. A crash after the SQLite commit but before a marker is harmless: the
next run repeats the idempotent memory transaction if necessary, verifies the
same plan hash and resumes missing quarantine artifacts. Markers bind the
target database and exact artifact hashes; a plan cannot resume against a
different target.

The review tree is:

```text
~/.neoth/migrations/review/<plan-sha256>/
  plan.json
  config/*.json
  cron/*.json
  agents/*.json
  skills/*.json
  credential-references.json
  reembed-queue.jsonl
  unsupported/*.json
```

No staged runtime artifact is copied into NEOTH's live config, jobs, agents or
skills directories. Re-embedding queue entries bind text/metadata sources by
path and SHA-256 and explicitly record `raw_vectors_copied: false`.

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

On Unix, migration files are mode `0600` and migration directories are mode
`0700`. On Windows they live below the per-user `.neoth` tree and inherit its
account ACL. Audit intent must be writable before mutation starts. Events are:

| Event | Meaning |
| --- | --- |
| `MIGRATION_STARTED` | Durable intent with operation id, source count, target path and atomicity flag. |
| `MIGRATION_BATCH` | One committed source result: claims seen, inserted, duplicate count. Emitted only after commit. |
| `MIGRATION_COMPLETE` | Successful terminal result; retains legacy `GROUNDTRUTH_IMPORTED` / `0x99` fields. |
| `MIGRATION_FAILED` | Failed preflight, transaction, or post-commit audit; stage, bounded error detail, and truthful rollback outcome. |

`neoth-migrate status` combines two independently durable views:

- audit lifecycle: `never_started`, `in_progress`, `complete`, or `failed`;
- plan lifecycle: `never_planned`, `planned`, `in_progress`, or `complete`,
  including plan SHA-256, committed/total artifacts, unsupported count,
  acknowledgement state and review path.

`--json` exposes both as top-level `audit` and `plan` objects for GUI and
automation consumers.

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

- 2026-07-14 — Added the complete GOLD-R3-08 contract: deterministic
  SHA-256-bound plan checkpoints, source mutation refusal, crash-resumable
  artifact markers, OpenHuman config/cron/agent/skill adoption, value-free
  credential checklists, review quarantine and vector re-embedding disposition.
- 2026-07-13 — Corrected the public contract to the shipped manifest/apply
  implementation; added complete assistant-home discovery, self-target
  refusal, fail-closed atomic preflight, durable failure audit and status.
- 2026-05-23 — Initial pre-implementation import proposal.
