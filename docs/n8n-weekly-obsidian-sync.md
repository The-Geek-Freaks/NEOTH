# Sync a weekly reflection archive to Obsidian

`POST /api/reflections/weekly/obsidian/sync` exports one existing ISO week's
archive to the configured Obsidian vault. Grant the dedicated
`reflections:weekly:obsidian:write` API-token scope, or use the instance's
operator master token. Dream, recall, memory-write and provider scopes do not
grant this operation.

Configure `obsidian_vault` as an absolute path in the accepted NEOTH
configuration. `obsidian_subdir` defaults to `NEOTH-sessions` when absent or
blank and must be one safe directory name. The request accepts exactly one
field and cannot override paths or content:

```json
{"week":"2026-W39"}
```

The week must be eight ASCII characters in `YYYY-Www` form and a real ISO week
for that ISO year. The source is `<NEOTH home>/reflections/<week>.jsonl` and
the destination is `<vault>/<subdir>/Reflections/<week>.md`. Dream enablement
and Dream scheduling do not control this explicit, scoped archive operation.
It neither produces new reflections nor changes the proactive queue.

Every complete JSONL record is checked before opening the vault for mutation.
Historical records without a producer key retain their order and are joined
using the existing reflection Markdown separator. A producer-owned record
must be the only keyed record and exactly match its persisted immutable
`weekly-intents/<week>.json`. No queue receipt is required for export.
Malformed, truncated, wrong-week, linked, unreadable or over-limit sources
are refused. Missing or empty archives return a quiet result without creating
vault directories. Limits are 8 MiB of source and rendered output, 1,024
records, 256 KiB per line and 128 KiB for an owned record's intent.

The response envelope's `data` contains `week`, `written`, `reflection_count`,
`bytes_written`, `durability`, `accepted_epoch` and `request_id`. Archive text,
producer keys and filesystem paths are excluded. Durability distinguishes:

| Value | Meaning |
| --- | --- |
| `not_written` | No source records were exported. |
| `published_and_synced` | Atomic publication and its durability were confirmed. |
| `published_durability_unknown` | Publication happened; disk durability was not confirmed. |

A repeat replaces the selected week's note atomically from a newly validated
archive snapshot. Source corruption leaves an existing note unchanged. Existing
linked or hardlinked target files are refused. The export is not an external
delivery receipt or an exactly-once operation.

Invalid requests return 400; insufficient scope or a retired generation returns
403. Missing vault configuration and storage/audit failures return redacted 503
errors. A failed request after admission, lost connection or unknown durability
does not prove rollback or authorize an automatic retry. Inspect the note and
audit evidence before manually retrying.

The blocking worker retains the accepted configuration's effect lease through
durable admission, filesystem work and the terminal audit attempt. Reload and
shutdown drain that lease, including when the HTTP waiter disconnects. Audit
records contain opaque verified caller identity, request ID, epoch, week and
outcome, without bearer values, note content or paths.

The `reflection_weekly_sync` n8n starter remains inactive after import. Its
editable default is Sunday at 19:00 UTC; it sends the current UTC ISO week
using Luxon's ISO week-year rather than the calendar year. Schedule it after
the weekly producer and select an HTTP Header Auth credential with the dedicated
scope. Set a NEOTH origin reachable from the n8n instance; importing a workflow
does not establish container-to-host connectivity or deliver note content.

Hosted compilation and behavior acceptance are recorded separately in the Gold
progress files. Source implementation alone is not a passing runtime gate.
