# Sync an archived Dream day to Obsidian from n8n

`POST /api/dreams/obsidian/sync` exports existing Dream records for one UTC day.
It does not generate Dreams, call a provider, or deliver the resulting note.
The route requires the dedicated `dreams:obsidian:write` API-token scope (or the
operator master token). Other read, memory-write and provider scopes do not grant it.

Configure the NEOTH instance's `obsidian_vault`, enable `dreaming.enabled`, and
use an autonomy level that allows scheduled Dream work. `obsidian_subdir`
defaults to `NEOTH-sessions` when absent or blank and must be one safe directory
name. The caller cannot select a home, vault, subdirectory or output path.

```json
{"day":"2026-09-24"}
```

The request accepts only `day`, in exactly ten ASCII characters `YYYY-MM-DD`.
The existing archive is `<NEOTH home>/dreams/<day>.jsonl`; nonempty validated
records become `<configured vault>/<subdir>/Dreams/<day>.md`. A repeat replaces
that day's note atomically. Missing or empty input returns `written:false` and
creates no vault directories. Corrupt, linked, mismatched-day, unreadable or
over-limit input is refused rather than silently counted as an empty day.
Limits are 8 MiB per source file, 256 KiB per JSONL record, 1024 records and
8 MiB of rendered output. Existing linked or hardlinked target files are refused.

The normal JSON envelope's `data` contains `day`, `written`, `dream_count`,
`bytes_written`, `accepted_epoch`, `request_id` and `durability`. It contains no
Dream text or filesystem paths. Durability has three values:

| Value | Meaning |
| --- | --- |
| `not_written` | The selected day was empty; no note was published. |
| `published_and_synced` | The note was published and the writer confirmed durability. |
| `published_durability_unknown` | The note was published, but durability could not be confirmed. This is not a failed publication or an instruction to retry. |

Malformed requests return 400. Scope or Dream policy refusal returns 403;
a missing vault or storage/audit failure returns a fixed, redacted 503.
A 503 after admission or a lost connection may leave the caller uncertain about
publication. Inspect the existing note and attributed audit records before a
manual retry; no automatic rollback or exactly-once delivery is promised.

Before a file operation, NEOTH durably records the verified caller identity,
request ID, accepted configuration epoch and day. The existing configuration
lease remains held through the operation and terminal audit, so reload and
daemon shutdown wait for admitted work. Bearer values, Dream content and vault
paths are excluded from these records.

The `dream_obsidian_sync` starter stays inactive after import. It schedules the
previous UTC day at 02:00 UTC, sends only the day, and uses an operator-selected
HTTP Header Auth credential. Set a NEOTH origin reachable from n8n and schedule
it after the Dream producer. A container's loopback address is its own network
namespace; installing the starter does not establish container-to-host access.
