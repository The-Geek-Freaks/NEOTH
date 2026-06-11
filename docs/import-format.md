# NEOTH Import Format

> Pre-v1.0 normative spec for **how operators bring data INTO NEOTH** —
> covers the `neoth-migrate` binary's input shape, the file layouts
> the migrator recognises, and the WAL frames the migration emits so
> imported events round-trip through `neoth recall`.

This document is the **public contract**. Operators writing custom
migrators (Hermes-incompatible profile tools, third-party chat
exports, bespoke knowledge bases) follow this spec to produce a
shape `neoth-migrate import` can consume without bespoke per-source
patching.

Closes **E-08** (PROGRESS.md) — the pre-v1.0 ship gate that
operators have a documented path for "I have N MB of past chat
history; how do I get NEOTH to see it as memory?"

> **Command status (current binary `1.0.0-beta.1`).** This document is the
> import/export *contract*; the binary you run today exposes only:
>
> - `neoth-migrate dry-run --manifest <file>` — ✅ **works**: validates the
>   manifest + reports rows/sample entries, scan-only (never writes the WAL).
> - `neoth-migrate apply --manifest <file>` — ⚠️ **preview-only in this release**:
>   validates the manifest then refuses and points you back at `dry-run`. The
>   real WAL-writing import (the `MIGRATE_RAN` + per-event frames described
>   below) is **post-v1.0** — not yet implemented.
> - `neoth-migrate export <file>` (§5) — ⚠️ **not yet implemented** (the planned
>   reverse path).
>
> So where this spec writes `neoth-migrate import …` it means the consume-side
> contract; the runnable command today is `dry-run`.

---

## 1. Input shape — `<source_id>.import.jsonl`

NEOTH ingests data via a single `.import.jsonl` file per source. The
file MUST be UTF-8 + one JSON object per line + ≤ 64 KB per line.
The wire shape:

```json
{
  "source_kind": "chat_export",
  "source_ref": "telegram-2024-09-12",
  "imported_at_unix": 1700000000,
  "events": [
    {
      "ts_unix": 1700000000,
      "kind": "raw_text",
      "text": "Hello, this is the imported message.",
      "channel_hint": "telegram",
      "operator_role": "user",
      "importance": 0.55
    },
    {
      "ts_unix": 1700000060,
      "kind": "provider_response",
      "text": "And this is the reply.",
      "channel_hint": "telegram",
      "operator_role": "assistant"
    }
  ]
}
```

### Top-level fields (required unless noted)

| Field | Type | Purpose |
| --- | --- | --- |
| `source_kind` | string (enum) | One of `chat_export`, `markdown_vault`, `voice_log`, `pdf_archive`, `email_thread`, `custom` |
| `source_ref` | string | Operator-readable identifier (e.g. `telegram-2024-09-12`, `obsidian-vault`). Stored on each emitted WAL frame so `neoth recall` can filter by source. |
| `imported_at_unix` | i64 | Unix seconds at import time. Migrator stamps this on every emitted frame. |
| `events` | array | One element per memory-worthy event in the source. Empty array → no-op import (still writes a `MIGRATE_RAN` audit frame). |
| `operator_id` | string (optional) | Override the operator id for these events. Default = `~/.neoth/freedom.yaml::operator_id`. |
| `notes` | string (optional) | Free-form operator note kept in the audit frame for "why I imported this". |

### Per-event fields

| Field | Type | Purpose |
| --- | --- | --- |
| `ts_unix` | i64 | Unix seconds when the event happened in the source system. Migrator emits this verbatim as the WAL frame's `ts_unix` field; **NEVER overwritten to now**. |
| `kind` | string (enum) | One of `raw_text`, `provider_response`, `voice_transcript`, `pdf_text`, `markdown_note`, `custom` |
| `text` | string | The event body. Trimmed; empty text is rejected with `EmptyText` error (caller must filter). |
| `channel_hint` | string (optional) | Free-form channel name (e.g. `telegram`, `slack`, `obsidian`). Surfaces in `neoth recall` "via X" labels. |
| `operator_role` | string (optional) | `user` / `assistant` / `system`. Default `user`. Drives the WAL event's role field. |
| `importance` | f32 (optional) | `[0.0, 1.0]` operator-assigned importance hint. Default `0.5`. Hebbian decay tier (`memory::tiers`) uses this for initial placement. |
| `embedding` | array<f32> (optional) | Pre-computed embedding vector. When absent, the migrator embeds via the operator's configured `inference.embedding_provider` (Day-14b path). |
| `tags` | array<string> (optional) | Operator tags. Stored verbatim, queryable via `neoth recall --tag <tag>`. |

---

## 2. Source-kind tables

Different `source_kind` values get different default classification +
WAL routing. The migrator MAY skip events whose `kind` doesn't match
the source's expected kinds.

| `source_kind` | Expected event `kind`s | WAL event types emitted |
| --- | --- | --- |
| `chat_export` | `raw_text`, `provider_response`, `voice_transcript` | `0x20 RAW_TEXT`, `0x21 PROVIDER_RESPONSE`, `0x22 VOICE_TRANSCRIPT` |
| `markdown_vault` | `markdown_note` | `0x23 MARKDOWN_NOTE` |
| `voice_log` | `voice_transcript` | `0x22 VOICE_TRANSCRIPT` |
| `pdf_archive` | `pdf_text` | `0x24 PDF_TEXT` |
| `email_thread` | `raw_text`, `provider_response` | `0x20 RAW_TEXT`, `0x21 PROVIDER_RESPONSE` |
| `custom` | any `kind` | `0x2F MIGRATE_CUSTOM` (operator-defined; migrator stamps `tags` for differentiation) |

---

## 3. Audit frames — every import emits these

Regardless of event count, every successful `neoth-migrate import
<file>` invocation emits two audit frames:

1. **`MIGRATE_RAN` (event_type `0x14`)** — wraps the import surface.
   Payload: `{ source_kind, source_ref, imported_at_unix,
   neoth_version, events_count, events_emitted, notes? }`.
   Operators can recover "what did I import + when" via
   `neoth wal show --kind migrate_ran`.

2. **`PROFILE_BASELINE_SNAPSHOT` (event_type `0x1B`)** — emitted only
   when the import covered profile-relevant content (`source_kind`
   in `{chat_export, markdown_vault, email_thread}`) AND the
   operator's `profile.learn_enabled = true`. Captures the
   pre-import profile snapshot so a post-import diff is comparable
   for "did importing change my profile?".

---

## 4. Pre-flight checks the migrator runs

Before emitting any frame, `neoth-migrate import` validates:

| Check | Error code |
| --- | --- |
| File exists + readable | `FileNotFound` |
| Valid UTF-8 | `InvalidUtf8` |
| Every line parses as JSON | `MalformedLine { line_no, err }` |
| `events[*].text` non-empty after trim | `EmptyText { line_no, event_idx }` |
| `events[*].ts_unix` within `(0, now + 86_400]` | `InvalidTimestamp` |
| `source_kind` is a known enum | `UnknownSourceKind` |
| Per-event `kind` allowed for `source_kind` | `KindNotAllowed { event_idx, expected }` |
| `importance` in `[0.0, 1.0]` | `ImportanceOutOfRange` |
| `embedding.len() == inference.embedding_provider.default_dim()` (when present) | `EmbeddingDimMismatch { expected, got }` |

The migrator is **atomic per file**: if any pre-flight check fails,
NO frames are emitted (no partial state). Operators get a single
error report listing every failure they need to fix.

---

## 5. Reverse path — exporting from NEOTH

> ⚠️ **Not yet implemented.** `export` is the planned reverse path (post-v1.0);
> the binary today exposes only `dry-run` + `apply`. This section is the target
> contract, not a shipped command.

`neoth-migrate export <output.jsonl>` will produce a file in this exact
same format so operators moving to a different daemon (or backing
up before a destructive op) can round-trip. The reverse path:

1. Walks `idx_episode` + `idx_consolidated` + `idx_longterm` tiers
2. Writes one event per row in the order encountered (oldest first)
3. Tags each event with its original `source_ref` if known, else
   the WAL segment offset

Round-trip identity is not byte-perfect (embeddings are re-computed
on the import side; the Hebbian decay state is dropped — fresh
import starts at the default importance), but **semantic identity
holds**: `neoth recall "query"` against the exported-then-reimported
WAL returns the same hits as against the source.

---

## 6. Wire shape stability guarantee

NEOTH commits to the import shape above being **wire-stable** through
v1.x. Field additions land via `serde(default)` so older
`.import.jsonl` files keep parsing. The migrator emits the same
audit frames regardless of future field additions, so historical
imports stay queryable.

Breaking changes (field removal, type changes) require a major
version bump + a `neoth-migrate v1-to-v2 <file>` upgrade path. We
have not committed any such changes yet.

---

## 7. Operator quick-start

```bash
# 1. Build the file. Anything that walks your data source + emits
#    one JSON object per event works (Python, jq, Rust, hand-typed).
python3 -c '
import json, sys
events = []
# ... walk your data source, append dicts to events ...
print(json.dumps({
    "source_kind": "chat_export",
    "source_ref": "my-export-2026-05-23",
    "imported_at_unix": 1735000000,
    "events": events,
}))
' > my-export.import.jsonl

# 2. Dry-run — validates every event, scan-only (no WAL frames). WORKS TODAY.
neoth-migrate dry-run --manifest my-export.import.jsonl

# 3. Apply — PREVIEW-ONLY in this release: validates then refuses and points
#    you back at dry-run. The real WAL-writing import (audit + per-event
#    frames) is post-v1.0.
neoth-migrate apply --manifest my-export.import.jsonl

# 4. Verify with recall (once the real apply ships).
neoth recall "something you imported" --since 30d
```

---

## 8. Where this fits in the broader migration story

`neoth-migrate` ships TWO related but distinct surfaces:

- **`import` (this spec)** — operator-curated `.import.jsonl` files.
  Used for one-off historical bring-ins ("here are 3 years of
  Telegram exports").
- **`legacy-import` / migration helpers** — project-specific migration
  tools can reuse the same WAL-write layer for private historical stores.
  Those helpers are not part of the generic user-facing import contract.

The two binaries share the WAL-write layer (same `MIGRATE_RAN`
0x14 audit frame, same atomicity rules), so operators who later
want to use both paths get one consistent set of WAL audit events.

---

## 9. Changelog

- **2026-05-23** — Initial import shape pinned for v1.x compatibility.
