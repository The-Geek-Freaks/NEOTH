# NEOTH-Vault

This is your NEOTH archive brain. Every noteworthy NEOTH event
(chats, provider responses, consent decisions, memory promotions)
materialises into `Daily/YYYY-MM-DD.md` so you can search, read,
and edit your AI activity the same way you read a journal.

## What's in here

- `Daily/` — one note per day, auto-written by NEOTH. Frontmatter
  carries event count + providers + top skills; the body is a
  bulleted list of the day's events.
- `Templates/` — Templater + Periodic Notes templates so new daily
  notes match the NEOTH shape.
- `.obsidian/` — curated app + appearance config so NEOTH-Vault
  feels like an archive (not a TODO app).

## Edit flow

Edit any note in Obsidian like normal. NEOTH's indexer (the O-5
"Archive Bridge" plugin) streams your edits back into the WAL so
your operator additions become first-class memory NEOTH can recall
from. Don't delete a daily note unless you want NEOTH to also
forget that day.

## Bootstrap plugins

NEOTH recommends 5 plugins:

- **Dataview** — query the vault as a database.
- **Smart Connections** — local-embedding semantic search.
- **Templater** — drives the daily-note template.
- **Periodic Notes** — daily / weekly / monthly convention.
- **NEOTH Archive Bridge** — custom plugin streaming edits back to NEOTH.

Enable each one in Settings → Community plugins after first launch.

## When NEOTH writes here

NEOTH writes when the operator's `freedom.yaml::archive.obsidian.enabled`
is `true` (default for operators who picked Obsidian in the wizard).
Disable by flipping that flag and `neoth reload` — NEOTH stops writing
but keeps respecting your edits via the Archive Bridge plugin.
