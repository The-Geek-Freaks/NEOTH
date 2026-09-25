# Weekly reflection archive

The weekly reflection producer stores the same canonical result in its private
archive and proactive queue. It uses the existing deterministic topic pass over
the last seven days of conversation data. It makes no provider request.

For an explicit NEOTH home, the producer retains:

- `reflections/weekly-intents/YYYY-Www.json`: the immutable first topic/body
  snapshot for that ISO week, with a content-bound producer key.
- `reflections/YYYY-Www.jsonl`: historical weekly records followed by at most
  one record for the canonical producer intent.
- `proactive_queue.json`: the pending item and its weekly admission receipt in
  the same atomic queue publication. The receipt survives drain and operator
  drop, so a later tick does not recreate that item.
- `reflections/subconscious_state.json`: the existing cadence timestamp,
  written after archive and queue admission settle.

Queue admission does not prove channel delivery. Existing routing, approvals,
delivery and operator-drop behavior continue to determine the item’s outcome.

The producer first checks for older unfinished intents, including across an ISO
week or year boundary. It settles the oldest one per tick before applying the
normal cadence gate. That tick does not also produce a new current-week item.
Recovery uses the frozen intent even when the database is missing or its topics
have changed. Fresh topics can still contribute independent staged observations;
an observation failure does not invalidate completed archive/queue admission.

Archive publication uses a bounded read and atomic replacement while retaining
the previous valid JSONL bytes. A matching canonical record is a replay; duplicate
or conflicting producer keys, wrong-week records, malformed/truncated JSONL and
linked inputs cause an error without rewriting the archive. A published file
whose durability is uncertain stops before queue admission. A subsequent tick
must reread the stored intent and reconcile the archive before proceeding.

Limits are 128 KiB per intent, 4,096 intent files, 16 MiB for a complete intent
inventory, and 8 MiB / 1,024 records / 256 KiB per line for each weekly archive.
Queue admission receipts are limited to 4,096 entries. Reaching a limit does not
evict an old receipt or silently discard history. Future valid intents are
validated but never selected early.

Historical records without `producer_key` remain readable and retain their
order. They are not evidence that the canonical producer intent has already
run. A pre-upgrade cadence timestamp can still suppress production for a week;
this change does not backfill an already suppressed week. An incompatible
pre-upgrade pending item is preserved and reported as a conflict.

Weekly reflection production is separate from `PeriodKind::Daily` and
`PeriodKind::Yearly`. The separate [weekly n8n/Obsidian consumer](n8n-weekly-obsidian-sync.md)
exports these archives with its own scoped authorization and checked reader.

Validation status: source implementation and focused regression cases passed
independent static review. Executable acceptance runs on GitHub because local executable
validation is suspended on this workstation. The earlier Dream API’s successful
Linux/Windows gates do not establish this new weekly batch’s behavior.
