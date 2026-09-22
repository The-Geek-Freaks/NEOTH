# Yearly reflection from period archives

`neoth reflect digest yearly` creates a local yearly reflection from canonical
Daily reflection archives. It uses the configured topic synonyms from
`reflect_topics.yaml` and the deterministic hygiene planner. A database-only
topic cannot enter this summary; the yearly path does not read `views.db`.
An empty archive produces no summary. Malformed, linked, oversized, or
conflicting source records produce an error rather than an incomplete summary.

The yearly record is an immutable snapshot for the current UTC calendar year,
using that year's eligible Daily records within the planner's 365-day horizon.
Its provenance tags include each contributing archive's SHA-256 and the
effective synonym map's SHA-256. Its generation timestamp comes from the newest
contributing Daily record, so repeating the same request later is idempotent.
Concurrent CLI and daemon publication converges on one record.

With the existing yearly cadence enabled, the daemon creates the snapshot once
after eligible Daily input is available. A valid saved record and completion
marker make later automatic ticks a no-op, including after another Daily record
arrives. A marker alone cannot hide a missing or damaged yearly record.

A manual digest always recomputes its candidate. If new input or changed
synonyms would produce a different same-year snapshot, it reports a conflict
and preserves the original. This is a current-year snapshot, not an automatically
updated year-end report. Existing Obsidian synchronization remains available.

This change does not enable archive deletion. The existing Daily retention
inventory still defers physical cleanup until its separate retention authority
is implemented. Hosted behavior verification for this implementation is pending.
