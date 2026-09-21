# W175 — durable Hippocampus importance selection

Road scope: GOLD-LF-P2-02; supporting source PLAN/CHERRY_PICK_RANKING.md,
item 1. Final source has independent STATIC-APPROVE Review04. Native execution
and Road completion remain pending.

The existing WAL indexer already persists event importance. The existing
two-hour decay/consolidation task now optionally maintains secondary
Hippocampus membership for live retained events with importance >= 0.75.
The new table contains only event IDs and selection timestamps; event text
and importance remain in the existing hot, warm or cold source tier.

`memory.hippocampus.enabled` defaults to false. The daemon checks the accepted
ReloadController snapshot at each tick and allows the new membership mutation
only under enabled Standard, Elevated or Full policy. Custom and disabled
selection leave that mutation inactive. The underlying existing decay task,
its skipped-missed-tick behavior, and its normal lifecycle are retained.

The additive v40-to-v41 views migration introduces idx_hippocampus without
rewriting existing importance. Membership insertion/removal occurs inside the
same consolidation transaction as decay, tier movement and retention. It is
idempotent and rolls back with a failed pass. Consolidation audit metadata
includes selected/removed counts without event text and retains no-op behavior.

`neoth memory --hippocampus [QUERY] --limit N` inspects current membership using
a read-only SQLite connection. It joins current tier data, filters importance
against the same threshold, limits results to 100 rows and uses stable ordering.
Stale or deleted membership sources are not presented. This command makes no
provider request, configuration write or WAL append and does not change recall
ranking.

Focused regression sources cover threshold boundaries, idempotence, decay and
retention, additive migration and failure rollback, current-row readback,
default-off and Custom policy, and rejected reloads. The integration fixture
exercises the actual short-interval scheduler with its accepted controller and
production inspection output. A test-only one-shot signals after the complete
pass and ends the test task; each phase awaits both its signal and JoinHandle.

All compiler, formatter, parser, test, fixture and product execution is reserved
for GitHub-hosted CI. Current native behavior, generated CLI reference,
formatting, strict Clippy and focused integration remain required. The source
manifest now admits the final reviewed freeze; W178 dirty sources remain excluded.
Review04 SHA-256: 5F7A6A80F2C8B9B5A30732E5A6DBA8E4DDF5D39BCB9F2F62FD99E71E54159F9D.
It binds the final regenerated Freeze03 (440F27E7A2A5C233CDF8759CC30918C036A876C92231E7570391325037C29282).
Stable Freeze04 has exactly the same nine source hashes and updated provenance
names: 72B7005430891822C488594ECC0808D44942843D71F8C2C1E89C2E124F3F0994.
Receipt04: 407A21D0DEC6E95BFF4D70E66154AA989FC3242B3610AEB209C5DC6CC831D0C7.
Older rejected reviews are retained. The fixed threshold is applied to current
post-decay importance; the exact-boundary integration event is pinned so normal
decay cannot move it below 0.75 before selection.

W175 Code Quality 35666212306 passed on da78c6a8. Preflight 35666214987's
22 exact formatting hunks across six files are imported. CLI build 35666228194
found one E0277 in the new renderer: rows already has slice-reference type, so
the loop now iterates rows directly. Fresh Hosted compilation and formatting
remain required, as do the eleven behavior tests.
Format receipt: FD47FB80BCB38EC766D470FE73B409C8E90C55BE36635E3DE56273A0C0F47DF7.
Compiler log: 55355A24DFBAD75F3B7B28077F2E357F75488754D02763AF198814E2586DBB1D.

Hosted follow-up on 405c9de6 passed CLI/reference 35666823374, Preflight
35666822254 and Code Quality 35666822323. The generated reference is imported
byte-for-byte (232129 bytes; SHA-256 14F8DABA4804E5CCA138FF4CDFF65446363ED43D5589C90104B117F65675DA43).
The native migration, scheduler and CLI behavioral tests remain required.
