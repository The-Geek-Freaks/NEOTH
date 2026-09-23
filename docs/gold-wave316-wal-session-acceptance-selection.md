# W316 - complete WAL session acceptance selection

W310 adds three live-egress frame regressions. They are only the new part of
GOLD-LF-P2-08: universal emitter propagation, persisted legacy migration,
wire compatibility and query isolation also require the original W159 family.

All 48 original W159 identities remain present in the canonical native test
matrix. Combined with the three W310 identities they form 51 distinct tests.
Seven are already selected by the grouped workflow, so W316 adds exactly the
remaining 44 existing native identities. No new fixture or implementation is
introduced; the resulting grouped selection contains 643 unique identities.

The complete family explicitly includes
`memory::migrations::tests::v39_to_v40_preserves_rows_as_unattributed_and_creates_session_indexes`,
`wal::header::tests::zero_session_header_stays_legacy_wire_compatible`, the exact
and unattributed segment reader, the indexed episode query, and each applicable
admitted-emitter regression. The canonical `wave316WalSessionParentAcceptance`
entry records both the additional dispatch identities and all 51 parent tests.

This is selection and source reconciliation, not execution evidence. P2-08
remains open until the relevant source-bound hosted results pass and its full
requirements are reviewed. No local executable validation ran under the BSOD
hold.
