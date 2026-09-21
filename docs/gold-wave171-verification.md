# W171 — immediate configured arXiv ingest

The remaining EL-02 operator follow-up adds `neoth arxiv ingest --now` to the
existing topic-feed implementation. It requires the current `arxiv.enabled`
opt-in and a nonempty configured topic list before any outbound request or
context-store write. It runs the existing authorized pass exactly once without
starting or enabling the periodic worker. Optional summaries retain the normal
provider authorization/audit and raw-abstract fallback.

The shared report now includes `topics_failed` alongside `topics_queried`,
`papers_indexed` and `papers_skipped`. The periodic worker keeps its established
continue-and-retry behavior. The immediate command finalizes its provider audit
and returns an error if a topic fetch or paper index write failed. Previously
indexed papers remain; this is not a transaction or rollback claim. If both
the pass and audit finalization fail, both causes are preserved.

Successful table, JSON and single-line JSONL output contain counters only.
Configuration and usage are documented in [configuration.md](configuration.md).
The generated full CLI reference was exported by successful GitHub run
35655672068 from ceea62cbb2126f6fa1e4cce9f772e61f65851189 and imported
byte-for-byte at SHA-256
C948D52B50F47917AD9E8510178974FFA9C4AD3D603B18B0CCE33E308FAE0493.
The source/hash receipt is in
`work/gold-20260906/wave171-next-batch/REFERENCE-IMPORT.json`.

Focused regressions cover the explicit flag, CLI parsing, opt-in/topics,
configuration parameter forwarding, counter serialization, the existing real
503 mock, partial index failure and all pass/audit result combinations. Source
review and GitHub build/test/reference results remain separate evidence gates.
No local compiler, formatter, parser, fixture, test or product execution is
permitted on this workstation. No Road checkbox closes on source evidence.
