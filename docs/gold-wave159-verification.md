# W159 - admitted WAL session identity and isolated replay

Status: reviewed integrated source admitted for GitHub-hosted verification. No local
compiler, parser probe, formatter, tests, fixture, product or GUI execution is
permitted during the workstation BSOD hold. Executable acceptance runs on
GitHub-hosted runners. GOLD-LF-P2-08 remains open.

## Identity and compatibility

A typed, non-serialized WalSessionContext is minted only after local or channel
turn admission. The existing home WAL HMAC key derives a domain-separated opaque
16-byte ID from a bounded canonical identity. The constructor does not create a
key or derive identity from provider/task JSON. Channel canonicalization checks
its complete length before allocation. The raw logical label is not written
into the header.

The existing WAL header slot and binary layout are unchanged. SessionId::ZERO
continues to mean legacy, unattributed or deliberately unscoped. Incognito,
unadmitted input, standalone ingestion and unrelated background work remain
unattributed. SessionPartition has a private representation: an exact named
partition cannot be constructed with ZERO, while the explicit `unattributed`
selector remains available.

## Propagation under review

The retained capability follows CLI/daemon/channel turns into provider attempts,
retries/fallbacks, subagents and QA, transcript birth, media/STT, Code Map evidence,
MCP calls and compaction, outer loops, permission/TrustDecision, goal judgment,
and related direct turn audits. Each contextual leaf accepts the already admitted
capability; a writer alone is not sufficient authority to infer a session.

Independent tracing found omissions at channel media, loop entry, permission/trust,
scope denial, snapshots, goal judgment and terminal TPS emission. Those findings
are repaired. The final finite accepted-turn inventory also covers Council,
hook, quota, streaming, channel refusal and agent-dispatch audit leaves. A source inventory or
one nonzero test frame does not establish universal propagation.

## Projection and operator query

SQLite schema v40 adds session columns and indexes to episode/provider projections.
Legacy records receive exactly sixteen zero bytes. RAW_TEXT and provider indexing
use the decoded authenticated header value. Episode assembly splits on session
identity as well as its temporal rules so adjacent conversations cannot coalesce.

`neoth wal show --session <32-lower-hex-id>` selects an exact opaque partition;
`--session unattributed` selects legacy/unscoped records. Invalid, raw-label and
exact-zero identifiers are rejected. Selection retains normal authenticated
reading and HLC replay ordering. `wal export` still emits a complete time-window
proof: the current verifier schema cannot prove omitted session subsets.

## Required evidence

Independent reports and exact source/test inventories are retained under
`work/gold-20260906/wave159-session-id`. Final source admission must bind the
actual integrated hashes and required native JUnit identities in the canonical
Gold manifest/matrix, then pass hosted formatting, compilation and focused plus
full native tests. Runtime proofs must decode actual header IDs, verify
cross-session replay/query isolation, and retain legacy/Incognito/unadmitted
zero behavior. Generated CLI reference must come from the matching hosted binary.
No roadmap checkbox or release readiness follows from source review alone.

## Admission evidence

34 production sources are retained in INTEGRATION-SOURCES.json. Independent
core/projection/execution and final emitter reviews cover the frozen source.
The final emitter review SHA-256 is
4EB37C070DDD3DC372A0979FE988798D7B6DE425649CAB60C8A376DE12ECE5C8.
Five pure CRLF-to-LF normalizations and two nonsemantic whitespace cleanups
are recorded separately and mapped to the final staged hashes. W162's separate
live-throughput module/export is excluded. No current-source hosted pass is claimed.

Current manifest: 351 source inputs; 316 universal native + 3 Windows-only +
2 Unix-only requirements; 56 universal GUI + 12 Linux/macOS callbacks; 7 optional
adapter cases. W159 contributes 48 session regressions, 44 newly required.

## First hosted follow-up

Source 482ffd1c passed Code Quality35630099785. Preflight35630100747 produced
79 formatting hunks across 20 files, imported with exact before/after receipts.
Reference35630100371 failed at two parameter documentation comments; both are
now ordinary comments. FORMAT-HOSTED.json and COMPILE-COMMENT-REPAIR.json retain
the source/log hashes. New hosted compilation/reference and native/GUI tests
remain pending. This patch does not admit W162 or close GOLD-LF-P2-08.

Repair536fafce passed Preflight35631163948, Code Quality35631164047 and hosted
Core/reference35631164764 (job106437432232). The generated reference is imported
byte-for-byte with SHA-256 9BE613783FC2C1E8DBD2A203BF75A65F9644889E260F29526B859E498119419C.
This establishes the core build and generated CLI surface, not native/GUI
behavior. Full hosted CI remains required on the resulting reference commit.
