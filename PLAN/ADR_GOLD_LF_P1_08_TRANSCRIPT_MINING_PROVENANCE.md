# ADR — GOLD-LF-P1-08 Transcript Mining Provenance Prerequisite

## Status

Accepted through Stage 3b on 2026-09-13. Stages 1–3a established the V37
schema and contract; Stage 3b adds the V38 local producer, authenticated
WAL delivery/recovery and guarded lifecycle transitions described below.
This record does not close `GOLD-LF-P1-08` or attest the complete mining,
labeling, grading and release workflow. Wave 11 Stage 4 local candidate export
is **COMPONENT ACCEPTED** on 2026-09-13; exact evidence is recorded in
`docs/gold-wave11-verification.md`. P1-08 remains open.

## Authority boundary

The V38 producer contract and its accepted scope are recorded at the end of
this ADR. Exact source and runtime evidence is in
`docs/gold-wave10-verification.md`; P1-08 remains open.

`raw_turns` remains the sole authority for retained operator/agent text. WAL
frames remain the sole authority for immutable WAL event bytes. A transcript
mining provenance record authorizes only a strictly modern, explicitly bound,
cross-verifiable subset of those two stores; it is neither an alternate text
store nor an alternate WAL.

The v36/v37 metadata stores only fixed-width digests, stable opaque IDs, closed
enums, bounded canonical payload bytes, and protocol header fields. It never
duplicates raw text, a raw platform subject ID, labels, filesystem paths,
credentials, secrets, or diagnostic/error text. `operator_raw_text_v1` is the
only source kind, and every prospective binding carries one finite retention
choice. The Rust boundary remains sealed and non-deserializable at its
least-authority construction points.

SQLite and the append-only WAL are different durability domains and cannot be
made atomic by a transaction in either system. The future writer must use an
outbox and reconciliation protocol; recovery must not infer an event from a
SQLite row, or a SQLite row from a WAL frame. A completed v37 plan is a retry
locator, not an assertion that a frame has been appended.

## Modern birth fences and no backfill

Legacy rows and legacy WAL frames are permanently `LegacyUnbound`. They are
never candidates for mining authority and must not be inferred, upgraded, or
backfilled from timestamps, hashes, row order, session names, an old witness,
or any other heuristic.

The v35→v36 migration creates no provenance/witness rows from historical raw
turns. A v36 raw turn has an authority epoch, but v37 adds a separate,
immutable `raw_frame_plan_epoch`: every existing v36 raw row is stamped `0`,
and only a raw turn born after v37 may be inserted with both epochs `1`. A
v36 witness does not change that fact. The v36→v37 migration creates no raw
frame plan, does not promote a witness, and does not fabricate a physical
frame digest, terminal cause, delivery evidence, or revocation outbox.

Historical v36 provenance/outbox/receipt metadata is retained unchanged as
**legacy-untrusted, quarantined audit material**. It is not v37-operable: a
preserved bound outbox lacks the new verified delivery digest, and an anomalous
v36 subtype-41 outbox makes migration fail closed rather than being
reinterpreted. No v37 transition may promote, deliver, or validate those legacy
payload bytes; preserving them is not a hidden privacy validation or upgrade.

## Exact raw-frame plan

Each prospective post-v37 binding will have exactly one immutable raw-frame
plan identified by its `frame_plan_id`, `provenance_id`, `lifecycle_id`, and
`raw_turn_id`. The reserved shape fixes an explicit, deterministic WAL locator
before any physical append:

- raw event type/subtype, WAL format, and event-schema versions;
- planned event ID, HLC physical timestamp, and HLC logical counter;
- the exact 96-byte protocol header plus its SHA-256 digest.

The protocol header contains bounded WAL routing/protocol fields (including
opaque WAL session/node identifiers), never raw payload text or a platform
subject ID. The plan has no raw-frame payload column and its header digest does
not stand in for a physical-frame digest. Stage 3a does not expose an
authenticated header constructor or canonical-payload validator, so ordinary
SQLite cannot insert even a `planned` row: accepting arbitrary candidate bytes
would create a raw-content/secret side channel. The initial planned row is
therefore also deferred to the Stage 3b attestation seam.

Stage 3b must reproduce this locator and header byte-for-byte. It must not scan
for a "close enough" content or timestamp match and must not write a duplicate
frame after an unknown crash boundary. If it cannot read back and authenticate
the exact planned frame, it must remain pending/reconcile rather than guess.
In v37, no ordinary SQLite mutation may assert that this read-back occurred:
the plan's header and digest are only candidate locator data until a future
authenticated boundary proves them.

The raw-frame state machine is closed and monotonic:

| State | Physical frame digest | Raw-frame delivery timestamp | Meaning |
| --- | --- | --- | --- |
| `planned` | `NULL` | `NULL` | Prepare committed; no physical frame is claimed. |
| `verified` | fixed 32-byte SHA-256 | non-`NULL` | Reserved for a later authenticated read-back proof. |
| `cancelled` | `NULL` | `NULL` | A raw-delete terminal transition won before verification. |

A verified plan, once a later stage can create one, is immutable audit evidence
and is never cancelled or rewritten. A planned plan may become cancelled only
in the same raw-delete terminal sequence. Stage 3a deliberately makes
`planned → verified`, outbox `pending → delivered`, and provenance
`pending → active` unreachable, including to direct SQLite writes. It is not
safe to treat an application-private Rust function as this boundary, because a
writer with ordinary SQLite access could invoke equivalent SQL.

Stage 3b must first add a connection-local, nonconstructible attestation seam
(or a later migration that introduces an equally enforceable authority). Only
that seam may parse and compare the exact header fields, verify the header
SHA-256, validate the canonical payload codec, append/re-read/authenticate the
planned WAL frame, record its physical SHA-256, and then atomically advance the
reserved states. A failed or unknown read-back remains pending for exact-locator
reconciliation; it never falls back to content or timestamp heuristics.

## Lifecycle, deletion, and receipts

While a binding is `pending` or `active`, its referenced raw turn's text,
session, role, timestamp, and mining birth epochs cannot change. There is no
cascading foreign key from provenance to `raw_turns`: audit metadata survives
raw-text deletion.

The v37 raw-delete trigger creates an internal delete-cause context before the
row disappears, then consumes it in the corresponding after-delete sequence.
The context cannot alone authorize a terminal state: while the raw row exists,
terminal transitions are rejected; after it disappears, a new context cannot
be inserted. The after-delete path uses the same cause/timestamp to make the
first live transition monotonic, create the matching immutable receipt, cancel
only pending bound work, and remove the context. An aborted delete rolls this
whole sequence back.

For this stage the only executable terminal cause is `raw_turn_deleted`:
`pending → cancelled` and `active → revoked`. The closed cause/receipt enums
reserve `operator_revoked` and `retention_expired` for later authenticated
flows, but direct SQL cannot use them today. Receipts, provenance, plans, and
outbox rows cannot be deleted or rewritten; no terminal lifecycle can be
resurrected. Explicit collision guards also reject SQLite `OR REPLACE` on raw
turns, witnesses, provenance, plans, receipts, and outbox rows, so a
conflict-resolution delete cannot bypass the ordinary immutable-delete guards.

## Logical outbox admission

Outbox identity is logical rather than merely numeric: one provenance/lifecycle
may have at most one `bound` record (WAL extended subtype `0x28`) and one
`revoked` record (`0x29`). The mapping is fixed in schema and the binding
fields are immutable.

`0x28` is structurally admitted only while its matching provenance is `pending`
or `active`, has no terminal cause, has not expired, and has an exact raw-frame
plan in `verified`. It would begin pending with no delivery claim. In v37 this
condition is intentionally unreachable because Stage 3a prohibits physical
verification; no `0x28` is emitted, delivered, or activated by this stage.
Only the future connection-local/nonconstructible attestation seam (or later
migration) may make the prerequisite proof state reachable after exact
header/codec/read-back verification.

`0x29` is structurally admitted only for a matching terminal provenance with a
matching immutable receipt, and only when the exact `0x28` binding is already
delivered and read-back-proven (same bound payload digest and fixed
delivered-frame digest). Its admission intentionally does **not** require the
raw-frame plan to still be `verified`: once an external binding has been
proven, a revocation remains mandatory even if raw-plan bookkeeping is later
degraded. Because v37 cannot create a delivered `0x28`, it consequently cannot
create or deliver a `0x29` unless such a delivered binding was first created by
the future authenticated authority. Stage 3a does not create, append, drain,
or activate either subtype.

## Consequences and deferred work

v37 provides an auditable crash-state model, not a live producer. From a fresh
v37 database, ordinary SQLite cannot create a plan, provenance binding, or
outbox row; it can only apply the terminal raw-delete sequence to rows that a
later authenticated authority has already created. `planned/no physical
digest`, `verified/exact physical digest`, `bound-pending`,
`bound-delivered`, and `revoked-pending` are reserved state shapes for later
reconciliation rather than claims v37 can create. Stage 3b must introduce the
smallest authenticated ingress and connection-local, nonconstructible
WAL-attestation writer seam (or a new migration that can enforce the same
separation) before it can construct a canonical plan, reproduce the exact
locator, append at-least-once, read back/authenticate, CAS the state, and
handle unknown outcomes without duplicate-on-heuristic recovery. It must
preserve expiry and revocation monotonicity and must not grant mining,
labeling, or release-gating authority merely because this schema exists.

## Stage 3b implementation contract — v38, accepted 2026-09-13

The preceding sections retain the accepted v37 boundary. V38 adds one fresh
local CLI producer, not a historical transcript upgrader. New local operator
turns require an explicit finite `memory.transcript_mining_retention` value
(`minutes15`, `hours24`, or `days30`). Missing/null disables new bindings;
Incognito bypasses the producer. Agent turns, imports and background input do
not receive the opaque local chat capability.

A prepare transaction creates the sole operator raw row, both birth epochs,
modern witness and immutable RAW_TEXT descriptor. The private store connection
holds the home-bound HMAC authority and commits with synchronous FULL. Normal
SQLite connections register default-deny attestor functions. Scoped grants
bind one closed operation to opaque lease IDs and immutable descriptor hashes;
they do not accept a caller-provided `verified` flag. Persistent leases make
raw deletion busy while an append outcome is owned or unknown.

The writer admits the exact planned RAW_TEXT through its private once queue,
forces an authentication marker and re-reads the authenticated physical frame.
Its proof allows the store to prepare one canonical metadata-only Bound
(`0x28`) with its exact header and payload. A second independently authenticated
append/readback allows a transaction to mark delivered, activate the binding
and release the lease. The normal post-reply path adds only the agent row.
Physical frame/location hashes remain distinct from the immutable operation
digest, which covers the persisted header/payload digests with its own domain.

Recovery uses the original descriptor, never a replacement header or an
approximate timestamp/content match. It is serialized by writer ownership and
the home authority lock. Exact authenticated evidence is reusable after an
unknown ACK; conflicts, duplicates and incomplete foreign prefixes cannot
prove absence. Archived HMAC keys verify the original prepared subject after
rotation. The explicit `recall-parity-harness reconcile-transcripts --home`
command can settle existing work after opt-in is disabled; its capability
cannot prepare a new raw birth.

Expiry is monotonic across every delivery boundary. An expired RAW receipt
cancels provenance before preparing Bound. A Bound absent from a complete
authenticated prefix is cancelled only with the writer's typed expired-absence
proof; the writer never newly appends that expired Bound. A Bound already in
the WAL remains detectable after expiry and requires its separate revocation.
Late Bound acknowledgements cannot activate an expired binding. Existing
active expiry and raw deletion create immutable local terminal receipts.
The fixed Revoked (`0x29`) outbox authenticates the delivered Bound and matching
terminal receipt independently of whether raw-plan bookkeeping remains usable.

Readers reconstitute the canonical binding from the current eligible operator
row, witness, epochs and lifecycle, then authenticate both exact physical WAL
frames and their retained receipts. An `active`/`verified`/`delivered` SQLite
flag alone grants no mining authority. Receipt frame/location fields and
terminal transitions reject ordinary SQL modification, including NULL writes.

The released V37 table definition remains unchanged. Fresh databases and old
V37 databases use the same additive V38 migration. Historical rows retain NULL
new metadata and `none` leases; no header, physical proof or authority is
fabricated for them. Ordinary legacy transcript insertion/deletion remains
available. These connection guards address normal application write paths;
they do not isolate a hostile process with unrestricted database and key-file
access as the same local operator.

The frozen sixteen-input source set passes 242 selected runtime tests plus
one parent-owned cross-process child, affected Core check, strict Clippy,
workspace formatting and independent review. The source and executable
hashes and exact test names are retained in `docs/verification/gold-wave10-*.json`.
Candidate export, operator labels, shadow runs, live grader execution and
the complete reproducible release report remain separate P1-08 work.

## Wave 11 Stage 4 — explicit local candidate export (component accepted)

Stage 4 adds an existing-home, read-only candidate list/export path to the
offline harness. `list-local-candidates` reveals bounded metadata for active,
unexpired authenticated bindings. `export-local-candidates` accepts only an
explicit UTF-8 JSONL vector, sorted by unique canonical candidate ID, where
each row selects one `provenance_id` and a nonempty UTF-8-aligned
`raw_offset`/optional `source_len` span. It does not discover, infer, backfill,
or label candidates.

The command requires an explicit `--local-evidence-home` and an out-of-band
`--expected-evidence-receipt-pubkey` matching that home's existing WAL signing
key. It opens the home and `views.db` read-only, holds no serializable home or
birth authority, and cannot mint a local ingress, recovery subject, WAL frame,
or mining authorization. Its artifact parent must already exist; the target is
an absolute path with no `.` or `..` navigation component. The output directory
is create-new/idempotent only for byte-identical retries. A single-attempt
export lock reports busy for concurrent mutation and the caller retries later;
it does not block or initialize a parent namespace. It contains the
selected-text `source.evidence`, `candidates.jsonl`, a bounded
`candidate-evidence-local-custody.json`, manifest, and detached receipt.
`source.evidence` is a deliberate copy of the selected spans; Stage 4 makes no
automatic purge promise.

The custody sidecar binds candidate IDs, opaque provenance/lifecycle IDs,
selected ranges and span hashes, timing, and RAW/Bound frame custody. It does
not persist the home path or raw database row ID. Manifest and receipt bind its
SHA-256; legacy source kinds retain compatible absence by omitting the optional
local-custody field rather than serializing `null`.

Every local consumer dynamically revalidates this signed artifact against the
current authenticated home: initial candidate validation, anchor intake, and
all later run reopen paths that consume the resulting evidence. The check
requires the exact selected source, active unexpired lifecycle, matching
RAW/Bound frames and custody, plus an unchanged read-only state version.
Deletion, revocation, expiry, absent/altered custody, changed source span, or
a concurrent state transition rejects the operation before derived state is
written. A signature is durable identity evidence, never durable permission.

This stage remains subordinate to the lifecycle rules above: it creates no
terminal receipt, revocation, deletion, provenance birth, provider result, or
release verdict. `GOLD-LF-P1-08` remains **OPEN** pending real operator labels,
a shadow run, live four-grader evidence, and methodology acceptance.
