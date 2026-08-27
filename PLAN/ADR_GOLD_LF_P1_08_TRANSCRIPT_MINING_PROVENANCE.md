# ADR — GOLD-LF-P1-08 Transcript Mining Provenance Prerequisite

## Status

Accepted for stages 1–3a only. Stage 3a is schema and contract work through
schema v37; it deliberately adds no RPC, publisher, WAL append/drain,
activation, forget, snapshot, miner, benchmark, dispatcher, labeler, grader,
report, or release gate. This record does not close `GOLD-LF-P1-08`.

## Authority boundary

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
