# ADR — GOLD-LF-P1-08 Transcript Mining Provenance Prerequisite

## Status

Accepted for stages 1–2 only. This record deliberately does not close
`GOLD-LF-P1-08`; mining, labeling, graders, report generation, and release
gating remain separate later stages.

## Decision

`raw_turns` remains the sole authority for retained operator/agent text. WAL
frames remain the sole authority for immutable WAL event bytes. A transcript
mining provenance record authorizes only a modern, explicitly bound subset of
those two stores; it is neither a replacement text store nor an alternate WAL.

The v36 schema stores only fixed-width digests and stable opaque identifiers in
provenance, outbox, and revocation receipts. It never duplicates raw text,
platform subject identifiers, labels, filesystem paths, credentials, or error
text. The binding requires a finite expiry and one closed source kind
(`operator_raw_text_v1`). The Rust boundary uses sealed construction and
closed payload codecs; it exposes no producer, miner, daemon, snapshot, chat,
forget, or activation authority in this prerequisite.

SQLite and the append-only WAL are separate durability domains and cannot be
made atomic by a transaction in either system. A later writer must use the
durable SQLite outbox, append the canonical extended WAL payload, and mark the
outbox terminal only after the append result is known. Recovery must reconcile
the two durable stores; it must never infer an event from the other store.

Legacy rows and legacy WAL frames are permanently `LegacyUnbound`. They are
not candidates for mining authority and must never be inferred, upgraded, or
backfilled from timestamps, hashes, row order, session names, or any other
heuristic. The v35→v36 migration creates empty new tables only.

An empty modern-raw witness ledger is the explicit boundary between historical
raw rows and later authenticated ingress. A provenance binding requires this
witness as well as the raw row; migration never creates witnesses. Thus an
extant raw row alone can never become modern mining authority, even if a later
writer sees a matching role or digest.

## Integrity and deletion contract

While a binding is `pending` or `active`, its referenced raw turn's text,
session, and role cannot be changed. A direct deletion of that raw turn is
fail-closed: SQLite atomically changes `active` bindings to `revoked` and
`pending` bindings to `cancelled`, creates a metadata-only revocation receipt,
and cancels pending outbox work. Provenance has no cascading foreign key to
`raw_turns`, so its audit metadata survives the text deletion.

## Consequences

The added tables are an authorization/reconciliation foundation, not proof that
any transcript is safe to mine. Later stages must authenticate the subject,
construct only modern bindings, drain/reconcile the outbox, and refuse every
legacy or incomplete record. They must also retain the same no-raw-content WAL
and diagnostic boundary established here.
