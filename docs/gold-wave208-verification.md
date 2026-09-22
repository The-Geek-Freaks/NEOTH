# Wave 208 origin-bound memory clustering admission

W208 adds a positive origin and consent boundary for episode vectors and
consolidation. Normal local chat and authenticated channel ingress emit a
metadata-only RawTextOrigin extended event (0x2E) after the actual RAW_TEXT
append. It binds the raw header event ID, payload hash and WAL session. Channel
origin additionally binds the authenticated ChannelRef and scoped sender hash.
Unknown/legacy/unconverted writers are not guessed to be local.

The v42 schema is additive and does not backfill provenance. Its projector
requires RAW before receipt, exact header/payload/session custody and strict
wire fields. A conflicting receipt removes positive origin, retains a tombstone,
and quarantines vectors and affected active synthesis/meta facts. Malformed
historical synthesis evidence is conservatively revoked. Invalid/missing links
return a typed Rejected outcome without stopping replay; real database failures
roll back the whole replay transaction and cursor.

Episode embedding requires an opaque capability constructed only by the actual
LocalQwen/LocalOuro factory. A generic provider name or trait object cannot grant
locality. Candidate selection requires a local receipt or channel origin plus
verified consent. The writer repeats eligibility in an IMMEDIATE transaction
after inference. Revoke deletes bound vectors and revokes derived facts; a late
vector cannot be stored. SQLite recall and persisted HNSW snapshots repeat the
eligibility check; filtered HNSW shortfalls fall back to eligible SQLite hits.
Consolidation loads receipt-scoped candidates and writes derived facts in one
IMMEDIATE transaction. Channel/account/sender scope, not display metadata,
determines the clustering domain. Ordinary historical text recall is preserved.

The local/channel emitters, indexer tail, serve startup, chat post-reply embedding
and CLI backfill are wired to these paths. CLI backfill retains its zero-limit
semantics and propagates candidate-query failures. Existing positive fixtures
now carry explicit origin receipts; separate negative fixtures cover bare raw,
invalid links, partial quarantine failures, cross-account/sender isolation,
revocation, stale HNSW results and late vector writes.

Independent static review passed after repairing malformed-evidence rollback,
incorrect conflict hashes, untyped projection failures, missing receipt ordering,
HNSW filtered-result shortfalls and outdated test fixtures. All executable
validation is pending on GitHub under the local workstation BSOD hold.

This is the complete origin/consumer admission slice, not a completed P2-22
consent ceremony. Production currently exposes no API that creates a verified
grant. Channel episodes therefore remain denied until the following sender-bound
challenge/echo slice is integrated and accepted. Synthetic verified rows exist
only in tests and are not an operator grant. No Road checkbox or release gate is
closed by this report. Tests of the actual grant/revoke commands and durable
audit protocol remain part of that next slice.
