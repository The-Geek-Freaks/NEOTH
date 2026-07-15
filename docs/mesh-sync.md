# Durable mesh synchronization

NEOTH's peeroxide and optional iroh carriers use one synchronization state
machine. The carrier authenticates the remote key; `views.db` owns ordering,
deduplication, content persistence, conflict records, outbound cursors and
ACKs.

## Commit and replay contract

For every destination peer, NEOTH stores the exact serialized pending frame
and the cursor that follows it. Queueing or writing a frame never advances the
cursor. The receiver validates the authenticated origin, protocol version,
canonical WAL CRC and metadata, replay window, event ACL, contiguous sequence,
content kind and SHA-256 digest. It then commits the receipt, foreign ledger,
canonical materialization, conflict records and inbound high-water mark in one
SQLite transaction.

Only after that transaction commits does the receiver return a `GossipAck`
bound to the exact origin, origin sequence and content digest. The sender
advances only when that ACK arrives from the destination peer and exactly
matches its persisted pending frame. A disconnect, full queue, send error,
missing ACK or database error leaves the pending frame and cursor unchanged.
After restart the same wire frame is replayed byte-for-byte. Duplicate frames
and duplicate ACKs are idempotent; gaps are rejected without an ACK.
Unreadable directories, malformed segment headers, failed decompression,
mid-segment corruption and torn-tail reconstruction errors also leave the
stored cursor untouched. Operators see the error instead of a skipped range.

State is per peer. A slow or disconnected peer cannot advance another peer's
cursor. Corrupt persisted state is an error and is never replaced with an
empty cursor.

## Protocol compatibility

The peeroxide handshake protocol is version 5. iroh uses ALPN
`neoth/cluster/gossip/2`. Older peers are rejected cleanly; there is no
best-effort downgrade that could bypass the durable ACK contract.

## Content and privacy

Memory-tier and ground-truth lifecycle events carry canonical snapshots with
stable content-derived identifiers. Memory snapshots preserve text, text hash,
tier, source timestamp, importance, last-access timestamp and access count;
ground-truth snapshots preserve statement, state, confidence, maturity and
timestamps, source, typed source weights, confirmation count and stable memory
content IDs for evidence. Receiver-local SQLite row IDs are never sent or
guessed. Sources restored from a peer are namespaced to the authenticated
origin, so remote provenance cannot impersonate local operator provenance. A
durable origin/content mapping allocates and reuses receiver-local IDs, and tier
changes move that mapped memory transactionally between hot, warm and cold
storage. Evidence that has not arrived yet remains explicitly unresolved; when
the matching memory snapshot is later committed, NEOTH resolves the local row
mapping in the original deterministic evidence order. The foreign ledger
retains the complete canonical envelope and the original CRC-protected WAL
frame, making content inspectable and restorable.
Same-origin updates are ordered by origin sequence. Different origins with the
same stable content ID remain separate and create a typed conflict record.

Canonical snapshots deliberately have no fields for credentials, permissions,
consent, operator profiles or provider secrets. Raw/private event classes cross
the mesh only when `cluster.gossip.replicate_raw_ingress` is enabled. Active
forget tombstones discard matching raw content while committing only a
digest receipt, so the sender can progress without resurrecting forgotten
data.

## Operations

`neoth cluster sync-state` prints every peer's acknowledged cursor, exact
pending sequence and attempt count, plus the next inbound sequence. Use
`--peer <PUBLIC_KEY>` to filter and global `--output json` or `--output jsonl`
for automation. `neoth cluster events` remains the foreign-content ledger
view.
