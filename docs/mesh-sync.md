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

## Protocol compatibility and causal frontier

The durable mesh frame protocol is version 6. Iroh uses ALPN
`neoth/cluster/gossip/3`. Older peers are rejected cleanly; there is no
best-effort downgrade that could reinterpret the causal clock or bypass the
durable ACK contract. During the v5-to-v6 database migration, pending v5
frames are discarded without moving their WAL cursors and are restaged from
the same event as v6. Existing receipts remain valid for duplicate ACKs but,
because they predate the full-frame digest binding, cannot advance the new
causal frontier.

`event_seq` and the vector clock deliberately serve different contracts.
`event_seq` is contiguous per destination stream and binds ACK/replay order.
The vector clock is a node-global durable causal frontier: a newly staged send
ticks the local node once in the same SQLite `IMMEDIATE` transaction that
stores its exact pending frame, and a retry reuses that frame byte-for-byte
without ticking again. A committed inbound frame, or a duplicate whose full
canonical frame digest matches its durable receipt, merges its clock inside
the same transaction as receipt/content/high-water state.

The frontier is bounded to 256 directly authenticated node identities. A new
257th identity fails explicitly instead of evicting causal history. A peer may
advance a third-party slot only after that identity has itself been observed
as an authenticated origin; unknown asserted identities are ignored. These
counters are causal provenance, not authentication, authorization or a trust
score. NEOTH does not use them to silently choose a winner: same-origin
sequence rules and the typed, operator-resolved cross-origin conflict ledger
remain authoritative.

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
Conflicts are unresolved until an operator chooses a materialized origin. The
decision is stored with the original rows rather than deleting forensic
evidence. An exact digest pair stays acknowledged; a later new pair is a fresh
conflict and becomes visible again.

Canonical snapshots deliberately have no fields for credentials, permissions,
consent, operator profiles or provider secrets. Raw/private event classes cross
the mesh only when `cluster.gossip.replicate_raw_ingress` is enabled. Active
forget tombstones discard matching raw content while committing only a
digest receipt, so the sender can progress without resurrecting forgotten
data.

Both gossip controls are live: Peeroxide inbound/outbound and iroh
inbound/outbound resolve `replicate_raw_ingress` and `replay_budget_days` from
the current reload snapshot for each operation. No carrier freezes startup
defaults. The replay window accepts 1 to 90 days.

## Operations

Configure the mesh through the GUI Cluster panel or the complete-snapshot CLI
transaction described in [Configuration](configuration.md#cluster-configuration-and-activation):

```bash
neoth cluster configure \
  --enabled true --name home \
  --transport peeroxide --peers-json '[]' \
  --mdns-enabled true --announce-on-untrusted-wifi false \
  --trusted-ssids-json '["Home Wi-Fi"]' \
  --replicate-raw-ingress false --replay-budget-days 30 \
  --listen-port 49737 \
  --passphrase-stdin
```

Feed the passphrase to stdin from a private prompt or secret manager; do not put
it in argv. The transaction refuses an incomplete enabled identity and returns
an exact secret-free receipt. Enabled lifecycle changes are durable but not
hot-applied: `restart_required: true` means restart the supervised daemon before
expecting transport or mDNS behavior to change. Gossip policy is hot-reloaded
by both carriers. Disabled plus stopped
is already inert and returns `false`. `reload_requested` alone is not evidence
of live activation, and a live acknowledgement is bound to both the exact
public snapshot and the owner-private identity binding.

Native desktop release binaries support both Peeroxide and Iroh. The headless
musl server supports Peeroxide only, and rejects an Iroh snapshot before
commit. `cluster.peers` is the Iroh bootstrap Node-ID list; Peeroxide normally
discovers and confirms peers through the authenticated discovery flow.

`neoth cluster sync-state` prints every peer's acknowledged cursor, exact
pending sequence and attempt count, plus the next inbound sequence. Use
`--peer <PUBLIC_KEY>` to filter and global `--output json` or `--output jsonl`
for automation. `neoth cluster events` remains the foreign-content ledger
view.

`neoth cluster frontier` prints the durable node-global causal frontier in
stable node-key order. It supports the same `--peer` filter and global JSON or
JSONL output. The command is intentionally read-only and labels the counters
as ordering evidence; it does not expose an unsafe "trust" or automatic merge
button.

`neoth cluster conflicts` lists unresolved content divergence. Use
`--content-id`, `--limit`, and global JSON output for automation; add `--all`
to include resolved history. Resolve one stable ID explicitly:

```bash
neoth cluster conflicts resolve <content-id> --prefer <origin-peer-key>
```

The command refuses an origin that has no matching materialized content and
returns a typed receipt. `neoth cluster status`, the Mesh GUI and `neoth
doctor` all surface the unresolved count; the GUI exposes the same Prefer A /
Prefer B action instead of applying a silent winner.
