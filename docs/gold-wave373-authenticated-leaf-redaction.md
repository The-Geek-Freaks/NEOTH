# W373 authenticated sealed-leaf redaction

W373 permits physical redaction only for a sealed compressed segment that is
the final member of a complete, authenticated WAL chain.  It is intentionally
not a general permission to rewrite historical WAL files; this is the one
scoped transaction that may rewrite retained compaction-marker evidence.

The established pre-W373 path for a `COMPRESSED`-only legacy segment remains
available and emits its normal generic redaction marker.  A segment explicitly
marked both `SEALED` and `COMPRESSED` enters the W373 authenticated path.  If
that path cannot prove a complete authenticated leaf, it fails closed; the CLI
does not reinterpret a missing key, malformed authentication state, or a
tamper failure as legacy and does not fall back to a generic rewrite.

The redactor first takes the target's stable rewrite lock, then performs the
normal bounded authenticated home scan.  The scan validates each compaction
window and every cross-segment rollover binding.  Writer rotation needs the
same predecessor lock before publishing a successor, so the target cannot gain
a successor between this proof and replacement.  An incomplete chain, a target
with a successor, unavailable HMAC key material, malformed marker, encrypted
sealed body without its explicit key path, raw body, or interior segment fails
closed.

Ordinary matched payloads are zeroed while retaining frame lengths, logical
offsets, event identity, and frame CRCs.  Matched compaction markers, rollover
links, redaction markers, and installed-Skill authority frames remain refused.
For the accepted leaf case, every existing marker is authenticated before any
mutation.  Its window start/end, adjacency and frame count must agree with the
complete decoded frame stream.  Rebinding preserves the existing marker JSON fields, including writer ts_ns,
updates the marker frame's `payload_hash`, and recalculates its CRC; it never
searches for a coincidental old HMAC string in arbitrary JSON.  The fixed
payload layout means no later logical offset moves.  `neoth verify` therefore
reports a normal HMAC pass rather than a redaction-exemption reclassification.

The scan and private staging complete before the dedicated receipt writer is
created: creating that writer first would turn a valid leaf into an interior
segment.  Before publication, the CLI retains one signed, content-free journal
record under the WAL root.  It binds the canonical home digest, direct-child
target basename and immutable header identity, old/new digests, lengths and a
digest of affected logical offsets.  The journal lock remains held through
prepare, atomic publish, the writer-owned append-once receipt readback,
Delivered transition, and safe finalization.

On restart the journal reads the stored direct-child basename through a bounded
no-follow capability and derives its current header identity again.  An exact
old image is safely abandoned; an exact new image retries only the closed
append-once receipt delivery; a Delivered record must still prove the same
receipt frame and exact new image before cleanup.  Any third image, changed
home or target identity, malformed journal, conflict, or indeterminate receipt
refuses recovery.  No erased input is reconstructed and an authenticated leaf
rewrite never emits a generic `0xF3 REDACTION_MARKER`; its closed rewrite
receipt is the audit evidence.
