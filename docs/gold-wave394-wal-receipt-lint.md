# W394 WAL receipt lint repair

Hosted Core8ac Clippy reported two production warnings promoted to errors:

- `wal::mod` re-exported `RedactionRewriteFrameReceipt` and
  `RedactionRewriteOnceError` without production consumers.
- `RedactionRewriteFrameReceipt::payload_sha256` and
  `RedactionRewriteFrameReceipt::location_sha256` had no callers.

The repair removes the unused frame-receipt export and the two unused accessors.
The receipt's payload and location digest fields remain stored and computed by
`receipt_for`; this change does not alter receipt encoding, lookup, descriptor
decoding, or authenticated proof validation.

`RedactionRewriteOnceError` remains available only under `#[cfg(test)]` because
existing WAL writer tests import it through `crate::wal`; production code uses
the defining `redaction_rewrite_receipts` path directly. No lint suppression was
added.
