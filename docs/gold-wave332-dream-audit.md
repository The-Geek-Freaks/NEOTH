# Gold Wave 332 - Dream phase WAL audit authority

W332 adds the WAL half of W331 Dream phase auditing. It is deliberately
separate from the Dream state machine: `views.db` owns preparation, effects and
its `audit_pending` outbox; WAL owns only authenticated, append-once delivery
of a completed outbox descriptor.

The caller constructs `DreamAuditDescriptor` from an immutable completed
`dream_phase_receipt` row and calls:

```rust
writer.append_dream_audit_once(home, descriptor).await
```

The fixed binary payload is schema version 1, phase, completed state,
`transition_id`, `run_id_hash`, and `result_sha256`. It contains no event text,
sender/account identifier, path, prompt, or provider material. The new
`ExtendedSubtype::DreamPhaseAudit` is `0x32`; this is an extended subtype only,
not the occupied top-level event code `0x32` (`CHANNEL_INGRESS`).

Generic writer APIs reject this subtype. The specialised writer verifies the
canonical requested home against its HMAC authority, takes a bounded
process-plus-file authority, closes the active authenticated tail, scans the
authenticated primary-WAL prefix, and then either returns an exact existing
receipt or appends and rereads exactly one frame. The same transition id with a
different canonical payload is a conflict; duplicate exact frames are an
error. A lost ACK or incomplete scan is indeterminate. The phase engine must
leave its SQLite outbox pending in that case and retry the identical descriptor;
it must never mint another transition id or mark delivery based on a generic
append ACK.

The receipt outcome distinguishes `ExistingExact` from `AppendedExact` and
provides only frame, payload and opaque location SHA-256 values. W332 does not
close W331 acceptance: hosted checks still need to exercise exact duplicate,
conflict, restart, home mismatch, and ACK-loss recovery through the Dream
outbox drain.
