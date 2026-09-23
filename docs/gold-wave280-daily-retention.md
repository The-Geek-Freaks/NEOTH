# Gold Wave 280 — Daily retention authority v2

`daily_retention` remains the v1, read-only horizon policy. Its default of 90
calendar days does not grant filesystem effects.

Recurring execution is a separate, explicit configuration snapshot:

```yaml
daily_retention:
  version: 1
  retention_days: 90
daily_retention_execution:
  version: 2
  enabled: true
  quarantine_grace_days: 7
```

An omitted execution block is strict default-off. The accepted execution schema
is version 2 and permits a recovery grace between one and 30 days. The topics
status output reports the horizon separately from this execution setting.

The private v2 protocol is Daily-specific. A completed Daily note can receive a
`DailyNoteReceiptV1` only from successful settlement; matching legacy bytes,
temporary files, missing receipts, or changed notes never become managed solely
through retention. The executor revalidates the receipt archive digest,
vault/Daily identity bindings, leaf name, marker generation, and note digest
immediately before each relevant rename. Receipt and journal records model the
required order: `prepared`, `archive_quarantined`, `note_quarantined`, and
`committed`. A nonterminal journal blocks a new candidate under the Daily
admission lock until exact recovery has reconciled it. Purge has a separate
durable intent and may record completion only after every exact receipt-owned
quarantine object is absent; `unlink_attempted` remains nonterminal after a
crash and cannot be reported as a completed purge.

The retained hygiene period input remains authoritative for yearly synthesis.
A retention effect must bind an exact matching Daily period input and never
remove or compact it. Archive and vault Daily leaves use distinct
same-filesystem quarantine capabilities (`.retention-v2/<run>` below the
archive parent and `.neoth-retention-v2/<run>` below the vault Daily parent);
a run never relies on a cross-device rename or claims cross-filesystem
all-or-none atomicity.

Yearly synthesis unions the validated Daily subset of durable hygiene inputs
with still-active archive leaves. Valid non-Daily hygiene records are outside
that reader. A hygiene-backed source uses the exact canonical Daily JSONL
digest (the serialized record plus its newline), so its `source:<tag>:<hash>`
provenance remains stable before and after archive quarantine or purge.
This compatibility rule applies to canonical writer-generated Daily JSONL only;
it makes no byte-equivalence claim for arbitrary hand-authored archive files.

Every quarantine rename starts from a retained file-object binding. Windows
commits through that retained mutation handle. Unix has no portable atomic
compare-object-and-rename operation: it installs into a no-replace quarantine
name, verifies the moved inode is the retained source, and attempts a
no-replace restore on mismatch. A restore conflict remains explicit recovery
evidence; it is never silently accepted as a same-byte replacement.

The source-level behavioral fixture module is
`reflection/retention_v2_tests.rs`, loaded only under `cfg(test)` by
`reflection/periodic.rs`. It covers default-off custody, enabled archive/note
quarantine, note object-identity replacement refusal, legacy-note custody,
period-input survival, every journal transition recovery boundary, interrupted
receipt/purge ordering, and bounded batch continuation. It is intentionally
not executed on the local BSOD hold; executable validation belongs to CI.
