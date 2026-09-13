# Local transcript provenance

Stage 3b accepted in Wave 10 on 2026-09-13. P1-08 remains open until the
complete mining, labeling and grading workflow has passed acceptance.

## Opt in for new local operator turns

Set one finite eligibility window in the selected instance's `freedom.yaml`:

```yaml
memory:
  transcript_mining_retention: hours24
```

The allowed values are `minutes15`, `hours24`, and `days30`. Omitting the field
or setting it to `null` disables new bindings. Incognito always skips this
producer, including when a window is configured. The window controls mining
eligibility; it does not change the existing raw transcript/WAL retention.

For an opted-in local chat, NEOTH stores the operator row before dispatch and
prepares the exact RAW_TEXT header. It authenticates that physical frame,
persists a fixed metadata-only Bound outbox descriptor, then authenticates the
independent Bound frame before completing the binding. The post-reply path
adds only the agent row, avoiding a duplicate operator row.

Existing transcripts, imports, agent responses and background notices remain
unbound. Matching text, timestamps, sessions or hashes cannot backfill them.
The producer does not send transcript data to a grading provider.

## Recover an interrupted operation

```powershell
neoth recall-parity-harness reconcile-transcripts --home C:\path\to\neoth-home
```

Recovery uses the persisted frame descriptors and authenticates exact WAL
evidence. It does not generate replacement identifiers or repeat an operation
based on similar content. Its report contains counts, not transcript text.
This explicit command also works after new mining opt-in has been disabled;
its capability cannot create new bindings.

An unresolved delivery keeps its persistent lease. A raw-text deletion that
encounters such a lease fails busy instead of racing a queued writer. Recovery
must settle that exact operation before deletion can proceed. An expired
Bound that has not been appended is cancelled using the writer's proof of
complete authenticated absence. An already-written Bound remains detectable
after expiry, and its revocation is a separate authenticated outbox operation.

## Evidence boundaries

SQLite stores retry state and metadata. It cannot authorize mining merely by
claiming `active`, `verified` or `delivered`: the reader compares the canonical
binding with its exact raw row and authenticates the referenced WAL frames.
Physical-frame and location digests are separate from immutable operation
descriptor digests. Recovery retains the original subject identity across
WAL key rotation and validates it against the home's retained key set.

The connection-local SQL guards protect ordinary application connections and
restricted state transitions. A process with unrestricted database and key
file access remains within the existing local operator trust boundary; these
guards do not claim to isolate a hostile process running as that operator.

The ADR in `PLAN/ADR_GOLD_LF_P1_08_TRANSCRIPT_MINING_PROVENANCE.md` defines the
canonical metadata contract. `docs/gold-wave10-verification.md` and its source
and test receipts record the runtime and recovery paths actually verified.
