# Local transcript provenance

Stages 1–3b are accepted in Wave 10 on 2026-09-13. Wave 11 Stage 4 candidate
export is **COMPONENT ACCEPTED**; see [the verification receipt](gold-wave11-verification.md).
P1-08 remains open until the
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

## Export explicit local candidate evidence

Stage 4 is a local, explicit selection path for an existing authenticated
home. It has no provider, network, daemon, WAL-writer, mining, label, grading,
or release authority. It cannot mint a new transcript binding or recovery
capability. The home is transient command input and is never written into an
evidence or parity artifact.

List currently active, unexpired provenance IDs before selecting spans:

```powershell
neoth recall-parity-harness list-local-candidates --local-evidence-home C:\path\to\neoth-home
```

Create a UTF-8 JSONL selection file, sorted by unique `candidate_id`. Each line
names an existing `provenance_id` plus a byte-aligned nonempty `raw_offset` and
optional `source_len`; if omitted, `source_len` selects the remaining retained
operator text.

```json
{"candidate_id":"cand-001","provenance_id":"prov-001","raw_offset":0,"source_len":120}
```

Export only those selected spans, supplying the existing home's expected WAL
signing public key out of band:

```powershell
neoth recall-parity-harness export-local-candidates --local-evidence-home C:\path\to\neoth-home --selections C:\path\to\selections.jsonl --bundle-id wave11-local-01 --evidence-dir C:\path\to\wave11-local-01 --expected-evidence-receipt-pubkey <base64-ed25519-public-key>
```

The artifact directory's parent must already exist. Supply an absolute target
without `.` or `..` navigation components. The directory is
create-new/idempotent: an interrupted retry may reuse only byte-identical
children; a differing artifact requires a new directory. Its single-attempt
export lock returns busy for concurrent work, so retry after the current export
finishes; it does not initialize or wait on an unrelated parent. Its five
immutable files are `source.evidence`, `candidates.jsonl`,
`candidate-evidence-local-custody.json`, `candidate-evidence-manifest.json`,
and `candidate-evidence-receipt.json`. `source.evidence` is an explicit copy
of the selected text spans, in selection order. The export makes no automatic
purge or deletion claim.

The custody sidecar is bounded and signed through the manifest and receipt. It
records only opaque provenance/lifecycle identities, selected offsets and
lengths, hashes, timestamps, and RAW/Bound frame custody; it persists neither
the local home path nor a raw database row ID. Existing legacy bundles remain
format-compatible: absent local custody is omitted, never serialized as a
`null` field.

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

## Wave 11 Stage 4 local-evidence boundary — component accepted

The local candidate list and export open an existing authenticated home in
read-only mode. Before export and before each immutable child is published,
they re-read the selected active binding and prove its RAW/Bound custody. A
local-source artifact is accepted by candidate validation only with
`--local-evidence-home`; its signed custody sidecar, selected spans, current
eligible text, exact frame proofs, expiry and state-version token are checked
again.

That same live revalidation applies to every later consumer of authenticated
local candidate evidence: anchor ingest and reopening a run for batch planning,
result verification/ingest, family-bias output, or attested gate reporting.
Deletion, revocation, expiry, missing custody, changed selected text, changed
WAL proof, or a concurrent state change rejects the consumer before it can
publish or mutate the derived artifact. A detached signature alone therefore
does not preserve authority after the local source is no longer eligible.

Stage 4 is not an automatic deletion or revocation workflow; the established
terminal receipt and revocation rules remain authoritative. It also does not
accept an imported artifact as authority to mint a local birth, bind a legacy
turn, or create a recovery subject. Operator labels, a real shadow run, live
four-grader evidence, and methodology acceptance are still required before
P1-08 can close.
