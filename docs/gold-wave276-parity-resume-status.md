# GOLD-W276 — Recall-parity resume status

`neoth recall-parity-harness resume-status` is a bounded, read-only checkpoint
for one explicitly selected existing P1-08 run. It accepts the same explicit
grader configuration and goldset bytes as the existing run readers, plus an
optional detached import receipt and its out-of-band public key:

```powershell
neoth recall-parity-harness resume-status `
  --run-dir C:\eval\run-001 `
  --grader-config C:\eval\grader-config.json `
  --goldset C:\eval\goldset.jsonl `
  --import-receipt C:\eval\import-receipt.json `
  --expected-receipt-pubkey <base64-ed25519-public-key>
```

It opens an existing bound run and its mandatory existing lock only. It does not
create a run directory, lockfile, state file, report, provider request, label,
batch plan, grade import, or release verdict. A concurrently writer-held lock
fails closed as a redacted unreadable run state. The optional receipt is verified only to report whether the
separate manual `attested-gate-report` transition has all of its required
inputs; `manual_gate_report_ready: true` is not a gate pass or a publication.

The JSON status contains only a fixed stage state (`missing`, `valid`,
`invalid`, or `blocked`), SHA-256 values, bounded record counts, and fixed error
categories. It never returns filesystem paths, local-home identifiers, database
row IDs, selected spans, candidate text, anchors, grade records, provider/model
metadata, or underlying validation errors.

Stages are evaluated in order: bound run, operator anchor and candidate custody,
four-grader plan, attested result group, family-bias summary, then the supplied
import receipt. A missing prerequisite leaves downstream stages `blocked`; an
invalid local custody, including revocation, expiry, changed source, or changed
artifact identity, leaves it `invalid` and cannot produce manual-report
readiness.

The synthetic `local_anchor_revalidation_rejects_revoked_source_without_mutating_run`
workflow covers a complete local-evidence/anchor/four-grader/receipt artifact
group, asserts resume readiness and an exact pre/post file snapshot, then
revokes local custody and asserts a redacted invalid anchor state with another
unchanged snapshot. It remains an offline fixture: it does not claim live
provider origin or external grading execution.
