# W142 - evidence-bound Self-improve quality

Self-improve proposals now carry versioned quality evidence produced from
Core-materialized baseline, candidate and fixed-corpus inputs. Model rationale
or imported scores do not certify a proposal. Stage discards imported evidence.

The corpus is read from the fixed `self_improve_eval/v1` root with bounded,
no-follow reads and exact manifest/case hashes. Only a byte-exact operator
approved verification command can produce evaluator results. Core validates
the complete `self_improve_eval_result.v1` binding, including evaluator,
baseline, candidate, source map, corpus and passing regression cases.
The evaluation workspace is bounded containment, not an OS/network sandbox.

The lifecycle preserves source-map refresh, evaluation, current-quality
validation, QA/audit approval and final acceptance checks. Corpus changes,
revoked verifier authority and target/source drift invalidate old evidence.
Legacy narrative scores remain incomplete and cannot unlock acceptance.

The public command `self-improve accept <id> --expected-evidence-sha256 <digest>`
binds consent to the selected evidence. Core compares this digest under the
existing transaction lock before write effects and returns a receipt from
that accepted snapshot. An already accepted proposal is idempotent only with
current matching evidence; no second Skill or ledger write is made.

The GUI uses the same eleven-field quality projection. A current,
verified-approved proposal can offer acceptance using its complete evidence
digest. Completion needs both an exact accept receipt and a fresh review
containing the selected accepted/current evidence. A running operation has
singleflight and revision checks. Missing or malformed evidence never becomes
a positive quality result. Display narrative is distinct from strict identity
and digest fields.

Eight added Core fixtures cover the actual evaluator-to-QA-to-accept path,
wrong result bindings, pre-spawn target drift, corpus drift, verifier revocation,
stale GUI consent, renewed evidence and imported-evidence removal. Four GUI
parser/receipt identities and a genuine native callback fixture extend the
required matrix. The native fixture uses the production callback, staged CLI
child and Slint event loop; its exact identity is registered in the macOS
custom harness as well as ordinary Linux discovery.

This document records implementation scope, not runtime acceptance. Independent
Core and GUI source reviews are recorded with their hashes in the matrix.
All executable checks remain GitHub-hosted. Exact-source native execution,
GUI render/accessibility evidence and the passive Buddy consumer remain
separate requirements. GOLD-LF-P2-05 stays open until those are proven.

Hosted follow-up: CLI-reference35595632250 built source
fb16a751da809951be8e656c5927f1b935288c86 successfully and exported reference
SHA-256 A223E291DBE80B7ED69247CCED489A9588B632685BFBC8789649BFC0116AE7E4.
CodeQuality35595614650 passed. Preflight35595614938 emitted 113 raw Rustfmt
hunks: 87 unique postimages across six files after identical test-path
aliases were collapsed. All postimages are imported; no local formatter ran.
Complete hosted-log SHA-256:
84AB4590657781B47AC192116F7C33B0F271F648FE48B36CA299C57B7C67C8AD.
Fresh native/GUI test execution remains required.
