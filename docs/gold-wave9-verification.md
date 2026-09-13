# Gold Wave 9 — Council dimensional agreement

Accepted 2026-09-13 for `GOLD-LF-P1-06`. Implementation is restricted to
AGENTER. The source baseline is `9c57a95109c70ccc34c9fdc2c4663015159e8b4f`;
the ten changed compiled inputs are bound by
`verification/gold-wave9-source-manifest.json`.

Production Council compares bounded model-declared factual claims,
recommendations and risk assessments using 50/30/20 weights. The comparator
normalizes case and whitespace only. Numbers, negation, punctuation, order
and paraphrases remain distinct. Partial agreement is reported, but consensus
requires every applicable dimension to be textually identical and the
existing whole-answer quorum/dissent gate to pass.

The static instruction is outside untrusted question JSON and before optional
ground-truth context. Recursive providers forward that framed prompt once.
Parsing happens before refusal classification, dissent, early quorum,
factual checks and winner selection. Ground-truth checks consume the normal
body plus only the factual declaration. Blank bodies and missing/malformed
evidence cannot establish consensus. Inner Split cannot export consensus
evidence to the outer debate. The original shared budget remains in use.

A private non-serializable, non-Debug execution result carries declarations
between recursive adapters. Public debate results, ordinary responses and
the new extended WAL event carry no raw declarations. CLI replay recognizes
`CouncilAgreementEvaluated` (extended subtype `0x2B`); the shared dispatch
suppresses transcripts and agreement audit in Incognito.
The complete behavior contract is [Council agreement V1](council-agreement-v1.md).

| Final gate | Result |
| --- | --- |
| `SRC/_test.bat --no-run --locked --offline -j1` | PASS, 5m10s |
| `SRC/_check.bat` | PASS, 1m31s |
| `SRC/_clippy.bat` (lib/tests, `-D warnings`) | PASS, 5m08s |
| Workspace fmt via `SRC/_gui_check.bat fmt --all -- --check` | PASS |
| `council::` (includes CLI Council tests) | 413 passed |
| `wal::events::` | 29 passed |
| `security::prompt_envelope::` | 6 passed |
| 22 selected CLI chat Council/hemisphere tests | 22 passed |
| Independent final source review | CLEAR |
| Roadmap release-gate unit tests | 11 passed |
| Lost-feature inventory/integrity tests | 19 passed |

Final behavior total: **470 passed, zero failed, zero ignored**. Selection
and exact test names are retained in
`verification/gold-wave9-test-matrix.json`. The binary lists 14,205 tests;
the table above does not claim the complete library suite was executed.

The fresh test binary is `SRC/target/debug/deps/neothd-a576cce183334209.exe`,
SHA-256 `D8EBFAE7283E5C898F40CC408BE3A9FD15216464066E7D6B1BEFB142E36C203D`.
Final read-back on 2026-09-13 verified all ten source hashes and the binary
hash/size with zero mismatches. The roadmap checker reports 1,324 total,
1,009 complete, 313 open and two partial items: 315 raw and 314 pre-tag blockers.
The existing vendor `peeroxide-dht` dead-code warning remains outside the
changed source and does not fail the strict no-deps gate.

The review and diagnostic runs caught late parsing, a stray marker leak,
empty-body consensus, recursive evidence loss and instructions framed as user
data. These were corrected before the final frozen build. The audit regression
counts the agreement event separately from the writer's mandatory
authentication marker and checks the full WAL bytes for accidental content.

This closes the dimension-scoring implementation item. It does not attest
live provider behavior, semantic agreement, factual correctness, a GUI/native
installer, the full cross-platform workspace suite, or a release candidate.
P1-08 producer provenance and the remaining release gates stay open.
