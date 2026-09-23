# W275 — P2-05 CLI acceptance fixture

`w275_cli_run_review_exact_digest_accept_readback_and_corpus_drift_refuses_before_mutation` is a hermetic, temporary-`NEOTH_HOME` acceptance test for the CLI handler boundaries of P2-05.

It drives the real `self-improve run --from` handler to stage a deterministic proposal, invokes the real JSON `review` handler before selecting the persisted typed-quality evidence digest, and invokes the real JSON `accept --expected-evidence-sha256` handler with that exact digest. A second real `review` handler call establishes the accepted readback.

The fixed-corpus evaluator and audited `VerifiedApproved` transition are prepared by the existing W142 core path: exact approved verifier, materialized corpus inputs, current-evidence gate, passing in-process QA advisor, and `persist_verified_approval_after_audit`. The fixture does not edit proposal status or quality evidence files directly.

The drift leg stages and approves a separate proposal, changes one fixed-corpus case after the review digest was selected, and invokes the same real CLI accept handler. It requires an error containing `stale` and byte-identical target skill, proposals store, and ledger afterward. This demonstrates refusal before acceptance mutation.

This is intentionally not a full CLI `Execute` test. `Execute` performs the same fixed-verifier evaluation and then requires configured provider-backed QA plus WAL finalization. W275 covers the actual CLI stage/review/accept/readback boundaries while exercising evaluator and approval as existing hermetic core paths; it makes no claim that CLI `Execute` provider QA was run.

The test uses `crate::test_env::lock()` while it sets and restores `NEOTH_HOME`, so it is safe with other process-environment tests. The W142 fixed verifier has Windows `.cmd` and non-Windows `sh` variants, so the fixture is platform-configured through the existing helper.

The focused selection also runs the four existing passive Buddy-quality tests from self_improve/passive.rs: exact shared quality/identity projection, malformed identity rejection, pending journal refusal without recovery/lock creation, and the final recovery probe. These exercise the actual passive reader used by Buddy; they do not claim a complete Buddy command or rendered GUI run.

## P2-05 hosted acceptance — 2026-09-23

GOLD-LF-P2-05 is accepted from three complementary evidence sets:

- [Group484 run35815551129](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35815551129):
  exact nine Core/CLI cases at 2b0c6f300b156954f8a634e58f097e2ec399f476.
- [Group489 run35816919838](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35816919838):
  all489 cases passed at b7ca8bf49ef16ea29589a108667f8855b9e3349f, including
  the four passive-quality cases at positions475–478. The full admission
  verifies107 source bindings, matrix/lock hashes and every ordered terminal.
- [GUI8f16 run35813667946](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35813667946):
  seven quality tests at positions23–27,105–106 passed individually. They
  cover exact current-evidence acknowledgements, GUI projection, stale/missing
  and unknown-quality refusal, explicit unavailable Buddy state, accept/readback
  and non-mutating exact-proposal Buddy handoff. The complete run was122/124;
  W153/W164 failed outside this acceptance and remain separate repair work.

The six relevant Core/GUI production paths have identical Git blobs fromb7ca
to7f84. GUI main.rs differs from8f16 only in unrelated W274/W155 test helpers;
the accepted W142/W149 tests and production quality path remain unchanged.

Retained closure:
work/gold-20260906/wave282-buddy-quality/CLOSURE.json,
SHA256 1DC05C055310A4020F4367C2B5FC42E9F2004C420CB24AB57CAD2FDC66C53326.
Group489 admission SHA256:
e510845f8c66e1023b75b6124a5cebf092bd885b218b95d765acb735687283e7.

This closes the versioned persistent quality/provenance and refusal/display
contract. It does not claim live-provider CLI Execute QA, a packaged GUI
launch, recipient delivery or overall release readiness.
