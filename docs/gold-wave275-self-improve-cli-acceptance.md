# W275 — P2-05 CLI acceptance fixture

`w275_cli_run_review_exact_digest_accept_readback_and_corpus_drift_refuses_before_mutation` is a hermetic, temporary-`NEOTH_HOME` acceptance test for the CLI handler boundaries of P2-05.

It drives the real `self-improve run --from` handler to stage a deterministic proposal, invokes the real JSON `review` handler before selecting the persisted typed-quality evidence digest, and invokes the real JSON `accept --expected-evidence-sha256` handler with that exact digest. A second real `review` handler call establishes the accepted readback.

The fixed-corpus evaluator and audited `VerifiedApproved` transition are prepared by the existing W142 core path: exact approved verifier, materialized corpus inputs, current-evidence gate, passing in-process QA advisor, and `persist_verified_approval_after_audit`. The fixture does not edit proposal status or quality evidence files directly.

The drift leg stages and approves a separate proposal, changes one fixed-corpus case after the review digest was selected, and invokes the same real CLI accept handler. It requires an error containing `stale` and byte-identical target skill, proposals store, and ledger afterward. This demonstrates refusal before acceptance mutation.

This is intentionally not a full CLI `Execute` test. `Execute` performs the same fixed-verifier evaluation and then requires configured provider-backed QA plus WAL finalization. W275 covers the actual CLI stage/review/accept/readback boundaries while exercising evaluator and approval as existing hermetic core paths; it makes no claim that CLI `Execute` provider QA was run.

The test uses `crate::test_env::lock()` while it sets and restores `NEOTH_HOME`, so it is safe with other process-environment tests. The W142 fixed verifier has Windows `.cmd` and non-Windows `sh` variants, so the fixture is platform-configured through the existing helper.

The focused selection also runs the four existing passive Buddy-quality tests from self_improve/passive.rs: exact shared quality/identity projection, malformed identity rejection, pending journal refusal without recovery/lock creation, and the final recovery probe. These exercise the actual passive reader used by Buddy; they do not claim a complete Buddy command or rendered GUI run.
