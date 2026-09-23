# Provider wizard acceptance and hosted failure repairs

GOLD-LF-P1-22 is functionally accepted against
`d93820411a27eec2126cfae81011cdd901807de1`. The evidence comprises 19 distinct
test identities: 18 existing identities passed on both macOS and Windows in
FullCI `35871801240` at `bc9db76c4ff72bfff9fa3674f20d904ead12fc76`, and the
new shared-commit integration passed in Linux GUI run `35893808092` at d938.
Root verified the complete individual terminals, artifact hashes and 13-path
source carry. The machine-readable record is
[`verification/gold-wave479-p122-acceptance.json`](verification/gold-wave479-p122-acceptance.json).

The new integration uses real GUI preparation, the private wizard IPC server,
`WizardSessionController::prepare_for_commit`, daemon-owned hash-bound commit,
GUI reentry and a second preparation, then reloads the effective `FreedomConfig`
with distinct left/right/cerebellum bindings. Existing cases cover canonical
role choices, invalid providers, readiness and CLI/GUI receipts. These are
functional proofs with their original tested sources; no full current-source
release or installed-package acceptance is claimed.

## Actual hosted results

At d938, all 145 selected Linux GUI cases passed. Group run `35894034625`
executed all 885 selected identities: 882 passed, two failed and one exceeded
its terminal timeout. Windows run `35894038715` executed 16 selected storage
and browser cases: 15 passed and the retained-parent swap case failed before
private publication with Win32 error 32. Core run `35892417444` at `8ec8bf6a`
passed slim Clippy and core test-target compilation; workspace Clippy reported
11 diagnostics. These failures remain failures, regardless of P1-22 acceptance.

## Repairs and focused coverage

- Workspace Clippy: remove needless wrappers/clones/references, factor the
  Raft-state return type, and enforce the private dispatch permit's intent
  identity before settlement.
- Parity inventory: point the Omi credential evidence at the actual extracted
  `finish_in_home` body.
- CLI streaming fixture: persist its selected `freedom.yaml` before real
  preparation, keeping all causation, secret and receipt assertions.
- GUI runtime: use a synchronous mutex for short state mutations in the
  synchronous producer sink. A separate asynchronous start-admission gate
  orders durable lifecycle creation and producer registration against shutdown;
  the state guard is released before WAL awaits. The prior Tokio
  `blocking_lock()` ran inside an asynchronous producer task. The observed
  hosted symptom was a missing terminal, not a captured panic trace.
- Windows retained parent: acquire descendant handles with delete sharing
  through the existing no-follow relative-handle helper. Publication retains
  its bound parent and uses relative native rename; it does not re-resolve an
  ambient pathname or close the authority handle.
- Quorum budget: two different followers simultaneously reserve the entire
  shared cap through three real OpenRaft/SQLite replicas. Exactly one grant may
  commit; the losing operation stays rejected on replay and after restart.

The 37 existing quorum-budget tests passed in Group885. P2-19 remains open
until the added concurrency regression has an actual hosted result. P2-26a
remains open pending producer-to-desktop-consumer proof. Independent static
review and hosted follow-up results are recorded separately; none of these
source repairs is counted as an executed regression pass.

All executable verification remains on GitHub under the local BSOD hold.
No local compiler, formatter, test, parser, GUI or product runtime was run.
