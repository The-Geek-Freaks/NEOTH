# W1572 Rollback publication repair

## Finding

Hosted run `36308031598` at source `15bfbcb0ae30e6909468f092765626903d55d627` completed Restore and Rollback setup, then returned `state=failed` and `failure_code=adoption_cleanup_failed`. Its redacted receipt records successful authenticated HTTP probes before and after the failure, but no raw stderr projection.

The Rollback contract was the concrete incompatible boundary. `managed_rollback::contract` set `authenticated_probe_sha256` to a fixed hash of `n8n-managed-rollback-historical-key-stdin`. The shared publisher creates `ReadyEvidence` from the actual post-commit probe receipt: `n8n-authenticated-workflows-probe-v1`, the literal loopback origin, HTTP 200, and the documented envelope. `ReadyEvidence::receipt_for` requires those digests to match. Consequently `mark_ready` rejects the Rollback job with `ReadyEvidenceMismatch`; the publisher mapped that rejection to the misleading `adoption_cleanup_failed` code.

## Repair

`managed_rollback::contract` now receives the validated source loopback endpoint and uses the shared `expected_authenticated_probe_sha256(endpoint)` function. The publisher and immutable Rollback contract now bind the same endpoint-specific 200-response receipt. The existing Rollback success regression additionally asserts that the stored contract carries that expected endpoint-bound probe digest.

The change preserves the original transaction boundaries: the contract is fixed before enqueue, the endpoint is parsed from the exact source runtime port before use, and no credential or runtime compensation behavior changed.

## Verification boundary

`git diff --check` passed for the owned patch. No Cargo, rustfmt, test, parser, product, container, or GUI command was run because of the active local BSOD hold. A hosted rerun is still required to prove the end-to-end publication path.
