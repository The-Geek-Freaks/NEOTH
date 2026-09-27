# W1572 - Rollback publication repair review

**Decision:** accepted for hosted GitHub gates.

## Reviewed source

- `SRC/neothd/src/integrations/n8n/managed_rollback.rs`
  - SHA-256: `1503DD74110072409F6FC5433C54A829A946367D856A8F68CA454390F97B4D7D`
- `SRC/neothd/src/integrations/n8n/managed_rollback_tests.rs`
  - SHA-256: `D9C42A27BB6868AE70E2FC5B6B528677BEDE821752E5273608803757CC29661F`

## Result

The prior rollback evidence contract used a fixed digest unrelated to the authenticated post-commit probe. `publish_adoption_in_job_with_cancel` constructs `ReadyEvidence` from `N8nProbeReceipt::authenticated_probe_sha256()`, which hashes the fixed receipt namespace, canonical endpoint origin, HTTP 200, and documented envelope. `mark_ready` therefore rejected an otherwise successful rollback publication as `ReadyEvidenceMismatch`, surfaced as `adoption_cleanup_failed`.

The repair changes only the Rollback contract construction:

1. The endpoint is parsed from `active_source`'s bound `host_port` before enqueue.
2. `active_source` ties that binding to a matching stored job and requires `is_active_runtime_source` plus a container ID before the port is used.
3. The contract delegates to the same parent-module `expected_authenticated_probe_sha256(endpoint)` helper used by the shared n8n adoption path.
4. The added regression assertion compares the persisted rollback contract against that same endpoint-bound digest.

Rust visibility is valid: `managed_rollback` is a descendant of the n8n module and can call its parent-private helper through `super::super`. The helper hashes only fixed metadata and the loopback origin. No API key, credential material, response body, or secret enters the job contract or receipt.

The change preserves the rollback manifest and custody checks and does not alter compensation, runtime mutation, or publication sequencing.

## Static checks

- `git diff --check`: passed.
- Focused source review: no critical or high issue found.

## Remaining proof boundary

No Cargo, clippy, rustfmt, test, parser, container, GUI, or product command was run locally under the BSOD hold. Acceptance requires the scheduled GitHub native/group/Windows gates and a hosted product rerun that reaches Rollback `Ready` without `adoption_cleanup_failed`.
