# Managed n8n uninstall

`neoth n8n uninstall` removes the container belonging to the current NEOTH
managed installation. The command checks the original successful install job,
its durable runtime binding, and the complete inspected container identity.
It removes only that exact container ID. The named data volume is retained.
There is no volume purge or foreign-container override on this command.

An adopted instance has no managed-container ownership and cannot be removed
through this command. Missing or conflicting runtime ownership stops removal.

## Managed repair

`neoth n8n repair` is a parameterless public command for the existing NEOTH
managed runtime. It takes no port, image, endpoint, container, volume or API-key
override. The command derives its target from the stored successful managed
install, durable runtime binding and stored credential authority. A healthy
runtime is an authenticated no-op; a stopped exact container may be started;
and a missing owned container may be recreated only when Docker returns and the
receipt persists that exact new ID.

Repair checks the pinned image, managed volume, stored binding and authenticated
loopback readiness before publishing Ready. It uses the same nonblocking
operation lock as uninstall and purge. An interrupted, malformed or uncertain
repair custody record fences uninstall and purge; an uncertain create is held
and cannot be retried by adoption or by accepting a later same-named container.
The structured completion action is `healthy`, `started`, or `recreated` only
when its receipt still agrees with the current source install and runtime
binding.

The implementation was independently statically reviewed. At source
`9c01fa10f3613a139648b6e731ab2173f0ac7be6`, which corrects the repair module
path and imports hosted formatting, native tests, compilation, and the actual
Docker product canary reported hosted failures; diagnosis and corrected runs
are pending. Do not treat the command as having
hosted execution success until those gates publish evidence.

## Interrupted commands

NEOTH stores the removal intent before invoking Docker. A failed command or a
terminated client can leave the removal outcome unknown. Running the command
again inspects the recorded container ID. It does not issue another removal
after the recorded dispatch boundary. Confirmed absence permits cleanup to
continue. A live or unknown container keeps the uninstall pending for repair.

Success requires a durable Uninstall job, a retained completion receipt, and
finalization of the old runtime binding. The original Ready install job remains
unchanged as history. Repeating a completed uninstall returns the same job
until another managed installation exists.

`neoth n8n status --job <job-id>` reports the operation separately from its
state. For an uninstall, `ready` means the removal operation completed. Its
disposition is `container_removed_data_volume_retained`. Reading status does
not recover jobs, run Docker, or delete configuration.

## Configuration and credentials

New completed publications retain a private job-bound ownership receipt. It
contains a secret commitment and configuration identity, not an API key. After
container absence is proven, the file-backed configuration and key are cleared
only when the endpoint, API version, backend, and key still match that receipt.
Unrelated configuration fields are preserved through the existing two-file
transaction.

The `config_cleanup` result states what happened:

| Value | Meaning |
| --- | --- |
| `cleared` | The matching file-backed endpoint and key were cleared. |
| `already_absent` | Both values were already absent in the file backend. |
| `preserved_unproven` | Ownership could not authorize deletion, or the installation uses the keychain backend. |
| `preserved_changed` | The current binding, key, or backend differs from the retained publication. |
| `unknown_or_preserved` | No valid completed cleanup receipt is available to the status reader. |

Historical installations without this receipt keep their configuration and
credentials. Keychain-backed configuration and credentials are also retained
in this implementation; automatic keychain deletion requires a separate
recoverable transaction. A successful container uninstall does not claim that
these retained credentials were revoked.

## Reinstall a retained bootstrap volume

A new uninstall receipt retains the original runtime identity and the original
bootstrap volume owner. To attach that existing data volume again, provide the
completed Uninstall job ID and pipe its still-valid API key to:

```text
neoth n8n install --reuse-uninstall <uninstall-job-id> --api-key-stdin
```

The command uses the receipt's original port and reviewed pinned image. It
requires the same named volume to exist with the original bootstrap ownership
labels. Missing, unknown or foreign volumes fail before container creation;
Docker is not allowed to silently create an empty replacement. The selector
cannot be combined with `--port` or `--bootstrap-owner`. The key is required on
stdin and is not read automatically from retained keychain credentials.

Reinstallation creates a new Install job while preserving the original Install
and Uninstall history. Later uninstall/reinstall cycles keep the original
bootstrap volume owner. This attaches the volume's current data; the receipt is
not a database snapshot. Workflow import remains a separate command.

A repeat while a managed runtime is active is rejected before Docker actions.
Older receipts without retained-volume proof and ordinary unlabelled default
volumes remain readable in status but cannot authorize this explicit selector.
The existing ordinary stdin-key installation path is unchanged.

## Permanently purge a retained bootstrap volume

After a successful uninstall, inspect the exact retained-data target:

```text
neoth n8n purge --uninstall <uninstall-job-id>
```

Without `--confirm`, this shows the receipt-derived volume and the confirmation
phrase; it does not delete the volume. To proceed, repeat the command with
`--confirm` and the exact displayed phrase. Purge permanently deletes the n8n
workflows, executions and other data stored in that volume.

The table output includes shell quotes around the `--confirm` argument. Copy
that argument as displayed; the quotes group the phrase and are not part of
its value. JSON output instead returns the raw phrase in `confirmation`.

| Response | Meaning |
| --- | --- |
| `state: "confirmation_required"` | Preview only; no deletion was requested. |
| `state: "ready"`, `disposition: "volume_removed"` | The selected purge has a completed receipt. |
| `disposition: "reconciliation_required"` | Completion is unproven; the command exits unsuccessfully. |

Preflight and execution errors also exit unsuccessfully and can be reported
before a job response is available.

The target comes exclusively from a completed managed-uninstall receipt and
its original install job. Only a bootstrap volume carrying the matching NEOTH
ownership labels is eligible. An active managed runtime, unproven ownership,
conflicting operation or incorrect confirmation prevents removal. There is no
volume-name, container, endpoint or filesystem override.

The separate Purge job records the dispatch before deleting the exact volume.
If the result is uncertain, repeating the command may establish that the volume
is absent; it cannot dispatch another deletion. A completed purge keeps the
original install and uninstall history, receipts and credentials. Repeating
that completed operation returns its recorded result. Retained reinstall is
no longer possible once the data volume is gone.

The integration-job lock coordinates NEOTH operations. Docker addresses a
volume by its name, so an external Docker administrator replacing the same
name between inspection and removal is outside that lock's protection.

## Validation boundary

The implementation includes focused fake-runner and configuration transaction
regressions. Source review and registered tests are distinct from executed
GitHub gates and an actual Docker lifecycle test. The n8n repair source review
is recorded in `docs/verification/gold-wave1407-n8n-repair.json`; its status is
`STATIC_REVIEW_HOSTED_PENDING`, not test or product acceptance. This document
does not close the broader safe-uninstall/purge, Obsidian, or release acceptance
criteria.

## Provenance and release boundary

The managed image reference and any recorded blob checksum establish only the
specific bytes or metadata checked. They are not upstream signatures or
attestations. Upstream signature/attestation verification and admission remain
open. Managed update and rollback remain open too. Neither a stored-identity
repair receipt nor a checksum authorizes an update, rollback, or a release
claim.
