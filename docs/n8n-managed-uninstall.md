# Managed n8n uninstall

`neoth n8n uninstall` removes the container belonging to the current NEOTH
managed installation. The command checks the original successful install job,
its durable runtime binding, and the complete inspected container identity.
It removes only that exact container ID. The named data volume is retained.
There is no volume purge or foreign-container override on this command.

An adopted instance has no managed-container ownership and cannot be removed
through this command. Missing or conflicting runtime ownership stops removal.

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

## Validation boundary

The implementation includes focused fake-runner and configuration transaction
regressions. Source review and registered tests are distinct from executed
GitHub gates and an actual Docker lifecycle test. This document does not close
the broader safe-uninstall/purge, Obsidian, or release acceptance criteria.
