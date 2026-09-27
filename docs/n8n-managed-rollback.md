# Roll back managed n8n to a verified Restore

Run `neoth n8n rollback --restore <restore-job-id> --api-key-stdin` with the
historical API key supplied on piped standard input. The Restore job must be
Ready and its verified Restore/Backup receipts and separately labelled volume
must remain present. The key must authenticate the historical database; the
current installation's key is not assumed to be valid for that database.

NEOTH validates the current managed runtime and the historical receipt chain,
stops the current container if necessary, and renames that same container to
`neoth-n8n-retired-<rollback-job-id-without-hyphens>`. It then starts a new live
container on the verified Restore volume using the recorded immutable image.
The old container ID and its volume remain retained. This operation changes
which database serves the configured loopback endpoint.

The new runtime must pass bounded health and authenticated API checks before
NEOTH publishes its configuration and runtime binding. A completion receipt
binds the Restore/Backup chain, new runtime, retained old container and image.
`neoth n8n status --job <rollback-job-id>` checks this saved historical evidence;
it is not a fresh health probe. A later Backup of the active Rollback runtime
uses receipt v2 with explicit Rollback source provenance.

Re-entering the same completed Restore selection returns the existing receipt.
Interrupted effects are reconciled from durable state. Unknown container-create
identity or uncertain configuration publication holds for reconciliation;
NEOTH does not adopt a container merely because its name matches or repeat an
uncertain publication. Before publication, recoverable failures remove only
the known new container and restore the original container's exact ID, name,
binding and previous running state. The historical Restore volume is retained.

The job store migrates to schema v7 while preserving earlier history. There
are no caller overrides for image, container, volume, endpoint or host port.
Pending Rollback custody blocks competing managed lifecycle changes.

This initial Rollback implementation still requires hosted native and actual
product acceptance. Reinstall and Purge of a Restore-owned Rollback volume are
not supported yet and remain a separate open batch. The retained old runtime
and its volume are not automatically deleted. This document does not establish
release readiness or complete installer-lifecycle acceptance.
