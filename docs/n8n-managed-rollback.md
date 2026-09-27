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

After a completed uninstall of the active Rollback runtime, its verified
Restore volume can be reattached with `install --reuse-uninstall` and the
historical key, or permanently removed with the exact receipt-derived Purge
confirmation. Repeated reattachments preserve the immutable Restore/Backup
origin. These operations affect the active Restore volume only; the older
retired container and its source volume remain retained. See
[managed uninstall and retained data](n8n-managed-uninstall.md).

Hosted native and actual product acceptance for this Rollback lifecycle are
still required. The compiled-product workflow has a separate `rollback_only`
scenario checking that two live-source credentials become the older snapshot's
one credential, alongside authenticated API access and retained workflows.
A source-reviewed scenario is not a passing product result or release proof.
