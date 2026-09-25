# Managed n8n full backup

Run `neoth n8n backup` to archive the `.n8n` data of the current NEOTH-managed
SQLite installation. NEOTH derives the exact container, image and volume from
its successful managed-install receipt. Adopted or foreign containers are not
backup targets. The command has no container, volume, image or output override.

A running source is stopped before copying its data and started again after
the archive has been copied. A source that was already stopped stays stopped.
The archive contains the complete supported data directory, including the
SQLite database and n8n configuration. It is sensitive: configuration includes
the credential encryption key. NEOTH stores the uncompressed tar privately at
`NEOTH_HOME/n8n-backups/<backup-job-id>.tar`, limited to 8 GiB. Only regular files
and directories are supported; linked or special entries are rejected rather
than followed outside the managed volume.

On success, JSON output includes a `receipt` with the source install, pinned
image, exact container and volume, generation, archive SHA-256 and byte count,
and original/restored running state. The durable job operation is `backup`.
Use `neoth n8n status --job <backup-job-id>` to inspect an earlier backup. Its
private receipt and archive remain available after later repair or uninstall;
status verifies their identity and archive digest without calling Docker.
A second completed backup creates a distinct job and archive.

If the command is interrupted, run it again to reconcile the recorded exact
container. A copy whose outcome is unknown is never repeated for that job.
After the original runtime state is confirmed restored, the job is marked
failed and a subsequent command can start a new backup. If runtime restoration
cannot be confirmed, the job retains custody and reports a reconciliation
error. Conflicting install, repair, uninstall and purge actions are held while
backup custody remains unresolved. Unverified partial archives stay private
and never receive a successful backup receipt.

The shared integration database upgrades from schema v4 to v5 to record the
separate Backup operation while retaining existing job history.

This command creates and verifies an archive. Restore into a new volume,
boot verification of restored credentials and workflows, version updates,
and rollback remain separate work; archive creation does not prove them.
