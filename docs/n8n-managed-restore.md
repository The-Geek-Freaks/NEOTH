# Validate a managed n8n backup

Run `neoth n8n restore --backup <backup-job-id>` to restore a completed managed
backup into a separate Docker volume. The backup job must be Ready, and its
private archive and receipt must still be present. The command verifies the
entire archive and uses its recorded immutable n8n image. It does not require
the original container or its current API key.

The live n8n installation continues using its existing volume. Restore creates
an isolated candidate without network access or published ports and keeps its
workflow server stopped. Inside that candidate it checks the SQLite database,
reads every workflow through the supported n8n export command, and decrypts
every credential through n8n. Temporary plaintext stays in private memory-backed
storage and is removed before a successful receipt is returned.

A Ready result means the separate candidate volume passed validation. Its
receipt reports `candidate_only: true`, the backup and restore job identities,
the image and archive digest, the retained volume, workflow and credential
counts, and whether credentials were decrypted. An empty credential table has
`credential_decryption_proven: false`; it does not count as a decryption test.
Every workflow must have a selected version and be exportable. The verifier
allows up to 32 MiB per temporary export within a 64 MiB memory-backed directory.

Use `neoth n8n status --job <restore-job-id>` to read the verified historical
receipt. The status command checks the saved provenance; it does not perform a
fresh Docker health check. The successful candidate container is removed and
only its separately labelled volume remains. Switching the live installation
to this volume, updating n8n and live rollback are separate operations and are
not performed by this command.

If interrupted, repeat the command with the same backup job. NEOTH reconciles
the existing job and never repeats an uncertain extraction, validation or
removal. Failed validation removes only the exactly identified candidate and
its owned volume before marking the job Failed. If ownership or absence cannot
be proved, reconciliation holds and other managed n8n operations remain blocked.
An interrupted container creation without a durably recorded container ID
requires operator reconciliation; NEOTH does not guess ownership from a name.

The integration job store upgrades to schema v6 while preserving earlier
install, repair, backup and removal history. There are no caller overrides for
the archive path, container, image, volume or host port.
