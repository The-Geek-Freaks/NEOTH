# Email cron: Obsidian recovery

The unattended email cron uses the existing IMAP fetch, triage and OCR sanitizer before writing an Obsidian note. Its new filenames are `Paperless/email-<full-unit-sha256>.md` under the configured vault subdirectory. The unit binds the normalized IMAP host, port, username, INBOX and full Message-ID; messages without a Message-ID also bind UIDVALIDITY and UID. The SHA-256 representation avoids the old lossy character replacement, truncation and case-insensitive filename collisions. Existing Paperless WAL unit hashes retain their original format.

The configured vault must already exist. Its subdirectory must be relative and contain ordinary path components; links or reparse points below the resolved vault root are rejected. The note contains deterministic source, input-digest, sanitized-body and findings metadata. Attempt timestamps are omitted so a retry can compare the exact rendition.

| Outcome | Behavior |
| --- | --- |
| Created | The new note was created without replacing another path, and synchronized. |
| AlreadyPresent | The existing note matches every expected byte; file and parent synchronization completed. No content was rewritten. |
| Conflict | Existing content, a partial write, or the destination type differs. Preserve the existing object and leave this email pending. |
| LegacyAmbiguous | An old sanitized filename exists and the new target is absent. Do not adopt, rename, delete or create a second note automatically. |
| I/O error | Do not mark this sink complete or continue to Paperless for this email. |

Only Created or AlreadyPresent permits the next configured sink to run. Paperless still requires its authenticated exact-original completion receipt before the email can be marked processed. A conflicting email does not erase another email's completed work. A crash-created partial note requires explicit recovery; the cron does not overwrite it. A matching observation does not guarantee that another actor will never edit or remove the file afterward.

The ordinary OCR-to-Obsidian API continues to support deliberate document replacement. These rules apply specifically to the unattended email cron.

## Scoped completion (schema 53)

New seen-state uses the same full mailbox-unit SHA256 as the WAL and note identity. Normalized host, port, case-sensitive account name and INBOX bind the mailbox. A full Message-ID is stable across UID changes; the UID fallback requires the current nonzero UIDVALIDITY and a nonempty UID. Passwords and raw message content are not stored in the completion table.

CLI `neoth email fetch` records **triage**, while the cron records **ingest** only after quarantine or all configured sinks complete. Neither stage completes the other. Read/open/write errors are surfaced; a query failure no longer means unseen, and an ignored insertion is not accepted as completion.

| State | CLI default | Cron |
| --- | --- | --- |
| Unseen for this mailbox and stage | Triage | Process through existing sink and WAL gates |
| Seen for this mailbox and stage | Skip as already seen | Skip as completed |
| Matching legacy unscoped row | Report `legacy_ambiguous`, skip | Report unknown account/purpose, leave pending; no sink effect |

Schema 52-to-53 creates the new scoped table transactionally. Legacy rows retain their exact keys, UIDs and timestamps; they are neither deleted nor assigned to a guessed account. A colliding schema object or failed version stamp rolls back the migration. A legacy key may have belonged to another account or only to CLI triage, so it cannot prove ingest completion or authorize replay.

Explicit `--include-seen` allows CLI re-triage and records only the scoped triage result. It does not clear the legacy row, unblock cron ingestion or authorize a second Paperless POST. Legacy reconciliation needs independent mailbox/effect evidence and remains a separate explicit recovery task. Destination/rendition revisions and the remaining A04 adapter contracts also remain open.

W2655 source and regression selection are prepared for hosted validation. Local executable validation remains prohibited by the BSOD hold; source integration alone is not runtime or Gold acceptance.
