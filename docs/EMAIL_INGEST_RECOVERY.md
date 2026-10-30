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

The ordinary OCR-to-Obsidian API continues to support deliberate document replacement. These rules apply specifically to the unattended email cron. The shared older CLI/cron seen ledger still uses unscoped legacy keys and can suppress messages across accounts or reused UIDs. This batch neither migrates those keys nor replays historical mail. Account-scoped seen-state recovery, destination-revision changes and the remaining A04 adapter contracts remain open.

The W2653 source and regression selection are prepared for hosted validation. Local runtime tests remain prohibited by the BSOD hold; source integration alone is not runtime or Gold acceptance.
