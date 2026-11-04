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

## Account-bound cron quarantine

Cron quarantine now uses the same full mailbox-unit identity as the WAL and vault. The identifier printed by quarantine list is email-<digest>; pass it unchanged to quarantine show. These commands inspect retained content and do not authorize delivery.

New records are created without replacement. The envelope binds the full raw-body SHA256 in addition to the visible 512-character preview, reason and findings. An exact retry preserves the first timestamp and file bytes, then synchronizes the file before reporting completion. A changed body, edited record, partial file, unexpected schema, link or nonregular target stays pending.

Existing legacy hash names, lossy names and renamed records with the raw UID remain ambiguous. Scan/read/parse failures and bounded scan exhaustion also leave work pending. The scan accepts at most4096 entries and16MiB of records, each at most1MiB. Crash partial files require explicit reconciliation. Concurrent legacy writers and hostile parent-directory replacement are outside this migration guarantee. The generic quarantine API retains its existing behavior for other callers.

The scoped completion ledger still lacks destination/input revision binding; completed old entries do not automatically become eligible for replay. W2657 runtime and native qualification remain pending.

## Incomplete Paperless configuration

A Paperless destination is declared if either its URL or token field is present, including an empty value. Both fields absent disable that destination. A declared destination without both nonempty values remains pending even when the configured Obsidian note was successfully created or found byte-for-byte intact. Repairing credentials allows the existing WAL reconciliation path to run; it grants no second POST for an uncertain historical effect.

Only authenticated Paperless completion and every configured vault completion allow delivered Ingest marking. Durable quarantine remains its separate terminal path. This prevents new premature completions; already marked historical units require explicit reconciliation. W2658 adds a real vault/ledger regression and two destination-state regressions, pending hosted validation.

## Input-bound completion (schema54)

New Ingest completions bind the exact sender, sender domain, subject, full raw body, ordered attachment names and Authentication-Results through a versioned SHA256. The existing mailbox-unit identity still binds Message-ID or UIDVALIDITY/UID; changing only the UID of the same Message-ID does not invalidate completion.

A matching completed unit is Seen. Changed input is InputConflict and is excluded from sink effects; the cron reports its own conflict count while continuing independent eligible messages. This comparison does not authorize a new delivery. The rotating IMAP page cursor and BODY.PEEK behavior remain selection-only and do not acknowledge or remove conflicted messages.

Migration53to54 preserves old completion rows with NULL input. They remain LegacyAmbiguous rather than adopting the current fetched bytes. Triage stays separate. An insertion must be followed by an exact matching completion read; an ignored or conflicting concurrent write is not success.

This is a post-completion input contract. Existing WAL and vault controls still govern uncertain effects before completion. Destination principal and approved target/rendition revisions are not established by this digest. W2659 runtime qualification remains pending.
