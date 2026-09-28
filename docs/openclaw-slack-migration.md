# Reversible OpenClaw Slack and Telegram migration

`neoth openclaw-migration` moves explicitly selected OpenClaw Slack and Telegram
accounts into named NEOTH accounts. It supports the file credentials backend,
including encrypted credentials. A single account or an ordered batch shares
one durable plan, apply, status, and rollback operation. Other channel families
and the keychain backend are not supported by this operation version.

The existing individual import and converted-channel relink commands
remain separate operations. A migration batch owns the config/credentials file
pair; it does not combine those separate commands or pause active channel traffic.

## Plan an explicit mapping

Keep the original `openclaw.json` and its resolved include files available. Put
the mapping in a private local JSON file:

```json
{
  "schema_version": 1,
  "channel": "slack",
  "source_account": "work",
  "account": "work",
  "allowed_user_id": "U0123456789"
}
```

`source_account` selects the OpenClaw account. `account` names the NEOTH account,
and `allowed_user_id` is an explicit NEOTH sender-policy input. Tokens come from
the selected, supported OpenClaw source fields; they do not belong in the mapping
file or command line. Unknown request fields and unsupported source shapes are
rejected.

For Telegram, use the same command with this private mapping. Its allowed user
is a positive integer; a Slack member ID remains a string:

```json
{
  "schema_version": 1,
  "channel": "telegram",
  "source_account": "work",
  "account": "work",
  "allowed_user_id": 123456789
}
```

Telegram migration refuses keychain-backed homes before preparing the account
or accessing its keychain token. Existing Slack v1 plans and recovery records
remain usable; Telegram operations use their own participant-bound v2 plans.

## Migrate several accounts together

Use a version-3 batch mapping for between one and 32 accounts. Each entry uses
the same version-1 account mapping shown above. Accounts are probed in request
order, then their changes are published together in one config/credentials pair:

```json
{
  "schema_version": 3,
  "channel": "batch",
  "participants": [
    {
      "schema_version": 1,
      "channel": "slack",
      "source_account": "work",
      "account": "work",
      "allowed_user_id": "U0123456789"
    },
    {
      "schema_version": 1,
      "channel": "telegram",
      "source_account": "work",
      "account": "work",
      "allowed_user_id": 123456789
    }
  ]
}
```

Source and destination account names must be unique within each channel. Slack
and Telegram may use the same name. Empty or nested batches, duplicate mappings,
unknown fields and unsupported participants are rejected. Every selected account
must come from the same source configuration and its resolved include set.

If any provider probe fails, no account in the batch is published. The complete
source set and private mapping are checked again after each probe and before the
single pair publication. A version-3 operation retains one immutable before/after
pair for all participants, including their exact encrypted credential bytes.
Rollback restores that entire pair only while it still matches this operation.
Existing version-1 Slack and version-2 Telegram operations retain their original
records and recovery behavior.

The following commands work with either a single-account or batch mapping:

```text
neoth --output json openclaw-migration plan --config /private/openclaw.json --request /private/migration-request.json
```

Retain the returned operation ID. The plan binds the resolved source set,
mapping, and current NEOTH config/credentials generation. Changing any of them
requires a fresh plan; an existing operation is never silently rebound.

## Apply, inspect, and resume

```text
neoth --output json openclaw-migration apply --id <operation-id> --config /private/openclaw.json --request /private/migration-request.json --confirm
neoth --output json openclaw-migration status --id <operation-id>
```

Apply verifies the exact Slack candidate with authenticated `auth.test` and binds
the resulting workspace. Telegram uses authenticated `getMe`; its returned bot
username is display information and never replaces the explicit allowed user
or prepared account incarnation. All probes share a 60-second validity window,
and the source and mapping are rechecked after each response. The
private recovery record retains the exact file images, including encrypted
credential bytes and account incarnation. If the process stops, repeat the
same apply command with the original source and mapping. Recovery reconciles
the actual files before deciding whether publication is still needed.

A completed retry preserves the recorded bytes. A different mapping, changed
source, invalid recovery record, or unexpected target generation prevents a
write. Status exposes the operation ID, phase, progress, and a redacted reason;
it does not print source paths, account labels, tokens, or file contents.

## Roll back the recorded generation

```text
neoth --output json openclaw-migration rollback --id <operation-id> --confirm
```

Rollback restores the exact config/credentials pair from before this operation,
including unknown fields and the distinction between absent and empty files.
It requires the current pair to match this operation's recorded postimage.
Later operator edits or another account change are not overwritten. Interrupted
rollback is resumed with the same rollback command.

Recovery files are private and may contain credential snapshots. Keep them
with the NEOTH home while the operation may need recovery or rollback; do not
publish them as diagnostic artifacts.

Successful apply and rollback request daemon reload after the terminal state
is durable. A reload request is not evidence that a running daemon adopted the
new generation or that the channel is connected. Inspect ordinary daemon
and channel status for live connectivity. This command does not undo messages
already delivered by an active channel.
