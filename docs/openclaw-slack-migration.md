# Reversible OpenClaw Slack and Telegram migration

`neoth openclaw-migration` moves one explicitly selected OpenClaw Slack or
Telegram account into one named NEOTH account of that channel. It supports the file credentials
backend, including encrypted credentials. It provides a durable plan, apply,
status, and rollback operation for that one account. Other channel families,
multiple-account batches, and the keychain backend are not supported by this
operation version.

The existing individual import and converted-channel relink commands
remain separate operations. A single-account migration does not claim atomic migration
across those commands or completion of the full OpenClaw migration roadmap.

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
or prepared account incarnation. Both recheck the source and mapping before publication. The
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
