# W731-W736: explicit OpenClaw Slack account import

The channel CLI adds `import-openclaw-slack` for one explicit OpenClaw account,
one named NEOTH account and one explicit allowed Slack member:

```text
neoth channel import-openclaw-slack --config openclaw.json --source-account work --account ops_a --allowed-user-id U123OPERATOR
```

The source must have `channels.slack.accounts.<source-account>` containing
exactly the two direct string fields `botToken` and `appToken`. The Slack
container must contain only `accounts`; unsupported policy/settings, direct
or default credentials, references, incomplete accounts and unknown account
labels fail before the candidate probe. Other source accounts are not imported.
The allowed member comes from the explicit command option, never from source
workspace/channel/default policy. Source tokens are consumed through the
existing zeroizing secret wrapper and are not command-line token arguments.

The importer uses the existing Slack prepare, `auth.test`, workspace-bound
compare-and-swap commit and reload path. It rechecks the complete OpenClaw
source-set binding after the probe and immediately before durable commit,
including included source files. A failed probe, invalid workspace observation,
source mutation or stale target pair aborts without a partial account write.
Success reports the source account, destination account and source-set digest;
bearer tokens and allowed-member details are absent from the receipt.

The shared transaction also continues to serve ordinary Slack add/rotation.
Existing Telegram import behavior stays covered by its six original CLI tests.
No external Slack message is sent by these hermetic tests.

W733 separately found that the original ADOPT31-H1 catalogue criterion is
already implemented for Cerebras, Fireworks and Nebius. Its two existing exact
catalogue/roster tests are now selected for hosted execution. This records no
live-provider or broader GUI/provider-parity acceptance.

Status: implementation and independent source review are complete. Ten new
regressions and eight existing targeted regressions are registered (native1392;
Group1119 plus the separate custody package lane). Executable validation
runs on GitHub only; the workstation remains under the absolute BSOD hold.
Whole migration, all-channel parity and release criteria remain open.

W735 also repairs an actual production queue-admission gate: valid sealed
Slack/slack pairs now pass beside Telegram/telegram, while crossed pairs remain
quarantined. The prior Group1104 completed1100PASS4FAIL, with all five WebChat
rejoin tests passing. Three Slack cases stopped at this queue gate; the fourth
failure was generated CLI drift. Both production changes passed independent
source review; current executable acceptance remains pending.
