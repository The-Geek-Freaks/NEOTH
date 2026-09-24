# Named Slack account lifecycle

W675/W676 completes file-backed operator commands for the authenticated Slack
account runtime. Telegram's existing command grammar stays compatible.

## Commands and private token input

`neoth channel account add-slack --account work --allowed-user-id U123ABC`
reads one bounded JSON object from standard input:

```json
{"schema_version":1,"channel":"slack","account":"work","bot_token":"<bot token>","app_token":"<app token>"}
```

Use the private input mechanism of your launcher or pipe a protected credential
file to stdin. Neither token is a command-line argument. Unknown/duplicate fields,
invalid JSON, unsupported schema, wrong channel/account and blank tokens reject
before publication. Parse errors do not echo input values.

`neoth channel account set-credentials slack --account work` reads the same
private object and preserves the current allowed-user policy inside the locked
prepared candidate. `neoth channel test slack --account work` resolves only that
configured account and calls `auth.test` for its bot token. A configured account
map requires explicit `--account`; no default or first entry is inferred.
The result proves bot authentication; Socket Mode app-token acceptance is still
reported separately by the running adapter.

`neoth channel account remove slack --account work` retires exactly that account
and requests reload after storage commits. Other accounts remain configured.
`neoth channel migrate-legacy slack --account work` atomically moves a complete
scalar Slack policy/bot/app triple into the explicit named account. Once a map
exists, flat Slack add/remove/set-credentials refuses to mutate it.

## Transaction behavior

The prepared candidate owns both raw file preimages and its exact proposed pair.
The CLI probes that candidate, then the commit compares both snapshots under the
existing transaction lock. A failed probe or any concurrent file change leaves
the current pair intact. Unknown YAML extensions survive, but omitted typed
Slack account IDs are removed from both renderers before their lossless overlay;
otherwise a retired account would be resurrected by serialization.

Credential rotation retains the existing account incarnation; removing then
recreating the same account name mints a new incarnation. The current Slack
lifecycle supports the file secrets backend. Keychain mode rejects before any
write until its dynamic bot/app token custody is implemented. Telegram's existing
keychain behavior is unchanged. The registry now identifies Telegram and Slack
as the two adapters with named-account runtime and transactional lifecycle.

Fourteen new regressions cover candidate publication, CAS drift on either file,
true retirement and re-add, unknown-field/sibling preservation, migration,
keychain refusal, private input, exact CLI selection, rotation and reload. The
existing canonical registry and migration-rejection tests are also selected.
Native inventory1328 and grouped selection1058; new execution is pending.

W679 also repairs two hosted compilation findings from source0c4da3b3:
`BindingTag` intentionally lacks Debug, so its inequality test now uses the same
boolean predicate without `assert_ne!` formatting; the old default-account shared
adapter helper has no remaining callers and is removed. Every current caller
already uses the explicit ChannelRef helper. No lint suppression is introduced.

Source review passed. No local compiler, parser, formatter or test ran. P1-16 and
all full channel/surface acceptance remain open; no Road checkbox closes here.
