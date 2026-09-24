# WebChat session rejoin and named Slack app DMs

W719 adds `neoth companion webchat --resume <session-id>`. Opening a new
WebChat prints its URL and nonsecret session ID; structured output includes
both. Resume uses the existing same-user audit RPC and requires a canonical
UUIDv7 with durable `webchat/default` lifecycle provenance. A saved transcript
by itself, native GUI history, legacy unattributed records, a different
account or Incognito history cannot authorize resume.

The default surface account joins preflight consent, the running turn and
durable lifecycle/WAL attribution. Incognito omits session/origin/account
identity. The reader streams the existing append-only ledger with a 16 KiB
per-record allocation bound, so normal accumulated history does not disable
all rejoin. Malformed or conflicting provenance refuses the request.

Resume creates a new one-use handoff and browser cookie. It reopens only the
proven session's saved transcript and creates fresh requests for subsequent
turns. Old requests, attach grants, cancel capabilities and live replay are
not restored. Five new regressions cover actual preflight/start persistence,
Incognito exclusion, large history, invalid origins, the real transcript
database and rejection of a previously started request through the resumed
HTTP session. Existing native attach coverage now enforces the account too.

W723 connects named Slack accounts to proactive app-DM delivery. Under the
existing delivery lock, the current accepted configuration pair must still
admit the exact sealed account/incarnation. Only its immutable allowed member
is used; the global Slack channel destination never selects this recipient.
After durable Prepared/Intent/Armed admission, the adapter calls
`conversations.open(users=<member>)` once and posts to the returned `D…` IM
ID. Open/post failures and unknown outcomes terminalize that attempt; recovery
does not automatically reopen or resend. Historical Telegram v4 remains
Telegram-only; incarnated v5 evidence supports Slack as well.

The Slack bot needs `im:write` for opening/resuming the one-person DM and
`chat:write` for posting. Official references:

- <https://docs.slack.dev/reference/methods/conversations.open/>
- <https://docs.slack.dev/reference/methods/chat.postMessage/>

User-ID posting is documented separately by Slack for App Home/USLACK; this
implementation uses the app DM ID explicitly. Nine new hermetic regressions
cover the adapter sequence, malformed/open/post failures, exact member
selection, configuration drift, cross-channel refusal and no repeated attempt.
No live provider message was sent.

Root independently verified Group1090 run35979627776 at40d56291: all1090
executed,1089PASS/1FAIL,205 fixture-source bindings and2 input bindings.
All seven workspace-binding cases and both onboarding cases pass. The one
remaining fixture expected successful local-inbox recovery under default
assisted autonomy, which correctly produced PolicySuppressed. Its setup now
uses Full autonomy; the original successful-recovery and no-duplicate
assertions remain. See verification/gold-wave725-group1090.json.

W724 diagnoses the prior macOS package runs as hitting their120/180-minute
hosted limits. The180-minute ARM lane completed its daemon before the GUI
timed out; neither lane saved a cache. The workflow now permits360minutes and
saves a source/architecture/toolchain/lockfile-keyed daemon cache checkpoint
before building the GUI. Release flags, bundle assembly and real packaged
Main/Buddy callback acceptance remain required; timeout diagnosis is not
package acceptance.

Independent source review found no actionable issues in the new product
changes. Their hosted compile and behavior runs remain pending. Portable
native1374/Group1104 includes fourteen new tests. No Road checkbox closes:
WebChat onboarding/migration and complete cross-channel account parity retain
their own remaining criteria. No local compiler, formatter, test or product
runtime was used.
