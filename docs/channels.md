# Channels

NEOTH exposes the same buddy through multiple surfaces. Channels are not second-class prompt pipes: they share profile memory, recall, skills, policy, redactions, provider routing, and audit.

## Channel matrix

| Channel | Best for | Transport |
| :-- | :-- | :-- |
| **GUI** | Normal users, setup, memory review, privacy controls. | Native Slint app. |
| **CLI** | Operators, SSH, scripts, coding sessions. | Local process. |
| **Telegram** | Fast personal phone access. | Bot API long polling. |
| **WhatsApp Business** | Mainstream phone access. | Meta Business Cloud API webhook. |
| **WhatsApp Web (Baileys)** | Operator-owned personal/dedicated account access. | Repository-owned Node sidecar, authenticated HTTP long-poll. |
| **Keet-identity private topic** | Private peer-to-peer conversations between NEOTH companions. | Repository-owned Pear/Hyperswarm companion over an authenticated loopback bridge; not an existing Keet app room. |
| **Slack** | Workspaces and team workflows. | Socket Mode WebSocket + Web API. |
| **Discord** | Community and DM usage. | Gateway WebSocket. |
| **Signal** | Private personal messaging. | Local signal-cli daemon (JSON-RPC/REST poll). |
| **Matrix** | Federated encrypted rooms/DMs with explicit invite policy. | matrix-sdk (`matrix-channel` feature, persistent crypto/session store). |
| **LINE** | Mainstream phone access (Asia). | Messaging API webhook + push REST. |
| **IRC / Twitch** | Ops channels, streams. | `irc` crate, dial-out TCP (`irc-channel` feature). |
| **Mattermost** | Self-hosted team chat. | WebSocket + REST, dial-out. |
| **Nostr** | Decentralized encrypted DMs. | NIP-17 via relays (`nostr-channel` feature); durable restart catch-up cursor with event-ID de-dup. |
| **iMessage** | Apple-ecosystem messaging. | BlueBubbles server on a Mac, REST poll (dial-out). |
| **Google Chat** | Workspace orgs. | GCP Pub/Sub PULL subscription, no public URL (`gchat-channel` feature). |
| **Email** | Local inbox triage and quarantine. | Source-build `imap_fetch` feature; IMAP over TLS with app-password or XOAUTH2. No SMTP/send path. |
| **Calendar** | List or create schedule items with approval. | CalDAV collection over authenticated WebDAV. |

> **Untrusted-audience readiness.** Six adapters — IRC/Twitch, iMessage
> (BlueBubbles), Mattermost, Google Chat, Matrix and Nostr — fail closed on
> their named inbound identity policy but still need the common
> operator/sender/conversation gate before they are suitable for an untrusted
> audience. Twitch additionally authenticates only the bot transport. Settings
> includes setup fields for these adapters, including their required sender
> identities where enforced. Native GUI and real-provider acceptance remain
> separate. See the [release notes](release-notes-v1.0.md) for the open items.

Every channel should pass through:

- identity mapping
- allowlist or account binding
- ingress sanitizer
- profile approval gate
- provider destination audit
- outbound send policy
- WAL event trail

## Required inbound sender fields in Settings

Settings → Channels exposes the required allowed sender for Slack, WhatsApp
Business, Discord, Signal, BlueBubbles iMessage, Mattermost, Google Chat and
Nostr. These values accompany the credentials during Add/Configure and are
required by the existing private setup request. An empty value stops setup
before any child is launched; no permissive default is created.

Use the platform identity requested by the field: Slack U/W user ID, numeric
Discord user ID, E.164 Signal number, Google Chat users/<id>, or Nostr public
key. The channel-specific CLI validators remain authoritative. Existing saved
credentials are not displayed while editing. Native setup and provider probes
remain required for release qualification.

## Account identity and channel leases

The daemon binds each inbound handler to a canonical channel and account at
adapter startup. A message cannot choose a different binding. Identity aliases,
inbound session keys, media references, rate-limit buckets and channel-originated
lease subjects include that binding.

Existing identity aliases remain visible as `legacy-unbound` in
`neoth identity list`. They are not automatically assigned to `default`.
The admitted legacy Telegram singleton can retain a configured operator UUID
only when its exact sender/chat alias already matches the operator pin. Other
aliases require an explicit identity merge to unify their account-qualified
identities. Merge keeps the original migration claim receipt unchanged.

Use the exact account-qualified subject when granting a channel send or MCP
lease. For example, in PowerShell:

```powershell
$subject = neoth lease channel-subject telegram default 123456789
neoth lease grant $subject channel_send --ttl 1h
neoth permissions check channel_send --subject $subject
```

`channel-subject` validates the channel and account and prints the subject; it
does not create a lease or access credentials. With `--output json` it returns
`subject` and `channel_ref`. Channel-originated MCP requests use the same
subject with a tool-specific lease such as `mcp_tool:server:tool`.
Existing bare-sender leases do not cover these account-qualified requests;
regrant any needed lease using the helper. A grant for one account cannot
authorize the same sender on another account.

### Telegram account maps (P1-16 in progress)

Telegram is the current account-map surface. Each configured account has an
explicit public `allowed_user_id` and a matching credential token. The token is
either present in the credentials file or represented there by a null
placeholder whose account-specific keychain value is loaded at runtime. A
partial, mismatched, blank, or zero-ID map is rejected; legacy scalar Telegram
fields cannot coexist with a map.

Migrate an admitted legacy Telegram singleton with:

```powershell
neoth channel migrate-legacy telegram --account <account-id>
```

The command commits the paired policy and credential migration before cleanup.
If later cleanup fails, retrying completes cleanup against that committed pair.
Its output never prints token material.

While a Telegram account map is active, the legacy flat `channel add telegram`,
`channel remove telegram`, and `channel set-credentials telegram` mutations are
rejected. Reload compares account-qualified credentials and restarts only the
changed Telegram adapter. Replies remain with the adapter that owns the inbound
account; flat proactive Telegram and Cron Telegram announcement paths refuse to
send while a map is active.

Named Telegram accounts can now be added or replaced one at a time with
`neoth channel account add telegram --account <id> --telegram-user-id <id>
--token <secret>`. The account-specific `set-credentials` form reads a strict,
account-bearing private-stdin JSON envelope; it accepts no unknown fields. Both
paths probe the candidate's exact account before committing the paired
configuration/credential update. A changed relevant file or named keychain
value produces a retry error instead of overwriting newer account state; output
is secret-free. The established legacy singleton must still be migrated
explicitly before a map is added.

Settings → Channels offers **Add account** for a valid map and for the exact
fresh Telegram state, alongside the explicit legacy **Configure** choice. Each
account row provides **Edit**, its exact-account **Test**, and **Retire** with
an explicit confirmation for the displayed account ID. A malformed map is
repair-only in the CLI; the GUI neither repairs it nor silently migrates it.
The UI's account request stays in private stdin and accepts only the exact
secret-free acknowledgement for that account.

The GUI retirement surface uses the existing explicit CLI transaction. Other
account families and remaining account-aware outbound routing are separate
P1-16 work. Native GUI acceptance and full CI remain required.

### Mapped Telegram DM pairing (W29; locally validated)

Pairing is disabled until an operator explicitly enables it for one mapped
Telegram account:

```powershell
neoth channel account set-dm-pairing telegram --account <account-id> --enabled
neoth channel pairing list telegram --account <account-id>
neoth channel pairing approve telegram --account <account-id> --code <code>
neoth channel pairing dismiss telegram --account <account-id> --request-id <id>
```

Only a private, non-pinned direct-message sender can create a pending request.
Requests are scoped to that account and its current binding, expire after one
hour, and are capped at three. Pinned operator groups and the established
`ConfirmBus` path keep their existing behavior. Edited Telegram messages cannot
create or refresh pending pairing requests. A binding rotation invalidates only
that account's pending state;
another mapped account remains separate. A missing authenticated mapped receipt
is surfaced as a failure and does not continue into the chat pipeline.

The local selection, Clippy, build, AccountConfigContracts, formatting, CLI-doc
generation, final GUI check, and integrity checks passed. This feature does not
provide pairing migration, physical-provider live acceptance, or complete
multi-account readiness.

### Account retirement and re-add (W32; validation pending)

The admitted W32 surface adds explicit retirement for one mapped Telegram
account:

```powershell
neoth channel account remove telegram --account <account-id>
```

The command never assumes a default account. A later re-add of the same visible
name receives a fresh internal UUID, so existing leases, pending pairing
requests, and queued work remain tied to the retired account. Historical records
with no UUID remain compatible only when the current account remains in that
same historical form; they are never silently relabelled as the replacement.
Settings → Channels exposes that same operation as **Retire** on each valid
mapped account row. Confirm shows the exact visible account ID; no default or
sole-account fallback is inferred. Only a successful process result with a
strict acknowledgement naming that Telegram account and `removed: true`
allows the GUI to refresh the account list. An error or mismatched response
leaves the operation unconfirmed and does not trigger an automatic retry.
The GUI selects the public account ID; it does not add an internal UUID-bound
confirmation contract to the existing CLI authority.
Validation is pending, and P1-16 remains open.

### SelfStage verified staging (W30; enablement pending)

SelfStage is an opt-in verified staging path. The manual command
`neoth update --self --apply` performs the binary swap. Self-probe and
SelfStageAllowed apply only to this lane; CLI, npm, Git, OSV, installer, and
Skill update lanes remain denied. Production runtime execution is pending the
proof that an enabled outer/helper route produces the required ordered receipts.
R3-18B remains open.

### Legacy Telegram and Slack provenance (W34; validation pending)

W34 adds sealed startup provenance only for legacy Telegram and Slack live
delivery. Mapped Telegram remains separate. This limited source-admitted slice
does not establish provenance for other channels or close P1-17.

### OpenClaw account import (W26; locally validated)

The OpenClaw importer accepts `--config`, `--source-account`, `--account`, and
`--telegram-user-id` to create one explicitly named target account from one
selected source account. It reads the selected token only in memory, probes the
prepared target before mutation, rechecks the source set, and then uses the
same prepared CAS commit path as the named-account workflow. Its report uses
shared raw-JSON custody and is canonically redacted. Local validation covers
the final selection (1,492 pass / 0 fail / 1 existing Unix-only ignored),
Compound Clippy, AccountConfigContracts, custody, formatting, and Python
checks. This does not claim a full OpenClaw configuration or transcript
migration, pairing migration, a physical provider live import, or registry
publication.

### Account-bound proactive Telegram routing (Wave 16; locally verified)

`neoth proactive route --default --channel telegram --account <account-id>`
selects an explicit Telegram
account for a new mapped route. It accepts only an exact, non-legacy
authenticated account bundle; a map-active Telegram route cannot omit an
account. The selected account is stored with queued work, so a later routing
default change cannot reroute it to another account.

At physical delivery, the worker holds the existing `DeliveryLock` and, just
before durable `Prepared` admission, reloads a fresh coherent config and
credential pair. It resolves the stored account against that pair and builds the
owning adapter from the returned bundle. The recipient is only that bundle's
`allowed_user_id`; routing data, a queued body, and a legacy recipient cannot
override it.

A credential or policy update completed before this fresh admission applies to
the attempt: it uses the current exact account bundle or settles without a send.
This does not promise retroactive cancellation once the coherent pair has
already been admitted. Under an active map, a missing, unknown, removed,
partial, mismatched, or legacy-unbound account fails closed and never falls back
to another account. A historical unbound Telegram item remains valid through the
existing legacy flat path while the effective map is empty.

New account-bound claims and durable delivery evidence use a version-4 typed
channel reference. Historical queue rows, claims, and WAL records retain their
existing versions and recovery semantics. P1-16 remains open for other account,
transport, pairing, UI, health, and outbound surfaces.

### Account transport evidence and Doctor flapping (W20; validation pending)

W20 adds a read-only, account-isolated transport-evidence view for two already
authorized paths: mapped nonlegacy Telegram live replies and v4 mapped Telegram
proactive egress. Only the validated `TelegramAccountBundle` path may attach the
bound account metadata to a live intent; generic/default bindings, the legacy
Telegram singleton, other channels, webhooks, probes, and outboxes remain
unbound.

The evidence reader performs one complete authenticated home-WAL scan. It first
validates each bound intent/result relationship and only then derives the
24-hour per-account counters. Incomplete, unavailable, malformed, replaced, or
unauthenticated WAL yields no partial counters. The stored typed reference is
historical evidence: it is never rebound through current configuration,
credentials, runtime health, or a route default.

`neoth doctor` can surface account-specific transport flapping from those
validated counters. It considers only completed adapter attempts for the failure
rate (initially at least five completed attempts and at least 20% failures).
Armed-without-result and unsettled live intents are explicit inconclusive
evidence and warn without being counted as completed attempts. A scan error is
unavailable rather than a partial report; no observed bound attempts passes the
check.

This is metadata and diagnosis only. It does not create authorization, routes,
credentials, retries, runtime-health authority, or a physical-delivery claim.
W20 now has nine admitted source files and TestBuild01 passes; four real
authenticated-WAL tests also pass. An initial selected run exposed a real legacy
JSON byte-order regression, repaired by restoring the former `json!` value plus
optional-reference writer shape; the raw-byte assertion remains unchanged.
Doctor's all-check documentation list has 60 entries, while `run_all_checks`
returns 59 runtime outcomes. The admitted mapped live-auth repair keeps the
existing opaque capability gates and `append_authenticated` path: `CHANNEL_SEND`
precedes the terminal marker for success and failure, without changing unbound
payload/order behavior. TestBuild02 **PASS** (4m07s; 183.27 GiB minimum free;
11.07 GiB peak), Selected02 **394/0/0** (before this repair), Python 19+11+8,
and Clippy03 **PASS** are intermediate evidence. Final TestBuild03 **PASS**
(3m49s; 202.66 GiB minimum free; 10.65 GiB peak), final selected **397/0/0**
(catalogue 14,389), 13 integration targets **157/0/0**, and formatting/GUI
lint/self-test pass. W20 is locally verified and published at
`080131b4320ac3935d1f5d05e242295e5c3625a8`. No current-head full-CI or cross-platform
acceptance is claimed. See
[the W20 verification receipt](gold-wave20-verification.md).

## Managing channels from the CLI

The `neoth channel` family manages the canonical messaging registry (Telegram,
Slack, WhatsApp Business, WhatsApp Web/Baileys, Keet-identity private topics,
Discord, Signal, LINE, IRC, iMessage/BlueBubbles, Mattermost, Google Chat,
Matrix, Twitch, and Nostr) without the full wizard:

```bash
neoth channel list                 # which channels are configured right now
neoth channel add telegram         # prompts for token + exact numeric sender ID
neoth channel test telegram        # live read-only credential check (no message sent)
neoth channel test telegram --account <account-id>  # one mapped Telegram account
neoth channel remove telegram      # clear token + sender policy
```

- **`add`** prompts for channel secrets with no terminal echo on an interactive
  TTY and for required public policy fields. Telegram commits its token in
  `~/.neoth/credentials.yaml` and its exact numeric sender allowlist in
  `~/.neoth/freedom.yaml` under one locked rollback-safe update. Script it with
  `neoth channel add telegram --token "$TOKEN" --telegram-user-id "$TELEGRAM_USER_ID"`.
- **`test`** validates the configured credentials with a protocol-specific,
  read-only check: Telegram `getMe`, Slack `auth.test`, WhatsApp Business
  phone-node lookup, Baileys/Keet companion health, Discord bot identity,
  signal-cli registered accounts, LINE bot identity, BlueBubbles ping,
  Mattermost current user, Google Pub/Sub subscription access, Matrix
  `/account/whoami`, Twitch OAuth identity/scopes, and Nostr relay connection.
  It sends no chat, consumes no inbound queue, and publishes no relay event.
  IRC returns the typed `unavailable` verdict because registering the configured
  nick is stateful and could collide with the live adapter. Matrix password-only
  auth is likewise `unavailable`; use a device-bound access token for a safe
  live probe.
- **Mapped Telegram `test`** requires an exact account: run
  `neoth channel test telegram --account <account-id>`. The account is never
  inferred from an active map, including `default`; an unknown or invalid map
  fails before a probe. `--account` is rejected for non-Telegram channels and
  for the legacy scalar Telegram singleton, where the existing no-account test
  remains the valid path.
- **`list`** / **`remove`** show and clear configured state. All four accept
  `--output json`.

For a valid Telegram account map, `channel list` emits one secret-free child
per configured `ChannelRef`. This is **static readiness**: it proves the
matching policy and effective credential bundle are usable, not that an adapter
or daemon is live. A partial or mismatched map remains an error instead of
producing usable-looking account children.

When a matching local daemon instance publishes a current private runtime
projection, the same child can additionally report `running`,
`configured_not_started`, `failed`, `inactive`, or `credentials_invalid`.
The projection is accepted only for the exact current account binding and live
daemon instance. A missing, stale, mismatched, unreadable, or unproven
projection is **unknown**, while the static account readiness stays visible;
JSON omits the optional runtime field in that case. Runtime projection is
observational only and is not credential or authorization evidence.

### Settings and `connect` account views (W18-19; locally verified)

**Settings → Channels** shows a Telegram account map as nested, secret-free
account rows. Each row separates its static configured state from the optional,
read-only runtime observation above. The panel can run the read-only Telegram
test only for the exact selected account and refuses to present a result for a
different account as that selection. It does not create accounts, pair devices,
or offer a migration workflow.

For operator detail, use an explicit account ID:

```powershell
neoth connect telegram --account ops_b
```

The map overview lists configured account children but has no implicit
`default` selection. An invalid or partial map is a repair state: no account is
usable or testable until matching policy, nonzero sender, and credentials are
complete. A legacy no-map Telegram setup retains its compatible no-account
detail and test path.

The W18-19 source is independently reviewed and locally verified: full GUI
test-source checking, 175 core and 350 actual GUI parser/action tests, final
Clippy, formatting and GUI lint pass. Native rendering and live delivery
acceptance remain separate. See
[the W18-19 verification receipt](gold-wave18-19-verification.md).

Wave 17 is locally verified by the focused unit and integration checks recorded
in [its verification receipt](gold-wave17-verification.md). Full cross-platform
CI and live Telegram acceptance remain separate.

Messaging-channel credentials live in `credentials.yaml` or the selected
keychain backend. While `neoth serve` is running, its reconciler watches the
effective credentials and config generation, debounces replacements, and
restarts only the changed channel. A malformed/unreadable credential store
stops the channel fleet fail-closed; NEOTH never keeps stale tokens active.
Email and calendar do not go through `neoth channel add` and are
not collected by `neoth init`: IMAP uses its documented environment/OAuth
inputs, while CalDAV uses `caldav_{url,username,password}` in
`credentials.yaml` or `NEOTH_CALDAV_*`.

`add` prompts per channel (B9): **discord** bot token + immutable user ID ·
**slack** bot/app tokens + immutable member ID · **whatsapp** Cloud credentials
+ exact E.164 sender · **signal** signal-cli URL + own and allowed E.164 numbers
· **line** channel access token + exact user ID (+ channel secret for inbound
webhooks; blank = push-only) · **irc** server host, nick, optional
NickServ password + channels csv · **imessage** BlueBubbles server URL +
password · **mattermost** server URL + token · **gchat** path to the GCP
service-account JSON key + Pub/Sub subscription name. Twelve adapters enforce
a mandatory inbound identity policy: Telegram requires `telegram_user_id`, IRC requires
`irc_allowed_account`, BlueBubbles requires
`imessage_allowed_sender`, Mattermost requires `mattermost_allowed_user_id`,
Google Chat requires `gchat_allowed_sender`, Nostr requires
`nostr_allowed_pubkey`, Discord requires `discord_allowed_user_id`, Slack
requires `slack_allowed_user_id`, WhatsApp Business requires
`whatsapp_allowed_sender`, Signal requires `signal_allowed_sender`, LINE
requires `line_allowed_sender`, and Matrix requires at least one of
`matrix_allowed_user_id` or `matrix_allowed_room_ids`. The shared
`--allowed-sender` flag supplies the channel-appropriate single identity;
Matrix additionally accepts `--allowed-rooms-csv`. `channel list` reports
canonical static configuration truth; `channel test` adds live
credential/reachability truth.

Twitch remains the explicit audience-policy exception: it authenticates the bot
and configured stream rooms, but does not yet bind inbound chat to an operator
identity or mention policy. Do not expose its tool-bearing pipeline to an
untrusted stream audience. Transport membership is never treated as operator
authorization for the other inbound adapters.

Matrix state-store selection, LINE webhook port, and IRC port/TLS/secondary
nick filtering now have CLI and GUI configuration surfaces. Their previously
file-only settings retain the same runtime defaults. Native and visual setup
acceptance remain required; field exposure alone does not close channel parity.

These keys are documented for existing operators, not presented as a
zero-friction setup claim. Generic descriptor-rendered forms, durable recovery
across a process crash between OS-keychain and file publication, and persisted
multi-account channel identity are still release-blocking work.

## Telegram

### Setup

1. Open Telegram and search for `@BotFather`.
2. Send `/newbot`.
3. Choose a display name and bot username.
4. Copy the token.
5. Get your numeric Telegram user ID (for example from `@userinfobot`). NEOTH
   requires this exact inbound allowlist and refuses an open bot.
6. Run:

```bash
neoth channel add telegram \
  --token "$TELEGRAM_BOT_TOKEN" \
  --telegram-user-id "$TELEGRAM_USER_ID"
neoth channel test telegram
neoth serve
```

### Notes

| Behavior | Detail |
| :-- | :-- |
| Identity | Numeric Telegram user IDs are used, not usernames. |
| Groups | The numeric sender allowlist still applies. There is no separate mention-only group mode. |
| Long replies | Split into continuation messages. |
| Streaming | NEOTH can edit an in-progress message where supported. |
| Inbound attachments | Photos, voice, audio, video, documents, stickers, and captions enter the media pipeline when enabled; downloads are capped at 16 MiB. |
| Outbound attachments | Images, MP4 video, MP3/M4A audio, documents, and Telegram stickers use native Bot API methods with MIME/size checks. Long captions fall back to split follow-up messages. |
| Flood control | Short Telegram `RetryAfter` responses are honored once; longer limits surface to the caller instead of sleeping indefinitely. |

## WhatsApp Business

NEOTH uses the official Meta WhatsApp Business Cloud API. No personal-number hacks and no browser automation.

### Setup

```bash
neoth channel add whatsapp
# Non-interactive equivalent includes --allowed-sender +491701234567
neoth channel test whatsapp
neoth serve
```

Credential fields:

| Field | Description |
| :-- | :-- |
| `whatsapp_token` | Meta Cloud API token. |
| `whatsapp_phone_id` | Phone number ID from Meta Business console. |
| `whatsapp_verify_token` | Secret used during webhook verification. |
| `whatsapp_app_secret` | Used for webhook signature verification. |
| `whatsapp_allowed_sender` | Exact operator phone number. Stored canonically as 7–15 digits; CLI accepts an optional leading `+`. |

### Notes

| Behavior | Detail |
| :-- | :-- |
| Transport | HTTPS webhook receiver plus Graph API send path. |
| Streaming | WhatsApp has no edit endpoint; NEOTH sends complete replies. |
| Approval | External sends remain policy-gated. |
| Inbound authorization | A valid Meta signature is transport authentication only. The decoded `from` must also match `whatsapp_allowed_sender` before dedup or pipeline dispatch; rejection is WAL-audited without message text. |
| Business review | Meta approval can take time; use Telegram while waiting. |

## WhatsApp Web through Baileys

This optional path uses the repository-owned sidecar in
`bridges/whatsapp-baileys/`. It is not Meta Cloud and never reads or reuses the
Meta token, phone ID, webhook secret, or proactive destination. Baileys is an
unofficial WhatsApp Web client; use a dedicated account and opt in only after
accepting the platform-policy risk.

```bash
cd bridges/whatsapp-baileys
pnpm install --frozen-lockfile
export NEOTH_WA_BRIDGE_TOKEN="$(openssl rand -hex 32)"
pnpm start                         # scan the QR on first start

neoth channel add whatsapp_baileys \
  --url http://127.0.0.1:9120 \
  --token "$NEOTH_WA_BRIDGE_TOKEN" \
  --allowed-sender '+491701234567' \
  --allowed-rooms-csv '120363000000000000@g.us'
neoth channel test whatsapp_baileys
neoth proactive route --channel whatsapp_baileys --dest '+491701234567'
neoth serve
```

The sender allowlist is mandatory. Groups are deny-by-default and require both
an allowed sender and an exact allowed `@g.us` group JID. The bridge stores QR
auth in its repo-owned atomic Signal-key store (not Baileys' demo multi-file
helper), plus a bounded durable inbound journal, restart dedup state, and
outbound idempotency state in `~/.neoth/whatsapp-baileys-bridge/` (owner-only). NEOTH
stores its own per-account cursor under `~/.neoth/channel-state/`; an expired
cursor fails closed instead of skipping unseen messages.

Every bridge request uses a dedicated bearer token. Plain HTTP is accepted only
on loopback; a bridge on another host needs HTTPS with redirects disabled. Text
and media (10 MiB maximum) work inbound and outbound. See
[`bridges/whatsapp-baileys/README.md`](../bridges/whatsapp-baileys/README.md) for
the user-service unit, recovery procedure, and protocol contract.

Delivery is deliberately at-most-once. NEOTH persists an inbound claim before
the provider/pipeline runs, so a crash can lose a reply but cannot replay the
same message into a second paid or tool-bearing turn. Outbound unknown outcomes
remain permanent pending tombstones until the operator reconciles them; they
are never removed by TTL or capacity pruning.

## Slack

Slack uses Socket Mode so you do not need a public HTTPS endpoint.

```bash
neoth channel add slack \
  --bot-token "$SLACK_BOT_TOKEN" \
  --app-token "$SLACK_APP_TOKEN" \
  --allowed-sender U0123456789
neoth channel test slack
neoth serve
```

Required Slack scopes:

| Scope | Purpose |
| :-- | :-- |
| `chat:write` | Send replies. |
| `im:history` / `channels:history` | Read messages. |
| `im:write` | Start or reply in DMs. |
| `users:read` | Resolve identity. |
| `connections:write` | Socket Mode app token. |

`slack_allowed_user_id` is the immutable `U…` or `W…` member ID, never a
display name or email. The daemon refuses token-only Socket Mode startup.
Every decoded event must match that ID before the shared pipeline runs;
mismatches are dropped without a reply and recorded as the metadata-only
`CHANNEL_GATE_REJECTED` WAL event.

## Discord

Discord stores its bot token and exact inbound-user policy in `credentials.yaml`
(`discord_bot_token` + `discord_allowed_user_id`). Configure both through the
CLI or the same registry-driven GUI form:

```bash
neoth channel add discord \
  --token "$DISCORD_BOT_TOKEN" \
  --allowed-sender 123456789012345678
neoth channel test discord
```

The allowed sender is the immutable numeric Discord user ID, not a mutable
username. `neoth serve` refuses to start the Gateway receive loop when the
policy is missing or blank. `neoth channel test discord` makes the read-only
Discord `GET /users/@me` identity probe without creating a message.

Discord notes:

| Behavior | Detail |
| :-- | :-- |
| Gateway | Uses Discord Gateway WebSocket. |
| Message content | Requires Message Content Intent. |
| Formatting | CommonMark-ish with Discord length limits and splitting. |
| Inbound authorization | Every non-bot message must match `discord_allowed_user_id` before the shared pipeline runs. Mismatches are dropped without a reply and audited as `CHANNEL_GATE_REJECTED`; no message text enters that audit event. |

## Signal

Signal uses a local `signal-cli` HTTP daemon. Configure the registered NEOTH
number and the one operator number allowed to drive inbound turns:

```bash
neoth channel add signal \
  --url http://127.0.0.1:8080 \
  --phone +491701111111 \
  --allowed-sender +491702222222
```

`signal_allowed_sender` is mandatory E.164. The poll loop is not constructed
without it. Envelopes from any other source are dropped before the pipeline and
WAL-audited; delivery receipts, typing events and sync envelopes remain
non-actionable.

## IRC

IRC requires an authenticated IRCv3 services account in addition to the server
and bot nick. `--allowed-sender` selects that account; an optional nick filter
cannot replace it:

```bash
neoth channel add irc \
  --server irc.example.org \
  --nick neoth \
  --allowed-sender operator-account \
  --channels-csv '#neoth' \
  --irc-port 6697 \
  --irc-tls true \
  --irc-allowed-nick operator-nick
```

The **Port**, **TLS** and **Secondary allowed nick** controls in the IRC form
configure those same fields. Ports must be integers from `1` through `65535`.
TLS has three choices: retain current/default, explicitly enabled, or explicitly
disabled. An omitted flag or retain-current choice preserves an existing
setting; it never silently turns an explicit `false` back into a default.
Blank port/nick fields preserve an existing override during credential updates.
With no prior configuration, the runtime defaults to port `6697`, TLS enabled,
and no additional nick filter. Nonblank nick filters cannot contain whitespace
or control characters. Channel removal clears the IRC configuration, including
settings-only state. The adapter reads these settings when it starts; saving
credentials does not claim a live connection reconfiguration.

## LINE

LINE outbound push can operate with an access token alone, but inbound startup
requires the channel secret and one immutable `U…` user ID:

```bash
neoth channel add line \
  --token "$LINE_CHANNEL_ACCESS_TOKEN" \
  --password "$LINE_CHANNEL_SECRET" \
  --allowed-sender U0123456789abcdef
```

Use `--line-webhook-port 9443` with the command above, or the optional
**Webhook port** field in the GUI, to select a listener port from `1` through
`65535`. Zero and out-of-range values are rejected. An omitted flag or blank
GUI field preserves an existing custom port during credential updates; a new
configuration without a port uses `8444`. The listener still binds only to
`127.0.0.1`, behind your reverse proxy. Saving the setting does not by itself
rebind a running listener; it applies when the channel starts.

The webhook must pass `X-Line-Signature` verification and the decoded source
must equal `line_allowed_sender`. Signature validity alone never authorizes a
turn. Missing/invalid policy keeps the listener off; rejected senders are
recorded as metadata-only gate events.

## Matrix

Matrix is opt-in at build time because the adapter includes the Matrix E2EE and
SQLite crypto-store stack. It requires Rust 1.93 (default builds that omit
`matrix-channel` remain supported on Rust 1.91):

```bash
cargo build -p neoth --features matrix-channel
neoth channel add matrix \
  --url https://matrix.example.org \
  --nick @neoth:example.org \
  --token "$MATRIX_ACCESS_TOKEN" \
  --allowed-sender @operator:example.org \
  --allowed-rooms-csv '!private:example.org,!ops:example.org'
neoth channel list
neoth serve
```

To route queued proactive items into Matrix, configure the operator-owned room
and a source/default route explicitly:

```bash
neoth proactive route --channel matrix --dest '!ops:example.org'
neoth proactive route --source coding_session --channel matrix
```

`--password` is the first-login fallback when no token is supplied. A configured
access token takes precedence and is verified with `/account/whoami`; the
returned user and device id are used to restore the exact device session. A
homeserver that omits the device id is rejected because inventing one would
break E2EE continuity. The resulting session is stored atomically at
`~/.neoth/matrix_store/neoth-matrix-session.json` inside the owner-restricted
crypto-store directory. Tokens and passwords are never printed by probes or
errors.

Choose a different crypto/session directory with `neoth channel add matrix
--matrix-store-path "C:\Matrix state"` alongside the usual account and policy
arguments, or use the optional **State store path** field in the GUI's Matrix
setup. Both save `matrix_store_path` through the existing channel configuration
operation. A nonblank path replaces the configured value; omission or a blank
field preserves an existing custom path when updating credentials. If no path
has ever been configured, the default is `matrix_store` beneath the selected
NEOTH home. Configuring a path does not move or migrate an existing E2EE store;
choose the directory containing the account's intended session state.

Matrix policy is fail-closed at the boundaries:

| Field / flag | Behavior |
| :-- | :-- |
| `matrix_allowed_user_id` / `--allowed-sender` | Restricts inbound senders and inviters to one Matrix user id. |
| `matrix_allowed_room_ids` / `--allowed-rooms-csv` | Restricts joins, inbound messages, and proactive sends to the listed room ids. |
| Both allowlists set | Both must match. One allowlist cannot bypass the other. |
| Neither allowlist set | Matrix is not started. Existing-room messages would otherwise bypass the invite-only gate, so an open adapter is refused. |
| `matrix_require_encryption` | Defaults to `true`, including old config files without the field. Plaintext rooms are neither read nor written. |
| `--allow-plaintext` | Explicitly writes `matrix_require_encryption: false`; `channel list`/doctor surface the plaintext posture as a warning. |

The adapter checks room encryption after an allowed join, before inbound text
enters the pipeline, and before every reply/proactive send. If encryption state
cannot be verified while enforcement is enabled, the operation is refused.
The proactive dispatcher uses the same credentials, persistent device store,
room allowlist, and encryption policy; it never accepts a destination from the
queued item itself. In a binary without `matrix-channel`, the saved Matrix route
remains sidecar-only and is never presented as a live delivery path.
Configured Matrix credentials in a binary without `matrix-channel` are reported
as an error and `neoth serve` logs that the adapter was not started; they are
never reported as live.

## Keet-identity Pear/Hyperswarm companion

Desktop release archives include `neoth-keet-bridge`, NEOTH's repository-owned,
full-duplex text companion. It uses `keet-identity-key` for portable sender
identity and Pear/Hyperswarm building blocks for an encrypted private topic. The
standalone includes its Bare runtime, so normal installs need neither Node.js nor
the Pear CLI.

Run setup once and keep the printed bearer token and `nk1_...` topic private:

```bash
neoth-keet-bridge setup
neoth-keet-bridge serve
```

On every peer, join the same topic and exchange only the printed `self_id`
values. Then wire the local companion interactively with `neoth channel add
keet`, or non-interactively:

```bash
neoth channel add keet \
  --url http://127.0.0.1:9130 \
  --token '<local companion bearer_token>' \
  --server 'nk1_<shared topic capability>' \
  --allowed-sender '<remote self_id>[,<another remote self_id>]'
neoth channel test keet
neoth serve
```

`--server` is the generic channel CLI field that carries the Keet topic. The
allowlist is mandatory and exact/case-sensitive. The live probe requires an
authenticated protocol/version handshake, both send and receive capabilities,
the configured joined topic, and its high-water cursor; static credential
presence alone never reports the channel healthy. Runtime receive starts at
that high-water cursor, so first startup does not replay arbitrary older local
history. Sends are durable and idempotent, and inbound sender IDs come from
verified Keet identity attestations before the allowlist and NEOTH pipeline.

This does **not** automate or read existing Keet desktop/mobile rooms. Keet has
no supported public room/message API, so NEOTH creates its own private
Keet-identity Pear/Hyperswarm conversation instead of guessing a proprietary
protocol. The old `keet_seed_phrase` field remains ignored and `--seed` is
rejected. `neoth channel remove keet` clears both the real companion credentials
and any legacy seed state. The separate NEOTH cluster mesh likewise remains a
different protocol.

Companion operations, recovery, exact HTTP contract, and threat boundary are in
[`bridges/keet/README.md`](../bridges/keet/README.md).

## Email

Email is treated as a sensitive channel because it contains other people's text, attachments, tracking links, and prompt-injection bait.

Network-live email requires a source build with `imap_fetch`; the named release
bundles intentionally omit that feature. Configure `NEOTH_IMAP_USERNAME` plus
an app-password or the documented Gmail OAuth inputs, then use
`neoth email fetch`. The command reads bounded UNSEEN messages with
`BODY.PEEK[]`, so triage does not mark mail read. `--dry-run` remains available
on builds without the feature. Email is not a bot token and does not go through
`neoth channel add` or `neoth init`.

Default behavior:

| Action | Default |
| :-- | :-- |
| Fetch inbox | Explicit command, or the separately opt-in email-ingest cron; both require `imap_fetch`. |
| Message state | Non-destructive `BODY.PEEK[]`; no read/delete/move mutation. |
| Triage | Sanitizer, deterministic threat score, trusted-domain annotation, and fail-closed quarantine. |
| LLM tie-break | Off by default because it can spend a provider call; failures preserve the conservative verdict. |
| Send or draft replies | Not implemented. There is no SMTP client or email-send path. |
| Attachments | Parsed within bounded message limits and subjected to the same hostile-content posture. |

## Calendar

Calendar is configured through `caldav_url`, `caldav_username`, and
`caldav_password` in `~/.neoth/credentials.yaml`, or the corresponding
`NEOTH_CALDAV_*` variables. `neoth calendar list` is read-only;
`neoth calendar add` performs the external write.

Default behavior:

| Action | Default |
| :-- | :-- |
| List VEVENTs | Read-only after credential configuration. |
| Add VEVENT | Requires the `calendar.writes_enabled` rail, the external-task-write gate, and confirmation unless already granted; emits calendar audit events. |
| Update/delete VEVENT | Not part of the current `neoth calendar` CLI surface. |
| Extract dates from email | No automatic email-to-calendar write path is claimed. |

## Cross-channel identity

NEOTH does not silently merge identities. If you talk to it from Telegram and
Slack, those stay separate by default — each channel is its own conversation
surface with its own consent gate.

When you DO want recall and profile to follow you across surfaces, link them
deliberately:

```bash
neoth identity list                 # every channel identity NEOTH has seen
neoth identity merge <keep> <fold>  # link two identities (audited, reversible)
```

The merge is operator-driven, written to a `0x9B IDENTITY_MERGED` WAL frame
(reversible tombstone — see [privacy.md](privacy.md)), and the alias map never
leaves the machine. Without an explicit merge, channels stay independent — the
fail-closed default.

## Channel safety checklist

| Check | Why |
| :-- | :-- |
| Allowlist enabled | Prevents random accounts from using your buddy. |
| Webhook signatures verified | Prevents spoofed inbound events. |
| Outbound sends gated | Avoids accidental external messages. |
| Attachments size-capped | Prevents resource exhaustion. |
| Ingest sanitized | Prevents prompt-injection and profile poisoning. |
| WAL events written | Makes actions auditable. |

## Live E2E checks

Use [live-e2e-protocol.md](live-e2e-protocol.md) before trusting a production channel.

Typical smoke:

```bash
neoth channel test <channel>   # read-only live check or typed unavailable
neoth doctor                    # full setup diagnostics (incl. channel wiring)
neoth serve
neoth privacy audit --last 1h
```
