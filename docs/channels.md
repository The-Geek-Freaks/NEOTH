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

Every channel should pass through:

- identity mapping
- allowlist or account binding
- ingress sanitizer
- profile approval gate
- provider destination audit
- outbound send policy
- WAL event trail

## Managing channels from the CLI

The `neoth channel` family manages the messaging channels (Telegram, Slack,
WhatsApp Business, WhatsApp Web/Baileys, Discord, Signal, LINE, IRC, iMessage/BlueBubbles, Mattermost,
Google Chat, Matrix, Twitch, and Nostr) without the full wizard:

```bash
neoth channel list                 # which channels are configured right now
neoth channel add telegram         # connect a channel (prompts for the token, no echo)
neoth channel test telegram        # live read-only credential check (no message sent)
neoth channel remove telegram      # clear a channel's credentials
```

- **`add`** prompts for the channel's credential(s) with no terminal echo on an
  interactive TTY, and writes them to `~/.neoth/credentials.yaml` (mode-0600).
  Pipe to script it: `printf '%s\n' "$TOKEN" | neoth channel add telegram`.
- **`test`** validates the configured credentials actually work — Telegram
  `getMe`, Slack `auth.test`, WhatsApp Business phone-node lookup, authenticated
  Discord `GET /users/@me`, and Baileys bridge health. It is read-only:
  nothing is sent, nothing is billed.
- **`list`** / **`remove`** show and clear configured state. All four accept
  `--output json`.

Messaging-channel credentials live in `credentials.yaml`; `neoth serve` reads
them on start. Email and calendar do not go through `neoth channel add` and are
not collected by `neoth init`: IMAP uses its documented environment/OAuth
inputs, while CalDAV uses `caldav_{url,username,password}` in
`credentials.yaml` or `NEOTH_CALDAV_*`.

`add` prompts per channel (B9): **discord** bot token · **signal** signal-cli
URL + own E.164 number · **line** channel access token (+ channel secret for
inbound webhooks; blank = push-only) · **irc** server host, nick, optional
NickServ password + channels csv · **imessage** BlueBubbles server URL +
password · **mattermost** server URL + token · **gchat** path to the GCP
service-account JSON key + Pub/Sub subscription name. Optional hardening fields
(`irc_allowed_account`, `imessage_allowed_sender`, per-channel allowlists) are
set directly in `credentials.yaml`. `test` live-checks telegram/slack/whatsapp/
whatsapp_baileys/discord; the rest report configured state via
`neoth channel list`.

## Telegram

### Setup

1. Open Telegram and search for `@BotFather`.
2. Send `/newbot`.
3. Choose a display name and bot username.
4. Copy the token.
5. Run:

```bash
neoth channel add telegram
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

### Notes

| Behavior | Detail |
| :-- | :-- |
| Transport | HTTPS webhook receiver plus Graph API send path. |
| Streaming | WhatsApp has no edit endpoint; NEOTH sends complete replies. |
| Approval | External sends remain policy-gated. |
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
neoth channel add slack
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

## Discord

Discord stores its bot token in `credentials.yaml` (`discord_bot_token`) —
`neoth channel add discord` prompts for it, and `neoth serve` starts the
Gateway loop when it is present. `neoth channel test discord` makes the
read-only Discord `GET /users/@me` identity probe; it validates the token
without creating a message.

Discord notes:

| Behavior | Detail |
| :-- | :-- |
| Gateway | Uses Discord Gateway WebSocket. |
| Message content | Requires Message Content Intent. |
| Formatting | CommonMark-ish with Discord length limits and splitting. |
| Scope | DM and configured guild/channel use based on allowlist policy. |

## Matrix

Matrix is opt-in at build time because the adapter includes the Matrix E2EE and
SQLite crypto-store stack:

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

Matrix policy is fail-closed at the boundaries:

| Field / flag | Behavior |
| :-- | :-- |
| `matrix_allowed_user_id` / `--allowed-sender` | Restricts inbound senders and inviters to one Matrix user id. |
| `matrix_allowed_room_ids` / `--allowed-rooms-csv` | Restricts joins, inbound messages, and proactive sends to the listed room ids. |
| Both allowlists set | Both must match. One allowlist cannot bypass the other. |
| Neither allowlist set | Existing joined rooms remain compatible, but every new invitation is rejected. |
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

## Keet is not a supported channel

Keet does not publish a supported room/message automation API. Pear Runtime embeds
Bare workers and talks to the host app over IPC; the archived `pear-bridge` package
serves local UI assets and is not a Keet message bridge. Therefore NEOTH compiles no
Keet transport and does not request or use a Keet seed:

```bash
neoth channel add keet       # rejected: unavailable
neoth channel test keet      # reports unavailable; makes no network call
neoth channel remove keet    # clears legacy keet_seed_phrase / Pear bearer state
```

NEOTH's optional peeroxide/Hyperswarm private mesh is a separate, NEOTH-specific
node protocol. It does not interoperate with Keet rooms.

Upstream references: [Pear Runtime](https://docs.pears.com/reference/pear/runtime/)
documents the embedded Bare-worker IPC contract; the official
[`pear-bridge`](https://github.com/holepunchto/pear-bridge) repository is archived
and documents only a local UI-asset server. The official
[Pear reference](https://docs.pears.com/reference/) publishes no Keet room/message API.

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
neoth channel test <channel>   # live credential check for one channel
neoth doctor                    # full setup diagnostics (incl. channel wiring)
neoth serve
neoth privacy audit --last 1h
```
