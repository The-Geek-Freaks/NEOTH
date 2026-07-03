# Channels

NEOTH exposes the same buddy through multiple surfaces. Channels are not second-class prompt pipes: they share profile memory, recall, skills, policy, redactions, provider routing, and audit.

## Channel matrix

| Channel | Best for | Transport |
| :-- | :-- | :-- |
| **GUI** | Normal users, setup, memory review, privacy controls. | Native Slint app. |
| **CLI** | Operators, SSH, scripts, coding sessions. | Local process. |
| **Telegram** | Fast personal phone access. | Bot API long polling or webhook. |
| **WhatsApp Business** | Mainstream phone access. | Meta Business Cloud API webhook. |
| **Slack** | Workspaces and team workflows. | Socket Mode WebSocket + Web API. |
| **Discord** | Community and DM usage. | Gateway WebSocket. |
| **Keet** | P2P/private channel direction. | Pears/Keet bridge. |
| **Signal** | Private personal messaging. | Local signal-cli daemon (JSON-RPC/REST poll). |
| **Matrix** | Federated rooms/DMs. | matrix-sdk (`matrix-channel` feature). |
| **LINE** | Mainstream phone access (Asia). | Messaging API webhook + push REST. |
| **IRC / Twitch** | Ops channels, streams. | `irc` crate, dial-out TCP (`irc-channel` feature). |
| **Mattermost** | Self-hosted team chat. | WebSocket + REST, dial-out. |
| **Nostr** | Decentralized encrypted DMs. | NIP-17 via relays (`nostr-channel` feature). |
| **iMessage** | Apple-ecosystem messaging. | BlueBubbles server on a Mac, REST poll (dial-out). |
| **Email** | Important-message detection, drafts, replies. | IMAP/OAuth provider adapters. |
| **Calendar** | Read/create/update schedule items with approval. | CalDAV/Google-style adapters. |

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
WhatsApp, Keet, Discord, Signal, LINE, IRC, iMessage/BlueBubbles, Mattermost)
without the full wizard:

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
  `getMe`, Slack `auth.test`, WhatsApp phone-node lookup, Keet seed-phrase format
  (offline). It is read-only: nothing is sent, nothing is billed.
- **`list`** / **`remove`** show and clear configured state. All four accept
  `--output json`.

Channel credentials live only in `credentials.yaml`; `neoth serve` reads them on
start. Email and calendar are configured through the wizard (`neoth init`) —
they are sensitive ingest surfaces, not bot tokens.

`add` prompts per channel (B9): **discord** bot token · **signal** signal-cli
URL + own E.164 number · **line** channel access token (+ channel secret for
inbound webhooks; blank = push-only) · **irc** server host, nick, optional
NickServ password + channels csv · **imessage** BlueBubbles server URL +
password · **mattermost** server URL + token. Optional hardening fields
(`irc_allowed_account`, `imessage_allowed_sender`, per-channel allowlists) are
set directly in `credentials.yaml`. `test` live-checks telegram/slack/whatsapp/
keet; the rest report configured state via `neoth channel list`.

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
| Groups | Bot can require mention before responding. |
| Long replies | Split into continuation messages. |
| Streaming | NEOTH can edit an in-progress message where supported. |
| Attachments | Photos, voice, audio, documents, and captions enter the media pipeline when enabled. |

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
| `whatsapp_access_token` | Meta Cloud API token. |
| `whatsapp_phone_number_id` | Phone number ID from Meta Business console. |
| `whatsapp_verify_token` | Secret used during webhook verification. |
| `whatsapp_app_secret` | Used for webhook signature verification. |

### Notes

| Behavior | Detail |
| :-- | :-- |
| Transport | HTTPS webhook receiver plus Graph API send path. |
| Streaming | WhatsApp has no edit endpoint; NEOTH sends complete replies. |
| Approval | External sends remain policy-gated. |
| Business review | Meta approval can take time; use Telegram while waiting. |

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
Gateway loop when it is present.

Discord notes:

| Behavior | Detail |
| :-- | :-- |
| Gateway | Uses Discord Gateway WebSocket. |
| Message content | Requires Message Content Intent. |
| Formatting | CommonMark-ish with Discord length limits and splitting. |
| Scope | DM and configured guild/channel use based on allowlist policy. |

## Keet

Keet is the private/P2P channel direction.

```bash
neoth channel add keet
neoth channel test keet
neoth serve
```

Keet is useful when the operator wants less platform gravity and more private mesh behavior.

## Email

Email is treated as a sensitive channel because it contains other people's text, attachments, tracking links, and prompt-injection bait.

Email is configured through the wizard (`neoth init`), which collects the IMAP
account binding — it is a sensitive ingest surface, not a bot token, so it does
not go through `neoth channel add`.

Default behavior:

| Action | Default |
| :-- | :-- |
| Read inbox | Operator-approved account binding. |
| Summarize important mail | Allowed by policy after setup. |
| Draft replies | Allowed; drafts are marked for review. |
| Send replies | Requires approval unless policy explicitly grants it. |
| Learn from email | Sanitizer and attribution gate before profile/memory. |
| Attachments | Media/document pipeline with prompt-injection checks. |

## Calendar

Calendar is configured through the wizard (`neoth init`), which collects the
CalDAV / provider account binding.

Default behavior:

| Action | Default |
| :-- | :-- |
| Read schedule | Allowed after account binding. |
| Suggest event | Allowed. |
| Create/update/delete event | Requires confirmation unless policy grants scoped permission. |
| Extract dates from email | Requires email ingest gate and operator confirmation. |

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
