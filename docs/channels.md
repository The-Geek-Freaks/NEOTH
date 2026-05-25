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

## Telegram

### Setup

1. Open Telegram and search for `@BotFather`.
2. Send `/newbot`.
3. Choose a display name and bot username.
4. Copy the token.
5. Run:

```bash
neoth channel setup telegram
neoth serve
```

Manual environment path:

```bash
export TELEGRAM_BOT_TOKEN="123456789:ABC-DEF..."
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
neoth channel setup whatsapp
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
neoth channel setup slack
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

```bash
neoth channel setup discord
neoth serve
```

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
neoth channel setup keet
neoth serve
```

Keet is useful when the operator wants less platform gravity and more private mesh behavior.

## Email

Email is treated as a sensitive channel because it contains other people's text, attachments, tracking links, and prompt-injection bait.

```bash
neoth channel setup email
```

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

```bash
neoth channel setup calendar
```

Default behavior:

| Action | Default |
| :-- | :-- |
| Read schedule | Allowed after account binding. |
| Suggest event | Allowed. |
| Create/update/delete event | Requires confirmation unless policy grants scoped permission. |
| Extract dates from email | Requires email ingest gate and operator confirmation. |

## Cross-channel identity

NEOTH does not silently merge identities. If you talk to it from Telegram and Slack, those can stay separate until you link them.

```bash
neoth identity list
neoth identity merge <telegram-uuid> <slack-uuid>
```

After a merge, recall and profile can follow the same operator across surfaces.

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
neoth channel doctor
neoth serve
neoth privacy audit --last 1h
```
