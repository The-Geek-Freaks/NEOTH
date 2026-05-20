# Channels

Neoth connects to messaging apps via channel adapters. Each adapter requires a token and
an allowlist of users who can interact with the bot.

| Channel  | Status (as of 2026-05-19) | Transport |
|----------|---------------------------|-----------|
| Telegram | operational, v0.1+        | long-poll (no public HTTPS needed) |
| WhatsApp | operational, v0.2+        | Meta Business Cloud webhook |
| Slack    | operational, v0.3+        | Socket Mode WebSocket |
| Discord  | operational (DM), v0.3+   | Gateway WebSocket |
| Keet     | preview, v0.3+            | Pears bridge (operator-pinned Path-3) |

Per-channel formatter dialects (Telegram MarkdownV2, Slack mrkdwn, Discord CommonMark,
WhatsApp basic, Keet plaintext) are handled by `channels::formatter`. The formatter
auto-splits long replies into numbered `[N/M]` continuation messages.

---

## Telegram

### Step 1 — Create the bot

1. Open Telegram and search for `@BotFather`
2. Send: `/newbot`
3. Give it a display name and a username ending in `bot`
4. BotFather sends a token: `123456789:ABC-DEF1234ghIkl...`

### Step 2 — Set the token

```
export TELEGRAM_BOT_TOKEN="123456789:ABC-DEF1234ghIkl..."
```

Add to your shell profile (`~/.bashrc` or `~/.zshrc`) to persist across reboots.

### Step 3 — Find your numeric user ID

Forward any message to `@userinfobot` in Telegram. It replies with your numeric ID, e.g. `987654321`.

**Important:** Neoth uses numeric IDs in the allowlist, not usernames. Usernames change; numeric
IDs do not.

### Step 4 — Add yourself to the allowlist

In `~/.neoth/policy.yaml`:

```yaml
channels:
  telegram:
    allowed_chat_ids: [987654321]    # your numeric ID
    require_dm: true                 # in groups: bot must be mentioned
```

### Step 5 — Start

```
neoth start
```

Send a message to your bot. It should reply.

### Telegram notes

- Messages longer than 4096 characters are split into continuation messages automatically.
- Streaming: Neoth sends a message, then edits it as the response generates. You see it
  appear incrementally.
- Only one Neoth instance can poll a bot token at a time. Starting a second instance fails
  with a clear error. See [troubleshooting.md#telegram-webhook-conflict](troubleshooting.md#telegram-webhook-conflict).

### Telegram attachment handling

Neoth downloads and processes photo, voice, and audio attachments inline. Documents are
deferred (require mime/extension detection routing before they land in the media pipeline).

| Telegram message type | What Neoth does |
|-----------------------|----------------|
| Photo | Downloads the largest resolution variant. JPEG. Routes through the vision extractor. CLIP embedding computed if the model is cached. |
| Voice | Downloads the OGG file. Routes through the audio extractor. Whisper transcription if the model is cached. |
| Audio | Downloads the file (any format). Routes through the audio extractor. Whisper transcription if the model is cached. |
| Text | Processed directly. No extractor. |
| Sticker / location / poll / service | Acknowledged with an unsupported-kind notice. No processing. |

Hard ceiling: attachments larger than 16 MiB are rejected before download when Telegram
reports the size in the metadata response; a post-download check enforces the ceiling for
files where the API omits the size field.

Captions on photo/audio messages are extracted alongside the media and passed to the LLM as
the text component of the inbound message.

---

## WhatsApp

Uses the Meta WhatsApp Business Cloud API — the official, TOS-compliant path. No personal
number hacks, no browser automation.

**Status:** operational since v0.2. The webhook receiver
(`channels::whatsapp_webhook`) verifies signatures, decodes the Cloud-API payload, and
hands inbound messages into the normal pipeline. The send path uses `whatsapp_api` against
graph.facebook.com.

**Warning:** Meta's approval process for WhatsApp Business accounts can take anywhere from
2 days to several weeks. Start the approval process early, before you need it.

### Credential fields (`credentials.yaml`)

| Field | Description |
|-------|-------------|
| `whatsapp_access_token` | Meta Cloud API long-lived system-user access token (`EAAxxxx…`). |
| `whatsapp_phone_number_id` | Numeric phone-number id from the Meta Business console. |
| `whatsapp_verify_token` | Arbitrary secret string used during the webhook handshake. |

### Prerequisites

- A Meta Business Manager account (business.facebook.com)
- A dedicated phone number for the bot (cannot be in use on personal WhatsApp)
- A publicly reachable HTTPS URL for webhook callbacks (your server needs a valid TLS cert)

### Setup steps

1. In Meta Business Manager: add your phone number, set up a WhatsApp Business app
2. Get a permanent System User token and your Phone Number ID
3. Add to `credentials.yaml`:

```yaml
whatsapp_access_token: "EAAxxxxx..."
whatsapp_phone_number_id: "123456789012345"
whatsapp_verify_token: "your-verify-secret"
```

4. Configure the webhook URL in Meta's dashboard to point to your Neoth
   instance (`https://<your-host>/webhook/whatsapp`). The `verify_token` you set above
   must match Meta's verification handshake.

### WhatsApp notes

- No message editing. WhatsApp Business API has no edit endpoint. Neoth sends the
  complete final response as one message instead of streaming edits.
- If Meta approval is delayed, Telegram is a fully functional alternative.
- Webhook transport: hyper-based HTTPS receiver inside the daemon (`A7 webhook_listener`).
  TLS via rustls or fronted by Caddy/nginx at the operator's choice.

---

## Slack

Uses Slack's Socket Mode — no public HTTPS endpoint required.

**Status:** operational since v0.3. The full receive→dispatch→send loop ships:
`channels::slack_socket` dials the WSS endpoint Slack hands back from
`apps.connections.open`, ACKs per frame, and routes events through `slack_events` into the
inbound dispatcher. The send path uses `slack_api::chat_post_message` and threads the
operator's reply back into the same conversation via the `OutboundSender` callback.

### Credential fields (`credentials.yaml`)

| Field | Description |
|-------|-------------|
| `slack_bot_token` | `xoxb-…` bot user OAuth token. Scopes: `channels:history`, `chat:write`, `im:history`, `im:write`, `users:read`. |
| `slack_app_token` | `xapp-…` app-level token with `connections:write` scope. Required for socket mode. |

### Prerequisites

A Slack workspace where you have admin or app-creation rights.

### Setup steps

1. Go to api.slack.com/apps and create a new app
2. Under "OAuth and Permissions": add bot token scopes:
   `channels:history`, `chat:write`, `im:history`, `im:write`, `users:read`
3. Install the app to your workspace; copy the Bot Token (`xoxb-…`)
4. Under "Socket Mode": enable Socket Mode, create an app-level token with `connections:write` scope; copy the App Token (`xapp-…`)
5. Under "Event Subscriptions": enable and subscribe to `message.im`, `message.channels`
6. Add to `credentials.yaml`:

```yaml
slack_bot_token: "xoxb-..."
slack_app_token: "xapp-..."
```

7. `neoth start` opens the socket-mode WebSocket automatically.

### Slack notes

- Transport: tokio-tungstenite socket-mode WebSocket client; Slack `events_api` JSON
  envelopes decoded into `InboundMessage` and ACKed per-frame.
- Streaming via `chat.update`: Neoth posts a message, then edits it per token batch as
  the response generates.

---

## Discord

Uses Discord's Gateway WebSocket. No public HTTPS endpoint required.

**Status:** operational since v0.3 for DMs. The send path is fully wired; the receive
loop handles direct-messages today and tags `MESSAGE_CREATE` events from guild channels
explicitly as v0.3+ scope (regression-tested in `channels::discord`).

### Credential fields (`credentials.yaml`)

| Field | Description |
|-------|-------------|
| `discord_bot_token` | Bot token from `discord.com/developers/applications` (no prefix). |

### Setup steps

1. Open `discord.com/developers/applications` and create a new application
2. Under "Bot": create a bot user, copy the token
3. Under "Privileged Gateway Intents": enable **Message Content Intent**
4. Add to `credentials.yaml`:

```yaml
discord_bot_token: "MTxxx..."
```

5. Invite the bot to a DM by visiting the OAuth2 URL Generator → `bot` scope → DM permissions
6. `neoth start` opens the Gateway WS automatically.

### Discord notes

- Formatter dialect: CommonMark-ish (`**bold**`, `*italic*`, fenced code, blockquotes).
  2000-char message cap, auto-split via `channels::formatter`.
- Heartbeat + sequence-resume already wired so transient disconnects don't lose state.
- Guild-channel receive is the next iteration; today's DM-only scope keeps the consent
  surface narrow.

---

## Keet (preview)

Uses a local bridge to the Pears chat surface (Keet.io). Operator-pinned Path-3 (HTTP
bridge) rather than the heavier native Pears stack.

**Status:** preview since v0.3. Outbound send works; inbound receive lives behind the
SP-5 channel-API expansion (richer `InboundMessage` + `send_text/send_media`). Full
two-way operation lands once a second production adapter motivates the SP-5 A-expansion.

### Keet notes

- Formatter dialect: plaintext (Pears chat does no markdown rendering). Code fences pass
  through as literal text but stay copy-paste friendly. Conservative 2000-char cap.

---

## Future channels (planned)

These are on the roadmap but have no timeline commitment:

| Channel | Status |
|---------|--------|
| Signal | Phase 3+ — planned (requires Signal Desktop) |
| Matrix | Phase 3+ — planned |
| iMessage | Phase 4 — Apple restricts automation; macOS only |
| LINE | Phase 3+ — planned |

---

## Cross-channel identity

If you use Neoth on both Telegram and Slack, you have two separate identities by default.
Neoth will not auto-merge them (different accounts could be different people).

To explicitly link your Telegram and Slack identities:

```
neoth identity merge <telegram-uuid> <slack-uuid>
```

Find your UUIDs:

```
neoth identity list
```

After a merge, recall queries cover your full conversation history regardless of which
channel you used. See [cli-reference.md](cli-reference.md#identity) for full merge options.
