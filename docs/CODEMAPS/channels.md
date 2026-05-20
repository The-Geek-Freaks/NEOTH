# Channels Codemap — Adapters

**Last Updated:** 2026-05-15
**Entry Points:** `SRC/neothd/src/channels/mod.rs`

## Architecture

```
Channel trait
  fn name() -> &'static str
  async fn run(handler: PipelineHandler) -> Result<()>
  async fn send_text(chat_id, text) -> Result<MessageId, ChannelError>
  async fn send_media(chat_id, media, caption) -> Result<MessageId, ChannelError>

PipelineHandler = Box<dyn Fn(InboundMessage) -> BoxFuture<Result<Option<OutboundMessage>>>>

InboundMessage {
  channel: ChannelKind,
  chat_id: String,
  thread_id: Option<String>,
  sender_id: String,
  sender_display: Option<String>,
  text: Option<String>,
  media: Option<MediaPayload>,
  reply_to: Option<String>,
  mention_kind: Option<MentionKind>,
  channel_ts_unix: u64,
  raw_ts_ms: Option<i64>,
}

MediaPayload { kind: MediaKind, mime: String, filename: Option<String>, data: Vec<u8> }
```

## channels/telegram.rs

**Status:** Fully operational.

### Constructor

```rust
TelegramChannel::new(token: SecretString, allowed_user_id: Option<u64>)
```

`allowed_user_id: None` = open to anyone (not for production). Single-user allowlist only
in v0.1.x; multi-user allowlist is a TODO.

### run() flow

1. `bot.get_me()` — verify token before entering the poll loop
2. `teloxide::repl` long-polling loop
3. Per message: allowlist check FIRST → `download_attachment_if_any` → assemble
   `InboundMessage` → call handler → send reply (MarkdownV2 with plain-text fallback)

### Attachment download

`download_attachment_if_any` dispatches on Telegram message type:

| Telegram type | MediaKind | MIME |
|--------------|-----------|------|
| `photo` | `Image` | `image/jpeg` (Telegram always converts) |
| `voice` | `Audio` | from API or `audio/ogg` |
| `audio` | `Audio` | from API or `audio/mpeg` |

Pre-download size gate: reject before download if API reports size > 16 MiB.
Post-download gate: reject if downloaded bytes > 16 MiB (covers API that omits size).

Documents deferred — need mime/extension routing before media pipeline ingestion.

### send_text

MarkdownV2 parse mode; falls back to plain on parse error (teloxide returns an error for
malformed Markdown without sending).

### send_media

`NotSupported { feature: "telegram.send_media" }` — not wired in v0.1.x.

## channels/whatsapp.rs

**Status:** Credential surface only. `run()` bails immediately.

### Constructor

```rust
WhatsAppChannel::new(
    access_token: SecretString,      // credentials.yaml: whatsapp_access_token
    phone_number_id: String,         // credentials.yaml: whatsapp_phone_number_id
    verify_token: SecretString,      // credentials.yaml: whatsapp_verify_token
)
```

### run() error

```
"whatsapp channel: webhook receiver deferred to Phase 2 — needs an HTTPS endpoint
 operator-side. Credentials accepted + serialised so the next release can wire the
 receiver without re-pairing. Use Telegram or CLI for v0.1.x."
```

### Phase 2 plan

hyper HTTPS webhook receiver; `POST /webhook` verifies Meta's `hub.verify_token`;
`/messages` Graph API for `send_text`; TLS via rustls or fronted by Caddy/nginx.

## channels/slack.rs

**Status:** Credential surface only. `run()` bails immediately.

### Constructor

```rust
SlackChannel::new(
    bot_token: SecretString,         // credentials.yaml: slack_bot_token  (xoxb-...)
    app_token: SecretString,         // credentials.yaml: slack_app_token  (xapp-...)
)
```

### run() error

```
"slack channel: socket-mode WebSocket client deferred to Phase 2. Credentials are
 accepted + serialised so a future release wires the receiver without re-creating the
 Slack app. Use Telegram or CLI for v0.1.x."
```

### Phase 2 plan

tokio-tungstenite socket-mode WebSocket; `apps.connections.open` for the WSS URL;
events_api JSON envelope decode; `chat.postMessage` / `chat.update` for streaming replies.

## ChannelError Variants

| Variant | When |
|---------|------|
| `NotSupported { feature }` | Default impl for unimplemented `send_text` / `send_media` |
| `Transport(String)` | Network or API error during send |
| `Parse(String)` | Response decode failure |

## Related Areas

- `cli/serve.rs::handle_media_attachment` — calls `route_to_first_match` for channel-attached media
- `channels/rate_limit.rs` — per-channel rate limiting (shared across all adapters)
- `channels/keet.rs` — Keet.io scaffold (separate from WhatsApp/Slack — P2P messenger)
- `config/credentials.rs` — credential field names referenced by all three adapters
