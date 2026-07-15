# Channels Codemap — Adapters

**Last Updated:** 2026-07-14
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

`allowed_user_id: None` = open to anyone (not for production). The v1 contract is
single-operator: `Some(id)` pins one numeric Telegram identity, including in groups. A
multi-user bot is outside that trust model rather than an unwired v1 promise.

### run() flow

1. `bot.get_me()` — verify token before entering the poll loop
2. `teloxide::Dispatcher` long-polling loop with message + edited-message branches
3. Per message: allowlist check FIRST → `download_attachment_if_any` → assemble
   `InboundMessage` → call handler → send reply (MarkdownV2 with plain-text fallback)

### Attachment download

`download_attachment_if_any` dispatches on Telegram message type:

| Telegram type | MediaKind | MIME |
|--------------|-----------|------|
| `photo` | `Image` | `image/jpeg` (Telegram always converts) |
| `voice` | `Audio` | from API or `audio/ogg` |
| `audio` | `Audio` | from API or `audio/mpeg` |
| `video` | `Video` | from API or `video/mp4` |
| `document` | `Document` | from API or `application/octet-stream` |
| `sticker` | `Sticker` | `image/webp`, `application/x-tgsticker`, or `video/webm` |

Pre-download size gate: reject before download if API reports size > 16 MiB.
Post-download gate: reject if downloaded bytes > 16 MiB (covers API that omits size).

### send_text

MarkdownV2 parse mode; falls back to plain only on Telegram's explicit
`CantParseEntities` rejection. Short, explicit flood-control responses are retried once;
ambiguous network failures are never blindly retried because that could duplicate a send.

### send_media

Native Bot API mapping is live for image, video, audio, document, and sticker payloads.
Uploads are preflighted for non-empty bytes, kind-specific MIME allowlists, safe filenames,
and a 16 MiB project ceiling (10 MiB photos, 512 KiB stickers). Captions up to 1024
characters ride with supported media; longer captions and all sticker captions are split
through the Telegram formatter and sent after the attachment. Post-upload caption failures
are logged but do not turn the successful attachment into a retryable error. Telegram
`RetryAfter <= 5s` is honored once; longer waits surface as `ChannelError::RateLimited`.
Transport errors redact the bot token before entering logs.

## channels/whatsapp.rs

**Status:** Live outbound through the Meta Graph API; live inbound through the
daemon-owned shared webhook listener.

### Constructor

```rust
WhatsAppChannel::new(
    access_token: SecretString,      // credentials.yaml: whatsapp_access_token
    phone_number_id: String,         // credentials.yaml: whatsapp_phone_number_id
    verify_token: SecretString,      // credentials.yaml: whatsapp_verify_token
)
```

### Live paths

- `send_text` calls the versioned `/messages` Graph API and returns the Meta
  `wamid`; proactive sends delegate to the same implementation.
- `Channel::run()` is intentionally not the receive entry point because Meta
  pushes webhooks. `cli/serve_tasks.rs::spawn_channel_adapters` starts
  `channels/webhook_listener.rs` when the access token, phone id, verify token,
  app secret, and provider are available.
- The listener binds to `127.0.0.1:<whatsapp_webhook_port>` (default `8443`).
  The operator supplies the public HTTPS reverse proxy or tunnel.
- GET verification checks the configured verify token. POST delivery verifies
  the Meta app-secret signature, deduplicates `wamid` redeliveries, decodes the
  payload, dispatches the pipeline, and routes governed replies through the
  Graph API. In-flight webhook work is tracked and drained during shutdown.
- With only send credentials, `neoth serve` reports `OUTBOUND-ONLY` instead of
  pretending the inbound listener started.

## channels/slack.rs

**Status:** Fully operational through Slack Socket Mode plus Web API sends.

### Constructor

```rust
SlackChannel::new(
    bot_token: SecretString,         // credentials.yaml: slack_bot_token  (xoxb-...)
    app_token: SecretString,         // credentials.yaml: slack_app_token  (xapp-...)
)
```

### Live paths

1. `run()` calls `apps.connections.open` with the `xapp-` token.
2. `slack_socket::run_socket_loop` connects to the returned WSS URL, ACKs every
   envelope, decodes `events_api` messages, and dispatches them to the pipeline.
3. Replies and proactive messages use `chat.postMessage` with the `xoxb-` token.
4. Streaming previews use `chat.update`; Slack reports message-edit support to
   `LiveDelivery` so API failures surface instead of silently degrading.

## channels/discord.rs

**Status:** Live Gateway receive, REST send, and read-only credential probe.

### Live paths

- `run()` owns the authenticated Gateway WebSocket loop: heartbeat, resume
  sequence, reconnect backoff, intents, `MESSAGE_CREATE` decode, pipeline
  dispatch, and REST reply.
- `send_text` posts to Discord API v10 and chunks content at Discord's
  2,000-character limit. Proactive sends delegate to the same path.
- `validate_bot` performs `GET /users/@me` without sending a message. This is
  the path behind `neoth channel test discord`; it returns the immutable bot
  snowflake and display identity and fails closed on auth/protocol errors.
- Redirects are disabled for authenticated REST calls, responses are bounded,
  and rate-limit responses surface as `ChannelError::RateLimited`.

## channels/keet.rs + channels/keet_bridge.rs

**Status:** Repository-owned full-duplex text channel through a local,
authenticated companion.

- `keet_bridge.rs` is the bounded HTTP client. It pins protocol version 1,
  requires `send_text` and `receive_text`, rejects redirects, authenticates
  every request, verifies the configured joined topic, sends with durable
  idempotency keys, and long-polls monotonic cursors.
- `keet.rs` implements the canonical `Channel` path. Startup first reads the
  current high-water cursor, then polls forward; verified sender IDs must match
  the exact configured allowlist before entering `PipelineHandler`.
- `cli/serve_tasks.rs::spawn_channel_adapters` starts the adapter only when URL,
  bearer token, topic, non-empty sender allowlist, and provider are complete.
  Partial state is surfaced as `CONFIGURED-NOT-STARTED`.
- `bridges/keet/` owns the Bare standalone and Pear/Hyperswarm peer protocol.
  Release/CI freeze its pnpm graph, tests and standalone build.
- Product boundary: topics are NEOTH-owned Keet-identity conversations. The
  adapter does not read or write existing Keet desktop/mobile rooms because no
  supported public room/message API exists.

## ChannelError Variants

| Variant | When |
|---------|------|
| `NotSupported { feature }` | Default impl for unimplemented `send_text` / `send_media` |
| `Transport(String)` | Network or API error during send |
| `Parse(String)` | Response decode failure |

## Readiness and credential reconciliation

- `channels/readiness.rs` owns the shared 10-second, no-redirect, bounded-body
  primitives plus Twitch OAuth validation. Adapter modules expose their own
  protocol-specific read-only probe so CLI and GUI consume the same semantics.
- `cli/channel.rs::test_channel_at` routes every canonical registry entry. IRC
  and Matrix password-only auth return typed `unavailable` rather than faking a
  TCP/auth success with a stateful connection.
- `cli/serve_tasks.rs::channel_credential_fingerprints` hashes each channel's
  effective file/keychain inputs independently, including in-place Google Chat
  service-account key rotation. Raw serialized secret bytes are zeroized after
  hashing.
- `cli/serve.rs` polls and debounces credential generations. It aborts and
  drains the old task before starting only the changed adapter; a corrupt
  effective credential store stops the whole fleet fail-closed. Finished tasks
  remain unhealthy until a credential change or explicit reload retries them,
  avoiding duplicate pollers and restart storms.

## Related Areas

- `cli/serve.rs::handle_media_attachment` — calls `route_to_first_match` for channel-attached media
- `channels/rate_limit.rs` — per-channel rate limiting (shared across all adapters)
- `bridges/keet/` — repository-owned standalone, durable journal, identity and authenticated peer transport.
- `config/credentials.rs` — credential field names referenced by the adapters
