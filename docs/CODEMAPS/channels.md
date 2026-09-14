# Channels Codemap — Adapters

**Last Updated:** 2026-09-13
**Entry Points:** `SRC/neothd/src/channels/mod.rs`, `SRC/neothd/src/cli/serve_tasks.rs`

## Account-bound inbound state

`serve_tasks` constructs one `AuthenticatedInboundBinding` per authenticated
adapter. Current singleton adapters use `ChannelRef::default_account`; the
payload never chooses an account. `serve_pipeline` rejects a mismatched
channel before I/O and resolves the human identity through the V39 v2 alias
table. Only the startup-owned opaque Telegram admission token can enable the
exact legacy operator claim. V1 aliases remain account-unbound history.

`channels/identity.rs` owns v2 lookup, atomic creation/claim, and atomic explicit
merge. Claim UUID/time remain historical facts across a merge.
`channels/rate_limit.rs` keys buckets by `(ChannelRef, sender)`.
`permissions/lease.rs::channel_lease_subject` is shared by inbound ChannelSend,
MCP authorization, and `neoth lease channel-subject`. Pipeline session, profile,
archive and media identifiers incorporate the bound account.

Telegram now has a limited P1-16 account-map setup: policy maps hold an explicit
`allowed_user_id`, credentials maps hold a matching token or a null
keychain-backed placeholder, and legacy scalar fields cannot coexist with a
map. W21 adds/replaces one explicitly named Telegram map account through
`channel account add telegram --account <id>` or strict account-bearing private
stdin. It probes the exact candidate before a paired file/keychain commit and
uses a CAS retry boundary; acknowledgement is secret-free. W22 exposes Add
account for a valid map and the exact fresh Telegram state beside explicit
legacy Configure, with per-account Edit and exact Test. Invalid maps remain
CLI-repair-only; the GUI does not silently migrate them.

Account removal/retirement, other account families, and remaining
account-aware routing remain open. Native GUI acceptance and macOS CI remain
separate.

## Mapped Telegram DM pairing (W29; locally validated)

`cli/mod.rs` dispatches account-scoped `channel account set-dm-pairing telegram
--account <id> --enabled` plus `channel pairing list|approve|dismiss telegram
--account <id>`; approval requires `--code` and dismissal `--request-id`.
`cli/channel.rs` resolves the exact account and binding before opening
`channels/dm_pairing.rs::DmPairingStore`.

The store owns a private bound-directory capability and SQLite access. Pending
rows are keyed by `ChannelRef` and binding tag, hold no pairing code, expire
after one hour, and are limited to three. `channels/telegram.rs` admits the
pairing branch only for private, non-pinned DMs; pinned operator groups and the
existing `ConfirmBus` branch retain their prior behavior. Edited Telegram
messages cannot create or refresh pending rows. A changed account binding invalidates only its own
requests, and missing authenticated mapped receipts remain ingress failures
before pipeline execution. The local selection, Clippy, build,
AccountConfigContracts, formatting, CLI doc generation, final GUI check, and
integrity checks passed. This is not a pairing-migration or live-provider
acceptance.

## W32 account retirement identity (validation pending)

`channel account remove telegram --account <id>` retires exactly one mapped
account through the paired prepared journal and dynamic-key CAS/rollback
boundary. A same-name re-add receives a fresh internal UUID. Lease subjects,
ingress permits, pairing state, v5 queue/claims/WAL/evidence, and fresh egress
binding consume that identity. Historical no-UUID records are compatible only
against exact current historical state, never as authority for a replacement.
P1-16 remains open.

## W30 SelfStage staging boundary (enablement pending)

The admitted owned-helper foundation carries ordered receipt outcomes for the
opt-in SelfStage staging lane. `neoth update --self --apply` is the manual
binary-swap path; SelfStageAllowed and self-probe do not authorize CLI, npm,
Git, OSV, installer, or Skill lanes. Runtime execution remains pending the
enabled production outer/helper-route proof. R3-18B remains open.

## W34 legacy factory provenance (validation pending)

Only legacy Telegram and Slack factories receive sealed startup provenance;
mapped Telegram remains a separate variant. P1-17 remains open for all other
channel provenance surfaces.

## OpenClaw account import (W26; locally validated)

The new importer selects exactly one OpenClaw source account through `--config`
and `--source-account`, then writes one explicit Telegram target via `--account`
and `--telegram-user-id`. The token stays in memory, the target candidate is
probed before commit, and a source-set recheck precedes the existing prepared
CAS commit. `raw_json` shared custody yields canonical redacted migration
reports. Manual publish/release code consumes that crate without publishing a
registry artifact. Local validation covers final selection, Compound Clippy,
AccountConfigContracts, custody, formatting, and Python checks. It does not
claim a full OpenClaw configuration or transcript migration, pairing migration,
a physical provider live import, or registry publication.

`cli/channel.rs` performs `neoth channel migrate-legacy telegram --account
<account-id>` as a paired migration with recovery cleanup. It does not expose
secret material. When a map is active, legacy flat Telegram add/remove/
set-credentials mutations fail before writing. `serve.rs` and `serve_tasks.rs`
fingerprint and reconcile Telegram by `ChannelRef`, restarting only an affected
account adapter. Inbound replies stay with the owning adapter. Flat proactive
Telegram and Cron announcement paths refuse mapped configuration; this does
not provide complete account-aware outbound routing.

## Account-bound proactive Telegram routing

`cli/proactive.rs` accepts `proactive route --default --channel telegram
--account <account-id>` for an
explicit mapped Telegram route. `channels/routing.rs` carries the selected
channel and typed account from the same route branch; `proactive::ProactiveItem`
serializes its optional account binding without changing historical JSON when it
is absent. Cron and other producers persist the selection. The dispatcher treats
a stored binding as authoritative instead of resolving a changed route default.

For an account-bound physical attempt, `daemon/proactive_egress.rs` holds
`DeliveryLock`, reloads the current coherent `RuntimeConfigPair`, checks the
accepted public configuration and exact stored account, then derives the adapter
and recipient only from the fresh authenticated bundle. The recipient is
`bundle.allowed_user_id`; routing destinations and queued content cannot affect
that choice. A completed credential update before pair admission applies; this
does not claim cancellation after admission.

New account-bound durable claims, intent/result WAL data, and projections use a
v4 domain-separated `ChannelRef` binding. v1-v3 claims/frames/records and old
queue bytes remain compatible. A map-active bad or missing stored ref settles
without a send and cannot bind A work to B. A historical unbound Telegram item
continues through the legacy flat path only while the effective map is empty.
This Telegram-only slice does not establish full multi-account readiness.

## Account transport evidence and Doctor flapping

W20 carries opaque bound metadata only from a validated nonlegacy
`TelegramAccountBundle`, through the private inbound/live-delivery path to its
intent. `daemon/channel_transport_evidence.rs` then combines that bound-live
metadata with the existing strict v4 proactive decoder in **one** complete
authenticated home-WAL scan. Generic/default bindings, legacy Telegram, other
channels, webhooks, probes, outboxes, provider events, and runtime health cannot
manufacture an account transport observation.

The reader validates intent/result relationships before applying its 24-hour
window and returns an error rather than partial counters for an incomplete,
unavailable, malformed, replaced, or unauthenticated prefix. Bound `ChannelRef`
values are historical WAL evidence and are not rebound from current config,
credentials, tags, or routing. It reports accepted adapter receipts, typed
failures, unknown-after-armed, unsettled live intent, or not-attempted states;
it never asserts remote or human receipt.

`cli/doctor/checks/providers.rs` consumes this one reader for account-isolated
transport flapping. The initial threshold is at least five completed attempts
and at least 20% failures. Unknown/unsettled counts warn but are excluded from
the completed failure rate; no observations passes, and a reader error fails as
unavailable without per-account partial details. This adds no new authorization,
route, credential, retry, or delivery behavior.

W20 has nine admitted source files, formatting and TestBuild01 pass, and four
real authenticated-WAL tests pass. An initial selected run found a real legacy
JSON byte-order regression; the repaired writer restores the former `json!`
value plus optional-reference shape, preserving the raw-byte assertion. Doctor's
all-check documentation list has 60 entries, while `run_all_checks` returns 59
runtime outcomes. The admitted mapped live-auth repair uses the existing opaque
capability gates and `append_authenticated` path: `CHANNEL_SEND` precedes its
terminal marker for both success and failure, while unbound payload/order stays
unchanged. TestBuild02 **PASS** (4m07s; 183.27 GiB minimum free; 11.07 GiB
peak), Selected02 **394/0/0** before this repair, Python 19+11+8, and Clippy03
**PASS** are intermediate evidence. Final TestBuild03 **PASS** (3m49s; 202.66
GiB minimum free; 10.65 GiB peak), final selected **397/0/0** (catalogue
14,389), 13 integration targets **157/0/0**, and formatting/GUI lint/self-test
pass. The slice is locally verified and published at
`080131b4320ac3935d1f5d05e242295e5c3625a8`. No current-head full-CI or cross-platform acceptance is
claimed; see
[the provisional receipt](../gold-wave20-verification.md).

## Account readiness and live-instance projection

`cli/channel.rs::run_list` derives Telegram account children from the coherent
authenticated config/credential pair. They are secret-free static readiness
records: a valid map produces one `ChannelRef` child with an `ok` configured
state, while partial or mismatched maps fail rather than inventing usable rows.

`neoth channel test telegram --account <account-id>` selects exactly one mapped
bundle and runs the existing read-only Telegram validator. An active map requires
the flag and never infers `default`; an unknown account fails before probing.
`--account` is rejected for non-Telegram channels and for legacy scalar Telegram,
which keeps its existing no-account test path.

`daemon/channel_runtime_health.rs` adds a private bounded runtime projection for
the same `ChannelRef` children. `serve.rs` publishes it from the owned fleet;
the list reader merges it only after the exact binding tags, current home, and
authenticated live daemon-instance proof match. It can report `running`,
`configured_not_started`, `failed`, `inactive`, or `credentials_invalid`.
Missing, stale, unreadable, mismatched, or unproven data is **unknown** rather
than a negative readiness result: table output says unknown and JSON omits the
optional runtime field. The projection is observation only, never authority or
credential material.

This Wave 17 slice is reviewed and locally verified by focused unit and
integration checks; see [the receipt](../gold-wave17-verification.md).
Cross-platform CI and live Telegram acceptance remain separate.

## Settings and Connect account views

The W18-19 GUI surface routes the canonical account-status projection through
`panel_logic.rs`, `main.rs`, `settings.slint`, and `main.slint`. **Settings →
Channels** renders nested Telegram account rows with static configured state and
an optional read-only runtime field; it has no account-creation, pairing, or
migration UI. Its selected-account test parses the core result only when the
returned account exactly matches the selected row, so an `ops_a` result cannot
be presented as `ops_b`.

`cli/connect.rs` consumes the same canonical list projection. `neoth connect
telegram --account ops_b` shows one exact configured account and directs the
operator to the corresponding read-only channel test. A map overview enumerates
accounts but does not infer `default`. An active invalid/partial map becomes a
repair-only state with no usable or testable account; legacy no-map Telegram
keeps its compatible no-account detail path.

This compound slice is independently reviewed and locally verified: GUI
test-source check, 175 core and 350 actual GUI parser/action tests, final Clippy,
formatting and GUI lint pass. Native rendering and live delivery remain
separate. Exact evidence is recorded in
[`gold-wave18-19-verification.md`](../gold-wave18-19-verification.md).

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
