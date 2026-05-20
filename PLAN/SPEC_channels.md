# NEOTH v0.6 -- Channel-Adapter Architecture Spec

> Status: Draft v1, amended 2026-05-14 with SP-5 C-prime decision (see below).
> Extends 00_DESIGN_v0.5_FINAL.md. Framework v4.1 compliant.
> Phase 1: WhatsApp Business Cloud API + Slack Socket Mode + Telegram Bot API.
> Phase 2: Discord, Signal, iMessage, LINE, Matrix.

## 2026-05-14 Amendment — SP-5 C-prime

Chorus 2-reviewer verdict (codex + gemini) picked Option C-prime from
`PLAN/chorus_sp5_artifact.md`. The Channel trait at v0.1.x ships in the
shape below; the richer surface in §1 is the **target state** for the
phase-A expansion triggered by the second production adapter.

### WAL band correction

The events `0x24..=0x27` listed in §6 conflict with the locked PROVIDER band
(`0x20..=0x2F`). Authoritative range table lives in `wal/events.rs`. Use the
CHANNEL band (`0x30..=0x3F`):

| Code | Name | Replaces |
|------|------|----------|
| `0x32` | `CHANNEL_INBOUND` (alias `CHANNEL_INGRESS`) | spec `0x24` |
| `0x33` | `CHANNEL_OUTBOUND` (alias `CHANNEL_EGRESS`) | spec `0x25` |
| `0x34` | `CHANNEL_ERROR` | (additive — new) |
| `0x35` | `INGRESS_QUARANTINED` | (Phase 11a S-4 — keep) |
| `0x36` | `INGRESS_SANITIZED` | (Phase 11a S-4 — keep) |
| `0x37` | `CHANNEL_ACK` | spec `0x26` |
| `0x38` | `CHANNEL_EDIT` | spec `0x27` |

### Trait shape at v0.1.x

Shipped: `name()`, `run(handler)`, `send_text`, `send_media`.
Deferred until the second production adapter ships: `spawn_receive_loop`,
`ack_received`, `get_chat_meta`, `send_action_indicator`, `edit_message`,
`send_proactive`, the `LiveDelivery` struct, and the cross-channel identity
view `idx_human_identity` (UUID v7 not introduced at v0.1.x).

### InboundMessage shape at v0.1.x

Adopted from §1 with two carve-outs:
- `human_uuid` is omitted — cross-channel identity stays deferred.
- `sender_id` remains a plain string instead of being resolved through the
  WAL identity view.

---

## Amendment 2026-05-14 (SP-5 Chorus C-prime)

The WAL event codes originally drafted at `0x24-0x27` collided with the locked
PROVIDER band `0x20-0x2F` (see `wal/events.rs` range-allocation table).
Superseded:

| Old (invalid)        | New (locked in code)         |
|----------------------|------------------------------|
| `0x24 CHANNEL_INBOUND`  | `0x32 CHANNEL_INGRESS` *(kept; alias new name)* |
| `0x25 CHANNEL_OUTBOUND` | `0x33 CHANNEL_EGRESS`           |
| `0x26 CHANNEL_ACK`      | `0x37 CHANNEL_ACK`              |
| `0x27 CHANNEL_EDIT`     | `0x38 CHANNEL_EDIT`             |

The trait surface in §1 is **aspirational** for the multi-adapter target
phase. v0.1.x ships with `name() + run(handler) + send_text + send_media`
only; `ack_received`, `edit_message`, `get_chat_meta`,
`send_action_indicator`, and `send_proactive` plus the `LiveDelivery` struct
and the `idx_human_identity` view stay deferred until the **second
production adapter** lands a feature that needs them. Trigger captured in
`memory/neoth-sp5-channel-api.md`.

---

## 1. Rust Channel Trait

All channel adapters implement this trait. No adapter may embed Schicht-1 logic (Anti-Pattern G.12).

```rust
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)] pub struct MessageId(pub String);

#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub human_uuid:    uuid::Uuid,
    pub channel:       ChannelKind,
    pub chat_id:       String,
    pub thread_id:     Option<String>,
    pub text:          Option<String>,
    pub media:         Option<MediaPayload>,
    pub reply_to:      Option<MessageId>,
    pub mention_kind:  Option<MentionKind>,
    pub raw_ts:        i64,
}

#[derive(Debug, Clone)]
pub struct MediaPayload { pub kind: MediaKind, pub data: bytes::Bytes, pub mime: String, pub filename: Option<String> }
#[derive(Debug, Clone)]
pub struct ChatMeta { pub chat_id: String, pub title: Option<String>, pub is_group: bool, pub member_ids: Vec<String> }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAction { Typing, UploadingMedia }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind { Telegram, WhatsAppBusiness, WhatsAppBaileys, Slack }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MentionKind { Native, ReplyToBot, QuotedBot, ThreadParticipant }
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("transport: {0}")] Transport(#[from] reqwest::Error),
    #[error("rejected: {status} {body}")] PlatformRejection { status: u16, body: String },
    #[error("not supported: {feature}")] NotSupported { feature: &'static str },
    #[error("rate limited: {retry_after_secs}s")] RateLimited { retry_after_secs: u64 },
    #[error("auth: {0}")] Auth(String),
}

#[async_trait]
pub trait Channel: Send + Sync {
    async fn send_text(&self, chat_id: &str, text: &str) -> Result<MessageId, ChannelError>;
    async fn send_media(&self, chat_id: &str, media: &MediaPayload, caption: Option<&str>) -> Result<MessageId, ChannelError>;
    fn spawn_receive_loop(&self, tx: mpsc::Sender<InboundMessage>, cancel: CancellationToken) -> JoinHandle<anyhow::Result<()>>;
    async fn ack_received(&self, message_id: &MessageId) -> Result<(), ChannelError>;
    async fn get_chat_meta(&self, chat_id: &str) -> Result<ChatMeta, ChannelError>;
    async fn send_action_indicator(&self, chat_id: &str, action: ChannelAction) -> Result<(), ChannelError>;
    async fn edit_message(&self, message_id: &MessageId, new_text: &str) -> Result<(), ChannelError>;

    /// A2 fix: PROACTIVE OUTPUT — outbound message NOT triggered by an inbound message.
    /// Reserved in trait Phase 1 (all adapters return ChannelError::NotSupported by default).
    /// Phase 3+ proactive_notify pipeline calls this to initiate communication with a user
    /// who has NOT just sent a message. Required for "Kumpel" brand voice — NEOTH reaching out.
    ///
    /// `recipient`: typed RecipientId (newtype over human_uuid) — channel resolves to chat_id internally.
    /// `body`: ResponseBody enum (Text/Markdown/Image/File) per SPEC_wire_header_v2_slim §5 typed payload.
    /// `trace_id`: TraceId for trajectory correlation.
    ///
    /// Constraint: implementations MUST emit WAL event 0x33 CHANNEL_EGRESS with `proactive=true`.
    /// Constraint: implementations MUST check `freedom.yaml channels.proactive.enabled` before sending.
    /// Channel-specific implementations decide HOW (e.g., Telegram = `sendMessage` with no reply_to).
    async fn send_proactive(
        &self,
        recipient: &RecipientId,
        body: &ResponseBody,
        trace_id: TraceId,
    ) -> Result<MessageId, ChannelError> {
        // Default impl: not supported. Adapters Phase 1 = NotSupported.
        Err(ChannelError::NotSupported { feature: "send_proactive" })
    }
}
```

---

## 2. Schicht Classification per Framework v4.1

| Component | Schicht | Justification |
|-----------|---------|---------------|
| channel.send_text | 0 | Stateless, deterministic. Input to platform POST to MessageId. |
| channel.send_media | 0 | Same as send_text; media bytes are input, not state. |
| channel.ack_received | 0 | Single idempotent API call. |
| channel.send_action_indicator | 0 | Fire-and-forget, no branching. |
| channel.edit_message | 0 | Single API call; NotSupported propagates as typed Err. |
| channel.get_chat_meta | 0 | Read-only cache-prefixed lookup; deterministic per chat_id. |
| Receive-loop daemon | 1 (Pipeline) | Long-running orchestration with connection state. Pipeline YAML with execution_model: daemon_loop. |
| Gate tools | 0 | Pure predicate functions: (message, policy) to Decision. No IO, no WAL mutation. |
| Cross-channel identity resolver | 0 | (channel, channel_user_id) to human_uuid from WAL view. Read-only, deterministic. |

Anti-Pattern G.12 defense: The receive-loop is a Schicht-1 Pipeline (pipelines/channel_ingest.yaml), not a tool. Tools are invoked per discrete action. Long-running state (socket, auth token) lives in adapter struct -- Schicht-0 resource managed by BrainStem, not in any tool function body.

execution_model: daemon_loop is a v0.6 extension to Framework v4.1 Teil-C. Justified: the Framework is a Pflegbarer Garten explicitly allowing organic extension. All other execution_model semantics (sequential, tick_gated) remain unmodified.

---

## 3. WhatsApp Adapter: Library Comparison and Recommendation

| Option | Rust-native? | Edit support | Suspension risk | Auth |
|--------|-------------|-------------|----------------|------|
| Meta WA Business Cloud API | Yes (reqwest) | No | None (official) | Meta Business Mgr + HTTPS webhook |
| baileys Node.js subprocess | No (stdio shim) | No | High (ToS) | QR scan, personal number |
| whatsapp-web.rs | Yes, experimental | No | High (ToS) | QR scan |
| Twilio WA API | Yes (reqwest) | No | None | Twilio + Meta approval |

Recommendation: Meta WA Business Cloud API -- WaBusinessApiAdapter (primary).

Rationale:
- Pure HTTP via reqwest. Zero Node.js, zero subprocess, zero additional runtime.
- Existing hyper gateway provides the HTTPS webhook Meta requires. No new infrastructure.
- Official Meta channel: zero suspension risk, official SLA, documented rate limits.
- edit_message returns Err(ChannelError::NotSupported). No edit endpoint in WA Business API as of 2026-05. Streaming preview degrades: pipeline sends final message instead.

Secondary: WaBaileysSubprocessAdapter for personal-number testing only. Spawns thin Node.js shim (neoth-wa-shim) via baileys@7.0.0-rc10 JSON-lines stdio. Never in production. Compile-time flag: wa-baileys-shim.

---

## 4. Slack Adapter Design

Crate: slack-morphism (0.43+) -- Rust native, Web API + Socket Mode.
Auth: SLACK_BOT_TOKEN (xoxb-) + SLACK_APP_TOKEN (xapp-).

```yaml
# adapters/slack.yaml
id: slack
kind: channel_adapter
version: "0.6.0"
execution_model: daemon_loop
config_schema:
  bot_token:  { env: SLACK_BOT_TOKEN, secret: true }
  app_token:  { env: SLACK_APP_TOKEN, secret: true }
  socket_mode: true
  debounce_ms: 800
capabilities:
  send_text: true
  send_media: true
  edit_message: true   # chat.update
  send_action_indicator: true
  ack_received: false
```

Socket Mode eliminates public HTTPS requirement. slack-morphism handles reconnect and heartbeat; adapter wraps with CancellationToken listener.
edit_message maps to chat.update. Draft-preview: postMessage, capture ts as MessageId, chat.update per batch, final chat.update.

---

## 5. Telegram Adapter Design

Crate: teloxide (0.13+) -- proven in Jarvis. Auth: TELEGRAM_BOT_TOKEN (env).

```yaml
# adapters/telegram.yaml
id: telegram
kind: channel_adapter
version: "0.6.0"
execution_model: daemon_loop
config_schema:
  bot_token: { env: TELEGRAM_BOT_TOKEN, secret: true }
  polling_timeout_secs: 30
  debounce_ms: 600
capabilities:
  send_text: true
  send_media: true
  edit_message: true   # editMessageText
  send_action_indicator: true   # sendChatAction
  ack_received: false
```

Constraints from openclaw maintainer notes:
- Do NOT use sendMessageDraft for streaming -- drafts are ephemeral 30-second previews.
- Pattern: sendMessage -> editMessageText -> finalize in-place.
- Text > 4096 chars: chain into continuation messages at adapter layer.
- Allowlist entries MUST use numeric sender IDs. Usernames are mutable and unreliable.
- BrainStem must hold exclusive flock on $STATE_DIR/telegram.lock before spawning receive-loop.

---

## 6. Receive-Loop Mapping to Framework Schicht-1 Pipeline

Each daemon loop iteration = one pipeline execution (normalize through dispatch_agent). Outer reconnect/poll loop managed by BrainStem supervision, not expressed in YAML.

```yaml
# pipelines/channel_ingest.yaml
id: channel_ingest
schicht: 1
execution_model: daemon_loop
version: "0.6.0"
description: >
  Receives raw platform events, applies gate checks,
  emits WAL events, dispatches to agent response pipeline.

steps:
  - id: normalize
    tool: channel.normalize_raw
    inputs: { raw_event: "$raw" }
    outputs: { message: InboundMessage }
  - id: allowlist_gate
    tool: gate.allowlist_match
    inputs: { message: "$normalize.message", policy: "$config.allowlist_policy" }
    outputs: { decision: AllowlistDecision }
  - id: mention_gate
    tool: gate.mention_decision
    inputs: { message: "$normalize.message", policy: "$config.mention_policy" }
    outputs: { decision: MentionDecision }
    condition: "allowlist_gate.decision.allowed == true"
  - id: command_gate
    tool: gate.command_check
    inputs: { message: "$normalize.message", policy: "$config.command_policy" }
    outputs: { decision: CommandDecision }
    condition: "mention_gate.decision.should_process == true"
  - id: resolve_identity
    tool: wal.resolve_human_uuid
    inputs: { channel: "$normalize.message.channel", channel_user_id: "$normalize.message.chat_id" }
    outputs: { human_uuid: Uuid }
    condition: "command_gate.decision.should_process == true"
  - id: emit_inbound
    tool: wal.emit
    inputs: { event_type: "0x32", payload: "$normalize.message", human_uuid: "$resolve_identity.human_uuid" }
  - id: dispatch_agent
    tool: pipeline.dispatch
    inputs: { pipeline_id: "agent_respond", context: { message: "$normalize.message", human_uuid: "$resolve_identity.human_uuid" } }
    condition: "command_gate.decision.should_process == true"
```

New WAL EventTypes (SP-5 C-prime 2026-05-14; original 0x24-0x27 codes collided with PROVIDER band 0x20-0x2F and were superseded — authoritative codes locked in `wal/events.rs` CHANNEL band 0x30-0x3F):

| Code   | Name                  | Replaces spec | Emitted when |
|--------|-----------------------|---------------|-------------|
| `0x32` | `CHANNEL_INGRESS`     | `0x24` CHANNEL_INBOUND | Message passes all gates and enters agent pipeline |
| `0x33` | `CHANNEL_EGRESS`      | `0x25` CHANNEL_OUTBOUND | Adapter successfully sends message to platform |
| `0x34` | `CHANNEL_ERROR`       | (additive)    | Adapter transport / platform error |
| `0x35` | `INGRESS_QUARANTINED` | (Phase 11a S-4) | Message held by ingress-sanitizer for manual review |
| `0x36` | `INGRESS_SANITIZED`   | (Phase 11a S-4) | Message passed sanitizer (control-chars stripped, NFKC normalized) |
| `0x37` | `CHANNEL_ACK`         | `0x26` CHANNEL_ACK | Platform delivery ACK received (where supported) |
| `0x38` | `CHANNEL_EDIT`        | `0x27` CHANNEL_EDIT | edit_message call completed (streaming step) |

---

## 7. Per-Channel Gate Tools (Schicht-0 Filter Layer)

All gate tools are pure functions: (input, policy) -> Decision. No IO. No WAL mutation. No state.

### 7.1 Allowlist Gate

```rust
pub struct AllowlistPolicy { pub entries: Vec<AllowlistEntry>, pub mode: AllowlistMode }
pub struct AllowlistDecision { pub allowed: bool, pub matched_entry: Option<String> }
pub fn allowlist_match(message: &InboundMessage, policy: &AllowlistPolicy) -> AllowlistDecision
```

Telegram: numeric sender IDs only. Usernames forbidden (mutable, unreliable).
Slack: member IDs (U...). WhatsApp: E.164 phone numbers or JIDs.
Wildcard "*" = allow all (dev mode only; logged at WARNING).

### 7.2 Command Gate

```rust
pub struct CommandPolicy { pub prefix: String, pub allowed_cmds: Vec<String>, pub require_owner: bool, pub owner_ids: Vec<String> }
pub struct CommandDecision { pub is_command: bool, pub command_authorized: bool, pub should_process: bool, pub should_block: bool }
pub fn command_check(message: &InboundMessage, policy: &CommandPolicy) -> CommandDecision
```

### 7.3 Mention Gate

```rust
pub struct MentionPolicy { pub require_mention_in_groups: bool, pub bot_id: String, pub implicit_kinds: Vec<MentionKind> }
pub struct MentionDecision { pub should_process: bool, pub matched_kind: Option<MentionKind> }
pub fn mention_decision(message: &InboundMessage, policy: &MentionPolicy) -> MentionDecision
```

In DMs, require_mention_in_groups ignored -- all DMs pass by default.
In groups: native @bot + any enabled implicit_kinds pass.

---

## 8. Cross-Channel Session Binding

WAL view: idx_human_identity

```sql
CREATE TABLE human_identity (
    human_uuid         BLOB NOT NULL,    -- UUID v7, 16 bytes
    channel            TEXT NOT NULL,    -- "telegram" | "whatsapp_business" | "slack"
    channel_user_id    TEXT NOT NULL,    -- platform-native ID
    first_seen_ts      INTEGER NOT NULL, -- epoch-ms
    last_seen_ts       INTEGER NOT NULL,
    operator_merged    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (channel, channel_user_id)
);
CREATE INDEX idx_human_identity_uuid ON human_identity(human_uuid);
```

Assignment policy:
- First message from (channel, channel_user_id): auto-assign new UUID v7.
- Subsequent messages from same tuple: resolve existing UUID.
- No auto-merge across channels (avoids false positives from shared phone numbers, shared Slack workspaces).
- Operator merges via: neothctl identity merge <uuid1> <uuid2>. Updates all uuid2 rows to uuid1, tombstones uuid2 in WAL.

openclaw comparison: openclaw uses per-channel ConversationBindingContext = {channel, accountId, conversationId} with no cross-channel linking. NEOTH adds human_uuid at the WAL layer, enabling cross-channel recall via WHERE human_uuid = ? while keeping per-channel context structs intact.

---

## 9. Draft Preview and Finalizer Inheritance from openclaw

openclaw deprecated draft-preview-finalizer.ts in favor of deliverFinalizableLivePreview from message/live.ts. NEOTH Rust equivalent is LiveDelivery:

```rust
pub struct LiveDelivery {
    pub channel:    Arc<dyn Channel>,
    pub chat_id:    String,
    pub message_id: Option<MessageId>,
}

impl LiveDelivery {
    pub async fn send_or_edit(&mut self, text: &str) -> Result<(), ChannelError> {
        match &self.message_id {
            None => {
                let id = self.channel.send_text(&self.chat_id, text).await?;
                self.message_id = Some(id);
            }
            Some(id) => {
                match self.channel.edit_message(id, text).await {
                    Ok(()) => {}
                    Err(ChannelError::NotSupported { .. }) => {
                        // WhatsApp Business API: no edit endpoint.
                        // Drop intermediate; finalize() sends new message with full text.
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
    pub async fn finalize(mut self, final_text: &str) -> Result<MessageId, ChannelError> {
        self.send_or_edit(final_text).await?;
        Ok(self.message_id.unwrap())
    }
}
```

| Channel | Initial send | Streaming edits | Finalize |
|---------|-------------|-----------------|----------|
| Telegram | sendMessage | editMessageText per token batch | Final editMessageText |
| Slack | chat.postMessage | chat.update per token batch | Final chat.update |
| WhatsApp Business API | messages POST | Dropped (NotSupported) | New messages POST with full text |

---

## 10. MVP Impact: 3 Channels vs Telegram-Only

v0.5 baseline: Day 7 telegram.send tool + telegram bot ingress. Day 30 MVP: Telegram echo + recall + Left Hemisphere response.

| Channel | Additional effort | Blocking dependency |
|---------|------------------|-------------------|
| Telegram | 0 days | None |
| Slack | +3 days | SLACK_BOT_TOKEN + SLACK_APP_TOKEN, Socket Mode app in Slack admin |
| WhatsApp Business API | +7 days | Meta Business Manager account, approved phone number, NEOTH gateway publicly reachable with valid TLS |

Total Phase-1 slip: +10 days. MVP demo: Day 30 -> Day 40.

WhatsApp 7-day breakdown:
- Day 1: Meta Business Manager setup + phone number registration (start Day 1 to parallelize approval).
- Day 2-3: Webhook verification, WaBusinessApiAdapter HTTP client, send_text / send_media.
- Day 4-5: Receive-loop (webhook handler in hyper gateway), normalization, allowlist gate.
- Day 6: Integration test: inbound WA message -> WAL -> Left Hemisphere -> WA reply.
- Day 7: Buffer for Meta approval delays.

Risk: Meta approval non-deterministic. If not approved by Day 37, WhatsApp cut from MVP, re-targeted Day 60. Telegram + Slack proceeds Day 40 as scheduled.

Verdict: +10 days acceptable for 3x channel coverage. Channel trait, WAL events, and identity view built once, amortize across Phase 2 (Discord, Signal, Matrix, LINE).

---

## 11. Top-5 Design Risks and Mitigations

| # | Risk | Severity | Mitigation |
|---|------|---------|------------|
| 1 | Meta Business API approval delay (2-5 days typical, weeks possible) | High | Start Meta registration Sprint Day 1 in parallel with Rust code. Gate Demo Day 40 on approval. Fallback: Telegram + Slack only. Never block code on approval status. |
| 2 | execution_model: daemon_loop not in Framework v4.1 | Medium | Document as explicit v0.6 extension in tool_framework_v4_1.md addendum. Chorus review before merge. Does not break any existing Schicht rule. |
| 3 | Cross-channel human_uuid merge ambiguity | Medium | No auto-merge. First-seen auto-assign only. Operator-explicit merge via neothctl identity merge. Same E.164 on WA and Telegram = two identities until operator merges. |
| 4 | Telegram long-polling conflict on multi-instance start | Medium | BrainStem acquires exclusive flock on $STATE_DIR/telegram.lock before spawning receive-loop. Second instance fails fast with clear error. |
| 5 | Slack Socket Mode disconnect storms under sustained load | Low-Medium | slack-morphism handles reconnect with backoff. Circuit breaker: reconnect count > 10 in 60s triggers BrainStem adapter restart. Emits 0x21 METRIC_SNAPSHOT for Cerebellum drift detection. |

---

## Build Sequence

1. crates/channel-trait/ -- Channel trait, InboundMessage, MessageId, ChannelError, LiveDelivery
2. crates/gate-tools/ -- allowlist_match, command_check, mention_decision (pure fns, no async)
3. crates/wal-identity/ -- idx_human_identity schema migration, wal.resolve_human_uuid tool
4. WAL EventTypes 0x32-0x38 (CHANNEL band per SP-5 C-prime) -- already locked in `wal/events.rs`; SPEC numbering 0x24-0x27 was invalid
5. pipelines/channel_ingest.yaml -- Schicht-1 daemon_loop pipeline
6. crates/channel-telegram/ -- TelegramAdapter via teloxide
7. crates/channel-slack/ -- SlackAdapter via slack-morphism
8. crates/channel-whatsapp-business/ -- WaBusinessApiAdapter via reqwest
9. BrainStem supervisor integration -- spawn receive-loops, single-instance lock for Telegram
10. Integration tests -- per-adapter round-trip, gate logic unit tests, identity resolution tests

---

## Locked Decisions Summary

| Decision | Choice |
|----------|--------|
| WhatsApp primary | Meta WA Business Cloud API (REST, reqwest, zero suspension risk) |
| WhatsApp secondary | baileys Node.js subprocess shim, feature-gated wa-baileys-shim, dev/test only |
| Slack | slack-morphism + Socket Mode |
| Telegram | teloxide (existing, proven in Jarvis) |
| Receive-loop Schicht | 1 (Pipeline), execution_model: daemon_loop |
| Gate tools Schicht | 0 (pure predicates) |
| Cross-channel identity | idx_human_identity WAL view, UUID v7, operator-explicit merge only |
| Streaming preview | LiveDelivery: edit on Telegram/Slack, final-only on WhatsApp |
| New WAL events (CHANNEL band 0x30..=0x3F) | `0x32` CHANNEL_INGRESS, `0x33` CHANNEL_EGRESS, `0x34` CHANNEL_ERROR, `0x35` INGRESS_QUARANTINED, `0x36` INGRESS_SANITIZED, `0x37` CHANNEL_ACK, `0x38` CHANNEL_EDIT (SP-5 C-prime 2026-05-14; original 0x24-0x27 invalidated by PROVIDER-band collision — see §"WAL band correction" at top of file) |
| MVP slip | +10 days (Day 30 -> Day 40) |
