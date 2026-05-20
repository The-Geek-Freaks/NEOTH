# SP-5 Channel API — paper conflict between code and spec

## Status

NEOTH v0.1 ships with a minimal `Channel` trait. `SPEC_channels.md` defines a
much richer surface. Phase 15 (R-2 Keet) is blocked on this resolution.

## Current code (`SRC/neothd/src/channels/mod.rs`)

```rust
pub struct InboundMessage {
    pub channel: &'static str,
    pub sender_id: String,
    pub sender_display: Option<String>,
    pub text: String,
    pub channel_ts_unix: u64,
}

pub struct OutboundMessage {
    pub recipient_id: String,
    pub text: String,
}

pub type PipelineHandler = Box<dyn Fn(InboundMessage) -> Pin<Box<dyn Future<
    Output = Result<Option<OutboundMessage>>> + Send>> + Send + Sync>;

#[async_trait]
pub trait Channel: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, handler: PipelineHandler) -> Result<()>;
}
```

WAL events currently used: 0x32 CHANNEL_INGRESS, 0x33 CHANNEL_EGRESS,
0x34 CHANNEL_ERROR (band 0x30-0x3F).

Channels implemented: telegram (teloxide long-poll). Working. 102+ tests pass.

## Spec (`PLAN/SPEC_channels.md`)

```rust
pub struct InboundMessage {
    pub human_uuid: uuid::Uuid,
    pub channel: ChannelKind,         // enum, not &'static str
    pub chat_id: String,
    pub thread_id: Option<String>,
    pub text: Option<String>,         // Option, not required
    pub media: Option<MediaPayload>,  // attachments first-class
    pub reply_to: Option<MessageId>,
    pub mention_kind: Option<MentionKind>,
    pub raw_ts: i64,
}

#[async_trait]
pub trait Channel: Send + Sync {
    async fn send_text(&self, chat_id: &str, text: &str) -> Result<MessageId, ChannelError>;
    async fn send_media(&self, chat_id: &str, media: &MediaPayload, caption: Option<&str>) -> Result<MessageId, ChannelError>;
    fn spawn_receive_loop(&self, tx: mpsc::Sender<InboundMessage>, cancel: CancellationToken) -> JoinHandle<Result<()>>;
    async fn ack_received(&self, message_id: &MessageId) -> Result<(), ChannelError>;
    async fn get_chat_meta(&self, chat_id: &str) -> Result<ChatMeta, ChannelError>;
    async fn send_action_indicator(&self, chat_id: &str, action: ChannelAction) -> Result<(), ChannelError>;
    async fn edit_message(&self, message_id: &MessageId, new_text: &str) -> Result<(), ChannelError>;
    async fn send_proactive(&self, recipient: &RecipientId, body: &ResponseBody, trace_id: TraceId) -> Result<MessageId, ChannelError>;
}
```

WAL events in spec: 0x24 CHANNEL_INBOUND, 0x25 CHANNEL_OUTBOUND, 0x26 CHANNEL_ACK,
0x27 CHANNEL_EDIT (band 0x20-0x2F, which is the **provider band** in the locked
range-table — direct collision with PROVIDER_REQUEST 0x20 / PROVIDER_RESPONSE 0x21).

Spec also requires `LiveDelivery { send_or_edit, finalize }` for streaming
previews, identity merging via `idx_human_identity` SQL view, and gate tools
(`allowlist_match`, `command_check`, `mention_decision`) as Schicht-0 pure
predicates.

## Three candidate paths

### A. Refactor to spec verbatim
Adopt every method, switch InboundMessage to spec shape, add LiveDelivery,
introduce gate tools, add identity SQL view. Fix the WAL band collision by
moving spec events from 0x24-0x27 to free slots in 0x30-0x3F (preserves current
0x32-0x34 numbers or replaces them).

- Pro: full spec compliance, unblocks Keet + Slack + WhatsApp work with one trait
- Pro: streaming previews ready, proactive send ready
- Con: 3-5 days of work, breaks current telegram adapter signature
- Con: requires identity SQL view + UUID v7 lib (only telegram uses string ids today)
- Con: 24 CLI subcommands all touch InboundMessage transitively — ripple risk

### B. Minimal extension
Add only `send_text` + `send_media` + leave `run(handler)` for the receive
loop. Drop the rest until concretely needed. Keep current InboundMessage. Keep
0x32-0x34 events. Defer LiveDelivery + identity view + gate tools until R-2
Keet or R-3 Slack actually need them.

- Pro: <1 day, unblocks Keet immediately
- Pro: keeps current telegram adapter working unchanged
- Pro: incremental, low risk
- Con: spec drift remains documented but unfixed
- Con: streaming reply UX (R-22 partial; Telegram editMessageText is unavailable through `run`)

### C. Hybrid — spec InboundMessage, minimal action methods
Adopt InboundMessage from spec (with media + reply_to + mention_kind + thread_id),
keep telegram unchanged at action surface (only add `send_text` + `send_media`),
add WAL events 0x37 CHANNEL_ACK + 0x38 CHANNEL_EDIT in current band when needed
(no collision). Drop spec's UUID v7 + identity view for v0.1.x — keep sender_id
as string until cross-channel actually exists.

- Pro: keeps message data model future-proof (media, threads, replies)
- Pro: still <2 days; telegram adapter only needs the new sends
- Pro: WAL band collision in spec resolved by staying in 0x30-0x3F
- Con: SPEC drift remains on UUID v7 + LiveDelivery + gate tools
- Con: Spec needs a documented amendment ("0x24-0x27 moved to 0x37-0x3A")

## Open questions for the council

1. Does the spec's UUID v7 cross-channel identity (`idx_human_identity`) earn its
   weight at v0.1.x, or is it a Phase 16+ concern once a second messenger exists?
2. Is `LiveDelivery` (streaming preview via editMessageText) operator-visible
   enough at v0.1.x to justify the trait expansion, given that local Qwen3
   (D14b) is still deferred and claude_cli is single-shot stream?
3. The spec puts CHANNEL events at 0x24-0x27 (collision with PROVIDER band in
   current locked range table). Move spec or move code?
4. Gate tools (allowlist/command/mention) are pure predicates. They could live
   as helpers without a trait. Are they worth a separate Schicht-0 module?

## What we want from review

For each candidate (A/B/C):
- Are the trade-offs faithfully captured? Missing risks?
- Pick one. Why.
- If your pick differs by phase ("B now, A later"), name the trigger event.
- Spec amendment shape for the WAL band collision.
