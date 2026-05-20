# NEOTH Channel Shipping Status — 2026-05-20

**Sources consulted:**
- `PLAN/SPEC_channels.md` (NEOTH v0.6 Channel-Adapter Architecture Spec)
- `PLAN/00_DESIGN_v1.1_FINAL.md`
- `docs/channels.md`
- `SRC/neothd/src/channels/` (all adapter files)
- `SRC/neothd/src/cli/mod.rs` (ChannelAction enum + dispatch)
- `SRC/neothd/src/cli/slack.rs`
- `SRC/neothd/src/config/credentials.rs` (Credentials struct)
- `SRC/neothd/src/config/mod.rs` (FreedomConfig)
- `SRC/neothd-gui/ui/main.slint` (wizard step, lines 536–583)
- `SRC/neothd-gui/ui/settings.slint` (Settings → Channels tab, lines 425–428)

---

## 1. Shipping Channels (code exists, documented as operational)

| Channel | Adapter files | CLI subcommand support | credentials.yaml field(s) | freedom.yaml field | Shipping version | Notes |
|---------|--------------|----------------------|--------------------------|-------------------|-----------------|-------|
| CLI (REPL) | n/a — built-in `neoth chat` / `neoth serve` | `neoth chat`, `neoth serve` | none | none | v0.1+ | Always on; cannot be disabled |
| Telegram | `channels/telegram.rs` | `neoth channel add telegram` (stub, not wired v0.1); init wizard sets token | `telegram_token` | `telegram_token` (flat, pre-nesting) | v0.1+ | Long-poll; no public HTTPS needed. `policy.yaml::channels.telegram.allowed_chat_ids`. Lock: `$STATE_DIR/telegram.lock` |
| WhatsApp | `channels/whatsapp.rs`, `whatsapp_api.rs`, `whatsapp_webhook.rs` | `neoth channel` stub only (unimplemented v0.1) | `whatsapp_token`, `whatsapp_phone_id`, `whatsapp_verify_token` | none yet | v0.2+ | Meta Business Cloud webhook; requires public HTTPS + Meta approval. Docs in `docs/channels.md` §WhatsApp |
| Slack | `channels/slack.rs`, `slack_api.rs`, `slack_events.rs`, `slack_socket.rs` | `neoth slack test`, `neoth slack send` | `slack_bot_token`, `slack_app_token` | none yet | v0.3+ | Socket Mode WebSocket; no public HTTPS needed. `cli/slack.rs` fully wired |
| Discord | `channels/discord.rs`, `discord_gateway.rs` | `neoth channel` stub only | `discord_bot_token` (in `docs/channels.md`; NOT in `credentials.rs` struct yet — gap) | none yet | v0.3+ (DMs only) | Gateway WebSocket. Guild-channel receive is next iteration. `discord_bot_token` missing from `Credentials` struct |
| Keet | `channels/keet.rs` | `neoth channel` stub only | `keet_seed_phrase` (internal; not in `credentials.rs` struct — gap) | none yet | v0.3+ (preview) | Pears/Hyperswarm bridge; 24-word seed phrase. Marked "preview" in docs |

**Key gap in credentials.rs:** `discord_bot_token` and the Keet seed-phrase field are NOT present in `SRC/neothd/src/config/credentials.rs::Credentials`. The struct only has `telegram_token`, `whatsapp_token/phone_id/verify_token`, `slack_bot_token`, `slack_app_token`. Discord and Keet load their tokens from a different path or directly from env — verify before shipping the credentials wizard step for those channels.

---

## 2. Planned Channels (mentioned in spec/design, no adapter code exists)

| Channel | Target version / Phase | Spec reference (file:line) |
|---------|----------------------|---------------------------|
| Signal | Phase 3+ | `PLAN/SPEC_channels.md` line 6; `docs/channels.md` line 253 |
| Matrix | Phase 3+ | `PLAN/SPEC_channels.md` line 6; `docs/channels.md` line 254 |
| LINE | Phase 3+ | `PLAN/SPEC_channels.md` line 6; `docs/channels.md` line 256 |
| iMessage | Phase 4 | `docs/channels.md` line 255 |

No adapter `.rs` files exist for any of these four. `SPEC_channels.md` header states: "Phase 2: Discord, Signal, iMessage, LINE, Matrix" — Discord has since shipped (moved to Phase 1 code), so Phase 2 effectively = Signal, Matrix, LINE, iMessage in the current state.

---

## 3. Research-Phase Channels

| Channel | Status notes |
|---------|-------------|
| Signal | Requires Signal Desktop running locally; no stable public API. Planned but multi-week integration work. Ref: `docs/channels.md`:253 |
| Matrix | Homeserver registration + matrix-rust-sdk integration. Planned. Ref: `docs/channels.md`:254 |
| iMessage | Apple-only, restricts automation. macOS-only deployment gate. Phase 4. Ref: `docs/channels.md`:255 |
| LINE | LINE Messaging API; similar complexity to Slack. Planned Phase 3+. Ref: `docs/channels.md`:256 |
| Facebook Messenger | memory-only, verify — NOT found in any spec, adapter code, or docs. If mentioned in operator memory notes it is unconfirmed |
| QQ / WeChat | memory-only, verify — NOT found in any source. Community speculation only |

---

## 4. Missing from GUI

### Wizard step (main.slint:536–583)

The wizard currently shows exactly three checkboxes (confirmed by code at lines 548–562):

1. CLI — always on, disabled
2. Telegram — enabled, bound to `enable-telegram`
3. Slack — disabled, label says "adapter scaffold only, not shipping in v0.1" — **LIE** (Slack ships v0.3+)
4. Keet — disabled, label says "research phase, multi-week" — **STALE** (Keet is v0.3+ preview, not multi-week research)

**Missing from wizard:**
- WhatsApp — has full adapter code (`v0.2+`), full `credentials.yaml` fields, full docs section. NOT in wizard.
- Discord — has full adapter code (`v0.3+ DM`), docs section. NOT in wizard.

The wizard comment at line 11–12 of main.slint confirms this is intentional debt: "Slack / Keet / Discord land when their adapters ship." But WhatsApp shipped as `v0.2+` and is also absent.

### Settings → Channels tab (settings.slint:425–428)

The Channels tab is a `PendingPanel` — a placeholder stub. Its subtitle text correctly lists all five operational/preview channels: "Telegram, WhatsApp, Slack, Discord, Keet." However, the panel renders no actual controls — it is not yet implemented. The `/connect <channel> | /disconnect <channel>` mirror-slash hint is shown but not actionable from the GUI.

---

## 5. Recommended GUI Channel List

Group by status. Each row: label, status badge, toggle behavior.

**Operator-facing checkbox list — Channels wizard step:**

| Row label | Status badge | Toggle behavior |
|-----------|-------------|-----------------|
| CLI (neoth chat / serve REPL) | Operational — always on | Hardcoded checked, `enabled: false` (keep as-is) |
| Telegram (long-poll, no public HTTPS needed) | Operational — v0.1+ | Enabled checkbox; shows token field when checked |
| WhatsApp (Meta Business Cloud webhook) | Operational — v0.2+ | Enabled checkbox; shows `whatsapp_token`, `whatsapp_phone_id`, `whatsapp_verify_token` fields when checked; warn: requires public HTTPS + Meta account |
| Slack (Socket Mode WebSocket) | Operational — v0.3+ | Enabled checkbox; shows `slack_bot_token` + `slack_app_token` fields when checked |
| Discord (Gateway WebSocket, DMs) | Operational — v0.3+ | Enabled checkbox; shows `discord_bot_token` field when checked; note: `discord_bot_token` must first be added to `credentials.rs` struct |
| Keet (Hyperswarm / Pears) | Preview — v0.3+ | Enabled checkbox but warn-badge "preview"; shows seed-phrase field when checked |
| Signal | Planned — Phase 3+ | Disabled, informational only; tooltip: "requires Signal Desktop" |
| Matrix | Planned — Phase 3+ | Disabled, informational only |
| LINE | Planned — Phase 3+ | Disabled, informational only |
| iMessage | Research — Phase 4 | Disabled, informational only; tooltip: "macOS only, Apple automation restrictions" |

**Settings → Channels tab:** Replace `PendingPanel` with a per-channel card for each of the five implemented channels (Telegram, WhatsApp, Slack, Discord, Keet). Each card: status indicator (connected/disconnected), credential validation button, connect/disconnect action. Mirror the `/connect <channel>` CLI surface.

---

## Summary of Key Discrepancies

1. Wizard shows Telegram + Slack (stub) + Keet (stub). Missing: WhatsApp (fully shipped) and Discord (fully shipped).
2. Settings → Channels tab is a `PendingPanel` placeholder — no channel is actually configurable from the GUI post-wizard.
3. `credentials.rs::Credentials` struct is missing `discord_bot_token` and a Keet seed field — Discord and Keet adapters load credentials through a different path; this must be unified before the GUI credentials step can handle them.
4. `neoth channel` CLI subcommand is fully hidden and returns an error in v0.1 (`cli/mod.rs:765–772`). The `ChannelAction` enum (`Add/List/Test/Remove`) exists as scaffolding only; no action is dispatched.
5. Facebook Messenger, QQ, WeChat: memory-only mentions — not found in any code, spec, or doc file. Flag as unconfirmed.
