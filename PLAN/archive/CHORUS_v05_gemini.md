Here is the review of AGENTER v0.5 against the new requirements and Framework v4.1 constraints.

### 1. 30-Day MVP Cutoff vs. WhatsApp/Slack + Plugins
**Ref:** Section 2 ("Channels: Phase 1 Telegram only") and Section 5 (Day 7, Day 30).
**Assessment:** Forcing WhatsApp, Slack, and a full plugin registry into Phase 1 **will unequivocally shatter the 30-day MVP cutoff**. 
- **Concrete Estimate:** 
  - +2 days for Slack ingress/egress/auth.
  - +3 days for WhatsApp (API verification, webhook handling, media parsing).
  - +7-10 days for a robust, memory-safe plugin registry in Rust (e.g., embedding a WASM runtime or dealing with unsafe `libloading` for dynamic libraries). 
  - **Total Delay: 12-15 days.** A 45-day MVP is realistic if these are forced into Phase 1.

### 2. Framework-Conformant Skill/Plugin Design
**Ref:** Section 2 (Tools vs. Pipelines).
**Assessment:**
- **Skills = Data-as-YAML (Schicht 1).** Skills (like openclaw's workflows) are declarative sequences of operations. They orchestrate tools and therefore belong as Pipelines in Schicht 1. They are loaded dynamically by the Pipeline-Router.
- **Plugins = Code-as-Rust/WASM (Schicht 0).** Plugins introduce new atomic capabilities (e.g., a custom API connector). To adhere to Framework Teil-B (Tools must be stateless + deterministic), plugins must expose pure functions. 
- **Design:** You cannot safely hot-reload Rust native code without risking segfaults or dealing with FFI nightmares. The conformant design is to embed a **WASM runtime** (like `wasmtime`). Plugins are compiled to `.wasm`, loaded at runtime, and register as stateless Schicht-0 tools. Skills (YAML) then call these WASM tools.

### 3. Multi-Node Clustering (Veronica Pattern)
**Ref:** Section 2 (`agenterd single binary`) & Section 4 (EventHeader v2).
**Assessment:** The v0.5 architecture is fundamentally single-node. 
- **Phase 1 Acceptability:** Single-node is absolutely acceptable and mandatory for Phase 1. Building distributed systems (Paxos/Raft consensus) takes months. 
- **The WAL Replication Story:** To support Veronica later, your WAL needs architectural runway *now*. The v0.5 `EventHeader` (Section 4) has `generation` but lacks a `node_id`. If two nodes write to their local WALs simultaneously, merging them will corrupt state. 
- **Required Fix:** Add `node_id: [u8; 4]` to the `EventHeader`. Replication will look like async leader-follower log shipping over the `hyper` Gateway via SSE, with `node_id` + `ts_ns` used to resolve CRDT-like view materialization.

### 4. Channel Adapters: Schicht-0 or Schicht-1?
**Ref:** Section 2 (Gateway).
**Assessment:** Framework Teil-A dictates channels are runtime ingress. It maps cleanly if split:
- **Ingress (Receiving) = Gateway (Runtime).** Receiving a WhatsApp message is neither Schicht 0 nor 1. The Gateway catches the webhook, normalizes the proprietary JSON into a standard `CHANNEL_EVENT`, and triggers a Schicht-1 pipeline.
- **Egress (Sending) = Schicht-0 Tool.** `telegram.send` or `whatsapp.send` are atomic, stateless actions. They take a payload and a destination ID, and return a success/fail boolean.

### 5. Top-5 Must-Fix Issues for v0.6
1. **Scope Collision:** Section 5 (Day 30 MVP) explicitly states "Telegram message". You must update the document to either expand the timeline to 45 days to include WhatsApp/Slack/Plugins, or formally reject the operator's new requirements for Phase 1.
2. **EventHeader Multi-Node Gap:** Add `node_id: [u8; 4]` or similar to the EventHeader in Section 4 to support future Veronica-style clustering without a breaking schema migration.
3. **Plugin Boundary Definition:** Explicitly define the plugin mechanism in Section 2. Mandate WASM for dynamic Schicht-0 plugins to avoid unsafe Rust FFI crashes.
4. **Unified Gateway Abstraction:** Refactor Section 2's inputs to show a `Normalization Gateway`. Do not hardcode Telegram logic into the Pipeline-Router; all channels must resolve to a generic `UserMessage` struct before hitting Schicht 1.
5. **Skill Auto-Loading Placement:** Section 6 defers Skill Auto-Loading to Phase 2, but the prompt demands it in Phase 1. Move it to the Phase 1 timeline (and take the schedule hit) or push back on the operator.

**Verdict:** request changes

## DONE