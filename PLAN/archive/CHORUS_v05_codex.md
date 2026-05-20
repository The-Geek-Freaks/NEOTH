request changes

The v0.5 artifact is no longer internally consistent with the new Phase-1 requirements. It still says “Build-ready” and “30-day hard MVP”, but the added WhatsApp + Slack + skill/plugin system materially changes scope. Do not start coding from this document without a v0.6 scope correction.

**1. Phase-1 Scope / 30-Day Cutoff**

Adding WhatsApp + Slack + plugin/skill system to Phase 1 breaks the current Day-30 plan.

Current v0.5 Day 30 target is explicitly:

- §1.6: “Telegram message → 2 WAL views → Left-Claude response”
- §5 Day 30: “Telegram message → recall from 2 views → Left-Claude response → Telegram reply”
- §2 contradicts itself: top input diagram lists `Telegram | WhatsApp | CLI | REPL`, but later says “Channels (Phase 1: Telegram only; Phase 2+: WhatsApp, Signal, …)”

Concrete estimate:

| Feature | Realistic added effort |
|---|---:|
| Slack ingress + egress + auth + event verification + retry/idempotency | 3-5 days |
| WhatsApp adapter via Cloud API/Twilio/Baileys decision, webhook validation, media/message model quirks | 5-8 days |
| Shared channel abstraction + canonical message envelope + per-channel identity mapping | 2-3 days |
| Plugin registry minimum viable design + manifest + versioning + loading + disable path | 4-6 days |
| Skill auto-loading minimum viable design + YAML schema + router integration + tests | 3-5 days |
| Integration hardening across 3 channels | 3-5 days |

Net: +20-32 days.

New realistic MVP is 45-60 days if all three channels and skills/plugins are truly Phase 1. If the 30-day cutoff is non-negotiable, Phase 1 must stay Telegram-only and only include a stubbed registry/schema, not operational Slack/WhatsApp/plugin loading.

**2. Framework-Conformant Skill / Plugin Design**

The artifact currently blurs “tool”, “skill”, “plugin”, and “router habit”. §1.7 says “Skill Auto-Loading routing” is Day 22, §2 says Tools are YAML-spec + Rust-impl, §6 moves Skill Auto-Loading to Day 31-60. That is a blocker.

Framework-conformant split should be:

- **Skills = Schicht 0 declarative data**
  - YAML only.
  - No side effects.
  - No runtime code.
  - Deterministic expansion into routing hints, prompt fragments, tool affordances, constraints, examples, metadata.
  - Loaded by content hash, versioned, auditable, disable-able.

- **Plugins = Schicht 0 tool packages, implemented as Rust crates or external processes**
  - A plugin may register one or more Tools.
  - Each registered Tool must satisfy Framework Teil-B: stateless, deterministic from declared inputs, explicit outputs, no hidden memory.
  - Any stateful behavior belongs in Schicht 1 pipelines or WAL-backed views, not inside the plugin.

Do not classify plugins themselves as Schicht 1. The plugin registry is Schicht 1 control-plane/runtime infrastructure, but the plugin-exposed capabilities are Schicht 0 tools. Plugin lifecycle state goes into WAL events, not hidden plugin-local state.

Required v0.6 refs to add:

- `SkillManifest` schema
- `PluginManifest` schema
- deterministic tool contract
- permission/capability declaration
- load/disable/version policy
- no dynamic plugin mutation of pipelines unless mediated by Schicht 1 registry events

**3. Multi-Node Clustering / Veronica Pattern**

Single-node-only is acceptable for Phase 1. Multi-node execution from Day 1 is not.

But v0.5 must explicitly say that. Right now there is no serious clustering design, no node identity in `EventHeader`, no replication protocol, no conflict semantics, and no WAL segment ownership story.

Minimum v0.6 position:

- Phase 1: single writer, single node.
- Phase 1 may include node-id reserved fields and WAL segment format compatibility.
- Phase 2/3: read-replica or follower node allowed.
- True active-active clustering is out of MVP unless the WAL model is redesigned.

WAL replication story needed:

- `node_id`
- `wal_segment_id`
- monotonically increasing local sequence number
- writer epoch / generation semantics across nodes
- replication cursor
- idempotent apply
- conflict policy for tombstone/supersede
- vector index rebuild/follower catch-up behavior
- snapshot + restore story

Current `EventHeader` has `generation` and `event_id`, but no node identity. That is not enough for Veronica-style multi-node. Add `node_id` now or explicitly declare single-node WAL compatibility only.

**4. Channel Adapters: Schicht 0 or Schicht 1**

Channel adapters should be split:

- **Schicht 0 Tools**
  - `telegram.send`
  - `slack.send`
  - `whatsapp.send`
  - possibly `channel.normalize_message`
  - pure-ish adapters with explicit inputs/outputs and no hidden orchestration

- **Schicht 1 Pipelines**
  - webhook ingress handling
  - auth verification
  - deduplication
  - canonical message conversion
  - session binding
  - response routing
  - retries/backoff
  - WAL emission

Framework Teil-A “channels are runtime ingress” maps cleanly to Schicht 1 ingress pipelines calling Schicht 0 send/normalize tools. Treating an entire channel as one Schicht-0 tool is wrong because ingress is stateful, retrying, identity-binding runtime behavior.

**5. Top-5 Must-Fix Issues for v0.6**

1. **Resolve Phase-1 contradiction**
   - §1.6 and §5 say Telegram-only.
   - new requirement says WhatsApp + Slack + Telegram.
   - §2 says both.
   - Pick one. My recommendation: 30-day MVP = Telegram only; Slack/WhatsApp Day 31-45.

2. **Define skills/plugins formally**
   - Skills are YAML data.
   - Plugins are tool packages exposing Schicht-0 tools.
   - Registry/runtime is Schicht 1.
   - No hidden plugin state.

3. **Declare clustering scope**
   - Either single-node-only Phase 1, or add real WAL replication fields/protocol.
   - Current design cannot support Veronica-style multi-node safely.

4. **Fix EventHeader `Option<u8>`**
   - `Option<u8>` in `#[repr(C)]` is a bad binary ABI choice.
   - Use `u8 brain_region` with `0 = NONE`, or `u16` if future-proofing.
   - Also the text says “5 brain regions” but lists Left/Right/Callosum + Amygdala + Insula + Cerebellum + BasalGanglia = 7 logical tags. Fix the terminology.

5. **Move non-MVP features out of Day 1-30**
   - Tailslayer + IVF + concept vocabulary + compression anchor + session ledger + skill router + refusal classifier are too much alongside three channels/plugins.
   - For a real 30-day MVP: WAL, two views, one channel, Claude adapter, recall, response loop, status endpoint.

Verdict: request changes.

The design is close in architecture, but the new requirements invalidate the “FINAL / build-ready / 30-day hard cutoff” claim. v0.6 needs a brutally explicit MVP boundary: either preserve Day 30 by deferring Slack/WhatsApp/plugins, or accept a 45-60 day Phase 1.

## DONE
