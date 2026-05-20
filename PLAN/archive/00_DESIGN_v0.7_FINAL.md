# AGENTER — Design v0.7 FINAL

> **Status:** Locked. Replaces v0.6. All 10 Codex blockers + 4 non-blockers fixed.
> **Foundation:** Tool-Framework v4.1 "Pflegbarer Garten".
> **MVP cutoff revised: Day 30 (lean Telegram-only slice). Day 31-60 Phase 2 adds channels + WASM.**
> **WAL:** v2 binary format with explicit LE wire spec, wal_format_version=1, event_schema_version=3.

---

## 0. Status Banner + Locked Decisions

| # | Decision | Source |
|---|----------|--------|
| Q1 | Rust core, ASM kernels via FFI only after profiling | v0.2 |
| Q2 | Council triggers: conservative + adaptive | v0.5 |
| Q3 | Block-cache: tombstone-bus-flush + 24h ceiling | v0.5 |
| Q4 | Embedding: Qwen3-Embedding-0.6B-Q8 via candle | v0.4 |
| Q5 | Hemispheres: Left=Claude Opus 4.7, Right=Gemini 3.1 Pro, Callosum=Codex GPT-5.5 | v0.4 |
| Q6 | YAML tool/pipeline format (Framework B.5/C.1) | v0.4 |
| Q7 | Mirror-Refusal spec adopted from SPEC_mirror_refusal.md | v0.5 |
| Q8 | Ecology-Schicht: Phase 4, Day 91+ | v0.5+v0.6 |
| N1 | Plugins = WASM via wasmtime (Phase 2+). Day-30 MVP: YAML skill loader only | v0.7 Codex B4 |
| N2 | Skills = YAML data + Schicht-1 declarative pipelines | v0.6 Gemini verdict |
| N3 | Channels: Ingress=Gateway (Runtime), Egress=Schicht-1 Effect Adapter | v0.7 NB2 fix |
| N4 | node_id: [u8;16] in WAL EventHeader from Day 1 | v0.6 |
| N5 | MVP cutoff Day 30 (Telegram-only). Phase 2 = Day 31-60 | v0.7 Codex B4 |
| N6 | Tailslayer default-ON + graceful mmap fallback | v0.5 |
| N7 | Needle: low_risk_intent allowlist gated. Send/write intents MUST NOT bypass LLM | v0.7 Codex B8 |
| N8 | LOWKEY: versioned + content_hash + per-eval disable + prompt_bundle_hash in WAL | v0.7 Codex B7 |
| N9 | Conductor 3-layer context (product.md + spec.md + plan.md) | v0.6 |
| N10 | MAGI ULTRA + OMEGA-PRIME as Council skills (Phase 2) | v0.6 LOWKEY |
| N11 | WAL atomic-commit + 120s idle stream-kill | v0.6 |
| N12 | CloakBrowser opt-in Phase 2 plugin. subprocess.run.cloak_browser named tool | v0.7 Codex B10 |
| N13 | NOT adopted: agentmemory (6 CVEs); only marketplace.json schema 20 lines | v0.6 |
| N14 | Effect Adapters are Schicht-1 boundary. Pure Schicht-0 = deterministic + no-side-effect | v0.7 NB2 fix |
| N15 | subprocess.exec REMOVED. Named per-command tools only | v0.7 Codex B10 |
| N16 | WASM Plugin Host Capability API: Phase 2 deliverable, hostcall surface defined below | v0.7 Codex B9 |
| N17 | Day-1 cargo deps minimal (see Section 12) | v0.7 Codex NB4 |


---

## 1. Diff from v0.6

### Blocker Fixes

| # | Blocker | Fix in v0.7 |
|---|---------|-------------|
| B1 | EventHeader Option<u8> not stable binary contract | brain_region: u8, 0=None, 1..5=Region. Explicit LE wire format defined separately from Rust struct. Section 3. |
| B2 | WAL framing incomplete | Added header_len: u16 + reserved_len: u16. total_len = full frame (magic..CRC). payload_len = payload only. Section 3. |
| B3 | schema_version ambiguous | Split into wal_format_version: u8 (=1) + event_schema_version: u8 (=3). Section 3. |
| B4 | Day-45 MVP too broad | Day-30 = 1 channel (Telegram) + WAL + recall + Left provider + Effect Adapter + YAML skill loader. WASM/WhatsApp/Slack/needle to Phase 2. Section 10. |
| B5 | Channel Ingress auth/replay/dedup/rate/quarantine/identity missing | Per-channel ingress security spec. Section 4. |
| B6 | FinalizeResponseArtifact untyped | Typed struct with ResponseBody enum + SafetyState enum. Section 5. |
| B7 | LOWKEY not versioned/hashable/auditable | version + content_hash + disabled_for_eval_sessions + prompt_bundle_hash per PROVIDER_REQUEST WAL event. Section 6. |
| B8 | Needle can bypass LLM for send/write intents | low_risk_intent allowlist defined. send/write MUST go to LLM or approval gate. Section 7. |
| B9 | WASM Plugin Host has no capability API | hostcall surface: fuel_limit, memory_max_bytes, timeout_ms, hostcall_allowlist. Phase 2 deliverable. Section 8. |
| B10 | subprocess.exec too broad | Removed. Named tools: subprocess.run.needle, subprocess.run.cloak_browser, subprocess.run.react_doctor. Section 9. |

### Non-Blocker Fixes

| # | Issue | Fix |
|---|-------|-----|
| NB1 | idx_episodic vs idx_episode inconsistent | All occurrences use idx_episode. |
| NB2 | Effect Adapters labeled Schicht-0 in channel diagram | Effect Adapters are Schicht-1 boundary throughout. |
| NB3 | "all 13 anti-patterns compliant" premature | Replaced with enforcement test plan. Section 11. |
| NB4 | Day-1 deps too heavy | Minimal Day-1 set defined. Section 12. |

---

## 2. Brain Region Table (idx_episode rename applied)

| Region | Index | Hard Invariant |
|--------|-------|----------------|
| Hippocampus | idx_episode | groups WAL events by 60-min windows, type:episode + concept-tags |
| Amygdala | idx_importance | importance_score + decay_policy REQUIRED |
| Insula | idx_council | council_round_id REQUIRED |
| Cerebellum | idx_motor | provider_id + latency_ns REQUIRED |
| Basal Ganglia | idx_habit | tool-router promotion/demotion + skill-keyword index |

WAL brain_region: u8 — 0=None, 1=Hippocampus, 2=Amygdala, 3=Insula, 4=Cerebellum, 5=Basal_Ganglia.
hemisphere field is separate: 0=N/A, 1=LEFT, 2=RIGHT, 3=CALLOSUM, 4=BOTH.


---

## 3. EventHeader v0.7 — Explicit Wire Format

### Rust Struct (logical representation — do NOT dump directly to disk)

```rust
#[repr(C)]
pub struct EventHeader {
    pub magic:                [u8; 4],   // b"AGNT"
    pub wal_format_version:   u8,        // = 1 (wire format version)
    pub event_schema_version: u8,        // = 3 (payload schema version)
    pub event_type:           u8,
    pub event_subtype:        u8,
    pub flags:                u8,        // bit0=TOMBSTONE bit1=SUPERSEDED bit2=SYNTHETIC bit3=REDACTED bit4=STREAM_PARTIAL
    pub brain_region:         u8,        // 0=None 1=Hippocampus 2=Amygdala 3=Insula 4=Cerebellum 5=Basal_Ganglia
    pub hemisphere:           u8,        // 0=N/A 1=LEFT 2=RIGHT 3=CALLOSUM 4=BOTH
    pub _pad0:                u8,        // write 0x00
    pub header_len:           u16,       // = 215 in v0.7
    pub reserved_len:         u16,       // = 0 in v0.7
    pub _pad1:                u8,        // write 0x00
    pub total_len:            u32,       // full frame: 4+header_len+reserved_len+payload_len+4
    pub payload_len:          u32,       // payload bytes only
    pub generation:           u32,
    pub event_id:             u64,
    pub ts_ns:                u64,       // Unix ns UTC
    pub importance:           f32,       // IEEE 754 LE
    pub scope:                u32,
    pub category:             u32,
    pub session_id:           [u8; 16],  // UUID v7 raw bytes
    pub node_id:              [u8; 16],  // UUID v7 raw bytes of originating node
    pub source_uri_hash:      u64,
    pub source_mtime_ns:      u64,
    pub content_hash:         [u8; 16],  // first 16 bytes of SHA-256
    pub chunk_id:             u32,
    pub chunk_range_start:    u32,
    pub chunk_range_end:      u32,
    pub embedding_model_id:   u8,
    pub _pad2:                u8,        // write 0x00
    pub embedding_dim:        u16,
    pub vector_blob_off:      u64,
    pub embedding_hash:       [u8; 16],
    pub parent_event_id:      u64,
    pub supersedes_event_id:  u64,
    pub prompt_bundle_hash:   [u8; 32],  // SHA-256(BlockA||B||C||D||E). Zero if not PROVIDER_REQUEST.
    pub _reserved:            [u8; 6],   // write zero; ignore on read
}
// header_len = 215 bytes in v0.7
```

### Wire Format — Little-Endian byte-by-byte serialization

Use `to_le_bytes()` / `from_le_bytes()` for every multi-byte field. Floats use IEEE 754 binary32 LE.
UUIDs stored as 16 raw bytes. Magic is 4 literal bytes (no endianness concern).

```
Offset   | Field                 | Size | Encoding
[0..4)   | magic                 |  4   | b"AGNT"
[4]      | wal_format_version    |  1   | u8 = 0x01
[5]      | event_schema_version  |  1   | u8 = 0x03
[6]      | event_type            |  1   | u8
[7]      | event_subtype         |  1   | u8
[8]      | flags                 |  1   | u8 bitfield
[9]      | brain_region          |  1   | u8 (0-5)
[10]     | hemisphere            |  1   | u8 (0-4)
[11]     | _pad0                 |  1   | 0x00
[12..14) | header_len            |  2   | u16 LE = 215
[14..16) | reserved_len          |  2   | u16 LE = 0
[16]     | _pad1                 |  1   | 0x00
[17..21) | total_len             |  4   | u32 LE
[21..25) | payload_len           |  4   | u32 LE
[25..29) | generation            |  4   | u32 LE
[29..37) | event_id              |  8   | u64 LE
[37..45) | ts_ns                 |  8   | u64 LE
[45..49) | importance            |  4   | f32 LE IEEE-754
[49..53) | scope                 |  4   | u32 LE
[53..57) | category              |  4   | u32 LE
[57..73) | session_id            | 16   | raw bytes
[73..89) | node_id               | 16   | raw bytes
[89..97) | source_uri_hash       |  8   | u64 LE
[97..105)| source_mtime_ns       |  8   | u64 LE
[105..121)| content_hash         | 16   | raw bytes
[121..125)| chunk_id             |  4   | u32 LE
[125..129)| chunk_range_start    |  4   | u32 LE
[129..133)| chunk_range_end      |  4   | u32 LE
[133]    | embedding_model_id    |  1   | u8
[134]    | _pad2                 |  1   | 0x00
[135..137)| embedding_dim        |  2   | u16 LE
[137..145)| vector_blob_off      |  8   | u64 LE
[145..161)| embedding_hash       | 16   | raw bytes
[161..169)| parent_event_id      |  8   | u64 LE
[169..177)| supersedes_event_id  |  8   | u64 LE
[177..209)| prompt_bundle_hash   | 32   | raw bytes SHA-256
[209..215)| _reserved            |  6   | 0x00
--- header ends at byte 215 (header_len = 215) ---
[215..215+reserved_len)           reserved extension (0 bytes in v0.7)
[215+reserved_len..end-4)         payload bytes
[end-4..end)                      CRC32c u32 LE (covers magic through last payload byte)

total_len = 4 + header_len + reserved_len + payload_len + 4
```

Version semantics:
- wal_format_version bumps on wire layout changes (add/remove/reorder fields). Current = 1.
- event_schema_version bumps on payload JSON/binary schema changes. Current = 3.
- Readers MUST check wal_format_version first. Reject versions above supported max.
  event_schema_version governs payload deserialization independently.


---

## 4. Channel Ingress Security Spec

Each webhook ingress implements all six controls before emitting WAL 0x24 CHANNEL_INBOUND.

### 4.1 Telegram

```
Signature:
  Header: X-Telegram-Bot-Api-Secret-Token
  Constant-time compare against configured secret_token value.
  Missing or mismatch -> HTTP 401, no WAL emit.

Replay window:
  message.date (Unix seconds) must be within [now-300s, now+300s].
  Outside window -> HTTP 200 (suppress Telegram retry storm), no WAL emit.

Dedup:
  key = sha256("telegram:" || message_id_string)
  Check in-memory bloom filter + idx_inbound_dedup SQLite.
  Hit -> HTTP 200, no WAL emit.
  Miss -> register in bloom + emit WAL 0x26 INBOUND_DEDUP_REGISTER.

Rate limits (token bucket):
  Per-channel: 1000 req/min.
  Per-user (raw_user_id): 60 req/min.
  Exceeded -> HTTP 429.

Attachment quarantine:
  Download to /tmp/agenter-quarantine/<uuid>/ before any pipeline access.
  Max 25 MB per file. Reject if content-length > 25MB or stream exceeds 25MB.
  Content-type allowlist: image/jpeg, image/png, image/gif, image/webp,
    audio/ogg, audio/mpeg, video/mp4, application/pdf, text/plain.
  Path stored in InboundMessage.attachments[].
  Downstream pipeline decides vault promotion.

Identity normalization:
  Telegram user_id (i64) + channel_id="telegram" -> lookup idx_human_identity.
  Not found: create UUID v7, insert (raw_user_id, channel_id, human_uuid).
  NO auto-merge across channels. Manual operator merge only.
```

### 4.2 WhatsApp (Phase 2)

```
Signature:
  Header: X-Hub-Signature-256: sha256=<hex>
  Compute HMAC-SHA256(app_secret, raw_body). Constant-time compare.
  Missing or mismatch -> HTTP 403.

Replay: message.timestamp Unix seconds, +-300s.

Dedup: key = sha256("whatsapp:" || message_id).

Rate limits: 500 req/min channel, 30 req/min per-user.

Attachment quarantine: same rules.
  WhatsApp media URL must be fetched within 30s of receipt or URL expires.

Identity: phone_number_id + channel_id="whatsapp" -> human_uuid.
  Never auto-merged with Telegram or Slack.
```

### 4.3 Slack (Phase 2)

```
Signature:
  Header: X-Slack-Signature: v0=<hex>
  Header: X-Slack-Request-Timestamp (Unix seconds)
  Replay check combined: |now - ts| > 300s -> reject.
  Compute HMAC-SHA256(signing_secret, "v0:" || ts || ":" || raw_body).
  Constant-time compare. Missing or mismatch -> HTTP 403.

Dedup: key = sha256("slack:" || event.event_id).

Rate limits: 500 req/min channel, 60 req/min per-user.

Attachment: Slack file URLs expire. Fetch immediately. Same size/type rules.

Identity: Slack user_id + channel_id="slack" -> human_uuid. Never auto-merged.
```

### 4.4 InboundMessage Normalized Schema

```rust
pub struct InboundMessage {
    pub inbound_id:  [u8; 16],         // UUID v7 (dedup anchor)
    pub channel_id:  ChannelId,
    pub human_uuid:  [u8; 16],
    pub raw_user_id: String,           // platform user_id (audit only)
    pub text:        Option<String>,
    pub attachments: Vec<QuarantinedPath>,
    pub reply_to_id: Option<String>,
    pub mentions:    Vec<String>,
    pub chat_meta:   serde_json::Value,
    pub received_at: u64,             // Unix ns
}
```

---

## 5. FinalizeResponseArtifact — Typed Schema

```rust
pub struct FinalizeResponseArtifact {
    pub channel:         ChannelId,
    pub recipient:       RecipientId,     // human_uuid + channel-specific handle
    pub reply_to:        Option<MessageId>,
    pub body:            ResponseBody,
    pub attachments:     Vec<MediaRef>,
    pub safety_state:    SafetyState,
    pub idempotency_key: [u8; 16],       // UUID v7 — Effect Adapter dedup
    pub trace_id:        TraceId,
}

pub enum ResponseBody {
    Text(String),
    Markdown(String),
    Image(MediaRef),
    File(MediaRef),
}

pub enum SafetyState {
    Clean,
    Refused(RefusalClass),    // 6 classes per SPEC_mirror_refusal.md
    Filtered(FilterReason),
    Limited(QuotaReason),
}

pub struct MediaRef {
    pub quarantine_path: Option<PathBuf>,
    pub content_type:    String,
    pub size_bytes:      u64,
    pub sha256:          [u8; 32],
}
```

Adapter logic (channel serialization, retry, error mapping) lives in the Effect Adapter.
The artifact is pure data — no behavior.
Only FinalizeResponseArtifact may reach channel-send Effect Adapters.
Raw strings from pipeline stages cannot directly invoke egress.


---

## 6. LOWKEY Versioning + Content Hash + Prompt Bundle Hash

### 6.1 Skill YAML additions (all LOWKEY skills)

```yaml
# ~/.agenter/skills/lowkey_base.yaml
skill_id: lowkey_base
version: 9.4.0                   # semver -- bump on any content change
content_hash: "<sha256_hex>"     # SHA-256(yaml_bytes || template_bytes), computed at load
mount:
  target: block_b
trigger:
  mode: always
  hemisphere_filter: any
  permission_required: None
content:
  inline: |
    [L.O.W.K.E.Y 9.4 Master-Prompt + Freedom Config]
    [DEBIAS: anti-smoothing, anti-loop, factual-anchoring]
    [POWER FIST: compression + pattern radar]
    [IMBA: directness + technical substance]
  max_tokens: 800
locality:
  sandboxed: true
  forbidden_side_effects: [filesystem, network, wal, oauth_vault]
```

content_hash = SHA-256(raw YAML file bytes || all inline template bytes concatenated).
Computed by YAML loader at startup. Exposed via `agenterctl skills list --hash`.

### 6.2 freedom.yaml additions

```toml
[lowkey]
enabled = true
disabled_for_eval_sessions = ["eval-001", "eval-002"]
janus_opt_in = false
```

When session_id starts with a prefix in disabled_for_eval_sessions:
- LOWKEY base stack NOT injected into Block B.
- WAL event 0x29 SKILL_INJECT_SKIPPED emitted with reason="eval_session_disable".

### 6.3 prompt_bundle_hash — per PROVIDER_REQUEST WAL event

Every PROVIDER_REQUEST WAL event (event_type=0x10) sets the prompt_bundle_hash field:

```
prompt_bundle_hash = SHA-256(Block_A_bytes || Block_B_bytes || Block_C_bytes || Block_D_bytes || Block_E_bytes)
```

Block B includes fully-rendered LOWKEY content when injected.
If LOWKEY skipped (eval session), Block B is shorter. Hash reflects actual bytes sent.
This enables replay-determinism: same hash = same prompt bundle, reconstructable from WAL.

All other WAL event types: prompt_bundle_hash = [0u8; 32].

---

## 7. Needle — low_risk_intent Allowlist

Needle (26M on-device router) MAY short-circuit the main LLM ONLY when ALL hold:
1. confidence >= configured threshold (default 0.7)
2. intent is in the allowlist below
3. tool exists in TOOL_CATALOG
4. FREEDOM authorization passes

### Allowlist

```toml
[needle.low_risk_intent_allowlist]
intents = [
    "recall.query",
    "vault.read",
    "status.check",
    "http.fetch.GET",           # GET only; URL must match whitelisted_url_patterns
    "schedule.cron.next_fire",  # read-only: returns next scheduled time
    "embed.encode",
    "concept_vocab_extract",
    "crc32c",
    "md_diff",
]

[needle.whitelisted_url_patterns]
patterns = [
    "https://api.github.com/*",
    "https://wttr.in/*",
]
```

### Blocked intents — MUST go to main LLM or operator approval gate

```
telegram.send, whatsapp.send, slack.send
vault.write, vault.delete
oauth.refresh, oauth.grant
http.post, http.put, http.delete, http.patch
subprocess.run.*
wal.emit (direct)
```

If needle classifies a blocked intent at high confidence:
- Emit WAL 0x27 NEEDLE_BLOCKED_INTENT with intent + confidence.
- Fall through to main LLM. LLM decides tool invocation subject to FREEDOM.

Operator approval gate: for any send/write bypassing LLM in future automation,
a WAL 0x2A OPERATOR_APPROVAL event must exist in current session with matching
tool + arguments hash, created by authenticated operator action.

---

## 8. WASM Plugin Host Capability API (Phase 2 Deliverable)

Day-30 MVP: YAML skill loader only. wasmtime NOT a Day-1 dependency.

### 8.1 Plugin Manifest

```toml
# plugins/needle/plugin.toml
[plugin]
id = "needle"
version = "0.1.0"
wasm = "needle.wasm"
phase = 2

[plugin.sandbox]
fuel_limit = 10_000_000       # WASM instruction cap (Cranelift fuel metering)
memory_max_bytes = 67_108_864 # 64 MiB
timeout_ms = 5000
hostcall_allowlist = ["log", "recall_read", "embed", "current_time"]

[plugin.permissions]
required = "ReadOnly"
oauth_vault_access = false
```

### 8.2 Hostcall Surface

All hostcalls log deterministically to WAL 0x28 PLUGIN_HOSTCALL.

```
log(level: u8, msg_ptr: u32, msg_len: u32) -> ()
  Writes to tracing log. No WAL side-effect beyond hostcall log entry.

recall_read(query_ptr: u32, query_len: u32, top_k: u32,
            out_ptr: u32, out_cap: u32) -> u32
  Read-only WAL recall. Returns bytes written.

embed(text_ptr: u32, text_len: u32, out_ptr: u32, out_cap: u32) -> u32
  Runs Qwen3 embedding. Returns f32 LE array length in bytes.

current_time_ns() -> u64
  Returns Unix nanoseconds (deterministic within session tick).
```

Prohibited (no hostcall exists):
- Filesystem access
- Network access
- Direct WAL writes
- Invoking other plugins or tools
- Any call not in plugin.sandbox.hostcall_allowlist

Memory: plugin gets one 64MiB linear memory. Host passes via ptr+len.
Plugin writes results into caller-provided buffer. No shared memory outside this protocol.

Fuel exhaustion -> WasmError::Trap -> agenterd emits PLUGIN_FUEL_EXHAUSTED WAL event
-> falls through to main pipeline. No crash, no panic.


---

## 9. Named Per-Command Subprocess Tools

`subprocess.exec` is REMOVED from the tool catalog.

### subprocess.run.needle

```yaml
tool_name: subprocess.run.needle
effect_adapter: true
idempotency_key: invocation_id
argv_schema:
  fixed: ["needle-cli"]
  positional:
    - name: model_path
      type: path
      source_env: NEEDLE_MODEL_PATH
    - name: query
      type: string
      max_len: 2048
  flags: []
cwd_policy: sandboxed_temp       # /tmp/agenter-needle-<uuid>/
env_allowlist:
  PATH: /usr/bin:/bin
  NEEDLE_MODEL_PATH: "${NEEDLE_MODEL_PATH}"
timeout_ms: 10000
stdout_cap_bytes: 65536
stderr_cap_bytes: 16384
secret_redact: true
audit_event_type: 0x28
```

### subprocess.run.cloak_browser

```yaml
tool_name: subprocess.run.cloak_browser
effect_adapter: true
idempotency_key: request_id
argv_schema:
  fixed: ["cloak-browser", "--headless", "--no-sandbox"]
  positional:
    - name: url
      type: url
      scheme_allowlist: [https]
      domain_allowlist_env: CLOAK_BROWSER_DOMAIN_ALLOWLIST
  flags:
    - name: screenshot
      flag: "--screenshot"
      type: bool
cwd_policy: sandboxed_temp
env_allowlist:
  PATH: /usr/bin:/bin:/usr/local/bin
  DISPLAY: "${DISPLAY}"
timeout_ms: 30000
stdout_cap_bytes: 1048576
stderr_cap_bytes: 262144
secret_redact: true
audit_event_type: 0x2B
```

### subprocess.run.react_doctor

```yaml
tool_name: subprocess.run.react_doctor
effect_adapter: true
idempotency_key: session_id
argv_schema:
  fixed: ["npx", "--yes", "react-doctor"]
  positional:
    - name: project_path
      type: path
      must_be_under_env: AGENTER_WORKSPACE_ROOT
  flags:
    - name: json
      flag: "--json"
      type: bool
      default: true
cwd_policy: project_path_arg
env_allowlist:
  PATH: /usr/bin:/bin:/usr/local/bin
  NODE_ENV: production
  HOME: "${HOME}"
timeout_ms: 60000
stdout_cap_bytes: 1048576
stderr_cap_bytes: 262144
secret_redact: true
audit_event_type: 0x2C
```

All three: env_allowlist is exhaustive (no inherited environment), outputs capped before WAL logging,
secrets redacted from stderr/stdout before logging.

---

## 10. Revised Phase Plan

### Phase 1 — Day 1-30: Lean Telegram-only MVP

| Day | Deliverable |
|-----|-------------|
| 1 | cargo workspace (minimal deps, Section 12). SOUL.md + freedom.yaml scaffold. panic handler. |
| 2 | WAL writer v2: explicit LE wire format, wal_format_version=1, event_schema_version=3, header_len+reserved_len, CRC32c, fsync group-commit, node_id |
| 3 | WAL reader v2: mmap, bad-magic repair-resync, version check, reject unknown wal_format_version |
| 4 | YAML loaders: B.5/C.1 tool + pipeline. LOWKEY skill loader with content_hash computation. |
| 5 | Claude CLI-OAuth adapter (Left Hemisphere stub) + 120s idle-kill |
| 6 | FREEDOM authorization layer |
| 7 | ChannelAdapter trait + InboundMessage. Telegram ingress: sig-verify, replay, dedup bloom, rate-limit, quarantine, identity-norm. Add teloxide here. |
| 8 | Telegram egress Effect Adapter (FinalizeResponseArtifact -> send, idempotency_key, WAL 0x25) |
| 9 | LOWKEY base stack auto-inject: versioned, content_hash, eval-disable, prompt_bundle_hash in WAL |
| 10 | idx_episode (Hippocampus: 60-min window grouping, episode summary events). Add rusqlite here. |
| 11 | idx_semantic SQLite view |
| 12 | Qwen3-Embedding-0.6B-Q8 via candle. Add candle-core + candle-transformers here. |
| 13 | VectorStore mmap-only (linear scan). Add memmap2 here. |
| 14 | Linear-scan top-k cosine recall |
| 15 | Hybrid Query-Planner (FTS + Vec + temporal-decay) |
| 16 | Amygdala importance-decay + DSPM formula |
| 17 | idx_dedup + REINFORCE events |
| 18 | session.start/end + idx_session |
| 19 | SESSION_LEDGER + session_resume pipeline |
| 20 | Effect Adapter layer: idempotency_key + audit + retry + exponential_jitter backoff |
| 21 | FinalizeResponseArtifact typed struct. finalize_response pipeline stage. |
| 22 | refusal_detect Schicht-0 tool (6 classes) |
| 23 | YAML skill loader (no WASM). Plugin YAML registry (empty, no wasmtime). |
| 24 | trajectory tracing + secrets redaction pipeline |
| 25 | Context-Engine 5-block assembler (Block A-E, prompt_bundle_hash computed) |
| 26 | respond_to_user pipeline (Left-only, no Council) |
| 27 | Health endpoint + agenterctl status + statusline |
| 28 | Anti-pattern enforcement test stubs: G.1-G.4, G.6-G.9, G.12, G.13 written RED. |
| 29 | Integration tests: Telegram round-trip (send/receive/WAL-verify) |
| 30 | **MVP DEMO**: Telegram working, LOWKEY active, recall working, Left-only response, WAL verifiable |

### Phase 2 — Day 31-60: Channels + Council + WASM

| Day range | Deliverables |
|-----------|-------------|
| 31-33 | WhatsApp ingress + egress. Add reqwest + ring (or hmac crate) here. |
| 34-35 | Slack adapter (socket mode). |
| 36-37 | Right Hemisphere (Gemini). G.1-G.4, G.6-G.9, G.12, G.13 tests GREEN. |
| 38-40 | Corpus Callosum (Codex). CouncilVerdict typed. Council debate pipeline (tick-gated). G.5 + G.10 GREEN. |
| 41-42 | MAGI ULTRA + OMEGA-PRIME as activatable Council skills. |
| 43-44 | Mirror-Refusal pipeline (per SPEC_mirror_refusal.md). |
| 45-46 | wasmtime Plugin Host: hostcall surface, fuel metering, memory cap, timeout. Add wasmtime here. |
| 47-48 | needle WASM plugin (opt-in, off by default). Allowlist enforcement. WAL 0x27 events. |
| 49-50 | CloakBrowser: subprocess.run.cloak_browser tool, opt-in. |
| 51-52 | Conductor 3-layer-context skill. Tailslayer dual-replica + IVF-index. |
| 53-54 | Basal Ganglia tool-router + skill keyword routing. mattpocock/skills seed (5 curated). |
| 55-56 | Dreaming-Pipeline (Light + REM). Memory-Integrity pipeline. |
| 57-58 | vault_sync pipeline (Obsidian nightly git). MCP server endpoint (mcp__agenter__*). |
| 59-60 | E2E tests: 3 channels x full pipeline x LOWKEY + Council. |

### Phase 3 — Day 61-90: Migration + Shadow + Cutover

- Multi-node WAL gossip-sync design (Veronica pattern, mTLS, per-node skill catalogs)
- Migration: 12 Jarvis stores -> AGENTER WAL (shadow-only)
- Eval-Goldset 100 queries
- Shadow-Run 14d (Telegram mirror)
- Recall-Parity target >= 0.85
- react-doctor coding skill
- Cutover

### Phase 4 — Day 91+: Ecology

- Ecology-Schicht (read-only, Framework E.5)
- MemPalace Hebbian graph
- Self-improvement loop (ACTIVE_MUTATIONS, ERL)
- Council-outcome tracking -> adaptive thresholds
- Tool-Genealogie
- G.11 enforcement test GREEN (Closed-Loop Ecology)


---

## 11. Anti-Pattern Enforcement Test Plan (G.1-G.13)

"All 13 anti-patterns compliant" claim replaced with a concrete scheduled test plan.

| Rule | Test Name | Target | Status |
|------|-----------|--------|--------|
| G.1 Stateful Tool | test_recall_query_is_pure_no_state | Day 28 stub -> Day 37 GREEN | stub RED |
| G.2 Self-Modifying | test_skill_spec_immutable_at_runtime | Day 28 stub -> Day 37 GREEN | stub RED |
| G.3 Goal-Seeking | test_no_retry_logic_in_schicht0_tools | Day 28 stub -> Day 37 GREEN | stub RED |
| G.4 Meta-Decision | test_pipeline_router_controls_flow_not_tools | Day 28 stub -> Day 37 GREEN | stub RED |
| G.5 Emergent Composition | test_council_trigger_is_deterministic | Phase 2 Day 40 | planned |
| G.6 Refusal-Umgehung | test_mirror_refusal_no_bypass | Day 28 stub -> Day 37 GREEN | stub RED |
| G.7 Scope-Inflation | test_locality_sandbox_rejects_out_of_scope | Day 28 stub -> Day 37 GREEN | stub RED |
| G.8 Starke Emergenz | test_tool_determinism_three_runs | Day 28 stub -> Day 37 GREEN | stub RED |
| G.9 Black-Box | test_cli_trace_in_every_provider_request_wal | Day 28 stub -> Day 37 GREEN | stub RED |
| G.10 Magic Scale | test_agreement_dimension_enum_not_cosine | Phase 2 Day 40 | planned |
| G.11 Closed-Loop Ecology | test_ecology_scanner_no_write_to_registry | Phase 4 Day 91 | planned |
| G.12 Level-Confusion | test_effect_adapters_are_schicht1_not_schicht0 | Day 28 stub -> Day 37 GREEN | stub RED |
| G.13 Bateson-III | test_no_identity_modification_in_tools | Day 28 stub -> Day 37 GREEN | stub RED |

Day-28: write 10 test functions with `todo!()` body and documented expected behavior.
Day-37: G.1-G.4, G.6-G.9, G.12, G.13 passing (GREEN).
G.5 + G.10 require Council (Phase 2 Day 40).
G.11 requires Ecology (Phase 4 Day 91).

---

## 12. Day-1 Minimal Cargo Dependencies

```toml
[dependencies]
tokio              = { version = "1", features = ["full"] }
serde              = { version = "1", features = ["derive"] }
serde_json         = "1"
tracing            = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
thiserror          = "1"
crc32c             = "0.6"
uuid               = { version = "1", features = ["v4", "v7"] }
xxhash-rust        = { version = "0.8", features = ["xxh3"] }
```

Added when the slice needs it (NOT before):

| Dep | Added at Day |
|-----|-------------|
| sha2 + hmac | Day 4 (LOWKEY content_hash) / Day 7 (channel sig-verify) |
| bloom crate | Day 7 (inbound dedup bloom filter) |
| memmap2 | Day 2 (WAL writer) |
| teloxide | Day 7 (Telegram adapter) |
| rusqlite | Day 10 (SQLite WAL views) |
| candle-core, candle-transformers | Day 12 (embedding) |
| reqwest | Day 31 (WhatsApp + Slack) |
| ring (or hmac) | Day 31 (HMAC-SHA256 for WhatsApp/Slack sig-verify) |
| rustls | Day 31 (TLS via reqwest feature flag) |
| wasmtime | Day 45 (Phase 2 WASM host) |

NOT on Day 1: ring, rustls, hyper, candle-*, wasmtime, reqwest, teloxide.
hyper is NOT added directly (comes through reqwest).
cargo build on Day 1 MUST complete in < 30s.
cargo tree MUST show only the 9 deps above on Day 1.

---

## 13. Pure Schicht-0 Tools vs Effect Adapters (Definitive)

**Pure Schicht-0 Tools** — deterministic, no side effects, locality-enforced:
```
recall.query
refusal_detect
embed.encode
council.should_trigger
council.round_controller
council.score_responses
council.synthesize
schedule.cron          (returns next-fire-time only, no execution)
md_diff
concept_vocab_extract
topk_heap
crc32c
freedom_check
```

**Effect Adapters** — Schicht-1 boundary, side-effect-ful, require idempotency_key:
```
telegram.send
whatsapp.send          (Phase 2)
slack.send             (Phase 2)
http.fetch             (outbound GET)
http.post              (outbound POST/PUT/DELETE)
wal.emit               (WAL append -- pipeline stages only, never from tools)
vault.write
vault.read             (filesystem I/O, not deterministic re: mtime)
oauth.refresh
oauth.grant
subprocess.run.needle
subprocess.run.cloak_browser
subprocess.run.react_doctor
```

Channel diagram (corrected from v0.6 Schicht-0 mislabel):

```
INGRESS (Gateway = Runtime, NOT Schicht-1)
  Telegram webhook
    -> sig-verify -> replay-check -> dedup-bloom -> rate-limit
    -> quarantine -> identity-norm
    -> InboundMessage
         |
         | WAL emit: 0x24 CHANNEL_INBOUND
         v
  Pipeline-Router (respond_to_user.yaml)
         |
         | FinalizeResponseArtifact
         v
  EGRESS Effect Adapter (SCHICHT-1 BOUNDARY)
    telegram.send
      idempotency_key=<uuid>, max_retries=3, backoff=exponential_jitter
         |
         | WAL emit: 0x25 CHANNEL_OUTBOUND
```

---

## 14. Files

```
PLAN/
  00_DESIGN_v0.7_FINAL.md       <- THIS (normative, replaces v0.6)
  00_DESIGN_v0.6_FINAL.md       <- historical record, locked, do not modify
  SPEC_mirror_refusal.md        <- locked
  SPEC_skill_plugin_system.md   <- update in Phase 2 for WASM hostcall surface
  SPEC_channels.md              <- update for per-channel ingress auth spec
  BLUEPRINT_v06_synthesis.md    <- locked (phase cuts superseded by v0.7 Section 10)
  tool_framework_v4_1.md        <- normative

SRC/ (empty -- Day-1: cargo new agenterd)
```

---

## 15. Day-1 Command (corrected from v0.6)

```bash
cd /path/to/AGENTER/SRC
cargo new agenterd
cd agenterd
cargo add tokio --features="full"
cargo add serde --features="derive"
cargo add serde_json
cargo add tracing
cargo add tracing-subscriber --features="env-filter"
cargo add thiserror
cargo add crc32c
cargo add uuid --features="v4,v7"
cargo add xxhash-rust --features="xxh3"
mkdir -p src/{wal,memory,channels,pipelines,tools,plugins,brain,context_engine}
mkdir -p ~/.agenter/{skills,plugins,memory}
touch ~/.agenter/soul.md
cat > ~/.agenter/freedom.yaml << 'YAML'
[lowkey]
enabled = true
disabled_for_eval_sessions = []
janus_opt_in = false

[permissions]
allow = []
YAML
printf 'fn main() {\n    println!("agenterd v0.7 -- Day 1");\n}\n' > src/main.rs
cargo build 2>&1 | tail -3
# Expected: Finished in < 30s.
# cargo tree should show only the 9 declared deps.
# NOT present: wasmtime candle ring rustls hyper reqwest teloxide
```

Day-2 starts WAL writer:
- LE serialization with explicit `to_le_bytes()` per field
- wal_format_version=1, event_schema_version=3
- header_len=215, reserved_len=0
- CRC32c over full frame (magic through last payload byte)
- node_id field populated from ~/.agenter/node.toml (create UUID v7 on first run)

