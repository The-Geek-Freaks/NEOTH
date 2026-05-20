# Architecture

How Neoth works under the hood. This is a high-level overview for users and operators.
Developers who want full spec detail should read the `PLAN/` directory.

---

## Block diagram

```
You
 |
 | (Telegram / WhatsApp / Slack / CLI)
 |
[Channel Adapter]
 |
 | InboundMessage
 |
[Gate Layer]         <-- allowlist check, mention check, command check
 |
 | (passes gate)
 |
[Pipeline Router]    <-- assembles context blocks A/B/C/D for the LLM
 |    |
 |    +--> [Recall]       <-- searches WAL for relevant past conversations
 |    |
 |    +--> [Profile]      <-- injects what Neoth knows about you (Phase 2)
 |    |
 |    +--> [Skills]       <-- injects relevant skill context (Day 23)
 |
 | assembled prompt
 |
[Left Hemisphere]    <-- Claude Opus (or configured cloud LLM)
 |                       The only hemisphere that talks to you.
 |
 | response
 |
[Channel Adapter]
 |
 | (Telegram / WhatsApp / Slack / CLI)
 |
You


Background (not on the critical path):
  [Profile Extractor]  <-- runs async after response; local Qwen3-4B (Phase 2)
  [Council Debate]     <-- fires when complexity + dissent gates pass (Phase 2)
  [WAL Compactor]      <-- nightly cleanup at 03:30
  [Profile Decay]      <-- nightly confidence decay at 03:30
```

---

## The WAL (Write-Ahead Log)

Everything Neoth does gets written to the WAL (write-ahead log) before it takes effect.
The WAL is an append-only event log stored at `~/.neoth/wal/`.

Every message in, every response out, every profile change, every council verdict — all
events. The WAL is the source of truth. Views (like `idx_profile`, `idx_episode`) are
derived from the WAL and can be rebuilt from scratch if needed.

Why append-only: you can't lose data you never deleted. You can audit what happened. You
can replay events to recover from corruption.

The WAL uses a 96-byte event header with a CRC checksum. If a frame is corrupted, Neoth
logs a WAL CRC error and recovers from the last valid checkpoint. See
[troubleshooting.md#wal-crc-errors](troubleshooting.md#wal-crc-errors).

Segments rotate at 256 MB or 24 hours, whichever comes first. Old segments are compacted
nightly (03:30). You can configure retention in `freedom.yaml`.

---

## Brain regions

Neoth organizes its memory into 7 named indexes. These are organized views over the WAL —
the names are analogies for how each type of memory behaves, not claims about AI consciousness.

| Region | Index | What it stores | Behavior |
|--------|-------|---------------|---------|
| Hippocampus | `idx_episode` | Recent conversation turns | Fast access, recent-biased |
| Amygdala | `idx_importance` | Importance scores per event | Weights recall ranking |
| Insula | `idx_council` | Council debate state | Council pipeline only |
| Cerebellum | `idx_motor` | Provider stats, quota tracking | Performance telemetry |
| Basal Ganglia | `idx_habit` | Skill trigger keywords, tool routing habits | Habit-based routing |
| Hypothalamus | `idx_profile` | Your learned profile (Phase 2) | Slow-changing, homeostatic |
| Visual Cortex | `idx_embedding` | Dense vector embeddings (CLIP image, future: audio/text) | Similarity search |

When Neoth searches past conversations (recall), it primarily queries Hippocampus and
uses Amygdala importance scores to rank results. Profile-aware ranking (Phase 2) adds
a bonus from Hypothalamus fields that match the current topic. `neoth recall --similar-to`
and `--similar-to-text` run a brute-force cosine scan over `idx_embedding` instead.

### idx_embedding — vector store

Schema v6 added `idx_embedding`. Each row is:

```
(source_kind, source_ref)  — natural key (UNIQUE); upsert replaces
model                      — which checkpoint produced the vector
embedding BLOB             — dim × 4 bytes, little-endian f32
dim INTEGER                — vector width; used as the filter in similarity queries
created_at INTEGER         — unix seconds
```

Embeddings are expected to be L2-normalised at insert time so similarity is a plain dot
product (no per-candidate division on the hot path). The brute-force scan walks every row
whose `dim` matches the query; HNSW / IVF is deferred until the corpus exceeds ~50k vectors.

Currently populated by the vision pipeline (`source_kind = "image"`, 512-dim CLIP ViT-B/32
vectors). Audio-segment and video-frame `source_kind` values are reserved for future
whisper-mel and video-frame embeddings.

---

## Multimodal pipeline

When a message arrives with an attachment (Telegram photo, voice, or audio message; or a
file ingested via `neoth ingest`), it travels through an extraction pipeline before the LLM
sees it:

```
Attachment bytes (in-memory or on-disk path)
 |
 | Asset { kind, mime, bytes | path }
 |
[MediaExtractor router]   route_to_first_match — first backend whose kind matches wins
 |
 +--[PdfExtractor]         pdfium text extraction + page count
 +--[VisionExtractor]      image decode (image crate) → RGB buffer
 |                          → CLIP ViT-B/32 forward pass → 512-dim L2-norm embedding
 |                          (embedding only if ~/.neoth/models/openai-clip-vit-base-patch32/ cached)
 +--[AudioExtractor]       decode to 16 kHz mono f32 → WhisperEngine.transcribe()
 |                          per-chunk language auto-detect → temperature fallback loop
 +--[VideoExtractor]       extract audio track → WhisperEngine; sample frames (future)
 |
 | Extraction { text, metadata { embedding?, extractor, ... } }
 |
[cli/ingest.rs]            persist embedding to idx_embedding (WAL 0x2C + 0x2D)
 OR
[cli/serve.rs]             ingest attachment inline; embedding persisted in handler
```

Two WAL events bracket a successful ingest:
- `0x2C INGEST_EXTRACTED` — text bytes, asset kind, model name, timestamp
- `0x2D EMBED_PERSISTED` — source_kind, source_ref, model, dim, timestamp

Both events are in the `0x20..=0x2F` LLM provider lifecycle band by current allocation.
They will migrate to a dedicated multimodal band when one is carved out.

### Model cache layout

Local inference models live under `~/.neoth/models/<repo-flattened>/`. The flattening
replaces `/` with `-` so `openai/clip-vit-base-patch32` becomes
`openai-clip-vit-base-patch32`. Each model directory contains the same three canonical
HuggingFace files:

```
~/.neoth/models/
  openai-clip-vit-base-patch32/
    config.json          (~1 KiB)
    model.safetensors    (~605 MiB)
    tokenizer.json       (~524 KiB)
  openai-whisper-large-v3-turbo/
    config.json
    model.safetensors    (~1.6 GiB)
    tokenizer.json
```

Models are pulled on-demand by `ClipEngine::new()` / `WhisperEngine::new()` (15-minute
HF Hub timeout) or proactively via `neoth models pull clip|whisper`. The engines mmap
the safetensors file; the SAFETY comment in both engines explains the concurrency contract
(read-only multi-process use is permitted; `neoth models pull` is a no-op against an
existing cache).

---

## Hysteria egress proxy

When `freedom.yaml` contains a `hysteria:` section with a non-empty `server`, `neothd
serve` spawns a `HysteriaSupervisor` before constructing any provider. The supervisor:

1. Writes the operator's config to `~/.neoth/hysteria/config.yaml` (deleted on drop).
2. Spawns `hysteria client --config <path>` as a subprocess.
3. Sets `NEOTH_HTTP_PROXY=socks5://127.0.0.1:<local_socks_port>` in the daemon's
   environment so providers constructed after this point route through the SOCKS5
   tunnel.

The config renderer (`transport::hysteria::render_yaml_config`) rejects newline and
control characters in `server` / `auth` to prevent YAML injection. Auth values are
redacted when `neoth hysteria render-config` prints to the terminal.

Binary lookup order: `$NEOTH_HYSTERIA_BIN` → `hysteria` on `$PATH` →
`~/.neoth/bin/hysteria[.exe]`. Missing binary is a hard error with an actionable message.

Phase 3b will route reqwest clients through the proxy; v0.1.x wires the subprocess and
sets the env but leaves provider-level SOCKS5 plumbing to a follow-up.

---

## Cloud archive mirror

NEOTH does not talk to Dropbox / GDrive / OneDrive APIs. The operator runs the cloud
vendor's desktop sync client and points `freedom.yaml::cloud_archive_dest` at the local
sync folder (e.g. `~/Dropbox`). The `cloud_sync_task` runs periodically (default 3600 s)
and mirrors `~/.neoth/archive/sessions/` into `<dest>/<subdir>/` using a copy-only,
skip-unchanged strategy. The cloud client handles transport.

`neoth cloud sync [--dest PATH] [--dry-run]` triggers an on-demand pass.
`neoth cloud status` prints the configured destination, subdir, and last-sync state.

Phase 2 follow-up: OpenDAL for direct API transport on headless servers.

---

## Cluster surface (R-7)

v0.1.x is single-node only. The cluster module exposes two policies (`LocalOnly` /
`LeastLoaded`) and the `OrchestratingPolicy::pick_peer` trait. `neoth cluster status`
always reports `single-node` / `local-only`. `neoth cluster plan --peers a:10,b:5`
dry-runs the routing decision without a real swarm.

Real peer discovery via Hyperswarm is deferred (see
`QUELLEN/research/R-A1_hyperswarm.md`). The CLI surface and policy trait are finalised
so the transport upgrade is additive.

---

## Context assembly

Before every LLM call, the Pipeline Router assembles a prompt from four blocks:

| Block | What goes in | Size limit |
|-------|-------------|-----------|
| A | System prompt, WAL metadata, session ID | ~500 tokens |
| B | Identity (soul.md), operational rules (claude.md), profile summary (Phase 2), active skills | ~1500 tokens |
| C | Recalled past conversations relevant to this query | ~2000 tokens |
| D | Per-request volatile context: skill triggers, tool outputs | ~1000 tokens |

The LLM never sees the raw WAL. It sees the assembled prompt. Recall results are selected
and formatted before inclusion.

---

## Tool-Framework v4.1 lineage

Neoth is built on the Tool-Framework v4.1 "Pflegbarer Garten" (maintainable garden) design.
The framework defines three layers (Tool / Pipeline / Ecology), five ingredients (Variation /
Constraints / Memory / Selection / Runtime), and 13 anti-patterns that Neoth's test suite
enforces.

The key guarantee: LLM tools are pure functions (stateless, deterministic given the same inputs).
State lives in the WAL. Pipelines orchestrate tools. The Ecology layer (Phase 4) observes and
does not mutate. This separation prevents tool drift and makes behavior auditable.

If you are a developer and want the full spec: `PLAN/tool_framework_v4_1.md`.

---

## Phase roadmap

| Phase | Timeline | Key additions |
|-------|----------|--------------|
| 1 (MVP) | Day 1-30 | Telegram + CLI + recall + Claude responses |
| 2 | Day 31-60 | WhatsApp + Slack + local model + profile learning + Council |
| 3 | Day 61-90 | Profile seed migration + eval framework + parity testing |
| 4 | Day 91+ | Drift detection + adaptive Council thresholds + Ecology layer |

Developer specs in `PLAN/00_DESIGN_v1.1_FINAL.md`.
