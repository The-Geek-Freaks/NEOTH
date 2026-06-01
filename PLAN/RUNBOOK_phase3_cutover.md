# RUNBOOK -- Phase 3 Cutover (Day 61-90)

> Status: Build-ready. No TBDs. Supersedes 6-bullet Phase 3 stub in 00_DESIGN_v0.7_FINAL.md Section 10.
> All WAL event codes, Rust types, command names match v0.7 wire format.

---

## Day 61-65: Pre-Migration Prep

### Day 61 -- Eval-Goldset Extraction

Extract 100 queries from live Jarvis transcripts.

Sources:
- ~/.claude/projects/*/sessions/*.jsonl (Claude CLI turns)
- ~/.openclaw/workspace/memory/*.md (OpenClaw session MDs)

Extraction script: eval/extract_goldset.py

Category split -- 4 x 25 queries:
- recall    25: e.g. "what did the operator say last Thursday about WiFi?"
- summarize 25: e.g. "summarize last week project work"
- action    25: e.g. "send the operator a reminder at 18:00"
- factual   25: e.g. "what is the Cube IP?"

Per query annotate:
- expected_sources: [event_id_1, event_id_2, event_id_3] -- top-3 expected Jarvis WAL event IDs
- expected_response_text: str -- reference answer (1-3 sentences)

Output: eval/goldset.jsonl (100 lines).
### Day 62 -- neothctl migrate-dry-run

Read-only scan of all 12 Jarvis stores. No WAL writes. Output: stdout + eval/dry-run-report.json.

Stores (from 02_MEMORY_LAYER_MAPPING.md):

| Store | Path | Expected |
|-------|------|----------|
| Obsidian Vault | /mnt/obsidian/Jarvis/**/*.md | ~1k files |
| Smart-Connections | .smart-env/multi/*.ajson | 1014 files |
| Hippocampus Core MD | ~/.openclaw/workspace/HIPPOCAMPUS_CORE.md | 1 file |
| Hippocampus index.json | ~/.openclaw/workspace/memory/index.json | rows |
| Hippo-Turbo vectors | ~/.openclaw/workspace/memory/hippo-turbo-vectors.json | JSON array |
| LanceDB-Pro | ~/.openclaw/memory/lancedb-pro | Arrow table |
| LanceDB-Pro Plugin | ~/.openclaw/plugins/memory-lancedb-pro | Arrow table |
| qmd | ~/.config/qmd/ | FAISS-style + bun-bin |
| OpenClaw Session-MD | ~/.openclaw/workspace/memory/*.md | session files |
| context-mode FTS5 | ~/.context-mode/ | SQLite |
| cq commons | ~/.cq/local.db | SQLite |
| github-backup | ~/github-backup/ | git working tree |

Report fields (dry-run-report.json):
- store_counts: per-store record counts
- dedup_pre_analysis: {estimated_unique, estimated_duplicates}
- vector_dimension_inventory: 1536d/1024d/768d/no_vector per store with count
- schema_drift_report: expected vs actual JSON keys per store

Operator reviews schema_drift_report before Day 63.

### Day 63 -- neoth migrate import

Language: Rust. Pure-Rust toolchain — no Python dependency.
Implementation: `crates/neoth-migrate` (Day-23 feature-gated bin alongside `neothd`).

Per-store parsers (all crates.io-available):
  - Markdown stores (Obsidian, Hippocampus, Session-MD)  -> pulldown-cmark
  - JSON stores (Smart-Connections .ajson, index.json,
    hippo-turbo-vectors.json)                            -> serde_json
  - LanceDB-Pro / Plugin Arrow tables                     -> lance (v0.20+, Arrow IPC)
  - qmd FAISS-style binary                                -> custom reader (~200 LOC)
  - context-mode FTS5, cq commons (SQLite)                -> rusqlite (bundled feature)
  - github-backup working tree                            -> git2

Output per store: migration-batch-N.jsonl (N = store index 1-12).
Each line = normalized NEOTH WAL event in pre-write JSON. **Every line MUST
carry `"_format_version": "internal-unstable"` as its first field** (Platform
Engineer review, OPEN_DECISIONS.md D-006) so a future v1.0 reader can refuse
files written against pre-1.0 schemas. Lines without the marker are rejected.

Fields:
  _format_version:"internal-unstable" (REQUIRED, first field),
  event_type:1 (RAW_TEXT), brain_region:1 (Hippocampus), importance:f32,
  scope:0, source_mtime_ns:u64, content_hash:[u8;16], text_payload:String,
  vector:Option<[f32;1024]>, embed_status:EMBED_PENDING

**Cross-platform text normalization (Platform Engineer review):** before any
hash, embedding, or dedup-key computation, text payloads MUST be normalized to
Unix line endings — `text = text.replace("\r\n", "\n").replace('\r', '\n')`.
Without this, a Markdown file imported on Windows and re-imported on Linux
produces different `content_hash` values for byte-identical content, breaking
the cross-platform dedup_key invariant.

Idempotency: dedup_key = SHA-256(normalized_text_bytes || scope_le32 || source_origin_ascii).
Check idx_dedup.bin. Hit -> emit REINFORCE (WAL 0x19), skip new event.
Re-running is a no-op for already-migrated content.

Importance reconciliation (from 02_MEMORY_LAYER_MAPPING.md):
  importance_new = max(
      importance_lance.unwrap_or(0.0),
      importance_hippo.unwrap_or(0.0),
      if in_smart_env { 0.5 } else { 0.0 },
      if reinforced_count > 5 { 0.4 } else { 0.0 },
      0.3,
  )

Concurrency: tokio multi-thread runtime, one task per store, bounded mpsc channel
to single WAL writer task (preserves append-only invariant from SPEC_wal_lifecycle.md).
Memory ceiling: 512 MiB resident; streams batches of 1024 events to disk before fsync.

### Day 64 -- Re-Embed Pipeline

All events where embed_status = EMBED_PENDING (non-1024d or missing vector).
- Model: Qwen3-Embedding-0.6B-Q8 via candle (same binary as production Day-12)
- Concurrency: 4 workers, batch size: 64
- State machine: EMBED_PENDING -> EMBED_IN_FLIGHT -> EMBED_DONE | EMBED_FAILED
- State tracked in eval/embed-status.jsonl

On EMBED_FAILED: log error, mark flags |= 0x20. Do not block pipeline.
After Day 64: neothctl migrate-dry-run --embed-check must show zero EMBED_PENDING.

### Day 65 -- Migration Smoke Test

Import 1 day of episodic data (Obsidian Daily + Session-MD + LanceDB rows).

Verification checklist (all must pass before Day 66):
1. neothctl wal verify --crc -- zero CRC failures
2. neothctl brain-regions --count -- all 5 regions non-zero
3. neothctl recall --query test -- >= 1 result with correct source event_id
4. neothctl dedup --report -- duplicate count matches Day-62 estimate +/- 10%
5. Manual spot-check: 3 events -- verify text, vector, importance

Any failure: fix root cause, re-run Days 63-65. Do NOT proceed to Day 66.

---

## Day 66-72: Shadow-Run Setup

### Day 66 -- pipelines/shadow_run.yaml

Telegram inbound webhook forks to two parallel branches.

Branch A (NEOTH): run respond_to_user. WAL 0x30 SHADOW_NEOTH_RESPONSE to
  eval/shadow-day-N/neoth-response.jsonl. Do NOT send to user.

Branch B (Jarvis): HTTP forward to openclaw-gateway localhost:18789.
  Send Jarvis response to user via telegram_egress_only.

Both branches run in parallel. Merge waits up to 35000ms.

Event 0x30 SHADOW_NEOTH_RESPONSE: response_text(str), trace_id(u64), latency_ns(u64).

### Day 67 -- Shadow-Run Start

  neothctl shadow start --days 14

Emits WAL event 0x31 SHADOW_RUN_STARTED:
  pub struct ShadowRunStarted {{start_day:u32, planned_end_day:u32,
      operator_uuid:[u8;16], permission_token_hash:[u8;32]}}

Hardware 2FA required (PermissionToken<Dangerous>).

### Day 68-71 -- Daily Review Pipeline

Cron at 04:00: neothctl shadow-diff --day N --output eval/shadow-day-N/divergence.md

Flags: Jaccard < 0.3 = significant divergence; empty/error = critical failure.

### Day 72 -- Mid-Shadow Checkpoint

Operator reviews eval/shadow-day-*/divergence.md for Days 67-71.

- recall_parity < 0.70 -> ABORT. WAL 0x32 SHADOW_RUN_ABORTED. Day-93 retry.
- recall_parity >= 0.85 -> Continue to Day 73.
- 0.70 <= recall_parity < 0.85 -> Operator decides. Default: continue heightened monitoring.

---

## Day 73-79: Shadow-Run Continue + Eval-Goldset

### Day 73-76 -- Goldset Daily Runs

Each day at 05:00: neothctl eval-goldset
  --goldset eval/goldset.jsonl --neoth-endpoint http://localhost:8888
  --jarvis-endpoint http://localhost:18789 --output eval/goldset-day-N.jsonl

### Day 77 -- 4-Grader Evaluation

Score (query x NEOTH_response) and (query x Jarvis_response) on 5 Likert (0-5):
- Grader A: Claude Opus 4.7
- Grader B: Codex GPT-5.5
- Grader C: Gemini 3.1 Pro
- Grader D: Mistral Large 2 OR DeepSeek-V3.5 OR Qwen2.5-72B-Instruct (external architecture — no Anthropic/OpenAI/Google lineage)

Grading prompt: eval/grading-prompt.md
Output: eval/grades-grader-A.jsonl, eval/grades-grader-B.jsonl, eval/grades-grader-C.jsonl, eval/grades-grader-D.jsonl
No cross-talk. Each API call: one (query, response) pair only.
Grader D is independent family-bias check: if A+B+C agree but D disagrees by >1 Likert, flag as family-prior collapse.

### Day 78 -- Inter-Rater Agreement

Cohens Kappa per dimension, pairwise across all 4 graders (AB, AC, AD, BC, BD, CD = 6 pairs), averaged per dimension.
- kappa < 0.60 -> rubric under-specified. Expand grading-prompt.md, redo Days 77-78.
- kappa >= 0.60 -> acceptable. kappa >= 0.80 -> strong.
- Pass condition: mean kappa >= 0.6 AND no individual pair < 0.4.
Output: eval/kappa-report.json with per-dimension kappa values and per-pair breakdown.

### Day 79 -- Decision Gate

Proceed to Day 80 ONLY if ALL hold:
  kappa-adjusted parity >= 0.85        eval/kappa-report.json
  No CRITICAL divergence 14d: 0 events eval/shadow-day-*/divergence.md
  WAL CRC failure rate < 0.01%         neothctl wal verify --since day-67
  NEOTH p95 recall latency < 8ms     neothctl perf --metric recall_p95
  No EMBED_FAILED remaining: 0         neothctl embed-status

If any fail: WAL event 0x33 CUTOVER_DEFERRED. Schedule Day-93 retry.

---

## Day 80: CUTOVER DAY

All times CET. Hardware 2FA device required.

### 08:00 -- Operator Authorization

  neothctl cutover authorize --operator <your-operator-id> --reason Day80 --2fa-mode yubikey

On success emits WAL event 0x2A CUTOVER_AUTHORIZED:
  pub struct CutoverAuthorized {{operator_uuid:[u8;16], operator_name:[u8;64],
    reason:[u8;256], authorized_at_ns:u64,
    expires_at_ns:u64,  // authorized_at_ns + 14_400_000_000_000
    permission_token_hash:[u8;32], totp_method:u8, _pad:[u8;7]}}

Authorization expires 4 hours after issuance.
3 auth failures -> 1h lockout -> WAL event 0x2D OPERATOR_AUTH_FAILED.

### 08:30 -- Jarvis State Snapshot

On debian VM (tgf@192.168.178.117):
  tar czf ~/backups/jarvis-pre-cutover-TIMESTAMP.tar.gz
    ~/.openclaw/ ~/.config/qmd/ ~/.context-mode/ ~/.cq/local.db /mnt/obsidian/Jarvis/

Verify > 5000 files. Upload to offline backup. Confirm receipt.
Backup path hash recorded in WAL 0x2A payload.

### 09:00 -- Stop Ingress

  systemctl --user stop openclaw-gateway openclaw-node
  setWebhook url= (Expected: ok:true) -- WAL event 0x34 INGRESS_STOPPED.

### 09:15 -- Queue Drain Verification

  neothctl shadow-diff --check-pending -- Expected: 0 pending

### 09:30 -- Switch Webhook to NEOTH

  setWebhook url=https://NEOTH_PUBLIC_ENDPOINT/webhook/telegram
    secret_token=NEOTH_TG_SECRET (Expected: ok:true) -- WAL 0x35 WEBHOOK_SWITCHED.

### 09:45 -- Cutover Test

Send cutover-test from personal Telegram. Must respond within 10s.
  neothctl wal tail --event-types 0x24,0x25 --last 60s
  Must see: CHANNEL_INBOUND (0x24) then CHANNEL_OUTBOUND (0x25) within 10s

If no response within 10s: execute Rollback Procedure immediately.

### 10:00 -- Enable Additional Channels (Phase 2 only)

  neothctl channels enable whatsapp (WAL 0x36 CHANNEL_ENABLED)
  neothctl channels enable slack (WAL 0x36 CHANNEL_ENABLED)
Skip if Phase 2 not complete. Only Telegram on Day 80.

### 10:30 -- Health-Check Pass

  neothctl status --full
Must show: all 5 brain-region views warm, no panics, Qwen3 loaded, FREEDOM responding, p95 < 8ms.

### 11:00 -- Cutover Complete

WAL event 0x37 CUTOVER_COMPLETE with parity score, shadow duration, event counts.
  chmod -R 0444 ~/.openclaw/workspace/memory/ ~/.openclaw/memory/lancedb-pro/
  (Executables and service configs NOT chmod-d)

---

## Day 81-86: Post-Cutover Hot-Watch

### 24/7 Alerting (neoth-monitor sidecar)

  WAL CRC failure -> WAL reader REPAIR event
  Recall p95 > 50ms for 5min -> 0x38 PERF_ALERT
  panic! -> 0x39 PANIC_EVENT
  Channel silence 30min 08:00-22:00 CET -> 0x3A CHANNEL_SILENT
  WAL CRC rate > 0.1%/day -> 0x3B CRC_RATE_ALERT

### Daily Review (Days 81-86 at 09:00)

1. OPERATOR_APPROVAL events (WAL 0x18) from previous day
2. 10 random recall queries against NEOTH + Jarvis cold-backup; compare
3. neothctl wal verify --since yesterday
4. EMBED_FAILED events from live ingestion?
Log to eval/hotwatch-day-N.md.

---

## Day 87-90: Stabilize + Phase 4 Prep

### Day 87-88 -- Migration Completeness Validation

  neothctl migrate-validate --source-stores all --wal ~/.neoth/wal/
    --report eval/migration-completeness.json

For each of 12 Jarvis stores: verify all records with createdAt before Day 63 are in WAL.
Acceptable gap: < 0.5% of total records.

### Day 89 -- Operator Sign-Off

Reviews: eval/migration-completeness.json, eval/hotwatch-day-81-88.md,
  WAL event counts by type, p95 recall latency trend Days 80-88.

Decision A: neothctl jarvis freeze --permanent -> WAL 0x3C JARVIS_FROZEN
Decision B: Rollback

### Day 90 -- Phase 3 Close

WAL event 0x3D PHASE3_COMPLETE.
  neothctl phase4 init --design-doc PLAN/SPEC_ecology_schicht.md
Ecology-Schicht read-only design starts Day 91 (v0.7 decisions Q8+N8).

---

## Rollback Procedure

### Trigger Conditions (any one sufficient)

  WAL CRC failure rate > 0.1%/day
  Recall p95 > 100ms sustained 15 minutes
  Panic events > 5 in any 24h window
  User-reported critical: data loss, wrong identity, wrong recipient
  Operator gut-call: unconditional

### Rollback Command

  neothctl rollback --to jarvis-pre-cutover
    --backup-path ~/backups/jarvis-pre-cutover-YYYYMMDD-HHMMSS.tar.gz
    --reason TEXT --2fa-mode yubikey

Same hardware 2FA as Cutover. Same 3-failure lockout.

### Rollback Steps (ETA: 30 minutes)

1. WAL event 0x2B ROLLBACK_INITIATED (reason, operator_uuid, backup_path_hash)
2. systemctl --user stop agenterd on all nodes (debian + Veronica 100.86.138.18)
3. Disable Telegram webhook: setWebhook url=
4. tar xzf jarvis-pre-cutover-*.tar.gz -C / on debian VM
5. systemctl --user start openclaw-gateway openclaw-node
6. Re-point Telegram webhook to openclaw-gateway endpoint
7. Send test message -- verify Jarvis responds within 10s
8. WAL event 0x2C ROLLBACK_COMPLETED (last event before NEOTH goes cold)

NEOTH stays stopped. Data preserved. Messages during cutover: eval/shadow-day-80+/*.jsonl.
Mandatory RCA in eval/rollback-rca.md before scheduling Day-93 retry.

---

## Operator Authentication Summary

Both Cutover and Rollback require PermissionToken<Dangerous> + hardware 2FA.

  [permissions.dangerous_ops]
  cutover_authorize = true; rollback_authorize = true; jarvis_freeze = true
  require_2fa = true; allowed_2fa_methods = [yubikey, totp]; totp_issuer = NEOTH

WAL: 0x2A CUTOVER_AUTHORIZED | 0x2B ROLLBACK_INITIATED | 0x2C ROLLBACK_COMPLETED | 0x2D OPERATOR_AUTH_FAILED

---

## Multi-Node (Veronica -- 100.86.138.18)

Shadow-run: debian primary only. Veronica observer mode Days 61-84.
WAL gossip-sync uses HLC ordering (see SPEC_multinode_clock.md).
Day 85: if cutover clean, Veronica promoted to hot-standby.
Veronica rollback: same neothctl rollback run separately on Veronica.

---

## Hermes Session-Recovery Pattern Applied

NEOTH startup runs idempotent WAL session recovery, adapted from
QUELLEN/hermes-webui/api/session_recovery.py recover_all_sessions_on_startup().

- Scan WAL for SESSION_START without SESSION_END
- Reconstruct from WAL events to last CRC-valid frame
- Emit 0x19 SESSION_RECOVERED or 0x1A SESSION_UNRECOVERABLE
- Idempotent: clean startup is a no-op

Key difference from Hermes: CRC-per-frame validation (not message-count comparison).
Corrupt frames: skipped via bad-magic resync (Day-3 WAL reader).
