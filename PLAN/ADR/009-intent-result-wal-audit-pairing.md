# ADR-009 — INTENT/RESULT WAL audit-event pairing for effectful operations

- **Status:** Accepted (2026-06-08, Session 45)
- **Relates to:** GOLD plan `PLAN/ROAD_TO_1_0_GOLD.md`; operator directive 2026-06-08

## Context

NEOTH's WAL is its primary tamper-evident audit trail. All security-relevant frames are fsynced immediately (neothd/src/wal/events.rs:1640, `needs_immediate_sync`). The daemon performs five classes of operations that are externally visible, irreversible, or security-relevant:

1. **OS tools** (file read/write, app launch, clipboard) — gated at `neothd/src/os_tools/gate.rs`. Already emits post-effect-only frames: `0xA8 OS_FILE_READ`, `0xAA OS_FILE_WRITE`, `0xAC OS_APP_LAUNCH`, `0xBC OS_CLIPBOARD_ACCESS` on success; `0xA9`, `0xAB`, `0xAD`, `0xBD` on denial (gate.rs:111–327, 347–511).

2. **Channel egress** (reply send path) — `neothd/src/channels/send_gate.rs` implements `decide_channel_send` (send_gate.rs:56–72) and emits `0x33 CHANNEL_EGRESS` (post-send), `0x67 CHANNEL_SEND` (send-governance, post-send), `0x3A PROACTIVE_SENT` (post-send). No frame is emitted before the adapter is invoked.

3. **Media** — `neothd/src/media/video_dispatch.rs:113` emits `0xC9 VIDEO_FRAME_SYNTHESIZED` after the cloud call returns; `neothd/src/media/stt_provider.rs:366` emits `0xCC STT_TRANSCRIBED` after the STT call completes; `neothd/src/media/tts_cloud.rs:292` emits `0xCD TTS_SYNTHESIZED` after TTS. All are post-hoc, single events.

4. **Self-update** — `neothd/src/cli/update.rs:240,286` and `neothd/src/daemon/auto_update.rs:249,268` emit a single `0xD2 SELF_UPDATE_APPLIED` AFTER `atomic_replace_binary` succeeds (self_update.rs:515–539). There is no frame emitted before the download begins, before SHA-256 verification, or before the atomic rename. `0xD7 MODEL_DOWNLOAD_START` / `0xD8 MODEL_DOWNLOAD_COMPLETE` (events.rs:1397–1404) are a partial INTENT/RESULT pair for HuggingFace model pulls, but these do not cover the daemon self-binary replacement.

5. **File write** (OS-tool surface) — same as class 1: `0xAA OS_FILE_WRITE` is emitted post-write at gate.rs:241–249, with no frame before the `write_file_atomic` call.

The pattern throughout is: **one post-hoc frame**, emitted after the effect has occurred. This means a daemon crash between the start of the effectful operation and its WAL frame leaves the audit trail with a silent gap: the operation may have happened (binary replaced, file written, message sent) with no durable evidence.

The existing `0xF2 PRE_MUTATION_SNAPSHOT` (events.rs:1832) already proves the INTENT-before-effect pattern works in production: `wal::snapshot::emit_snapshot` (`wal/snapshot.rs:155`) is its live producer, documented with the exact contract *"The mutation MUST NOT run until this call returns Ok — otherwise the audit anchor is missing and rollback for that mutation is impossible"*, and `cli/rollback.rs` + `cli/checkpoint.rs` consume it to reconstruct pre-mutation state. **But** it is a single GENERIC anchor with an opaque `mutation_kind` string, scoped to rollback-able mutations only — it is not per-class typed, carries no paired RESULT frame, and `neoth wal show --type pre_mutation_snapshot` cannot filter it by effect class. So the INTENT half is already a proven, load-bearing mechanism for one subsystem; this ADR generalises that discipline to the five externally-visible effect classes with typed, paired codes.

## Decision

For the five effect classes — OS file-write, channel egress, media cloud calls, self-update, and OS app-launch — the standard WAL audit shape becomes a typed **INTENT/RESULT pair**:

- An `*_INTENT` frame is emitted **before** the external call / filesystem mutation begins, and is written with `needs_immediate_sync = true`.
- A `*_RESULT` frame is emitted **after** the call completes (success or failure), also immediate-sync.

**Naming convention:** `EVENT_TYPE_<OP>_INTENT` / `EVENT_TYPE_<OP>_RESULT`. The INTENT frame carries enough context to identify what was attempted (target path/hash, provider, channel, component+version). The RESULT frame carries the outcome (bytes written, status, error kind). Both frames share a stable correlation field (`op_id` — a u64 generated at the call site before the INTENT is emitted) so a WAL replay can pair them without full-scan ordering.

The five concrete new event pairs to allocate (next free slots in appropriate bands):

| Class | INTENT code | RESULT code | Band |
|---|---|---|---|
| OS file-write | `0xBE OS_FILE_WRITE_INTENT` | `0xBF OS_FILE_WRITE_RESULT` | 0xB0-overflow (existing precedent: 0xBC/0xBD clipboard) |
| Channel egress | `0x69 CHANNEL_SEND_INTENT` | `0x6A CHANNEL_SEND_RESULT` | 0x60-governance band (existing: 0x67/0x68 CHANNEL_SEND/DENIED) |
| Media cloud call | `0xF6 MEDIA_CALL_INTENT` (GR-079: `0xCF` is already `RISK_GATE_BLOCKED` and the **entire 0xC0 tool band is full** — the INTENT moves to the 0xF6+ overflow band) | promote existing `0xC9/0xCC/0xCD` to RESULT role with an `op_id` field added | 0xF6+ overflow (0xC0 band full) |
| Self-update apply | `0xDA SELF_UPDATE_INTENT` (already taken by PRESET_APPLIED) → use `0xDE SELF_UPDATE_APPLY_INTENT` | promote existing `0xD2 SELF_UPDATE_APPLIED` to RESULT role with `op_id` field | 0xD0 config-lifecycle band |
| OS app-launch | `0xBE` is now file-write; `OS_APP_LAUNCH_INTENT` deferred to next free 0xB slot | — |

For backwards compatibility, existing `*_APPLIED` / `*_SYNTHESIZED` / `*_WRITE` frames are KEPT as-is and promoted to the "RESULT" semantic — they gain an `op_id` field. New INTENT frames are added before each call site. Crash detection: on startup, a WAL scanner checking for an INTENT frame with no paired RESULT frame within the same segment can surface it as a `0x50 RECOVERY_TRUNCATED`-style alert; this is the canonical "operation was in-flight when the daemon crashed" signal.

## Consequences

**Positive:**
- A daemon crash between INTENT and RESULT is detectable: an unpaired INTENT in the WAL is forensic proof that an operation was initiated and not confirmed complete.
- Enables `neoth wal show --type os_file_write_intent` to show every write attempt, including those that crashed mid-flight.
- Consistent pattern across effect classes removes per-class audit-coverage ambiguity.
- Operators running `neoth verify` can detect crashes that corrupted the self-update binary replacement sequence.
- Aligns with the existing partial INTENT/RESULT pattern already present for local inference (`0x2A LOCAL_INFERENCE_START` / `0x2B LOCAL_INFERENCE_END`, events.rs:224–231) and HF model downloads (`0xD7 MODEL_DOWNLOAD_START` / `0xD8 MODEL_DOWNLOAD_COMPLETE`, events.rs:1397–1404).

**Negative:**
- WAL event budget: each effectful operation now writes 2 immediate-sync frames instead of 1. For high-cadence channel sends this doubles the fsync calls on the egress path. Mitigation: INTENT frames for read-only OS calls (OS_FILE_READ) are excluded — only write/launch/send/update operations need pairs.
- The WAL band allocation table (events.rs:12–34) is nearly full in several bands (0xB0-0xBF: 4 slots remaining; 0xD0-0xDF: 0xDE/0xDF free; 0x60-0x6F: 0x69-0x6F free). Adding 5 new INTENT codes requires careful band placement; two classes require overflow or band-extension.
- Existing WAL consumers (`neoth wal show`, pattern_cron, profile extractor) must be updated to handle the new INTENT codes without treating them as unknown/corrupt frames.
- The `op_id` correlation field adds ~9 bytes to every INTENT and RESULT payload; tolerable at 2 frames per operation.

## Alternatives considered

**Alternative 1: Single post-hoc event (current state, rejected).** All five classes currently use this pattern. Rejected because a crash between operation start and WAL write leaves a silent audit gap with no detection path.

**Alternative 2: Two-Phase Commit (rejected).** A full 2PC protocol (prepare, commit, rollback) would guarantee atomicity but requires distributed-coordinator machinery, rollback logic per effect class, and a lock-step interaction with external systems (messaging APIs, filesystems) that do not support 2PC. Disproportionate complexity for the goal of tamper-evident audit; the existing `atomic_replace_binary` (self_update.rs:515) already handles the filesystem-atomic case.

**Alternative 3: Reuse 0xF2 PRE_MUTATION_SNAPSHOT for all five classes (rejected, but it stays for its own role).** `EVENT_TYPE_PRE_MUTATION_SNAPSHOT = 0xF2` (events.rs:1832) is the proven INTENT anchor for the rollback subsystem (producer `wal::snapshot::emit_snapshot`, consumers `cli/rollback.rs` + `cli/checkpoint.rs`). Broadening it to cover channel/media/self-update/app-launch was considered. Rejected because it uses an opaque `mutation_kind` string, so `neoth wal show --type pre_mutation_snapshot` would return heterogeneous frames that cannot be filtered per effect class, and it carries no paired RESULT. Typed per-class pairs are preferred. This ADR does NOT supersede 0xF2 — it keeps its rollback-anchor role intact and adds typed pairs alongside it for the five effect classes (a file-write effect may legitimately emit BOTH a 0xF2 rollback anchor and a `0xBE OS_FILE_WRITE_INTENT`).

**Alternative 4: Write INTENT only for self-update and file-write; skip channel/media (partial approach, considered but not adopted).** The crash-window risk is highest for the self-update binary-replace path (silent overwrite of the running daemon) and file-writes (potential data loss). Limiting pairs to only these two would reduce WAL budget pressure. Not adopted because the same crash-window argument applies to channel sends (a message sent but not audited is an undetectable privacy event) and media cloud calls (audio/video leaving the device with no WAL anchor).

## Compliance audit

**Class 1 — OS file-write:**
- Current: `emit_write` emits `0xAA OS_FILE_WRITE` AFTER `write_file_atomic` at gate.rs:241–249. `emit_write_denied` emits `0xAB OS_FILE_WRITE_DENIED` before returning on any refusal (gate.rs:202, 211, 223, 253). No INTENT frame before `write_file_atomic` at gate.rs:240.
- Gap: a crash inside `write_file_atomic` leaves no WAL evidence the write was attempted.
- What INTENT/RESULT adds: `0xBE OS_FILE_WRITE_INTENT` emitted at gate.rs:239 (after the autonomy gate passes, before `write_file_atomic` is called). Existing `0xAA` promoted to RESULT role with `op_id` field.

**Class 2 — Channel egress:**
- Current: `0x33 CHANNEL_EGRESS` is emitted post-send at webhook_listener.rs:899,937 and n8n_api/handlers.rs:486. `0x67 CHANNEL_SEND` is emitted by the send-governance path in the same locations. The `decide_channel_send` function in send_gate.rs:56–72 is pure (no WAL side-effect). No frame is written before the adapter's HTTP call is made.
- Gap: a crash during the adapter HTTP POST (WhatsApp, Telegram, Slack) leaves no WAL evidence that a send was attempted. `0x3A PROACTIVE_SENT` (events.rs:342) is post-send only.
- What INTENT/RESULT adds: `0x69 CHANNEL_SEND_INTENT` emitted after `decide_channel_send` returns `Send`, before the adapter's network call. Existing `0x33 CHANNEL_EGRESS` / `0x67 CHANNEL_SEND` promoted to RESULT role with `op_id`.

**Class 3 — Media cloud calls:**
- Current: `0xC9 VIDEO_FRAME_SYNTHESIZED` at video_dispatch.rs:113 is emitted after the provider call returns. `0xCC STT_TRANSCRIBED` at stt_provider.rs:366 and `0xCD TTS_SYNTHESIZED` at tts_cloud.rs:292 are both post-hoc. There is no INTENT frame before any cloud media call.
- Gap: a crash during a multi-second video/STT/TTS cloud call leaves no WAL evidence that audio/video/text left the device.
- What INTENT/RESULT adds: `0xF6 MEDIA_CALL_INTENT` (GR-079: NOT `0xCF`, which is `RISK_GATE_BLOCKED`; the 0xC0 band is full) emitted before every cloud media dispatch (video_dispatch.rs, stt_dispatch.rs, tts_dispatch.rs). Existing `0xC9`, `0xCC`, `0xCD` gain `op_id` field and become the RESULT frames.

**Class 4 — Self-update:**
- Current: `0xD2 SELF_UPDATE_APPLIED` is emitted at cli/update.rs:240,286–344 and daemon/auto_update.rs:249,268 AFTER `atomic_replace_binary` (self_update.rs:678,844) completes. `0xD7 MODEL_DOWNLOAD_START` / `0xD8 MODEL_DOWNLOAD_COMPLETE` form a partial pair for HF model pulls (events.rs:1393–1404) but do NOT cover the daemon binary replace path.
- Gap: a crash during `atomic_replace_binary` (which performs rename of the running binary) leaves no WAL evidence that a self-replace was in progress. The binary on disk may be in a partial/backup state.
- What INTENT/RESULT adds: `0xDE SELF_UPDATE_APPLY_INTENT` emitted in cli/update.rs and daemon/auto_update.rs immediately before the `apply_downloaded`/`apply_from_staged`/`atomic_replace_binary` sequence begins. Existing `0xD2 SELF_UPDATE_APPLIED` gains `op_id` and becomes the RESULT frame.

**Class 5 — OS app-launch:**
- Current: `0xAC OS_APP_LAUNCH` emitted at gate.rs:311–313 AFTER `launch_program` returns its PID. `0xAD OS_APP_LAUNCH_DENIED` emitted on any refusal path. No INTENT before `launch_program` at gate.rs:311.
- Gap: a crash between `launch_program` call and WAL write leaves no evidence a process was spawned. The process may be running.
- What INTENT/RESULT adds: `OS_APP_LAUNCH_INTENT` emitted after the autonomy gate passes, before `launch_program` is called (gate.rs:310). Band overflow placement (next free slot in 0xB0-0xBF beyond 0xBF, or new band allocation needed; 0xBE = OS_FILE_WRITE_INTENT, 0xBF = OS_FILE_WRITE_RESULT, so app-launch intent may require 0xC0-band carve-out).

**Partial prior art in the codebase (compliant examples):**
- `0x2A LOCAL_INFERENCE_START` / `0x2B LOCAL_INFERENCE_END` (events.rs:224–231): a correct INTENT/RESULT pair for local Qwen3 inference.
- `0xD7 MODEL_DOWNLOAD_START` / `0xD8 MODEL_DOWNLOAD_COMPLETE` (events.rs:1393–1404): a correct INTENT/RESULT pair for HF model downloads.
- `0x05 TURN_JOURNAL_OPENED` / `0x06 TURN_JOURNAL_CLOSED` (events.rs:54–61): a correct INTENT/RESULT pair for turn recovery.
These three pairs already satisfy ADR-009; their code should be cross-referenced in the implementation guide as model examples.

## References

- neothd/src/wal/events.rs:36-2208 (full event registry)
- neothd/src/wal/events.rs:1640 (needs_immediate_sync)
- neothd/src/os_tools/gate.rs:111-327 (OS file-read/write gate + emit sites)
- neothd/src/os_tools/gate.rs:265-327 (OS app-launch gate)
- neothd/src/channels/send_gate.rs:56-72 (decide_channel_send — no WAL side-effect)
- neothd/src/channels/webhook_listener.rs:899,937 (CHANNEL_EGRESS emit sites)
- neothd/src/n8n_api/handlers.rs:486 (CHANNEL_EGRESS emit site)
- neothd/src/media/video_dispatch.rs:113 (VIDEO_FRAME_SYNTHESIZED emit — post-hoc)
- neothd/src/media/stt_provider.rs:366 (STT_TRANSCRIBED emit — post-hoc)
- neothd/src/media/tts_cloud.rs:292 (TTS_SYNTHESIZED emit — post-hoc)
- neothd/src/cli/update.rs:240,286-344 (SELF_UPDATE_APPLIED emit — post-hoc)
- neothd/src/daemon/auto_update.rs:249,268 (SELF_UPDATE_APPLIED staged emit — post-hoc)
- neothd/src/updater/self_update.rs:515-539 (atomic_replace_binary — no pre-INTENT)
- neothd/src/wal/events.rs:1832 (0xF2 PRE_MUTATION_SNAPSHOT — the existing INTENT anchor; kept for rollback, complemented not superseded)
- neothd/src/wal/snapshot.rs:155 (emit_snapshot — live 0xF2 producer with the INTENT-before-mutation contract)
- neothd/src/wal/events.rs:224-231 (0x2A/0x2B LOCAL_INFERENCE_START/END — compliant prior art)
- neothd/src/wal/events.rs:1393-1404 (0xD7/0xD8 MODEL_DOWNLOAD_START/COMPLETE — compliant prior art)
- neothd/src/wal/events.rs:54-61 (0x05/0x06 TURN_JOURNAL_OPENED/CLOSED — compliant prior art)
- ADR-006 (ecology-council adaptation hook — same WAL-event discipline)
