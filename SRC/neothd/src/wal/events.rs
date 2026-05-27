// Compile-time band invariants below use `let _ = [(); 1][(...) as usize]`
// to trip a const-eval index OOB on bad assignments — that pattern
// intentionally creates unit-typed let-bindings.
#![allow(clippy::let_unit_value)]

//! WAL event-type registry.
//!
//! Centralises every `event_type` byte used across the daemon. Keeping these
//! in one place prevents collisions and makes the spec-vs-code audit (see
//! `PLAN/OPEN_DECISIONS.md` D-006) tractable.
//!
//! ## Range allocation table (LOCKED — Phase 33a AU-B2)
//!
//! Every event-code MUST claim a band. Adding a code outside the registered
//! bands is a hard error. New bands must be appended to this table before any
//! constant is added.
//!
//! | Range          | Purpose                                                |
//! |----------------|--------------------------------------------------------|
//! | `0x01..=0x0F`  | Memory + recall (RAW_TEXT, REINFORCE, …)               |
//! | `0x10..=0x1F`  | Daemon lifecycle (BOOT, SHUTDOWN, UPDATE_RAN, …)        |
//! | `0x20..=0x2F`  | LLM provider lifecycle (REQUEST/RESPONSE/ERROR/STREAM) |
//! | `0x2A..=0x2B`  | (reserved Phase 10 D14b) local Qwen3 inference trace   |
//! | `0x30..=0x3F`  | Channels (ingress/egress/error + sanitizer)            |
//! | `0x40..=0x4F`  | Cron / scheduled jobs                                  |
//! | `0x50..=0x5F`  | (reserved) panic / recovery                            |
//! | `0x60..=0x6F`  | Council debate + callosum (CH-08)                      |
//! | `0x70..=0x7F`  | (reserved)                                             |
//! | `0x80..=0x8F`  | (reserved Phase 29) Hooks lifecycle                    |
//! | `0x90..=0x9F`  | Memory tiers (R-22..R-24) — consolidation, decay, GT   |
//! | `0xA0..=0xAF`  | Permissions / autonomy (R-23)                          |
//! | `0xB0..=0xEF`  | (reserved)                                             |
//! | `0xF0..=0xFF`  | Operator / system (QUOTA_BREACHED, …)                  |

// ---- 0x01..=0x0F  Memory + recall -----------------------------------------

/// Raw user-supplied text. The baseline content event.
pub const EVENT_TYPE_RAW_TEXT: u8 = 0x01;
/// Reinforcement of a previously seen content_hash (dedup hit).
///
/// Moved from `0x19` to `0x02` in Phase 33a (AU-B1) — `0x19` lived in the
/// lifecycle band and collided with the R-22 0x9X memory-tier allocation
/// downstream of this fix.
pub const EVENT_TYPE_REINFORCE: u8 = 0x02;

/// R-01 (Session 24) — operator opened a Turn-Journal for one
/// `neoth chat` invocation. The companion JSONL file at
/// `~/.neoth/journals/<turn_id>.jsonl` records mid-stream provenance
/// (prompt → provider call(s) → partial chunks → final response) so
/// a crash between OPENED and CLOSED leaves enough state on disk for
/// the next launch's recovery flow to decide retry / discard / surface
/// the partial. Payload carries the turn_id + journal_path + ts_unix.
pub const EVENT_TYPE_TURN_JOURNAL_OPENED: u8 = 0x05;

/// R-01 (Session 24) — companion to `EVENT_TYPE_TURN_JOURNAL_OPENED`.
/// Emitted when a `neoth chat` turn completes cleanly + the JSONL
/// file has been deleted. A journal sitting on disk without a
/// matching CLOSED frame is the canonical "crash recovery candidate"
/// signal that `neoth recover` consumes.
pub const EVENT_TYPE_TURN_JOURNAL_CLOSED: u8 = 0x06;

// ---- 0x10..=0x1F  Daemon lifecycle ----------------------------------------

/// Daemon successfully started + opened its WAL.
pub const EVENT_TYPE_BOOT: u8 = 0x10;
/// Daemon received a shutdown signal and is draining.
pub const EVENT_TYPE_SHUTDOWN: u8 = 0x11;
/// D3b-7 (2026-05-22 Session 20): a NEOTH-managed CLI (claude-cli,
/// antigravity-cli, codex) was first-time-installed by `neoth init`
/// wizard step 5 OR `neoth update --apply`. Historical frames may
/// carry `gemini-cli` in `cli_name` — that name was retired
/// 2026-05-19 in favour of antigravity-cli (binary `agy`). Distinct
/// from `UPDATE_RAN` (0x13) which fires on later version bumps —
/// `INSTALLER_RAN` fires when the binary first lands on PATH.
/// Payload: `{ cli_name, version, login_state, ts_unix }`.
pub const EVENT_TYPE_INSTALLER_RAN: u8 = 0x12;
/// A NEOTH-managed component (claude-cli, antigravity-cli, codex,
/// obsidian, ...) was upgraded by the auto-update task or
/// `neoth update --apply`. Historical frames may name the legacy
/// `gemini-cli` component — Component's serde alias maps both
/// strings to the same variant.
/// Payload: `{ component, old_version, new_version, status, ts }`.
pub const EVENT_TYPE_UPDATE_RAN: u8 = 0x13;
/// WAL segment rolled over (rotated). Emitted by the writer just before
/// switching to a new segment file. Payload:
/// `{ closed_seq, closed_bytes, opened_seq, opened_path, reason }`.
/// Phase 33b SP-1.
pub const EVENT_TYPE_SEGMENT_ROLLOVER: u8 = 0x14;
/// HMAC compaction marker. Emitted periodically (every N frames or T
/// seconds) and contains an HMAC-SHA256 over every frame written since
/// the previous marker. Tamper detection: a downstream reader recomputes
/// the HMAC from the bytes-on-disk and compares. Phase 33b SP-2.
/// Payload: `{from_offset, to_offset, frame_count, hmac_hex, ts_ns}`.
pub const EVENT_TYPE_COMPACTION_MARKER: u8 = 0x15;

/// Mirror-refusal pipeline (SPEC_mirror_refusal.md). v0.1.x ships the
/// detector at `security::refusal_detect`; the full pipeline that
/// emits these events lands when the daemon's chat loop integrates
/// the classifier on every provider response.
///
/// `0x16 REFUSAL_OBSERVED` — Schicht-0 detector classified an
/// assistant response as one of the six refusal categories. Payload:
/// `{refusal_class, confidence, matched_patterns[], response_hash}`.
pub const EVENT_TYPE_REFUSAL_OBSERVED: u8 = 0x16;
/// `0x17 REFUSAL_MIRRORED` — pipeline emitted the operator-facing
/// "mirror" response template. Payload:
/// `{parent_event_id, template, attempt_count}`. Parent is the 0x16
/// frame it responds to.
pub const EVENT_TYPE_REFUSAL_MIRRORED: u8 = 0x17;
/// `0x18 REFUSAL_REDIRECTED` — operator authorised a retry (explicit
/// override, human-in-the-loop). Payload:
/// `{parent_event_id, operator_directive}`.
/// Owned by SPEC_mirror_refusal.md. Distinct from `0x19 REFUSAL_REROUTED`
/// which records automated hemisphere/provider switches.
pub const EVENT_TYPE_REFUSAL_REDIRECTED: u8 = 0x18;
/// `0x19 REFUSAL_REROUTED` — automated hemisphere/provider switch in
/// the recovery pipeline (no operator interaction). Payload:
/// `{parent_event_id, from_role, to_role, from_provider, to_provider,
///  ts_unix}`. R-3 Gremium 2026-05-16 — resolves the 0x18 semantic
/// collision between operator-grant and automated routing.
/// Owned by SPEC_refusal_recovery.md §4.3.
pub const EVENT_TYPE_REFUSAL_REROUTED: u8 = 0x19;
/// `0x1A REFUSAL_PERSISTENT` — N consecutive refusals for the same
/// task. Payload: `{attempt_count, final_class, session_id}`.
pub const EVENT_TYPE_REFUSAL_PERSISTENT: u8 = 0x1A;
/// `0x1B PROFILE_PRESET_APPLIED` — operator picked a profile preset
/// (LOWKEY / FORMAL / DEEPDIVE / TUTOR / OPSEC) via the wizard or
/// `neoth profile preset apply <name>`. Payload (JSON):
/// `{preset_name, source, ts_unix}` where `source` ∈ `"wizard" |
/// "cli" | "gui"`. Drives downstream profile injection (CH-09).
/// P-02 + P-05 (Session 21).
pub const EVENT_TYPE_PROFILE_PRESET_APPLIED: u8 = 0x1B;
/// `0x1C SELF_DEV_PROPOSED` — proactive self-dev loop emitted a
/// proposed adjustment for operator review. Payload:
/// `{proposal_id, kind, reason, confidence, ts_unix}`. Operator
/// reviews via `neoth self-dev review`. P-04 + P-05 (Session 21).
pub const EVENT_TYPE_SELF_DEV_PROPOSED: u8 = 0x1C;
/// `0x1D SELF_DEV_ACCEPTED` — operator accepted a self-dev proposal
/// (`neoth self-dev accept <proposal_id>`). Payload:
/// `{proposal_id, ts_unix}`. The matching PROFILE_DELTA lands
/// immediately after this event. P-04 + P-05 (Session 21).
pub const EVENT_TYPE_SELF_DEV_ACCEPTED: u8 = 0x1D;
/// `0x1E SELF_DEV_DECLINED` — operator declined or let the
/// proposal time-out. Payload: `{proposal_id, reason, ts_unix}`.
/// `reason` ∈ `"declined" | "timeout"`. P-04 + P-05 (Session 21).
pub const EVENT_TYPE_SELF_DEV_DECLINED: u8 = 0x1E;
/// `0x1F HEMISPHERE_REBOUND` — operator changed the provider binding
/// for one hemisphere role (Left/Right/Cerebellum) via `neoth
/// hemispheres set` or the wizard step 5d. Payload:
/// `{role, prior_provider, new_provider, model, source, ts_unix}`.
/// `source` is `"cli"` | `"wizard"` | `"gui"`. Owned by
/// SPEC_hemisphere_provider_selection.md §8.
pub const EVENT_TYPE_HEMISPHERE_REBOUND: u8 = 0x1F;

// ---- 0x20..=0x2F  Provider + multimodal lifecycle -------------------------
//
// 0x20..=0x2B: LLM provider calls (request / response / error / stream
//   chunk + local-inference start/end).
// 0x2C..=0x2F: media + embedding pipeline (R-9 ingest pipeline). These
//   sit in the same band because they share the "external-data-touched-
//   the-daemon" semantic — an `INGEST_EXTRACTED` frame is to multimodal
//   what `PROVIDER_REQUEST` is to text. A future carve-out into a
//   dedicated 0xB0..=0xBF band would force every audit consumer to
//   relearn the layout, so the band stays as-is; the comment is the
//   single source of truth.

/// Outbound request to an LLM provider. Payload: prompt hash + model + ts.
pub const EVENT_TYPE_PROVIDER_REQUEST: u8 = 0x20;
/// Inbound response from an LLM provider. Payload: response hash + tokens + latency.
pub const EVENT_TYPE_PROVIDER_RESPONSE: u8 = 0x21;
/// Provider returned an error or timed out.
pub const EVENT_TYPE_PROVIDER_ERROR: u8 = 0x22;
/// One incremental delta during a streaming response. Payload: seq + delta hash + bytes.
pub const EVENT_TYPE_PROVIDER_STREAM_CHUNK: u8 = 0x23;
/// HTTP 429 returned by a remote provider, the daemon recorded a backoff
/// window, and the operator-visible quota state was updated. Source of
/// truth for the Council Governance H5 cascade (`PLAN/SPEC_council_governance.md`
/// §2). Payload: `{provider, retry_after_secs, requests_today, daily_cap?, ts}`.
/// Emitted at most once per 429 — repeat 429s inside an active backoff window
/// extend the window in place without spamming the WAL.
pub const EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED: u8 = 0x24;

/// Local Qwen3 forward-pass started. Phase 33e AP-2 — gives the Day-37
/// trace test something to observe so the local-inference path satisfies
/// G.9 (Black-Box without Introspection). Payload:
/// `{request_id, prompt_hash, model, ts}`.
pub const EVENT_TYPE_LOCAL_INFERENCE_START: u8 = 0x2A;
/// Local Qwen3 forward-pass completed. Payload:
/// `{request_id, output_hash, input_tokens, output_tokens, latency_ns, ts}`.
pub const EVENT_TYPE_LOCAL_INFERENCE_END: u8 = 0x2B;

/// Multimodal asset was extracted + persisted via `neoth ingest`. Payload:
/// `{path, asset_kind, mime, text_bytes, model, ts}`. Emitted regardless
/// of whether an embedding was produced — operators get an audit row for
/// every successful extraction.
pub const EVENT_TYPE_INGEST_EXTRACTED: u8 = 0x2C;
/// CLIP / future multimodal embedding was written to `idx_embedding`.
/// Payload: `{source_kind, source_ref, model, dim, ts}`. Always paired
/// with a preceding 0x2C `INGEST_EXTRACTED` (or a channel-side counterpart
/// once Telegram/Keet land the image-attachment path).
pub const EVENT_TYPE_EMBED_PERSISTED: u8 = 0x2D;
/// Round-3 v0.4 ARCH-04 — prompt-assembly block-layer hard token cap
/// triggered + graceful degradation applied. Emitted once per
/// PROVIDER_REQUEST that needed truncation. The matching
/// PROVIDER_REQUEST carries the new paired fields
/// `prompt_token_estimate` (pre-truncation) + `prompt_token_actual`
/// (post-truncation); this event captures the per-block diff.
///
/// Payload (JSON):
///   - `cap`: u32 — operator's configured cap
///   - `original_total`: u32 — pre-degradation token estimate
///   - `new_total`: u32 — post-degradation token estimate
///   - `dropped_d_count`: u32 — episode/recall items removed (oldest first)
///   - `dropped_c_count`: u32 — profile-context items removed (lowest-importance first)
///   - `conductor_truncated`: bool — did we eat into Conductor.plan/spec?
///   - `request_id`: String — matches the downstream PROVIDER_REQUEST
///
/// Pre-condition for KF-08 (token-cap-aware adaptive layering).
pub const EVENT_TYPE_BUDGET_EXCEEDED: u8 = 0x2F;

// ---- 0x30..=0x3F  Channels ------------------------------------------------

/// Inbound message arrived on a channel (Telegram / WhatsApp / Slack / ...).
/// Payload: channel name + sender id + text hash + bytes + ts.
pub const EVENT_TYPE_CHANNEL_INGRESS: u8 = 0x32;
/// Outbound reply sent through a channel. Payload: channel name + recipient + text hash + bytes.
pub const EVENT_TYPE_CHANNEL_EGRESS: u8 = 0x33;
/// Channel transport-level error (auth failure, network error, vendor 5xx).
pub const EVENT_TYPE_CHANNEL_ERROR: u8 = 0x34;
/// Inbound message was quarantined by the ingress sanitizer before reaching
/// the provider. Payload: `{ channel, sender_id, input_hash, findings[], ts }`.
/// See `security/ingress_sanitizer.rs`.
pub const EVENT_TYPE_INGRESS_QUARANTINED: u8 = 0x35;
/// Inbound message was sanitised (NFKC / control chars stripped) but allowed
/// through. Payload: `{ channel, sender_id, input_hash, findings[], ts }`.
pub const EVENT_TYPE_INGRESS_SANITIZED: u8 = 0x36;
/// Platform-level delivery acknowledgement received for a previously sent
/// outbound message (where the channel supports it — Telegram: implicit ok,
/// Slack: chat.postMessage response, WhatsApp Business: status webhook).
/// Phase 33b SP-5 (C-prime). Payload: `{channel, message_id, ts}`.
pub const EVENT_TYPE_CHANNEL_ACK: u8 = 0x37;
/// An existing outbound message was edited via the channel's edit endpoint
/// (Telegram editMessageText, Slack chat.update). Used by streaming preview.
/// Phase 33b SP-5 (C-prime, deferred to LiveDelivery — placeholder reserved).
/// Payload: `{channel, message_id, new_text_hash, bytes, ts}`.
pub const EVENT_TYPE_CHANNEL_EDIT: u8 = 0x38;
/// `0x39 N8N_REQUEST` — n8n workflow hit the NEOTH localhost HTTP API.
/// One frame per inbound request to `/api/*` (after bearer-auth success).
/// Payload: `{endpoint, source_ip, request_id, ts_unix}`. The matching
/// downstream event (PROVIDER_REQUEST / CHANNEL_EGRESS / RECALL_HIT)
/// carries the same `request_id` so WAL replay shows the trigger chain
/// end-to-end. N-3 (Session 21).
pub const EVENT_TYPE_N8N_REQUEST: u8 = 0x39;

// ---- 0x50..=0x5F  Panic / recovery (Pick #35 Session 14 WAL recovery) -----

/// `0x50 RECOVERY_TRUNCATED` — emitted by `wal::recovery::scan_tail` at
/// daemon startup when a torn frame is detected in the tail of a WAL
/// segment. The writer truncates the segment to the last good frame
/// boundary BEFORE this event is appended, so the event becomes the
/// first new frame in the recovered segment. Operators reading
/// `neoth wal show` see a clear marker for "the daemon recovered from
/// a crash here; events between `torn_at` and `good_through` are gone".
///
/// Payload (JSON):
///   - `segment_path`: absolute path of the truncated segment
///   - `good_through`: byte offset of the last verified-good frame
///   - `torn_at`: byte offset where the corruption started
///   - `bytes_dropped`: `torn_at - good_through`
///   - `ts_unix`: wall-clock seconds of the recovery event
pub const EVENT_TYPE_RECOVERY_TRUNCATED: u8 = 0x50;

/// ADV-01 (F4 finding, SPEC §4.3) — emitted when the crash-recovery
/// scan encounters a `.cpt` compaction file whose paired `.cpt.hmac`
/// is missing, wrong length, or fails HMAC-SHA256 verification.
/// Both files are quarantined (renamed with a `.rejected.<ts>` suffix)
/// and the corresponding `.bin` segment is left untouched.
///
/// Payload (JSON):
///   - `cpt_path`: absolute path of the rejected `.cpt` file
///   - `reason`: human-readable cause ("hmac mismatch", "hmac missing",
///               "hmac wrong length")
///   - `ts_unix`: wall-clock seconds of the rejection event
///   - `quarantine_path`: where the offending `.cpt` was renamed to
pub const EVENT_TYPE_COMPACTION_AUTH_FAILED: u8 = 0x51;

// ---- 0x40..=0x4F  Cron / scheduled jobs -----------------------------------

/// Scheduled job fired by the cron scheduler.
/// Payload: `{ job_id, name, schedule_expr, fired_at_ts }`.
pub const EVENT_TYPE_JOB_FIRED: u8 = 0x40;
/// Scheduled job completed successfully.
/// Payload: `{ job_id, name, duration_ms, output_bytes }`.
pub const EVENT_TYPE_JOB_SUCCESS: u8 = 0x41;
/// Scheduled job failed (provider error, channel delivery failure, timeout, …).
/// Payload: `{ job_id, name, duration_ms, error }`.
pub const EVENT_TYPE_JOB_FAILED: u8 = 0x42;
/// P-08 cron consumer (Workstream C, Session 22) — scheduled job
/// suppressed by the briefing-gate verdict before any provider call.
/// Surfaces as a non-failure audit record so operators can see that
/// the cron task fired AND the gate (silent-hours / inactivity /
/// duplicate-emit policy) decided "do nothing this tick".
/// Payload: `{ job_id, name, reason, current_hour, ts_unix_ms }`.
pub const EVENT_TYPE_JOB_SKIPPED_BY_GATE: u8 = 0x43;

/// U-04 (2026-05-26): updater cron task fired one check pass.
/// Emitted by every tick of the self-update / skill+plugin /
/// CLI-version cron — operators see "the updater ran" even when
/// no upgrade was needed. Payload: `{ task_kind, ts_unix }` where
/// `task_kind ∈ neoth_self | skill_plugin | cli_versions`.
pub const EVENT_TYPE_UPDATER_TASK_FIRED: u8 = 0x44;

/// U-04: updater cron task completed. One frame per
/// `0x44 UPDATER_TASK_FIRED`. Payload carries the per-component
/// outcome list — `{ task_kind, ts_unix, duration_ms, components:
/// [{ name, prior_version?, new_version?, status }] }` where
/// `status ∈ up_to_date | upgraded | failed | skipped_by_gate`.
pub const EVENT_TYPE_UPDATER_TASK_RESULT: u8 = 0x45;

/// EL-01 (v0.5 Session 25): the `neoth doctor` cron task completed
/// one tick. Payload is the full [`crate::daemon::doctor_cron::DoctorCronReport`]
/// serialised as JSON — `ts_unix`, counters (`pass_count` /
/// `warn_count` / `fail_count`), and per-check findings with
/// `runbook_id` + `suggested_command`. Operators audit "what did
/// the doctor see when?" by grep'ing for 0x46 frames; the frame
/// fires on every tick whether clean or not so the audit chain
/// proves the cron actually ran.
pub const EVENT_TYPE_DOCTOR_TICK: u8 = 0x46;

// ---- 0x60..=0x6F  Council debate + callosum (CH-08) ----------------------

/// `0x60 COUNCIL_SYNTHESIS_ATTEMPTED` — chat dispatch hit
/// `Verdict::Split` and called `council::callosum::resolve` against the
/// Cerebellum hemisphere. Records the outcome regardless of whether the
/// synthesis succeeded so operators can audit the recovery path
/// (frequency of Splits → reachability of callosum → operator-decision
/// fallback rate).
///
/// Payload: `{prompt_hash, outcome, synthesis_chars, reason, ts}`
///   - `prompt_hash`: xxh3_64 of the original chat prompt, hex-rendered.
///   - `outcome`: `"synthesis"` or `"irreconcilable_conflict"`.
///   - `synthesis_chars`: char count of the synthesised text (omitted
///     on conflict).
///   - `reason`: failure reason on conflict (omitted on synthesis).
///
/// A5-tail follow-up shipped 2026-05-16.
pub const EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED: u8 = 0x60;

/// `0x61 COUNCIL_PARTIAL_REFUSAL` — Session 13 A-1 audit frame emitted
/// whenever `CouncilDebate::is_partial_refusal()` is true after a debate,
/// regardless of which code path consumed the result (Consensus winning_text,
/// Split→callosum, or QuorumFailed diagnostic). Operators MUST see when
/// any hemisphere refused even if the reply text was synthesised from the
/// usable subset — silent partial-refusal would let provider safety
/// policies drift undetected in the council audit log.
///
/// Payload: `{prompt_hash, refused_count, usable_count, refused, ts}`
///   - `prompt_hash`: xxh3_64 of the original prompt, hex-rendered.
///   - `refused_count` / `usable_count`: u32.
///   - `refused`: array of `{role, provider, class, cause}` objects, one
///      entry per refused hemisphere.
pub const EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL: u8 = 0x61;

/// `0x62 COUNCIL_SKIP` — Session 13 B-1 audit frame emitted whenever the
/// council smart-trigger returned `TriggerDecision::Skip` for a chat or
/// channel prompt. Records WHY the council didn't fire (operator opt-out
/// via NEOTH_COUNCIL_DISABLE, prompt below complexity threshold, rate
/// cooldown, budget exhausted, single-mode short-circuit) so operators
/// auditing `neoth wal show` can distinguish "single hemisphere answered
/// because trigger said skip" from "council fired but everyone agreed".
///
/// Payload: `{prompt_hash, reason, ts}`
///   - `prompt_hash`: xxh3_64 of the original prompt, hex-rendered.
///   - `reason`: human-readable trigger reason from
///      `TriggerDecision::Skip { reason }`.
pub const EVENT_TYPE_COUNCIL_SKIP: u8 = 0x62;

/// Pick #8 SP-2 (Session 14) — role-agnostic "smartest-wins" winner
/// selection emitted whenever `config.council.selection_mode` is
/// `ConsensusOrBest` or `BestAlways` AND
/// `CouncilDebate::best_response` returned a winner. Operator's WAL
/// audit trail shows WHICH hemisphere won + WHY (quality score
/// composite), distinguishing role-agnostic dispatch from the
/// legacy verdict-driven path.
///
/// Payload (JSON): `{prompt_hash, depth, role, provider, score, mode}`
///   - `prompt_hash`: xxh3_64 of the prompt, decimal-rendered
///   - `depth`: recursion level — `0` at the outer council, `>0`
///     for fractal inner councils (F7 fractal-synthesis hard rule:
///     EVERY 0x63 event MUST carry depth so audit reconstruction
///     of recursion trees stays unambiguous)
///   - `role`: winning hemisphere role ("left"/"right"/"cerebellum")
///   - `provider`: provider id the winning hemisphere ran on
///   - `score`: composite `QualityScore::total()` value (0.0..=1.0)
///   - `mode`: serialised SelectionMode ("consensus_or_best" or
///     "best_always"); LegacyMajority NEVER emits this event
pub const EVENT_TYPE_COUNCIL_WINNER_SELECTED: u8 = 0x63;

/// `0x64 COUNCIL_DIVERSITY_WARNING` — Pick #8 F8 hard rule (Session 14
/// Pick #20). Emitted once per `run_council_debate` invocation when
/// the operator's `InferenceTopology` produces a non-`Distinct`
/// `DiversityVerdict`. The Smartest-Wins selection assumes provider
/// diversity across the three hemispheres; this frame records when
/// that assumption is violated so the audit trail shows why a
/// council's dissent + diversity_bonus signals are degraded.
///
/// Payload (JSON): `{prompt_hash, verdict, left, right, cerebellum, overlap?}`
///   - `prompt_hash`: xxh3_64 of the prompt, hex-rendered (matches
///     the other 0x6x frames)
///   - `verdict`: one of `partial_overlap` / `monoculture` /
///     `misconfigured` (never `distinct` — that case skips emission)
///   - `left` / `right` / `cerebellum`: each slot's provider id, or
///     `null` for the `misconfigured` case where the slot is empty
///   - `overlap`: present only on `partial_overlap` — the provider
///     id that appears on two of the three slots
pub const EVENT_TYPE_COUNCIL_DIVERSITY_WARNING: u8 = 0x64;

/// P-02 (Session 24) — operator's consent-gate decision. Fires on
/// every `ensure_granted_or_prompt_tri` call that took an operator
/// answer (skips re-prompts on already-granted state to keep the
/// audit log signal-to-noise). Payload:
/// `{kind, decision, source, ts_unix}`. `decision` ∈
/// `allow_once | allow_always | deny`. `allow_always` persists a
/// marker file; the other two leave operator state untouched but
/// still produce the audit anchor so an operator denying once can
/// prove they denied even if the next attempt succeeds.
///
/// Note on band: PROGRESS spec language said "0x30 CONSENT_DECISION
/// (claim band)" but 0x30..=0x3F is the channels band. Slot 0x65 is
/// adjacent to the council/decisions band (0x60..=0x6F) which is the
/// semantic neighborhood for operator decisions; using it here keeps
/// the existing channels band intact.
pub const EVENT_TYPE_CONSENT_DECISION: u8 = 0x65;

// ---- 0x70..=0x7F  Coding workflow (V11 Pick #38, 2026-05-19) --------------
//
// Hermes-adapted autonomous software engineering pipeline per
// `PLAN/SPEC_coding_workflow.md`. Operators inspecting `neoth wal show
// --grep kanban` see every session opening, task transition, comment
// + completion frame in chronological order. All seven need
// `needs_immediate_sync=true` (audit chain MUST survive crash mid-task).

/// `0x70 KANBAN_SESSION_OPENED` — operator typed `neoth code "..."`,
/// the orchestrator (Cerebellum) accepted the request. Payload:
/// `{session_id, prompt_hash, source_channel, operator_id, ts}`.
pub const EVENT_TYPE_KANBAN_SESSION_OPENED: u8 = 0x70;

/// `0x71 KANBAN_TASK_CREATED` — the decomposer produced one row in
/// `idx_kanban_task`. Payload: `{session_id, task_id, task_type,
/// title_hash, parent_task_id, ts}`. Title body lives in sqlite to
/// keep the WAL compact; the hash lets `neoth wal show` correlate
/// frames to rows when sqlite is offline.
pub const EVENT_TYPE_KANBAN_TASK_CREATED: u8 = 0x71;

/// `0x72 KANBAN_TASK_ASSIGNED` — the classifier picked a hemisphere
/// + the dispatcher resolved a provider. Payload: `{task_id,
/// hemisphere, worker, eta_ns, ts}`.
pub const EVENT_TYPE_KANBAN_TASK_ASSIGNED: u8 = 0x72;

/// `0x73 KANBAN_STATUS_CHANGED` — task moved between columns. Payload:
/// `{task_id, old_status, new_status, ts}`. Snake_case status strings
/// per `coding::types::TaskStatus::as_str`.
pub const EVENT_TYPE_KANBAN_STATUS_CHANGED: u8 = 0x73;

/// `0x74 KANBAN_TASK_COMMENT` — inter-hemisphere or operator comment
/// thread. Payload: `{task_id, author, body_hash, ts}`. Comment body
/// lives in `idx_kanban_comment` (operators read it via the GUI / CLI
/// `neoth kanban show`); the hash lets the audit chain reference it
/// without inflating the WAL.
pub const EVENT_TYPE_KANBAN_TASK_COMMENT: u8 = 0x74;

/// `0x75 KANBAN_TASK_COMPLETED` — worker reported a patch + tests.
/// Payload: `{task_id, patch_path, tests_added, tests_passing,
/// tests_failing, tests_skipped, summary_hash, ts}`. The patch file
/// itself lives at `~/.neoth/sessions/<id>/<task_id>.patch`; the WAL
/// frame records the metadata an operator scans for in
/// `neoth wal show --type 0x75`.
pub const EVENT_TYPE_KANBAN_TASK_COMPLETED: u8 = 0x75;

/// `0x76 KANBAN_SESSION_CLOSED` — every task reached a terminal status
/// (done OR archived) AND Cerebellum produced the final session
/// summary. Payload: `{session_id, status, summary_hash,
/// tasks_done, tasks_archived, ts}`.
pub const EVENT_TYPE_KANBAN_SESSION_CLOSED: u8 = 0x76;

/// `0x77 KANBAN_TASK_PROGRESS` — Pick #6 dispatcher progress heartbeat
/// (reserved 2026-05-20 per `PLAN/CHORUS_dispatcher_design.md` Q2).
/// Emitted ~every 30s while a worker runs so `neoth kanban watch`
/// shows "still working" without the audit chain bloating
/// per-token. Payload: `{task_id, hemisphere, bytes_emitted,
/// ts}`. Not yet wired — Pick #6 implementation lands this.
pub const EVENT_TYPE_KANBAN_TASK_PROGRESS: u8 = 0x77;

// ---- 0x80..=0x8F  Hook lifecycle (Phase 29 R-15) --------------------------

/// A hook fired at a pipeline stage (matcher passed, action ran). Payload:
/// `{name, stage, action_kind, ts}`. Phase 29 H-4.
pub const EVENT_TYPE_HOOK_FIRED: u8 = 0x80;
/// A `block` hook stopped the pipeline. Payload: `{name, stage, reason, ts}`.
pub const EVENT_TYPE_HOOK_BLOCKED: u8 = 0x81;
/// A `replace` hook mutated the body. Payload: `{name, stage, before_hash,
/// after_hash, ts}` — bodies hashed, not stored, to keep the WAL small.
pub const EVENT_TYPE_HOOK_REPLACED: u8 = 0x82;
/// Hook execution failed (bad regex, internal error). Payload:
/// `{name, stage, error, ts}`.
pub const EVENT_TYPE_HOOK_ERROR: u8 = 0x83;
/// Sub-agent review stage completed (Phase 30 R-18 + obra/superpowers
/// Item #2 port). One frame per stage; payload:
/// `{agent_name, stage, passed, feedback_hash_xxh3, ts}`. The feedback
/// body itself is NOT in the WAL — only a hash — to keep the log small.
pub const EVENT_TYPE_SUBAGENT_REVIEW_STAGE: u8 = 0x84;

// ---- 0x90..=0x9F  Memory tiers (R-22..R-24) -------------------------------

/// One event moved from `idx_episode` (hot) into `idx_consolidated` (warm).
/// Phase 28a R-22 MT-6. Payload: `{event_id, kind, day, importance, ts}`.
pub const EVENT_TYPE_EPISODE_CONSOLIDATED: u8 = 0x90;
/// One event crossed the 90-day boundary AND `PROMOTION_THRESHOLD`; moved
/// from warm → cold tier (`idx_longterm`).
/// Payload: `{event_id, from_importance, to_importance, ts}`.
pub const EVENT_TYPE_EPISODE_PROMOTED: u8 = 0x91;
/// One event reached the archive-only state — dropped from queryable views
/// because importance fell below `FORGET_FLOOR` or it was never promoted at
/// the 90-day boundary. Archive MD file remains.
/// Payload: `{event_id, reason, last_importance, ts}`.
pub const EVENT_TYPE_EPISODE_ARCHIVED: u8 = 0x92;
/// Single-event Hebbian reinforce audit (recall-hit bump). Distinct from
/// `EVENT_TYPE_REINFORCE = 0x02` (dedup-hit on the content_hash). Phase 28a
/// MT-3. Payload: `{event_id, old, new, query_hash, ts}`.
pub const EVENT_TYPE_IMPORTANCE_REINFORCED: u8 = 0x93;

/// One daily consolidation pass completed. Summary frame (not per-event).
/// Phase 28c R-24 GT-3. Payload: `{ts, events_touched, mean_before, mean_after,
/// count_forgotten, count_promoted}`.
pub const EVENT_TYPE_CONSOLIDATION_PASS: u8 = 0x94;
/// An event crossed `FORGET_FLOOR` (downward) or `PROMOTION_THRESHOLD`
/// (upward) on the current pass. Payload: `{event_id, before, after, direction}`.
pub const EVENT_TYPE_IMPORTANCE_THRESHOLD_CROSSED: u8 = 0x95;
/// Operator opened an archive MD file directly (filesystem-level, not via
/// recall). Does NOT trigger reinforce — direct access bypasses the
/// importance-weighted ranker, crediting it corrupts the signal.
pub const EVENT_TYPE_ARCHIVE_ACCESSED_DIRECT: u8 = 0x96;
/// New ground-truth row inserted. Phase 28c GT-10.
/// Payload: `{id, source, scope, ts}`.
pub const EVENT_TYPE_GROUNDTRUTH_ADDED: u8 = 0x97;
/// Existing ground-truth row revoked. Payload: `{id, ts}`.
pub const EVENT_TYPE_GROUNDTRUTH_REVOKED: u8 = 0x98;
/// Ground-truth rows imported from a foreign-agent source. Payload:
/// `{source, count, ts}`.
pub const EVENT_TYPE_GROUNDTRUTH_IMPORTED: u8 = 0x99;
/// Round-3 v0.4 QU-11 / ARS-6 — multi-session pipeline checkpoint.
/// Snapshot of the chat session's resumable state (provider target,
/// council mode, hemisphere routing, MCP scope) emitted before any
/// long-running pipeline so a future `neoth chat resume from
/// <checkpoint_hash>` can hydrate the same context. The QU-11 spec
/// originally suggested `0xB3` but that slot was claimed by
/// `EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT` (R-22 Phase 3 drift anchor)
/// before QU-11 landed; `0x9A` is the next free slot in the Hippocampus
/// memory-ops band (0x90..=0x9F), which fits semantically — session-
/// state recovery is fundamentally a memory-recall operation.
/// Payload: `{checkpoint_hash, session_id, mode, ts}`.
pub const EVENT_TYPE_MODE_CHECKPOINT: u8 = 0x9A;

// ---- 0xA0..=0xAF  Permissions / autonomy (R-23) ---------------------------

/// Permission decision returned `Allow` (after a possible Confirm round-trip).
/// Phase 28b AU-5. Payload: `{action, level, reason?, ts}`.
pub const EVENT_TYPE_PERMISSION_GRANTED: u8 = 0xA0;
/// Permission decision returned `Deny`. Payload: `{action, level, reason, ts}`.
pub const EVENT_TYPE_PERMISSION_DENIED: u8 = 0xA1;
/// Operator changed the autonomy level upward via `neoth autonomy --set ...`.
/// Payload: `{from_level, to_level, source, ts}`.
pub const EVENT_TYPE_LEVEL_ELEVATED: u8 = 0xA2;
/// Operator changed the autonomy level downward.
/// Payload: `{from_level, to_level, source, ts}`.
pub const EVENT_TYPE_LEVEL_DEROGATED: u8 = 0xA3;

/// Pre-call cost preview shown to the operator before a provider
/// dispatch (C-14 ex-ante cost transparency). Payload:
/// `{provider, model, input_tokens, output_tokens_est, total_eur,
///  threshold_eur, decision, ts_unix}`. Emitted regardless of whether
/// the call ultimately fires — `decision` records "auto-allowed",
/// "operator-confirmed", or "operator-rejected".
pub const EVENT_TYPE_COST_ESTIMATE_SHOWN: u8 = 0xA4;

// ---- 0xB0..=0xBF  Hypothalamus / user-profile -----------------------------
//
// Single-writer band for `profile.apply` (SPEC_proactive_learning.md §1.3,
// SPEC_profile_claim_guard.md §7). Every event in this band MUST be
// emitted by the apply Effect Adapter — the gate is conventional in v0.1
// (the wire header doesn't yet carry a `region_tag` field), Phase-2 wire-
// format extension will enforce it cryptographically via the header.

/// One profile claim applied to the operator's profile state.
/// Payload: `{extraction_id, field, value_json, confidence, evidence_event_ids,
///  guard_version, ts_unix}`.
pub const EVENT_TYPE_PROFILE_DELTA: u8 = 0xB0;
/// Existing profile claim reinforced by a new claim with the same field
/// and same value but equal-or-higher confidence. The old row's
/// confidence is bumped + last_access updated; no new row is created.
/// Payload carries `prior_event_id`, `field`, `old_confidence`,
/// `new_confidence`, `extraction_id`, `ts_unix`.
pub const EVENT_TYPE_PROFILE_REINFORCED: u8 = 0xB1;
/// Existing profile claim superseded by a new claim with the same
/// field but DIFFERENT value. The old row's `superseded_at` is set;
/// the new claim's `PROFILE_DELTA` frame fires alongside. Payload
/// carries `prior_event_id`, `field`, `old_value_hash`, `new_value_hash`,
/// `extraction_id`, `ts_unix`.
pub const EVENT_TYPE_PROFILE_SUPERSEDED: u8 = 0xB2;

/// `0xB3 PROFILE_BASELINE_SNAPSHOT` — v1.1 §A3 Phase-3 drift anchor.
///
/// Emitted ONCE during the Phase-3 Day-65 seed-migration pass after
/// `profile.extract` produces the operator's first stable claim set.
/// Captures the full snapshot in a single frame so a later
/// drift-detection pass can compare any future profile state against
/// the seed without having to walk the entire delta chain.
///
/// **Invariants** (per v1.1 §A3 + audit notes 2026-05-19):
///   - `importance=1.0` at write — the entry MUST survive every
///     decay pass.
///   - never compacted, never tombstoned — `wal::compaction` skips
///     this event type; `tombstone` rejects it with a clear error.
///   - SYNC_ON_WRITE — loss would break the Phase-4 drift baseline.
///   - exactly-once enforcement: caller checks for an existing
///     PROFILE_BASELINE_SNAPSHOT before emit; a second write is a
///     hard error (not a silent re-anchor).
///
/// v1.1 §A3 originally proposed `0x37` for this event but that code
/// was locked to `CHANNEL_ACK` by the SP-5 C-prime amendment
/// (2026-05-14). `0xB3` is the next free slot in the profile band so
/// the event lands next to its sibling PROFILE_* frames.
///
/// Payload (JSON): `{snapshot_id, claim_count, claim_hashes,
/// embedding_b64, neoth_version, seeded_at_ts_unix}`. `embedding_b64`
/// is the behavioural-style embedding referenced in v1.1 §A3 for the
/// Phase-3 parity-substrate evaluation; populated via
/// [`crate::providers::embed::EmbedProvider::embed`] (Day-14b Phase 1b
/// shipped 2026-05-23 — `local_qwen` `EmbedProvider` impl returns
/// L2-normalised hidden-state mean-pooled vectors). Left `null` when
/// no `EmbedProvider` is wired into the seed migration path yet
/// (Phase 4 of the embed-wire plan).
///
/// **NOT YET EMITTED.** This constant reserves the code for the Phase-3
/// emitter; the daemon today never writes a frame with `event_type =
/// 0xB3`. Validation tooling (`needs_immediate_sync`, the band-membership
/// check below) treats it correctly so the emitter can land without
/// touching the durability surface.
pub const EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT: u8 = 0xB3;

/// Stage-5 guard rejected an entire delta. Audit-trail row that records
/// which claim was blocked and why — operator can grep
/// `neoth wal show --type 0xB4` to see exactly what NEOTH refused.
/// Payload: `{extraction_id, reason, blocked_delta_hash, guard_version,
///  ts_unix}`.
pub const EVENT_TYPE_PROFILE_DELTA_BLOCKED: u8 = 0xB4;

/// ADV-03 item 4 (Session 24 follow-up) — a profile delta extracted
/// by the LLM has been parked in `idx_profile_pending` awaiting
/// operator approval. Fires when `freedom.yaml::profile.require_approval`
/// is true (the new default for fresh installs) AND the daemon is
/// running in tty-less mode (so no interactive `dialoguer::Confirm`
/// is available).
///
/// Payload (JSON):
///   - `extraction_id`: stable id from the extractor
///   - `claim_count`: how many claims got parked
///   - `field_summary`: comma-joined list of `field` names (truncated at 8)
///   - `conversation_hash`: links the pending row back to the source window
pub const EVENT_TYPE_PROFILE_DELTA_PENDING: u8 = 0xB5;

/// ADV-03 item 4 — operator approved a pending profile delta. The
/// `apply_delta` pipeline ran AFTER this frame; readers correlate
/// approval -> apply via `extraction_id`.
///
/// Payload (JSON): `{ extraction_id, approved_at_ts_unix, claim_count }`
pub const EVENT_TYPE_PROFILE_DELTA_APPROVED: u8 = 0xB6;

/// ADV-03 item 4 — operator declined a pending profile delta. The
/// claims are dropped + the pending row is deleted; no `apply_delta`
/// runs.
///
/// Payload (JSON): `{ extraction_id, declined_at_ts_unix, claim_count, reason: Option<String> }`
pub const EVENT_TYPE_PROFILE_DELTA_DECLINED: u8 = 0xB7;

// ---- 0xF0..=0xFF  Operator / system ---------------------------------------

/// Daemon refused a WAL write because `~/.neoth/` exceeded the configured
/// disk-quota ceiling. Last frame written before writes stop. Phase 33c BS-4.
/// Payload: `{used_bytes, ceiling_bytes, ts}`.
pub const EVENT_TYPE_QUOTA_BREACHED: u8 = 0xF0;
// ---- 0xC0..=0xCF  Tool invocations (MCP, future plugin SDK) ---------------

/// `0xC0 MCP_TOOL_CALLED` — operator's MCP client invoked a tool on
/// an external server. Payload: `{server_id, tool, arguments_hash,
/// content_bytes, is_error, ts_unix}`. `arguments_hash` is xxh3-64 of
/// the canonical-JSON argument blob — full args are NOT logged
/// because they may contain secrets the operator passed through.
/// Owned by CDX-03 MCP security hardening.
pub const EVENT_TYPE_MCP_TOOL_CALLED: u8 = 0xC0;

/// `0xC2 PLUGIN_LOADED` — V10-04 Pick #34b. Emitted when wasmtime
/// successfully compiles + instantiates a `.wasm` plugin discovered
/// under `~/.neoth/plugins/<id>/`. Payload: `{plugin_id, version,
/// requested_permission, hook_stages, fuel_budget, ts_unix}`.
pub const EVENT_TYPE_PLUGIN_LOADED: u8 = 0xC2;

/// `0xC3 PLUGIN_REJECTED` — V10-04 Pick #34b. Operator-readable
/// rejection: manifest invalid, wasm bytes won't compile, signature
/// mismatch (future), id-directory mismatch. Payload: `{plugin_dir,
/// reason, ts_unix}`.
pub const EVENT_TYPE_PLUGIN_REJECTED: u8 = 0xC3;

/// `0xC4 PLUGIN_HOSTCALL` — V10-04 Pick #34b. Fired from inside the
/// wasmtime `neoth.emit_event` hostcall — plugin emitted a custom
/// event. Payload: `{plugin_id, kind, payload_bytes, ts_unix}`.
/// `kind` is the plugin-supplied string identifier; `payload_bytes`
/// is the size of the body the plugin attached (NOT the body itself
/// — operator policy may want to redact plugin-supplied data, so the
/// frame stays small).
pub const EVENT_TYPE_PLUGIN_HOSTCALL: u8 = 0xC4;

/// `0xC5 PLUGIN_FUEL_EXHAUSTED` — V10-04 Pick #34b. Wasmtime trapped
/// the plugin because it consumed its full fuel budget. Operator
/// reads this in `neoth plugins list --crash-log`. Payload:
/// `{plugin_id, fuel_budget, ts_unix}`.
pub const EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED: u8 = 0xC5;
/// `0xC1 MCP_TOOL_REJECTED` — operator's MCP client refused to invoke
/// a tool because either (a) the tool name is not in the server's
/// `allow_tools` list, (b) the tool description failed the prompt-
/// injection sanitizer, or (c) the autonomy gate denied the call.
/// Payload: `{server_id, tool, reason, ts_unix}`. Owned by CDX-03.
pub const EVENT_TYPE_MCP_TOOL_REJECTED: u8 = 0xC1;

// ---- 0xD0..=0xDF  Config lifecycle (Pick #37 Session 14 hot-reload) -------

/// `0xD0 CONFIG_RELOADED` — emitted when an operator-triggered
/// `neoth reload` completed an atomic `ArcSwap` of `FreedomConfig`.
/// `changed_fields` is the best-effort list of top-level fields
/// whose YAML serialisation differed between old + new. Nested
/// changes within e.g. `council.*` show up as the top-level field
/// (`council`), not a per-leaf diff — operator wants "I changed
/// council settings", not 9 sub-events.
///
/// Payload (JSON): `{changed_fields, source_path, ts_unix}`
pub const EVENT_TYPE_CONFIG_RELOADED: u8 = 0xD0;

/// `0xD1 CONFIG_RELOAD_REJECTED` — operator triggered `neoth reload`
/// but the freedom.yaml on disk changed an IMMUTABLE field
/// (`operator_id`, `provider_kind`, `telegram_user_id`). The
/// `ArcSwap` value did NOT change; the daemon still runs against
/// the pre-reload config. Operator must restart to apply the
/// rejected change.
///
/// Payload (JSON): `{reason, source_path, ts_unix}`
pub const EVENT_TYPE_CONFIG_RELOAD_REJECTED: u8 = 0xD1;

/// `0xD2 SELF_UPDATE_APPLIED` — V03-09 Phase 2b. Emitted when
/// `neoth update --self --apply` (or a future scheduled
/// auto-update) successfully completed the download → SHA-256
/// verify → extract → atomic-replace chain. The replacement
/// landed on disk; the new binary takes effect on next daemon
/// restart. Operators following the audit chain see a clear
/// "version X → Y at time T" anchor.
///
/// Payload (JSON): `{from_version, to_version, backup_path,
/// repo, target_triple, ts_unix}`. `backup_path` lets the
/// operator revert with a single `mv` on Unix or via the
/// rollback CLI later.
pub const EVENT_TYPE_SELF_UPDATE_APPLIED: u8 = 0xD2;

/// `0xD3 PATCH_APPLIED` — Pick #6 Phase 4. Emitted after the
/// dispatcher successfully applies a worker-produced patch
/// inside the task-scoped git worktree. Per the Chorus verdict
/// (`PLAN/CHORUS_pick6_phase4_VERDICT.md`), the frame carries
/// enough state for `neoth rollback` to find + restore.
///
/// Payload (JSON): `{task_id, session_id, worktree_path,
/// base_commit, patch_hash, ts_unix}`. `patch_hash` is the
/// SHA-256 of the patch file body, computed via
/// `coding::worktree::patch_hash`.
pub const EVENT_TYPE_PATCH_APPLIED: u8 = 0xD3;

/// `0xD4 PATCH_APPLY_FAILED` — companion to
/// `EVENT_TYPE_PATCH_APPLIED`. Fires when `git apply --check`
/// (or the apply itself) rejected the patch OR the test command
/// failed inside the worktree. The dispatcher transitions the
/// task to Blocked after one retry (per the Chorus verdict's
/// conservative-for-v0.2 stance); future v0.3 may raise to 3
/// retries via WorkerRetryPolicy.
///
/// Payload (JSON): `{task_id, session_id, worktree_path,
/// stage, reason, ts_unix}`. `stage` is one of
/// `"apply_check"`, `"apply"`, `"tests"` so the operator can
/// tell whether the diff conflicted vs the tests failed.
pub const EVENT_TYPE_PATCH_APPLY_FAILED: u8 = 0xD4;

/// W-08 (2026-05-26): wizard finished its system-detection step.
/// `installers::detect::probe_all` aggregated probes for Docker /
/// docker-compose / npm / node / git / ffmpeg / GPU / disk free
/// and the wizard cached the result at
/// `~/.neoth/detect_cache.json` (24 h TTL). One frame per detect
/// run — operators see the full system profile NEOTH worked with
/// at wizard-time.
///
/// Note: originally specced as 0x11 in W-08 but 0x11 is taken by
/// SHUTDOWN; relocated to the config-lifecycle band where it
/// naturally fits (wizard-time = config-time).
/// Payload: `{ probed_at_unix, docker_version?, docker_compose_*?,
///             npm_version?, node_version?, git_version?,
///             ffmpeg_version?, gpu? (kind + vram_mib + vendor +
///             name), disk_free_bytes? }`.
pub const EVENT_TYPE_DETECT_COMPLETE: u8 = 0xD5;

/// W-08 + SC-17 (2026-05-26): operator imported credentials. The
/// payload is the [`crate::security::credential_redact::
/// RedactedCredentialImportPayload`] — every field non-identifying
/// by design (no names / URLs / usernames / secrets reach the
/// WAL). `services_redacted: true` is the audit-trail invariant
/// downstream graders assert.
///
/// Note: originally specced as 0x15 in W-08 but 0x15 is taken by
/// COMPACTION_MARKER; relocated to the config-lifecycle band.
/// Payload: `{ source, entry_count, distinct_tags_sorted,
///             services_hash, target_vault_id, ts_unix,
///             services_redacted: true }`.
pub const EVENT_TYPE_CREDENTIAL_IMPORT: u8 = 0xD6;

// ---- 0xE0..=0xE7  Cluster lifecycle (R-7, Session 19) ---------------------
//
// Per `PLAN/CHORUS_hyperswarm_heartbeat_VERDICT.md`. Frames in
// this band trace cluster mode events — peer discovery, heart-
// beat receive, disconnect, rejection — so a multi-host
// operator can reconstruct who-was-up-when from the audit
// chain. Emit fires from inside `cli::serve` (the daemon path
// that has a live WalWriterHandle); CLI one-shots stay silent.

/// `0xE0 CLUSTER_PEER_CONNECTED` — emitted once per peer
/// connection after the handshake completes (our Hello sent,
/// peer's Hello received + validated).
///
/// Payload (JSON): `{peer_id, remote_public_key_hex,
/// cluster, ts_unix}`.
pub const EVENT_TYPE_CLUSTER_PEER_CONNECTED: u8 = 0xE0;

/// `0xE1 CLUSTER_PEER_DISCONNECTED` — emitted when a peer
/// connection closes (clean EOF, Goodbye, or error). `reason`
/// is one of `"eof"` / `"goodbye"` / `"error"`.
///
/// Payload (JSON): `{peer_id, reason, error, ts_unix}`.
/// `error` is `null` for clean disconnects; redacted via
/// `security::redact::redact_text` when present so a
/// validation-failure message can't leak secrets the peer
/// shoved into a frame.
pub const EVENT_TYPE_CLUSTER_PEER_DISCONNECTED: u8 = 0xE1;

/// `0xE2 CLUSTER_PEER_REJECTED` — handshake failure (wrong
/// protocol / version, cluster_name_hash mismatch, malformed
/// CBOR Hello). Distinct from `DISCONNECTED` so audit greps
/// can tell "we lost a peer" from "we refused a peer".
///
/// Payload (JSON): `{peer_id_claim, reason, ts_unix}`.
/// `peer_id_claim` is whatever the peer advertised — may be
/// untrusted (no handshake completed) so the audit log
/// quotes it verbatim. `reason` is redacted.
pub const EVENT_TYPE_CLUSTER_PEER_REJECTED: u8 = 0xE2;

/// `0xE3 CLUSTER_HEARTBEAT_FIRST` — emitted on the first
/// valid heartbeat from a peer after CONNECTED. Subsequent
/// heartbeats are NOT logged individually (would flood the
/// WAL at 5s cadence × N peers); load-class changes get
/// their own dedicated frame (planned: `0xE4`).
///
/// Payload (JSON): `{peer_id, tokens_per_sec, healthy,
/// inflight_requests, ts_unix}`.
pub const EVENT_TYPE_CLUSTER_HEARTBEAT_FIRST: u8 = 0xE3;

/// `0xE4 CLUSTER_PEER_HEALTH_CHANGED` — emitted when a peer's
/// `healthy` flag transitions (true → false or false → true).
/// One of the two operator-relevant heartbeat-band events;
/// other heartbeats land only in the in-memory PeerLoadRegistry.
///
/// Payload (JSON): `{peer_id, from_healthy, to_healthy,
/// last_tps, ts_unix}`.
pub const EVENT_TYPE_CLUSTER_PEER_HEALTH_CHANGED: u8 = 0xE4;

/// `0xE5 CLUSTER_CAPABILITIES_CHANGED` — emitted when a
/// peer's `capabilities_hash` changes (operator reconfigured
/// the peer's provider bindings while it was up). Distinct
/// from disconnect-then-reconnect so audit consumers see "X
/// added capability foo" as a single event.
///
/// Payload (JSON): `{peer_id, capabilities, ts_unix}`.
pub const EVENT_TYPE_CLUSTER_CAPABILITIES_CHANGED: u8 = 0xE5;

/// `0xE6 CLUSTER_PEER_CONFIRMED` — operator ran `neoth cluster
/// confirm` and the peer was written into `~/.neoth/cluster.yaml`.
/// Distinct from `CONNECTED` (0xE0): confirm is the operator's
/// pairing consent (Phase 4 ratified per architect), connect is
/// the transport-handshake (Phase 6 gossip).
///
/// Payload (JSON): `{pub_key_hex, instance_label, addr,
/// discovered_via, autonomy_level, ts_unix}`.
pub const EVENT_TYPE_CLUSTER_PEER_CONFIRMED: u8 = 0xE6;

/// `0xE7 CLUSTER_PEER_REVOKED` — operator ran `neoth cluster
/// revoke` and the peer was removed from cluster.yaml. Future
/// announces from this peer will surface as `PENDING_CONSENT`
/// in the doctor until re-confirmed.
///
/// Payload (JSON): `{pub_key_hex, ts_unix}`.
pub const EVENT_TYPE_CLUSTER_PEER_REVOKED: u8 = 0xE7;

/// `0xE8 CLUSTER_ROLE_CHANGED` — emitted when the local node's
/// cluster role transitions (e.g. `follower` → `orchestrator`,
/// `orchestrator` → `passive`). Drives the operator-facing
/// `neoth cluster status` line so a leader handoff is visible in
/// the WAL replay.
///
/// Payload (JSON): `{old_role, new_role, ts_unix, reason}`.
/// `reason` is one of `"election"` / `"manual"` / `"peer_loss"`.
/// C-5 Phase 5 (Session 21).
pub const EVENT_TYPE_CLUSTER_ROLE_CHANGED: u8 = 0xE8;

/// `0xE9 CLUSTER_REQUEST_FORWARDED` — emitted by the orchestrator
/// when an inbound `complete()` request is routed to a peer for
/// load/capability reasons (e.g. peer holds the GPU model the
/// local node lacks). Replay surfaces the routing decision next
/// to the matching `PROVIDER_REQUEST`.
///
/// Payload (JSON): `{request_id, target_peer_pubkey, reason,
/// ts_unix}`. `reason` is one of `"capability"` / `"load"` /
/// `"affinity"` / `"fallback"`.
/// C-5 Phase 5 (Session 21).
pub const EVENT_TYPE_CLUSTER_REQUEST_FORWARDED: u8 = 0xE9;

// Cluster band 0xE0..=0xE9 currently assigned. 0xEA..=0xEF reserved
// for further cluster lifecycle events (split-brain detection,
// cluster-wide config sync, leader stand-down, ...).

/// Pick #40 (Session 14, Agent #1 phase 2 fsync-batching design):
/// classify each `event_type` into "sync immediately" vs "batchable".
///
/// **SYNC_ON_WRITE (returns `true`)** — operator-correctness frames
/// whose loss on a crash would break audit / consent / durability
/// guarantees. These keep the existing per-frame `sync_data()`:
///   - lifecycle (BOOT) + segment markers (COMPACTION_MARKER)
///   - permission gates (PERMISSION_GRANTED/DENIED, LEVEL_ELEVATED/DEROGATED)
///   - provider final responses (PROVIDER_RESPONSE) — anchors the
///     reply, the chat dispatch reads this when reconstructing
///   - channel ingress/egress + ACK/EDIT (CHANNEL_*)
///   - profile mutations (PROFILE_DELTA/REINFORCED/SUPERSEDED/BLOCKED) —
///     load-bearing for the outbox-replay invariant
///   - tombstone + snapshot anchors (TOMBSTONE_REQUESTED, PRE_MUTATION_SNAPSHOT)
///   - quota + recovery (QUOTA_BREACHED, RECOVERY_TRUNCATED) — debug anchors
///   - config-lifecycle (CONFIG_RELOADED/REJECTED) — operator-visible audit
///
/// **BATCHABLE (returns `false`)** — high-cadence non-critical frames
/// whose loss in a crash-window of seconds is acceptable. These
/// piggyback their durability on the next SYNC_ON_WRITE frame OR
/// the writer's shutdown drain:
///   - streaming chunks (PROVIDER_STREAM_CHUNK) — the final
///     PROVIDER_RESPONSE anchors the same conversation
///   - hook lifecycle (HOOK_FIRED/BLOCKED/REPLACED/ERROR) —
///     observability, not durability
///   - local-inference progress (LOCAL_INFERENCE_START/END) —
///     diagnostic timing data
///
/// Default for unrecognised event_type: `true` (sync-immediately).
/// New event types err on the side of durability — they need
/// explicit opt-in to be batchable.
pub fn needs_immediate_sync(event_type: u8) -> bool {
    !matches!(
        event_type,
        EVENT_TYPE_PROVIDER_STREAM_CHUNK
            | EVENT_TYPE_HOOK_FIRED
            | EVENT_TYPE_HOOK_BLOCKED
            | EVENT_TYPE_HOOK_REPLACED
            | EVENT_TYPE_HOOK_ERROR
            | EVENT_TYPE_LOCAL_INFERENCE_START
            | EVENT_TYPE_LOCAL_INFERENCE_END
    )
}

/// Operator-initiated GDPR-style erasure request. Records the intent
/// and scope of a `neoth memory --forget <topic>` invocation in the WAL.
/// The SQLite tier cascade-delete plus groundtruth-revoke happens
/// synchronously; the physical WAL rewrite (replacing original payload
/// bytes with tombstone padding plus HMAC recompaction) is Phase-2 work
/// (CDX-01 follow-up). Until then, this event is the audit anchor:
/// even after Phase 2 ships, the original tombstone frame remains as
/// the proof-of-request row.
///
/// Payload fields: `topic`, `episode_rows`, `consolidated_rows`,
/// `longterm_rows`, `groundtruth_revoked`, `embedding_rows`, `ts_unix`,
/// `source` (one of `cli` / `gui` / `api`).
pub const EVENT_TYPE_TOMBSTONE_REQUESTED: u8 = 0xF1;

/// B-Rollback (CDX-02): pre-mutation snapshot frame. Effect-adapter
/// call sites (file write, channel send, SQL mutation, MCP tool invoke)
/// emit one of these BEFORE running the mutation so a later
/// `neoth rollback --to <id>` can restore the prior state.
///
/// Payload: `{mutation_kind, target, before_state (opaque bytes),
/// ts_unix}`. `mutation_kind` is a stable string id (`file_write`,
/// `channel_send`, `mcp_tool_invoke`, ...); `target` is the resource
/// identifier (file path, channel id, tool name); `before_state` is
/// whatever the adapter needs to undo the mutation (file content
/// snapshot, prior message id for delete-the-edit, ...). The snapshot
/// frame is the audit anchor; the rollback CLI consumes these to plan
/// + execute restoration.
pub const EVENT_TYPE_PRE_MUTATION_SNAPSHOT: u8 = 0xF2;

/// C-15 follow-up: operator-authorised redaction marker. Emitted by
/// `memory::forget --physical` AFTER `wal::redact::scan_and_redact`
/// finishes, one frame per touched segment. Records: segment path,
/// list of redacted frame offsets, byte count, audit reason
/// (`topic = "X"`), operator source (`cli`/`gui`/`api`), ts_unix.
///
/// Why this exists: redaction rewrites payload bytes + CRC of matched
/// frames, but the trailing `0x15 COMPACTION_MARKER`'s HMAC still
/// covers the ORIGINAL bytes. A naive integrity check would flag the
/// post-redaction segment as tampered. This marker is the audit
/// anchor that says "the HMAC mismatch on offsets [...] is
/// operator-authorised, not adversarial". Future `neoth verify`
/// reads these markers and skips the original-HMAC check on listed
/// offsets.
///
/// Payload: `{ segment, redacted_offsets: [u64], bytes_redacted: u64,
/// topic, source, ts_unix }`. Topic is the substring predicate that
/// matched, so a future audit consumer can map each marker back to
/// its driving forget request.
pub const EVENT_TYPE_REDACTION_MARKER: u8 = 0xF3;

// ---------------------------------------------------------------------------
// Compile-time invariants: assert every constant sits in its declared band.

const _: () = {
    let _ = [(); 1][(EVENT_TYPE_RAW_TEXT < 0x01 || EVENT_TYPE_RAW_TEXT > 0x0F) as usize];
    let _ = [(); 1][(EVENT_TYPE_REINFORCE < 0x01 || EVENT_TYPE_REINFORCE > 0x0F) as usize];
    let _ = [(); 1][(EVENT_TYPE_BOOT < 0x10 || EVENT_TYPE_BOOT > 0x1F) as usize];
    let _ = [(); 1][(EVENT_TYPE_SHUTDOWN < 0x10 || EVENT_TYPE_SHUTDOWN > 0x1F) as usize];
    let _ = [(); 1][(EVENT_TYPE_INSTALLER_RAN < 0x10 || EVENT_TYPE_INSTALLER_RAN > 0x1F) as usize];
    let _ = [(); 1][(EVENT_TYPE_UPDATE_RAN < 0x10 || EVENT_TYPE_UPDATE_RAN > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_SEGMENT_ROLLOVER < 0x10 || EVENT_TYPE_SEGMENT_ROLLOVER > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_COMPACTION_MARKER < 0x10 || EVENT_TYPE_COMPACTION_MARKER > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_REFUSAL_OBSERVED < 0x10 || EVENT_TYPE_REFUSAL_OBSERVED > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_REFUSAL_MIRRORED < 0x10 || EVENT_TYPE_REFUSAL_MIRRORED > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_REFUSAL_REDIRECTED < 0x10 || EVENT_TYPE_REFUSAL_REDIRECTED > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_REFUSAL_REROUTED < 0x10 || EVENT_TYPE_REFUSAL_REROUTED > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_REFUSAL_PERSISTENT < 0x10 || EVENT_TYPE_REFUSAL_PERSISTENT > 0x1F) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_PRESET_APPLIED < 0x10
        || EVENT_TYPE_PROFILE_PRESET_APPLIED > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_SELF_DEV_PROPOSED < 0x10 || EVENT_TYPE_SELF_DEV_PROPOSED > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_SELF_DEV_ACCEPTED < 0x10 || EVENT_TYPE_SELF_DEV_ACCEPTED > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_SELF_DEV_DECLINED < 0x10 || EVENT_TYPE_SELF_DEV_DECLINED > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_HEMISPHERE_REBOUND < 0x10 || EVENT_TYPE_HEMISPHERE_REBOUND > 0x1F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PROVIDER_REQUEST < 0x20 || EVENT_TYPE_PROVIDER_REQUEST > 0x2F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PROVIDER_RESPONSE < 0x20 || EVENT_TYPE_PROVIDER_RESPONSE > 0x2F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_PROVIDER_ERROR < 0x20 || EVENT_TYPE_PROVIDER_ERROR > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROVIDER_STREAM_CHUNK < 0x20
        || EVENT_TYPE_PROVIDER_STREAM_CHUNK > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED < 0x20
        || EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_LOCAL_INFERENCE_START < 0x20
        || EVENT_TYPE_LOCAL_INFERENCE_START > 0x2F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_LOCAL_INFERENCE_END < 0x20 || EVENT_TYPE_LOCAL_INFERENCE_END > 0x2F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_INGEST_EXTRACTED < 0x20 || EVENT_TYPE_INGEST_EXTRACTED > 0x2F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_EMBED_PERSISTED < 0x20 || EVENT_TYPE_EMBED_PERSISTED > 0x2F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_BUDGET_EXCEEDED < 0x20 || EVENT_TYPE_BUDGET_EXCEEDED > 0x2F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_CHANNEL_INGRESS < 0x30 || EVENT_TYPE_CHANNEL_INGRESS > 0x3F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_CHANNEL_EGRESS < 0x30 || EVENT_TYPE_CHANNEL_EGRESS > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CHANNEL_ERROR < 0x30 || EVENT_TYPE_CHANNEL_ERROR > 0x3F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_INGRESS_QUARANTINED < 0x30 || EVENT_TYPE_INGRESS_QUARANTINED > 0x3F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_INGRESS_SANITIZED < 0x30 || EVENT_TYPE_INGRESS_SANITIZED > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CHANNEL_ACK < 0x30 || EVENT_TYPE_CHANNEL_ACK > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CHANNEL_EDIT < 0x30 || EVENT_TYPE_CHANNEL_EDIT > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_N8N_REQUEST < 0x30 || EVENT_TYPE_N8N_REQUEST > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_JOB_FIRED < 0x40 || EVENT_TYPE_JOB_FIRED > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_JOB_SUCCESS < 0x40 || EVENT_TYPE_JOB_SUCCESS > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_JOB_FAILED < 0x40 || EVENT_TYPE_JOB_FAILED > 0x4F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_JOB_SKIPPED_BY_GATE < 0x40 || EVENT_TYPE_JOB_SKIPPED_BY_GATE > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_DOCTOR_TICK < 0x40 || EVENT_TYPE_DOCTOR_TICK > 0x4F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_RECOVERY_TRUNCATED < 0x50 || EVENT_TYPE_RECOVERY_TRUNCATED > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED < 0x60
        || EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL < 0x60
        || EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_SKIP < 0x60 || EVENT_TYPE_COUNCIL_SKIP > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_WINNER_SELECTED < 0x60
        || EVENT_TYPE_COUNCIL_WINNER_SELECTED > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_DIVERSITY_WARNING < 0x60
        || EVENT_TYPE_COUNCIL_DIVERSITY_WARNING > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_HOOK_FIRED < 0x80 || EVENT_TYPE_HOOK_FIRED > 0x8F) as usize];
    let _ = [(); 1][(EVENT_TYPE_HOOK_BLOCKED < 0x80 || EVENT_TYPE_HOOK_BLOCKED > 0x8F) as usize];
    let _ = [(); 1][(EVENT_TYPE_HOOK_REPLACED < 0x80 || EVENT_TYPE_HOOK_REPLACED > 0x8F) as usize];
    let _ = [(); 1][(EVENT_TYPE_HOOK_ERROR < 0x80 || EVENT_TYPE_HOOK_ERROR > 0x8F) as usize];
    let _ = [(); 1][(EVENT_TYPE_SUBAGENT_REVIEW_STAGE < 0x80
        || EVENT_TYPE_SUBAGENT_REVIEW_STAGE > 0x8F) as usize];
    let _ = [(); 1][(EVENT_TYPE_EPISODE_CONSOLIDATED < 0x90
        || EVENT_TYPE_EPISODE_CONSOLIDATED > 0x9F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_EPISODE_PROMOTED < 0x90 || EVENT_TYPE_EPISODE_PROMOTED > 0x9F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_EPISODE_ARCHIVED < 0x90 || EVENT_TYPE_EPISODE_ARCHIVED > 0x9F) as usize];
    let _ = [(); 1][(EVENT_TYPE_IMPORTANCE_REINFORCED < 0x90
        || EVENT_TYPE_IMPORTANCE_REINFORCED > 0x9F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_CONSOLIDATION_PASS < 0x90 || EVENT_TYPE_CONSOLIDATION_PASS > 0x9F) as usize];
    let _ = [(); 1][(EVENT_TYPE_IMPORTANCE_THRESHOLD_CROSSED < 0x90
        || EVENT_TYPE_IMPORTANCE_THRESHOLD_CROSSED > 0x9F) as usize];
    let _ = [(); 1][(EVENT_TYPE_ARCHIVE_ACCESSED_DIRECT < 0x90
        || EVENT_TYPE_ARCHIVE_ACCESSED_DIRECT > 0x9F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_GROUNDTRUTH_ADDED < 0x90 || EVENT_TYPE_GROUNDTRUTH_ADDED > 0x9F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_GROUNDTRUTH_REVOKED < 0x90 || EVENT_TYPE_GROUNDTRUTH_REVOKED > 0x9F) as usize];
    let _ = [(); 1][(EVENT_TYPE_GROUNDTRUTH_IMPORTED < 0x90
        || EVENT_TYPE_GROUNDTRUTH_IMPORTED > 0x9F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_MODE_CHECKPOINT < 0x90 || EVENT_TYPE_MODE_CHECKPOINT > 0x9F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PERMISSION_GRANTED < 0xA0 || EVENT_TYPE_PERMISSION_GRANTED > 0xAF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PERMISSION_DENIED < 0xA0 || EVENT_TYPE_PERMISSION_DENIED > 0xAF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_LEVEL_ELEVATED < 0xA0 || EVENT_TYPE_LEVEL_ELEVATED > 0xAF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_LEVEL_DEROGATED < 0xA0 || EVENT_TYPE_LEVEL_DEROGATED > 0xAF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_COST_ESTIMATE_SHOWN < 0xA0 || EVENT_TYPE_COST_ESTIMATE_SHOWN > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_DELTA < 0xB0 || EVENT_TYPE_PROFILE_DELTA > 0xBF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PROFILE_REINFORCED < 0xB0 || EVENT_TYPE_PROFILE_REINFORCED > 0xBF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PROFILE_SUPERSEDED < 0xB0 || EVENT_TYPE_PROFILE_SUPERSEDED > 0xBF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_DELTA_BLOCKED < 0xB0
        || EVENT_TYPE_PROFILE_DELTA_BLOCKED > 0xBF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT < 0xB0
        || EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT > 0xBF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_MCP_TOOL_CALLED < 0xC0 || EVENT_TYPE_MCP_TOOL_CALLED > 0xCF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PLUGIN_LOADED < 0xC0 || EVENT_TYPE_PLUGIN_LOADED > 0xCF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_PLUGIN_REJECTED < 0xC0 || EVENT_TYPE_PLUGIN_REJECTED > 0xCF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_PLUGIN_HOSTCALL < 0xC0 || EVENT_TYPE_PLUGIN_HOSTCALL > 0xCF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED < 0xC0
        || EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED > 0xCF) as usize];
    // V11 Pick #38 (2026-05-19): coding-workflow band 0x70..=0x7F.
    let _ = [(); 1][(EVENT_TYPE_KANBAN_SESSION_OPENED < 0x70
        || EVENT_TYPE_KANBAN_SESSION_OPENED > 0x7F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_KANBAN_TASK_CREATED < 0x70 || EVENT_TYPE_KANBAN_TASK_CREATED > 0x7F) as usize];
    let _ = [(); 1][(EVENT_TYPE_KANBAN_TASK_ASSIGNED < 0x70
        || EVENT_TYPE_KANBAN_TASK_ASSIGNED > 0x7F) as usize];
    let _ = [(); 1][(EVENT_TYPE_KANBAN_STATUS_CHANGED < 0x70
        || EVENT_TYPE_KANBAN_STATUS_CHANGED > 0x7F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_KANBAN_TASK_COMMENT < 0x70 || EVENT_TYPE_KANBAN_TASK_COMMENT > 0x7F) as usize];
    let _ = [(); 1][(EVENT_TYPE_KANBAN_TASK_COMPLETED < 0x70
        || EVENT_TYPE_KANBAN_TASK_COMPLETED > 0x7F) as usize];
    let _ = [(); 1][(EVENT_TYPE_KANBAN_SESSION_CLOSED < 0x70
        || EVENT_TYPE_KANBAN_SESSION_CLOSED > 0x7F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_CONFIG_RELOADED < 0xD0 || EVENT_TYPE_CONFIG_RELOADED > 0xDF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CONFIG_RELOAD_REJECTED < 0xD0
        || EVENT_TYPE_CONFIG_RELOAD_REJECTED > 0xDF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_SELF_UPDATE_APPLIED < 0xD0 || EVENT_TYPE_SELF_UPDATE_APPLIED > 0xDF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PATCH_APPLIED < 0xD0 || EVENT_TYPE_PATCH_APPLIED > 0xDF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PATCH_APPLY_FAILED < 0xD0 || EVENT_TYPE_PATCH_APPLY_FAILED > 0xDF) as usize];
    // R-7 cluster lifecycle band (0xE0..=0xE7).
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_CONNECTED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_CONNECTED > 0xE7) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_DISCONNECTED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_DISCONNECTED > 0xE7) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_REJECTED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_REJECTED > 0xE7) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_HEARTBEAT_FIRST < 0xE0
        || EVENT_TYPE_CLUSTER_HEARTBEAT_FIRST > 0xE7) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_HEALTH_CHANGED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_HEALTH_CHANGED > 0xE7) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_CAPABILITIES_CHANGED < 0xE0
        || EVENT_TYPE_CLUSTER_CAPABILITIES_CHANGED > 0xE7) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_CONFIRMED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_CONFIRMED > 0xE7) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_REVOKED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_REVOKED > 0xE7) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_ROLE_CHANGED < 0xE0
        || EVENT_TYPE_CLUSTER_ROLE_CHANGED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_REQUEST_FORWARDED < 0xE0
        || EVENT_TYPE_CLUSTER_REQUEST_FORWARDED > 0xEF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_MCP_TOOL_REJECTED < 0xC0 || EVENT_TYPE_MCP_TOOL_REJECTED > 0xCF) as usize];
    // 0xF0-0xFF band: u8 max == 0xFF so upper-bound check is trivially
    // true (clippy::absurd_extreme_comparisons). Only lower-bound check
    // is meaningful here.
    let _ = [(); 1][(EVENT_TYPE_QUOTA_BREACHED < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_TOMBSTONE_REQUESTED < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_PRE_MUTATION_SNAPSHOT < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_REDACTION_MARKER < 0xF0) as usize];
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Every published event-code must be unique. Catches accidental
    /// duplicate-assignment when a new code is added.
    #[test]
    fn all_event_codes_are_unique() {
        let codes = [
            ("RAW_TEXT", EVENT_TYPE_RAW_TEXT),
            ("REINFORCE", EVENT_TYPE_REINFORCE),
            ("BOOT", EVENT_TYPE_BOOT),
            ("SHUTDOWN", EVENT_TYPE_SHUTDOWN),
            ("INSTALLER_RAN", EVENT_TYPE_INSTALLER_RAN),
            ("UPDATE_RAN", EVENT_TYPE_UPDATE_RAN),
            ("SEGMENT_ROLLOVER", EVENT_TYPE_SEGMENT_ROLLOVER),
            ("COMPACTION_MARKER", EVENT_TYPE_COMPACTION_MARKER),
            ("REFUSAL_OBSERVED", EVENT_TYPE_REFUSAL_OBSERVED),
            ("REFUSAL_MIRRORED", EVENT_TYPE_REFUSAL_MIRRORED),
            ("REFUSAL_REDIRECTED", EVENT_TYPE_REFUSAL_REDIRECTED),
            ("REFUSAL_REROUTED", EVENT_TYPE_REFUSAL_REROUTED),
            ("REFUSAL_PERSISTENT", EVENT_TYPE_REFUSAL_PERSISTENT),
            ("PROFILE_PRESET_APPLIED", EVENT_TYPE_PROFILE_PRESET_APPLIED),
            ("SELF_DEV_PROPOSED", EVENT_TYPE_SELF_DEV_PROPOSED),
            ("SELF_DEV_ACCEPTED", EVENT_TYPE_SELF_DEV_ACCEPTED),
            ("SELF_DEV_DECLINED", EVENT_TYPE_SELF_DEV_DECLINED),
            ("HEMISPHERE_REBOUND", EVENT_TYPE_HEMISPHERE_REBOUND),
            ("PROVIDER_REQUEST", EVENT_TYPE_PROVIDER_REQUEST),
            ("PROVIDER_RESPONSE", EVENT_TYPE_PROVIDER_RESPONSE),
            ("PROVIDER_ERROR", EVENT_TYPE_PROVIDER_ERROR),
            ("PROVIDER_STREAM_CHUNK", EVENT_TYPE_PROVIDER_STREAM_CHUNK),
            (
                "PROVIDER_QUOTA_EXCEEDED",
                EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED,
            ),
            ("LOCAL_INFERENCE_START", EVENT_TYPE_LOCAL_INFERENCE_START),
            ("LOCAL_INFERENCE_END", EVENT_TYPE_LOCAL_INFERENCE_END),
            ("INGEST_EXTRACTED", EVENT_TYPE_INGEST_EXTRACTED),
            ("EMBED_PERSISTED", EVENT_TYPE_EMBED_PERSISTED),
            ("BUDGET_EXCEEDED", EVENT_TYPE_BUDGET_EXCEEDED),
            ("CHANNEL_INGRESS", EVENT_TYPE_CHANNEL_INGRESS),
            ("CHANNEL_EGRESS", EVENT_TYPE_CHANNEL_EGRESS),
            ("CHANNEL_ERROR", EVENT_TYPE_CHANNEL_ERROR),
            ("INGRESS_QUARANTINED", EVENT_TYPE_INGRESS_QUARANTINED),
            ("INGRESS_SANITIZED", EVENT_TYPE_INGRESS_SANITIZED),
            ("CHANNEL_ACK", EVENT_TYPE_CHANNEL_ACK),
            ("CHANNEL_EDIT", EVENT_TYPE_CHANNEL_EDIT),
            ("N8N_REQUEST", EVENT_TYPE_N8N_REQUEST),
            ("JOB_FIRED", EVENT_TYPE_JOB_FIRED),
            ("JOB_SUCCESS", EVENT_TYPE_JOB_SUCCESS),
            ("JOB_FAILED", EVENT_TYPE_JOB_FAILED),
            ("RECOVERY_TRUNCATED", EVENT_TYPE_RECOVERY_TRUNCATED),
            (
                "COUNCIL_SYNTHESIS_ATTEMPTED",
                EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED,
            ),
            (
                "COUNCIL_PARTIAL_REFUSAL",
                EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL,
            ),
            ("COUNCIL_SKIP", EVENT_TYPE_COUNCIL_SKIP),
            (
                "COUNCIL_WINNER_SELECTED",
                EVENT_TYPE_COUNCIL_WINNER_SELECTED,
            ),
            (
                "COUNCIL_DIVERSITY_WARNING",
                EVENT_TYPE_COUNCIL_DIVERSITY_WARNING,
            ),
            ("HOOK_FIRED", EVENT_TYPE_HOOK_FIRED),
            ("HOOK_BLOCKED", EVENT_TYPE_HOOK_BLOCKED),
            ("HOOK_REPLACED", EVENT_TYPE_HOOK_REPLACED),
            ("HOOK_ERROR", EVENT_TYPE_HOOK_ERROR),
            ("SUBAGENT_REVIEW_STAGE", EVENT_TYPE_SUBAGENT_REVIEW_STAGE),
            ("EPISODE_CONSOLIDATED", EVENT_TYPE_EPISODE_CONSOLIDATED),
            ("EPISODE_PROMOTED", EVENT_TYPE_EPISODE_PROMOTED),
            ("EPISODE_ARCHIVED", EVENT_TYPE_EPISODE_ARCHIVED),
            ("IMPORTANCE_REINFORCED", EVENT_TYPE_IMPORTANCE_REINFORCED),
            ("CONSOLIDATION_PASS", EVENT_TYPE_CONSOLIDATION_PASS),
            (
                "IMPORTANCE_THRESHOLD_CROSSED",
                EVENT_TYPE_IMPORTANCE_THRESHOLD_CROSSED,
            ),
            (
                "ARCHIVE_ACCESSED_DIRECT",
                EVENT_TYPE_ARCHIVE_ACCESSED_DIRECT,
            ),
            ("GROUNDTRUTH_ADDED", EVENT_TYPE_GROUNDTRUTH_ADDED),
            ("GROUNDTRUTH_REVOKED", EVENT_TYPE_GROUNDTRUTH_REVOKED),
            ("GROUNDTRUTH_IMPORTED", EVENT_TYPE_GROUNDTRUTH_IMPORTED),
            ("MODE_CHECKPOINT", EVENT_TYPE_MODE_CHECKPOINT),
            ("PERMISSION_GRANTED", EVENT_TYPE_PERMISSION_GRANTED),
            ("PERMISSION_DENIED", EVENT_TYPE_PERMISSION_DENIED),
            ("LEVEL_ELEVATED", EVENT_TYPE_LEVEL_ELEVATED),
            ("LEVEL_DEROGATED", EVENT_TYPE_LEVEL_DEROGATED),
            ("COST_ESTIMATE_SHOWN", EVENT_TYPE_COST_ESTIMATE_SHOWN),
            ("PROFILE_DELTA", EVENT_TYPE_PROFILE_DELTA),
            ("PROFILE_REINFORCED", EVENT_TYPE_PROFILE_REINFORCED),
            ("PROFILE_SUPERSEDED", EVENT_TYPE_PROFILE_SUPERSEDED),
            (
                "PROFILE_BASELINE_SNAPSHOT",
                EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
            ),
            ("PROFILE_DELTA_BLOCKED", EVENT_TYPE_PROFILE_DELTA_BLOCKED),
            ("MCP_TOOL_CALLED", EVENT_TYPE_MCP_TOOL_CALLED),
            ("MCP_TOOL_REJECTED", EVENT_TYPE_MCP_TOOL_REJECTED),
            ("PLUGIN_LOADED", EVENT_TYPE_PLUGIN_LOADED),
            ("PLUGIN_REJECTED", EVENT_TYPE_PLUGIN_REJECTED),
            ("PLUGIN_HOSTCALL", EVENT_TYPE_PLUGIN_HOSTCALL),
            ("PLUGIN_FUEL_EXHAUSTED", EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED),
            ("KANBAN_SESSION_OPENED", EVENT_TYPE_KANBAN_SESSION_OPENED),
            ("KANBAN_TASK_CREATED", EVENT_TYPE_KANBAN_TASK_CREATED),
            ("KANBAN_TASK_ASSIGNED", EVENT_TYPE_KANBAN_TASK_ASSIGNED),
            ("KANBAN_STATUS_CHANGED", EVENT_TYPE_KANBAN_STATUS_CHANGED),
            ("KANBAN_TASK_COMMENT", EVENT_TYPE_KANBAN_TASK_COMMENT),
            ("KANBAN_TASK_COMPLETED", EVENT_TYPE_KANBAN_TASK_COMPLETED),
            ("KANBAN_SESSION_CLOSED", EVENT_TYPE_KANBAN_SESSION_CLOSED),
            ("KANBAN_TASK_PROGRESS", EVENT_TYPE_KANBAN_TASK_PROGRESS),
            ("CONFIG_RELOADED", EVENT_TYPE_CONFIG_RELOADED),
            ("CONFIG_RELOAD_REJECTED", EVENT_TYPE_CONFIG_RELOAD_REJECTED),
            ("SELF_UPDATE_APPLIED", EVENT_TYPE_SELF_UPDATE_APPLIED),
            ("PATCH_APPLIED", EVENT_TYPE_PATCH_APPLIED),
            ("PATCH_APPLY_FAILED", EVENT_TYPE_PATCH_APPLY_FAILED),
            ("CLUSTER_PEER_CONNECTED", EVENT_TYPE_CLUSTER_PEER_CONNECTED),
            (
                "CLUSTER_PEER_DISCONNECTED",
                EVENT_TYPE_CLUSTER_PEER_DISCONNECTED,
            ),
            ("CLUSTER_PEER_REJECTED", EVENT_TYPE_CLUSTER_PEER_REJECTED),
            (
                "CLUSTER_HEARTBEAT_FIRST",
                EVENT_TYPE_CLUSTER_HEARTBEAT_FIRST,
            ),
            (
                "CLUSTER_PEER_HEALTH_CHANGED",
                EVENT_TYPE_CLUSTER_PEER_HEALTH_CHANGED,
            ),
            (
                "CLUSTER_CAPABILITIES_CHANGED",
                EVENT_TYPE_CLUSTER_CAPABILITIES_CHANGED,
            ),
            ("CLUSTER_PEER_CONFIRMED", EVENT_TYPE_CLUSTER_PEER_CONFIRMED),
            ("CLUSTER_PEER_REVOKED", EVENT_TYPE_CLUSTER_PEER_REVOKED),
            ("CLUSTER_ROLE_CHANGED", EVENT_TYPE_CLUSTER_ROLE_CHANGED),
            (
                "CLUSTER_REQUEST_FORWARDED",
                EVENT_TYPE_CLUSTER_REQUEST_FORWARDED,
            ),
            ("QUOTA_BREACHED", EVENT_TYPE_QUOTA_BREACHED),
            ("TOMBSTONE_REQUESTED", EVENT_TYPE_TOMBSTONE_REQUESTED),
            ("PRE_MUTATION_SNAPSHOT", EVENT_TYPE_PRE_MUTATION_SNAPSHOT),
            ("REDACTION_MARKER", EVENT_TYPE_REDACTION_MARKER),
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(
                    codes[i].1, codes[j].1,
                    "event-code collision: {} and {} both = 0x{:02X}",
                    codes[i].0, codes[j].0, codes[i].1,
                );
            }
        }
    }

    /// REINFORCE must sit in the memory band, not the lifecycle band.
    /// Regression guard for Phase 33a AU-B1.
    #[test]
    fn plugin_event_codes_are_in_tool_band() {
        // V10-04 Pick #34b — every plugin event lives in 0xC0..=0xCF
        // alongside MCP_TOOL_*. Pin the literals so the operator
        // runbook `neoth wal show --type 0xC2` stays stable.
        assert_eq!(EVENT_TYPE_PLUGIN_LOADED, 0xC2);
        assert_eq!(EVENT_TYPE_PLUGIN_REJECTED, 0xC3);
        assert_eq!(EVENT_TYPE_PLUGIN_HOSTCALL, 0xC4);
        assert_eq!(EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED, 0xC5);
        for code in [
            EVENT_TYPE_PLUGIN_LOADED,
            EVENT_TYPE_PLUGIN_REJECTED,
            EVENT_TYPE_PLUGIN_HOSTCALL,
            EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED,
        ] {
            assert!(
                (0xC0..=0xCF).contains(&code),
                "0x{code:02X} escaped tool band 0xC0..=0xCF",
            );
        }
    }

    #[test]
    fn plugin_events_need_immediate_sync() {
        // Plugin lifecycle frames are durability-critical (LOADED +
        // REJECTED anchor the operator's plugin-state audit trail;
        // FUEL_EXHAUSTED records a crash). Non-batchable.
        for code in [
            EVENT_TYPE_PLUGIN_LOADED,
            EVENT_TYPE_PLUGIN_REJECTED,
            EVENT_TYPE_PLUGIN_HOSTCALL,
            EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED,
        ] {
            assert!(needs_immediate_sync(code));
        }
    }

    /// V11 Pick #38 (2026-05-19): coding-workflow event codes live in
    /// 0x70..=0x7F. Pin the literals so operator runbooks (`neoth wal
    /// show --type 0x70`) + the SPEC + the kanban dispatcher all stay
    /// in agreement.
    #[test]
    fn kanban_event_codes_are_in_coding_band() {
        assert_eq!(EVENT_TYPE_KANBAN_SESSION_OPENED, 0x70);
        assert_eq!(EVENT_TYPE_KANBAN_TASK_CREATED, 0x71);
        assert_eq!(EVENT_TYPE_KANBAN_TASK_ASSIGNED, 0x72);
        assert_eq!(EVENT_TYPE_KANBAN_STATUS_CHANGED, 0x73);
        assert_eq!(EVENT_TYPE_KANBAN_TASK_COMMENT, 0x74);
        assert_eq!(EVENT_TYPE_KANBAN_TASK_COMPLETED, 0x75);
        assert_eq!(EVENT_TYPE_KANBAN_SESSION_CLOSED, 0x76);
        for code in [
            EVENT_TYPE_KANBAN_SESSION_OPENED,
            EVENT_TYPE_KANBAN_TASK_CREATED,
            EVENT_TYPE_KANBAN_TASK_ASSIGNED,
            EVENT_TYPE_KANBAN_STATUS_CHANGED,
            EVENT_TYPE_KANBAN_TASK_COMMENT,
            EVENT_TYPE_KANBAN_TASK_COMPLETED,
            EVENT_TYPE_KANBAN_SESSION_CLOSED,
        ] {
            assert!(
                (0x70..=0x7F).contains(&code),
                "0x{code:02X} escaped coding band 0x70..=0x7F",
            );
        }
    }

    #[test]
    fn kanban_events_need_immediate_sync() {
        // The full coding-workflow audit chain MUST survive a crash
        // mid-task. A daemon that segfaults during a worker dispatch
        // must reopen with the kanban session + every transition that
        // landed before the crash intact. None of these are
        // batchable.
        for code in [
            EVENT_TYPE_KANBAN_SESSION_OPENED,
            EVENT_TYPE_KANBAN_TASK_CREATED,
            EVENT_TYPE_KANBAN_TASK_ASSIGNED,
            EVENT_TYPE_KANBAN_STATUS_CHANGED,
            EVENT_TYPE_KANBAN_TASK_COMMENT,
            EVENT_TYPE_KANBAN_TASK_COMPLETED,
            EVENT_TYPE_KANBAN_SESSION_CLOSED,
        ] {
            assert!(
                needs_immediate_sync(code),
                "0x{code:02X} MUST have immediate_sync=true — coding audit"
            );
        }
    }

    #[test]
    fn reinforce_is_in_memory_band() {
        assert!(
            (0x01..=0x0F).contains(&EVENT_TYPE_REINFORCE),
            "REINFORCE = 0x{:02X} escaped memory band 0x01..=0x0F",
            EVENT_TYPE_REINFORCE,
        );
    }

    // ── PROFILE_BASELINE_SNAPSHOT 0xB3 (v1.1 §A3 Phase-3 reservation) ─

    /// Pin the literal so a future code-shuffle doesn't quietly drift
    /// the Phase-3 drift anchor onto a different event-type. Operators
    /// have `neoth wal show --type 0xB3` baked into runbooks; the test
    /// freezes the code as part of the public contract.
    #[test]
    fn profile_baseline_snapshot_is_0xb3() {
        assert_eq!(EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT, 0xB3);
    }

    /// Profile band invariant: the event must sit in 0xB0..=0xBF so
    /// the band-membership compile-time check still covers it.
    #[test]
    fn profile_baseline_snapshot_lives_in_profile_band() {
        assert!(
            (0xB0..=0xBF).contains(&EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT),
            "PROFILE_BASELINE_SNAPSHOT = 0x{:02X} escaped profile band 0xB0..=0xBF",
            EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
        );
    }

    /// Phase-3 invariant: the snapshot frame MUST land with an
    /// immediate fsync. Loss on a crash would break the Phase-4 drift
    /// detection baseline — the audit-trail is the entire point of
    /// the event. `needs_immediate_sync` is a deny-list, so the
    /// default for any unknown event_type is `true` — this test pins
    /// that PROFILE_BASELINE_SNAPSHOT was NOT accidentally added to
    /// the batchable allowlist.
    #[test]
    fn profile_baseline_snapshot_needs_immediate_sync() {
        assert!(needs_immediate_sync(EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT));
    }

    /// Distinct from every other profile-band event so the band test
    /// in `event_codes_have_no_collisions` (line 817) actually catches
    /// any future drift back onto a sibling code.
    #[test]
    fn profile_baseline_snapshot_is_distinct_from_siblings() {
        assert_ne!(
            EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
            EVENT_TYPE_PROFILE_DELTA
        );
        assert_ne!(
            EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
            EVENT_TYPE_PROFILE_REINFORCED
        );
        assert_ne!(
            EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
            EVENT_TYPE_PROFILE_SUPERSEDED
        );
        assert_ne!(
            EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
            EVENT_TYPE_PROFILE_DELTA_BLOCKED
        );
    }
}
