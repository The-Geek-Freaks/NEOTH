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
//! | `0x50..=0x5F`  | Safety / recovery — panic, risk-gate, hints, web-extract|
//! | `0x60..=0x6F`  | Council debate + callosum (CH-08)                      |
//! | `0x70..=0x7F`  | (reserved)                                             |
//! | `0x80..=0x8F`  | (reserved Phase 29) Hooks lifecycle                    |
//! | `0x90..=0x9F`  | Memory tiers (R-22..R-24) — consolidation, decay, GT   |
//! | `0xA0..=0xAF`  | Permissions / autonomy (R-23)                          |
//! | `0xB0..=0xDF`  | (reserved)                                             |
//! | `0xE0..=0xEF`  | Cluster lifecycle (R-7) — 0xE0..=0xEA assigned         |
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
/// Inbound response from an LLM provider. Payload: response hash + tokens
/// (incl. `prompt_token_actual`, pairing with PROVIDER_REQUEST's
/// `prompt_token_estimate` per ARCH-04) + latency.
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
/// SPEC-03b — a provider FALLBACK hop was ATTEMPTED: the primary (or a
/// prior hop) returned a 429 and the fallback chain moved the prompt to
/// the next consented provider. This closes the trust-claim audit gap —
/// when a prompt "wanders" from provider A to provider B under quota
/// pressure, the move is now durably recorded, not just `tracing::warn!`.
/// Emitted at the hop-decision site inside `providers::fallback`, once per
/// actual attempt (a 429-backoff SKIP does NOT emit — no hop is taken).
///
/// Payload (JSON):
///   - `from_provider`: the chain PRIMARY (`chain[0]`) — the head of the
///     fallback chain, NOT necessarily the immediate 429-source on a
///     multi-hop chain. For a 3+ provider chain the immediate source of
///     hop N is the candidate at position N-1; reconstruct the exact walk
///     from `hop` (1-based) against the static `freedom.yaml::fallback.chain`
///     order. (Single-fallback chains — the common case — have one hop, so
///     primary IS the 429-source there.)
///   - `to_provider`: the provider being attempted on this hop
///   - `reason`: `"quota_429"` (the only trigger — non-429 errors propagate
///               immediately without failover)
///   - `hop`: 1-based hop index (does not count the primary attempt)
///   - `prompt_hash_xxh3`: xxh3-64 of the prompt text, correlates with the
///                         `PROVIDER_REQUEST` (0x20) frame for the same turn
///   - `ts_unix`: seconds since epoch
pub const EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED: u8 = 0x25;
/// GOLD-FEAT-08 Tier-3 — the abliterated local-model fallback produced a
/// non-refused completion that replaced the cloud refusal. Payload:
/// `{model, prompt_hash_xxh3, ts_unix}`.
pub const EVENT_TYPE_REFUSAL_ABLITERATED_USED: u8 = 0x26;
/// GOLD-FEAT-08 Tier-3 — the abliterated fallback was attempted but the cloud
/// re-ask still failed; the original refusal is surfaced. Payload:
/// `{model, error, prompt_hash_xxh3, ts_unix}`.
pub const EVENT_TYPE_REFUSAL_ABLITERATED_FAILED: u8 = 0x27;
/// GOLD-FEAT-08 — a prompt matched the permanent hard-block floor (CSAM /
/// bio-chem weapon / mass-casualty); no reframing or local routing is
/// attempted. Payload: `{reason, prompt_hash_xxh3, ts_unix}`.
pub const EVENT_TYPE_REFUSAL_HARD_BLOCKED: u8 = 0x28;
/// Round-3 v0.4 ARCH-07 — LOWKEY skill injection was SKIPPED for the
/// current turn (operator-disabled / disabled_for_eval_sessions /
/// content_hash mismatch against the pinned baseline). Sits in the
/// provider-lifecycle band because the skip influences which prompt
/// blocks reach PROVIDER_REQUEST.
///
/// Payload (JSON):
///   - `skill_id`: stable ID of the skipped skill
///   - `content_hash`: 64-char hex SHA-256 of the skill's yaml||template
///   - `reason`: one of `"eval_session"` / `"operator_disabled"` /
///                `"hash_mismatch"` / `"feature_off"`
///   - `request_id`: matches the downstream PROVIDER_REQUEST that
///                   ran without the skill's injection
pub const EVENT_TYPE_SKILL_INJECT_SKIPPED: u8 = 0x29;

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
/// SPEC-04 (Session 28) — profile-extraction provider-target audit
/// frame. Emitted once per `profile::run_pipeline` invocation, BEFORE
/// the Stage-3 extract LLM call, recording which provider will handle
/// the operator's raw conversation window + whether that provider is
/// on-device (`local`) or off-device (`cloud`). Gives an auditor
/// durable proof-in-the-WAL of the privacy posture for every
/// extraction turn — the `neoth privacy audit` CLI reports the
/// *current* config; this frame records what *actually happened* per
/// turn, so a posture regression is visible in the audit chain even
/// if the config was later flipped back.
///
/// **Band note**: the SPEC text proposed `0x3A/0x3B/0x3C` but that
/// band (`0x30..=0x3F`) is Channels. Provider-target audit is a
/// provider-lifecycle concern, so it lands in `0x20..=0x2F` next to
/// PROVIDER_REQUEST / LOCAL_INFERENCE_START. One event with a typed
/// `target` field replaces the 3 proposed codes (local/cloud/skipped
/// collapse to one frame shape).
///
/// Payload (JSON):
///   - `trigger_event_id`: i64 — the RAW_TEXT event that triggered
///     this extraction (correlates the audit frame to the turn)
///   - `provider`: String — `Provider::name()` of the extract provider
///   - `target`: String — `"local"` (on-device, no privacy concern)
///     or `"cloud"` (off-device; operator's raw window leaves the box)
///   - `ts_unix`: i64
pub const EVENT_TYPE_PROFILE_EXTRACT_TARGET: u8 = 0x2E;
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

/// `0x30 EMAIL_INGRESS_QUARANTINED` — EM-01b/PL-05b. High-signal subset of
/// `0x3D EMAIL_INGRESS_TRIAGED`: emitted ADDITIONALLY when an inbound email's
/// body was WITHHELD from the agent — either dropped at the ingress sanitizer
/// (prompt-injection / MIME poisoning) or scored into Quarantine. Lets an
/// operator `wal show --type email_ingress_quarantined` to see exactly the
/// dangerous mail. Metadata only (sender domain + score + which body-withheld
/// action), never the body.
///
/// Payload (JSON): `{uid, from_domain, score, action, ts_unix}`.
pub const EVENT_TYPE_EMAIL_INGRESS_QUARANTINED: u8 = 0x30;

/// `0x31 EMAIL_TIEBREAK_APPLIED` — PL-05b. Emitted when the LLM second-opinion
/// tie-breaker was CONSULTED on a borderline (ReviewQueue) email — the
/// security-relevant record of an LLM influencing an inbound-mail decision.
/// Carries the verdict + the resulting band (the input band is always
/// review-queue, so a `quarantine`/`deliver` result means the LLM OVERRODE the
/// deterministic rules). Metadata only.
///
/// Payload (JSON): `{uid, from_domain, verdict, resulting_action, ts_unix}`.
pub const EVENT_TYPE_EMAIL_TIEBREAK_APPLIED: u8 = 0x31;

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
/// `0x3A PROACTIVE_SENT` — the daemon, on its OWN initiative (no inbound
/// prompt), delivered a proactive message OUT to a messaging channel via
/// `Channel::send_proactive`. Distinct from `0x33 CHANNEL_EGRESS` (the
/// reply path) so an operator can grep exactly when "the daemon spoke
/// unprompted". Emitted by the G-01 proactive delivery tick. Payload:
/// `{channel, recipient_hash, dedup_key, source, status, autonomy, ts_unix}`
/// — `recipient_hash` is a SHA-256 of the chat id (never the raw id; the
/// audit log must not carry a live user identifier), `status` is one of
/// `delivered` / `failed` / `suppressed` / `sidecar_only`. G-01 (Session
/// 28d, 4-lens gremium).
pub const EVENT_TYPE_PROACTIVE_SENT: u8 = 0x3A;

/// `0x3B CHANNEL_GATE_REJECTED` — an inbound channel message was dropped
/// by the adapter's allowlist gate (sender not on the operator's
/// allowlist) BEFORE it reached the pipeline handler. The gate itself is
/// not new (the adapter has always dropped non-allowlisted senders before
/// touching the WAL — so a blocked sender never produces a `0x32
/// CHANNEL_INGRESS` frame); this frame closes SF-03's audit gap: the drop
/// was previously `tracing::warn`-only, leaving no `neoth wal show` trail
/// of rejected inbound. Now the operator can see WHO tried + how often.
/// Payload: `{channel, sender_id, reason, ts_unix}` — `reason` is
/// `"not_on_allowlist"`; no message text (the gate fires before the text
/// is even read, so there is none to leak). SF-03 (Session 29).
pub const EVENT_TYPE_CHANNEL_GATE_REJECTED: u8 = 0x3B;

/// `0x3C CHANNEL_PRIVILEGE_BLOCKED` — an allowlisted channel sender invoked
/// a DESTRUCTIVE operator slash-action (`/config set`, `/autonomy`,
/// `/consent`, `/provider`, `/connect`, `/disconnect`, `/reload`,
/// `/wizard`) over a messaging channel. The ADV-09 privilege ceiling in
/// `slash::dispatch_action` rejects it — destructive config/consent/
/// autonomy mutation requires LOCAL CLI authentication, so a Telegram
/// message can't reconfigure or escalate the daemon. This frame closes the
/// audit gap: before ADV-09 wired the ceiling into the channel path, such a
/// command was silently rendered into an LLM prompt with no block + no
/// trail. Distinct from `0x3B` (allowlist drop, pre-pipeline): the sender
/// here IS on the allowlist but lacks the privilege for this action.
/// Payload: `{channel, sender_id, action, ts_unix}` — `action` is the
/// `SlashAction::as_str()` wire name; no message text. ADV-09 (Session 30).
pub const EVENT_TYPE_CHANNEL_PRIVILEGE_BLOCKED: u8 = 0x3C;

/// `0x3D EMAIL_INGRESS_TRIAGED` — EM-01b/PL-05b. The BASE inbound-email audit
/// record: one frame per message `neoth email fetch` triaged, capturing the
/// band NEOTH assigned (dropped-at-sanitizer / quarantine / review-queue /
/// deliver). Email is an inbound channel, so this lives in the `0x3X` channels
/// band. Metadata ONLY — the body/subject are NEVER recorded, only the sender
/// DOMAIN (no display name / local-part) + score + action + optional tie-break
/// verdict. Emitted best-effort via the one-shot writer, or forwarded over
/// audit-RPC when a daemon owns the WAL (allowlisted). The two sibling events
/// `0x30 EMAIL_INGRESS_QUARANTINED` + `0x31 EMAIL_TIEBREAK_APPLIED` give
/// high-signal `wal show --type` filters over the dangerous subset.
///
/// Payload (JSON): `{uid, from_domain, score, action, tiebreak, ts_unix}`.
pub const EVENT_TYPE_EMAIL_INGRESS_TRIAGED: u8 = 0x3D;

/// `0x3E EVAL_CRITICAL_DIVERGENCE` — ARCH-05/SPEC-08 recall-parity gate. A
/// goldset query where NEOTH's recall diverged CRITICALLY from the reference
/// system: factual or usefulness kappa-parity below 0.50, or an empty/error
/// response. A single CRITICAL aborts the reference→NEOTH cutover (SPEC §7) — this
/// is the durable evidence. Emitted by `neoth recall score` per flagged query.
/// (The `0x3X` band is channels + adjacent recall/eval observability; eval
/// divergence lives at the tail of the band per the SPEC's slot choice.)
///
/// Payload (JSON): `{query_id, reason, factual_parity_kappa, usefulness_parity_kappa, ts_unix}`.
pub const EVENT_TYPE_EVAL_CRITICAL_DIVERGENCE: u8 = 0x3E;

/// `0x3F REGRESSION_ALERT` — ADV-14 longitudinal recall-regression anchor. The
/// daemon's weekly regression cron re-asked an anchor query, embedded the fresh
/// answer, and found its cosine to the cutover anchor vector BELOW
/// `regression_anchor.threshold` — durable evidence the model's answer to a
/// known query drifted after a model/config change. Last slot of the `0x3X`
/// band (channels + adjacent recall/eval observability), next to
/// `0x3E EVAL_CRITICAL_DIVERGENCE`.
///
/// Payload (JSON): `{query, cosine, threshold, ts_unix}`.
pub const EVENT_TYPE_REGRESSION_ALERT: u8 = 0x3F;

// ---- 0x50..=0x5F  Safety / recovery — panic-recovery + risk-gate audit -----

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

// ── GOLD-ADOPT-23 (operator points 3 + 4) — distinct risk-gate audit types.
// The earlier single `0xCF RISK_GATE_BLOCKED` (still registered for old WALs)
// carried the outcome in a `verdict` field; the operator prefers DISTINCT event
// TYPES so `neoth wal show --type risk_gate_denied` filters precisely. These
// live in the safety/recovery band (a guard firing is a safety-boundary event,
// adjacent to crash recovery) — 0xC0..=0xCF, the natural tool band, is full.

/// `0x52 RISK_GATE_DENIED` — the dispatch-loop risk gate hard-blocked a tool
/// call (Critical dangerous command under `dangerous_commands=deny`, or egress
/// under `egress.mode=deny_unknown`). Payload `{server, tool, verdict:"denied",
/// rule, ts_unix}` — the raw command is NEVER stored.
pub const EVENT_TYPE_RISK_GATE_DENIED: u8 = 0x52;

/// `0x53 RISK_GATE_CONFIRM_REQUIRED` — the risk gate blocked a call pending
/// operator confirmation (`dangerous_commands=confirm`, `confirm_high`, or
/// `egress.mode=confirm_unknown`). The operator lifts it for a TTL window with
/// `neoth risk-confirm`. Payload `{server, tool, verdict:"confirm_required",
/// rule, ts_unix}`.
pub const EVENT_TYPE_RISK_GATE_CONFIRM_REQUIRED: u8 = 0x53;

/// `0x54 RISK_CONFIRM_GRANTED` — `neoth risk-confirm --ttl N` granted an
/// operator risk-override lease (the operationalised "confirm"). Payload
/// `{subject:"operator", scopes:[…], ttl_secs, expires_unix, source:"cli",
/// ts_unix}`. The companion lease lifecycle (`LEASE_GRANTED 0xA5` etc.) also
/// fires; this is the risk-gate-specific marker.
pub const EVENT_TYPE_RISK_CONFIRM_GRANTED: u8 = 0x54;

/// `0x55 RISK_CONFIRM_USED` — a blocked tool call was LIFTED by an active
/// operator risk-override lease (the confirm window was spent). Payload
/// `{server, tool, verdict:"lifted_by_lease", rule:<lease_id>, ts_unix}`.
pub const EVENT_TYPE_RISK_CONFIRM_USED: u8 = 0x55;

/// `0x56 RISK_CONFIRM_EXPIRED` — a tool call was blocked while a matching
/// risk-override lease existed but had already LAPSED, so the block stood. Tells
/// the operator their `risk-confirm` window expired. Payload `{server, tool,
/// verdict:"expired", rule, ts_unix}`.
pub const EVENT_TYPE_RISK_CONFIRM_EXPIRED: u8 = 0x56;

/// `0x57 RISK_GATE_ALLOWED_BY_READONLY_CACHE` — GOLD-ADOPT-22 SmartApprove
/// auto-approved a Confirm-gated tool call because the tool's server-DECLARED
/// EFFECT metadata (`readOnlyHint`, not its name) marked it read-only. Opt-in
/// (`security.smart_approve`); NEVER fires on a `Deny` (the hard floor stands).
/// Payload `{server, tool, reason:"readonly_hint", source:"smart_approve",
/// ts_unix}` — args never stored.
pub const EVENT_TYPE_RISK_GATE_ALLOWED_BY_READONLY_CACHE: u8 = 0x57;

/// `0x58 HINT_LOADED` — GOLD-ADOPT-18. The MCP dispatch loop's
/// [`crate::mcp::hints::SubdirHintTracker`] loaded a subdirectory's
/// `.neothhints` / `AGENTS.md` into the agent's context after the agent entered
/// that dir via a tool-call path arg. Payload `{dir, bytes, ts_unix}` — the dir
/// path + injected size only, never the hint body. Safety/recovery band (the
/// 0x40 cron band is full); a context-enrichment event sits fine next to the
/// other advisory/safety frames. PRIVACY: `dir` is an absolute local path,
/// subject to the same export/gossip considerations as `0xA8 OS_FILE_READ`.
pub const EVENT_TYPE_HINT_LOADED: u8 = 0x58;

/// `0x59 WEB_EXTRACT_HIT` — GOLD-ADOPT-04. A CSS selector (operator-supplied or
/// cached) matched ≥1 element on a freshly-fetched page. Payload `{url_hash
/// (xxh3-64 hex, NEVER the raw URL), selector, cache_key, extracted_bytes
/// (count only), ts_unix}`. Batchable (high-cadence, re-derivable from the HTTP
/// response). NOTE: `selector` + `cache_key` are stored PLAINTEXT (both
/// operator-supplied; the WAL is operator-local) — only the URL is hashed.
pub const EVENT_TYPE_WEB_EXTRACT_HIT: u8 = 0x59;

/// `0x5A WEB_EXTRACT_SELECTOR_STALE` — GOLD-ADOPT-04. A cached selector matched
/// ZERO elements (the site structure changed); the adaptive re-find ran against
/// the stored fingerprint. Payload `{url_hash, cache_key, old_selector,
/// stale_recovered, new_selector?, similarity_score?, ts_unix}`. IMMEDIATE-SYNC
/// (a structural-change audit anchor must survive a crash).
pub const EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE: u8 = 0x5A;

/// `0x5B CONTEXT_COMPACTION_START` — GOLD-ADOPT-19. The MCP dispatch loop's
/// accumulated prompt crossed the compaction threshold (a fraction of
/// `freedom.yaml::tokens.max_per_request`) and an LLM summarization pass is
/// about to run. Payload `{iteration, prompt_tokens, threshold_tokens,
/// ts_unix}`. Batchable (informational; the compaction either succeeds → DONE,
/// or fails → the original prompt is kept, both observable downstream).
pub const EVENT_TYPE_CONTEXT_COMPACTION_START: u8 = 0x5B;

/// `0x5C CONTEXT_COMPACTION_DONE` — GOLD-ADOPT-19. The summarization pass
/// finished and the loop prompt was replaced by the dense `[CONTEXT SUMMARY]`.
/// Payload `{iteration, before_tokens, after_tokens, ts_unix}`. Batchable.
pub const EVENT_TYPE_CONTEXT_COMPACTION_DONE: u8 = 0x5C;

/// `0x5D COMPRESSION_APPLIED` — GOLD-HR-08. A tool-result block was shrunk by
/// the WS-HR compression pipeline before entering the next loop prompt (lossy
/// on the wire, lossless via CCR — the original is in the store under each
/// `cache_key`). Payload `{iteration, before_bytes, after_bytes, steps,
/// cache_keys, ts_unix}`. Batchable; emitted only when bytes were actually
/// saved (a passthrough emits nothing).
pub const EVENT_TYPE_COMPRESSION_APPLIED: u8 = 0x5D;

/// `0x5E INDEXER_TAMPER_SUSPECT` — GR-164. The WAL memory indexer hit an
/// unreconstructable segment (`logical_segment_bytes` failed — HMAC mismatch
/// or corrupt zstd blob) and skipped it for this pass. Without this frame the
/// tamper event was warn-only and not auditable after the fact. Payload
/// `{segment, error, ts_unix}`. (0x5D is the WS-HR COMPRESSION_APPLIED frame;
/// this took 0x5E so both merges stay collision-free.)
pub const EVENT_TYPE_INDEXER_TAMPER_SUSPECT: u8 = 0x5E;
/// `0x5F WATCHDOG_RESTART` — GOLD-FEAT-09. The daemon watchdog cron found a
/// supervised local service (n8n / Ollama) down for `consecutive_failures_
/// before_restart` ticks and acted. Payload `{service, decision, restarts_in_
/// window, ts_unix}` where `decision` is one of `restart` (Elevated+ autonomy
/// spawned the restart command), `alert_only` (service down but autonomy
/// below Elevated — observe-only), or `rate_limited` (restart budget for the
/// window exhausted — crash-loop guard tripped). Batchable behind the next
/// sync-on-write frame. `0x5D`/`0x5E` are reserved for in-flight branches
/// (COMPRESSION_APPLIED / INDEXER_TAMPER_SUSPECT) — do not reuse.
pub const EVENT_TYPE_WATCHDOG_RESTART: u8 = 0x5F;

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

/// SL-03 (A2 #3): the ResourcePressureWatcher cron observed live GPU
/// VRAM usage at-or-above `resource_watch.vram_threshold_pct`. Payload:
/// `{used_mib, total_mib, pct, threshold_pct, ts_unix}`. Advisory —
/// emitted ONLY on a breach (not every tick), so
/// `neoth wal show --type resource_pressure_alert` is a clean "the box
/// ran hot at T" signal, not idle noise. No-op on non-GPU hosts.
pub const EVENT_TYPE_RESOURCE_PRESSURE_ALERT: u8 = 0x47;

/// `0x48 WAL_CRC_ALERT` — HO-07 monitor cron detected one or more WAL
/// integrity anomalies (`0x50 RECOVERY_TRUNCATED` or `0x51
/// COMPACTION_AUTH_FAILED` frames) in the configured look-back window.
/// Operators see this as "the WAL had corruption events in the last N
/// seconds; inspect with `neoth wal show --type recovery_truncated`".
/// Emitted ONLY when the count is non-zero so every frame is
/// actionable. Immediate-sync (durability-critical — a corruption alert
/// that is itself lost on crash is an audit hole).
///
/// Payload (JSON):
///   - `recovery_truncated_count`: u32 — frames of type 0x50 in the window
///   - `compaction_auth_failed_count`: u32 — frames of type 0x51
///   - `window_secs`: u64 — look-back window in seconds
///   - `ts_unix`: i64
pub const EVENT_TYPE_WAL_CRC_ALERT: u8 = 0x48;

/// `0x49 CRASH_LOG_ALERT` — HO-07 monitor cron detected new content in
/// `~/.neoth/crash.log` since the previous tick (the panic handler writes
/// there; the WAL writer channel is unreliable during a panic so crash
/// signals reach the WAL only via this monitor). Emitted ONLY when new
/// content appears. Immediate-sync (a crash-alert frame that is itself
/// lost on crash is an audit hole).
///
/// Payload (JSON):
///   - `crash_log_path`: String — absolute path of the crash log
///   - `new_crashes_since_last_check`: u32 — count of new `[neoth panic]`
///     lines since the last tick
///   - `last_crash_ts_unix`: i64 — unix timestamp of the most recent panic
///     line parsed, 0 when unparseable
///   - `ts_unix`: i64
pub const EVENT_TYPE_CRASH_LOG_ALERT: u8 = 0x49;

/// `0x4A CHANNEL_SILENCE_ALERT` — HO-07 monitor cron detected that no
/// `0x32 CHANNEL_INGRESS` or `0x33 CHANNEL_EGRESS` frames have appeared
/// in the WAL for `monitor.channel_silence_secs` (default 1800s / 30 min)
/// while the current UTC hour falls inside the operator's configured
/// active window (`monitor.channel_silence_active_utc_start` ..
/// `monitor.channel_silence_active_utc_end`; default 07..21 UTC ≈
/// 08..22 CET). Advisory — batchable (silence is not durability-critical;
/// loss in a crash window is acceptable).
///
/// Payload (JSON):
///   - `last_activity_ts_unix`: i64 — unix timestamp of the last
///     CHANNEL_INGRESS/EGRESS frame seen, 0 when none found in look-back
///   - `silence_duration_secs`: u64 — seconds since last activity
///   - `active_window_utc_start`: u8 — hour (0-23) the active window opens
///   - `active_window_utc_end`: u8 — hour (0-23) the active window closes
///   - `ts_unix`: i64
pub const EVENT_TYPE_CHANNEL_SILENCE_ALERT: u8 = 0x4A;

/// `0x4B RECALL_LATENCY_ALERT` — MONITOR-03 / RECALL-METER-01. The daemon's
/// recall-latency cron read the recent `idx_recall_latency` window (samples
/// recorded by each one-shot `neoth recall`) and found the p95 ABOVE
/// `recall_latency.p95_threshold_ms` — durable evidence that recall is
/// degrading (cold cache, disk pressure, an index regression). Cron band.
///
/// Payload (JSON): `{p95_ms, threshold_ms, sample_count, ts_unix}`.
pub const EVENT_TYPE_RECALL_LATENCY_ALERT: u8 = 0x4B;

/// `0x4C ECOLOGY_SCHEDULER_FIRED` — F4-01 Phase 1. The Ecology auto-scheduler
/// cron ticked, detected a low-dissent council regime (one provider winning a
/// streak ≥ `ecology.correlation_min_streak`), and ran the P-04 self-dev
/// proposal generator. Proposals are STAGED for `neoth self-dev review`, never
/// auto-applied — this frame is the audit trail proving the scheduler only ever
/// PROPOSES (the DESIGN_CH13 P2 constraint: fitness must never silently rewrite
/// policy). Cron band. Emitted only when ≥1 streak signal fired this tick.
///
/// Payload (JSON): `{streak_signals_count, proposals_queued, ts_unix}`.
pub const EVENT_TYPE_ECOLOGY_SCHEDULER_FIRED: u8 = 0x4C;

/// `0x4D WORKER_DIED` — MONITOR-02 real-time worker-task death detection. A
/// long-running daemon cron/worker loop should NEVER finish on its own; one that
/// does has panicked or exited unexpectedly. The worker-watch task polls each
/// worker's `AbortHandle::is_finished()` and emits this frame (once per worker)
/// naming the dead task — lower latency + WHICH-task attribution vs the HO-07
/// `0x49 CRASH_LOG_ALERT` retro crash.log scan. Cron band. Durable (a worker
/// dying is an operational-integrity signal that must survive a crash).
///
/// Payload (JSON): `{ worker, ts_unix }` — `worker` is the static task name
/// (e.g. `"monitor_cron"`, `"ecology_scheduler"`).
pub const EVENT_TYPE_WORKER_DIED: u8 = 0x4D;

/// `0x4E RSS_FEED_ITEM_INDEXED` — GOLD-ADOPT-26. The RSS feed poller wrote one
/// feed entry into the ctx knowledge store. Payload: `{feed_label,
/// entry_id_hash, title_hash, ctx_key, ts_unix}` — the title + entry id are
/// xxh3-HASHED, never stored verbatim in the WAL frame (privacy).
pub const EVENT_TYPE_RSS_FEED_ITEM_INDEXED: u8 = 0x4E;

/// `0x4F RSS_FEED_PASS_COMPLETE` — GOLD-ADOPT-26. One full RSS sweep finished.
/// Payload: `{feeds_checked, entries_indexed, entries_skipped, ts_unix}`.
pub const EVENT_TYPE_RSS_FEED_PASS_COMPLETE: u8 = 0x4F;

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

/// `0x66 COUNCIL_TRANSCRIPT` — KF-01 full. The verbatim response text of
/// ONE hemisphere in a council debate, persisted so `neoth council replay
/// <prompt_hash>` can show the actual prose, not just the hashed metadata
/// the `0x60..=0x64` frames carry. OPT-IN: emitted only when
/// `freedom.yaml::council.persist_transcripts = true` (default false —
/// hemisphere prose is sensitive; the operator chooses durability over
/// privacy explicitly, mirroring the PROVIDER_RESPONSE hash-by-default
/// rule). Keyed by `prompt_hash` (same xxh3 wire form as the other
/// council frames) so the replay reader correlates a transcript with its
/// debate. Payload: `{prompt_hash, role, provider, text}`. Durable
/// (immediate-sync) — a persisted transcript the operator opted into is
/// part of the auditable record.
pub const EVENT_TYPE_COUNCIL_TRANSCRIPT: u8 = 0x66;

/// `0x67 CHANNEL_SEND` — SC-SEND (Session 39). An OUTBOUND channel send was
/// GOVERNED + executed (or dry-run previewed) through the send-gate: the
/// channel-send permission was evaluated (gate), required-audit fail-closed +
/// dry-run honoured, and the adapter performed (or previewed) the send. The
/// dedicated governance event for the now-reachable WhatsApp send adapter
/// (GR-01 Pick B) + the telegram notice path — DISTINCT from `0x33
/// CHANNEL_EGRESS` (the generic "a reply was released to the transport" record
/// the indexer feeds into recall) so an operator can grep exactly when an
/// adapter actually SENT under governance. A failed attempt carries
/// `delivered:false` + `error_kind` in the same frame.
///
/// **Band note**: the natural home is the channels band `0x30..=0x3F`, but that
/// band is FULL. A channel-send GATE decision (allow / deny / confirm / dry-run
/// + required-audit) is an operator-GOVERNANCE decision — the same reason
/// `0x65 CONSENT_DECISION` already lives in this `0x60..=0x6F` band — so the
/// send-governance pair lands here next to it.
///
/// Payload (JSON, metadata-only): `{channel, to_hash, message_hash,
/// message_bytes, provider_message_id, dry_run, confirm_degraded, ts_unix}`.
pub const EVENT_TYPE_CHANNEL_SEND: u8 = 0x67;

/// `0x68 CHANNEL_SEND_DENIED` — SC-SEND (Session 39). The channel-send gate
/// DENIED an outbound send (`send_gate::decide_channel_send` returned a hard
/// Deny). Distinct from `0xA1 PERMISSION_DENIED` (the generic gate-denial the
/// pipeline ChannelSend gate still emits) so an operator can grep specifically
/// for blocked CHANNEL sends. Metadata-only: hashed recipient + the gate's
/// reason, never the body. Same `0x60..=0x6F` band-note as `0x67 CHANNEL_SEND`.
/// Payload (JSON): `{action:"channel_send", channel, to_hash, reason, ts_unix}`.
pub const EVENT_TYPE_CHANNEL_SEND_DENIED: u8 = 0x68;

/// `0x69 TOKEN_TPS_SAMPLE` — GOLD-ADAPT-HERMES-09 token-throughput metering.
/// The [`daemon::metering`] meter emits this after a streaming provider
/// response completes. Carries the measured tokens-per-second rate, total
/// token count, elapsed window, and chunk count so operators can track
/// throughput trends across model swaps or hardware changes. Token counts
/// are not PII; the payload is in the clear.
/// **Band note**: metering is a provider-lifecycle signal; lands in the free
/// tail of `0x60..=0x6F` (same rationale as `0x6E TOKEN_ANOMALY_DETECTED`).
/// Payload (JSON): `{tps, total_tokens, elapsed_ms, observe_count, ts_unix}`.
pub const EVENT_TYPE_TOKEN_TPS_SAMPLE: u8 = 0x69;

/// `0x6A COUNCIL_SELF_SCORE` — GOLD-ADAPT-LOWKEY-01 deterministic self-score audit frame.
/// Emitted by `cli::chat::dispatch_council_with_recovery` after the SP-5 block resolves
/// `final_text`. Scores the resolved answer on 4 axes (correctness, completeness, coherence,
/// evidence) via `council::self_reflect::score_answer` — zero LLM calls, pure deterministic
/// heuristics. Always emitted so the WAL audit chain has a score frame for every council
/// decision; `below_threshold` flags when the composite fell below the operator minimum.
/// **Durable by default** — absent from `needs_immediate_sync` deny-list so it syncs
/// immediately like all gate/decision events in this band.
/// Payload (JSON): `{prompt_hash, correctness, completeness, coherence, evidence, composite,
/// below_threshold, ts_unix}`.
pub const EVENT_TYPE_COUNCIL_SELF_SCORE: u8 = 0x6A;

/// `0x6E TOKEN_ANOMALY_DETECTED` — GOLD-ADAPT-JV-PRO-02 token-anomaly tripwire.
/// The daemon cron buckets WAL `0x21 PROVIDER_RESPONSE` token usage by UTC day
/// and emits this when the most recent active day shows a σ-spike, a `>1M` jump
/// over the baseline max, or a model unseen across the baseline window — a
/// leaked provider key / runaway loop / unexpected model route can look like
/// this. Token COUNTS + model NAMES are not secrets, so the payload is in the
/// clear (no PII to hash, unlike channel-send egress).
/// **Band note**: a usage-anomaly is a provider-lifecycle concern whose natural
/// home is the `0x20..=0x2F` provider band, but that band is FULL — so it lands
/// in the free tail of `0x60..=0x6F` next to the other gate/decision events
/// (same band-note rationale as `0x67 CHANNEL_SEND`).
/// Payload (JSON): `{kinds:[..], day_tokens, baseline_mean, baseline_stddev,
/// baseline_max, baseline_days, day_models:[..], new_models:[..], ts_unix}`.
pub const EVENT_TYPE_TOKEN_ANOMALY_DETECTED: u8 = 0x6E;

/// `0x6F SESSION_HEALTH_DEGRADED` — GOLD-ADAPT-VIEW-05 session-health cron. The
/// daemon grades the most-recent active UTC day A–F from the WAL audit trail
/// (refusal-failures `0x1A`/`0x27` + job-failures `0x42` over `0x21` activity)
/// and emits this when the grade is at or below the configured floor (default
/// `D`). Counts + a grade are not secrets → the payload is in the clear.
/// **Band note**: a health/outcome signal sits in the free tail of
/// `0x60..=0x6F` next to the other gate/decision/monitor events (same rationale
/// as `0x6E`).
/// Payload (JSON): `{grade, score, day_unix, activity, refusal_failures,
/// job_failures, refusal_rate, failure_rate, mean_input_tokens}`.
pub const EVENT_TYPE_SESSION_HEALTH_DEGRADED: u8 = 0x6F;

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

/// One consolidation/decay pass completed. Summary frame (not per-event).
/// Phase 28c R-24 GT-3; emit site wired by KF-10 (Session 36) from the decay
/// task. Emitted only when the pass actually touched rows (a no-op pass writes
/// nothing — keeps the audit clean). Payload: `{ts_unix, hot_decayed,
/// consolidated, hot_archived, promoted, warm_archived, warm_decayed,
/// cold_decayed, cold_swept, pre_decay_drafted}` — mirrors
/// `memory::consolidate::PassReport` so an operator can correlate
/// `neoth wal show --type consolidation_pass` with the Obsidian PreDecay drafts.
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

/// `0x9B IDENTITY_MERGED` — SPEC-11. The operator ran `neoth identity merge
/// <canonical> <victim>`: every alias of `victim` was reassigned to `canonical`
/// and `victim` was tombstoned (kept, `merged_into` set). The frame carries the
/// FULL before-state (the reassigned aliases) so the merge is auditable AND
/// reversible — a future `neoth identity split` can reconstruct it. Memory-ops
/// band — identity is a memory-attribution operation.
///
/// Payload (JSON): `{canonical, victim, aliases: [{channel, sender_id,
/// chat_id}], aliases_reassigned, ts_unix}`.
pub const EVENT_TYPE_IDENTITY_MERGED: u8 = 0x9B;

/// `0x9C OMI_ACTION_PROMOTED` — OM-01. A transcript item from the operator's
/// LOCAL OMI backend crossed `omi.confidence_threshold` and was inserted into
/// `idx_groundtruth` as a new ground-truth seed. SC-14 hard rule: `api.omi.me`
/// is refused at daemon startup, so this event can only originate from a
/// self-hosted endpoint. Memory-ops band (it mints a memory seed). Metadata
/// only — the statement's hash, never the raw transcript.
///
/// Payload (JSON): `{text_hash, source: "omi", scope, confidence, ts_unix}`.
pub const EVENT_TYPE_OMI_ACTION_PROMOTED: u8 = 0x9C;

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

/// `0xA5 LEASE_GRANTED` — SL-01a. The operator (or a cluster master)
/// granted a subject (a paired peer pub-key or a plugin id) a
/// TTL-bounded scoped capability. A lease is how a delegated task (SL-01)
/// or a proactive bounded write (G-01) gets authorised without a fresh
/// per-action prompt — and the lease lives in the audit chain, so
/// `neoth wal show --type lease_granted` shows exactly who may do what,
/// until when. Payload: `{lease_id, granted_to, scope, expires_unix}`.
pub const EVENT_TYPE_LEASE_GRANTED: u8 = 0xA5;
/// `0xA6 LEASE_EXPIRED` — SL-01a. A lease lapsed (TTL elapsed) and was
/// pruned. The capability is GONE — the gate falls back to its
/// fail-closed default. Emitted at prune time so the audit trail shows
/// the exact moment a delegation ended. Payload:
/// `{lease_id, granted_to, scope}`.
pub const EVENT_TYPE_LEASE_EXPIRED: u8 = 0xA6;
/// `0xA7 LEASE_REVOKED` — SL-01a. The operator explicitly revoked a lease
/// before its TTL (`neoth lease revoke <id>`). The kill switch for a
/// delegated capability. Payload: `{lease_id, granted_to, scope}`.
pub const EVENT_TYPE_LEASE_REVOKED: u8 = 0xA7;
/// `0xA8 OS_FILE_READ` — PC-01. NEOTH read a file on the operator's OS via
/// the gated OS-tool surface, AFTER it passed the path allowlist + the
/// autonomy gate. OS file access is an autonomy/permission decision, so it
/// sits in the permissions band. Payload: `{path, bytes, ts_unix}`.
pub const EVENT_TYPE_OS_FILE_READ: u8 = 0xA8;
/// `0xA9 OS_FILE_DENIED` — PC-01. An OS file read was refused — by the path
/// allowlist (default deny-all / not-in-allowlist / traversal attempt) or by
/// the autonomy gate (Deny / Confirm-with-no-TTY). The audit trail records
/// every blocked filesystem reach. Payload: `{path, reason, ts_unix}`.
pub const EVENT_TYPE_OS_FILE_DENIED: u8 = 0xA9;
/// `0xAA OS_FILE_WRITE` — PC-01 (write slice). Emitted when the daemon WROTE a
/// file through the gated OS-tool surface, AFTER it passed the write-allowlist
/// (canonical parent under `allowed_write_paths`) + the autonomy gate. Payload:
/// `{path, bytes, existed, ts_unix}` (`existed` = whether it overwrote).
pub const EVENT_TYPE_OS_FILE_WRITE: u8 = 0xAA;
/// `0xAB OS_FILE_WRITE_DENIED` — PC-01. An OS file write was refused — by the
/// write-allowlist (deny-all / parent-not-in-allowlist / traversal / symlink
/// escape) or the autonomy gate (Deny / Confirm-with-no-TTY). Payload:
/// `{path, reason, ts_unix}`.
pub const EVENT_TYPE_OS_FILE_WRITE_DENIED: u8 = 0xAB;
/// `0xAC OS_APP_LAUNCH` — PC-01 (app-launch slice). NEOTH launched an
/// operator-allowlisted program through the gated OS-tool surface, AFTER it
/// passed the exec-allowlist (the target canonicalizes to EXACTLY one
/// `freedom.yaml::tools.os.allowed_exec_paths` entry — exact match, never a
/// directory prefix) + the autonomy gate. Launched with NO arguments and NO
/// shell (direct `argv[0]`, stdio detached). Payload: `{program, pid, ts_unix}`.
pub const EVENT_TYPE_OS_APP_LAUNCH: u8 = 0xAC;
/// `0xAD OS_APP_LAUNCH_DENIED` — PC-01. A program launch was refused — by the
/// exec-allowlist (deny-all / not-an-allowlisted-binary / not-a-regular-file /
/// traversal) or the autonomy gate (Deny / Confirm-with-no-TTY), or the spawn
/// itself failed. The audit trail records every blocked process launch.
/// Payload: `{program, reason, ts_unix}`.
pub const EVENT_TYPE_OS_APP_LAUNCH_DENIED: u8 = 0xAD;
/// `0xAE AUDIT_RPC_ACCEPT` — AUDIT-RPC-01. The daemon's loopback audit-RPC
/// listener accepted an authenticated audit intent from a one-shot CLI (which
/// could not write the WAL itself because the daemon owns the single writer)
/// and appended the forwarded frame. Emitted by the DAEMON, not the client —
/// an observability record that the IPC channel was used. Payload:
/// `{forwarded_event_type, bytes, ts_unix}`.
pub const EVENT_TYPE_AUDIT_RPC_ACCEPT: u8 = 0xAE;
/// `0xAF AUDIT_RPC_REJECT` — AUDIT-RPC-01. The audit-RPC listener REFUSED an
/// inbound request — bad/missing bearer token, non-loopback peer, oversized
/// body, malformed frame, or a `forwarded_event_type` outside the compile-time
/// client allowlist (the anti-audit-poisoning gate). Emitted by the DAEMON.
/// Auth failures are NOT recorded here (avoids a forged-frame paradox + WAL
/// spam); only post-auth rejects (allowlist / decode) are. Payload:
/// `{reason, ts_unix}`.
pub const EVENT_TYPE_AUDIT_RPC_REJECT: u8 = 0xAF;

// ---- 0xB0..=0xBF  Hypothalamus / user-profile -----------------------------
//
// Profile-pipeline band (SPEC_proactive_learning.md §1.3,
// SPEC_profile_claim_guard.md §7). The original spec called this the
// `profile.apply` "single-writer" band, but in practice multiple
// profile-pipeline subsystems own slots in it: `profile::apply` emits
// `0xB0`/`0xB1`/`0xB2`/`0xB4`, `cli/profile.rs` emits `0xB3` (seed-baseline
// migration), the approval-gate emits `0xB5`/`0xB6`/`0xB7`, redaction
// emits `0xB8`, and `profile::runner` emits `0xB9` (Stage-3 graceful 429
// skip). Phase-2 wire-format extension will add a `region_tag` field that
// can express which subsystem owns a write, but the apply-only
// single-writer claim is no longer accurate today.

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
/// Emitted by `neoth profile seed-baseline` (`cli/profile.rs::
/// run_seed_baseline`) — a one-shot operator/onboarding command that
/// reads every active `idx_profile` claim, hashes each, and writes this
/// frame once (exactly-once gated via a WAL scan; refuses while the
/// daemon is live so the single-writer invariant holds). The
/// `embedding_b64` field stays `null` until the embed-wire Phase-4
/// follow-up populates it.
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

/// ADV-04 (Session 28) — `profile.apply` dropped a per-claim insert
/// because the field has an active `never_recreate=1` redaction.
/// Defence-in-depth complement to the Stage-5 guard's `FieldRedacted`
/// reason — a delta can pass the guard, get parked in
/// `idx_profile_pending`, then have a redaction added by the operator
/// between approval-gate parking + `neoth profile approve` running
/// `apply_delta`; this frame proves the apply step honoured the
/// fresh redaction instead of resurrecting the claim.
///
/// Payload (JSON): `{ extraction_id, field, redaction_id, asserted_by,
/// guard_version, ts_unix }`. NB: deliberately no `value_json` — the
/// operator redacted the field because they don't want any value of
/// it preserved, and the audit frame mirrors that.
pub const EVENT_TYPE_PROFILE_REDACT_BLOCKED: u8 = 0xB8;

/// `0xB9 PROFILE_EXTRACT_SKIPPED` — the profile pipeline's Stage 3 LLM
/// call returned HTTP 429 (rate-limit) so the pipeline gracefully
/// skipped instead of propagating a generic error that would lose the
/// provider + `Retry-After` signal. ADV-10 Slice A (Session 28g,
/// gremium-unanimous rank 1).
///
/// Payload (JSON): `{ provider, retry_after_secs, trigger_event_id,
/// ts_unix }`. `provider` is the static name (e.g. `"openai_api"`);
/// `retry_after_secs` is `null` when the 429 carried no `Retry-After`
/// header (the dispatcher then falls back to `DEFAULT_BACKOFF`).
pub const EVENT_TYPE_PROFILE_EXTRACT_SKIPPED: u8 = 0xB9;

/// `0xBA PROFILE_DRIFT_ALERT` — the daemon's drift-alert cron (HO-09b)
/// detected that the operator's profile drifted from its baseline by
/// more than `freedom.yaml::drift_alert.threshold`. Emitted ONLY when
/// `drift_alert.enabled = true` AND the drift ratio strictly exceeds the
/// threshold, so every frame that fires is operator-actionable (review
/// via `neoth profile show`, then re-anchor with `neoth profile drift
/// baseline`). The cron reuses the same baseline-resolution path as
/// `neoth profile drift report` — working baseline first, else the 0xB3
/// migration anchor.
///
/// Payload (JSON): `{ drift_ratio, threshold, added_count, removed_count,
/// baseline_source, ts_unix }`. `baseline_source` is `"working/<src>"`
/// or `"anchor/<snapshot_id>"`. Claim hashes are NOT included — the
/// frame is a drift SIGNAL, not a claim dump (operator inspects via CLI).
pub const EVENT_TYPE_PROFILE_DRIFT_ALERT: u8 = 0xBA;
/// `0xBB OPERATOR_FEEDBACK` — G-03 self-correction loop. Emitted when an
/// operator's chat turn reads as a CORRECTION of the preceding reply (the
/// rule-based follow-up-tone scorer crosses the negative threshold). The
/// durable signal that "the operator pushed back here" — queryable via
/// `neoth wal show --type operator_feedback` so an operator can see where
/// NEOTH underperformed, and (follow-on slice) the profile-adapt cron can
/// consume it to bias self-dev proposals. Profile band because feedback
/// drives profile adaptation. Payload (JSON):
/// `{ sentiment_score, matched_patterns, prompt_hash, ts_unix }` — the
/// prompt itself is NOT stored (hash only; no message-content leak).
pub const EVENT_TYPE_OPERATOR_FEEDBACK: u8 = 0xBB;

/// `0xBC OS_CLIPBOARD_ACCESS` — PC-01 (clipboard slice). A gated OS clipboard
/// READ or WRITE succeeded through `os_tools::gate`. **Band note:** clipboard is
/// an OS-tool action (sibling of `0xA8 OS_FILE_READ` / `0xAC OS_APP_LAUNCH`) but
/// the 0xA permissions band is FULL (0xAE/0xAF = AUDIT_RPC), so it overflows into
/// the reserved 0xB0..=0xDF space here — the same "semantically-adjacent
/// overflow" precedent as `0x67 CHANNEL_SEND` (channels band full → council band).
/// Payload (JSON): `{ op: "read" | "write", bytes, ts_unix }`. **`bytes` is a
/// COUNT only — the clipboard CONTENT is NEVER recorded** (a clipboard frequently
/// holds a just-copied password/token; logging it would be the exact exfil this
/// gate exists to prevent).
pub const EVENT_TYPE_OS_CLIPBOARD_ACCESS: u8 = 0xBC;
/// `0xBD OS_CLIPBOARD_DENIED` — PC-01 (clipboard slice). A gated OS clipboard
/// read/write was REFUSED: a runtime kill-switch (`tools.os.clipboard.*`), the
/// autonomy gate, the size cap, the pastejacking newline guard, or an
/// unavailable backend (headless / no display). Same 0xB-overflow band note as
/// `0xBC`. Payload (JSON): `{ op: "read" | "write", reason, ts_unix }` — `reason`
/// is a policy/diagnostic string + byte count, NEVER clipboard content.
pub const EVENT_TYPE_OS_CLIPBOARD_DENIED: u8 = 0xBD;

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
/// `0xC6 PLUGIN_CAP_USED` — KF-09 (first slice). A WASM plugin exercised
/// a READ capability that is otherwise UNTRACED. Today: `neoth.recall_top`
/// (reads operator memory by prompt-hash). Unlike `0xC4 PLUGIN_HOSTCALL`
/// (the Write-side `emit_event` audit), the read hostcalls left NO durable
/// signal — so a plugin could probe operator memory invisibly. This frame
/// makes every read auditable via `neoth wal show --type plugin_cap_used`.
/// Durable (immediate-sync): a plugin probing operator memory is a
/// security-relevant signal and NEOTH's whole wedge is a *complete*,
/// crash-survivable audit trail — dropping read-audit frames on crash
/// would leave a hole exactly where a hostile plugin wants one. The emit
/// is best-effort only at the CALL SITE (`try_append_sync` never blocks
/// the plugin or changes the read hint); once queued the frame fsyncs
/// like its `0xC4`/`0xC7` siblings. Payload:
/// `{plugin, capability, prompt_hash, hits}`.
pub const EVENT_TYPE_PLUGIN_CAP_USED: u8 = 0xC6;
/// `0xC7 PLUGIN_CAP_DENIED` — SC-04. A WASM plugin attempted a hostcall
/// whose required permission level EXCEEDS the level the operator granted
/// it (the manifest's `requested_permissions`, approved at `neoth plugin
/// enable`). The hostcall is REFUSED fail-closed (`emit_event` writes no
/// frame + returns code 7; `recall_top` returns 0 hits) and this frame is
/// the durable record of the refusal — so a plugin reaching beyond its
/// grant is VISIBLE in `neoth wal show --type plugin_cap_denied`, never
/// silent. Without this the capability gate would deny invisibly and the
/// "No ambient plugin power" guarantee would be unauditable. Durable
/// (immediate-sync, like its `0xC4`/`0xC6` siblings) so the refusal
/// survives a crash; the emit is best-effort only at the CALL SITE
/// (`try_append_sync` — a full WAL queue drops the audit frame but
/// NEVER changes the fail-closed refusal the plugin already got).
/// Payload: `{plugin, hostcall, required, granted}`.
pub const EVENT_TYPE_PLUGIN_CAP_DENIED: u8 = 0xC7;

/// `0xC8 TODO_WRITE` — TD-02. The operator created or completed a task on an
/// EXTERNAL task service (CalDAV today; the Todoist/Google REST writes can fold
/// in) through `neoth todo --provider <p> add|close`. An outbound network
/// mutation, gated by the autonomy/consent layer (`Action::ExternalTaskWrite`)
/// + an interactive/`--yes` confirm, so the audit records that a write left the
/// device + to which provider. `--dry-run` does NOT emit (no write happened).
/// Payload (JSON): `{provider, action, uid, summary?, ts_unix}`.
pub const EVENT_TYPE_TODO_WRITE: u8 = 0xC8;

/// `0xCA CALENDAR_WRITE` — EM-02b. The operator wrote an event to an EXTERNAL
/// calendar (CalDAV today) through `neoth calendar add`. Semantically distinct
/// from `0xC8 TODO_WRITE` — a calendar event is its own domain — so it carries
/// its own event code + the event-specific fields. An outbound network
/// mutation, gated by the autonomy/consent layer (`Action::ExternalTaskWrite`)
/// + the `calendar.writes_enabled` kill switch + an interactive/`--yes` confirm.
/// `--dry-run` would not emit (no write happened).
/// Payload (JSON): `{provider, action, uid, summary_hash, start, end, ts_unix}`
/// — `summary_hash` is xxh3-64 hex of the title (NO raw summary, NO credentials,
/// so external proof bundles never leak the event text).
pub const EVENT_TYPE_CALENDAR_WRITE: u8 = 0xCA;

/// `0xCB CALENDAR_WRITE_DENIED` — EM-02b. A `neoth calendar add` was REFUSED
/// before any network write — the `calendar.writes_enabled` kill switch was off
/// (or a future policy gate denied it). The durable record that the surface
/// refused fail-closed, so a disabled calendar surface is auditable rather than
/// silent. Payload (JSON): `{provider, action, reason, ts_unix}`.
pub const EVENT_TYPE_CALENDAR_WRITE_DENIED: u8 = 0xCB;

/// `0xCE CALENDAR_WRITE_FAILED` — EM-02b. A `neoth calendar add` was ATTEMPTED
/// (it passed the `calendar.writes_enabled` kill switch AND the autonomy gate)
/// but the CalDAV network PUT failed — transport error or non-success HTTP
/// status. Distinct from `0xCB CALENDAR_WRITE_DENIED` (policy refusal BEFORE any
/// network) and `0xCA CALENDAR_WRITE` (success). The Err arm emits this before
/// the error propagates so a network failure on a calendar write leaves a
/// durable audit anchor instead of vanishing silently. `reason` is the
/// formatted error chain (URL + HTTP status, never credentials).
/// Payload (JSON): `{provider, action, uid, reason, ts_unix}`.
pub const EVENT_TYPE_CALENDAR_WRITE_FAILED: u8 = 0xCE;

/// `0xC9 VIDEO_FRAME_SYNTHESIZED` — MM-02b. A multimodal video-analysis call
/// completed: NEOTH decoded N frames from a clip + sent them to a vision
/// provider (Anthropic/OpenAI/Gemini) for a prompt-guided synthesis. An
/// operator-initiated, credentialed cloud call — the audit records that frames
/// left the device + to which provider, WITHOUT the prompt text or the frame
/// pixels (only a prompt hash + counts). Per-clip single event (immediate-sync).
/// Payload (JSON): `{provider, frame_count, prompt_hash, output_chars, ts_unix}`.
pub const EVENT_TYPE_VIDEO_FRAME_SYNTHESIZED: u8 = 0xC9;

/// `0xCC STT_TRANSCRIBED` — MM-01b. A CLOUD speech-to-text call completed:
/// audio left the device to OpenAI Whisper / Azure Speech and a transcript came
/// back. Per the privacy model the TRANSCRIPT is NEVER WAL-stored — this frame
/// is metadata-only durable evidence that audio went to a cloud provider, so an
/// operator can audit cloud-media use without the spoken content being recorded.
/// Tool band. Payload (JSON): `{provider, audio_bytes, output_chars, ts_unix}`.
pub const EVENT_TYPE_STT_TRANSCRIBED: u8 = 0xCC;

/// `0xCD TTS_SYNTHESIZED` — MM-03b. A CLOUD text-to-speech call completed: text
/// left the device to Azure / ElevenLabs and audio came back. The input TEXT is
/// never stored — only its xxh3-64 HASH + byte length — so this is durable
/// evidence of cloud-media use without recording what was spoken. Tool band.
/// Payload (JSON): `{provider, input_hash, input_bytes, audio_bytes, ts_unix}`.
pub const EVENT_TYPE_TTS_SYNTHESIZED: u8 = 0xCD;

/// `0xC1 MCP_TOOL_REJECTED` — operator's MCP client refused to invoke
/// a tool because either (a) the tool name is not in the server's
/// `allow_tools` list, (b) the tool description failed the prompt-
/// injection sanitizer, or (c) the autonomy gate denied the call.
/// Payload: `{server_id, tool, reason, ts_unix}`. Owned by CDX-03.
pub const EVENT_TYPE_MCP_TOOL_REJECTED: u8 = 0xC1;

/// `0xCF RISK_GATE_BLOCKED` — GOLD-ADOPT-23 P0/P1. The dispatch-loop risk gate
/// blocked an LLM-issued tool call because its arguments carried a Critical
/// dangerous-command pattern or a non-allowlisted egress destination. Audit
/// proof that the gate fired. Payload:
/// `{server, tool, verdict, rule, ts_unix}` where `verdict` is `"denied"` or
/// `"confirm_required"` and `rule` is the dangerous-rule id (e.g. `rm_rf_root`)
/// or `"egress"`. The raw command is NEVER stored — only the rule id.
pub const EVENT_TYPE_RISK_GATE_BLOCKED: u8 = 0xCF;

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

/// `0xD7 MODEL_DOWNLOAD_START` — HF-01. Emitted by `cli::models::run_pull`
/// immediately BEFORE a HuggingFace model download begins (when the
/// `updater.allow_huggingface_downloads` gate permits it). Durable audit
/// of exactly-what-we-fetched-when. Payload:
/// `{ model_id, expected_files, ts_unix }`.
pub const EVENT_TYPE_MODEL_DOWNLOAD_START: u8 = 0xD7;

/// `0xD8 MODEL_DOWNLOAD_COMPLETE` — HF-01. Emitted by `cli::models::run_pull`
/// after a download finishes, recording the on-disk cache location +
/// wall-clock duration. Payload:
/// `{ model_id, cached_path, duration_ms, ts_unix }`.
pub const EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE: u8 = 0xD8;

/// `0xD9 HMAC_KEY_ROTATED` — SC-09. Emitted when the WAL HMAC integrity key is
/// REPLACED on disk — today by `neoth security rewrap-hmac-key` (Tier-1
/// recovery: a plaintext backup re-wrapped for a new machine/user), and by any
/// future `rotate-hmac-key`. This frame is the ROTATION BOUNDARY that
/// `neoth wal verify --since-rotation` uses: compaction markers BEFORE it were
/// signed with the old key and are skipped; markers after verify under the new
/// key. Audit metadata ONLY — never the raw key bytes; just the SHA-256 of the
/// installed key for correlation. Payload:
/// `{ new_key_sha256, replaced, reason, ts_unix }`.
pub const EVENT_TYPE_HMAC_KEY_ROTATED: u8 = 0xD9;

/// `0xDA PRESET_APPLIED` — QM-8 + P1. `neoth preset apply <name>` merged a saved
/// preset bundle INTO `freedom.yaml`. A preset can change provider / cloud-
/// fallback / rail / autonomy-adjacent fields, so the merge is security-relevant
/// + deserves a durable record: WHICH preset, WHICH fields changed, from WHICH
/// surface. Config-lifecycle band. Under `required_for_oneshot_permission_
/// events` the apply REFUSES fail-closed if this audit cannot be written.
/// Payload (JSON): `{name, fields_changed, source, ts_unix}` (no secret values —
/// only the changed field NAMES).
pub const EVENT_TYPE_PRESET_APPLIED: u8 = 0xDA;

/// `0xDB CONSENT_GRANTED` — SR-017 / GOLD-SEC-30. `neoth consent grant
/// <provider>` (or the equivalent in-wizard path) wrote a cloud-provider
/// consent marker (`~/.neoth/consent/<kind>.granted`), authorising NEOTH to
/// route operator text to that third-party provider. Granting consent is a
/// security-relevant privilege change — like `neoth autonomy set`, the marker
/// path previously mutated permission state with NO forensic WAL record
/// (`EVENT_TYPE_CONSENT_DECISION 0x65` covers only the in-chat decision prompt,
/// not the deliberate CLI grant/revoke). Config-lifecycle band. Payload (JSON):
/// `{provider, source, ts_unix}` — the provider slug only, never a key/secret.
///
/// Naming: SR-017 is the consent-audit gap; the GOLD-SEC-30 task text borrowed
/// the `SUDOMODE_*` names from the separate `neoth sudomode` CLI feature
/// (gold-audit item #18, NOT this task), so these are named for what they
/// actually record — the consent grant/revoke path.
pub const EVENT_TYPE_CONSENT_GRANTED: u8 = 0xDB;

/// `0xDC CONSENT_REVOKED` — SR-017 / GOLD-SEC-30. Companion to
/// [`EVENT_TYPE_CONSENT_GRANTED`]: `neoth consent revoke <provider>` removed a
/// cloud-provider consent marker, so the next cloud-bound call re-prompts (or
/// bails in non-interactive contexts). Revocation is the security-positive
/// direction and is equally worth a forensic record. Config-lifecycle band.
/// Payload (JSON): `{provider, source, ts_unix}`.
pub const EVENT_TYPE_CONSENT_REVOKED: u8 = 0xDC;

/// `0xDD SUDOMODE_PRESET_APPLIED` — GOLD-FEAT-01c. `neoth autonomy full-auto`
/// (a.k.a. `neoth sudomode`) applied the full-auto preset: autonomy → `Full` AND
/// the entire bundled skill library force-enabled (`skills.enable_all_bundled`).
/// A companion to the generic `0xA2 LEVEL_ELEVATED` that `emit_autonomy_change`
/// already records, scoped to the full-auto/sudomode code path so a forensic
/// reader can tell "operator dropped the gate via the full-auto preset" apart
/// from any other elevation. Config-lifecycle band. Payload (JSON):
/// `{previous, source, ts_unix}`.
pub const EVENT_TYPE_SUDOMODE_PRESET_APPLIED: u8 = 0xDD;

/// `0xDE SELF_UPDATE_REJECTED` — F55. The tamper-suspect companion to
/// `0xD2 SELF_UPDATE_APPLIED`: emitted when the staged fast-path
/// (`apply_from_staged`) refuses a staged artifact because its minisign
/// signature or SHA-256 failed to RE-verify at apply time. The artifact is a
/// tamper-suspect (anyone who can write the stage dir controls it), so the
/// apply is refused — NOT silently retried via a fresh download — the staged
/// file is cleared, and this anchor records the security event.
///
/// Payload (JSON): `{to_version, repo, target_triple, reason, trigger_source,
/// ts_unix}`. `reason` is the integrity-violation message (no binary bytes).
pub const EVENT_TYPE_SELF_UPDATE_REJECTED: u8 = 0xDE;

/// `0xDF MORAL_CORE_TOGGLED` — GOLD-FEAT-07b. Emitted when the operator flips the
/// moral-core kill-switch (`moral_core.enabled` in freedom.yaml) and the daemon
/// hot-reloads. A dedicated audit anchor on top of the generic
/// `0xD0 CONFIG_RELOADED`: the moral core is the sovereign position-0 directive
/// layer, so enabling/disabling it is a security-relevant change an operator
/// should be able to grep for directly (not buried in a generic reload's
/// `changed_fields`).
///
/// Payload (JSON): `{enabled: bool, ts_unix: i64}`. No directive content — only
/// the on/off transition is recorded.
pub const EVENT_TYPE_MORAL_CORE_TOGGLED: u8 = 0xDF;

// ---- 0xE0..=0xEF  Cluster lifecycle (R-7, Session 19; 0xE0..=0xEA assigned) ----
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

/// `0xEA CLUSTER_HEARTBEAT_SENT` — emitted when the local node sends its FIRST
/// outbound heartbeat to a peer on a connection (SL-00(1c) outbound sender).
/// Anchors the bidirectional transport in the audit chain: `0xE3
/// CLUSTER_HEARTBEAT_FIRST` records the first heartbeat RECEIVED from a peer;
/// this is its send-side mirror. Emitted once per peer connection (not every
/// tick) to keep the WAL from filling with periodic noise.
///
/// Payload (JSON): `{peer_id, tokens_per_sec, inflight_requests, healthy,
/// ts_unix}` — the local load snapshot the heartbeat carried.
/// SL-00(1c) (Session 33).
pub const EVENT_TYPE_CLUSTER_HEARTBEAT_SENT: u8 = 0xEA;

/// `0xEB CLUSTER_TASK_ACCEPTED` — the 3-checkpoint accept gate passed for a
/// task DELEGATED by a cluster master (SL-01): the peer is paired, holds an
/// active `ClusterTaskAccept` lease, and the autonomy floor allows. The task
/// is dispatched to the local provider. Security-relevant audit anchor.
///
/// Payload (JSON): `{task_id, peer_pubkey, lease_backed, autonomy, ts_unix}`.
/// `peer_pubkey` is the AUTHENTICATED Noise static key (never a payload field).
/// SL-01 (Session 33).
pub const EVENT_TYPE_CLUSTER_TASK_ACCEPTED: u8 = 0xEB;

/// `0xEC CLUSTER_TASK_REJECTED` — a delegated task was refused. `reason`
/// distinguishes the failed checkpoint (`malformed` / `not_paired` /
/// `no_active_lease` / `autonomy_deny` / `busy` / `no_provider`) so the
/// operator's audit trail shows exactly why. Security-relevant.
///
/// Payload (JSON): `{task_id, peer_pubkey, reason, ts_unix}`.
/// SL-01 (Session 33).
pub const EVENT_TYPE_CLUSTER_TASK_REJECTED: u8 = 0xEC;

/// `0xED CLUSTER_GOSSIP_SENT` — the gossip-tick broadcast a batch of replicable
/// WAL frames to paired peers (SL-01b). High-cadence diagnostic (batchable, NOT
/// immediate-sync). Payload (JSON): `{frame_count, peer_count, ts_unix}`.
pub const EVENT_TYPE_CLUSTER_GOSSIP_SENT: u8 = 0xED;

/// `0xEE CLUSTER_GOSSIP_RECEIVED` — an inbound gossip frame was ACCEPTED
/// (tag/budget/dedup/band all passed). The primary "what this node learned from
/// peers" signal. Batchable. Payload: `{origin_peer, event_seq, payload_event_type,
/// vc_changed, ts_unix}`. (Payload application into local memory is deferred.)
pub const EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED: u8 = 0xEE;

/// `0xEF CLUSTER_GOSSIP_DROPPED` — an inbound gossip frame was rejected, with
/// the reason (`do_not_gossip` / `outside_replay_budget` / `duplicate`). Batchable.
/// Operator-actionable (a flood of `outside_replay_budget` ⇒ a peer needs repair).
/// Payload: `{origin_peer, event_seq, reason, ts_unix}`.
pub const EVENT_TYPE_CLUSTER_GOSSIP_DROPPED: u8 = 0xEF;

// Cluster band 0xE0..=0xEF now FULLY assigned (0xED..0xEF = SL-01b gossip).

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
            // SL-01b gossip diagnostics are high-cadence + re-derivable; batch
            // them behind the next sync-on-write frame rather than fsyncing each.
            | EVENT_TYPE_CLUSTER_GOSSIP_SENT
            | EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED
            | EVENT_TYPE_CLUSTER_GOSSIP_DROPPED
            // HO-07: channel silence is advisory; loss in a crash window is
            // acceptable. WAL-CRC and crash-log alerts are immediate-sync by
            // the default-true rule (not listed here).
            | EVENT_TYPE_CHANNEL_SILENCE_ALERT
            // GOLD-ADOPT-18: a subdirectory-hint injection is advisory +
            // high-cadence (one per newly-entered dir); fsyncing each would
            // harm latency on deep projects. Re-derivable, loss-tolerant.
            | EVENT_TYPE_HINT_LOADED
            // GOLD-ADOPT-04: a web-extract HIT is high-cadence + re-derivable
            // from the HTTP response. The STALE event (0x5A) stays immediate-
            // sync — a structural-change audit anchor must survive a crash.
            | EVENT_TYPE_WEB_EXTRACT_HIT
            // GOLD-ADOPT-19: context-compaction START/DONE are informational
            // (the outcome is observable from the loop result + the DONE frame).
            // Batchable behind the next sync-on-write frame.
            | EVENT_TYPE_CONTEXT_COMPACTION_START
            | EVENT_TYPE_CONTEXT_COMPACTION_DONE
            // GOLD-FEAT-09: a watchdog restart/alert is an operational anchor
            // (the service is back or flagged) — observable from the next
            // probe + the frame itself. Batchable behind the next sync frame.
            | EVENT_TYPE_WATCHDOG_RESTART
    )
}

/// Operator-facing event-type name table for `neoth wal show --type <name>`.
/// Maps the snake_case names operators see in `--type` filters + docs to
/// their code. Curated to the auditable surfaces an operator actually
/// filters on (plugin / provider / council / consent / refusal / lifecycle /
/// ingest); any code not listed is still reachable by its hex value
/// (`--type 0xC7`). The `event_type_names_are_unique_and_resolve` test pins
/// that every entry resolves to a distinct code so a rename can't silently
/// orphan a documented `--type` name.
pub const EVENT_NAME_TABLE: &[(&str, u8)] = &[
    ("raw_text", EVENT_TYPE_RAW_TEXT),
    ("reinforce", EVENT_TYPE_REINFORCE),
    ("boot", EVENT_TYPE_BOOT),
    ("shutdown", EVENT_TYPE_SHUTDOWN),
    ("provider_request", EVENT_TYPE_PROVIDER_REQUEST),
    ("provider_response", EVENT_TYPE_PROVIDER_RESPONSE),
    ("provider_error", EVENT_TYPE_PROVIDER_ERROR),
    (
        "provider_quota_exceeded",
        EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED,
    ),
    (
        "provider_fallback_attempted",
        EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED,
    ),
    (
        "refusal_abliterated_used",
        EVENT_TYPE_REFUSAL_ABLITERATED_USED,
    ),
    (
        "refusal_abliterated_failed",
        EVENT_TYPE_REFUSAL_ABLITERATED_FAILED,
    ),
    ("refusal_hard_blocked", EVENT_TYPE_REFUSAL_HARD_BLOCKED),
    ("budget_exceeded", EVENT_TYPE_BUDGET_EXCEEDED),
    ("ingest_extracted", EVENT_TYPE_INGEST_EXTRACTED),
    ("embed_persisted", EVENT_TYPE_EMBED_PERSISTED),
    ("refusal_observed", EVENT_TYPE_REFUSAL_OBSERVED),
    ("refusal_mirrored", EVENT_TYPE_REFUSAL_MIRRORED),
    ("refusal_redirected", EVENT_TYPE_REFUSAL_REDIRECTED),
    ("refusal_rerouted", EVENT_TYPE_REFUSAL_REROUTED),
    ("refusal_persistent", EVENT_TYPE_REFUSAL_PERSISTENT),
    (
        "council_synthesis_attempted",
        EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED,
    ),
    (
        "council_partial_refusal",
        EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL,
    ),
    ("council_skip", EVENT_TYPE_COUNCIL_SKIP),
    (
        "council_winner_selected",
        EVENT_TYPE_COUNCIL_WINNER_SELECTED,
    ),
    (
        "council_diversity_warning",
        EVENT_TYPE_COUNCIL_DIVERSITY_WARNING,
    ),
    ("consent_decision", EVENT_TYPE_CONSENT_DECISION),
    ("council_transcript", EVENT_TYPE_COUNCIL_TRANSCRIPT),
    ("channel_send", EVENT_TYPE_CHANNEL_SEND),
    ("channel_send_denied", EVENT_TYPE_CHANNEL_SEND_DENIED),
    ("token_tps_sample", EVENT_TYPE_TOKEN_TPS_SAMPLE),
    ("council_self_score", EVENT_TYPE_COUNCIL_SELF_SCORE),
    ("token_anomaly_detected", EVENT_TYPE_TOKEN_ANOMALY_DETECTED),
    (
        "session_health_degraded",
        EVENT_TYPE_SESSION_HEALTH_DEGRADED,
    ),
    ("mcp_tool_called", EVENT_TYPE_MCP_TOOL_CALLED),
    ("mcp_tool_rejected", EVENT_TYPE_MCP_TOOL_REJECTED),
    ("risk_gate_blocked", EVENT_TYPE_RISK_GATE_BLOCKED),
    ("risk_gate_denied", EVENT_TYPE_RISK_GATE_DENIED),
    (
        "risk_gate_confirm_required",
        EVENT_TYPE_RISK_GATE_CONFIRM_REQUIRED,
    ),
    ("risk_confirm_granted", EVENT_TYPE_RISK_CONFIRM_GRANTED),
    ("risk_confirm_used", EVENT_TYPE_RISK_CONFIRM_USED),
    ("risk_confirm_expired", EVENT_TYPE_RISK_CONFIRM_EXPIRED),
    (
        "risk_gate_allowed_by_readonly_cache",
        EVENT_TYPE_RISK_GATE_ALLOWED_BY_READONLY_CACHE,
    ),
    ("hint_loaded", EVENT_TYPE_HINT_LOADED),
    ("web_extract_hit", EVENT_TYPE_WEB_EXTRACT_HIT),
    (
        "web_extract_selector_stale",
        EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE,
    ),
    (
        "context_compaction_start",
        EVENT_TYPE_CONTEXT_COMPACTION_START,
    ),
    (
        "context_compaction_done",
        EVENT_TYPE_CONTEXT_COMPACTION_DONE,
    ),
    ("indexer_tamper_suspect", EVENT_TYPE_INDEXER_TAMPER_SUSPECT),
    ("watchdog_restart", EVENT_TYPE_WATCHDOG_RESTART),
    ("plugin_loaded", EVENT_TYPE_PLUGIN_LOADED),
    ("plugin_rejected", EVENT_TYPE_PLUGIN_REJECTED),
    ("plugin_hostcall", EVENT_TYPE_PLUGIN_HOSTCALL),
    ("plugin_fuel_exhausted", EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED),
    ("plugin_cap_used", EVENT_TYPE_PLUGIN_CAP_USED),
    ("plugin_cap_denied", EVENT_TYPE_PLUGIN_CAP_DENIED),
    ("todo_write", EVENT_TYPE_TODO_WRITE),
    ("calendar_write", EVENT_TYPE_CALENDAR_WRITE),
    ("calendar_write_denied", EVENT_TYPE_CALENDAR_WRITE_DENIED),
    ("calendar_write_failed", EVENT_TYPE_CALENDAR_WRITE_FAILED),
    (
        "video_frame_synthesized",
        EVENT_TYPE_VIDEO_FRAME_SYNTHESIZED,
    ),
    ("stt_transcribed", EVENT_TYPE_STT_TRANSCRIBED),
    ("tts_synthesized", EVENT_TYPE_TTS_SYNTHESIZED),
    ("preset_applied", EVENT_TYPE_PRESET_APPLIED),
    ("consent_granted", EVENT_TYPE_CONSENT_GRANTED),
    ("consent_revoked", EVENT_TYPE_CONSENT_REVOKED),
    (
        "sudomode_preset_applied",
        EVENT_TYPE_SUDOMODE_PRESET_APPLIED,
    ),
    ("permission_granted", EVENT_TYPE_PERMISSION_GRANTED),
    ("permission_denied", EVENT_TYPE_PERMISSION_DENIED),
    ("lease_granted", EVENT_TYPE_LEASE_GRANTED),
    ("lease_expired", EVENT_TYPE_LEASE_EXPIRED),
    ("lease_revoked", EVENT_TYPE_LEASE_REVOKED),
    ("os_file_read", EVENT_TYPE_OS_FILE_READ),
    ("os_file_denied", EVENT_TYPE_OS_FILE_DENIED),
    ("os_file_write", EVENT_TYPE_OS_FILE_WRITE),
    ("os_file_write_denied", EVENT_TYPE_OS_FILE_WRITE_DENIED),
    ("os_app_launch", EVENT_TYPE_OS_APP_LAUNCH),
    ("os_app_launch_denied", EVENT_TYPE_OS_APP_LAUNCH_DENIED),
    ("audit_rpc_accept", EVENT_TYPE_AUDIT_RPC_ACCEPT),
    ("audit_rpc_reject", EVENT_TYPE_AUDIT_RPC_REJECT),
    ("operator_feedback", EVENT_TYPE_OPERATOR_FEEDBACK),
    ("os_clipboard_access", EVENT_TYPE_OS_CLIPBOARD_ACCESS),
    ("os_clipboard_denied", EVENT_TYPE_OS_CLIPBOARD_DENIED),
    (
        "eval_critical_divergence",
        EVENT_TYPE_EVAL_CRITICAL_DIVERGENCE,
    ),
    ("regression_alert", EVENT_TYPE_REGRESSION_ALERT),
    ("email_ingress_triaged", EVENT_TYPE_EMAIL_INGRESS_TRIAGED),
    (
        "email_ingress_quarantined",
        EVENT_TYPE_EMAIL_INGRESS_QUARANTINED,
    ),
    ("email_tiebreak_applied", EVENT_TYPE_EMAIL_TIEBREAK_APPLIED),
    ("tombstone_requested", EVENT_TYPE_TOMBSTONE_REQUESTED),
    ("dream_composed", EVENT_TYPE_DREAM_COMPOSED),
    (
        "memory_transfer_exported",
        EVENT_TYPE_MEMORY_TRANSFER_EXPORTED,
    ),
    ("recon_run", EVENT_TYPE_RECON_RUN),
    ("identity_merged", EVENT_TYPE_IDENTITY_MERGED),
    ("omi_action_promoted", EVENT_TYPE_OMI_ACTION_PROMOTED),
    ("wal_crc_alert", EVENT_TYPE_WAL_CRC_ALERT),
    ("crash_log_alert", EVENT_TYPE_CRASH_LOG_ALERT),
    ("channel_silence_alert", EVENT_TYPE_CHANNEL_SILENCE_ALERT),
    ("recall_latency_alert", EVENT_TYPE_RECALL_LATENCY_ALERT),
    (
        "ecology_scheduler_fired",
        EVENT_TYPE_ECOLOGY_SCHEDULER_FIRED,
    ),
    ("worker_died", EVENT_TYPE_WORKER_DIED),
    ("rss_feed_item_indexed", EVENT_TYPE_RSS_FEED_ITEM_INDEXED),
    ("rss_feed_pass_complete", EVENT_TYPE_RSS_FEED_PASS_COMPLETE),
];

/// Resolve a `--type` filter token to an event code. Accepts (in order):
/// a curated snake_case name from [`EVENT_NAME_TABLE`] (case-
/// insensitive), a hex code (`0xC7` / `C7`), or a decimal code (`199`).
/// Returns `None` when nothing matches so the caller can surface a clear
/// "unknown event type" error instead of silently filtering to nothing.
pub fn event_code_from_filter(token: &str) -> Option<u8> {
    let t = token.trim();
    if t.is_empty() {
        return None;
    }
    // Name (case-insensitive).
    let lower = t.to_ascii_lowercase();
    if let Some((_, code)) = EVENT_NAME_TABLE.iter().find(|(name, _)| *name == lower) {
        return Some(*code);
    }
    // Hex: 0xNN or bare NN.
    let hex = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"));
    if let Some(h) = hex {
        return u8::from_str_radix(h, 16).ok();
    }
    if let Ok(b) = u8::from_str_radix(t, 16) {
        // Bare two-hex-digit form (e.g. `c7`) when it isn't valid decimal.
        if t.len() <= 2 && t.chars().any(|c| c.is_ascii_alphabetic()) {
            return Some(b);
        }
    }
    // Decimal.
    t.parse::<u8>().ok()
}

/// Reverse lookup: the curated operator-facing name for a code, if one
/// exists. Used by `neoth wal show` to label each frame; falls back to the
/// hex code at the call site when this returns `None`.
pub fn event_name_from_code(code: u8) -> Option<&'static str> {
    EVENT_NAME_TABLE
        .iter()
        .find(|(_, c)| *c == code)
        .map(|(name, _)| *name)
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

/// `0xF4 DREAM_COMPOSED` — SPEC-12 / R-02. The dreaming pass (operator-triggered
/// `neoth dream now`, or the nightly cron) composed one or more dream records
/// over a recent window: it embedded the window's episodes, cosine-clustered
/// them into themes, and appended a Dream per cluster to
/// `~/.neoth/dreams/YYYY-MM-DD.jsonl`. The audit trail for memory consolidation
/// — an operator can reconstruct when dreams were formed + over how many events.
///
/// Payload (JSON): `{day, dreams, events_considered, path_taken, ts_unix}`
/// (`path_taken` = "Embedding" | "Deterministic").
pub const EVENT_TYPE_DREAM_COMPOSED: u8 = 0xF4;

/// `0xF5 MEMORY_TRANSFER_EXPORTED` — A3-01. The operator ran `neoth transfer
/// --dest <pubkey>` to export a recipient-encrypted, operator-signed memory
/// bundle (ephemeral X25519 ECDH → HKDF-SHA256 → AES-256-GCM, ed25519-signed).
/// The audit anchor records THAT an export happened + to whom + how large —
/// never the plaintext (the bundle ciphertext lives in `~/.neoth/exports/`).
///
/// Payload (JSON): `{dest_pubkey_b64, bundle_bytes, events_exported, window,
/// ts_unix}`.
pub const EVENT_TYPE_MEMORY_TRANSFER_EXPORTED: u8 = 0xF5;

/// `0xF6 RECON_RUN` — the operator ran a gated recon tool (`neoth recon
/// uncover` / `tlsx`) for an authorized engagement. Records THAT recon ran +
/// which tool, a hash of the args (NEVER the raw query / target hosts — those
/// could be a Shodan dork or a victim list), the result count, and the autonomy
/// level it ran under. Brings recon to the same audit level as the MCP tool
/// band (`0xC0`): one-shot CLI runs forward this frame to the live daemon over
/// the audit-RPC channel, or write it directly when no daemon owns the WAL.
///
/// Payload (JSON): `{tool, args_hash, result_count, autonomy_level,
/// operator_id, ts_unix}`.
pub const EVENT_TYPE_RECON_RUN: u8 = 0xF6;

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
    let _ = [(); 1][(EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED < 0x20
        || EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_LOCAL_INFERENCE_START < 0x20
        || EVENT_TYPE_LOCAL_INFERENCE_START > 0x2F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_LOCAL_INFERENCE_END < 0x20 || EVENT_TYPE_LOCAL_INFERENCE_END > 0x2F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_INGEST_EXTRACTED < 0x20 || EVENT_TYPE_INGEST_EXTRACTED > 0x2F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_EMBED_PERSISTED < 0x20 || EVENT_TYPE_EMBED_PERSISTED > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_EXTRACT_TARGET < 0x20
        || EVENT_TYPE_PROFILE_EXTRACT_TARGET > 0x2F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_BUDGET_EXCEEDED < 0x20 || EVENT_TYPE_BUDGET_EXCEEDED > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_SKILL_INJECT_SKIPPED < 0x20
        || EVENT_TYPE_SKILL_INJECT_SKIPPED > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_REFUSAL_ABLITERATED_USED < 0x20
        || EVENT_TYPE_REFUSAL_ABLITERATED_USED > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_REFUSAL_ABLITERATED_FAILED < 0x20
        || EVENT_TYPE_REFUSAL_ABLITERATED_FAILED > 0x2F) as usize];
    let _ = [(); 1][(EVENT_TYPE_REFUSAL_HARD_BLOCKED < 0x20
        || EVENT_TYPE_REFUSAL_HARD_BLOCKED > 0x2F) as usize];
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
    let _ =
        [(); 1][(EVENT_TYPE_PROACTIVE_SENT < 0x30 || EVENT_TYPE_PROACTIVE_SENT > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CHANNEL_GATE_REJECTED < 0x30
        || EVENT_TYPE_CHANNEL_GATE_REJECTED > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CHANNEL_PRIVILEGE_BLOCKED < 0x30
        || EVENT_TYPE_CHANNEL_PRIVILEGE_BLOCKED > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_EMAIL_INGRESS_TRIAGED < 0x30
        || EVENT_TYPE_EMAIL_INGRESS_TRIAGED > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_EMAIL_INGRESS_QUARANTINED < 0x30
        || EVENT_TYPE_EMAIL_INGRESS_QUARANTINED > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_EMAIL_TIEBREAK_APPLIED < 0x30
        || EVENT_TYPE_EMAIL_TIEBREAK_APPLIED > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_EVAL_CRITICAL_DIVERGENCE < 0x30
        || EVENT_TYPE_EVAL_CRITICAL_DIVERGENCE > 0x3F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_REGRESSION_ALERT < 0x30 || EVENT_TYPE_REGRESSION_ALERT > 0x3F) as usize];
    let _ = [(); 1][(EVENT_TYPE_JOB_FIRED < 0x40 || EVENT_TYPE_JOB_FIRED > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_JOB_SUCCESS < 0x40 || EVENT_TYPE_JOB_SUCCESS > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_JOB_FAILED < 0x40 || EVENT_TYPE_JOB_FAILED > 0x4F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_JOB_SKIPPED_BY_GATE < 0x40 || EVENT_TYPE_JOB_SKIPPED_BY_GATE > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_DOCTOR_TICK < 0x40 || EVENT_TYPE_DOCTOR_TICK > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_RESOURCE_PRESSURE_ALERT < 0x40
        || EVENT_TYPE_RESOURCE_PRESSURE_ALERT > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_WAL_CRC_ALERT < 0x40 || EVENT_TYPE_WAL_CRC_ALERT > 0x4F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_CRASH_LOG_ALERT < 0x40 || EVENT_TYPE_CRASH_LOG_ALERT > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CHANNEL_SILENCE_ALERT < 0x40
        || EVENT_TYPE_CHANNEL_SILENCE_ALERT > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_RECALL_LATENCY_ALERT < 0x40
        || EVENT_TYPE_RECALL_LATENCY_ALERT > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_ECOLOGY_SCHEDULER_FIRED < 0x40
        || EVENT_TYPE_ECOLOGY_SCHEDULER_FIRED > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_WORKER_DIED < 0x40 || EVENT_TYPE_WORKER_DIED > 0x4F) as usize];
    // GR-166 — the RSS feed band-guards were missing; 0x4E/0x4F live in the
    // 0x40-0x4F job/monitor band like every other code here.
    let _ = [(); 1][(EVENT_TYPE_RSS_FEED_ITEM_INDEXED < 0x40
        || EVENT_TYPE_RSS_FEED_ITEM_INDEXED > 0x4F) as usize];
    let _ = [(); 1][(EVENT_TYPE_RSS_FEED_PASS_COMPLETE < 0x40
        || EVENT_TYPE_RSS_FEED_PASS_COMPLETE > 0x4F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_RECOVERY_TRUNCATED < 0x50 || EVENT_TYPE_RECOVERY_TRUNCATED > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COMPACTION_AUTH_FAILED < 0x50
        || EVENT_TYPE_COMPACTION_AUTH_FAILED > 0x5F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_RISK_GATE_DENIED < 0x50 || EVENT_TYPE_RISK_GATE_DENIED > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_RISK_GATE_CONFIRM_REQUIRED < 0x50
        || EVENT_TYPE_RISK_GATE_CONFIRM_REQUIRED > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_RISK_CONFIRM_GRANTED < 0x50
        || EVENT_TYPE_RISK_CONFIRM_GRANTED > 0x5F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_RISK_CONFIRM_USED < 0x50 || EVENT_TYPE_RISK_CONFIRM_USED > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_RISK_CONFIRM_EXPIRED < 0x50
        || EVENT_TYPE_RISK_CONFIRM_EXPIRED > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_RISK_GATE_ALLOWED_BY_READONLY_CACHE < 0x50
        || EVENT_TYPE_RISK_GATE_ALLOWED_BY_READONLY_CACHE > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_HINT_LOADED < 0x50 || EVENT_TYPE_HINT_LOADED > 0x5F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_WEB_EXTRACT_HIT < 0x50 || EVENT_TYPE_WEB_EXTRACT_HIT > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE < 0x50
        || EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CONTEXT_COMPACTION_START < 0x50
        || EVENT_TYPE_CONTEXT_COMPACTION_START > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CONTEXT_COMPACTION_DONE < 0x50
        || EVENT_TYPE_CONTEXT_COMPACTION_DONE > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_INDEXER_TAMPER_SUSPECT < 0x50
        || EVENT_TYPE_INDEXER_TAMPER_SUSPECT > 0x5F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_WATCHDOG_RESTART < 0x50 || EVENT_TYPE_WATCHDOG_RESTART > 0x5F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED < 0x60
        || EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL < 0x60
        || EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_SKIP < 0x60 || EVENT_TYPE_COUNCIL_SKIP > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_WINNER_SELECTED < 0x60
        || EVENT_TYPE_COUNCIL_WINNER_SELECTED > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_COUNCIL_DIVERSITY_WARNING < 0x60
        || EVENT_TYPE_COUNCIL_DIVERSITY_WARNING > 0x6F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_COUNCIL_TRANSCRIPT < 0x60 || EVENT_TYPE_COUNCIL_TRANSCRIPT > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_CHANNEL_SEND < 0x60 || EVENT_TYPE_CHANNEL_SEND > 0x6F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_CHANNEL_SEND_DENIED < 0x60 || EVENT_TYPE_CHANNEL_SEND_DENIED > 0x6F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_TOKEN_TPS_SAMPLE < 0x60 || EVENT_TYPE_TOKEN_TPS_SAMPLE > 0x6F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_COUNCIL_SELF_SCORE < 0x60 || EVENT_TYPE_COUNCIL_SELF_SCORE > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_TOKEN_ANOMALY_DETECTED < 0x60
        || EVENT_TYPE_TOKEN_ANOMALY_DETECTED > 0x6F) as usize];
    let _ = [(); 1][(EVENT_TYPE_SESSION_HEALTH_DEGRADED < 0x60
        || EVENT_TYPE_SESSION_HEALTH_DEGRADED > 0x6F) as usize];
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
    let _ =
        [(); 1][(EVENT_TYPE_IDENTITY_MERGED < 0x90 || EVENT_TYPE_IDENTITY_MERGED > 0x9F) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_OMI_ACTION_PROMOTED < 0x90 || EVENT_TYPE_OMI_ACTION_PROMOTED > 0x9F) as usize];
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
    let _ = [(); 1][(EVENT_TYPE_LEASE_GRANTED < 0xA0 || EVENT_TYPE_LEASE_GRANTED > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_LEASE_EXPIRED < 0xA0 || EVENT_TYPE_LEASE_EXPIRED > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_LEASE_REVOKED < 0xA0 || EVENT_TYPE_LEASE_REVOKED > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_OS_FILE_READ < 0xA0 || EVENT_TYPE_OS_FILE_READ > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_OS_FILE_WRITE < 0xA0 || EVENT_TYPE_OS_FILE_WRITE > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_OS_FILE_WRITE_DENIED < 0xA0
        || EVENT_TYPE_OS_FILE_WRITE_DENIED > 0xAF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_OS_FILE_DENIED < 0xA0 || EVENT_TYPE_OS_FILE_DENIED > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_OS_APP_LAUNCH < 0xA0 || EVENT_TYPE_OS_APP_LAUNCH > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_OS_APP_LAUNCH_DENIED < 0xA0
        || EVENT_TYPE_OS_APP_LAUNCH_DENIED > 0xAF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_AUDIT_RPC_ACCEPT < 0xA0 || EVENT_TYPE_AUDIT_RPC_ACCEPT > 0xAF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_AUDIT_RPC_REJECT < 0xA0 || EVENT_TYPE_AUDIT_RPC_REJECT > 0xAF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_DELTA < 0xB0 || EVENT_TYPE_PROFILE_DELTA > 0xBF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PROFILE_REINFORCED < 0xB0 || EVENT_TYPE_PROFILE_REINFORCED > 0xBF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PROFILE_SUPERSEDED < 0xB0 || EVENT_TYPE_PROFILE_SUPERSEDED > 0xBF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_DELTA_BLOCKED < 0xB0
        || EVENT_TYPE_PROFILE_DELTA_BLOCKED > 0xBF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT < 0xB0
        || EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT > 0xBF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_REDACT_BLOCKED < 0xB0
        || EVENT_TYPE_PROFILE_REDACT_BLOCKED > 0xBF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PROFILE_EXTRACT_SKIPPED < 0xB0
        || EVENT_TYPE_PROFILE_EXTRACT_SKIPPED > 0xBF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PROFILE_DRIFT_ALERT < 0xB0 || EVENT_TYPE_PROFILE_DRIFT_ALERT > 0xBF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_OPERATOR_FEEDBACK < 0xB0 || EVENT_TYPE_OPERATOR_FEEDBACK > 0xBF) as usize];
    // PC-01 clipboard — OS-tool overflow from the full 0xA band into reserved 0xB space.
    let _ = [(); 1]
        [(EVENT_TYPE_OS_CLIPBOARD_ACCESS < 0xB0 || EVENT_TYPE_OS_CLIPBOARD_ACCESS > 0xBF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_OS_CLIPBOARD_DENIED < 0xB0 || EVENT_TYPE_OS_CLIPBOARD_DENIED > 0xBF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_MCP_TOOL_CALLED < 0xC0 || EVENT_TYPE_MCP_TOOL_CALLED > 0xCF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PLUGIN_LOADED < 0xC0 || EVENT_TYPE_PLUGIN_LOADED > 0xCF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_PLUGIN_REJECTED < 0xC0 || EVENT_TYPE_PLUGIN_REJECTED > 0xCF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_PLUGIN_HOSTCALL < 0xC0 || EVENT_TYPE_PLUGIN_HOSTCALL > 0xCF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED < 0xC0
        || EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED > 0xCF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_PLUGIN_CAP_USED < 0xC0 || EVENT_TYPE_PLUGIN_CAP_USED > 0xCF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PLUGIN_CAP_DENIED < 0xC0 || EVENT_TYPE_PLUGIN_CAP_DENIED > 0xCF) as usize];
    let _ = [(); 1][(EVENT_TYPE_TODO_WRITE < 0xC0 || EVENT_TYPE_TODO_WRITE > 0xCF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_CALENDAR_WRITE < 0xC0 || EVENT_TYPE_CALENDAR_WRITE > 0xCF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CALENDAR_WRITE_DENIED < 0xC0
        || EVENT_TYPE_CALENDAR_WRITE_DENIED > 0xCF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CALENDAR_WRITE_FAILED < 0xC0
        || EVENT_TYPE_CALENDAR_WRITE_FAILED > 0xCF) as usize];
    let _ = [(); 1][(EVENT_TYPE_VIDEO_FRAME_SYNTHESIZED < 0xC0
        || EVENT_TYPE_VIDEO_FRAME_SYNTHESIZED > 0xCF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_STT_TRANSCRIBED < 0xC0 || EVENT_TYPE_STT_TRANSCRIBED > 0xCF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_TTS_SYNTHESIZED < 0xC0 || EVENT_TYPE_TTS_SYNTHESIZED > 0xCF) as usize];
    // GR-166 — RISK_GATE_BLOCKED (0xCF) sits at the top of the 0xC0-0xCF tool
    // band but had no band-guard; pin it like its neighbours.
    let _ = [(); 1]
        [(EVENT_TYPE_RISK_GATE_BLOCKED < 0xC0 || EVENT_TYPE_RISK_GATE_BLOCKED > 0xCF) as usize];
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
    // GOLD-COR-06 / A-80: 0x77 KANBAN_TASK_PROGRESS was registered in the
    // coding-workflow band but never added here, so the compile-time band guard
    // silently did not cover it. Now it does.
    let _ = [(); 1][(EVENT_TYPE_KANBAN_TASK_PROGRESS < 0x70
        || EVENT_TYPE_KANBAN_TASK_PROGRESS > 0x7F) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_CONFIG_RELOADED < 0xD0 || EVENT_TYPE_CONFIG_RELOADED > 0xDF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CONFIG_RELOAD_REJECTED < 0xD0
        || EVENT_TYPE_CONFIG_RELOAD_REJECTED > 0xDF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_SELF_UPDATE_APPLIED < 0xD0 || EVENT_TYPE_SELF_UPDATE_APPLIED > 0xDF) as usize];
    let _ = [(); 1][(EVENT_TYPE_PATCH_APPLIED < 0xD0 || EVENT_TYPE_PATCH_APPLIED > 0xDF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_PATCH_APPLY_FAILED < 0xD0 || EVENT_TYPE_PATCH_APPLY_FAILED > 0xDF) as usize];
    // HF-01 model-download band membership (0xD0..=0xDF).
    let _ = [(); 1][(EVENT_TYPE_MODEL_DOWNLOAD_START < 0xD0
        || EVENT_TYPE_MODEL_DOWNLOAD_START > 0xDF) as usize];
    let _ = [(); 1][(EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE < 0xD0
        || EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE > 0xDF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_HMAC_KEY_ROTATED < 0xD0 || EVENT_TYPE_HMAC_KEY_ROTATED > 0xDF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_PRESET_APPLIED < 0xD0 || EVENT_TYPE_PRESET_APPLIED > 0xDF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_CONSENT_GRANTED < 0xD0 || EVENT_TYPE_CONSENT_GRANTED > 0xDF) as usize];
    let _ =
        [(); 1][(EVENT_TYPE_CONSENT_REVOKED < 0xD0 || EVENT_TYPE_CONSENT_REVOKED > 0xDF) as usize];
    let _ = [(); 1][(EVENT_TYPE_SUDOMODE_PRESET_APPLIED < 0xD0
        || EVENT_TYPE_SUDOMODE_PRESET_APPLIED > 0xDF) as usize];
    let _ = [(); 1][(EVENT_TYPE_SELF_UPDATE_REJECTED < 0xD0
        || EVENT_TYPE_SELF_UPDATE_REJECTED > 0xDF) as usize];
    let _ = [(); 1][(EVENT_TYPE_MORAL_CORE_TOGGLED < 0xD0
        || EVENT_TYPE_MORAL_CORE_TOGGLED > 0xDF) as usize];
    // R-7 cluster lifecycle band (0xE0..=0xEF).
    // All eleven assigned codes (0xE0..=0xEA) and the four reserved slots
    // (0xEB..=0xEF) share one declared band. Every assertion uses the full
    // 0xEF upper bound so a future reassignment of any code within the band
    // is caught at compile time regardless of which slot it lands on.
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_CONNECTED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_CONNECTED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_DISCONNECTED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_DISCONNECTED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_REJECTED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_REJECTED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_HEARTBEAT_FIRST < 0xE0
        || EVENT_TYPE_CLUSTER_HEARTBEAT_FIRST > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_HEALTH_CHANGED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_HEALTH_CHANGED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_CAPABILITIES_CHANGED < 0xE0
        || EVENT_TYPE_CLUSTER_CAPABILITIES_CHANGED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_CONFIRMED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_CONFIRMED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_PEER_REVOKED < 0xE0
        || EVENT_TYPE_CLUSTER_PEER_REVOKED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_ROLE_CHANGED < 0xE0
        || EVENT_TYPE_CLUSTER_ROLE_CHANGED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_REQUEST_FORWARDED < 0xE0
        || EVENT_TYPE_CLUSTER_REQUEST_FORWARDED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_HEARTBEAT_SENT < 0xE0
        || EVENT_TYPE_CLUSTER_HEARTBEAT_SENT > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_TASK_ACCEPTED < 0xE0
        || EVENT_TYPE_CLUSTER_TASK_ACCEPTED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_TASK_REJECTED < 0xE0
        || EVENT_TYPE_CLUSTER_TASK_REJECTED > 0xEF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_CLUSTER_GOSSIP_SENT < 0xE0 || EVENT_TYPE_CLUSTER_GOSSIP_SENT > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED < 0xE0
        || EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED > 0xEF) as usize];
    let _ = [(); 1][(EVENT_TYPE_CLUSTER_GOSSIP_DROPPED < 0xE0
        || EVENT_TYPE_CLUSTER_GOSSIP_DROPPED > 0xEF) as usize];
    let _ = [(); 1]
        [(EVENT_TYPE_MCP_TOOL_REJECTED < 0xC0 || EVENT_TYPE_MCP_TOOL_REJECTED > 0xCF) as usize];
    // 0xF0-0xFF band: u8 max == 0xFF so upper-bound check is trivially
    // true (clippy::absurd_extreme_comparisons). Only lower-bound check
    // is meaningful here.
    let _ = [(); 1][(EVENT_TYPE_QUOTA_BREACHED < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_TOMBSTONE_REQUESTED < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_PRE_MUTATION_SNAPSHOT < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_REDACTION_MARKER < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_DREAM_COMPOSED < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_MEMORY_TRANSFER_EXPORTED < 0xF0) as usize];
    let _ = [(); 1][(EVENT_TYPE_RECON_RUN < 0xF0) as usize];
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
            (
                "PROVIDER_FALLBACK_ATTEMPTED",
                EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED,
            ),
            (
                "REFUSAL_ABLITERATED_USED",
                EVENT_TYPE_REFUSAL_ABLITERATED_USED,
            ),
            (
                "REFUSAL_ABLITERATED_FAILED",
                EVENT_TYPE_REFUSAL_ABLITERATED_FAILED,
            ),
            ("REFUSAL_HARD_BLOCKED", EVENT_TYPE_REFUSAL_HARD_BLOCKED),
            ("LOCAL_INFERENCE_START", EVENT_TYPE_LOCAL_INFERENCE_START),
            ("LOCAL_INFERENCE_END", EVENT_TYPE_LOCAL_INFERENCE_END),
            ("INGEST_EXTRACTED", EVENT_TYPE_INGEST_EXTRACTED),
            ("EMBED_PERSISTED", EVENT_TYPE_EMBED_PERSISTED),
            ("PROFILE_EXTRACT_TARGET", EVENT_TYPE_PROFILE_EXTRACT_TARGET),
            ("BUDGET_EXCEEDED", EVENT_TYPE_BUDGET_EXCEEDED),
            ("SKILL_INJECT_SKIPPED", EVENT_TYPE_SKILL_INJECT_SKIPPED),
            ("CHANNEL_INGRESS", EVENT_TYPE_CHANNEL_INGRESS),
            ("CHANNEL_EGRESS", EVENT_TYPE_CHANNEL_EGRESS),
            ("PROACTIVE_SENT", EVENT_TYPE_PROACTIVE_SENT),
            ("CHANNEL_GATE_REJECTED", EVENT_TYPE_CHANNEL_GATE_REJECTED),
            (
                "CHANNEL_PRIVILEGE_BLOCKED",
                EVENT_TYPE_CHANNEL_PRIVILEGE_BLOCKED,
            ),
            (
                "EVAL_CRITICAL_DIVERGENCE",
                EVENT_TYPE_EVAL_CRITICAL_DIVERGENCE,
            ),
            ("REGRESSION_ALERT", EVENT_TYPE_REGRESSION_ALERT),
            ("EMAIL_INGRESS_TRIAGED", EVENT_TYPE_EMAIL_INGRESS_TRIAGED),
            (
                "EMAIL_INGRESS_QUARANTINED",
                EVENT_TYPE_EMAIL_INGRESS_QUARANTINED,
            ),
            ("EMAIL_TIEBREAK_APPLIED", EVENT_TYPE_EMAIL_TIEBREAK_APPLIED),
            ("CHANNEL_ERROR", EVENT_TYPE_CHANNEL_ERROR),
            ("INGRESS_QUARANTINED", EVENT_TYPE_INGRESS_QUARANTINED),
            ("INGRESS_SANITIZED", EVENT_TYPE_INGRESS_SANITIZED),
            ("CHANNEL_ACK", EVENT_TYPE_CHANNEL_ACK),
            ("CHANNEL_EDIT", EVENT_TYPE_CHANNEL_EDIT),
            ("N8N_REQUEST", EVENT_TYPE_N8N_REQUEST),
            ("JOB_FIRED", EVENT_TYPE_JOB_FIRED),
            ("JOB_SUCCESS", EVENT_TYPE_JOB_SUCCESS),
            ("JOB_FAILED", EVENT_TYPE_JOB_FAILED),
            (
                "RESOURCE_PRESSURE_ALERT",
                EVENT_TYPE_RESOURCE_PRESSURE_ALERT,
            ),
            ("WAL_CRC_ALERT", EVENT_TYPE_WAL_CRC_ALERT),
            ("CRASH_LOG_ALERT", EVENT_TYPE_CRASH_LOG_ALERT),
            ("CHANNEL_SILENCE_ALERT", EVENT_TYPE_CHANNEL_SILENCE_ALERT),
            ("RECALL_LATENCY_ALERT", EVENT_TYPE_RECALL_LATENCY_ALERT),
            (
                "ECOLOGY_SCHEDULER_FIRED",
                EVENT_TYPE_ECOLOGY_SCHEDULER_FIRED,
            ),
            ("WORKER_DIED", EVENT_TYPE_WORKER_DIED),
            ("RSS_FEED_ITEM_INDEXED", EVENT_TYPE_RSS_FEED_ITEM_INDEXED),
            ("RSS_FEED_PASS_COMPLETE", EVENT_TYPE_RSS_FEED_PASS_COMPLETE),
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
            ("COUNCIL_TRANSCRIPT", EVENT_TYPE_COUNCIL_TRANSCRIPT),
            ("CHANNEL_SEND", EVENT_TYPE_CHANNEL_SEND),
            ("CHANNEL_SEND_DENIED", EVENT_TYPE_CHANNEL_SEND_DENIED),
            ("TOKEN_TPS_SAMPLE", EVENT_TYPE_TOKEN_TPS_SAMPLE),
            ("COUNCIL_SELF_SCORE", EVENT_TYPE_COUNCIL_SELF_SCORE),
            ("TOKEN_ANOMALY_DETECTED", EVENT_TYPE_TOKEN_ANOMALY_DETECTED),
            (
                "SESSION_HEALTH_DEGRADED",
                EVENT_TYPE_SESSION_HEALTH_DEGRADED,
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
            ("IDENTITY_MERGED", EVENT_TYPE_IDENTITY_MERGED),
            ("OMI_ACTION_PROMOTED", EVENT_TYPE_OMI_ACTION_PROMOTED),
            ("PERMISSION_GRANTED", EVENT_TYPE_PERMISSION_GRANTED),
            ("PERMISSION_DENIED", EVENT_TYPE_PERMISSION_DENIED),
            ("LEVEL_ELEVATED", EVENT_TYPE_LEVEL_ELEVATED),
            ("LEVEL_DEROGATED", EVENT_TYPE_LEVEL_DEROGATED),
            ("LEASE_GRANTED", EVENT_TYPE_LEASE_GRANTED),
            ("LEASE_EXPIRED", EVENT_TYPE_LEASE_EXPIRED),
            ("LEASE_REVOKED", EVENT_TYPE_LEASE_REVOKED),
            ("OS_FILE_READ", EVENT_TYPE_OS_FILE_READ),
            ("OS_FILE_DENIED", EVENT_TYPE_OS_FILE_DENIED),
            ("OS_FILE_WRITE", EVENT_TYPE_OS_FILE_WRITE),
            ("OS_FILE_WRITE_DENIED", EVENT_TYPE_OS_FILE_WRITE_DENIED),
            ("OS_APP_LAUNCH", EVENT_TYPE_OS_APP_LAUNCH),
            ("OS_APP_LAUNCH_DENIED", EVENT_TYPE_OS_APP_LAUNCH_DENIED),
            ("AUDIT_RPC_ACCEPT", EVENT_TYPE_AUDIT_RPC_ACCEPT),
            ("AUDIT_RPC_REJECT", EVENT_TYPE_AUDIT_RPC_REJECT),
            ("COST_ESTIMATE_SHOWN", EVENT_TYPE_COST_ESTIMATE_SHOWN),
            ("PROFILE_DELTA", EVENT_TYPE_PROFILE_DELTA),
            ("PROFILE_REINFORCED", EVENT_TYPE_PROFILE_REINFORCED),
            ("PROFILE_SUPERSEDED", EVENT_TYPE_PROFILE_SUPERSEDED),
            (
                "PROFILE_BASELINE_SNAPSHOT",
                EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
            ),
            ("PROFILE_DELTA_BLOCKED", EVENT_TYPE_PROFILE_DELTA_BLOCKED),
            ("PROFILE_REDACT_BLOCKED", EVENT_TYPE_PROFILE_REDACT_BLOCKED),
            (
                "PROFILE_EXTRACT_SKIPPED",
                EVENT_TYPE_PROFILE_EXTRACT_SKIPPED,
            ),
            ("PROFILE_DRIFT_ALERT", EVENT_TYPE_PROFILE_DRIFT_ALERT),
            ("OPERATOR_FEEDBACK", EVENT_TYPE_OPERATOR_FEEDBACK),
            ("OS_CLIPBOARD_ACCESS", EVENT_TYPE_OS_CLIPBOARD_ACCESS),
            ("OS_CLIPBOARD_DENIED", EVENT_TYPE_OS_CLIPBOARD_DENIED),
            ("MCP_TOOL_CALLED", EVENT_TYPE_MCP_TOOL_CALLED),
            ("MCP_TOOL_REJECTED", EVENT_TYPE_MCP_TOOL_REJECTED),
            ("RISK_GATE_BLOCKED", EVENT_TYPE_RISK_GATE_BLOCKED),
            ("RISK_GATE_DENIED", EVENT_TYPE_RISK_GATE_DENIED),
            (
                "RISK_GATE_CONFIRM_REQUIRED",
                EVENT_TYPE_RISK_GATE_CONFIRM_REQUIRED,
            ),
            ("RISK_CONFIRM_GRANTED", EVENT_TYPE_RISK_CONFIRM_GRANTED),
            ("RISK_CONFIRM_USED", EVENT_TYPE_RISK_CONFIRM_USED),
            ("RISK_CONFIRM_EXPIRED", EVENT_TYPE_RISK_CONFIRM_EXPIRED),
            (
                "RISK_GATE_ALLOWED_BY_READONLY_CACHE",
                EVENT_TYPE_RISK_GATE_ALLOWED_BY_READONLY_CACHE,
            ),
            ("HINT_LOADED", EVENT_TYPE_HINT_LOADED),
            ("WEB_EXTRACT_HIT", EVENT_TYPE_WEB_EXTRACT_HIT),
            (
                "WEB_EXTRACT_SELECTOR_STALE",
                EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE,
            ),
            (
                "CONTEXT_COMPACTION_START",
                EVENT_TYPE_CONTEXT_COMPACTION_START,
            ),
            (
                "CONTEXT_COMPACTION_DONE",
                EVENT_TYPE_CONTEXT_COMPACTION_DONE,
            ),
            ("WATCHDOG_RESTART", EVENT_TYPE_WATCHDOG_RESTART),
            ("PLUGIN_LOADED", EVENT_TYPE_PLUGIN_LOADED),
            ("PLUGIN_REJECTED", EVENT_TYPE_PLUGIN_REJECTED),
            ("PLUGIN_HOSTCALL", EVENT_TYPE_PLUGIN_HOSTCALL),
            ("PLUGIN_FUEL_EXHAUSTED", EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED),
            ("PLUGIN_CAP_USED", EVENT_TYPE_PLUGIN_CAP_USED),
            ("PLUGIN_CAP_DENIED", EVENT_TYPE_PLUGIN_CAP_DENIED),
            ("TODO_WRITE", EVENT_TYPE_TODO_WRITE),
            ("CALENDAR_WRITE", EVENT_TYPE_CALENDAR_WRITE),
            ("CALENDAR_WRITE_DENIED", EVENT_TYPE_CALENDAR_WRITE_DENIED),
            ("CALENDAR_WRITE_FAILED", EVENT_TYPE_CALENDAR_WRITE_FAILED),
            (
                "VIDEO_FRAME_SYNTHESIZED",
                EVENT_TYPE_VIDEO_FRAME_SYNTHESIZED,
            ),
            ("STT_TRANSCRIBED", EVENT_TYPE_STT_TRANSCRIBED),
            ("TTS_SYNTHESIZED", EVENT_TYPE_TTS_SYNTHESIZED),
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
            ("MODEL_DOWNLOAD_START", EVENT_TYPE_MODEL_DOWNLOAD_START),
            (
                "MODEL_DOWNLOAD_COMPLETE",
                EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE,
            ),
            ("HMAC_KEY_ROTATED", EVENT_TYPE_HMAC_KEY_ROTATED),
            ("PRESET_APPLIED", EVENT_TYPE_PRESET_APPLIED),
            ("CONSENT_GRANTED", EVENT_TYPE_CONSENT_GRANTED),
            ("CONSENT_REVOKED", EVENT_TYPE_CONSENT_REVOKED),
            (
                "SUDOMODE_PRESET_APPLIED",
                EVENT_TYPE_SUDOMODE_PRESET_APPLIED,
            ),
            ("SELF_UPDATE_REJECTED", EVENT_TYPE_SELF_UPDATE_REJECTED),
            ("MORAL_CORE_TOGGLED", EVENT_TYPE_MORAL_CORE_TOGGLED),
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
            ("CLUSTER_HEARTBEAT_SENT", EVENT_TYPE_CLUSTER_HEARTBEAT_SENT),
            ("CLUSTER_TASK_ACCEPTED", EVENT_TYPE_CLUSTER_TASK_ACCEPTED),
            ("CLUSTER_TASK_REJECTED", EVENT_TYPE_CLUSTER_TASK_REJECTED),
            ("CLUSTER_GOSSIP_SENT", EVENT_TYPE_CLUSTER_GOSSIP_SENT),
            (
                "CLUSTER_GOSSIP_RECEIVED",
                EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED,
            ),
            ("CLUSTER_GOSSIP_DROPPED", EVENT_TYPE_CLUSTER_GOSSIP_DROPPED),
            ("QUOTA_BREACHED", EVENT_TYPE_QUOTA_BREACHED),
            ("TOMBSTONE_REQUESTED", EVENT_TYPE_TOMBSTONE_REQUESTED),
            ("PRE_MUTATION_SNAPSHOT", EVENT_TYPE_PRE_MUTATION_SNAPSHOT),
            ("REDACTION_MARKER", EVENT_TYPE_REDACTION_MARKER),
            ("DREAM_COMPOSED", EVENT_TYPE_DREAM_COMPOSED),
            (
                "MEMORY_TRANSFER_EXPORTED",
                EVENT_TYPE_MEMORY_TRANSFER_EXPORTED,
            ),
            ("RECON_RUN", EVENT_TYPE_RECON_RUN),
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
        assert_eq!(EVENT_TYPE_PLUGIN_CAP_USED, 0xC6);
        assert_eq!(EVENT_TYPE_PLUGIN_CAP_DENIED, 0xC7);
        for code in [
            EVENT_TYPE_PLUGIN_LOADED,
            EVENT_TYPE_PLUGIN_REJECTED,
            EVENT_TYPE_PLUGIN_HOSTCALL,
            EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED,
            EVENT_TYPE_PLUGIN_CAP_USED,
            EVENT_TYPE_PLUGIN_CAP_DENIED,
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

    #[test]
    fn clipboard_audit_frames_are_durable() {
        // PC-01: a clipboard ACCESS (a read that captured a secret, or a write)
        // and a DENIED (a refused pastejack / policy refusal) are security-relevant
        // audit anchors — they MUST survive a crash. `needs_immediate_sync` is a
        // deny-list (absent ⇒ immediate fsync); this pins that 0xBC/0xBD are NEVER
        // added to the batchable list.
        assert!(needs_immediate_sync(EVENT_TYPE_OS_CLIPBOARD_ACCESS));
        assert!(needs_immediate_sync(EVENT_TYPE_OS_CLIPBOARD_DENIED));
    }

    #[test]
    fn event_type_name_table_is_unique_and_round_trips() {
        // Every operator-facing `--type <name>` must resolve to a distinct
        // code AND round-trip back to the same name — a rename that
        // orphans a documented filter name (the `wal show --type` class of
        // false-guarantee) fails here.
        for (name, code) in EVENT_NAME_TABLE {
            assert_eq!(
                event_code_from_filter(name),
                Some(*code),
                "name {name} did not resolve to its code"
            );
            assert_eq!(
                event_name_from_code(*code),
                Some(*name),
                "code 0x{code:02X} did not round-trip to {name}"
            );
        }
        // Uniqueness of codes in the table.
        let mut seen = std::collections::HashSet::new();
        for (name, code) in EVENT_NAME_TABLE {
            assert!(
                seen.insert(*code),
                "name-table code collision at 0x{code:02X} ({name})"
            );
        }
    }

    #[test]
    fn event_code_from_filter_accepts_name_hex_decimal() {
        // The three operator input forms for `wal show --type`.
        assert_eq!(
            event_code_from_filter("plugin_cap_denied"),
            Some(EVENT_TYPE_PLUGIN_CAP_DENIED)
        );
        assert_eq!(
            event_code_from_filter("PLUGIN_CAP_DENIED"),
            Some(EVENT_TYPE_PLUGIN_CAP_DENIED)
        );
        assert_eq!(event_code_from_filter("0xC7"), Some(0xC7));
        assert_eq!(event_code_from_filter("0xc7"), Some(0xC7));
        assert_eq!(event_code_from_filter("c7"), Some(0xC7));
        assert_eq!(event_code_from_filter("199"), Some(199)); // 0xC7 decimal
        assert_eq!(event_code_from_filter("not_a_real_type"), None);
        assert_eq!(event_code_from_filter(""), None);
    }

    #[test]
    fn council_transcript_is_0x66_in_council_band_and_durable() {
        // KF-01 full: pin the literal (operators bake `neoth wal show
        // --type 0x66` into runbooks) + confirm it sits in the council
        // band + is durable (an opted-in transcript is part of the
        // auditable record, must survive a crash).
        assert_eq!(EVENT_TYPE_COUNCIL_TRANSCRIPT, 0x66);
        assert!(
            (0x60..=0x6F).contains(&EVENT_TYPE_COUNCIL_TRANSCRIPT),
            "0x{:02X} escaped council band 0x60..=0x6F",
            EVENT_TYPE_COUNCIL_TRANSCRIPT
        );
        assert!(needs_immediate_sync(EVENT_TYPE_COUNCIL_TRANSCRIPT));
    }

    #[test]
    fn plugin_cap_audit_frames_are_durable() {
        // SC-04 / KF-09: the capability-audit frames (read-probe 0xC6,
        // refusal 0xC7) are security signals — NEOTH's audit wedge is a
        // complete, crash-survivable trail, so they MUST fsync, not
        // batch. `needs_immediate_sync` is a deny-list; these two are
        // (deliberately) NOT on it. This pins that decision so a future
        // "let's batch the high-volume read audit" change is a conscious
        // edit to this test, not a silent durability regression that
        // opens an audit hole exactly where a hostile plugin wants one.
        assert!(
            needs_immediate_sync(EVENT_TYPE_PLUGIN_CAP_USED),
            "0xC6 PLUGIN_CAP_USED MUST be immediate-sync (read-probe audit)"
        );
        assert!(
            needs_immediate_sync(EVENT_TYPE_PLUGIN_CAP_DENIED),
            "0xC7 PLUGIN_CAP_DENIED MUST be immediate-sync (refusal audit)"
        );
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

    /// SL-00(1c) — pin the literal so operator runbooks (`neoth wal show
    /// --type 0xEA`) and the send-side audit anchor stay stable. Also
    /// confirms the code sits in the full cluster band (0xE0..=0xEF) and
    /// is durable (the first outbound heartbeat per connection is an audit
    /// anchor — it must survive a crash).
    #[test]
    fn cluster_heartbeat_sent_is_0xea_in_cluster_band_and_durable() {
        assert_eq!(EVENT_TYPE_CLUSTER_HEARTBEAT_SENT, 0xEA);
        assert!(
            (0xE0..=0xEF).contains(&EVENT_TYPE_CLUSTER_HEARTBEAT_SENT),
            "CLUSTER_HEARTBEAT_SENT = 0x{:02X} escaped cluster band 0xE0..=0xEF",
            EVENT_TYPE_CLUSTER_HEARTBEAT_SENT,
        );
        assert!(
            needs_immediate_sync(EVENT_TYPE_CLUSTER_HEARTBEAT_SENT),
            "CLUSTER_HEARTBEAT_SENT MUST be immediate-sync (outbound heartbeat audit anchor)"
        );
    }

    #[test]
    fn cluster_task_accept_reject_are_0xeb_0xec_durable() {
        assert_eq!(EVENT_TYPE_CLUSTER_TASK_ACCEPTED, 0xEB);
        assert_eq!(EVENT_TYPE_CLUSTER_TASK_REJECTED, 0xEC);
        for code in [
            EVENT_TYPE_CLUSTER_TASK_ACCEPTED,
            EVENT_TYPE_CLUSTER_TASK_REJECTED,
        ] {
            assert!(
                (0xE0..=0xEF).contains(&code),
                "task event 0x{code:02X} escaped the cluster band"
            );
            assert!(
                needs_immediate_sync(code),
                "task accept/reject 0x{code:02X} MUST be immediate-sync (security audit anchor)"
            );
        }
        assert_ne!(
            EVENT_TYPE_CLUSTER_TASK_ACCEPTED, EVENT_TYPE_CLUSTER_TASK_REJECTED,
            "accept and reject must be distinct codes"
        );
    }

    /// GOLD-ADOPT-04: pin the literals so operator runbooks (`neoth wal show
    /// --type 0x5A`) stay stable, and assert the durability contract:
    /// HIT is batchable (high-cadence, re-derivable from the HTTP response);
    /// STALE is immediate-sync (structural-change audit anchor must survive a crash).
    #[test]
    fn web_extract_codes_literal_and_durability() {
        assert_eq!(EVENT_TYPE_WEB_EXTRACT_HIT, 0x59);
        assert_eq!(EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE, 0x5A);
        // HIT is batchable.
        assert!(
            !needs_immediate_sync(EVENT_TYPE_WEB_EXTRACT_HIT),
            "0x59 WEB_EXTRACT_HIT must be batchable"
        );
        // STALE is a structural-change audit anchor — must survive a crash.
        assert!(
            needs_immediate_sync(EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE),
            "0x5A WEB_EXTRACT_SELECTOR_STALE MUST be immediate-sync"
        );
    }

    #[test]
    fn cluster_gossip_codes_are_0xed_0xee_0xef_batchable() {
        assert_eq!(EVENT_TYPE_CLUSTER_GOSSIP_SENT, 0xED);
        assert_eq!(EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED, 0xEE);
        assert_eq!(EVENT_TYPE_CLUSTER_GOSSIP_DROPPED, 0xEF);
        for code in [
            EVENT_TYPE_CLUSTER_GOSSIP_SENT,
            EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED,
            EVENT_TYPE_CLUSTER_GOSSIP_DROPPED,
        ] {
            assert!(
                (0xE0..=0xEF).contains(&code),
                "gossip 0x{code:02X} in cluster band"
            );
            // High-cadence + re-derivable ⇒ batchable, NOT immediate-sync.
            assert!(
                !needs_immediate_sync(code),
                "gossip diagnostic 0x{code:02X} must be batchable"
            );
        }
    }

    #[test]
    fn channel_send_codes_are_0x67_0x68_distinct_durable_and_in_band() {
        // SC-SEND (Session 39): dedicated channel-send governance events.
        // Pin the literals (operators bake `neoth wal show --type channel_send`
        // into runbooks) + confirm they replace, not collide with, the generic
        // codes they used to reuse.
        assert_eq!(EVENT_TYPE_CHANNEL_SEND, 0x67);
        assert_eq!(EVENT_TYPE_CHANNEL_SEND_DENIED, 0x68);
        assert_ne!(EVENT_TYPE_CHANNEL_SEND, EVENT_TYPE_CHANNEL_SEND_DENIED);
        for code in [EVENT_TYPE_CHANNEL_SEND, EVENT_TYPE_CHANNEL_SEND_DENIED] {
            assert!(
                (0x60..=0x6F).contains(&code),
                "0x{code:02X} escaped the operator-decision band 0x60..=0x6F"
            );
            // Governance audit anchors — durability-critical, never batched.
            assert!(
                needs_immediate_sync(code),
                "0x{code:02X} must be immediate-sync"
            );
        }
        // Distinct from the generic codes they replace.
        assert_ne!(EVENT_TYPE_CHANNEL_SEND, EVENT_TYPE_CHANNEL_EGRESS);
        assert_ne!(EVENT_TYPE_CHANNEL_SEND_DENIED, EVENT_TYPE_PERMISSION_DENIED);
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
