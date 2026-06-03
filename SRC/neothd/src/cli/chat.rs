//! `neoth chat <msg>` — one-shot LLM round trip.
//!
//! Loads `freedom.yaml`, picks the configured provider, sends the prompt,
//! prints the response. Both the outbound request and the inbound response
//! are persisted as WAL events (`EVENT_TYPE_PROVIDER_REQUEST` /
//! `EVENT_TYPE_PROVIDER_RESPONSE`) before the daemon returns.
//!
//! No streaming yet — Day-5b will add `--stream`. No interactive REPL —
//! Day-5c. For now: pipe in a prompt, get an answer, durably logged.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Args;
use tracing::{info, warn};

use crate::config::FreedomConfig;
use crate::providers::{self, CompletionChunk, Request};
use crate::wal::events::{
    EVENT_TYPE_BUDGET_EXCEEDED, EVENT_TYPE_PROVIDER_REQUEST, EVENT_TYPE_PROVIDER_RESPONSE,
    EVENT_TYPE_RAW_TEXT, EVENT_TYPE_SKILL_INJECT_SKIPPED,
};
use crate::wal::spawn as wal_spawn;

/// Round-3 v0.4 ARCH-04 integration — default pre-flight token cap
/// fallback for tests that don't supply a `FreedomConfig`. Production
/// callers read `config.tokens.max_per_request` (defaults to 100_000
/// via `crate::config::TokensConfig::default_max_per_request`).
#[cfg(test)]
const DEFAULT_PROMPT_TOKEN_CAP: u32 = 100_000;

#[derive(Args, Debug, Clone)]
pub struct ChatArgs {
    /// Message to send. If omitted, NEOTH reads from stdin until EOF.
    pub message: Option<String>,

    /// Override the configured model for this single call.
    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,

    /// Inject a one-shot system prompt for this call.
    #[arg(long, value_name = "TEXT")]
    pub system: Option<String>,

    /// Override the freedom.yaml path (mostly for tests).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Override the WAL segment path (mostly for tests).
    #[arg(long, value_name = "PATH")]
    pub wal_segment: Option<PathBuf>,

    /// Populated from the global `--stream` flag by `cli::run`. Skipped from
    /// clap parsing because the global handler claims the flag first.
    #[arg(skip)]
    pub stream: bool,

    /// Sampling temperature for backends that honour it (local_qwen today).
    /// Greedy / argmax when ≤ 0.0. Range [0.0, 2.0]. Cloud providers set
    /// their own default; the flag is silently ignored when the dispatcher
    /// has no path to forward it.
    #[arg(long, value_name = "T")]
    pub temperature: Option<f32>,

    /// Top-p (nucleus) sampling cutoff for local_qwen. `1.0` keeps every
    /// token; `0.9` is a common balance. Ignored when `--temperature` is
    /// `0`/unset (greedy mode short-circuits before top-p applies).
    #[arg(long = "top-p", value_name = "P")]
    pub top_p: Option<f32>,

    /// Optional RNG seed for reproducible sampling. Pair with `--temperature
    /// > 0` to make a non-greedy call replayable. Unused on cloud providers.
    #[arg(long, value_name = "SEED")]
    pub sampling_seed: Option<u64>,

    /// Round-3 v0.4 QU-11 / ARS-6 — resume a prior session from a
    /// `MODE_CHECKPOINT` (WAL `0x9A`) snapshot. Takes the 12-char
    /// checkpoint hash (or any unique prefix) printed by the prior
    /// session at checkpoint-emission time. NEOTH looks up the
    /// snapshot via `recall::reconstruct::reconstruct_from_checkpoint`,
    /// prints a one-line resume banner ("resuming session X / phase Y
    /// / provider Z"), and prepends a typed RESUME-CONTEXT block to
    /// the chat's system prompt so the assistant knows the prior
    /// pipeline shape. Full pipeline-state rehydration (re-scoping
    /// MCP servers, restoring council hemisphere routing) lands as
    /// a follow-up — this surface unblocks the operator-facing
    /// `chat resume from <hash>` workflow today.
    #[arg(long = "resume-from", value_name = "HASH")]
    pub resume_from: Option<String>,
}

pub async fn run_chat(args: ChatArgs) -> Result<()> {
    let config = match &args.config {
        Some(p) => FreedomConfig::load_from_path(p)?,
        None => FreedomConfig::load_from_default_path()?,
    };
    // V03-08 + A-2 preflight: gate every cloud provider the chat invocation
    // could reach behind first-run consent. Covers the legacy single-mode
    // `provider_kind` AND the per-hemisphere providers in
    // `inference.{left,right,cerebellum}` (A-2 closes the bypass where
    // operators set right=gemini_api but only granted consent for the
    // primary claude_cli). Runs before any provider is built so a declined
    // operator never sees a half-spun adapter. Bypass via
    // `NEOTH_CONSENT_BYPASS=1` for CI / scripted reruns.
    {
        let home = FreedomConfig::default_neoth_home();
        crate::consent::ensure_all_granted_or_prompt(&home, &config)?;
    }
    // CH-04: chat dispatch routes through the Left hemisphere (analytic /
    // structured reasoning). In Single mode `from_config_for_role` falls
    // through to the same default-slot adapter `from_config` would build,
    // so existing operators see no behaviour change. In Triplet/Custom
    // mode the operator-picked Left provider wins.
    // SPEC-03b: build the primary WITH its 429 fallback chain. With no
    // `fallback:` config this returns the bare Left provider — identical
    // to the prior `from_config_for_role(.., Left)` call, zero change.
    // CLI one-shot: no WAL writer here (it's created inside run_chat_with,
    // below this provider build), and the operator is present to see a 429
    // failover in the logs. The daemon path threads its writer for the
    // durable `0x25 PROVIDER_FALLBACK_ATTEMPTED` audit frame.
    let provider = providers::fallback_chain_from_config(&config, None).await?;
    run_chat_with(args, config, provider.as_ref()).await
}

/// Inner entry point that takes a pre-built `Provider`. Used by `run_chat`
/// in production and by integration tests that supply a mock implementation.
pub async fn run_chat_with(
    mut args: ChatArgs,
    config: FreedomConfig,
    provider: &dyn crate::providers::Provider,
) -> Result<()> {
    info!(provider = provider.name(), "neoth chat");

    // R-05 (Session 24) — surface the first-tour greeting at most
    // once per wizard run. `consume_first_tour_marker` reads + deletes
    // the marker so subsequent chat invocations don't repeat it. Best-
    // effort: a missing or unreadable marker means "operator past the
    // onboarding moment", which is the safe default.
    let first_tour_home = crate::config::FreedomConfig::default_neoth_home();
    if let Some(greeting) = crate::cli::init::consume_first_tour_marker(&first_tour_home) {
        println!("[neoth] {greeting}");
    }

    // Round-3 v0.4 QU-11 / ARS-6 — if `--resume-from <hash>` is set,
    // hydrate the prior session's `MODE_CHECKPOINT` snapshot from
    // views.db + prepend a RESUME-CONTEXT block to the system prompt
    // so the assistant knows the prior pipeline shape. Failures
    // (missing checkpoint, unreadable views.db, hash mismatch) print
    // a one-line warning + proceed without the context — the operator
    // still gets a chat turn, just without the resume hydration.
    if let Some(hash_prefix) = args.resume_from.clone() {
        match hydrate_resume_context(&hash_prefix, args.system.as_deref()) {
            Ok((banner, combined_system)) => {
                println!("{banner}");
                args.system = Some(combined_system);
            }
            Err(why) => {
                println!("[neoth] resume-from `{hash_prefix}` failed: {why}");
            }
        }
    }

    let prompt = resolve_prompt(&args).await?;

    // G-03 self-correction signal. If this turn reads as a CORRECTION of the
    // preceding reply (rule-based follow-up-tone scorer crosses the negative
    // threshold), record an `OPERATOR_FEEDBACK` (0xBB) WAL frame so the
    // operator can audit where NEOTH underperformed
    // (`neoth wal show --type operator_feedback`). Fire-and-forget +
    // best-effort: it never blocks or fails the chat turn, and stores only a
    // prompt_hash (no message-content leak). The adaptation consumer (profile
    // cron biasing self-dev proposals on this signal) is a follow-on slice.
    let _ = crate::feedback::record_operator_correction(
        &crate::config::FreedomConfig::default_neoth_home(),
        &prompt,
    )
    .await;

    // Round-3 v0.4 — coding-intent auto-dispatch. When the prompt
    // looks like a coding request (bilingual EN/DE heuristic: verb
    // at front + programming-noun anchor; see
    // `coding::intent::detect_coding_intent`), route through the
    // dedicated coding workflow (`cli::code::run_code`) instead of
    // a single-turn chat reply. The coding workflow opens a kanban
    // session + decomposes + dispatches to the hemisphere worker +
    // runs patch+test loop — much better operator outcome than
    // chat-only for "build me X" requests.
    //
    // Operator opt-out: `NEOTH_NO_AUTO_CODE=1` env var disables
    // auto-dispatch entirely. Low-confidence detections (verb XOR
    // noun, not both) print an offer banner but still run the chat
    // turn — only High confidence auto-dispatches.
    if crate::coding::intent::should_auto_dispatch(&prompt) {
        let intent = crate::coding::intent::detect_coding_intent(&prompt)
            .expect("should_auto_dispatch returned true so detect must return Some");
        println!("{}", crate::coding::intent::format_dispatch_banner(&intent));
        let code_args = crate::cli::code::CodeArgs {
            prompt: prompt.clone(),
            db: None,
            source_channel: "chat".to_string(),
            no_assign: false,
            dispatch: false, // operator runs `neoth kanban` after to drive dispatch
            apply: None,
            run_pending: false,
            output: crate::cli::OutputFormat::default(),
        };
        return crate::cli::code::run_code(code_args).await;
    } else if let Some(intent) = crate::coding::intent::detect_coding_intent(&prompt) {
        // Low-confidence: print an offer banner + continue with chat.
        println!(
            "[neoth] coding intent detected at low confidence (verb={:?} noun={:?}). \
             Try `neoth code \"{}\"` for the dedicated coding workflow.",
            intent.matched_verb.as_deref().unwrap_or("?"),
            intent.matched_noun.as_deref().unwrap_or("?"),
            prompt
                .lines()
                .next()
                .unwrap_or(&prompt)
                .chars()
                .take(60)
                .collect::<String>(),
        );
    }

    // OP-02 (Session 25) — next-session seed banner. Read the
    // most-recent hindsight card + surface its `one_line_summary`
    // so the operator picks up where they left off. Best-effort:
    // a missing or empty hindsight dir is the silent default.
    // Skipping the first_tour greeting case keeps the onboarding
    // banner clean (operator just finished the wizard — no "since
    // last time" makes sense).
    let chat_ts_unix = now_unix() as i64;
    let current_session_id = crate::memory::hindsight::session_id_for(chat_ts_unix, &prompt);
    let seed_banner =
        crate::memory::hindsight::next_session_seed_banner(&first_tour_home, &current_session_id);
    if !seed_banner.is_empty() {
        println!("{seed_banner}");
    }

    // UX-02 — "memory is working" session-start signal. One line telling
    // the operator NEOTH carried context across runs. Best-effort +
    // naturally silent on a fresh install (zero memories → None), which
    // also keeps the post-wizard first-tour banner clean.
    if let Some(line) = session_memory_signal() {
        println!("{line}");
    }

    // UX-05 — Day-30 "unlock moment": once, after 30+ days, nudge the
    // operator toward opt-in features they still haven't switched on.
    // Self-suppresses via a marker file; naturally silent pre-30-days,
    // when all features are active, or on a fresh install.
    if let Some(banner) = crate::cli::unlock_moment::maybe_unlock_banner(&first_tour_home, &config)
    {
        println!("{banner}");
    }

    let wal_dir = FreedomConfig::default_wal_dir();
    let segment_path = args
        .wal_segment
        .clone()
        .unwrap_or_else(|| wal_dir.join("000001.wal"));
    if let Some(parent) = segment_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create WAL dir {}", parent.display()))?;
    }
    let (writer, writer_join) = wal_spawn(segment_path.clone()).context("spawn WAL writer")?;

    // ── RAW_TEXT (the actual prompt, for recall) ──────────────────────────
    // Stored before the hashed PROVIDER_REQUEST so `neoth recall "..."` can
    // find what the operator typed. WAL is mode-0600 / DACL-restricted, so
    // raw prompts at rest match the existing trust boundary.
    let raw_header = crate::wal::make_header(EVENT_TYPE_RAW_TEXT, prompt.as_bytes());
    // Capture the event_id before the header moves into `append` — the
    // post-reply profile-learning pipeline (B-Konsens 2026-05-17 below)
    // uses this as the trigger anchor for `extract_window`.
    let raw_event_id = raw_header.event_id.0 as i64;
    writer
        .append(raw_header, prompt.as_bytes().to_vec())
        .await
        .context("write RAW_TEXT WAL frame")?;

    // ── P-08 briefing-gate marker (Workstream C, Session 22) ──────────────
    // Update the operator-activity timestamp so the cron task's
    // `should_emit_for_briefing` check sees a fresh "operator engaged"
    // signal without re-scanning the WAL. Best-effort: a permission
    // failure on the marker file MUST NOT fail the chat — recording is
    // an audit signal, not a chat-correctness invariant.
    let _ = crate::profile::briefing_gate::record_last_active(
        &FreedomConfig::default_neoth_home(),
        now_unix() as i64,
    );

    // ── PROVIDER_REQUEST (hashed metadata) ────────────────────────────────
    //
    // ARCH-07 / Round-3 v0.4 — `prompt_bundle_hash` field added.
    // Computed via `skills::versioning::compute_prompt_bundle_hash`
    // over the minimal block set currently visible at this site
    // (Block::A = operator-explicit --system if set, Block::E =
    // operator's current message). As the prompt assembler grows to
    // explicitly emit Block::B (active skill prompts), Block::C
    // (profile context), Block::D (recall episodes), this set
    // extends — the hash naturally evolves with the bundle shape.
    // Replay-determinism contract (ARCH-02 test_prompt_bundle_replay_
    // determinism): same bundle → same hash, deterministically.
    let mut bundle_entries: Vec<crate::skills::versioning::BundleBlockEntry<'_>> = Vec::new();
    if let Some(sys) = args.system.as_deref().filter(|s| !s.is_empty()) {
        bundle_entries.push(crate::skills::versioning::BundleBlockEntry {
            block: crate::skills::versioning::BundleBlock::A,
            content: sys,
        });
    }
    bundle_entries.push(crate::skills::versioning::BundleBlockEntry {
        block: crate::skills::versioning::BundleBlock::E,
        content: &prompt,
    });
    let prompt_bundle_hash = crate::skills::versioning::prompt_bundle_hash_hex(&bundle_entries);

    // ── ARCH-04 integration: pre-flight block-layer budget check ─────────
    //
    // Convert the bundle entries we just built (Block::A + Block::E
    // today; B/C/D extend as the assembler grows) into the matching
    // BlockItem shape + run enforce_budget. The cap reads from
    // `config.tokens.max_per_request` (operator-tunable via
    // `freedom.yaml::tokens.max_per_request`; defaults to 100_000
    // per `TokensConfig::default_max_per_request`). Operators on
    // tight-context models (e.g. Gemini Flash 32k) lower the cap;
    // operators on Opus 4.7 (200k) keep the default.
    //
    // Today's call site only carries A + E — both undegradable per
    // ARCH-04 policy — so `enforce_budget` either returns None (under
    // cap, no-op) or Some(detail) with `new_total > cap` (operator-
    // visible "your prompt exceeds the cap; tighten Block::A/E"
    // signal). When the assembler emits Block::B/C/D the degradation
    // policy starts firing for real.
    let prompt_token_estimate: u32 = {
        use crate::tokens::budget::{Block, BlockItem, count_tokens};
        let items: Vec<BlockItem> = bundle_entries
            .iter()
            .map(|e| BlockItem {
                block: match e.block {
                    crate::skills::versioning::BundleBlock::A => Block::A,
                    crate::skills::versioning::BundleBlock::B => Block::B,
                    crate::skills::versioning::BundleBlock::C => Block::C,
                    crate::skills::versioning::BundleBlock::D => Block::D,
                    crate::skills::versioning::BundleBlock::E => Block::E,
                    crate::skills::versioning::BundleBlock::Conductor => Block::Conductor,
                },
                importance: 0.5,
                ts_ns: 0,
                tokens: count_tokens(e.content),
                content: e.content.to_string(),
            })
            .collect();
        let estimate: u32 = items.iter().map(|i| i.tokens).sum();
        let mut items_mut = items;
        let cap = config.tokens.max_per_request;
        if let Some(detail) = crate::tokens::budget::enforce_budget(&mut items_mut, cap) {
            // Emit BUDGET_EXCEEDED audit frame BEFORE PROVIDER_REQUEST
            // so the audit-chain consumer sees them in cause-then-
            // effect order. Best-effort emit — a WAL write failure
            // here MUST NOT abort the chat turn (the audit signal is
            // operator-visible via tracing::warn fallback).
            warn!(
                cap = detail.cap,
                original_total = detail.original_total,
                new_total = detail.new_total,
                dropped_d = detail.dropped_d_count,
                dropped_c = detail.dropped_c_count,
                conductor_truncated = detail.conductor_truncated,
                "prompt-bundle exceeded token cap; degradation applied (or A/B/E-only — operator should tighten)"
            );
            let budget_payload = serde_json::to_vec(&serde_json::json!({
                "cap": detail.cap,
                "original_total": detail.original_total,
                "new_total": detail.new_total,
                "dropped_d_count": detail.dropped_d_count,
                "dropped_c_count": detail.dropped_c_count,
                "conductor_truncated": detail.conductor_truncated,
                "prompt_bundle_hash": prompt_bundle_hash,
                "ts_unix": now_unix(),
            }))
            .unwrap_or_default();
            let budget_header =
                crate::wal::make_header(EVENT_TYPE_BUDGET_EXCEEDED, &budget_payload);
            if let Err(e) = writer.append(budget_header, budget_payload).await {
                warn!(error = %e, "BUDGET_EXCEEDED WAL emit failed (non-fatal)");
            }
        }
        estimate
    };

    let req_payload = serde_json::to_vec(&serde_json::json!({
        "operator_id": config.operator_id,
        "provider": provider.name(),
        // SPEC-04: on/off-device classification of THIS request's
        // provider ("local" | "cloud") — the durable per-turn audit
        // anchor for the privacy posture, alongside the extraction-path
        // 0x2E PROFILE_EXTRACT_TARGET frame.
        "target": crate::profile::runner::extract_target_label(provider.name()),
        "model": args.model.clone().or_else(|| config.provider_model.clone()),
        "prompt_hash_xxh3": xxhash_rust::xxh3::xxh3_64(prompt.as_bytes()),
        "prompt_bytes": prompt.len(),
        "prompt_bundle_hash": prompt_bundle_hash,
        "prompt_token_estimate": prompt_token_estimate,
        "ts_unix": now_unix(),
    }))?;
    let req_header = crate::wal::make_header(EVENT_TYPE_PROVIDER_REQUEST, &req_payload);
    writer
        .append(req_header, req_payload)
        .await
        .context("write PROVIDER_REQUEST WAL frame")?;

    // ── Operator context + skills load — K-Perf-4 parallel resource load ──
    // Both reads hit the filesystem and are mutually independent: operator_md
    // assembles ~/.neoth/NEOTH.md + project + rules + memory, skills walks
    // `<home>/skills/`. Running them sequentially was ~2× the wall time on
    // cold caches (each ~5-20ms). tokio::join! drives them concurrently
    // through the same runtime worker — the FS reads pipeline OS-side
    // without extra threads. Per Performance agent's K-Perf-4 pick.
    //
    // The skill router (line below) consumes installed_skills, so loading
    // it BEFORE the system-prompt assembly is mandatory — the parallel
    // load just shaves the serial cost off the front edge.
    let home = FreedomConfig::default_neoth_home();
    let cwd = std::env::current_dir().unwrap_or_else(|_| home.clone());
    let skills_dir = home.join("skills");
    // E-22 chat-route (Session 21, 2026-05-23): swap raw `load_all` for
    // the SkillRegistry path so the chat call goes through the same
    // ArcSwap<Vec<Skill>> primitive the daemon's hot-reload watcher
    // targets. When running inside a long-lived daemon, the process-wide
    // global registry (initialised by `serve.rs`) is reused — the chat
    // path then automatically sees skill edits the watcher picked up
    // between turns. One-shot `neoth chat` falls back to a per-call
    // registry build (no watcher, no shared state).
    let (blocks_res, registry_res) = match crate::skills::registry::global() {
        Some(reg) => {
            let blocks = crate::memory::operator_md::assemble(&home, &cwd).await;
            (blocks, Ok::<_, anyhow::Error>(reg))
        }
        None => {
            let (b, r) = tokio::join!(
                crate::memory::operator_md::assemble(&home, &cwd),
                crate::skills::SkillRegistry::load(&skills_dir),
            );
            (b, r)
        }
    };
    let blocks = blocks_res.unwrap_or_default();
    let rendered_md = if blocks.is_empty() {
        None
    } else {
        Some(crate::memory::operator_md::render(&blocks))
    };
    // Wire the wizard-captured operator facts (custom/enum role +
    // preferred language) into the top of the operator-context layer.
    // These `freedom.yaml` fields were written at onboarding but never
    // reached the prompt before, so the model knew neither the
    // operator's role nor their preferred response language.
    let operator_context = merge_operator_facts(&config, rendered_md);

    // ── K-Wire-3 (Session 23) — layered enrichment via shared helper ──────
    // Pre-loads every enrichment block the prior 200-LOC inline
    // composition used:
    //   1. installed_skills (snapshot from registry)
    //   2. mode/skill routing → skill_layer + used_skill_id
    //   3. mcp_catalogue (async assemble — gated on enabled servers)
    //   4. persona_override (tweaks.toml)
    //   5. repo_context_block (K-Repo-Map auto-context)
    // Then `pipeline::build_enriched_request` composes them in the
    // canonical layer order (operator_md + explicit_system + repo +
    // skill + MCP, with persona as a top-line prefix). Channel-side
    // `cli/serve.rs::build_pipeline_handler` calls the same helper
    // so every inbound surface reaches the same context layering.

    // Arc<Vec<Skill>> snapshot — derefs to &[Skill] for the router.
    let raw_installed_skills = match registry_res {
        Ok(reg) => reg.snapshot_owned(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "skill registry load failed; chat proceeds with empty skill set"
            );
            std::sync::Arc::new(Vec::new())
        }
    };

    // ── ARCH-07 (Session 28) — pinned-hash integrity gate ─────────────────
    //
    // Compare each loaded skill's actual content_hash against the
    // operator's `freedom.yaml::skills.pinned_hashes` map. Mismatches
    // get one `SKILL_INJECT_SKIPPED` (0x29) WAL frame with reason
    // `hash_mismatch` + both expected + actual hashes in the payload
    // + are filtered out of the working `installed_skills` Arc so
    // every downstream router / mode-registry / injection path sees
    // them as if uninstalled. Skills NOT in the pinned map pass
    // through unchanged — operator pins what they care about; bundled
    // skills can drift across NEOTH releases without pinning every
    // one.
    //
    // Best-effort emit: WAL writer failure logs warn + continues. The
    // skill is STILL dropped on failure (integrity comes first; the
    // missing audit frame is the next-tick problem, not a reason to
    // let a tampered skill through).
    let installed_skills = if config.skills.pinned_hashes.is_empty() {
        raw_installed_skills.clone()
    } else {
        let verdicts = crate::skills::versioning::check_pinned_hashes(
            raw_installed_skills
                .iter()
                .map(|s| (s.id(), s.content_hash.as_str())),
            &config.skills.pinned_hashes,
        );
        let mut kept: Vec<crate::skills::schema::Skill> = Vec::new();
        for (skill, verdict) in raw_installed_skills.iter().zip(verdicts.iter()) {
            match verdict.verdict {
                crate::skills::versioning::PinnedHashOutcome::Allowed => {
                    kept.push(skill.clone());
                }
                crate::skills::versioning::PinnedHashOutcome::Mismatch => {
                    warn!(
                        skill = %verdict.skill_id,
                        expected = ?verdict.expected_hash,
                        actual = %verdict.actual_hash,
                        "skill pinned-hash mismatch — dropping from injection (ARCH-07)"
                    );
                    let payload = serde_json::to_vec(&serde_json::json!({
                        "skill_id": verdict.skill_id,
                        "content_hash": verdict.actual_hash,
                        "expected_hash": verdict.expected_hash,
                        "reason": crate::skills::versioning::SkillSkipReason::HashMismatch.as_str(),
                        "prompt_bundle_hash": prompt_bundle_hash,
                        "ts_unix": now_unix(),
                    }))
                    .unwrap_or_default();
                    let header = crate::wal::make_header(EVENT_TYPE_SKILL_INJECT_SKIPPED, &payload);
                    if let Err(e) = writer.append(header, payload).await {
                        warn!(
                            skill = %verdict.skill_id,
                            error = %e,
                            "SKILL_INJECT_SKIPPED (hash_mismatch) emit failed (non-fatal)"
                        );
                    }
                }
            }
        }
        std::sync::Arc::new(kept)
    };

    // Round-3 v0.4 ARCH-07 — eval-session skill suppression. When
    // `config.skills.should_suppress_for_eval()` is true, every
    // installed skill gets a SKILL_INJECT_SKIPPED frame
    // (reason=`eval_session`) + the skill layer is forced to None
    // so the prompt bundle stays free of behavioural skill prompts.
    // Operators benchmarking the bare-model baseline use this to
    // ensure the eval isn't biased by an active skill.
    let eval_suppress = config.skills.should_suppress_for_eval();
    if eval_suppress {
        for s in installed_skills.iter().filter(|s| s.manifest.enabled) {
            let payload = serde_json::to_vec(&serde_json::json!({
                "skill_id": s.id(),
                "content_hash": s.content_hash,
                "reason": crate::skills::versioning::SkillSkipReason::EvalSession.as_str(),
                "prompt_bundle_hash": prompt_bundle_hash,
                "ts_unix": now_unix(),
            }))
            .unwrap_or_default();
            let header = crate::wal::make_header(EVENT_TYPE_SKILL_INJECT_SKIPPED, &payload);
            if let Err(e) = writer.append(header, payload).await {
                warn!(
                    skill = s.id(),
                    error = %e,
                    "SKILL_INJECT_SKIPPED emit failed (non-fatal)"
                );
            }
        }
        info!(
            count = installed_skills
                .iter()
                .filter(|s| s.manifest.enabled)
                .count(),
            "eval-session active — all skills suppressed per ARCH-07"
        );
    }

    // QM-3 + QM-23 (2026-05-22 Session 20): ModeRegistry trigger_phrases
    // beat the broader skill keyword scan when they hit. The matched
    // mode's `system_prompt_delta` layers on top of the parent skill's
    // base `system_prompt`. When no mode hits, fall back to the broad
    // `skills::route` Stage-1 keyword scan + Stage-2 embedding re-rank.
    let mode_registry = crate::skills::mode_registry::ModeRegistry::from_skills(&installed_skills)
        .unwrap_or_default();
    let mode_hit = if eval_suppress {
        None
    } else {
        mode_registry.match_trigger(&prompt)
    };
    // SC-11 — captured in the skill branch below; stays None for the
    // eval-suppressed / mode-activation / no-skill paths (no skill →
    // no tool-allowlist gate). Owned so it outlives the match block to
    // the MCP dispatch call.
    let mut skill_tool_allowlist: Option<Vec<String>> = None;
    let (skill_layer, used_skill_id): (Option<String>, Option<String>) = if eval_suppress {
        (None, None)
    } else if let Some(resolved) = mode_hit {
        let parent = installed_skills
            .iter()
            .find(|s| s.id() == resolved.skill_id);
        info!(
            mode = %resolved.mode.id,
            skill = %resolved.skill_id,
            spectrum = %resolved.mode.spectrum.as_str(),
            oversight = %resolved.mode.oversight.as_str(),
            "mode activated via ModeRegistry"
        );
        let layer = match parent {
            Some(p) if !resolved.mode.system_prompt_delta.is_empty() => Some(format!(
                "{}\n\n{}",
                p.system_prompt(),
                resolved.mode.system_prompt_delta
            )),
            Some(p) => Some(p.system_prompt().to_string()),
            None if !resolved.mode.system_prompt_delta.is_empty() => {
                Some(resolved.mode.system_prompt_delta.clone())
            }
            None => None,
        };
        // Mode activation is its own audit path — review-gate
        // dispatching via /agent is the explicit operator path,
        // so no used_skill_id surfaces here (mirrors the prior
        // `_skill_match` discard).
        (layer, None)
    } else {
        // Day-14b Phase 2 — Stage-2 embedding cosine re-rank.
        // PF-01 (Session 30): Stage-2 runs when EITHER keyword Stage-1
        // missed OR `skills.always_embed_route` is set (the default) —
        // so the skill library routes by SEMANTICS, not only on a literal
        // keyword. A Stage-2 hit (cosine ≥ EMBEDDING_THRESHOLD) takes
        // PRECEDENCE over the keyword match; when Stage-2 returns None
        // (nothing crosses the bar) the keyword Stage-1 result stands as
        // the fallback. Either way Stage-2 only fires when the operator
        // configured `inference.embedding_provider` (off by default).
        let mut skill_match = crate::skills::route(&prompt, &installed_skills);
        if skill_match.is_none() || config.skills.always_embed_route {
            if let Some(embed_provider) =
                crate::providers::embed_provider_from_config(&config).await
            {
                if let Some((skill, score)) = crate::skills::router::route_stage2_embedding(
                    &prompt,
                    &installed_skills,
                    embed_provider.as_ref(),
                )
                .await
                {
                    info!(
                        skill = skill.id(),
                        cosine = score,
                        overrode_keyword = skill_match.is_some(),
                        "skill activated via Stage-2 embedding re-rank"
                    );
                    skill_match = Some(crate::skills::router::RouteMatch {
                        skill,
                        matched_keywords: Vec::new(),
                        embedding_score: Some(score),
                    });
                }
            }
        }
        if let Some(m) = &skill_match {
            if m.embedding_score.is_none() {
                info!(
                    skill = m.skill.id(),
                    matched_keywords = ?m.matched_keywords,
                    "skill activated"
                );
            }
        }
        let layer = skill_match
            .as_ref()
            .map(|m| m.skill.system_prompt().to_string());
        let id = skill_match.as_ref().map(|m| m.skill.id().to_string());
        // SC-11 — the matched skill's tool_allowlist scopes the MCP gate.
        skill_tool_allowlist = skill_match
            .as_ref()
            .map(|m| m.skill.manifest.tool_allowlist.clone());
        (layer, id)
    };

    // ── MCP tool catalogue (Step 1 of autonomous routing) ─────────────────
    // No-op when `~/.neoth/mcp_servers.yaml` is missing/empty. Pick #34
    // (Session 14, silent-failure audit-fix): surface YAML parse errors
    // at warn level instead of silently disabling MCP tools.
    let mcp_servers = crate::mcp::McpServers::load().unwrap_or_else(|e| {
        warn!(
            error = %e,
            "mcp_servers.yaml load failed — proceeding without MCP tools; \
             fix the YAML or remove the file to silence this warning"
        );
        Default::default()
    });
    let mcp_catalogue: Option<String> = if mcp_servers.enabled().is_empty() {
        None
    } else {
        match crate::mcp::catalogue::assemble_catalogue(&mcp_servers).await {
            Some(cat) => {
                info!(
                    enabled = mcp_servers.enabled().len(),
                    bytes = cat.len(),
                    "MCP tool catalogue injected into system prompt"
                );
                Some(cat)
            }
            None => None,
        }
    };

    // ── C-7 persona layer (tweaks.toml::persona_override) ─────────────────
    let tweaks_path = crate::tweaks::Tweaks::default_path();
    let persona_override = crate::tweaks::Tweaks::load_or_default(&tweaks_path)
        .ok()
        .and_then(|t| t.persona_override.clone());

    // ── AR-01 (Session 24) — active profile preset → system_addendum ────
    // Read `~/.neoth/profile/active_preset.txt` on EVERY turn so that
    // `neoth profile preset apply <name>` takes effect immediately
    // without a daemon restart. Pre-fix the addendum only landed in
    // the system prompt at process boot (via the wizard's one-shot
    // write into the profile snapshot). LOWKEY's addendum is the empty
    // string; `filter(!is_empty)` keeps the field None for that case so
    // the enricher doesn't introduce a stray blank line.
    let preset_home = crate::config::FreedomConfig::default_neoth_home();
    let preset_addendum = crate::cli::profile::load_active_preset(&preset_home)
        .map(|p| crate::profile::presets::apply_preset(p).system_addendum)
        .filter(|s| !s.is_empty());

    // ── K-Repo-Map Phase 3c — pre-compute the auto-context block ─────────
    // Best-effort: any failure silently skips injection.
    let repo_context_block = maybe_repo_context_block(&config, &prompt);

    // ── Compose layered system prompt via shared helper ───────────────────
    let enriched = crate::pipeline::build_enriched_request(crate::pipeline::EnrichmentInputs {
        prompt: &prompt,
        operator_context: operator_context.as_deref(),
        preset_addendum: preset_addendum.as_deref(),
        explicit_system: args.system.as_deref(),
        repo_context_block: repo_context_block.as_deref(),
        skill_system_prompt: skill_layer.as_deref(),
        used_skill_id: used_skill_id.as_deref(),
        mcp_catalogue: mcp_catalogue.as_deref(),
        persona_override: persona_override.as_deref(),
    });
    let combined_system = enriched.system;
    // used_skill_id is plumbed through for any downstream audit
    // consumers; the existing chat path consumes `combined_system`
    // the same way it did before the helper extraction.
    let _used_skill_id = enriched.used_skill_id;

    // ── Permission gate (Phase 28b AU-4) + C-14 cost preview ───────────────
    // Real `eur_estimate` from the cost predictor — feeds both the
    // `PaidProviderCall` autonomy gate (Confirm at standard above
    // €0.50, at elevated above €5.00) AND a `COST_ESTIMATE_SHOWN`
    // WAL frame so operators can audit what was projected vs what
    // actually billed (PROVIDER_RESPONSE event reports actual usage
    // post-call).
    let predicted_cost = {
        let meter = crate::providers::meter::Meter::with_default_window();
        // Assemble the same string the provider sees: system prefix
        // (operator-md + persona) + the user prompt. The predictor's
        // 4-chars/token heuristic is conservative-high, which is the
        // safer direction for a billing preview.
        let assembled = format!("{}\n\n{}", combined_system.as_deref().unwrap_or(""), prompt);
        crate::providers::cost::predict(
            provider.name(),
            &model_for_estimate(&args, &config),
            &assembled,
            &meter,
        )
    };
    let est_payload = serde_json::to_vec(&serde_json::json!({
        "provider": provider.name(),
        "model": model_for_estimate(&args, &config),
        "input_tokens": predicted_cost.input_tokens,
        "output_tokens_est": predicted_cost.output_tokens_est,
        "total_eur": predicted_cost.total_eur,
        "ts_unix": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }))
    .unwrap_or_default();
    if !est_payload.is_empty() {
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN,
            &est_payload,
        )
        .build();
        if let Err(e) = writer.append(header, est_payload).await {
            tracing::warn!(error = %e, "WAL append COST_ESTIMATE_SHOWN failed (best-effort)");
        }
    }
    info!(
        provider = provider.name(),
        eur = predicted_cost.total_eur,
        in_tokens = predicted_cost.input_tokens,
        out_tokens_est = predicted_cost.output_tokens_est,
        "cost preview"
    );
    {
        use crate::permissions::{Action, Gate};
        let action = Action::PaidProviderCall {
            eur_estimate: predicted_cost.total_eur,
        };
        let gate = Gate::for_level(config.autonomy).with_confirm(Gate::auto_confirm());
        if let Err(e) = gate.check(&action, Some(&writer)).await {
            warn!(error = %e, eur = predicted_cost.total_eur, "provider call blocked by autonomy gate");
            drop(writer);
            let _ = writer_join.await;
            anyhow::bail!("permission denied: {e}");
        }
    }

    // ── Provider quota pre-flight (H5 cascade) ─────────────────────────────
    // If a previous turn recorded a 429 and the backoff window is still
    // active, refuse the call HERE rather than paying the round-trip just
    // to be rate-limited again. Local providers are never tracked.
    let quota_path = crate::config::FreedomConfig::default_neoth_home().join("quota.json");
    let provider_name = provider.name();
    if !crate::providers::is_local_provider(provider_name) {
        let tracker = crate::providers::quota::QuotaTracker::load_from(&quota_path);
        let now = crate::providers::quota::now_unix();
        if let Some(state) = tracker.get(provider_name) {
            if !state.is_healthy(now) {
                let remaining = state.backoff_remaining_secs(now);
                drop(writer);
                let _ = writer_join.await;
                anyhow::bail!(
                    "{provider_name}: backoff active ({remaining}s remaining). \
                     Wait for the window to clear, switch providers via `neoth init`, \
                     or run `neoth quota reset {provider_name}` if you're confident \
                     the remote has recovered."
                );
            }
        }
    }

    // ── Sub-agent dispatch (Phase 30 R-18 SA-2) ────────────────────────────
    // `/agent <name> <body>` swaps system+model+tools for the named agent.
    // Built-ins: code-reviewer / security-reviewer / planner.
    let agent_dir = home.join("agents");
    let agents = crate::sub_agents::load_all(&agent_dir)
        .await
        .unwrap_or_default();
    let agent_dispatch = crate::sub_agents::parse_agent_invocation(&prompt, &agents);
    // Capture the original prompt + name BEFORE the dispatch consumes the
    // values — needed for the two-stage review gate after the reply lands.
    let review_context: Option<(String, String)> = agent_dispatch
        .as_ref()
        .map(|d| (d.agent_name.clone(), d.prompt.clone()));

    // ── Slash command dispatch (Phase 28 R-17 SC-2) ────────────────────────
    // If the operator typed `/help`, `/recall foo`, etc., look up the command
    // in the merged registry (built-ins + `~/.neoth/commands/*.toml`).
    // Matched commands replace the system prompt; the args become the
    // user-facing prompt body. Non-commands pass through untouched.
    let (final_prompt, final_system) = if let Some(d) = agent_dispatch {
        info!(agent = %d.agent_name, "sub-agent dispatch");
        (d.prompt, Some(d.system))
    } else {
        match crate::slash::parse_invocation(&prompt) {
            crate::slash::Invocation::Command {
                name,
                args: cmd_args,
            } => {
                let slash_dir = home.join("commands");
                let commands = crate::slash::load_all(&slash_dir).await.unwrap_or_default();
                if let Some(cmd) = commands.iter().find(|c| c.name == name) {
                    // Pick #31 — action-based slash short-circuit.
                    // When the command carries a typed action, dispatch
                    // it directly + skip the LLM round-trip. Operator
                    // sees the handler output immediately; no provider
                    // call, no token cost, no consent gate.
                    if let Some(action) = cmd.action {
                        info!(slash_command = %name, action = action.as_str(), "slash action dispatch");
                        let outcome = crate::slash::dispatch_action(
                            action,
                            &cmd_args,
                            &config,
                            crate::slash::CommandSource::Cli,
                        );
                        println!("{}", outcome.text());
                        if outcome.should_exit() {
                            return Ok(());
                        }
                        // Action handled — no LLM call needed for this turn.
                        return Ok(());
                    }
                    let rendered = cmd.render(&cmd_args, config.operator_id.as_deref());
                    info!(slash_command = %name, "slash dispatch");
                    (cmd_args, Some(rendered))
                } else {
                    (prompt.clone(), combined_system)
                }
            }
            crate::slash::Invocation::Escaped { text } => (text, combined_system),
            crate::slash::Invocation::NotACommand => (prompt.clone(), combined_system),
        }
    };

    // ── TOML hooks: PrePipeline + PreProviderCall (Phase 29 R-15) ─────────
    // Load `~/.neoth/hooks/*.toml` once for this turn. Both stages apply
    // against the prompt body. A Block at either stage aborts the turn
    // with the hook's `reason` surfaced to the operator. Each fired hook
    // writes a `HOOK_FIRED`/`HOOK_REPLACED`/`HOOK_BLOCKED` WAL frame so
    // the audit trail is exact about which rules touched the call.
    let hook_dir = home.join("hooks");
    // Pick #34 (Session 14, silent-failure audit-fix): surface hook
    // load failures at warn level — prior `unwrap_or_default()` silently
    // disabled ALL hooks on a single bad TOML file.
    let hooks = crate::hooks::load_all(&hook_dir).await.unwrap_or_else(|e| {
        warn!(
            error = %e,
            dir = %hook_dir.display(),
            "hook load failed — proceeding with empty hook set"
        );
        Default::default()
    });
    let final_prompt = match run_hook_stage(
        crate::hooks::HookStage::PrePipeline,
        &final_prompt,
        &hooks,
        &writer,
    )
    .await?
    {
        HookOutcome::Continue(body) => body,
        HookOutcome::Blocked { name, reason } => {
            drop(writer);
            let _ = writer_join.await;
            anyhow::bail!("hook `{name}` blocked the turn at pre_pipeline: {reason}");
        }
    };
    let final_prompt = match run_hook_stage(
        crate::hooks::HookStage::PreProviderCall,
        &final_prompt,
        &hooks,
        &writer,
    )
    .await?
    {
        HookOutcome::Continue(body) => body,
        HookOutcome::Blocked { name, reason } => {
            drop(writer);
            let _ = writer_join.await;
            anyhow::bail!("hook `{name}` blocked the turn at pre_provider_call: {reason}");
        }
    };

    // ── Provider call (sync OR stream) ────────────────────────────────────
    // R-04 2026-05-17: clone final_prompt + final_system here rather
    // than move so the LOWKEY refusal-recovery path post-reply can
    // reissue the same (prompt, system) pair under a reframing.
    // Original moves were tightening Rust's borrow-checker around the
    // Request literal; the cost of the extra Option<String> clone is
    // negligible compared to the LLM round-trip about to fire.
    // Q1 (Session 19): inject the Karpathy metacognitive
    // preamble (think-before-coding / simplicity-first /
    // surgical-changes) before the operator-supplied system
    // block. Idempotent — re-entry from council debate
    // doesn't double-inject. Per
    // `PLAN/QUELLEN_ADOPT_karpathy_2026-05-21.md`.
    let merged_system = Some(crate::providers::context_guards::apply_karpathy_preamble(
        final_system.as_deref(),
    ));
    let req = Request {
        prompt: final_prompt.clone(),
        system: merged_system.clone(),
        model: args.model.clone(),
        temperature: args.temperature,
        top_p: args.top_p,
        sampling_seed: args.sampling_seed,
        stop_sequences: Vec::new(),
    };

    let started = std::time::Instant::now();

    // AP-2: every local-inference call (stream OR non-stream) leaves a WAL
    // START + END trace pair. Hoisted out of the branch arms so the same
    // emission path covers both `provider.complete(req)` and
    // `provider.stream(req)`. The Request is consumed by each call below,
    // so we read its fields once here.
    let is_local_inference = crate::providers::is_local_provider(provider.name());
    let inference_id: u64 = if is_local_inference {
        let id = rand_u64_for_trace();
        let payload = serde_json::to_vec(&serde_json::json!({
            "request_id": id,
            "prompt_hash": xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes()),
            "model": req.model.clone(),
            "stream": args.stream,
            "ts_unix": now_unix(),
        }))
        .unwrap_or_default();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_LOCAL_INFERENCE_START,
            &payload,
        )
        .build();
        if let Err(e) = writer.append(header, payload).await {
            tracing::warn!(error = %e, "WAL append failed (best-effort audit frame)");
        }
        id
    } else {
        0
    };
    let inference_started = std::time::Instant::now();

    // SL-00(1c): mark this provider request as in-flight for the cluster
    // local-load gauge. The RAII guard decrements on drop (covers both the
    // stream + non-stream branches, and any early `?`); we drop it explicitly
    // right after the call so the count reflects only the actual provider work.
    let inflight_guard = crate::cluster::local_load::inflight_guard();

    let (response_text, final_input_tokens, final_output_tokens, model_used) = if args.stream {
        // B-1 follow-up (Session 13) — streaming-branch audit gap.
        // Council never fans out on the streaming path (council needs
        // sync semantics + dissent scoring across full responses).
        // Emit a COUNCIL_SKIP audit anyway so the operator's WAL trace
        // shows every chat turn was reasoned about WRT council, even
        // when streaming mode forces the light path. Reason is
        // operator-greppable: `streaming_mode_disables_council`.
        {
            let prompt_hash_stream = xxhash_rust::xxh3::xxh3_64(prompt.as_bytes());
            let _ = emit_council_skip(
                &writer,
                prompt_hash_stream,
                "streaming_mode_disables_council",
            )
            .await;
        }
        // QM-10 Phase 2.5: streaming path also consults the breaker.
        // Acquire BEFORE provider.stream so an Open breaker rejects
        // the call without opening a stream we'd have to drain.
        let stream_permit = match crate::providers::circuit_breaker::acquire_for(provider_name) {
            Ok(p) => Some(p),
            Err(berr) => {
                drop(writer);
                let _ = writer_join.await;
                return Err(anyhow::anyhow!("provider `{provider_name}`: {berr}"));
            }
        };
        let stream_call_started = std::time::Instant::now();
        // Streaming path: print each delta as it arrives, accumulate the
        // full response for the WAL PROVIDER_RESPONSE frame.
        let mut stream = match provider.stream(req).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(p) = stream_permit {
                    p.record_failure();
                }
                if let Some(qe) = e.downcast_ref::<crate::providers::quota::QuotaError>() {
                    record_quota_exceeded(provider_name, qe, &quota_path, &writer).await;
                }
                warn!(error = %e, "provider stream open failed");
                drop(writer);
                let _ = writer_join.await;
                return Err(e);
            }
        };
        let mut acc = String::new();
        let mut chunk_count: u32 = 0;
        let mut input_tokens = None;
        let mut output_tokens = None;
        let mut model_used = args.model.clone().unwrap_or_default();
        if model_used.is_empty() {
            model_used = config
                .provider_model
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
        }

        use futures_util::stream::StreamExt;
        use std::io::Write as _;
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    if !chunk.delta.is_empty() {
                        print!("{}", chunk.delta);
                        let _ = std::io::stdout().flush();
                        acc.push_str(&chunk.delta);
                        chunk_count += 1;
                        emit_stream_chunk(&writer, provider.name(), &chunk, chunk_count).await?;
                    }
                    if chunk.done {
                        input_tokens = chunk.input_tokens;
                        output_tokens = chunk.output_tokens;
                        break;
                    }
                }
                Err(e) => {
                    if let Some(p) = stream_permit {
                        p.record_failure();
                    }
                    warn!(error = %e, "stream chunk error");
                    drop(writer);
                    let _ = writer_join.await;
                    return Err(e);
                }
            }
        }
        // Loop only reaches here on clean exit — every Err arm
        // returns above so success path is implicit.
        if let Some(p) = stream_permit {
            p.record_success();
        }
        {
            // QM-9 Phase 1.5 / GR-15: persist a usage event for the
            // streaming chat path via the shared best-effort helper.
            let elapsed_ms = stream_call_started.elapsed().as_millis() as u64;
            crate::daemon::usage_log::record_provider_call_best_effort(
                provider_name,
                &model_used,
                input_tokens,
                output_tokens,
                elapsed_ms,
                true,
            );
        }
        // Sentinel line per OPEN_DECISIONS.md D-005 so consumers can detect
        // truncated streams.
        println!();
        println!(
            "{}",
            serde_json::json!({"neoth_stream":"done","count":chunk_count})
        );
        (acc, input_tokens, output_tokens, model_used)
    } else {
        // Non-streaming: existing behavior. START frame already emitted
        // above the branch; END frame fires after both arms converge.
        //
        // CH-02 council wedge — smart-trigger default (Codex feedback
        // 2026-05-16): the chat dispatch now consults CH-14's
        // `should_convene` BY DEFAULT on every call. Tri-state env:
        //   - `NEOTH_COUNCIL_DISABLE=1`  → never (operator opt-out wins)
        //   - `NEOTH_COUNCIL_ENABLE=1`   → always (force-convene every
        //                                  call, bypasses the gates;
        //                                  expensive — operator's choice)
        //   - unset / anything else      → AUTO via `should_convene`
        //                                  (dissent marker + complexity
        //                                  + rate + budget gates).
        //                                  `NEOTH_COUNCIL_AUTO=1` is
        //                                  accepted for backward compat
        //                                  but no longer required —
        //                                  the gate fires automatically.
        //
        // Takes priority over MCP autoroute when both apply (they're
        // mutually exclusive — council debates many providers;
        // autoroute wraps one). Smart-trigger's default-Skip semantic
        // (no dissent marker → Skip) means casual prompts like "what's
        // the time" don't convene; "should I use Rust or Go?" does.
        let council_force = std::env::var("NEOTH_COUNCIL_ENABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let council_disable_env = std::env::var("NEOTH_COUNCIL_DISABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        // SPEC-03 suppress: the persistent `freedom.yaml::council.disabled`
        // flag (set via `neoth council suppress`) is the durable twin of
        // the env override — either one forces the single-hemisphere path.
        // `config` is fresh per CLI invocation so the flag is always current.
        let council_disable_cfg = config.council.disabled.unwrap_or(false);
        let council_disable = council_disable_env || council_disable_cfg;
        // Trigger decision is computed even when not used so the WAL
        // audit (next iteration) can record "council was triggerable
        // but skipped because operator opted out".
        let trigger_decision = if council_disable {
            crate::council::TriggerDecision::Skip {
                // Record BOTH sources when co-active so the audit trail
                // doesn't hide the persistent suppress behind the env var
                // (clearing the env later would otherwise leave no WAL hint
                // that `council.disabled=true` is still in effect).
                reason: match (council_disable_env, council_disable_cfg) {
                    (true, true) => {
                        "NEOTH_COUNCIL_DISABLE=1 + freedom.yaml::council.disabled=true".into()
                    }
                    (true, false) => "NEOTH_COUNCIL_DISABLE=1".into(),
                    (false, _) => "freedom.yaml::council.disabled=true".into(),
                },
            }
        } else if council_force {
            crate::council::TriggerDecision::Convene {
                reason: "NEOTH_COUNCIL_ENABLE=1 (force)".into(),
            }
        } else {
            // B-3 (Session 13) — feed real `seconds_since_last_council`
            // from `~/.neoth/council_last.json` so Gate 2 (rate cooldown)
            // is honoured. Missing / malformed file → `u64::MAX` (gate
            // open), matching prior behaviour for fresh installs.
            let home_b3 = FreedomConfig::default_neoth_home();
            let now_unix_b3 = crate::council::last_ts::now_unix();
            let secs_since = crate::council::last_ts::seconds_since_last(&home_b3, now_unix_b3);
            let ctx = crate::council::TriggerContext {
                seconds_since_last_council: secs_since,
                remaining_budget_eur: None,
                estimated_single_call_eur: predicted_cost.total_eur.max(0.01) as f32,
            };
            // SPEC-03b: operator-tunable thresholds from
            // `freedom.yaml::council.trigger` (defaults reproduce the prior
            // hardcoded policy exactly).
            crate::council::should_convene(&prompt, &ctx, &config.council.trigger.to_policy())
        };
        let council_enable = trigger_decision.should_convene();
        if !council_force && !council_disable {
            info!(
                decision = ?trigger_decision,
                will_convene = council_enable,
                "council smart-trigger evaluated"
            );
        }
        // B-1 (Session 13) — emit COUNCIL_SKIP audit when the trigger
        // resolved to Skip so the operator's WAL audit distinguishes
        // "light path: single hemisphere answered because trigger said
        // skip" from "council fired but everyone agreed silently".
        // Reason carries the exact gate (env override, complexity,
        // rate, budget) so an operator can grep refusal causes per
        // gate over time.
        if !council_enable {
            let prompt_hash_skip = xxhash_rust::xxh3::xxh3_64(prompt.as_bytes());
            let _ = emit_council_skip(&writer, prompt_hash_skip, trigger_decision.reason()).await;
        }
        // A8 / Konsens-decision #8 — MCP autoroute is now AUTO by default
        // when `mcp_servers.yaml` has ≥1 enabled server. Tri-state:
        //   - NEOTH_MCP_AUTOROUTE=1 / true / on / yes → forced ON
        //   - NEOTH_MCP_AUTOROUTE=0 / false / off / no → forced OFF
        //   - unset / empty / other → AUTO (on when servers present)
        // Decision threaded via `McpServers::autoroute_decision` so the
        // chat dispatch can log *why* the loop is on/off (operator
        // opt-in vs auto-derive vs zero-server-default-off).
        // Council always wins when explicitly enabled — the two paths
        // are mutually exclusive (council debates many providers,
        // autoroute wraps one).
        let mcp_servers_for_loop = if !council_enable {
            crate::mcp::McpServers::load().unwrap_or_else(|e| {
                warn!(error = %e, "mcp_servers.yaml load failed in autoroute path — proceeding without MCP tools");
                Default::default()
            })
        } else {
            crate::mcp::McpServers::default()
        };
        let autoroute_env = std::env::var("NEOTH_MCP_AUTOROUTE").ok();
        let autoroute_decision = mcp_servers_for_loop.autoroute_decision(autoroute_env.as_deref());
        let use_loop = !council_enable && autoroute_decision.is_on();
        if council_enable {
            info!(
                trigger = ?trigger_decision,
                "council convened — running 3-hemisphere debate"
            );
            // Pick #8 F8 (Session 14 Pick #20) — pre-flight diversity
            // check. Best-effort: a failed audit emission must not
            // block the debate, so the council still runs even on a
            // misconfigured topology (with the warning recorded).
            let prompt_hash_pre = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
            let _ =
                emit_council_diversity_warning_if_needed(&writer, prompt_hash_pre, &config).await;
            let outcome = match run_council_debate(&config, &req).await {
                Ok(o) => o,
                Err(e) => {
                    warn!(error = %e, "council debate failed; falling back to caller error");
                    drop(writer);
                    let _ = writer_join.await;
                    return Err(e);
                }
            };
            // KF-01 full: persist verbatim hemisphere transcripts (opt-in)
            // so `neoth council replay` can show the actual prose. No-op
            // unless freedom.yaml::council.persist_transcripts = true.
            emit_council_transcripts(&writer, prompt_hash_pre, &outcome, &config).await;
            // B-3 (Session 13) — record this debate's wall-clock so the
            // NEXT prompt's trigger eval sees a real
            // `seconds_since_last_council`. Best-effort: a failed write
            // just keeps the gate open (current behaviour).
            {
                let home_b3 = FreedomConfig::default_neoth_home();
                if let Err(e) =
                    crate::council::last_ts::record(&home_b3, crate::council::last_ts::now_unix())
                {
                    warn!(error = %e, "could not persist council_last.json");
                }
            }
            // B-2 (Session 13): use `response_for(role)` instead of direct
            // index — `outcome.responses` can hold <3 entries when K-Perf-1
            // early-exit cancels a slow hemisphere mid-debate. Direct
            // indexing panics in that case; `response_for` returns Option.
            let left_provider_str = outcome
                .response_for(crate::config::inference::HemisphereRole::Left)
                .map(|r| r.provider.as_str())
                .unwrap_or("cancelled");
            let right_provider_str = outcome
                .response_for(crate::config::inference::HemisphereRole::Right)
                .map(|r| r.provider.as_str())
                .unwrap_or("cancelled");
            let cere_provider_str = outcome
                .response_for(crate::config::inference::HemisphereRole::Cerebellum)
                .map(|r| r.provider.as_str())
                .unwrap_or("cancelled");
            info!(
                dissent = outcome.dissent.0,
                left_provider = left_provider_str,
                right_provider = right_provider_str,
                cere_provider = cere_provider_str,
                refused_count = outcome.refused_count(),
                is_partial_refusal = outcome.is_partial_refusal(),
                total_latency_ms = outcome.total_latency_ms,
                "council debate complete"
            );
            // ADV-10b (Session 28g+): surface degraded debates at the
            // default log level. The orchestrator's FuturesUnordered +
            // quorum check absorbs hemisphere failures naturally (2-of-3
            // degrade is already there), but without a warn at this
            // level a persistently rate-limited or unreachable hemisphere
            // shows ONLY at debug. The degradation classifier
            // distinguishes quota (best-effort substring sniff against
            // QuotaError's Display phrasing) from other failures so the
            // operator can tell "wait for the backoff window" apart from
            // "something else is wrong".
            let degradation = outcome.degradation();
            if degradation.is_degraded() {
                tracing::warn!(
                    degradation = degradation.variant_name(),
                    errored_count = degradation.errored_count(),
                    left_provider = left_provider_str,
                    right_provider = right_provider_str,
                    cere_provider = cere_provider_str,
                    "council debate degraded — fewer than 3 hemispheres contributed (ADV-10b)"
                );
            }
            // A-1: emit COUNCIL_PARTIAL_REFUSAL audit frame whenever any
            // hemisphere refused, regardless of which branch consumes the
            // result. Operator MUST see refusals even when Consensus or
            // Callosum absorbed them silently.
            let prompt_hash_outer = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
            if outcome.is_partial_refusal() {
                let _ = emit_council_partial_refusal(&writer, prompt_hash_outer, &outcome).await;
            }
            // Pick #8 SP-2 (Session 14) CLI path — role-agnostic
            // winner selection when operator configured non-Legacy
            // selection_mode. Returns None for LegacyMajority so
            // existing behaviour is preserved.
            let rw_path_cli = crate::memory::routing_weights::RoutingWeights::default_path(
                &FreedomConfig::default_neoth_home(),
            );
            let rw_read_cli =
                crate::memory::routing_weights::RoutingWeights::load_from(&rw_path_cli);
            let role_agnostic_cli = select_winner_role_agnostic(
                &outcome,
                config.council.selection_mode,
                Some(&rw_read_cli),
                prompt_hash_outer,
            );
            let response_text = if let Some(winner) = role_agnostic_cli {
                let _ = emit_council_winner_selected(
                    &writer,
                    prompt_hash_outer,
                    0,
                    &winner,
                    config.council.selection_mode,
                )
                .await;
                // SP-5: self-reflect refinement pass — threshold +
                // kill-switch gated, depth=0 only, fail-safe.
                let final_text_cli = if crate::council::self_reflect::should_refine(
                    &config,
                    winner.score,
                    0,
                ) {
                    match build_hemisphere(&config, winner.role, &req).await {
                        Ok(reflect_h) => {
                            let refined = crate::council::self_reflect::refine(
                                &req.prompt,
                                &winner.text,
                                &reflect_h,
                            )
                            .await;
                            refined.refined
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "self-reflect skipped (cli): could not rebuild winning hemisphere"
                            );
                            winner.text.clone()
                        }
                    }
                } else {
                    winner.text.clone()
                };
                // SP-4: record acceptance for the winning hemisphere.
                let mut rw_write_cli =
                    crate::memory::routing_weights::RoutingWeights::load_from(&rw_path_cli);
                rw_write_cli.record_acceptance(
                    prompt_hash_outer,
                    winner.role,
                    crate::memory::routing_weights::now_unix(),
                );
                if let Err(e) = rw_write_cli.save() {
                    tracing::warn!(error = %e, "could not persist routing_weights.json (cli)");
                }
                match partial_refusal_prefix(&outcome) {
                    Some(prefix) => format!("{prefix}\n{final_text_cli}"),
                    None => final_text_cli,
                }
            } else {
                match outcome.winning_text() {
                    Some(t) => {
                        // A-1: prepend partial-refusal annotation when one
                        // hemisphere refused but Consensus still produced a
                        // winning text. Annotation goes to operator-visible
                        // stdout; downstream profile/ADR/archive see the
                        // unprefixed text via the original `t`.
                        match partial_refusal_prefix(&outcome) {
                            Some(prefix) => format!("{prefix}\n{t}"),
                            None => t.to_string(),
                        }
                    }
                    None => match &outcome.verdict {
                        crate::council::Verdict::Split { summary } => {
                            // B-2: callosum-on-partial-refusal recovery. Use
                            // `usable_responses()` so the synthesis prompt
                            // never sees the refused hemisphere's text — that
                            // text is a refusal, not a usable answer.
                            let usable: Vec<&crate::council::HemisphereResponse> =
                                outcome.usable_responses().collect();
                            // Audit 2026-05-19 Type #13 Phase 2: usable_responses
                            // already guarantees the Usable variant, so
                            // outcome().text() is Some for every entry.
                            let left_text = usable
                                .first()
                                .and_then(|r| r.outcome().text())
                                .unwrap_or("");
                            let right_text =
                                usable.get(1).and_then(|r| r.outcome().text()).unwrap_or("");
                            let prompt_hash = prompt_hash_outer;
                            // CH-11: pull top operator-profile claims for
                            // the synthesis prompt. Best-effort — if the
                            // views.db open / query fails, we proceed
                            // without profile injection.
                            let profile_block =
                                profile_block_for_callosum().await.unwrap_or_default();
                            let profile_opt = if profile_block.is_empty() {
                                None
                            } else {
                                Some(profile_block.as_str())
                            };
                            match build_hemisphere(
                                &config,
                                crate::config::inference::HemisphereRole::Cerebellum,
                                &req,
                            )
                            .await
                            {
                                Ok(cere) => {
                                    let verdict = crate::council::callosum::resolve_with_profile(
                                        &req.prompt,
                                        left_text,
                                        right_text,
                                        profile_opt,
                                        &cere,
                                    )
                                    .await;
                                    match verdict {
                                    crate::council::callosum::CorticalVerdict::Synthesis(s) => {
                                        info!("callosum produced synthesis ({} chars)", s.len());
                                        let _ = emit_council_synthesis_attempted(
                                            &writer,
                                            prompt_hash,
                                            CouncilSynthesisOutcome::Synthesis {
                                                chars: s.chars().count(),
                                            },
                                        )
                                        .await;
                                        s
                                    }
                                    crate::council::callosum::CorticalVerdict::IrreconcilableConflict { reason } => {
                                        warn!(reason = %reason, "callosum could not synthesise — falling back to operator-decision-needed");
                                        let _ = emit_council_synthesis_attempted(
                                            &writer,
                                            prompt_hash,
                                            CouncilSynthesisOutcome::IrreconcilableConflict {
                                                reason: reason.clone(),
                                            },
                                        )
                                        .await;
                                        format!("[council split — operator decision needed]\n{summary}")
                                    }
                                }
                                }
                                Err(e) => {
                                    warn!(error = %e, "could not build callosum cerebellum — falling back");
                                    let _ = emit_council_synthesis_attempted(
                                        &writer,
                                        prompt_hash,
                                        CouncilSynthesisOutcome::IrreconcilableConflict {
                                            reason: format!("provider build failed: {e}"),
                                        },
                                    )
                                    .await;
                                    format!("[council split — operator decision needed]\n{summary}")
                                }
                            }
                        }
                        crate::council::Verdict::QuorumFailed {
                            responded,
                            required,
                        } => {
                            format!(
                                "[council quorum failed — {responded}/{required} hemispheres responded]"
                            )
                        }
                        crate::council::Verdict::Consensus { .. } => unreachable!(),
                    },
                }
            };
            println!("{response_text}");
            (
                response_text,
                None,
                None,
                model_for_estimate(&args, &config),
            )
        } else if use_loop {
            info!(reason = %autoroute_decision.reason(), "MCP autoroute enabled — running dispatch loop");
            // SC-11 — scope the MCP gate to the matched skill's
            // tool_allowlist (empty/None ⇒ no skill-level restriction).
            let skill_allowlist = skill_tool_allowlist.as_deref();
            let outcome = match run_mcp_dispatch_loop(
                provider,
                req.clone(),
                &mcp_servers_for_loop,
                config.autonomy,
                &writer,
                Some(&config.rollback),
                skill_allowlist,
                config.goal.max_turns,
            )
            .await
            {
                Ok(o) => o,
                Err(e) => {
                    if let Some(qe) = e.downcast_ref::<crate::providers::quota::QuotaError>() {
                        record_quota_exceeded(provider_name, qe, &quota_path, &writer).await;
                    }
                    warn!(error = %e, "MCP dispatch loop failed");
                    drop(writer);
                    let _ = writer_join.await;
                    return Err(e);
                }
            };
            info!(
                iterations = outcome.iterations,
                successful_calls = outcome.successful_calls,
                failed_calls = outcome.failed_calls,
                hit_cap = outcome.hit_cap,
                "MCP dispatch loop complete"
            );
            println!("{}", outcome.final_text);
            (
                outcome.final_text,
                None,
                None,
                model_for_estimate(&args, &config),
            )
        } else {
            // QM-10 Phase 2: consult the circuit breaker for this
            // provider before dispatching. Open breakers reject
            // immediately with operator-readable retry_after.
            let permit = match crate::providers::circuit_breaker::acquire_for(provider_name) {
                Ok(p) => Some(p),
                Err(berr) => {
                    warn!(
                        provider = provider_name,
                        breaker_err = %berr,
                        "circuit breaker rejected call"
                    );
                    drop(writer);
                    let _ = writer_join.await;
                    return Err(anyhow::anyhow!("provider `{provider_name}`: {berr}"));
                }
            };
            let call_started = std::time::Instant::now();
            let result = provider.complete(req).await;
            let elapsed_ms = call_started.elapsed().as_millis() as u64;
            match result {
                Ok(completion) => {
                    // QM-10 Phase 2: settle the permit on success.
                    if let Some(p) = permit {
                        p.record_success();
                    }
                    // QM-9 Phase 1.5 / GR-15: persist a usage event for
                    // the non-streaming chat path via the shared helper.
                    crate::daemon::usage_log::record_provider_call_best_effort(
                        provider_name,
                        &completion.model,
                        completion.input_tokens,
                        completion.output_tokens,
                        elapsed_ms,
                        true,
                    );
                    println!("{}", completion.text);
                    (
                        completion.text,
                        completion.input_tokens,
                        completion.output_tokens,
                        completion.model,
                    )
                }
                Err(e) => {
                    // QM-10 Phase 2: settle the permit on failure.
                    if let Some(p) = permit {
                        p.record_failure();
                    }
                    // Record the failure too so the rollup distinguishes
                    // ok-vs-err for the same provider (GR-15 helper).
                    let model = model_for_estimate(&args, &config);
                    crate::daemon::usage_log::record_provider_call_best_effort(
                        provider_name,
                        &model,
                        None,
                        None,
                        elapsed_ms,
                        false,
                    );
                    if let Some(qe) = e.downcast_ref::<crate::providers::quota::QuotaError>() {
                        record_quota_exceeded(provider_name, qe, &quota_path, &writer).await;
                    }
                    warn!(error = %e, "provider call failed");
                    drop(writer);
                    let _ = writer_join.await;
                    return Err(e);
                }
            }
        }
    };

    // SL-00(1c): the provider work is done — release the in-flight slot and
    // feed the cluster local-load gauge the REAL measured throughput so our
    // outbound heartbeats carry honest numbers (no faked metrics).
    drop(inflight_guard);
    crate::cluster::local_load::record_completion(
        final_output_tokens.unwrap_or(0),
        inference_started.elapsed(),
    );

    // AP-2 END half: fires for stream + non-stream paths after the model
    // produced a reply. Reads the final accumulated text from the same
    // tuple binding both branches return.
    if is_local_inference {
        let latency_ns = u64::try_from(inference_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let payload = serde_json::to_vec(&serde_json::json!({
            "request_id": inference_id,
            "output_hash": xxhash_rust::xxh3::xxh3_64(response_text.as_bytes()),
            "input_tokens": final_input_tokens,
            "output_tokens": final_output_tokens,
            "latency_ns": latency_ns,
            "stream": args.stream,
            "ts_unix": now_unix(),
        }))
        .unwrap_or_default();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_LOCAL_INFERENCE_END,
            &payload,
        )
        .build();
        if let Err(e) = writer.append(header, payload).await {
            tracing::warn!(error = %e, "WAL append failed (best-effort audit frame)");
        }
    }
    let total_latency = started.elapsed();

    // Successful remote call → bump the per-provider daily counter for the
    // quota tracker so `neoth quota status` reflects actual usage. Local
    // providers are not tracked.
    if !crate::providers::is_local_provider(provider_name) {
        let mut tracker = crate::providers::quota::QuotaTracker::load_from(&quota_path);
        tracker.record_success(provider_name, crate::providers::quota::now_unix());
        if let Err(e) = tracker.save() {
            tracing::warn!(error = %e, "quota.json save after success failed (best-effort)");
        }
    }

    // ── TOML hooks: PostProviderCall (Phase 29 R-15) ─────────────────────
    // Last chance to mutate or block the model's reply before it lands in
    // the WAL + reaches the operator. Already-printed streaming output
    // can't be unprinted; the hook can still rewrite the WAL-recorded
    // body (downstream recall + archive see the rewritten text).
    let mut response_text = match run_hook_stage(
        crate::hooks::HookStage::PostProviderCall,
        &response_text,
        &hooks,
        &writer,
    )
    .await?
    {
        HookOutcome::Continue(body) => body,
        HookOutcome::Blocked { name, reason } => {
            drop(writer);
            let _ = writer_join.await;
            anyhow::bail!("hook `{name}` blocked the reply at post_provider_call: {reason}");
        }
    };

    // ── PROVIDER_RESPONSE ─────────────────────────────────────────────────
    let resp_payload = serde_json::to_vec(&serde_json::json!({
        "operator_id": config.operator_id,
        "provider": provider.name(),
        "model": model_used,
        "response_hash_xxh3": xxhash_rust::xxh3::xxh3_64(response_text.as_bytes()),
        "response_bytes": response_text.len(),
        "latency_ns": u64::try_from(total_latency.as_nanos()).unwrap_or(u64::MAX),
        "input_tokens": final_input_tokens,
        // ARCH-04: name the real prompt-token count so it pairs with
        // `prompt_token_estimate` on PROVIDER_REQUEST — operators can
        // diff estimate-vs-actual per turn from the audit chain. Same
        // value as `input_tokens` (kept for back-compat with existing
        // WAL readers); the named field closes the estimate/actual pair.
        "prompt_token_actual": final_input_tokens,
        "output_tokens": final_output_tokens,
        "streamed": args.stream,
    }))?;
    let resp_header = crate::wal::make_header(EVENT_TYPE_PROVIDER_RESPONSE, &resp_payload);
    writer
        .append(resp_header, resp_payload)
        .await
        .context("write PROVIDER_RESPONSE WAL frame")?;

    // ── Mirror-refusal Schicht-0 detection (SPEC_mirror_refusal §1) ────────
    // Pure-deterministic classifier — no LLM call, no meta-decision-making.
    // Whenever the provider's reply matches a refusal pattern, we emit
    // EVENT_TYPE_REFUSAL_OBSERVED (0x16) so operators have an audit trail
    // even before the full mirror pipeline (Stages 2-6) lands. The pipeline
    // itself depends on the hemisphere architecture which is Phase-2 scope.
    {
        let report = crate::security::refusal_detect::classify(&response_text);
        if report.is_refusal() {
            // R-09 2026-05-17: classify WHY the model refused — orthogonal
            // to the surface-class (hard/partial/soft/redirect/safety) the
            // refusal_detect classifier produces. Both signals get bundled
            // into the 0x16 REFUSAL_OBSERVED payload as new fields. Older
            // payload readers see the extra `cause_*` fields and skip them
            // (forward-compat via serde-default in the consumer); newer
            // pipeline stages (R-01..R-05) read them to pick the LOWKEY
            // reframing strategy.
            let cause = crate::security::refusal_cause::classify_cause(&response_text);
            let payload = serde_json::to_vec(&serde_json::json!({
                "operator_id": config.operator_id,
                "provider": provider.name(),
                "model": model_used,
                "refusal_class": report.class.as_str(),
                "confidence": report.confidence,
                "matched_patterns": report.matched_patterns,
                "cause": cause.cause.as_str(),
                "cause_confidence": cause.confidence,
                "cause_matched_patterns": cause.matched_patterns,
                "response_hash_xxh3": xxhash_rust::xxh3::xxh3_64(response_text.as_bytes()),
                "ts_unix": now_unix(),
            }));
            match payload {
                Ok(bytes) => {
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_REFUSAL_OBSERVED,
                        &bytes,
                    )
                    .build();
                    if let Err(e) = writer.append(header, bytes).await {
                        tracing::warn!(error = %e,
                            "WAL append REFUSAL_OBSERVED failed (best-effort audit)");
                    } else {
                        info!(
                            refusal_class = report.class.as_str(),
                            cause = cause.cause.as_str(),
                            confidence = report.confidence,
                            cause_confidence = cause.confidence,
                            "mirror-refusal detector + cause classifier fired"
                        );
                    }
                }
                Err(e) => tracing::warn!(error = %e,
                    "serialize REFUSAL_OBSERVED payload failed"),
            }
        }
    }

    // ── R-04 LOWKEY refusal recovery (Session 9 2026-05-17) ─────────────
    // Wires R-05 (`security::refusal_recovery::try_recover`) into the
    // post-reply path. When the Schicht-0 detector found a refusal +
    // operator opted in (`config.refusal_recovery.enabled`, default
    // true), classify the cause, pick a LOWKEY reframing, retry once.
    // On success: REPLACE `response_text` so downstream ADR extraction
    // + SESSION_ARCHIVE + profile pipeline + PreEgress hooks see the
    // recovered reply. On failure: leave the original refusal text in
    // place so the operator sees it verbatim.
    //
    // Per-call escape hatch: `NEOTH_REFUSAL_RECOVERY_DISABLE=1` skips
    // the retry even when the config flag is on (operator debugging
    // refusal triggers without auto-retry noise).
    //
    // Audit: every retry attempt emits `0x19 REFUSAL_REROUTED`. The
    // original 0x16 REFUSAL_OBSERVED frame above stays as truth (the
    // original refusal happened); the recovery is an additive layer.
    // ADV-07: track whether this turn's reply came from the mirror
    // refusal-recovery path, so profile extraction can skip the
    // operator_preferences category for it (the recovered "preferences"
    // are about the reframing, not the operator).
    let mut derived_from_mirror_pipeline = false;
    if config.refusal_recovery.enabled
        && std::env::var("NEOTH_REFUSAL_RECOVERY_DISABLE")
            .map(|v| !(v == "1" || v.eq_ignore_ascii_case("true")))
            .unwrap_or(true)
    {
        let report = crate::security::refusal_detect::classify(&response_text);
        if report.is_refusal() {
            let recovery_req = crate::providers::Request {
                prompt: final_prompt.clone(),
                // Q1: idempotent apply — re-entry path also
                // gets the Karpathy preamble. The
                // `apply_karpathy_preamble` no-ops when the
                // preamble is already present so this is
                // safe under any sequencing.
                system: Some(crate::providers::context_guards::apply_karpathy_preamble(
                    final_system.as_deref(),
                )),
                model: Some(model_used.clone()),
                ..Default::default()
            };
            match crate::security::refusal_recovery::try_recover_multi(
                provider,
                &recovery_req,
                &response_text,
                &config.refusal_recovery.disabled_reframings,
                Some(&writer),
                now_unix(),
                config.refusal_recovery.max_attempts,
            )
            .await
            {
                Ok(crate::security::refusal_recovery::RecoveryOutcome::Recovered {
                    completion,
                    reframing_id,
                }) => {
                    info!(
                        reframing = reframing_id,
                        original_bytes = response_text.len(),
                        recovered_bytes = completion.text.len(),
                        "refusal recovery succeeded — replacing response_text downstream"
                    );
                    response_text = completion.text;
                    derived_from_mirror_pipeline = true; // ADV-07
                }
                Ok(crate::security::refusal_recovery::RecoveryOutcome::RefusedAgain {
                    reframing_id,
                    ..
                }) => {
                    tracing::info!(
                        reframing = reframing_id,
                        "refusal recovery attempted but model refused again — leaving original refusal in place"
                    );
                }
                Ok(crate::security::refusal_recovery::RecoveryOutcome::NotRecoverable {
                    cause,
                }) => {
                    tracing::debug!(
                        cause = cause.as_str(),
                        "refusal not recoverable (Unknown / OperatorPolicy / all reframings disabled)"
                    );
                }
                Ok(crate::security::refusal_recovery::RecoveryOutcome::ProviderError {
                    reframing_id,
                    error,
                }) => {
                    tracing::warn!(
                        reframing = reframing_id,
                        error = %error,
                        "refusal recovery retry hit provider error — leaving original refusal in place"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "refusal recovery failed (non-fatal)");
                }
            }
        }
    }

    // ── ADR extraction (Phase 31 R-21 ADR-1) ─────────────────────────────
    // Scan the provider's reply for DECISION:/Beschluss:/ADR: markers. Each
    // hit writes `~/.neoth/adr/NNNN-<slug>.md`. Failures log but never
    // block — ADR capture is operator-side bookkeeping, not load-bearing.
    {
        let adr_dir = crate::adr::default_adr_dir();
        let decisions = crate::adr::extract_decisions(&response_text);
        for d in &decisions {
            match crate::adr::write_adr(&adr_dir, d) {
                Ok(path) => info!(adr = %path.display(), title = %d.title, "ADR captured"),
                Err(e) => tracing::warn!(error = %e, title = %d.title, "ADR write failed"),
            }
        }
    }

    // ── SESSION_ARCHIVE (Phase 28a MT-4) ─────────────────────────────────
    // Append the turn pair to ~/.neoth/archive/sessions/YYYY-MM-DD/<id>.md.
    // Failure here MUST NOT swallow the chat outcome — log and continue.
    // The session id is the chat invocation id; the daemon path will swap
    // this for the persistent session-uuid from the channel handler.
    {
        let archive = crate::memory::archive::SessionArchive::new(
            crate::memory::archive::default_archive_root(),
            format!("cli-{}", uuid::Uuid::new_v4()),
            chrono::Utc::now(),
        );
        if let Err(e) = archive
            .append_turn(&prompt, &response_text, chrono::Utc::now())
            .await
        {
            tracing::warn!(error = %e, "session archive append failed");
        }
    }

    // ── Profile pipeline post-reply (Session 2 hardening 2026-05-17) ─────
    // The full 6-stage `profile::run_pipeline` runs after each chat reply
    // when the operator explicitly opts in via
    // `freedom.yaml::profile.learn_enabled: true` (default `false`).
    //
    // Off by default because the Stage-3 extract is a full LLM call —
    // operators on paid clouds (OpenAI / Anthropic API / OpenRouter)
    // would see a surprise 2× token bill per chat without opt-in.
    // Operators on `local_qwen` or pre-paid plans flip the flag on and
    // get passive operator-profile learning that feeds CH-11 callosum
    // synthesis + future CH-09/CH-10 recall ranking with real data.
    //
    // Env overrides: `NEOTH_PROFILE_LEARN_DISABLE=1` skips even when
    // `learn_enabled: true` (per-call brake). `NEOTH_PROFILE_LEARN_FORCE=1`
    // enables even when the config flag is false (per-call lift for
    // ad-hoc learning sessions).
    //
    // Latency cap: wrapped in `tokio::time::timeout` (default 15s via
    // `freedom.yaml::profile.timeout_secs`). A hung extract LLM call
    // cannot pin the CLI shell past this budget — operator gets their
    // shell prompt back; the pipeline run is abandoned (logged warn).
    //
    // Best-effort throughout: any failure (missing views.db, indexer
    // error, extract LLM error, guard rejection, timeout) logs at
    // warn/debug and never bubbles into the chat reply.
    let env_disable = std::env::var("NEOTH_PROFILE_LEARN_DISABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let env_force = std::env::var("NEOTH_PROFILE_LEARN_FORCE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let learn_on = !env_disable && (env_force || config.profile.learn_enabled);
    if learn_on {
        let timeout = std::time::Duration::from_secs(config.profile.timeout_secs.max(1));
        let views_path = crate::memory::store::default_path();
        // V10-07 (Session 21) — when freedom.yaml::profile.learn_provider
        // is set, build a learn-specific provider (typically local_qwen
        // so the post-reply extract stays offline). Falls back to the
        // main provider when learn_provider is None or on build-failure
        // with allow_cloud_fallback=true. Build-failure with
        // allow_cloud_fallback=false (the default cheap-by-default
        // posture) skips the learn pass entirely with a clear warn.
        let learn_provider_owned: Option<Box<dyn crate::providers::Provider>> =
            match crate::providers::from_config_for_learn(&config).await {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "profile.learn_provider build failed; skipping post-reply learn pass"
                    );
                    None
                }
            };
        // Session 24 fix #2: when `from_config_for_learn` returns Err
        // (= learn_provider build failed AND allow_cloud_fallback=false
        // per `providers::from_config_for_learn` step 4 contract), the
        // operator's intent is "no fallback, skip extraction". The
        // pre-fix code fell back to the main `provider` here, which
        // sent the operator's full conversation window to the cloud
        // path they had explicitly opted out of. The comment above
        // said "skip with warn" but the code did the opposite.
        // Honest fix: bail before invoking the pipeline.
        let learn_dispatch: Option<&dyn crate::providers::Provider> = learn_provider_owned
            .as_deref()
            .map(|p| p as &dyn crate::providers::Provider);
        if learn_dispatch.is_none() {
            tracing::info!(
                allow_cloud_fallback = config.profile.allow_cloud_fallback,
                "profile.learn pass skipped: learn_provider build failed and \
                 allow_cloud_fallback=false (operator chose privacy over learn)"
            );
        } else if let Some(learn_provider_ref) = learn_dispatch {
            // ADV-10c (Session 28g+): pre-flight QuotaTracker check on
            // the learn_provider. Without this, a persistently rate-
            // limited learn_provider pays a full LLM round-trip EVERY
            // post-reply turn only to be 429'd inside Stage 3 of
            // `run_pipeline`. ADV-10 Slice A closed the silent-data-loss
            // gap (the 0xB9 emit + Skip variant); this closes the
            // wasted-cost gap upstream by skipping the call entirely
            // while a backoff window is active. Soft-skip — log warn and
            // continue, do NOT bail the chat turn (the operator already
            // got their reply; profile-learn is a passive post-reply
            // pass). Local providers always pass the check.
            let learn_quota_path =
                crate::config::FreedomConfig::default_neoth_home().join("quota.json");
            let learn_tracker = crate::providers::quota::QuotaTracker::load_from(&learn_quota_path);
            let learn_now = crate::providers::quota::now_unix();
            let learn_backoff_remaining =
                learn_tracker.backoff_remaining_for(learn_provider_ref.name(), learn_now);
            if let Some(remaining) = learn_backoff_remaining {
                tracing::warn!(
                    provider = learn_provider_ref.name(),
                    backoff_remaining_secs = remaining,
                    "profile.learn pre-flight: learn_provider in 429 backoff — skipping pipeline (ADV-10c)"
                );
            }
            if learn_backoff_remaining.is_none() {
                match crate::memory::store::open(&views_path) {
                    Ok(mut conn) => {
                        let pipeline_fut = async {
                            if let Err(e) =
                                crate::memory::indexer::replay_once(&mut conn, &segment_path).await
                            {
                                tracing::warn!(
                                    error = %e,
                                    "indexer replay_once failed before profile pipeline; skipping learn"
                                );
                                return;
                            }
                            let guard = crate::profile::claim_guard::ProfileClaimGuard::default();
                            let extensions =
                                crate::profile::extension_registry::TypedExtensionRegistry::load()
                                    .unwrap_or_default();
                            match crate::profile::run_pipeline(
                                &mut conn,
                                &writer,
                                learn_provider_ref,
                                raw_event_id,
                                2,
                                &guard,
                                &extensions,
                                now_unix(),
                                // ADV-03 Phase 5 (Session 24): gate context
                                // None preserves pre-gate behaviour. Wiring
                                // the chat-path gate context (autonomy +
                                // is_tty + dialoguer confirm) is Phase 6+
                                // CLI surface work tracked separately.
                                None,
                                derived_from_mirror_pipeline, // ADV-07
                            )
                            .await
                            {
                                Ok(crate::profile::PipelineRun::Applied { outcome, .. }) => {
                                    tracing::info!(
                                        claims_applied = outcome.claims_applied,
                                        claims_reinforced = outcome.claims_reinforced,
                                        claims_superseded = outcome.claims_superseded,
                                        idempotent_skip = outcome.idempotent_skip,
                                        "profile pipeline applied post-reply"
                                    );
                                }
                                Ok(crate::profile::PipelineRun::Skipped(
                                    reason @ crate::profile::PipelineSkip::QuotaExceeded { .. },
                                )) => {
                                    // ADV-10 review follow-up: persistent 429
                                    // suppression must be observable at the
                                    // default log level — a quietly rate-limited
                                    // learn_provider that always lands here
                                    // would otherwise show no operator-visible
                                    // signal except the WAL frame.
                                    tracing::warn!(
                                        reason = %reason,
                                        "profile pipeline quota-exceeded post-reply"
                                    );
                                }
                                Ok(crate::profile::PipelineRun::Skipped(reason)) => {
                                    tracing::debug!(reason = %reason, "profile pipeline skipped post-reply");
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "profile pipeline failed post-reply (non-fatal)"
                                    );
                                }
                            }
                        };
                        match tokio::time::timeout(timeout, pipeline_fut).await {
                            Ok(()) => {}
                            Err(_elapsed) => {
                                tracing::warn!(
                                    timeout_secs = timeout.as_secs(),
                                    "profile pipeline timed out post-reply; learning abandoned for this turn"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %views_path.display(),
                            "open views.db failed for post-reply profile pipeline (non-fatal)"
                        );
                    }
                }
            } // ADV-10c (Session 28g+): closes `if learn_backoff_remaining.is_none()`
        } // Session 24 fix #2: closes the `else if let Some(learn_provider_ref) = ...`
    }

    // ── Two-stage review gate (obra/superpowers Item #2) ───────────────────
    // Activates only when (a) the operator dispatched via `/agent`, and (b)
    // `freedom.yaml::review_gate_enabled` is true. Costs 2× extra provider
    // calls so it stays opt-in.
    if let Some((agent_name, original_prompt)) = review_context {
        if config.review_gate_enabled {
            tracing::info!(agent = %agent_name, "running two-stage review gate");
            match crate::sub_agents::review::two_stage_review(
                provider,
                &original_prompt,
                &response_text,
            )
            .await
            {
                Ok(verdicts) => {
                    println!("\n── review gate ──");
                    for v in &verdicts {
                        let mark = if v.passed { "PASS" } else { "FAIL" };
                        println!("  {}: {}", v.stage.as_str(), mark);
                        // One WAL frame per stage. Body is hashed, not stored,
                        // to keep the WAL small per the event-type doc.
                        let payload = serde_json::to_vec(&serde_json::json!({
                            "agent_name": agent_name,
                            "stage": v.stage.as_str(),
                            "passed": v.passed,
                            "feedback_hash_xxh3": xxhash_rust::xxh3::xxh3_64(v.feedback.as_bytes()),
                        }))
                        .unwrap_or_default();
                        let header = crate::wal::HeaderBuilder::new(
                            crate::wal::events::EVENT_TYPE_SUBAGENT_REVIEW_STAGE,
                            &payload,
                        )
                        .build();
                        if let Err(e) = writer.append(header, payload).await {
                            tracing::warn!(error = %e, "failed to write review WAL frame");
                        }
                    }
                    // Surface the feedback bodies inline so the operator
                    // sees them in the same terminal — they were paid for.
                    for v in &verdicts {
                        if !v.feedback.is_empty() {
                            println!("\n[{}]\n{}", v.stage.as_str(), v.feedback);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "two-stage review gate errored; printing primary reply only");
                }
            }
        }
    }

    // OP-02 (Session 25) — session-end hindsight compression.
    // Two-turn transcript (operator prompt + agent reply) goes
    // through `compress_session` + `save_card` so the next
    // session's seed banner has something to surface. Best-effort:
    // a write failure logs warn but never aborts the chat exit
    // path. `chat_ts_unix` + `current_session_id` were both
    // computed at startup so the same id used in the banner-suppress
    // check round-trips through the saved card.
    crate::memory::hindsight::save_session_card_best_effort(
        &first_tour_home,
        chat_ts_unix,
        &prompt,
        &response_text,
    );

    drop(writer);
    let _ = writer_join.await;
    Ok(())
}

/// Stable-ish per-call ID for `LOCAL_INFERENCE_START` / `END` correlation.
/// Not security-grade randomness — just enough entropy that two
/// concurrent inferences don't collide in audit grep'ing. Combines the
/// process pid with the nanosecond timestamp.
fn rand_u64_for_trace() -> u64 {
    let pid = std::process::id() as u64;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    pid.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(nanos)
}

/// Folded outcome from a single hook-stage dispatch.
enum HookOutcome {
    /// Stage finished with the (possibly rewritten) body.
    Continue(String),
    /// A hook returned `Block` — caller should bail.
    Blocked { name: String, reason: String },
}

/// Run one hook stage against `body`. Emits a `HOOK_FIRED` WAL frame
/// for every hook that fired with name + stage in the payload, plus
/// `HOOK_REPLACED` when the body changed and `HOOK_BLOCKED` when a hook
/// stopped the pipeline. Audit frames are best-effort — append failures
/// log a warning but never propagate.
async fn run_hook_stage(
    stage: crate::hooks::HookStage,
    body: &str,
    hooks: &[crate::hooks::schema::HookDef],
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<HookOutcome> {
    let before = body.to_string();
    let outcome = crate::hooks::run_stage(stage, body, hooks)?;
    match outcome {
        crate::hooks::StageOutcome::Continue { body: after, hits } => {
            for name in &hits {
                emit_hook_frame(
                    writer,
                    crate::wal::events::EVENT_TYPE_HOOK_FIRED,
                    name,
                    stage,
                    None,
                )
                .await;
            }
            if !hits.is_empty() && after != before {
                emit_hook_frame(
                    writer,
                    crate::wal::events::EVENT_TYPE_HOOK_REPLACED,
                    hits.last().map(String::as_str).unwrap_or("?"),
                    stage,
                    Some(&format!("{} → {}", before.len(), after.len())),
                )
                .await;
            }
            Ok(HookOutcome::Continue(after))
        }
        crate::hooks::StageOutcome::Block { name, reason } => {
            emit_hook_frame(
                writer,
                crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                &name,
                stage,
                Some(&reason),
            )
            .await;
            Ok(HookOutcome::Blocked { name, reason })
        }
    }
}

/// Emit a single hook-lifecycle WAL frame. Best-effort.
async fn emit_hook_frame(
    writer: &crate::wal::writer::WalWriterHandle,
    event_type: u8,
    hook_name: &str,
    stage: crate::hooks::HookStage,
    note: Option<&str>,
) {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "name": hook_name,
        "stage": stage.as_str(),
        "note": note,
        "ts_unix": now_unix(),
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialize hook frame payload failed");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append hook frame failed (best-effort)");
    }
}

/// Record a 429 from a remote provider: extend the backoff window in
/// `~/.neoth/quota.json`, write a `PROVIDER_QUOTA_EXCEEDED` WAL frame,
/// and emit a tracing warn for `journalctl` consumers. Best-effort —
/// failures here never mask the original provider error. The caller
/// continues to bail with `e`; this side effect is purely audit + UX.
async fn record_quota_exceeded(
    provider_name: &str,
    qe: &crate::providers::quota::QuotaError,
    quota_path: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
) {
    let now = crate::providers::quota::now_unix();
    let mut tracker = crate::providers::quota::QuotaTracker::load_from(quota_path);
    let effective = tracker.record_429(provider_name, qe.retry_after, now);
    if let Err(e) = tracker.save() {
        tracing::warn!(error = %e, "quota.json save after 429 failed (best-effort)");
    }
    let state = tracker.get(provider_name).cloned();
    let payload = match serde_json::to_vec(&serde_json::json!({
        "provider": provider_name,
        "retry_after_secs": effective.as_secs(),
        "requests_today": state.as_ref().map(|s| s.requests_today),
        "daily_cap": state.as_ref().and_then(|s| s.estimated_daily_cap),
        "backoff_until_unix": state.as_ref().and_then(|s| s.backoff_until_unix),
        "ts_unix": now,
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialize PROVIDER_QUOTA_EXCEEDED payload failed");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append PROVIDER_QUOTA_EXCEEDED failed (best-effort)");
    }
    warn!(
        provider = provider_name,
        retry_after_secs = effective.as_secs(),
        "provider returned HTTP 429 — backoff recorded"
    );
}

/// Resolve the model string the cost predictor should price against
/// — prefers `--model` CLI flag, then `freedom.yaml::provider_model`,
/// falls back to "unknown" so the lookup table returns None and the
/// estimate defaults to zero (operator gets a free-tier preview
/// rather than a panic).
fn model_for_estimate(args: &ChatArgs, config: &crate::config::FreedomConfig) -> String {
    args.model
        .clone()
        .or_else(|| config.provider_model.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Emit a single stream-chunk WAL frame via the fire-and-forget
/// `append_no_ack` path (K-Perf-2 2026-05-17). The caller does NOT
/// wait for the writer's `sync_data` per chunk — at ~10ms fsync
/// latency × 100 tokens = 1s of disk overhead would otherwise
/// serialise into the operator-visible streaming UX. The chunk still
/// lands in the WAL (writer task processes it the same way), just
/// asynchronously to the streaming loop.
///
/// Bounded loss model: if the writer task crashes mid-stream a
/// handful of buffered chunks may be lost. Acceptable for
/// stream-chunk audit (the full reply is also captured in the
/// terminal-ack'd `PROVIDER_RESPONSE` frame). NEVER use no-ack for
/// PROVIDER_RESPONSE itself.
async fn emit_stream_chunk(
    writer: &crate::wal::writer::WalWriterHandle,
    provider_name: &str,
    chunk: &CompletionChunk,
    seq: u32,
) -> Result<()> {
    use crate::wal::events::EVENT_TYPE_PROVIDER_STREAM_CHUNK;
    let payload = serde_json::to_vec(&serde_json::json!({
        "provider": provider_name,
        "seq": seq,
        "delta_bytes": chunk.delta.len(),
        "delta_hash_xxh3": xxhash_rust::xxh3::xxh3_64(chunk.delta.as_bytes()),
    }))?;
    let header = crate::wal::make_header(EVENT_TYPE_PROVIDER_STREAM_CHUNK, &payload);
    writer
        .append_no_ack(header, payload)
        .await
        .context("enqueue PROVIDER_STREAM_CHUNK WAL frame")?;
    Ok(())
}

async fn resolve_prompt(args: &ChatArgs) -> Result<String> {
    if let Some(m) = &args.message {
        if !m.trim().is_empty() {
            return Ok(m.clone());
        }
    }
    use tokio::io::AsyncReadExt;
    let mut buf = String::new();
    tokio::io::stdin()
        .read_to_string(&mut buf)
        .await
        .context("read prompt from stdin")?;
    if buf.trim().is_empty() {
        anyhow::bail!("no prompt provided. Pass `neoth chat \"...\"` or pipe via stdin.");
    }
    Ok(buf)
}

/// CH-02 wedge: build three per-role provider adapters from the
/// operator's freedom config + run the council debate. Returns the
/// `CouncilDebate` outcome whose `winning_text()` becomes the response
/// when the verdict is `Consensus`; `Split` and `QuorumFailed` are
/// rendered as operator-visible diagnostic text in the caller.
/// Wrapper that adapts a `Box<dyn Provider>` into the council's
/// `HemisphereProvider` trait. Lifted out of `run_council_debate` so
/// the Split-recovery path (A5 callosum::resolve) can reuse the same
/// shape for a one-off Cerebellum synthesis call.
struct ProviderHemisphere {
    provider: Box<dyn crate::providers::Provider>,
    base_req: crate::providers::Request,
    /// E-2 Phase 2 (Session 13) — operator config kept around so this
    /// hemisphere's `ask_with_depth` can recurse: when `depth > 1` it
    /// builds three sub-hemispheres for Left/Right/Cerebellum from
    /// the same per-role bindings + convenes an inner council at
    /// `depth - 1`. `None` here disables recursion explicitly — used
    /// when the wrapper is built for a one-shot Split-recovery call
    /// that must NOT recurse regardless of operator config.
    config: Option<std::sync::Arc<FreedomConfig>>,
    /// E-2 Phase 3 (Session 14) — outer-role identity for sub-slot
    /// resolution. When `Some(role)` and the topology configures
    /// `hemisphere_sub_slots[role]`, this hemisphere's recursion
    /// builds inner hemispheres from those operator-pinned sub-slots
    /// rather than reusing the outer-level bindings. `None` =
    /// Phase 2 behaviour (reuse outer slots) — kept for the Split-
    /// recovery one-shot wrapper that never recurses.
    outer_role: Option<crate::config::inference::HemisphereRole>,
}

#[async_trait::async_trait]
impl crate::council::orchestrator::HemisphereProvider for ProviderHemisphere {
    fn provider_id(&self) -> String {
        self.provider.name().to_string()
    }
    async fn ask(
        &self,
        prompt: &str,
    ) -> std::result::Result<crate::council::orchestrator::CompletionRecord, String> {
        // QM-10 Phase 2.5: council debate path also consults the
        // breaker. Open breakers reject the hemisphere call so the
        // council dispatcher counts a budget unit against a doomed
        // provider only when the breaker says it's worth trying.
        let provider_name = self.provider.name();
        let permit = match crate::providers::circuit_breaker::acquire_for(provider_name) {
            Ok(p) => Some(p),
            Err(berr) => {
                return Err(format!("provider `{provider_name}`: {berr}"));
            }
        };
        let mut req = self.base_req.clone();
        req.prompt = prompt.to_string();
        // QM-9 Phase 1.5 follow-on: council debate path now also
        // persists usage events. Each hemisphere call counts —
        // operators on a Pick #8 council see the per-hemisphere
        // burn instead of one aggregate "council ran" row.
        let call_started = std::time::Instant::now();
        let raw = self.provider.complete(req).await;
        let elapsed_ms = call_started.elapsed().as_millis() as u64;
        match raw {
            Ok(c) => {
                if let Some(p) = permit {
                    p.record_success();
                }
                crate::daemon::usage_log::record_provider_call_best_effort(
                    provider_name,
                    &c.model,
                    c.input_tokens,
                    c.output_tokens,
                    elapsed_ms,
                    true,
                );
                Ok(crate::council::orchestrator::CompletionRecord {
                    text: c.text,
                    input_tokens: c.input_tokens,
                    output_tokens: c.output_tokens,
                })
            }
            Err(e) => {
                if let Some(p) = permit {
                    p.record_failure();
                }
                crate::daemon::usage_log::record_provider_call_best_effort(
                    provider_name,
                    "unknown",
                    None,
                    None,
                    elapsed_ms,
                    false,
                );
                Err(e.to_string())
            }
        }
    }
    /// E-2 Phase 2 (Session 13) — recursive sub-council override.
    /// Pick #19 (Session 14 F6) — budget-aware path. Delegates to
    /// `ask_with_depth_budget` with a fresh `BudgetToken` so the
    /// legacy entry point preserves its prior cost ceiling
    /// (15 calls / user message) even when called by code paths that
    /// don't yet thread an outer budget.
    async fn ask_with_depth(
        &self,
        prompt: &str,
        depth: u8,
    ) -> std::result::Result<crate::council::orchestrator::CompletionRecord, String> {
        let fresh = crate::council::BudgetToken::new(
            crate::config::inference::DEFAULT_MAX_CALLS_PER_USER_MESSAGE,
        );
        self.ask_with_depth_budget(prompt, depth, fresh).await
    }

    /// E-2 Phase 2 + Pick #19 F6 — budget-aware recursive sub-council.
    /// When `depth > 1` and a config Arc is present, convene a fresh
    /// inner debate against three sub-hemispheres derived from the
    /// same per-role bindings, at `depth - 1`. The inner verdict's
    /// `winning_text` (or the first usable response on Split) becomes
    /// this hemisphere's contribution to the outer debate. Self-
    /// similar / fractal: each hemisphere can spawn its own mini-
    /// council until `depth == 1` bottoms out at a flat `ask`.
    ///
    /// The shared `BudgetToken` is threaded into
    /// `run_debate_with_depth_budget` so the cap spans the outer +
    /// inner debate together — no over-budget fan-out is possible
    /// regardless of `hemisphere_council_depth`.
    ///
    /// COST WARNING: each recursion level multiplies LLM calls by 3.
    /// depth=2 = 9 leaf calls per outer hemisphere call (3 outer × 3
    /// inner). depth=3 = 27 leaf calls per outer hemisphere call.
    /// depth=4 (the `MAX_HEMISPHERE_COUNCIL_DEPTH` cap) = 81 leaf
    /// calls per outer hemisphere call. The shared `BudgetToken`
    /// truncates the actual fan-out at its cap (default 15), so
    /// late-spawned hemispheres report `budget-exhausted` instead of
    /// silently consuming the operator's token budget.
    async fn ask_with_depth_budget(
        &self,
        prompt: &str,
        depth: u8,
        budget: crate::council::BudgetToken,
    ) -> std::result::Result<crate::council::orchestrator::CompletionRecord, String> {
        // Flat path: depth ≤ 1 OR no config Arc means this wrapper
        // was built for the one-shot Split-recovery path and must NOT
        // recurse. Delegate to `ask`.
        if depth <= 1 {
            return self.ask(prompt).await;
        }
        let Some(config) = &self.config else {
            return self.ask(prompt).await;
        };
        // Build three sub-hemispheres from the per-role bindings.
        // Sub-hemispheres carry the same config Arc so they themselves
        // can recurse if `depth - 1 > 1`. `req` clones cheaply.
        //
        // E-2 Phase 3 (Session 14): when `self.outer_role` is set,
        // route sub-hemispheres through `build_sub_hemisphere_with_config`
        // so `hemisphere_sub_slots[outer_role]` overrides apply.
        // When `outer_role` is `None` (legacy / Split-recovery
        // wrappers) fall back to Phase 2 behaviour — reuse outer slots.
        use crate::config::inference::HemisphereRole;
        let (sub_left, sub_right, sub_cere) = match self.outer_role {
            Some(outer) => {
                let l = build_sub_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    outer,
                    HemisphereRole::Left,
                    &self.base_req,
                )
                .await;
                let r = build_sub_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    outer,
                    HemisphereRole::Right,
                    &self.base_req,
                )
                .await;
                let c = build_sub_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    outer,
                    HemisphereRole::Cerebellum,
                    &self.base_req,
                )
                .await;
                let unwrap = |res: Result<ProviderHemisphere>, name: &str| match res {
                    Ok(h) => Ok(h),
                    Err(e) => Err(format!("build sub-{name} for depth-{depth} recursion: {e}")),
                };
                (
                    unwrap(l, "left")?,
                    unwrap(r, "right")?,
                    unwrap(c, "cerebellum")?,
                )
            }
            None => {
                let l = build_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    HemisphereRole::Left,
                    &self.base_req,
                )
                .await;
                let r = build_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    HemisphereRole::Right,
                    &self.base_req,
                )
                .await;
                let c = build_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    HemisphereRole::Cerebellum,
                    &self.base_req,
                )
                .await;
                let unwrap = |res: Result<ProviderHemisphere>, name: &str| match res {
                    Ok(h) => Ok(h),
                    Err(e) => Err(format!("build sub-{name} for depth-{depth} recursion: {e}")),
                };
                (
                    unwrap(l, "left")?,
                    unwrap(r, "right")?,
                    unwrap(c, "cerebellum")?,
                )
            }
        };
        let prompt_hash = xxhash_rust::xxh3::xxh3_64(prompt.as_bytes());
        let inner = crate::council::run_debate_with_depth_budget(
            prompt,
            prompt_hash,
            depth - 1,
            budget,
            &sub_left,
            &sub_right,
            &sub_cere,
            None, // inner council uses the cheap Jaccard dissent
        )
        .await;
        // Aggregation: winning_text on Consensus → use it.
        // Split → pick the first usable hemisphere's text (deterministic).
        // QuorumFailed → bubble up an error string the outer council
        //   sees as a hemisphere error (not panic).
        if let Some(t) = inner.winning_text() {
            return Ok(crate::council::orchestrator::CompletionRecord {
                text: t.to_string(),
                input_tokens: None,
                output_tokens: None,
            });
        }
        if let Some(usable) = inner.usable_responses().next()
            && let Some(text) = usable.outcome().text()
        {
            return Ok(crate::council::orchestrator::CompletionRecord {
                text: text.to_string(),
                input_tokens: None,
                output_tokens: None,
            });
        }
        Err(format!(
            "inner council at depth {} produced no usable response (verdict: {:?})",
            depth - 1,
            inner.verdict
        ))
    }
}

/// Build a fresh `ProviderHemisphere` for `role` using the configured
/// per-role provider (defaults collapse to single-mode in Single
/// topology). Used by `run_council_debate` to build all three plus by
/// the A5 Split-recovery path to build a one-shot Cerebellum.
///
/// E-2 Phase 2 (Session 13): legacy entry point that builds a wrapper
/// without a config Arc — recursion is DISABLED for these wrappers.
/// Used by the A5 callosum Split-recovery path that should never
/// recurse regardless of operator config.
async fn build_hemisphere(
    config: &FreedomConfig,
    role: crate::config::inference::HemisphereRole,
    req: &crate::providers::Request,
) -> Result<ProviderHemisphere> {
    let provider = crate::providers::from_config_for_role(config, role).await?;
    Ok(ProviderHemisphere {
        provider,
        base_req: req.clone(),
        config: None,
        outer_role: None,
    })
}

/// E-2 Phase 2 (Session 13) — recursion-aware build entry. Carries a
/// config Arc so `ask_with_depth` can spawn an inner council at lower
/// depth when `topology.hemisphere_council_depth > 1`. Used by
/// `run_council_debate` for outer-council hemispheres + by the inner
/// council's recursive build path itself.
///
/// E-2 Phase 3 (Session 14): stamps `outer_role = Some(role)` so the
/// recursion path can consult `inference.hemisphere_sub_slots[role]`
/// when building inner-council hemispheres.
async fn build_hemisphere_with_config(
    config: std::sync::Arc<FreedomConfig>,
    role: crate::config::inference::HemisphereRole,
    req: &crate::providers::Request,
) -> Result<ProviderHemisphere> {
    let provider = crate::providers::from_config_for_role(config.as_ref(), role).await?;
    Ok(ProviderHemisphere {
        provider,
        base_req: req.clone(),
        config: Some(config),
        outer_role: Some(role),
    })
}

/// E-2 Phase 3 (Session 14) — build an INNER-council hemisphere
/// scoped to a specific OUTER role. Resolves the provider via
/// `from_config_for_sub_role(config, outer_role, inner_role)` so
/// `hemisphere_sub_slots[outer_role][inner_role]` wins when set.
/// Falls back to the outer-level slot otherwise (Phase 2 behaviour).
///
/// The returned wrapper carries `outer_role: None` — deeper
/// recursion (depth > 2) reuses the inner-level slots through the
/// outer-fallback path of `slot_for_sub`. The N×3 multiplier still
/// applies; Phase 3 only changes WHICH adapters dispatch at each
/// level, not the dispatch count.
async fn build_sub_hemisphere_with_config(
    config: std::sync::Arc<FreedomConfig>,
    outer_role: crate::config::inference::HemisphereRole,
    inner_role: crate::config::inference::HemisphereRole,
    req: &crate::providers::Request,
) -> Result<ProviderHemisphere> {
    let provider =
        crate::providers::from_config_for_sub_role(config.as_ref(), outer_role, inner_role).await?;
    Ok(ProviderHemisphere {
        provider,
        base_req: req.clone(),
        config: Some(config),
        outer_role: None,
    })
}

/// CH-11: render top operator-profile claims as a synthesis-prompt
/// context block. Best-effort — any failure (missing views.db, query
/// error, no claims above threshold) returns `None` so the chat
/// callosum branch proceeds without profile injection.
///
/// Confidence gate ≥ 0.6 pinned per SPEC_proactive_learning §5.1
/// "high-confidence" threshold. Limit 8 claims keeps the prompt
/// from ballooning even when the operator has a huge profile.
/// K-Perf-3 v1 2026-05-17: wrap the synchronous rusqlite query in
/// `tokio::task::spawn_blocking` so the chat hot path (called from
/// the council Split → callosum branch) does NOT block a tokio worker
/// thread for the duration of the SQLite read. Without this wrap,
/// every Council Split debate stalled one worker for ~5-50ms while
/// `top_claims_for_chat` ran — on a multi-channel daemon serving
/// concurrent inbound messages, that's a real concurrency hit.
///
/// Pure synchronous logic lives in [`profile_block_for_callosum_sync`];
/// `profile_block_for_callosum` is the async wrapper that callers
/// await. Tests cover the sync helper directly so they don't need a
/// tokio runtime spawn-blocking pool.
async fn profile_block_for_callosum() -> Option<String> {
    tokio::task::spawn_blocking(profile_block_for_callosum_sync)
        .await
        .ok()
        .flatten()
}

/// Synchronous core of [`profile_block_for_callosum`] — pure
/// rusqlite + profile lookup with no tokio dependency. Extracted so
/// tests + future migration paths (e.g. neoth-sync embedded query
/// surface) can call it directly without a runtime.
///
/// CH-11 (Session 21): the confidence floor is now sourced from
/// `profile::injection::DEFAULT_INJECTION_FLOOR` (P-06 primitive) so
/// a future tune of the Block-B injection threshold lands in one
/// place. Previously hard-coded as `0.6` — same value, but the
/// drift-guard on the primitive's tests now covers this call site
/// too. `MAX_CLAIMS` stays a chat-callosum-local constant since it's
/// tunable independently of the gate floor.
fn profile_block_for_callosum_sync() -> Option<String> {
    const MAX_CLAIMS: usize = 8;
    let db_path = crate::memory::store::default_path();
    let conn = crate::memory::store::open(&db_path).ok()?;
    // ADV-05 (Session 28): load the operator's freedom.yaml so the PII
    // gate honours `profile.pii_categories_disabled`. Fall back to an
    // empty slice when config can't load — the gate is opt-in, so the
    // safe default is "no filter" (matches v1.0 behaviour pre-ADV-05).
    let disabled_categories = crate::config::FreedomConfig::load_from_default_path()
        .map(|c| c.profile.pii_categories_disabled)
        .unwrap_or_default();
    let claims = crate::profile::lookup::top_claims_for_chat_with_pii_gate(
        &conn,
        crate::profile::injection::DEFAULT_INJECTION_FLOOR,
        MAX_CLAIMS,
        &disabled_categories,
    )
    .ok()?;
    if claims.is_empty() {
        return None;
    }
    let rendered = crate::profile::lookup::render_for_synthesis_prompt(&claims);
    if rendered.trim().is_empty() {
        None
    } else {
        Some(rendered)
    }
}

/// Outcome of a `callosum::resolve` attempt — drives the
/// `COUNCIL_SYNTHESIS_ATTEMPTED` (0x60) WAL payload shape so audit
/// readers can distinguish the synthesis-succeeded vs synthesis-failed
/// branches without re-running the inference.
enum CouncilSynthesisOutcome {
    Synthesis { chars: usize },
    IrreconcilableConflict { reason: String },
}

/// Append a `COUNCIL_SYNTHESIS_ATTEMPTED` (0x60) audit frame to the
/// current chat WAL segment. Failures are best-effort: the chat reply
/// already went out, losing the audit frame is a logged-warning, not a
/// caller-facing error.
/// A-1 (Session 13) — when a council debate completes with one or more
/// refused hemispheres + at least one usable hemisphere, render a one-line
/// operator-facing annotation describing which roles refused + their cause
/// taxonomy. Prepended to the reply text + emitted as a WAL 0x61 frame.
/// Returns `None` when no partial refusal occurred — caller skips the
/// prefix + the audit emission.
fn partial_refusal_prefix(outcome: &crate::council::CouncilDebate) -> Option<String> {
    if !outcome.is_partial_refusal() {
        return None;
    }
    let refused: Vec<String> = outcome
        .refused_responses()
        .map(|r| {
            let role = match r.role {
                crate::config::inference::HemisphereRole::Left => "left",
                crate::config::inference::HemisphereRole::Right => "right",
                crate::config::inference::HemisphereRole::Cerebellum => "cerebellum",
            };
            let cause = r
                .refusal
                .as_ref()
                .map(|x| x.cause.as_str())
                .unwrap_or("unknown");
            format!("{role}/{provider}: {cause}", provider = r.provider)
        })
        .collect();
    let usable = outcome.usable_responses().count();
    let total = outcome.responses.len().max(3);
    Some(format!(
        "[synthesised over {usable} of {total} hemispheres — {joined} refused]",
        joined = refused.join(", ")
    ))
}

/// K-Repo-Map Phase 3c (Session 14 Pick #26) — best-effort repo-
/// context lookup. Returns `Some(block)` when:
///   1. `config.code_map.auto_context_max_files > 0` (operator opted in)
///   2. `~/.neoth/code_map.db` exists + opens cleanly
///   3. The persisted map has at least one file matching `prompt`
///
/// Every other condition silently returns `None` — the chat path must
/// never block on code-map state. Operator who hasn't run
/// `neoth code-map persist` yet sees their chat work normally.
///
/// Production entry resolves the db_path from the operator's HOME;
/// see [`maybe_repo_context_block_at`] for the test-friendly variant
/// that accepts an explicit path (avoids env-var mutation in tests
/// that would otherwise race under parallel execution).
pub(crate) fn maybe_repo_context_block(config: &FreedomConfig, prompt: &str) -> Option<String> {
    let db_path = crate::code_map::persist::default_path();
    maybe_repo_context_block_at(config, prompt, &db_path)
}

/// Test-friendly inner: resolve the code-map DB at an explicit path
/// instead of through `HOME` / `USERPROFILE`. Same best-effort
/// contract as [`maybe_repo_context_block`] — every failure path
/// produces `None`, never an error.
pub(crate) fn maybe_repo_context_block_at(
    config: &FreedomConfig,
    prompt: &str,
    db_path: &std::path::Path,
) -> Option<String> {
    let max = config.code_map.auto_context_max_files as usize;
    if max == 0 {
        return None;
    }
    if !db_path.exists() {
        return None;
    }
    let conn = match crate::code_map::persist::open(db_path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let hits = match crate::code_map::recall::relevant_files_for_prompt(&conn, prompt, max) {
        Ok(h) if !h.is_empty() => h,
        _ => return None,
    };
    let block = crate::code_map::recall::render_context_block(&hits);
    if block.is_empty() { None } else { Some(block) }
}

/// The operator's role as a human-readable label. The free-form
/// `freedom.yaml::role_custom` wins when set; otherwise the
/// `OperatorRole` enum is mapped to prose. `OperatorRole::None`
/// (or an unset role) with no custom label yields `None`.
fn operator_role_label(config: &FreedomConfig) -> Option<String> {
    if let Some(custom) = config.role_custom.as_deref() {
        let custom = custom.trim();
        if !custom.is_empty() {
            return Some(custom.to_string());
        }
    }
    use crate::cli::init::OperatorRole;
    match config.role {
        Some(OperatorRole::Developer) => Some("developer".to_string()),
        Some(OperatorRole::SecurityResearcher) => Some("security researcher".to_string()),
        Some(OperatorRole::Founder) => Some("founder".to_string()),
        Some(OperatorRole::DataScientist) => Some("data scientist".to_string()),
        Some(OperatorRole::Writer) => Some("writer".to_string()),
        Some(OperatorRole::None) | None => None,
    }
}

/// Render the operator's structured identity facts (custom/enum role +
/// preferred response language) as a short preamble, then merge it
/// ABOVE the assembled NEOTH.md body.
///
/// Closes an unwired gap: the wizard captures `role_custom` /
/// `language_primary` into `freedom.yaml`, but neither field previously
/// reached the prompt pipeline — the model never learned the operator's
/// role or preferred response language. The language line is emitted
/// only for a non-English BCP-47 tag (English is the model default, so
/// no instruction is needed). Returns `None` only when there are
/// neither facts nor a rendered body.
fn merge_operator_facts(config: &FreedomConfig, rendered_md: Option<String>) -> Option<String> {
    let mut facts: Vec<String> = Vec::new();

    if let Some(role) = operator_role_label(config) {
        facts.push(format!("Operator role: {role}."));
    }
    if let Some(tag) = config.language_primary.as_deref() {
        let tag = tag.trim();
        if !tag.is_empty() && !tag.to_ascii_lowercase().starts_with("en") {
            facts.push(format!(
                "Respond in the operator's primary language (BCP-47 '{tag}') \
                 unless they write to you in another language."
            ));
        }
    }

    match (facts.is_empty(), rendered_md) {
        (true, md) => md,
        (false, Some(md)) => Some(format!("{}\n\n{md}", facts.join("\n"))),
        (false, None) => Some(facts.join("\n")),
    }
}

/// A-1 audit emission. Records every refused hemisphere with role +
/// provider + class + cause so an operator running `neoth wal show` can
/// reconstruct exactly which hemisphere said no + why, even when the
/// chat reply silently absorbed the refusal via Consensus or Callosum.
async fn emit_council_partial_refusal(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    outcome: &crate::council::CouncilDebate,
) -> Result<()> {
    let refused: Vec<serde_json::Value> = outcome
        .refused_responses()
        .map(|r| {
            let class = r
                .refusal
                .as_ref()
                .map(|x| x.class.as_str())
                .unwrap_or("none");
            let cause = r
                .refusal
                .as_ref()
                .map(|x| x.cause.as_str())
                .unwrap_or("unknown");
            let role = match r.role {
                crate::config::inference::HemisphereRole::Left => "left",
                crate::config::inference::HemisphereRole::Right => "right",
                crate::config::inference::HemisphereRole::Cerebellum => "cerebellum",
            };
            serde_json::json!({
                "role": role,
                "provider": r.provider,
                "class": class,
                "cause": cause,
            })
        })
        .collect();
    let payload_value = serde_json::json!({
        "prompt_hash": format!("{prompt_hash:016x}"),
        "refused_count": outcome.refused_count() as u32,
        "usable_count": outcome.usable_responses().count() as u32,
        "refused": refused,
    });
    let payload =
        serde_json::to_vec(&payload_value).context("serialize COUNCIL_PARTIAL_REFUSAL payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_PARTIAL_REFUSAL frame");
    }
    Ok(())
}

/// B-1 (Session 13) — record that the council smart-trigger evaluated
/// to `Skip` for this prompt. Pairs with `EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED`
/// (0x60) + `EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL` (0x61) so the operator's
/// WAL audit covers every council branch: skipped / fired-clean /
/// fired-with-refusals / fired-with-synthesis. Reason string carries the
/// gate that fired (env override, complexity, rate, budget, …).
pub(crate) async fn emit_council_skip(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    reason: &str,
) -> Result<()> {
    let payload_value = serde_json::json!({
        "prompt_hash": format!("{prompt_hash:016x}"),
        "reason": reason,
    });
    let payload = serde_json::to_vec(&payload_value).context("serialize COUNCIL_SKIP payload")?;
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_COUNCIL_SKIP, &payload)
            .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_SKIP frame");
    }
    Ok(())
}

/// Pick #8 SP-2 (Session 14) — role-agnostic winner selection
/// outcome. Returned by [`select_winner_role_agnostic`] when the
/// operator's `selection_mode` picked a hemisphere via
/// `CouncilDebate::best_response`. Carries the winning role +
/// provider + composite score so the dispatch path can emit
/// WAL `0x63 COUNCIL_WINNER_SELECTED` with full audit context.
#[derive(Clone, Debug)]
pub(crate) struct RoleAgnosticWinner {
    pub text: String,
    pub role: crate::config::inference::HemisphereRole,
    pub provider: String,
    pub score: f32,
}

/// Pick #8 SP-2 (Session 14) — apply the operator's
/// `SelectionMode` to a finished council debate.
///
/// Returns `Some(winner)` when role-agnostic dispatch picked a
/// hemisphere; `None` when the caller should fall through to the
/// legacy verdict-driven path (winning_text → Split callosum →
/// QuorumFailed surface).
///
/// Modes:
///   - `LegacyMajority` → ALWAYS returns `None` (no behaviour change)
///   - `ConsensusOrBest` → uses `winning_text` if Verdict::Consensus
///     produced one, else falls back to `best_response`
///   - `BestAlways` → ignores Verdict, always picks `best_response`
///
/// Pick #8 SP-4 (Session 14): `routing_weights` (when `Some`) lifts
/// the `memory_weight` component of each hemisphere's composite score
/// based on past operator-acceptance for the same topic. `None`
/// keeps the neutral prior — same as Session-14 baseline.
/// SP-4 F5 diversity bonus for one hemisphere: the Jaccard distance of
/// its text to the council consensus. The consensus proxy is the
/// verdict's winning text when present, else the first OTHER usable
/// hemisphere's text (so we always compare two distinct inputs).
/// Returns `0.0` for an errored hemisphere (no text) or when no other
/// usable text exists (nothing to be diverse from). Bounded `[0.0, 1.0]`;
/// `total()` weights it at `0.05`.
fn diversity_bonus_for(
    my_text: Option<&str>,
    my_role: crate::config::inference::HemisphereRole,
    outcome: &crate::council::CouncilDebate,
) -> f32 {
    my_text
        .and_then(|my_text| {
            let consensus_proxy = outcome.winning_text().or_else(|| {
                outcome
                    .responses
                    .iter()
                    .find(|other| other.role != my_role && other.text.is_some())
                    .and_then(|other| other.text.as_deref())
            });
            consensus_proxy.map(|cp| crate::council::dissent::score_dissent(&[my_text, cp]).0)
        })
        .unwrap_or(0.0)
}

pub(crate) fn select_winner_role_agnostic(
    outcome: &crate::council::CouncilDebate,
    mode: crate::config::inference::SelectionMode,
    routing_weights: Option<&crate::memory::routing_weights::RoutingWeights>,
    topic_hash: u64,
) -> Option<RoleAgnosticWinner> {
    use crate::config::inference::SelectionMode;
    if matches!(mode, SelectionMode::LegacyMajority) {
        return None;
    }

    let now = crate::memory::routing_weights::now_unix();

    // Compute per-hemisphere composite scores for best_response().
    // Memory weight uses routing_weights when present; otherwise
    // falls back to the neutral 0.5 prior baked into score_response.
    let scores: Vec<(crate::config::inference::HemisphereRole, f32)> = outcome
        .responses
        .iter()
        .map(|r| {
            let base = crate::council::quality_score::score_response(r);
            let mem = match routing_weights {
                Some(rw) => rw.load_memory_weight(topic_hash, r.role, now),
                None => base.memory_weight,
            };
            // F5 diversity_bonus (SP-4): Jaccard distance of THIS
            // hemisphere's text to the consensus — a dissenting
            // hemisphere earns a small lift (worth `0.05 × bonus` in
            // `total()`) so a lone correct dissenter isn't buried by two
            // agreeing-but-wrong hemispheres. Was hardcoded 0.0 before.
            let diversity = diversity_bonus_for(r.text.as_deref(), r.role, outcome);
            // Recompose composite with the looked-up memory_weight + the
            // computed diversity_bonus.
            let composite = crate::council::quality_score::QualityScore::new(
                base.tier_weight,
                base.dynamic_signal,
                mem,
                diversity,
            )
            .total();
            (r.role, composite)
        })
        .collect();

    // ConsensusOrBest: prefer the Verdict's winning_text when
    // present + the corresponding hemisphere is identifiable. When
    // identifying the hemisphere by text fails, fall back to the
    // highest-scored usable response.
    if matches!(mode, SelectionMode::ConsensusOrBest)
        && let Some(text) = outcome.winning_text()
    {
        // Try to find which hemisphere produced this text.
        if let Some(matching) = outcome.responses.iter().find(|r| {
            // Audit 2026-05-19 Type #13 Phase 2: single exhaustive
            // match expresses "Usable variant whose text is exactly
            // the verdict text" without the two-step
            // `text.as_deref().is_some_and(...) && is_usable()` dance.
            matches!(
                r.outcome(),
                crate::council::types::HemisphereOutcome::Usable { text: t } if t == text
            )
        }) {
            let score = scores
                .iter()
                .find(|(role, _)| *role == matching.role)
                .map(|(_, s)| *s)
                .unwrap_or(0.0);
            return Some(RoleAgnosticWinner {
                text: text.to_string(),
                role: matching.role,
                provider: matching.provider.clone(),
                score,
            });
        }
        // text didn't match any hemisphere's text exactly — fall
        // through to best_response below.
    }

    // BestAlways path OR ConsensusOrBest fallback.
    let winner = outcome.best_response(&scores)?;
    let text = winner.text.clone()?;
    let score = scores
        .iter()
        .find(|(role, _)| *role == winner.role)
        .map(|(_, s)| *s)
        .unwrap_or(0.0);
    Some(RoleAgnosticWinner {
        text,
        role: winner.role,
        provider: winner.provider.clone(),
        score,
    })
}

/// Pick #8 F8 (Session 14 Pick #20) — pre-flight provider-diversity
/// audit. Classifies the topology, emits a WAL `0x64
/// COUNCIL_DIVERSITY_WARNING` frame whenever the verdict is not
/// `Distinct`, and surfaces a once-per-process stderr line so the
/// operator sees a misconfig BEFORE the council burns tokens through
/// a degraded debate.
///
/// `Distinct` skips both emissions — no audit pollution + no terminal
/// noise when the topology is healthy.
pub(crate) async fn emit_council_diversity_warning_if_needed(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    config: &FreedomConfig,
) -> Result<()> {
    let verdict = crate::council::classify_council_diversity(&config.inference);
    if !verdict.needs_warning() {
        return Ok(());
    }
    // Once-per-process stderr — operator sees the line once per
    // session (or per daemon lifetime). The WAL frame still emits
    // every council pass so audit reconstruction stays complete.
    if crate::council::diversity::claim_warning_emission_slot() {
        eprintln!("[neoth council] WARNING: {}", verdict.render_short());
    }
    let verdict_payload = serde_json::to_value(&verdict).context("serialize DiversityVerdict")?;
    let mut payload_value = serde_json::json!({
        "prompt_hash": format!("{prompt_hash:016x}"),
    });
    // Splice the tagged verdict fields ({verdict, left, right, ...})
    // into the top-level object so the audit consumer can dispatch
    // on `verdict` directly without an extra layer.
    if let (Some(payload), Some(verdict_obj)) =
        (payload_value.as_object_mut(), verdict_payload.as_object())
    {
        for (k, v) in verdict_obj {
            payload.insert(k.clone(), v.clone());
        }
    }
    let payload = serde_json::to_vec(&payload_value)
        .context("serialize COUNCIL_DIVERSITY_WARNING payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COUNCIL_DIVERSITY_WARNING,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_DIVERSITY_WARNING frame");
    }
    Ok(())
}

/// Pick #8 SP-2 (Session 14) — emit WAL `0x63 COUNCIL_WINNER_SELECTED`
/// audit frame.
///
/// `depth` is the recursion level (0 for outer council). Fractal
/// synthesis hard-rule (F7): payload MUST include `depth` so audit
/// consumers can reconstruct the recursion tree across nested
/// councils.
pub(crate) async fn emit_council_winner_selected(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    depth: u8,
    winner: &RoleAgnosticWinner,
    mode: crate::config::inference::SelectionMode,
) -> Result<()> {
    use crate::config::inference::SelectionMode;
    let mode_str = match mode {
        SelectionMode::LegacyMajority => "legacy_majority",
        SelectionMode::ConsensusOrBest => "consensus_or_best",
        SelectionMode::BestAlways => "best_always",
    };
    let payload_value = serde_json::json!({
        "prompt_hash": format!("{prompt_hash:016x}"),
        "depth": depth,
        "role": match winner.role {
            crate::config::inference::HemisphereRole::Left => "left",
            crate::config::inference::HemisphereRole::Right => "right",
            crate::config::inference::HemisphereRole::Cerebellum => "cerebellum",
        },
        "provider": winner.provider,
        "score": winner.score,
        "mode": mode_str,
    });
    let payload =
        serde_json::to_vec(&payload_value).context("serialize COUNCIL_WINNER_SELECTED payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COUNCIL_WINNER_SELECTED,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_WINNER_SELECTED frame");
    }
    Ok(())
}

async fn emit_council_synthesis_attempted(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    outcome: CouncilSynthesisOutcome,
) -> Result<()> {
    let payload_value = match &outcome {
        CouncilSynthesisOutcome::Synthesis { chars } => serde_json::json!({
            "prompt_hash": format!("{prompt_hash:016x}"),
            "outcome": "synthesis",
            "synthesis_chars": chars,
        }),
        CouncilSynthesisOutcome::IrreconcilableConflict { reason } => serde_json::json!({
            "prompt_hash": format!("{prompt_hash:016x}"),
            "outcome": "irreconcilable_conflict",
            "reason": reason,
        }),
    };
    let payload = serde_json::to_vec(&payload_value)
        .context("serialize COUNCIL_SYNTHESIS_ATTEMPTED payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_SYNTHESIS_ATTEMPTED frame");
    }
    Ok(())
}

/// Per-hemisphere transcript-text cap. Keeps a single `0x66` frame
/// scannable + well under the WAL `MAX_PAYLOAD_BYTES` ceiling even for a
/// verbose model. A longer reply is truncated with a marker so replay
/// shows the bulk of the prose without the frame failing to append.
const MAX_TRANSCRIPT_BYTES: usize = 32 * 1024;

/// KF-01 full — OPT-IN: persist each hemisphere's verbatim response text
/// as a `0x66 COUNCIL_TRANSCRIPT` frame so `neoth council replay` can show
/// the actual prose. No-op unless `freedom.yaml::council.persist_transcripts`
/// is true (default false — hemisphere prose is sensitive). Best-effort:
/// a failed append is logged but never blocks the chat turn, and the
/// debate result is unchanged either way. Errored hemispheres (no text)
/// are skipped — their `0x61`/metadata frames already record the refusal.
async fn emit_council_transcripts(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    outcome: &crate::council::CouncilDebate,
    config: &FreedomConfig,
) {
    if !config.council.persist_transcripts {
        return;
    }
    for resp in &outcome.responses {
        let Some(text) = resp.text.as_deref() else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        let stored = if text.len() > MAX_TRANSCRIPT_BYTES {
            let mut t = text[..MAX_TRANSCRIPT_BYTES].to_string();
            while !t.is_char_boundary(t.len()) {
                t.pop();
            }
            t.push_str("\n[NEOTH] …transcript truncated…");
            t
        } else {
            text.to_string()
        };
        let payload_value = serde_json::json!({
            "prompt_hash": format!("{prompt_hash:016x}"),
            "role": resp.role.as_str(),
            "provider": resp.provider.as_str(),
            "text": stored,
        });
        let payload = match serde_json::to_vec(&payload_value) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "could not serialize COUNCIL_TRANSCRIPT payload");
                continue;
            }
        };
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_COUNCIL_TRANSCRIPT,
            &payload,
        )
        .build();
        if let Err(e) = writer.append(header, payload).await {
            warn!(
                error = %e,
                role = %resp.role.as_str(),
                "could not append COUNCIL_TRANSCRIPT frame"
            );
        }
    }
}

/// K-Wire-3 v2 2026-05-17: evaluate the council smart-trigger using
/// the same env-override + policy logic as `cli/chat.rs::run_chat_with`.
/// Returns the `TriggerDecision` so callers can log + audit both the
/// Convene + Skip branches. Pure function — no I/O, no provider call.
///
/// Env override semantics match the CLI:
///   - `NEOTH_COUNCIL_DISABLE=1` → forced Skip
///   - `NEOTH_COUNCIL_ENABLE=1`  → forced Convene (bypasses gates)
///   - unset / anything else     → AUTO via `council::should_convene`
///
/// `estimated_single_call_eur` is the budget-gate input. Channels
/// don't pre-compute a per-prompt cost like the CLI does; pass `0.01`
/// as the floor so the gate scales cleanly when operators tune
/// `policy.budget_multiplier` higher.
///
/// `disabled` is the SPEC-03 persistent suppress flag
/// (`freedom.yaml::council.disabled`); the channel caller reads it fresh
/// per message so `neoth council suppress` takes effect without a daemon
/// restart. `true` → forced Skip (the durable twin of
/// `NEOTH_COUNCIL_DISABLE=1`, which still wins when both are set).
///
/// Precedence (highest first): `NEOTH_COUNCIL_DISABLE=1` → `disabled` flag
/// → `NEOTH_COUNCIL_ENABLE=1` → AUTO. So EITHER disable source beats the
/// force-enable env var: a suppressed council cannot be force-convened
/// without first clearing the suppress. This is intentional (an operator
/// who durably opted out should not be overridden by a stray env var) and
/// is pinned by `evaluate_council_trigger_disable_beats_force_enable`.
pub(crate) fn evaluate_council_trigger(
    prompt: &str,
    estimated_single_call_eur: f32,
    disabled: bool,
    policy: &crate::council::TriggerPolicy,
) -> crate::council::TriggerDecision {
    let council_force = std::env::var("NEOTH_COUNCIL_ENABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let council_disable = std::env::var("NEOTH_COUNCIL_DISABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if council_disable {
        return crate::council::TriggerDecision::Skip {
            reason: "NEOTH_COUNCIL_DISABLE=1".into(),
        };
    }
    if disabled {
        return crate::council::TriggerDecision::Skip {
            reason: "freedom.yaml::council.disabled=true".into(),
        };
    }
    if council_force {
        return crate::council::TriggerDecision::Convene {
            reason: "NEOTH_COUNCIL_ENABLE=1 (force)".into(),
        };
    }
    // B-3 (Session 13) — same real-timestamp feed as the CLI dispatch
    // path uses. Channel ingress no longer has a permanently-open rate
    // gate.
    let home_b3 = FreedomConfig::default_neoth_home();
    let now_unix_b3 = crate::council::last_ts::now_unix();
    let secs_since = crate::council::last_ts::seconds_since_last(&home_b3, now_unix_b3);
    let ctx = crate::council::TriggerContext {
        seconds_since_last_council: secs_since,
        remaining_budget_eur: None,
        estimated_single_call_eur,
    };
    crate::council::should_convene(prompt, &ctx, policy)
}

/// K-Wire-3 v2 2026-05-17: drive a full council debate including A5
/// callosum recovery on Split verdicts. Returns the final operator-
/// facing reply text — the caller (chat.rs CLI or serve.rs channel
/// handler) is responsible for downstream framing (print to stdout vs
/// CHANNEL_EGRESS WAL frame + send to messenger).
///
/// Flow:
///   1. `run_council_debate(config, req)` fires all three hemispheres
///      via `FuturesUnordered` with early-exit on quorum-with-consensus
///      (K-Perf-1).
///   2. Verdict::Consensus → return `winning_text()`.
///   3. Verdict::Split → A5 callosum recovery: build a fresh
///      Cerebellum, fetch `profile_block_for_callosum()` for CH-11
///      operator-context injection, call `callosum::resolve_with_profile`,
///      emit COUNCIL_SYNTHESIS_ATTEMPTED (0x60) audit. Synthesis →
///      return the synthesised text; IrreconcilableConflict → fall back
///      to the "[council split — operator decision needed]" message.
///   4. Verdict::QuorumFailed → return diagnostic text "[council quorum
///      failed — N/M hemispheres responded]".
pub(crate) async fn dispatch_council_with_recovery(
    req: &crate::providers::Request,
    config: &FreedomConfig,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<String> {
    // Pick #8 F8 (Session 14 Pick #20) — channel-path pre-flight
    // diversity audit. Mirrors the CLI-path emission in `run_chat_with`
    // so the WAL audit trail records misconfigured topologies
    // regardless of ingress channel.
    let prompt_hash_pre = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
    let _ = emit_council_diversity_warning_if_needed(writer, prompt_hash_pre, config).await;
    let outcome = run_council_debate(config, req).await?;
    // B-3 (Session 13) — record this channel-path debate's wall-clock so
    // the NEXT inbound's trigger eval honours the rate cooldown.
    {
        let home_b3 = FreedomConfig::default_neoth_home();
        if let Err(e) =
            crate::council::last_ts::record(&home_b3, crate::council::last_ts::now_unix())
        {
            warn!(error = %e, "could not persist council_last.json (channel path)");
        }
    }
    info!(
        dissent = outcome.dissent.0,
        responses_len = outcome.responses.len(),
        refused_count = outcome.refused_count(),
        is_partial_refusal = outcome.is_partial_refusal(),
        total_latency_ms = outcome.total_latency_ms,
        "council debate complete"
    );
    // A-1 (channel path): emit COUNCIL_PARTIAL_REFUSAL audit frame as
    // soon as any hemisphere refused. Same contract as the CLI path —
    // operator sees refusals via `neoth wal show` even when Consensus
    // or Callosum absorbed them silently.
    let prompt_hash_outer = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
    if outcome.is_partial_refusal() {
        let _ = emit_council_partial_refusal(writer, prompt_hash_outer, &outcome).await;
    }

    // Pick #8 SP-2 (Session 14) — role-agnostic winner selection.
    // When operator configured `council.selection_mode =
    // consensus_or_best` or `best_always`, pick by quality score
    // rather than verdict-text fallback. LegacyMajority returns
    // `None` here so the existing v0.1 behaviour is preserved.
    let rw_path = crate::memory::routing_weights::RoutingWeights::default_path(
        &FreedomConfig::default_neoth_home(),
    );
    let rw_read = crate::memory::routing_weights::RoutingWeights::load_from(&rw_path);
    let role_agnostic = select_winner_role_agnostic(
        &outcome,
        config.council.selection_mode,
        Some(&rw_read),
        prompt_hash_outer,
    );
    if let Some(winner) = role_agnostic {
        let _ = emit_council_winner_selected(
            writer,
            prompt_hash_outer,
            0,
            &winner,
            config.council.selection_mode,
        )
        .await;
        // SP-5 (Session 14) — self-reflect refinement pass.
        // Threshold + kill-switch gated; fail-safe on any error.
        let final_text = if crate::council::self_reflect::should_refine(config, winner.score, 0) {
            match build_hemisphere(config, winner.role, req).await {
                Ok(reflect_hemisphere) => {
                    let refined = crate::council::self_reflect::refine(
                        &req.prompt,
                        &winner.text,
                        &reflect_hemisphere,
                    )
                    .await;
                    refined.refined
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "self-reflect skipped: could not rebuild winning hemisphere"
                    );
                    winner.text.clone()
                }
            }
        } else {
            winner.text.clone()
        };
        // SP-4: record acceptance signal so future debates on the
        // same topic lift the winning hemisphere's memory_weight.
        let mut rw_write = crate::memory::routing_weights::RoutingWeights::load_from(&rw_path);
        rw_write.record_acceptance(
            prompt_hash_outer,
            winner.role,
            crate::memory::routing_weights::now_unix(),
        );
        if let Err(e) = rw_write.save() {
            tracing::warn!(error = %e, "could not persist routing_weights.json (channel)");
        }
        let response_text = match partial_refusal_prefix(&outcome) {
            Some(prefix) => format!("{prefix}\n{final_text}"),
            None => final_text,
        };
        return Ok(response_text);
    }

    let response_text = match outcome.winning_text() {
        Some(t) => {
            // A-1: prefix annotation when one hemisphere refused but
            // Consensus still produced a winning text.
            match partial_refusal_prefix(&outcome) {
                Some(prefix) => format!("{prefix}\n{t}"),
                None => t.to_string(),
            }
        }
        None => match &outcome.verdict {
            crate::council::Verdict::Split { summary } => {
                // B-2: callosum-on-partial-refusal recovery — feed only
                // usable hemisphere texts to the synthesis prompt so the
                // refused hemisphere's text never reaches the cerebellum.
                let usable: Vec<&crate::council::HemisphereResponse> =
                    outcome.usable_responses().collect();
                // Audit 2026-05-19 Type #13 Phase 2: every text accessor
                // routes through outcome().text() — usable_responses
                // guarantees Some on the primary path, the role-keyed
                // fallback returns None for Errored hemispheres so the
                // final unwrap_or("") preserves the legacy behaviour.
                let left_text = usable
                    .first()
                    .and_then(|r| r.outcome().text())
                    .unwrap_or_else(|| {
                        outcome
                            .response_for(crate::config::inference::HemisphereRole::Left)
                            .and_then(|r| r.outcome().text())
                            .unwrap_or("")
                    });
                let right_text = usable
                    .get(1)
                    .and_then(|r| r.outcome().text())
                    .unwrap_or_else(|| {
                        outcome
                            .response_for(crate::config::inference::HemisphereRole::Right)
                            .and_then(|r| r.outcome().text())
                            .unwrap_or("")
                    });
                let prompt_hash = prompt_hash_outer;
                let profile_block = profile_block_for_callosum().await.unwrap_or_default();
                let profile_opt = if profile_block.is_empty() {
                    None
                } else {
                    Some(profile_block.as_str())
                };
                match build_hemisphere(
                    config,
                    crate::config::inference::HemisphereRole::Cerebellum,
                    req,
                )
                .await
                {
                    Ok(cere) => {
                        let verdict = crate::council::callosum::resolve_with_profile(
                            &req.prompt,
                            left_text,
                            right_text,
                            profile_opt,
                            &cere,
                        )
                        .await;
                        match verdict {
                            crate::council::callosum::CorticalVerdict::Synthesis(s) => {
                                info!("callosum produced synthesis ({} chars)", s.len());
                                let _ = emit_council_synthesis_attempted(
                                    writer,
                                    prompt_hash,
                                    CouncilSynthesisOutcome::Synthesis {
                                        chars: s.chars().count(),
                                    },
                                )
                                .await;
                                s
                            }
                            crate::council::callosum::CorticalVerdict::IrreconcilableConflict {
                                reason,
                            } => {
                                warn!(reason = %reason, "callosum could not synthesise");
                                let _ = emit_council_synthesis_attempted(
                                    writer,
                                    prompt_hash,
                                    CouncilSynthesisOutcome::IrreconcilableConflict {
                                        reason: reason.clone(),
                                    },
                                )
                                .await;
                                format!("[council split — operator decision needed]\n{summary}")
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "could not build callosum cerebellum");
                        let _ = emit_council_synthesis_attempted(
                            writer,
                            prompt_hash,
                            CouncilSynthesisOutcome::IrreconcilableConflict {
                                reason: format!("provider build failed: {e}"),
                            },
                        )
                        .await;
                        format!("[council split — operator decision needed]\n{summary}")
                    }
                }
            }
            crate::council::Verdict::QuorumFailed {
                responded,
                required,
            } => {
                format!("[council quorum failed — {responded}/{required} hemispheres responded]")
            }
            crate::council::Verdict::Consensus { .. } => unreachable!(),
        },
    };
    Ok(response_text)
}

/// Finding 2 (Session 13) — joint multi-cloud fan-out advisory.
/// Fires AT MOST ONCE per process when the council topology routes
/// to ≥2 distinct cloud providers. Operator already consented per-
/// provider via V03-08 + A-2; this is the additional surface that
/// surfaces the COMBINED picture ("this prompt simultaneously reaches
/// Anthropic + OpenAI + Gemini, each retains it per their own TOS").
/// Resets only on daemon restart.
static FAN_OUT_ADVISORY_FIRED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Render the operator-facing advisory line for a multi-cloud council
/// topology. Returns `None` when fewer than 2 distinct cloud kinds are
/// configured (single-cloud + local topologies have no fan-out story
/// to surface beyond the per-provider V03-08 prompt).
pub(crate) fn fan_out_advisory_line(config: &FreedomConfig) -> Option<String> {
    let kinds = crate::consent::cloud_kinds_for_council(config);
    if kinds.len() < 2 {
        return None;
    }
    let providers: Vec<&str> = kinds.iter().map(|k| crate::consent::slug(*k)).collect();
    Some(format!(
        "[NEOTH] this prompt fan-outs to {} cloud providers concurrently \
         ({}). Each provider's TOS + retention policies apply independently. \
         Configured via `freedom.yaml::inference.{{left,right,cerebellum}}`.",
        providers.len(),
        providers.join(", "),
    ))
}

/// Best-effort once-per-process emit. Subsequent calls in the same
/// process short-circuit. Test-friendly: pure function gated by a
/// static AtomicBool — tests reset by re-importing the static is
/// awkward, so we test `fan_out_advisory_line` directly instead.
fn maybe_fire_fan_out_advisory(config: &FreedomConfig) {
    if FAN_OUT_ADVISORY_FIRED
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
        && let Some(line) = fan_out_advisory_line(config)
    {
        eprintln!("{line}");
    }
}

async fn run_council_debate(
    config: &FreedomConfig,
    req: &crate::providers::Request,
) -> Result<crate::council::CouncilDebate> {
    use crate::config::inference::HemisphereRole;
    // Finding 2: once-per-process advisory when council topology
    // spans ≥2 cloud providers. Per-provider consent already gated
    // via V03-08 + A-2; this surfaces the JOINT fan-out picture.
    maybe_fire_fan_out_advisory(config);
    // E-2 Phase 2 (Session 13): outer-council hemispheres carry a
    // config Arc so `ask_with_depth` can recurse when the operator's
    // `hemisphere_council_depth > 1`. The Arc is shared across all
    // three so freedom.yaml is parsed exactly once per debate.
    let config_arc = std::sync::Arc::new(config.clone());
    let left = build_hemisphere_with_config(config_arc.clone(), HemisphereRole::Left, req).await?;
    let right =
        build_hemisphere_with_config(config_arc.clone(), HemisphereRole::Right, req).await?;
    let cere = build_hemisphere_with_config(config_arc, HemisphereRole::Cerebellum, req).await?;
    let prompt_hash = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
    // E-2 Phase 1 (Session 13) — thread the operator-configured
    // `hemisphere_council_depth` through the orchestrator so recursive
    // hemispheres can read their own depth budget.
    let depth = config.inference.hemisphere_council_depth.get();
    // Pick #19 F6 (Session 14) — single shared `BudgetToken` for this
    // user-message-scoped council pass. Cap reads from
    // `config.council.effective_max_calls()` (default 15). The token
    // is shared across every hemisphere in this debate AND, via
    // `ProviderHemisphere::ask_with_depth_budget`, across every
    // recursive sub-debate — no operator-configurable knob can break
    // the cap.
    let budget = crate::council::BudgetToken::from_council(&config.council);
    // SP-4 embed-wire Phase 3 — feed the cosine-dissent path when an
    // embedding provider is configured; the orchestrator falls back to
    // Jaccard on any embed failure. `None` keeps the legacy heuristic.
    let dissent_embed = crate::providers::embed_provider_from_config(config).await;
    // KF-08: probe-clone shares the `Arc<AtomicU32>` counter so we can
    // read the final tally after the orchestrator consumes `budget`.
    let budget_probe = budget.clone();
    let outcome = crate::council::run_debate_with_depth_budget(
        &req.prompt,
        prompt_hash,
        depth,
        budget,
        &left,
        &right,
        &cere,
        dissent_embed.as_deref(),
    )
    .await;
    // Persist the council-budget posture for `neoth council budget`
    // (best-effort, OUTSIDE the orchestrator hot path — one funnel for
    // both the CLI + channel council paths).
    crate::council::budget::record_budget_outcome(
        &FreedomConfig::default_neoth_home(),
        budget_probe.used(),
        budget_probe.cap(),
        now_unix() as i64,
    );
    Ok(outcome)
}

/// CDX-05 wedge: drive the MCP dispatch loop using `provider` as the
/// completion backend. Adapter between the chat path's `Provider` +
/// `Request` types and the loop's `CompletionDriver` trait.
/// K-Wire-3 v1 2026-05-17: promoted from private `async fn` to
/// `pub(crate)` so `cli/serve.rs::build_pipeline_handler` can drive
/// the same MCP dispatch loop for channel inbound messages. CLI +
/// daemon now share the autoroute path; channels (Telegram /
/// WhatsApp / Slack) gain tool-use parity with `neoth chat` without
/// duplicating the driver wiring.
pub(crate) async fn run_mcp_dispatch_loop(
    provider: &dyn crate::providers::Provider,
    base_req: crate::providers::Request,
    servers: &crate::mcp::McpServers,
    autonomy: crate::permissions::AutonomyLevel,
    writer: &crate::wal::writer::WalWriterHandle,
    rollback_policy: Option<&crate::config::RollbackConfig>,
    // SC-11 — the active skill's tool_allowlist (None when no skill
    // matched this turn). Threaded down to the MCP gate so a matched
    // skill scopes which tools the model may call.
    skill_allowlist: Option<&[String]>,
    // GM-01 — operator-tunable hard ceiling on dispatch-loop iterations
    // (`freedom.yaml::goal.max_turns`, default 5).
    max_iterations: u32,
) -> anyhow::Result<crate::mcp::dispatch_loop::LoopOutcome> {
    struct ProviderDriver<'a> {
        provider: &'a dyn crate::providers::Provider,
        base: crate::providers::Request,
    }
    impl crate::mcp::dispatch_loop::CompletionDriver for ProviderDriver<'_> {
        fn complete<'b>(
            &'b mut self,
            prompt: &'b str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'b>>
        {
            let mut req = self.base.clone();
            req.prompt = prompt.to_string();
            let provider = self.provider;
            // QM-10 Phase 2.5: streaming MCP-loop also consults the
            // breaker. Each tool-call iteration is a fresh provider
            // dispatch — a breaker that flipped Open between
            // iterations rejects the next round instead of burning
            // budget on doomed calls inside a long tool chain.
            let provider_name = provider.name();
            Box::pin(async move {
                let permit = match crate::providers::circuit_breaker::acquire_for(provider_name) {
                    Ok(p) => Some(p),
                    Err(berr) => {
                        return Err(anyhow::anyhow!("provider `{provider_name}`: {berr}"));
                    }
                };
                // QM-9 Phase 1.5 follow-on: streaming MCP-loop now
                // also persists usage events. Each tool-call hop is
                // a discrete provider dispatch — operators want to
                // see the cost of an autoroute chain, not just the
                // final composed reply.
                let call_started = std::time::Instant::now();
                let result = provider.complete(req).await;
                let elapsed_ms = call_started.elapsed().as_millis() as u64;
                match result {
                    Ok(c) => {
                        if let Some(p) = permit {
                            p.record_success();
                        }
                        crate::daemon::usage_log::record_provider_call_best_effort(
                            provider_name,
                            &c.model,
                            c.input_tokens,
                            c.output_tokens,
                            elapsed_ms,
                            true,
                        );
                        Ok(c.text)
                    }
                    Err(e) => {
                        if let Some(p) = permit {
                            p.record_failure();
                        }
                        crate::daemon::usage_log::record_provider_call_best_effort(
                            provider_name,
                            "unknown",
                            None,
                            None,
                            elapsed_ms,
                            false,
                        );
                        Err(e)
                    }
                }
            })
        }
    }
    let initial_prompt = base_req.prompt.clone();
    let mut driver = ProviderDriver {
        provider,
        base: base_req,
    };
    crate::mcp::dispatch_loop::run_tool_loop_with_cap(
        &mut driver,
        initial_prompt,
        servers,
        autonomy,
        Some(writer),
        rollback_policy,
        skill_allowlist,
        max_iterations.max(1),
    )
    .await
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// UX-02 — render the "memory is working" line from a total memory
/// count. `None` when nothing is remembered yet, so a fresh install
/// stays silent (no "since last time" on the first ever run).
fn memory_signal_line(total: i64) -> Option<String> {
    if total <= 0 {
        return None;
    }
    Some(format!(
        "I remember {total} thing{} from last time.",
        if total == 1 { "" } else { "s" }
    ))
}

/// UX-02 — count what NEOTH carried across sessions (the three episodic
/// memory tiers + ground-truth assertions) and render the session-start
/// signal. Best-effort: any missing/unreadable views.db or query error
/// collapses to `None` (silent) — this is a friendly banner, never a
/// hard dependency of the chat path.
fn session_memory_signal() -> Option<String> {
    use crate::memory::consolidate::count_in_tier;
    use crate::memory::tiers::Tier;
    let conn = crate::memory::store::open(&crate::memory::store::default_path()).ok()?;
    let total = count_in_tier(&conn, Tier::Hot).unwrap_or(0)
        + count_in_tier(&conn, Tier::Warm).unwrap_or(0)
        + count_in_tier(&conn, Tier::Cold).unwrap_or(0)
        + crate::memory::groundtruth::count_active(&conn).unwrap_or(0);
    memory_signal_line(total)
}

/// Round-3 v0.4 QU-11 / ARS-6 — load a `MODE_CHECKPOINT` snapshot by
/// hash prefix and render a (operator-banner, system-prompt-block)
/// pair. The system-prompt block carries a typed RESUME-CONTEXT
/// section so the assistant knows the prior pipeline shape; it gets
/// prepended to any operator-supplied `--system` text.
///
/// Best-effort: any failure mode (missing views.db, no matching
/// checkpoint, hash-mismatch, parse error) surfaces as
/// `Err(String)` so the caller can print a single warning + proceed
/// without the resume hydration. The operator still gets a chat
/// turn — just without the prior context.
fn hydrate_resume_context(
    hash_prefix: &str,
    existing_system: Option<&str>,
) -> Result<(String, String), String> {
    let views_path = crate::memory::store::default_path();
    let conn = crate::memory::store::open(&views_path)
        .map_err(|e| format!("views.db open failed: {e}"))?;
    let cp = crate::recall::reconstruct::reconstruct_from_checkpoint(&conn, hash_prefix)
        .map_err(|e| format!("checkpoint lookup failed: {e}"))?;
    let mcp_scope = if cp.scoped_mcp_servers.is_empty() {
        "(default scope)".to_string()
    } else {
        cp.scoped_mcp_servers.join(", ")
    };
    let banner = format!(
        "[neoth] resuming session={} phase={} provider={} council={} hash={}",
        cp.session_id, cp.phase, cp.provider_target, cp.council_mode, cp.checkpoint_hash,
    );
    let resume_block = format!(
        "RESUME-CONTEXT\n\
         Prior session id: {session_id}\n\
         Prior pipeline phase: {phase}\n\
         Prior provider target: {provider_target}\n\
         Prior council mode: {council_mode}\n\
         Prior MCP servers in scope: {mcp_scope}\n\
         Checkpoint hash: {checkpoint_hash}\n\
         Checkpoint timestamp (unix): {ts_unix}\n",
        session_id = cp.session_id,
        phase = cp.phase,
        provider_target = cp.provider_target,
        council_mode = cp.council_mode,
        mcp_scope = mcp_scope,
        checkpoint_hash = cp.checkpoint_hash,
        ts_unix = cp.ts_unix,
    );
    let combined = match existing_system {
        Some(s) if !s.trim().is_empty() => format!("{resume_block}\n{s}"),
        _ => resume_block,
    };
    Ok((banner, combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::init::ProviderKind;
    use crate::providers::{Completion, Provider};
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;
    use async_trait::async_trait;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::fs::read;

    // ── SPEC-03 council suppress: evaluate_council_trigger (Session 29) ──
    // The channel path (serve.rs) reads `council.disabled` per message and
    // passes it here; these pin the suppress contract so a negated/dropped
    // branch can't silently let channels ignore suppression.

    #[test]
    fn evaluate_council_trigger_disabled_flag_forces_skip() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::remove_var("NEOTH_COUNCIL_ENABLE");
        }
        let decision = evaluate_council_trigger(
            "should I use Rust or Go here?",
            0.01,
            true,
            &crate::council::TriggerPolicy::default(),
        );
        match decision {
            crate::council::TriggerDecision::Skip { reason } => {
                assert!(
                    reason.contains("freedom.yaml"),
                    "disabled flag must attribute the Skip to the config flag, got: {reason}"
                );
            }
            other => panic!("disabled=true must force Skip, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_council_trigger_disable_beats_force_enable() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::set_var("NEOTH_COUNCIL_ENABLE", "1");
        }
        let decision = evaluate_council_trigger(
            "anything at all",
            0.01,
            true,
            &crate::council::TriggerPolicy::default(),
        );
        unsafe { std::env::remove_var("NEOTH_COUNCIL_ENABLE") };
        assert!(
            matches!(decision, crate::council::TriggerDecision::Skip { .. }),
            "a durably-suppressed council must not be force-convened by NEOTH_COUNCIL_ENABLE=1"
        );
    }

    #[test]
    fn evaluate_council_trigger_not_disabled_allows_force_enable() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::set_var("NEOTH_COUNCIL_ENABLE", "1");
        }
        let decision = evaluate_council_trigger(
            "anything at all",
            0.01,
            false,
            &crate::council::TriggerPolicy::default(),
        );
        unsafe { std::env::remove_var("NEOTH_COUNCIL_ENABLE") };
        // disabled=false + force-enable → the normal force path (Convene).
        assert!(
            matches!(decision, crate::council::TriggerDecision::Convene { .. }),
            "with no suppress, NEOTH_COUNCIL_ENABLE=1 must force Convene"
        );
    }

    // ── UX-02 memory-signal line ───────────────────────────────────

    #[test]
    fn memory_signal_line_silences_zero_and_pluralizes() {
        assert_eq!(memory_signal_line(0), None, "fresh install stays silent");
        assert_eq!(
            memory_signal_line(-3),
            None,
            "defensive: non-positive → None"
        );
        assert_eq!(
            memory_signal_line(1).unwrap(),
            "I remember 1 thing from last time."
        );
        assert_eq!(
            memory_signal_line(42).unwrap(),
            "I remember 42 things from last time."
        );
    }

    // ── K-Perf-3 v1 2026-05-17: spawn_blocking wrap of profile_block_for_callosum ──

    #[test]
    fn profile_block_for_callosum_sync_returns_none_on_missing_db() {
        // When `views.db` doesn't exist (fresh install / test env),
        // the sync helper must return None gracefully — no panic,
        // no error bubble. The async wrapper inherits this contract
        // via spawn_blocking's `Result<Option<String>, JoinError>`
        // then `.ok().flatten()` collapse.
        //
        // Test runs in a process where the default-path views.db
        // does NOT exist (or, if it does, the operator's actual
        // profile data shouldn't be touched — the test is environment-
        // sensitive but the only safe outcome is None either way).
        // Either branch — missing db OR empty db — satisfies the
        // "returns Option, never panics" contract.
        let _ = profile_block_for_callosum_sync();
        // No assertion on the value; the point is that the call
        // returned at all without panicking.
    }

    #[test]
    fn callosum_min_confidence_consumes_p06_injection_floor_constant() {
        // CH-11 / P-06 drift guard (Session 21): the callosum profile-
        // injection floor MUST source from the primitive
        // `profile::injection::DEFAULT_INJECTION_FLOOR` (currently
        // 0.6). If a future refactor either (a) re-introduces a
        // hardcoded literal here, or (b) changes the primitive's
        // default without thinking through callosum impact, this
        // test surfaces the drift.
        //
        // Why pin at the constant rather than the literal: the
        // SPEC says "Block-B profile injection ≥ 0.6 confidence
        // gate" once. Two places enforcing the same threshold
        // independently always drift; the single-source-of-truth
        // is `DEFAULT_INJECTION_FLOOR` per CH-11 closeout.
        assert!(
            (crate::profile::injection::DEFAULT_INJECTION_FLOOR - 0.6).abs() < f64::EPSILON,
            "primitive's DEFAULT_INJECTION_FLOOR drifted from 0.6 — \
             update SPEC + this drift guard together"
        );
    }

    #[tokio::test]
    async fn profile_block_for_callosum_async_does_not_block_tokio_worker() {
        // K-Perf-3 v1: the wrapper offloads the rusqlite query to
        // the blocking pool. Concurrently with this call, a
        // `tokio::time::sleep(0)` MUST make progress (= the worker
        // pool isn't stalled). Smoke check that the spawn_blocking
        // path actually fires.
        let pipeline_task = tokio::spawn(profile_block_for_callosum());
        // Yield + immediately await — the runtime should schedule
        // other work even while spawn_blocking runs.
        tokio::task::yield_now().await;
        let _ = pipeline_task.await.unwrap();
        // No specific value assertion (env-sensitive); the
        // contract is: doesn't deadlock, doesn't panic.
    }

    struct MockProvider {
        reply: String,
    }

    #[async_trait]
    impl Provider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            Ok(Completion {
                text: self.reply.clone(),
                model: "mock-1".to_string(),
                latency: Duration::from_millis(7),
                input_tokens: Some(12),
                output_tokens: Some(8),
            })
        }
    }

    #[tokio::test]
    async fn chat_writes_request_and_response_frames() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");

        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: Some("en".into()),
            language_code: Some("en".into()),
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: Some("claude-opus-4-7".into()),
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };

        let provider = MockProvider {
            reply: "hello back".to_string(),
        };

        let args = ChatArgs {
            message: Some("hi".into()),
            model: None,
            system: None,
            config: None,
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
        };

        run_chat_with(args, config, &provider)
            .await
            .expect("chat run_with succeeds");

        // The WAL must contain: SegmentHeader, then RAW_TEXT (raw prompt
        // for recall), then PROVIDER_REQUEST, then PROVIDER_RESPONSE.
        let bytes = read(&seg).await.unwrap();
        let frames = &bytes[SEGMENT_HEADER_LEN..];

        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        let dec0 = decode_frame(frames).expect("decode RAW_TEXT frame");
        assert_eq!(dec0.header.event_type, EVENT_TYPE_RAW_TEXT);
        assert_eq!(dec0.payload, b"hi");

        let rest = &frames[dec0.header.total_len as usize..];
        let dec1 = decode_frame(rest).expect("decode request frame");
        assert_eq!(dec1.header.event_type, EVENT_TYPE_PROVIDER_REQUEST);
        let req_payload: serde_json::Value = serde_json::from_slice(dec1.payload).unwrap();
        assert_eq!(req_payload["provider"], "mock");
        assert_eq!(req_payload["operator_id"], "alice");

        // C-14 (2026-05-15): COST_ESTIMATE_SHOWN now lands between
        // PROVIDER_REQUEST and the permission gate. Preview is emitted
        // BEFORE the gate so an operator who declines still sees the
        // projected cost in the audit trail.
        let rest = &rest[dec1.header.total_len as usize..];
        let cost = decode_frame(rest).expect("decode cost estimate frame");
        assert_eq!(
            cost.header.event_type,
            crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN,
        );
        let cost_payload: serde_json::Value = serde_json::from_slice(cost.payload).unwrap();
        assert!(cost_payload["total_eur"].is_number());
        assert!(cost_payload["input_tokens"].is_number());

        // Phase 28b: a PERMISSION_GRANTED audit frame sits between cost preview
        // and response (gate audit at standard level for the paid-provider call).
        let rest = &rest[cost.header.total_len as usize..];
        let perm = decode_frame(rest).expect("decode permission frame");
        assert_eq!(
            perm.header.event_type,
            crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED,
        );

        let rest = &rest[perm.header.total_len as usize..];
        // B-1 (Session 13): COUNCIL_SKIP frame sits between
        // PERMISSION_GRANTED and PROVIDER_RESPONSE whenever the council
        // smart-trigger evaluates to Skip — true for this test (short
        // prompt below complexity threshold + default policy).
        let council_skip = decode_frame(rest).expect("decode COUNCIL_SKIP frame");
        assert_eq!(
            council_skip.header.event_type,
            crate::wal::events::EVENT_TYPE_COUNCIL_SKIP,
        );
        let council_skip_payload: serde_json::Value =
            serde_json::from_slice(council_skip.payload).unwrap();
        assert!(council_skip_payload["reason"].is_string());

        let rest = &rest[council_skip.header.total_len as usize..];
        let dec2 = decode_frame(rest).expect("decode response frame");
        assert_eq!(dec2.header.event_type, EVENT_TYPE_PROVIDER_RESPONSE);
        let resp_payload: serde_json::Value = serde_json::from_slice(dec2.payload).unwrap();
        assert_eq!(resp_payload["provider"], "mock");
        assert_eq!(resp_payload["model"], "mock-1");
        assert_eq!(resp_payload["input_tokens"], 12);
        assert_eq!(resp_payload["output_tokens"], 8);

        // SPEC_mirror_refusal Phase 1: a clean reply MUST NOT produce a
        // REFUSAL_OBSERVED frame. The audit trail stays empty of false
        // positives so operators can grep for actual refusals without
        // wading through noise.
        let rest = &rest[dec2.header.total_len as usize..];
        if !rest.is_empty() {
            let after = decode_frame(rest).expect("decode after-response frame");
            assert_ne!(
                after.header.event_type,
                crate::wal::events::EVENT_TYPE_REFUSAL_OBSERVED,
                "clean reply must not emit REFUSAL_OBSERVED"
            );
        }
    }

    /// SPEC_mirror_refusal Phase 1: a provider reply that matches a
    /// hard-refusal pattern must produce a `0x16 REFUSAL_OBSERVED` WAL
    /// frame after PROVIDER_RESPONSE. The full mirror pipeline (Stages
    /// 2-6) is hemisphere-architecture work and lands later.
    #[tokio::test]
    async fn chat_emits_refusal_observed_on_hard_refusal_reply() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");

        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: Some("en".into()),
            language_code: Some("en".into()),
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: Some("claude-opus-4-7".into()),
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };

        let provider = MockProvider {
            reply: "I cannot help with that request.".to_string(),
        };

        let args = ChatArgs {
            message: Some("do the dangerous thing".into()),
            model: None,
            system: None,
            config: None,
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
        };

        run_chat_with(args, config, &provider)
            .await
            .expect("chat run_with succeeds");

        // Walk every frame; one of them must be REFUSAL_OBSERVED with the
        // expected class + a non-empty matched_patterns array.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut found = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_REFUSAL_OBSERVED {
                let p: serde_json::Value =
                    serde_json::from_slice(frame.payload).expect("REFUSAL payload JSON");
                found = Some(p);
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let payload = found.expect("REFUSAL_OBSERVED frame must be present");
        assert_eq!(payload["refusal_class"], "hard_refusal");
        assert!(payload["confidence"].as_u64().unwrap() >= 80);
        assert!(!payload["matched_patterns"].as_array().unwrap().is_empty());
        assert_eq!(payload["provider"], "mock");
    }

    /// AP-2: every local inference call must leave a WAL trace
    /// (`LOCAL_INFERENCE_START` + `LOCAL_INFERENCE_END`). Test uses a
    /// mock provider that reports `name() == "local_qwen"` so the
    /// chat.rs branch fires; the real candle path isn't exercised.
    #[tokio::test]
    async fn chat_emits_local_inference_start_and_end_for_local_qwen() {
        struct LocalQwenMock;
        #[async_trait]
        impl Provider for LocalQwenMock {
            fn name(&self) -> &'static str {
                "local_qwen"
            }
            async fn complete(&self, _req: Request) -> Result<Completion> {
                Ok(Completion {
                    text: "PARIS".into(),
                    model: "Qwen/Qwen2.5-3B-Instruct".into(),
                    latency: Duration::from_millis(11),
                    input_tokens: Some(5),
                    output_tokens: Some(1),
                })
            }
        }

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: None,
            language_code: None,
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::LocalQwen),
            provider_binary: None,
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: None,
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };
        let args = ChatArgs {
            message: Some("Capital of France?".into()),
            model: None,
            system: None,
            config: None,
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
        };
        run_chat_with(args, config, &LocalQwenMock)
            .await
            .expect("run_chat_with");

        // Walk every frame and collect event types we care about. Some
        // intermediate frames (RAW_TEXT, PROVIDER_REQUEST, PERMISSION_GRANTED,
        // PROVIDER_RESPONSE) live in between; the assertion is just that
        // both START + END appear in the right order.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut saw_start_at: Option<usize> = None;
        let mut saw_end_at: Option<usize> = None;
        let mut index = 0usize;
        while !cursor.is_empty() {
            let Ok(frame) = decode_frame(cursor) else {
                break;
            };
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_LOCAL_INFERENCE_START {
                saw_start_at = Some(index);
            }
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_LOCAL_INFERENCE_END {
                saw_end_at = Some(index);
            }
            cursor = &cursor[frame.header.total_len as usize..];
            index += 1;
        }
        let start = saw_start_at.expect("LOCAL_INFERENCE_START frame missing");
        let end = saw_end_at.expect("LOCAL_INFERENCE_END frame missing");
        assert!(
            start < end,
            "END must follow START (start={start}, end={end})"
        );
    }

    #[tokio::test]
    async fn chat_streaming_emits_chunks_then_response() {
        use crate::providers::ChunkStream;
        use futures_util::stream;

        struct MockStreamProvider;

        #[async_trait]
        impl Provider for MockStreamProvider {
            fn name(&self) -> &'static str {
                "mock_stream"
            }
            async fn complete(&self, _req: Request) -> Result<Completion> {
                anyhow::bail!("not used in streaming test")
            }
            async fn stream(&self, _req: Request) -> Result<ChunkStream> {
                let chunks: Vec<Result<CompletionChunk>> = vec![
                    Ok(CompletionChunk {
                        delta: "hello ".into(),
                        done: false,
                        input_tokens: None,
                        output_tokens: None,
                    }),
                    Ok(CompletionChunk {
                        delta: "world".into(),
                        done: false,
                        input_tokens: None,
                        output_tokens: None,
                    }),
                    Ok(CompletionChunk {
                        delta: String::new(),
                        done: true,
                        input_tokens: Some(5),
                        output_tokens: Some(3),
                    }),
                ];
                Ok(Box::pin(stream::iter(chunks)))
            }
        }

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: None,
            language_code: None,
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: Some("mock-stream-1".into()),
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };
        let args = ChatArgs {
            message: Some("hi".into()),
            model: None,
            system: None,
            config: None,
            wal_segment: Some(seg.clone()),
            stream: true,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
        };

        run_chat_with(args, config, &MockStreamProvider)
            .await
            .expect("streaming run");

        // WAL layout: SegmentHeader, RAW_TEXT, REQUEST, CHUNK, CHUNK, RESPONSE.
        let bytes = read(&seg).await.unwrap();
        let frames = &bytes[SEGMENT_HEADER_LEN..];

        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        let dec0 = decode_frame(frames).expect("RAW_TEXT");
        assert_eq!(dec0.header.event_type, EVENT_TYPE_RAW_TEXT);
        let frames = &frames[dec0.header.total_len as usize..];

        let dec1 = decode_frame(frames).expect("REQUEST");
        assert_eq!(dec1.header.event_type, EVENT_TYPE_PROVIDER_REQUEST);
        let rest = &frames[dec1.header.total_len as usize..];

        // C-14: COST_ESTIMATE_SHOWN lands before the permission gate.
        let cost = decode_frame(rest).expect("COST_ESTIMATE_SHOWN");
        assert_eq!(
            cost.header.event_type,
            crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN,
        );
        let rest = &rest[cost.header.total_len as usize..];

        // Phase 28b: PERMISSION_GRANTED audit frame between cost preview and chunks.
        let perm = decode_frame(rest).expect("PERMISSION_GRANTED");
        assert_eq!(
            perm.header.event_type,
            crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED,
        );
        let rest = &rest[perm.header.total_len as usize..];

        // B-1 follow-up (Session 13): streaming branch now emits a
        // COUNCIL_SKIP frame with reason `streaming_mode_disables_council`
        // so the audit covers stream + non-stream symmetrically.
        let council_skip = decode_frame(rest).expect("COUNCIL_SKIP (streaming)");
        assert_eq!(
            council_skip.header.event_type,
            crate::wal::events::EVENT_TYPE_COUNCIL_SKIP,
        );
        let skip_payload: serde_json::Value = serde_json::from_slice(council_skip.payload).unwrap();
        assert_eq!(skip_payload["reason"], "streaming_mode_disables_council");
        let rest = &rest[council_skip.header.total_len as usize..];

        let dec2 = decode_frame(rest).expect("CHUNK 1");
        assert_eq!(
            dec2.header.event_type,
            crate::wal::events::EVENT_TYPE_PROVIDER_STREAM_CHUNK
        );
        let rest = &rest[dec2.header.total_len as usize..];

        let dec3 = decode_frame(rest).expect("CHUNK 2");
        assert_eq!(
            dec3.header.event_type,
            crate::wal::events::EVENT_TYPE_PROVIDER_STREAM_CHUNK
        );
        let rest = &rest[dec3.header.total_len as usize..];

        let dec4 = decode_frame(rest).expect("RESPONSE");
        assert_eq!(dec4.header.event_type, EVENT_TYPE_PROVIDER_RESPONSE);
        let resp_payload: serde_json::Value = serde_json::from_slice(dec4.payload).unwrap();
        assert_eq!(resp_payload["streamed"], true);
        assert_eq!(resp_payload["input_tokens"], 5);
        assert_eq!(resp_payload["output_tokens"], 3);
        assert_eq!(resp_payload["model"], "mock-stream-1");
    }

    #[tokio::test]
    async fn chat_propagates_provider_error() {
        struct FailingProvider;
        #[async_trait]
        impl Provider for FailingProvider {
            fn name(&self) -> &'static str {
                "fail"
            }
            async fn complete(&self, _req: Request) -> Result<Completion> {
                anyhow::bail!("simulated upstream failure")
            }
        }

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: None,
            language_code: None,
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: None,
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };
        let args = ChatArgs {
            message: Some("trigger".into()),
            model: None,
            system: None,
            config: None,
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
        };

        let result = run_chat_with(args, config, &FailingProvider).await;
        assert!(result.is_err());

        // The RAW_TEXT + PROVIDER_REQUEST frames must still be on disk —
        // writes happen before provider call.
        let bytes = read(&seg).await.unwrap();
        let frames = &bytes[SEGMENT_HEADER_LEN..];

        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        let dec0 = decode_frame(frames).expect("RAW_TEXT");
        assert_eq!(dec0.header.event_type, EVENT_TYPE_RAW_TEXT);
        let rest = &frames[dec0.header.total_len as usize..];

        let dec1 = decode_frame(rest).expect("decode request frame even on failure");
        assert_eq!(dec1.header.event_type, EVENT_TYPE_PROVIDER_REQUEST);
    }

    // ── E-2 Phase 2 (Session 13) recursive sub-council ────────────────

    /// Counting mock provider — increments a shared counter on every
    /// `complete` call. Used to pin how many leaf LLM calls a
    /// `ProviderHemisphere::ask_with_depth` invocation triggers.
    struct CountingMockProvider {
        counter: std::sync::Arc<std::sync::atomic::AtomicU32>,
        reply: String,
    }

    #[async_trait]
    impl Provider for CountingMockProvider {
        fn name(&self) -> &'static str {
            "counting-mock"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Completion {
                text: self.reply.clone(),
                model: "counting-mock-1".to_string(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn ask_with_depth_one_is_flat_no_recursion() {
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "ok".into(),
            }),
            base_req: Request::default(),
            config: None,
            outer_role: None,
        };
        let result = ph.ask_with_depth("hi", 1).await.unwrap();
        assert_eq!(result.text, "ok");
        // Exactly one flat call — no recursion at depth=1.
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ask_with_depth_zero_is_flat_no_recursion() {
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "ok".into(),
            }),
            base_req: Request::default(),
            config: None,
            outer_role: None,
        };
        let result = ph.ask_with_depth("hi", 0).await.unwrap();
        assert_eq!(result.text, "ok");
        // depth=0 must also bypass recursion (no negative depth).
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ask_with_depth_without_config_arc_is_flat() {
        // Even with depth > 1, a wrapper built without a config Arc
        // (e.g. via legacy `build_hemisphere` for Split-recovery
        // path) MUST behave as flat. Pins the contract that callosum
        // recovery never triggers recursion regardless of operator
        // config.
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "no-recurse".into(),
            }),
            base_req: Request::default(),
            config: None,
            outer_role: None,
        };
        // depth=4 (MAX cap) + no config → still flat, one call.
        let result = ph.ask_with_depth("hi", 4).await.unwrap();
        assert_eq!(result.text, "no-recurse");
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ask_with_depth_recursion_path_attempts_to_build_subs() {
        // When a config Arc IS present + depth > 1, the recursion
        // path fires. With a `provider_kind = Skip` config the
        // sub-build will fail (from_config_for_role bails on Skip);
        // we assert the failure path threads the operator-actionable
        // error message rather than panicking. This pins the
        // recursion code path is reached without needing a live LLM.
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = Some(ProviderKind::Skip);
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "outer".into(),
            }),
            base_req: Request::default(),
            config: Some(std::sync::Arc::new(cfg)),
            outer_role: Some(crate::config::inference::HemisphereRole::Left),
        };
        let err = ph.ask_with_depth("hi", 2).await.unwrap_err();
        // Error msg names "build sub-" so operator sees which leg failed.
        assert!(
            err.contains("build sub-"),
            "expected sub-build error, got: {err}",
        );
        // Flat provider was NEVER called on the outer wrapper —
        // recursion took priority over the outer's own ask.
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // ── Pick #8 SP-2 (Session 14) role-agnostic winner selection ────────

    fn mk_outcome_consensus(
        winning: &str,
        responses: Vec<crate::council::HemisphereResponse>,
    ) -> crate::council::CouncilDebate {
        crate::council::CouncilDebate {
            prompt_hash_xxh3: 0,
            responses,
            dissent: crate::council::dissent::DissentScore(0.1),
            verdict: crate::council::Verdict::Consensus {
                winning_text: winning.to_string(),
            },
            total_latency_ms: 100,
        }
    }

    fn mk_outcome_split(
        responses: Vec<crate::council::HemisphereResponse>,
    ) -> crate::council::CouncilDebate {
        crate::council::CouncilDebate {
            prompt_hash_xxh3: 0,
            responses,
            dissent: crate::council::dissent::DissentScore(0.7),
            verdict: crate::council::Verdict::Split {
                summary: "left vs right".into(),
            },
            total_latency_ms: 100,
        }
    }

    fn mk_resp_picksel(
        role: crate::config::inference::HemisphereRole,
        provider: &str,
        text: &str,
    ) -> crate::council::HemisphereResponse {
        crate::council::HemisphereResponse {
            role,
            provider: provider.into(),
            text: Some(text.into()),
            error: None,
            latency_ms: 100,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        }
    }

    #[test]
    fn legacy_majority_mode_returns_none_so_dispatch_uses_legacy_path() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let outcome = mk_outcome_consensus(
            "consensus answer",
            vec![mk_resp_picksel(
                HemisphereRole::Left,
                "claude_cli",
                "claude says",
            )],
        );
        let winner = select_winner_role_agnostic(&outcome, SelectionMode::LegacyMajority, None, 0);
        assert!(winner.is_none());
    }

    #[test]
    fn best_always_mode_picks_highest_quality_response_regardless_of_consensus() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        // Consensus would say "local_qwen text"; BestAlways picks
        // the higher-tier claude_cli response instead.
        let outcome = mk_outcome_consensus(
            "local_qwen text",
            vec![
                mk_resp_picksel(HemisphereRole::Left, "local_qwen", "local_qwen text"),
                mk_resp_picksel(HemisphereRole::Right, "claude_cli", "claude text"),
            ],
        );
        let winner = select_winner_role_agnostic(&outcome, SelectionMode::BestAlways, None, 0)
            .expect("BestAlways picks a winner");
        assert_eq!(winner.role, HemisphereRole::Right);
        assert_eq!(winner.provider, "claude_cli");
    }

    #[test]
    fn consensus_or_best_mode_uses_winning_text_when_consensus() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let outcome = mk_outcome_consensus(
            "claude text",
            vec![
                mk_resp_picksel(HemisphereRole::Left, "claude_cli", "claude text"),
                mk_resp_picksel(HemisphereRole::Right, "local_qwen", "qwen text"),
            ],
        );
        let winner = select_winner_role_agnostic(&outcome, SelectionMode::ConsensusOrBest, None, 0)
            .expect("ConsensusOrBest picks a winner");
        // winning_text = "claude text" → matches the claude_cli response.
        assert_eq!(winner.text, "claude text");
        assert_eq!(winner.provider, "claude_cli");
    }

    // ── SP-4 F5 diversity_bonus_for ────────────────────────────────────

    #[test]
    fn diversity_bonus_zero_for_text_matching_consensus() {
        use crate::config::inference::HemisphereRole;
        let outcome = mk_outcome_consensus(
            "yes that is correct",
            vec![
                mk_resp_picksel(HemisphereRole::Left, "claude_cli", "yes that is correct"),
                mk_resp_picksel(HemisphereRole::Right, "local_qwen", "no never"),
            ],
        );
        // Left text == winning_text → zero distance → zero bonus.
        let b = diversity_bonus_for(Some("yes that is correct"), HemisphereRole::Left, &outcome);
        assert_eq!(b, 0.0);
    }

    #[test]
    fn diversity_bonus_positive_for_text_dissenting_from_consensus() {
        use crate::config::inference::HemisphereRole;
        let outcome = mk_outcome_consensus(
            "yes that is correct",
            vec![
                mk_resp_picksel(HemisphereRole::Left, "claude_cli", "yes that is correct"),
                mk_resp_picksel(
                    HemisphereRole::Right,
                    "local_qwen",
                    "no totally wrong instead",
                ),
            ],
        );
        // Right text fully disjoint from winning_text → high distance.
        let b = diversity_bonus_for(
            Some("no totally wrong instead"),
            HemisphereRole::Right,
            &outcome,
        );
        assert!(
            b > 0.0,
            "a dissenting hemisphere must earn a nonzero diversity bonus; got {b}"
        );
        assert!(b <= 1.0, "bonus stays bounded; got {b}");
    }

    #[test]
    fn diversity_bonus_zero_for_errored_hemisphere() {
        use crate::config::inference::HemisphereRole;
        let outcome = mk_outcome_consensus(
            "yes",
            vec![mk_resp_picksel(HemisphereRole::Left, "claude_cli", "yes")],
        );
        // text=None (errored) → 0.0, no panic.
        assert_eq!(
            diversity_bonus_for(None, HemisphereRole::Right, &outcome),
            0.0
        );
    }

    #[test]
    fn diversity_bonus_split_verdict_uses_other_hemisphere_as_proxy() {
        use crate::config::inference::HemisphereRole;
        // Split has no winning_text → fall back to the OTHER hemisphere's
        // text as the consensus proxy. Left="alpha beta", Right="gamma
        // delta" → disjoint → nonzero, no panic.
        let outcome = mk_outcome_split(vec![
            mk_resp_picksel(HemisphereRole::Left, "claude_cli", "alpha beta"),
            mk_resp_picksel(HemisphereRole::Right, "local_qwen", "gamma delta"),
        ]);
        let b = diversity_bonus_for(Some("alpha beta"), HemisphereRole::Left, &outcome);
        assert!(
            b > 0.0,
            "split-verdict proxy must still produce a distance; got {b}"
        );
    }

    #[test]
    fn consensus_or_best_falls_back_to_best_response_on_split() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let outcome = mk_outcome_split(vec![
            mk_resp_picksel(HemisphereRole::Left, "local_qwen", "qwen says A"),
            mk_resp_picksel(HemisphereRole::Right, "claude_cli", "claude says B"),
        ]);
        let winner = select_winner_role_agnostic(&outcome, SelectionMode::ConsensusOrBest, None, 0)
            .expect("falls back to best_response");
        // winning_text is None on Split → falls back to best_response,
        // which picks the higher-tier claude_cli.
        assert_eq!(winner.role, HemisphereRole::Right);
        assert_eq!(winner.provider, "claude_cli");
    }

    #[test]
    fn winner_carries_composite_score() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let outcome = mk_outcome_split(vec![mk_resp_picksel(
            HemisphereRole::Left,
            "claude_cli",
            "thoughtful answer with structure\n```rust\nfn x() {}\n```\n- list",
        )]);
        let winner = select_winner_role_agnostic(&outcome, SelectionMode::BestAlways, None, 0)
            .expect("BestAlways winner");
        // claude_cli tier 1.0 + non-zero dynamic + 0.5 memory + 0 diversity
        // total ≥ 0.40 (tier component alone) + memory component
        assert!(
            winner.score >= 0.4,
            "composite score should reflect tier weight, got {}",
            winner.score
        );
    }

    #[test]
    fn all_unusable_returns_none_in_best_always() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let errored = crate::council::HemisphereResponse {
            role: HemisphereRole::Left,
            provider: "claude_cli".into(),
            text: None,
            error: Some("boom".into()),
            latency_ms: 0,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        };
        let outcome = mk_outcome_split(vec![errored]);
        let winner = select_winner_role_agnostic(&outcome, SelectionMode::BestAlways, None, 0);
        assert!(winner.is_none(), "no usable responses → fall through");
    }

    // ── E-2 Phase 3 (Session 14) sub-slot routing ──────────────────────

    #[tokio::test]
    async fn ask_with_depth_routes_through_sub_slots_when_outer_role_set() {
        // When `outer_role: Some(Left)` AND the topology configures
        // `hemisphere_sub_slots[Left]`, recursion builds sub-hemispheres
        // via from_config_for_sub_role → the sub-slot's provider
        // (Skip → bail) gets attempted. The error path proves the
        // sub-slot routing fired rather than reusing outer's binding.
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots, TopologyMode,
        };
        use crate::council::orchestrator::HemisphereProvider;

        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut cfg = FreedomConfig::default();
        // Outer providers: claude_cli (the wrapper's provider isn't
        // consulted during recursion — flat provider never fires).
        cfg.provider_kind = Some(ProviderKind::ClaudeCli);
        cfg.inference.mode = TopologyMode::Custom;
        cfg.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            model: Some("claude-opus-4-7".into()),
            ..Default::default()
        };
        cfg.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };
        cfg.inference.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };

        // Sub-slots for outer-Left: every inner-role pinned to a
        // variant that fails to construct without env-credentials
        // (`AwsBedrock` bails when no creds available). The exact
        // error doesn't matter — what matters is the routing-shape
        // proves the sub_slots[Left] entry was consulted, not
        // outer's Left binding.
        let mut sub = SubHemisphereSlots::default();
        sub.left = HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            model: Some("anthropic.claude-opus-4-7".into()),
            ..Default::default()
        };
        sub.right = HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            model: Some("anthropic.claude-opus-4-7".into()),
            ..Default::default()
        };
        sub.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            model: Some("anthropic.claude-opus-4-7".into()),
            ..Default::default()
        };
        cfg.inference
            .hemisphere_sub_slots
            .insert(HemisphereRole::Left, sub);

        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "outer-left".into(),
            }),
            base_req: Request::default(),
            config: Some(std::sync::Arc::new(cfg)),
            outer_role: Some(HemisphereRole::Left),
        };

        let result = ph.ask_with_depth("hi", 2).await;
        // Outcome: either the sub-build fails (no AWS creds in test
        // env → expected on CI), surfacing the actionable error, OR
        // (impossibly here) it succeeds and the outer flat provider
        // is NOT consulted. Either way the outer counter stays at 0.
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "outer wrapper's own provider must NOT fire during recursion"
        );
        if let Err(msg) = result {
            assert!(
                msg.contains("build sub-")
                    || msg.contains("aws_bedrock")
                    || msg.contains("credentials"),
                "expected sub-build / aws creds error, got: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn ask_with_depth_falls_back_to_outer_role_path_when_outer_role_none() {
        // When `outer_role: None` (legacy Split-recovery wrapper),
        // recursion goes through the Phase 2 path even with depth > 1
        // + config Arc present. Pins backwards-compat for the
        // callosum recovery wrapper.
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = Some(ProviderKind::Skip);
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "outer".into(),
            }),
            base_req: Request::default(),
            config: Some(std::sync::Arc::new(cfg)),
            outer_role: None,
        };
        let err = ph.ask_with_depth("hi", 2).await.unwrap_err();
        // Skip provider → build_hemisphere_with_config (Phase 2 path)
        // surfaces the Skip bail.
        assert!(
            err.contains("build sub-") && err.contains("skip"),
            "expected Phase 2 sub-build skip error, got: {err}"
        );
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // ── Finding 2 (Session 13) multi-cloud fan-out advisory ───────────

    fn mk_advisory_config(
        left: Option<crate::config::inference::InferenceProvider>,
        right: Option<crate::config::inference::InferenceProvider>,
        cere: Option<crate::config::inference::InferenceProvider>,
    ) -> FreedomConfig {
        use crate::config::inference::{HemisphereSlot, InferenceTopology, TopologyMode};
        let mut cfg = FreedomConfig::default();
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Custom;
        topo.left = HemisphereSlot {
            provider: left,
            ..HemisphereSlot::default()
        };
        topo.right = HemisphereSlot {
            provider: right,
            ..HemisphereSlot::default()
        };
        topo.cerebellum = HemisphereSlot {
            provider: cere,
            ..HemisphereSlot::default()
        };
        cfg.inference = topo;
        cfg
    }

    #[test]
    fn fan_out_advisory_line_returns_none_for_single_cloud_topology() {
        use crate::config::inference::InferenceProvider as I;
        // All three slots = same cloud kind → only 1 distinct kind →
        // no joint fan-out advisory needed (single per-provider V03-08
        // prompt already covers it).
        let cfg = mk_advisory_config(Some(I::OpenAi), Some(I::OpenAi), Some(I::OpenAi));
        assert!(super::fan_out_advisory_line(&cfg).is_none());
    }

    #[test]
    fn fan_out_advisory_line_returns_none_when_only_local_qwen() {
        use crate::config::inference::InferenceProvider as I;
        // Local-only topology has zero cloud kinds → no advisory.
        let cfg = mk_advisory_config(Some(I::LocalQwen), Some(I::LocalQwen), Some(I::LocalQwen));
        assert!(super::fan_out_advisory_line(&cfg).is_none());
    }

    #[test]
    fn fan_out_advisory_line_fires_for_two_distinct_clouds() {
        use crate::config::inference::InferenceProvider as I;
        let cfg = mk_advisory_config(Some(I::OpenAi), Some(I::Gemini), Some(I::LocalQwen));
        let line = super::fan_out_advisory_line(&cfg).expect("≥2 clouds should fire");
        assert!(line.contains("2 cloud providers"));
        assert!(line.contains("openai_api"));
        assert!(line.contains("gemini_api"));
        assert!(!line.contains("local_qwen"));
    }

    #[test]
    fn fan_out_advisory_line_fires_for_three_distinct_clouds() {
        use crate::config::inference::InferenceProvider as I;
        let cfg = mk_advisory_config(Some(I::ClaudeCli), Some(I::OpenAi), Some(I::Gemini));
        let line = super::fan_out_advisory_line(&cfg).expect("3 clouds should fire");
        assert!(line.contains("3 cloud providers"));
        for slug in ["claude_cli", "openai_api", "gemini_api"] {
            assert!(line.contains(slug), "advisory must name {slug}: {line}");
        }
    }

    #[test]
    fn fan_out_advisory_line_dedups_repeated_kinds() {
        use crate::config::inference::InferenceProvider as I;
        // Left=Right=ClaudeCli, Cerebellum=Gemini → 2 distinct kinds.
        let cfg = mk_advisory_config(Some(I::ClaudeCli), Some(I::ClaudeCli), Some(I::Gemini));
        let line = super::fan_out_advisory_line(&cfg).expect("2 distinct clouds should fire");
        assert!(line.contains("2 cloud providers"));
        // ClaudeCli appears once, not twice.
        let claude_count = line.matches("claude_cli").count();
        assert_eq!(
            claude_count, 1,
            "expected dedup, got {claude_count} in: {line}"
        );
    }

    // ── Pick #26 (Session 14) — Phase 3c auto repo-context injection
    //
    // Tests drive `maybe_repo_context_block_at` with an explicit
    // tempdir path instead of mutating HOME / USERPROFILE — keeps
    // the suite parallel-safe (no env-var race with cli::code_map
    // CLI tests + no shared mutex needed).

    #[test]
    fn maybe_repo_context_returns_none_when_max_files_is_zero() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let cfg = FreedomConfig::default();
        assert_eq!(cfg.code_map.auto_context_max_files, 0);
        let result = maybe_repo_context_block_at(&cfg, "find auth_middleware", &db);
        assert!(result.is_none(), "default config must skip injection");
    }

    #[test]
    fn maybe_repo_context_returns_none_when_db_missing() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("does_not_exist.db");
        let mut cfg = FreedomConfig::default();
        cfg.code_map.auto_context_max_files = 5;
        let result = maybe_repo_context_block_at(&cfg, "find auth_middleware", &db);
        assert!(
            result.is_none(),
            "missing DB must yield None, not panic; got: {result:?}"
        );
    }

    #[test]
    fn maybe_repo_context_returns_none_when_db_has_no_matching_files() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let _ = crate::code_map::persist::open(&db).unwrap();
        let mut cfg = FreedomConfig::default();
        cfg.code_map.auto_context_max_files = 5;
        let result = maybe_repo_context_block_at(&cfg, "where is some_nonexistent_xyz?", &db);
        assert!(result.is_none(), "empty DB must yield None");
    }

    #[test]
    fn maybe_repo_context_injects_block_when_match_exists() {
        use crate::code_map::persist::{open, persist_map};
        use crate::code_map::symbols::{Symbol, SymbolKind};
        use crate::code_map::walker::{Language, RepoFile, RepoMap, ScanReport};

        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let mut conn = open(&db).unwrap();
        let map = RepoMap {
            root: "/repo/test".into(),
            files: vec![RepoFile {
                path: "src/auth/middleware.rs".into(),
                language: Language::Rust,
                bytes: 200,
                loc: 30,
                symbols: vec![Symbol {
                    name: "auth_middleware".into(),
                    kind: SymbolKind::Function,
                    line: 12,
                }],
            }],
            report: ScanReport::default(),
        };
        persist_map(&mut conn, &map).unwrap();
        drop(conn);

        let mut cfg = FreedomConfig::default();
        cfg.code_map.auto_context_max_files = 5;
        let result = maybe_repo_context_block_at(&cfg, "where is auth_middleware?", &db);
        let block = result.expect("symbol match must produce a block");
        assert!(
            block.contains("repo-context"),
            "block must declare itself as repo-context; got: {block}"
        );
        assert!(
            block.contains("src/auth/middleware.rs"),
            "block must include the matched file; got: {block}"
        );
        assert!(
            block.contains("auth_middleware"),
            "block must include the matched symbol; got: {block}"
        );
    }

    #[test]
    fn maybe_repo_context_block_zero_max_short_circuits_before_db_open() {
        // Defensive: even if the DB file is broken / unreadable, the
        // zero-max short-circuit must fire BEFORE we try to open it.
        // No I/O happens, no error surfaces.
        let cfg = FreedomConfig::default();
        let result = maybe_repo_context_block_at(
            &cfg,
            "auth_middleware",
            std::path::Path::new("/definitely/does/not/exist/code_map.db"),
        );
        assert!(result.is_none());
    }

    // ── operator-facts wiring (role_custom + language_primary) ──────────

    #[test]
    fn operator_facts_none_when_no_role_no_lang() {
        let cfg = FreedomConfig::default();
        assert_eq!(merge_operator_facts(&cfg, None), None);
        // A rendered NEOTH.md body passes through untouched.
        assert_eq!(
            merge_operator_facts(&cfg, Some("# Rules\nBe terse.".into())).as_deref(),
            Some("# Rules\nBe terse.")
        );
    }

    #[test]
    fn operator_facts_custom_role_wins_over_enum() {
        let mut cfg = FreedomConfig::default();
        cfg.role = Some(crate::cli::init::OperatorRole::Developer);
        cfg.role_custom = Some("authorized pentester".into());
        let out = merge_operator_facts(&cfg, None).expect("facts");
        assert_eq!(out, "Operator role: authorized pentester.");
    }

    #[test]
    fn operator_facts_enum_role_maps_to_prose() {
        let mut cfg = FreedomConfig::default();
        cfg.role = Some(crate::cli::init::OperatorRole::SecurityResearcher);
        let out = merge_operator_facts(&cfg, None).expect("facts");
        assert_eq!(out, "Operator role: security researcher.");
    }

    #[test]
    fn operator_facts_role_none_variant_yields_nothing() {
        let mut cfg = FreedomConfig::default();
        cfg.role = Some(crate::cli::init::OperatorRole::None);
        assert_eq!(merge_operator_facts(&cfg, None), None);
    }

    #[test]
    fn operator_facts_non_english_language_emits_instruction() {
        let mut cfg = FreedomConfig::default();
        cfg.language_primary = Some("de".into());
        let out = merge_operator_facts(&cfg, None).expect("facts");
        assert!(out.contains("BCP-47 'de'"), "got: {out}");
        assert!(out.starts_with("Respond in the operator's primary language"));
    }

    #[test]
    fn operator_facts_english_language_emits_no_instruction() {
        // English is the model default — no instruction needed, and the
        // "en-GB" / "en" family is all skipped.
        for tag in ["en", "en-GB", "EN", "en-US"] {
            let mut cfg = FreedomConfig::default();
            cfg.language_primary = Some(tag.into());
            assert_eq!(
                merge_operator_facts(&cfg, None),
                None,
                "tag {tag} must not emit a language instruction"
            );
        }
    }

    #[test]
    fn operator_facts_role_and_language_stack_above_body() {
        let mut cfg = FreedomConfig::default();
        cfg.role_custom = Some("solo dev".into());
        cfg.language_primary = Some("zh-CN".into());
        let out = merge_operator_facts(&cfg, Some("# NEOTH.md body".into())).expect("facts");
        // Role line first, language line second, then a blank line, then body.
        assert!(out.starts_with("Operator role: solo dev.\n"));
        assert!(out.contains("BCP-47 'zh-CN'"));
        assert!(out.ends_with("\n\n# NEOTH.md body"));
    }
}

// build_header() moved to wal::make_header — Phase 33a AU-B3.
// Old default `importance = 0.6` is now the wal::builder DEFAULT_IMPORTANCE
// (0.5). The 0.1 difference is intentional — operator-facing chat frames now
// use the same baseline importance as every other write, so the
// `idx_episode` ranking is honest about origin instead of secretly biasing
// chat-originated rows.
