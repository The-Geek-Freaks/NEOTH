//! Background dreaming task â€” R-02 Phase 4c.
//!
//! Wraps the existing [`crate::daemon::dreaming`] composer in a tokio
//! interval task so the daemon writes one batch of dreams per cadence
//! tick (default: daily). When an `EmbedProvider` is wired into the
//! daemon (`freedom.yaml::inference.embedding_provider`) the task
//! uses [`crate::daemon::dreaming::compose_dreams_with_embeddings`]
//! for cosine-clustered themes; otherwise it falls back to the
//! deterministic [`crate::daemon::dreaming::compose_dream`] path so
//! operators without local inference still get a daily dream record.
//!
//! Off by default â€” opt in via `freedom.yaml::dreaming.enabled: true`.
//! The interval is operator-tunable (`dreaming.interval_secs`). Errors
//! log + retry next tick; never crash the daemon.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::daemon::dreaming::{
    DREAMING_CLUSTER_THRESHOLD, EventRef, append_dream, compose_dream,
    compose_dreams_with_embeddings,
};
use crate::providers::cost_authorization::AuthorizedProvider;
use crate::providers::embed::EmbedProvider;
use crate::wal::writer::WalWriterHandle;

/// Default cadence: every 24h. Matches the "nightly dreaming" UX the
/// R-02 SPEC describes (cron 03:00). On a long-running daemon a 24h
/// interval lands one batch per day; operators who want more
/// frequent passes flip `dreaming.interval_secs: 3600` for hourly.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default window: last 24h. The composer reads `idx_episode` rows
/// whose `ts_ns` falls inside `now - window`. Aligns with the daily
/// interval so each tick processes one fresh day.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum events to embed per dreaming pass. Above this the task
/// truncates with a warn â€” protects operator-LLM cost on
/// high-traffic days (a 5k-event day at ~50ms/embed = 4min compute).
/// Tunable via `dreaming.max_events_per_pass`.
pub const DEFAULT_MAX_EVENTS: usize = 500;

/// Spawn the dreaming task. Returns the `JoinHandle` so the caller
/// can `.abort()` on shutdown.
///
/// `interval = None` â†’ [`DEFAULT_INTERVAL`]. `window = None` â†’
/// [`DEFAULT_WINDOW`]. `max_events = None` â†’ [`DEFAULT_MAX_EVENTS`].
/// `embed_provider = None` â†’ deterministic theme labels only
/// (composer still runs, dreams still land). `chat_provider = Some`
/// (SPEC-12 Phase 4b) â†’ LLM-summarised cluster theme labels; `None`
/// keeps the deterministic `cluster-N-seed-id` labels. `writer = Some`
/// â†’ the daemon owns the WAL writer and each non-empty pass emits a
/// `0xF4 DREAM_COMPOSED` audit frame (`None` for one-shot callers that
/// audit separately, e.g. `neoth dream now`).
pub fn spawn(
    home: PathBuf,
    embed_provider: Option<std::sync::Arc<dyn EmbedProvider>>,
    chat_provider: Option<std::sync::Arc<AuthorizedProvider>>,
    interval: Option<Duration>,
    window: Option<Duration>,
    max_events: Option<usize>,
    writer: Option<WalWriterHandle>,
    auto_distill: bool,
) -> JoinHandle<Result<()>> {
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    let window = window.unwrap_or(DEFAULT_WINDOW);
    let max_events = max_events.unwrap_or(DEFAULT_MAX_EVENTS);
    tokio::spawn(async move {
        run(
            home,
            embed_provider,
            chat_provider,
            interval,
            window,
            max_events,
            writer,
            auto_distill,
        )
        .await
    })
}

async fn run(
    home: PathBuf,
    embed_provider: Option<std::sync::Arc<dyn EmbedProvider>>,
    chat_provider: Option<std::sync::Arc<AuthorizedProvider>>,
    interval: Duration,
    window: Duration,
    max_events: usize,
    writer: Option<WalWriterHandle>,
    auto_distill: bool,
) -> Result<()> {
    info!(
        interval_secs = interval.as_secs(),
        window_secs = window.as_secs(),
        max_events,
        embed_enabled = embed_provider.is_some(),
        summarize_themes = chat_provider.is_some(),
        "dreaming task started"
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick â€” fresh boot has no new events to
    // process yet (the prior daemon's last tick already covered
    // the window).
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match run_one_pass(
            &home,
            embed_provider.as_deref(),
            chat_provider.as_deref(),
            window,
            max_events,
            writer.as_ref(),
        )
        .await
        {
            Ok(report) => {
                if report.dreams_written > 0 {
                    info!(
                        events = report.events_considered,
                        dreams = report.dreams_written,
                        path = %report.path.display(),
                        "dreaming task wrote dream batch",
                    );
                    // OBSIDIAN-DREAMING-01 â€” push the just-composed day into the
                    // operator's vault so the Dreams folder stays fresh without a
                    // manual sync. Gate: a configured `obsidian_vault` IS the
                    // operator's vault opt-in. Dreams land only as bounded
                    // markdown under `<vault>/<subdir>/Dreams/` â€” they never
                    // re-enter recall/groundtruth, so no preload poisoning.
                    // The dream batch is already durable, so a vault failure
                    // cannot roll it back; surface it explicitly and retry on
                    // the next tick instead of silently treating policy/config
                    // corruption as "no vault configured".
                    if let Err(error) = sync_day_to_obsidian(&home, &report).await {
                        warn!(
                            error = %error,
                            "dreamâ†’Obsidian sync failed (dreams still persisted locally)"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "dreaming pass failed (will retry next tick)");
            }
        }
        // Slice C â€” nightly auto self-improve. In full-auto mode (or when the
        // operator explicitly enabled `auto`) stage a SkillOpt proposal so
        // improvements accrue without a manual `neoth self-improve run`. NEVER
        // auto-accepts: the review-then-adopt gate still requires an explicit
        // `accept`. Daemon-cron only â€” `neoth dream now` calls run_one_pass
        // directly and never triggers this. Best-effort: any miss logs + skips.
        self_improve_auto_pass(&home).await;
        // GOLD-ADAPT-KB-03 â€” Slice D: nightly distill scan (skills.auto_distill).
        // Reads trajectory JSONL under `~/trajectories/` and logs repeated
        // tool-call sequences via tracing. Daemon-cron only. Best-effort.
        if auto_distill {
            distill_auto_pass(&home).await;
        }
    }
}

/// GOLD-ADAPT-KB-03 â€” nightly background distill scan. Runs the same n-gram
/// scan as `neoth distill` but emits via `tracing::info` (no stdout) so it is
/// safe in the daemon loop. Best-effort: returns silently on any miss.
async fn distill_auto_pass(home: &std::path::Path) {
    let traj_dir = home.join("trajectories");
    let records = crate::cli::distill::read_trajectories(&traj_dir);
    if records.is_empty() {
        return;
    }
    let patterns = crate::cli::distill::find_repeated_sequences(&records, 3, 2);
    if patterns.is_empty() {
        return;
    }
    tracing::info!(
        pattern_count = patterns.len(),
        top_sequence = %patterns[0].sequence.join(" -> "),
        top_occurrences = patterns[0].occurrences,
        "distill: repeated tool-call sequences found -- consider `neoth distill`",
    );
}

#[cfg(test)]
mod distill_auto_pass_tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn distill_auto_pass_is_noop_on_missing_trajectories_dir() {
        // No trajectories dir under the temp home â†’ must return without panic.
        let dir = TempDir::new().unwrap();
        distill_auto_pass(dir.path()).await;
    }
}

/// Resolve the vault opt-in: a non-blank `obsidian_vault` gates the sync;
/// `obsidian_subdir` falls back to the default. Returns `None` when no vault
/// is configured (the operator has not opted into a vault) OR when the subdir
/// fails the path-traversal guard.
fn resolve_obsidian_target(
    vault: Option<String>,
    subdir: Option<String>,
) -> Option<(String, String)> {
    let vault = vault.filter(|v| !v.trim().is_empty())?;
    let subdir = subdir
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "NEOTH-sessions".to_string());
    // P2 guard: reuse the same validate_subdir() used by the normal Obsidian sync
    // path (cli::obsidian). Rejects `..` traversal, absolute paths, null bytes,
    // colons, backslashes, and multi-component values. Fail-closed: never write
    // outside the vault â€” log the bad value and return None (no panic, no sync).
    if let Err(e) = crate::cli::obsidian::validate_subdir(std::path::Path::new(&subdir)) {
        warn!(
            subdir = %subdir,
            error = %e,
            "dreaming: obsidian_subdir rejected by path-traversal guard; skipping vault sync"
        );
        return None;
    }
    Some((vault, subdir))
}

/// OBSIDIAN-DREAMING-01 â€” push the day a dream batch just landed in into the
/// operator's Obsidian vault. No-op when no `obsidian_vault` is configured.
/// The day is taken from the pass report's JSONL filename stem so the exact
/// composed day is synced (never a midnight-rollover mismatch). Runs the
/// blocking file write off the async runtime. A genuinely missing config uses
/// compiled defaults; an existing unreadable or malformed config is surfaced.
async fn sync_day_to_obsidian(home: &Path, report: &PassReport) -> Result<()> {
    let cfg = crate::config::FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))?;
    let Some((vault, subdir)) = resolve_obsidian_target(cfg.obsidian_vault, cfg.obsidian_subdir)
    else {
        return Ok(()); // vault not configured â†’ operator has not opted into a vault
    };
    let Some(day) = report
        .path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_string)
    else {
        return Ok(());
    };
    let home = home.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        crate::daemon::dreaming::sync_dreams_to_obsidian(
            &home,
            std::path::Path::new(&vault),
            &subdir,
            &day,
        )
    })
    .await??;
    if outcome.written {
        info!(
            day = %outcome.day,
            dreams = outcome.dream_count,
            path = %outcome.target_path.display(),
            "dreaming task synced day to Obsidian vault",
        );
    }
    Ok(())
}

/// Nightly auto self-improve pass (Slice C). Gated by the EFFECTIVE
/// self-improve switch (full-auto implies on, an explicit operator choice
/// wins) AND SkillOpt being installed. Stages one proposal for the default
/// persona's `skill.md`; the operator still must `neoth self-improve accept`
/// it. Runs the (blocking, possibly slow) engine off the async runtime.
async fn self_improve_auto_pass(home: &Path) {
    let home = home.to_path_buf();
    match tokio::task::spawn_blocking(move || self_improve_auto_pass_blocking(&home)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(error = %format!("{e:#}"), "self-improve auto-pass failed closed"),
        Err(e) => warn!(error = %e, "self-improve auto-pass task join failed"),
    }
}

fn self_improve_auto_pass_blocking(home: &Path) -> Result<()> {
    use crate::self_improve as si;
    let autonomy =
        match crate::config::FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml")) {
            Ok(config) => config.autonomy,
            Err(error) => {
                return Err(error)
                    .context("self-improve auto-pass: freedom.yaml invalid; refusing the tick");
            }
        };
    // B19: fail-closed â€” corrupt config stops this tick rather than defaulting
    // to auto-on and re-enabling a deliberately-disabled master switch.
    let cfg = match si::SelfImproveConfig::load_strict(home) {
        Ok(opt) => si::effective_from_option(opt, autonomy),
        Err(e) => return Err(e).context("self-improve auto-pass: config is corrupt"),
    };
    if !cfg.auto || !si::is_installed() {
        return Ok(()); // not in auto mode, or engine absent â†’ nothing to do
    }
    let persona = "default";
    // Don't pile up: if a proposal for this persona is already awaiting review,
    // skip this tick (and skip spawning the engine entirely).
    if si::load_proposals(home)?
        .iter()
        .any(|p| p.skill == persona && p.status == si::ProposalStatus::Pending)
    {
        return Ok(());
    }
    let skill_path = crate::skills::installer::default_skills_dir()
        .join(persona)
        .join("skill.md");
    let before = match std::fs::read_to_string(&skill_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read baseline skill {}", skill_path.display()));
        }
    };
    // F13 â€” bounded run: a hung/runaway SkillOpt python process must not block
    // the dreaming tick (best-effort "any miss logs + skips" contract).
    let (after, quality, parsed_spec) = match si::run_skillopt_capped(persona, si::SKILLOPT_TIMEOUT)
    {
        Ok(o) => si::parse_proposal_output(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => return Err(e).context("self-improve auto-pass: SkillOpt run failed/timed out"),
    };
    if after.trim().is_empty() || after == before {
        return Ok(()); // engine proposed nothing new â†’ don't stage a no-op
    }
    let now = crate::time::now_unix_i64();
    let id = format!("p{now}");
    let staged_id = si::stage_proposal(
        home,
        si::Proposal {
            id: id.clone(),
            skill: persona.to_string(),
            skill_path: skill_path.display().to_string(),
            before,
            after,
            summary: format!("nightly SkillOpt proposal for {persona}"),
            status: si::ProposalStatus::Pending,
            at_unix: now,
            backup: None,
            score_before: quality.score_before,
            score_after: quality.score_after,
            heldout_eval_summary: quality.heldout_eval_summary,
            why_this_improves: quality.why_this_improves,
            risk_notes: quality.risk_notes,
            spec: parsed_spec, // IMPR-01: carry parßÏ}¶‰žËkºwµçI•ì((€€€€m…Íå¹}ÑÉ…¥Ðèé…Íå¹}ÑÉ…¥Ñt(€€€¥µÁ°µ‰•‘AÉ½Ù¥‘•È™½È±Ý…åÍ]•…Ñ¡•Éµ‰•ì(€€€€€€€™¸¹…µ” ™Í•±˜¤€´ø€˜ÍÑ…Ñ¥ŒÍÑÈì(€€€€€€€€€€€€‰…±Ý…åÍ}Ý•…Ñ¡•Èˆ(€€€€€€€ô(€€€€€€€™¸‘•™…Õ±Ñ}‘¥´ ™Í•±˜¤€´øÕÍ¥é”ì(€€€€€€€€€€€€Ð(€€€€€€€ô(€€€€€€€…Íå¹Œ™¸•µ‰• (€€€€€€€€€€€€™Í•±˜°(€€€€€€€€€€€}É•ÄèÉ…Ñ”èéÁÉ½Ù¥‘•ÉÌèé•µ‰•èéµ‰•‘I•ÅÕ•ÍÐ°(€€€€€€€€¤€´øI•ÍÕ±ÐñÉ…Ñ”èéÁÉ½Ù¥‘•ÉÌèé•µ‰•èéµ‰•‘I•ÍÁ½¹Í”øì(€€€€€€€€€€€€¼¼±°Ñ•áÑÌ±…¹¥¸Í±½Ð€ÀƒŠH½Í¥¹”€ô€Ä¸À‰•ÑÝ••¸…¹ä(€€€€€€€€€€€€¼¼Á…¥ÈƒŠHÍ¥¹±”±ÕÍÑ•È¸(€€€€€€€€€€€±•ÐµÕÐØ€ôÙ•Œ…lÀ¸Á˜ÌÈì€Ñtì(€€€€€€€€€€€ÙlÁt€ô€Ä¸Àì(€€€€€€€€€€€=¬¡É…Ñ”èéÁÉ½Ù¥‘•ÉÌèé•µ‰•èéµ‰•‘I•ÍÁ½¹Í”ì(€€€€€€€€€€€€€€€Ù•Ñ½ÈèØ°(€€€€€€€€€€€€€€€µ½‘•°è€‰…±Ý…åÍ}Ý•…Ñ¡•Èˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€±…Ñ•¹äèÕÉ…Ñ¥½¸èé™É½µ}µ¥É½Ì Ä¤°(€€€€€€€€€€€ô¤(€€€€€€€ô(€€€ô((€€€ÍÑÉÕÐ…¥±¥¹µ‰•ì((€€€€m…Íå¹}ÑÉ…¥Ðèé…Íå¹}ÑÉ…¥Ñt(€€€¥µÁ°µ‰•‘AÉ½Ù¥‘•È™½È…¥±¥¹µ‰•ì(€€€€€€€™¸¹…µ” ™Í•±˜¤€´ø€˜ÍÑ…Ñ¥ŒÍÑÈì(€€€€€€€€€€€€‰™…¥±¥¹œˆ(€€€€€€€ô(€€€€€€€™¸‘•™…Õ±Ñ}‘¥´ ™Í•±˜¤€´øÕÍ¥é”ì(€€€€€€€€€€€€Ð(€€€€€€€ô(€€€€€€€…Íå¹Œ™¸•µ‰• (€€€€€€€€€€€€™Í•±˜°(€€€€€€€€€€€}É•ÄèÉ…Ñ”èéÁÉ½Ù¥‘•ÉÌèé•µ‰•èéµ‰•‘I•ÅÕ•ÍÐ°(€€€€€€€€¤€´øI•ÍÕ±ÐñÉ…Ñ”èéÁÉ½Ù¥‘•ÉÌèé•µ‰•èéµ‰•‘I•ÍÁ½¹Í”øì(€€€€€€€€€€€…¹å¡½Üèé‰…¥°„ ‰ÁÉ½Ù¥‘•È‘½Ý¸ˆ¤(€€€€€€€ô(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸½¹•}Á…ÍÍ}É•ÑÕÉ¹Í}•µÁÑå}É•Á½ÉÑ}™½É}µ¥ÍÍ¥¹}Ù¥•ÝÍ}‘ˆ ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€U1Q}]%9=\°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹•Ù•¹ÑÍ}½¹Í¥‘•É•°€À¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹‘É•…µÍ}ÝÉ¥ÑÑ•¸°€À¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹Á…Ñ¡}Ñ…­•¸°É•…µ¥¹A…Ñ èé•Ñ•Éµ¥¹¥ÍÑ¥Œ¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸½¹•}Á…ÍÍ}ÝÉ¥Ñ•Í}‘•Ñ•Éµ¥¹¥ÍÑ¥}‘É•…µ}Ý¡•¹}¹½}ÁÉ½Ù¥‘•È ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¸€ô¹½Ý}¹Ì ¤ì(€€€€€€€Í••‘}Ù¥•ÝÍ}‘ˆ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€€™l(€€€€€€€€€€€€€€€€ Ä°¸€´€ÌØÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰™¥ÉÍÐ•Ù•¹Ðˆ¤°(€€€€€€€€€€€€€€€€ È°¸€´€ÄàÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰Í•½¹•Ù•¹Ðˆ¤°(€€€€€€€€€€€t°(€€€€€€€€¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€U1Q}]%9=\°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹•Ù•¹ÑÍ}½¹Í¥‘•É•°€È¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹‘É•…µÍ}ÝÉ¥ÑÑ•¸°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹Á…Ñ¡}Ñ…­•¸°É•…µ¥¹A…Ñ èé•Ñ•Éµ¥¹¥ÍÑ¥Œ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡É•Á½ÉÐ¹Á…Ñ ¹•á¥ÍÑÌ ¤¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸½¹•}Á…ÍÍ}ÕÍ•Í}•µ‰•‘‘¥¹}Á…Ñ¡}Ý¡•¹}ÁÉ½Ù¥‘•É}…Ù…¥±…‰±” ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¸€ô¹½Ý}¹Ì ¤ì(€€€€€€€Í••‘}Ù¥•ÝÍ}‘ˆ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€€™l(€€€€€€€€€€€€€€€€ Ä°¸€´€ÌØÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰™¥ÉÍÐ•Ù•¹Ðˆ¤°(€€€€€€€€€€€€€€€€ È°¸€´€ÄàÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰Í•½¹•Ù•¹Ðˆ¤°(€€€€€€€€€€€€€€€€ Ì°¸€´€äÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰Ñ¡¥É•Ù•¹Ðˆ¤°(€€€€€€€€€€€t°(€€€€€€€€¤ì(€€€€€€€±•ÐÁÉ½Ù¥‘•È€ô±Ý…åÍ]•…Ñ¡•Éµ‰•ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€M½µ” ™ÁÉ½Ù¥‘•È¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€U1Q}]%9=\°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹•Ù•¹ÑÍ}½¹Í¥‘•É•°€Ì¤ì(€€€€€€€€¼¼±Ý…åÍ]•…Ñ¡•È½±±…ÁÍ•Ì•Ù•ÉåÑ¡¥¹œÑ¼½¹”±ÕÍÑ•ÈƒŠH€Ä‘É•…´¸(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹‘É•…µÍ}ÝÉ¥ÑÑ•¸°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹Á…Ñ¡}Ñ…­•¸°É•…µ¥¹A…Ñ èéµ‰•‘‘¥¹œ¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸½¹•}Á…ÍÍ}™…±±Í}‰…­}Ñ½}‘•Ñ•Éµ¥¹¥ÍÑ¥}Ý¡•¹}•µ‰•‘}™…¥±Ì ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¸€ô¹½Ý}¹Ì ¤ì(€€€€€€€Í••‘}Ù¥•ÝÍ}‘ˆ¡‘¥È¹Á…Ñ  ¤°€™l Ä°¸€´€ÌØÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰™¥ÉÍÐ•Ù•¹Ðˆ¥t¤ì(€€€€€€€±•ÐÁÉ½Ù¥‘•È€ô…¥±¥¹µ‰•ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€M½µ” ™ÁÉ½Ù¥‘•È¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€U1Q}]%9=\°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹•Ù•¹ÑÍ}½¹Í¥‘•É•°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹‘É•…µÍ}ÝÉ¥ÑÑ•¸°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•Á½ÉÐ¹Á…Ñ¡}Ñ…­•¸°(€€€€€€€€€€€É•…µ¥¹A…Ñ èé•Ñ•Éµ¥¹¥ÍÑ¥Œ°(€€€€€€€€€€€€‰ÁÉ½Ù¥‘•È•ÉÉ½ÈµÕÍÐÑÉ¥•È‘•Ñ•Éµ¥¹¥ÍÑ¥Œ™…±±‰…¬°¹•Ù•ÈÉ…Í ˆ(€€€€€€€€¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸½¹•}Á…ÍÍ}É•ÍÁ•ÑÍ}µ…á}•Ù•¹ÑÍ}ÑÉÕ¹…Ñ¥½¸ ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¸€ô¹½Ý}¹Ì ¤ì(€€€€€€€±•ÐÉ½ÝÌèY•Œñ|ø€ô€ Å¤ØÐ¸¸ôÄÀ¤(€€€€€€€€€€€€¹µ…À¡ñ¥ð€¡¤°¸€´¤€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰•Ù•¹Ðˆ¤¤(€€€€€€€€€€€€¹½±±•Ð ¤ì(€€€€€€€±•ÐÉ½ÝÍ}É•˜èY•Œñ|ø€ôÉ½ÝÌ¹¥Ñ•È ¤¹µ…À¡ð¡„°ˆ°Œ¥ð€ ©„°€©ˆ°€©Œ¤¤¹½±±•Ð ¤ì(€€€€€€€Í••‘}Ù¥•ÝÍ}‘ˆ¡‘¥È¹Á…Ñ  ¤°€™É½ÝÍ}É•˜¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ¡‘¥È¹Á…Ñ  ¤°9½¹”°9½¹”°U1Q}]%9=\°€Ì°9½¹”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹•Ù•¹ÑÍ}½¹Í¥‘•É•°€Ì°€‰ÑÉÕ¹…Ñ”…Ðµ…á}•Ù•¹ÑÌôÌˆ¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸½¹•}Á…ÍÍ}¥¹½É•Í}•Ù•¹ÑÍ}½ÕÑÍ¥‘•}Ý¥¹‘½Ü ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¸€ô¹½Ý}¹Ì ¤ì(€€€€€€€€¼¼=¹”•Ù•¹Ð¥¹Í¥‘”Ñ¡”€Äµ¡½ÕÈÑ•ÍÐÝ¥¹‘½Ü°½¹”½ÕÑÍ¥‘”¸(€€€€€€€Í••‘}Ù¥•ÝÍ}‘ˆ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€€™l(€€€€€€€€€€€€€€€€ Ä°¸€´€ØÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰¥¹Í¥‘”ˆ¤°€¼¼€ØÁÌ…¼(€€€€€€€€€€€€€€€€ È°¸€´€ÌØÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ€¨€ÈÐ°€‰½ÕÑÍ¥‘”ˆ¤°(€€€€€€€€€€€t°€¼¼€ÈÑ …¼(€€€€€€€€¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ÄàÀÀ¤°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•Á½ÉÐ¹•Ù•¹ÑÍ}½¹Í¥‘•É•°€Ä°(€€€€€€€€€€€€‰Ý¥¹‘½Ü•á±Õ‘•ÌÑ¡”€ÈÑ µ…¼É½Üˆ(€€€€€€€€¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ñ}…Ñ•Í}½¹}Ù…Õ±Ñ}…¹‘}‘•™…Õ±ÑÍ}ÍÕ‰‘¥È ¤ì(€€€€€€€€¼¼9¼Ù…Õ±ÐƒŠH9½¹”€¡½Á•É…Ñ½È¡…Ì¹½Ð½ÁÑ•¥¸¤¸(€€€€€€€…ÍÍ•ÉÐ„¡É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ð¡9½¹”°9½¹”¤¹¥Í}¹½¹” ¤¤ì(€€€€€€€…ÍÍ•ÉÐ„¡É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ð¡M½µ” ˆ€€€ˆ¹¥¹Ñ¼ ¤¤°9½¹”¤¹¥Í}¹½¹” ¤¤ì(€€€€€€€€¼¼Y…Õ±ÐÍ•Ð°¹¼ÍÕ‰‘¥ÈƒŠH‘•™…Õ±ÐÍÕ‰‘¥È¸(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ð¡M½µ” ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤¤°9½¹”¤°(€€€€€€€€€€€M½µ”  ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤°€‰9=Q µÍ•ÍÍ¥½¹Ìˆ¹¥¹Ñ¼ ¤¤¤(€€€€€€€€¤ì(€€€€€€€€¼¼Y…Õ±Ð€¬‰±…¹¬ÍÕ‰‘¥ÈƒŠH‘•™…Õ±Ðì•áÁ±¥¥ÐÍÕ‰‘¥È¡½¹½ÕÉ•¸(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ð¡M½µ” ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤¤°M½µ” ˆ€€ˆ¹¥¹Ñ¼ ¤¤¤°(€€€€€€€€€€€M½µ”  ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤°€‰9=Q µÍ•ÍÍ¥½¹Ìˆ¹¥¹Ñ¼ ¤¤¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ð¡M½µ” ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤¤°M½µ” ‰É•…µÌµÕÍÑ½´ˆ¹¥¹Ñ¼ ¤¤¤°(€€€€€€€€€€€M½µ”  ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤°€‰É•…µÌµÕÍÑ½´ˆ¹¥¹Ñ¼ ¤¤¤(€€€€€€€€¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ñ}É•©•ÑÍ}ÑÉ…Ù•ÉÍ…±}ÍÕ‰‘¥ÉÌ ¤ì(€€€€€€€€¼¼QÉ…Ù•ÉÍ…°¥¹ÁÕÑÌµÕÍÐ‰”É•©•Ñ•™…¥°µ±½Í•€¡¹¼ÝÉ¥Ñ”½ÕÑÍ¥‘”Ù…Õ±Ð¤¸(€€€€€€€™½È‰…¥¸€™lˆ¸¸¼¸¸½•Í…Á”ˆ°€ˆ¸¸ˆ°€ˆ½…‰Ì½Á…Ñ ‰tì(€€€€€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€€€€€É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ð¡M½µ” ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤¤°M½µ”  ©‰…¤¹¥¹Ñ¼ ¤¤¤¹¥Í}¹½¹” ¤°(€€€€€€€€€€€€€€€€‰•áÁ•Ñ•9½¹”™½È‰…ÍÕ‰‘¥Èí‰…èýôˆ(€€€€€€€€€€€€¤ì(€€€€€€€ô(€€€€€€€€¼¼±•…¸Í¥¹±”µ½µÁ½¹•¹Ð¹…µ•Ì…É”ÍÑ¥±°…•ÁÑ•¸(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ð¡M½µ” ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤¤°M½µ” ‰9=Q µÍ•ÍÍ¥½¹Ìˆ¹¥¹Ñ¼ ¤¤¤¹¥Í}Í½µ” ¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•Í½±Ù•}½‰Í¥‘¥…¹}Ñ…É•Ð¡M½µ” ˆ½Ù…Õ±Ðˆ¹¥¹Ñ¼ ¤¤°M½µ” ‰É•…µÌµÕÍÑ½´ˆ¹¥¹Ñ¼ ¤¤¤¹¥Í}Í½µ” ¤(€€€€€€€€¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸Ñ½‘…å}ÕÑ}‘…Ñ•}É•¹‘•ÉÍ}åååå}µµ}‘ ¤ì(€€€€€€€±•ÐÌ€ôÑ½‘…å}ÕÑ}‘…Ñ” ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ì¹±•¸ ¤°€ÄÀ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ì¹¡…ÉÌ ¤¹¹Ñ  Ð¤°M½µ” œ´œ¤¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ì¹¡…ÉÌ ¤¹¹Ñ  Ü¤°M½µ” œ´œ¤¤ì(€€€€€€€€¼¼¥ÉÍÐ€Ð¡…ÉÌÁ…ÉÍ”…Ìå•…È¸(€€€€€€€±•Ð|èÔÌÈ€ôÍl¸¸Ñt¹Á…ÉÍ” ¤¹Õ¹ÝÉ…À ¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸Ñ…Í­}…‰½ÉÑÍ}±•…¹±ä ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÑ…Í¬€ôÍÁ…Ý¸ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤¹Ñ½}Á…Ñ¡}‰Õ˜ ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€M½µ”¡ÕÉ…Ñ¥½¸èé™É½µ}µ¥±±¥Ì ÔÀ¤¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€ÑÉÕ”°€¼¼=1µAPµ-´ÀÌè…ÕÑ½}‘¥ÍÑ¥±°(€€€€€€€€¤ì(€€€€€€€Ñ½­¥¼èéÑ¥µ”èéÍ±••À¡ÕÉ…Ñ¥½¸èé™É½µ}µ¥±±¥Ì ÈÀ¤¤¹…Ý…¥Ðì(€€€€€€€Ñ…Í¬¹…‰½ÉÐ ¤ì(€€€€€€€±•Ð|€ôÑ…Í¬¹…Ý…¥Ðì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸½¹ÍÑ…¹ÑÍ}Á¥¹¹• ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡U1Q}%9QIY0¹…Í}Í•Ì ¤°€àÙ|ÐÀÀ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡U1Q}]%9=\¹…Í}Í•Ì ¤°€àÙ|ÐÀÀ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡U1Q}5a}Y9QL°€ÔÀÀ¤ì(€€€ô((€€€€¼¼ƒŠRŠR MA´ÄÈ‘…•µ½¸µÍ¥‘”€ÁáÐI5}=5A=M•µ¥Ð€¬¡…Ðµ±…‰•°Ý¥É¥¹œƒŠRŠRŠRŠRŠRŠR ((€€€€¼¼¼½Õ¹Ð€ÁáÐI5}=5A=M€™É…µ•Ì¥¸„Í•…±•]0Í•µ•¹Ð¸(€€€™¸½Õ¹Ñ}‘É•…µ}½µÁ½Í•‘}™É…µ•Ì¡Í•œè€™A…Ñ ¤€´øÕÍ¥é”ì(€€€€€€€±•Ð=¬¡‰åÑ•Ì¤€ôÍÑèé™ÌèéÉ•…¡Í•œ¤•±Í”ì(€€€€€€€€€€€É•ÑÕÉ¸€Àì(€€€€€€€ôì(€€€€€€€±•Ð=¬¡¡‘È¤€ôÉ…Ñ”èéÝ…°èéÍ•µ•¹Ñ}¡•…‘•ÈèéÁ…ÉÍ•}Í•µ•¹Ñ}¡•…‘•È ™‰åÑ•Ì¤•±Í”ì(€€€€€€€€€€€É•ÑÕÉ¸€Àì(€€€€€€€ôì(€€€€€€€±•ÐµÕÐÕÉÍ½È€ô¡‘È¹¡•…‘•É}±•¸ ¤ì(€€€€€€€±•ÐµÕÐ½Õ¹Ð€ô€ÁÕÍ¥é”ì(€€€€€€€Ý¡¥±”ÕÉÍ½È€ð‰åÑ•Ì¹±•¸ ¤ì(€€€€€€€€€€€±•Ð‘•Œ€ôµ…Ñ É…Ñ”èéÝ…°èé™É…µ”èé‘•½‘•}™É…µ” ™‰åÑ•ÍmÕÉÍ½È¸¹t¤ì(€€€€€€€€€€€€€€€=¬¡¤€ôø°(€€€€€€€€€€€€€€€ÉÈ¡|¤€ôø‰É•…¬°(€€€€€€€€€€€ôì(€€€€€€€€€€€¥˜‘•Œ¹¡•…‘•È¹•Ù•¹Ñ}ÑåÁ”€ôôÉ…Ñ”èéÝ…°èé•Ù•¹ÑÌèéY9Q}QeA}I5}=5A=Mì(€€€€€€€€€€€€€€€½Õ¹Ð€¬ô€Äì(€€€€€€€€€€€ô(€€€€€€€€€€€±•ÐÑ½Ñ…°€ô‘•Œ¹¡•…‘•È¹Ñ½Ñ…±}±•¸…ÌÕÍ¥é”ì(€€€€€€€€€€€¥˜Ñ½Ñ…°€ôô€Àì(€€€€€€€€€€€€€€€‰É•…¬ì(€€€€€€€€€€€ô(€€€€€€€€€€€ÕÉÍ½È€ôÕÉÍ½È¹Í…ÑÕÉ…Ñ¥¹}…‘¡Ñ½Ñ…°¤ì(€€€€€€€ô(€€€€€€€½Õ¹Ð(€€€ô((€€€€¼¼¼¡…ÐÁÉ½Ù¥‘•ÈÉ•ÑÕÉ¹¥¹œ„™¥á•É•Á±äƒŠP•á•É¥Í•ÌÑ¡”ÉÕ¹}½¹•}Á…ÍÌ(€€€€¼¼¼¡…Ðµ±…‰•°Ý¥É¥¹œ•¹µÑ¼µ•¹¸(€€€ÍÑÉÕÐ¥á•‘1…‰•±¡…Ðì(€€€€m…Íå¹}ÑÉ…¥Ðèé…Íå¹}ÑÉ…¥Ñt(€€€¥µÁ°AÉ½Ù¥‘•È™½È¥á•‘1…‰•±¡…Ðì(€€€€€€€™¸¹…µ” ™Í•±˜¤€´ø€˜ÍÑ…Ñ¥ŒÍÑÈì(€€€€€€€€€€€€‰™¥á•‘}±…‰•±}¡…Ðˆ(€€€€€€€ô(€€€€€€€…Íå¹Œ™¸½µÁ±•Ñ” (€€€€€€€€€€€€™Í•±˜°(€€€€€€€€€€€}É•ÄèÉ…Ñ”èéÁÉ½Ù¥‘•ÉÌèéI•ÅÕ•ÍÐ°(€€€€€€€€¤€´øI•ÍÕ±ÐñÉ…Ñ”èéÁÉ½Ù¥‘•ÉÌèé½µÁ±•Ñ¥½¸øì(€€€€€€€€€€€=¬¡É…Ñ”èéÁÉ½Ù¥‘•ÉÌèé½µÁ±•Ñ¥½¸ì(€€€€€€€€€€€€€€€Ñ•áÐè€‰Ý••­•¹ÑÉ¥ÀÁ±…¹¹¥¹œˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€¥‘•¹Ñ¥Ñäè•™…Õ±Ðèé‘•™…Õ±Ð ¤°(€€€€€€€€€€€€€€€µ½‘•°è€‰™¥á•‘}±…‰•±}¡…Ðˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€±…Ñ•¹äèÕÉ…Ñ¥½¸èé™É½µ}µ¥É½Ì Ä¤°(€€€€€€€€€€€€€€€¥¹ÁÕÑ}Ñ½­•¹Ìè9½¹”°(€€€€€€€€€€€€€€€½ÕÑÁÕÑ}Ñ½­•¹Ìè9½¹”°(€€€€€€€€€€€€€€€…¡•}É•…Ñ¥½¹}Ñ½­•¹Ìè9½¹”°(€€€€€€€€€€€€€€€…¡•}É•…‘}Ñ½­•¹Ìè9½¹”°(€€€€€€€€€€€ô¤(€€€€€€€ô(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÉÕ¹}½¹•}Á…ÍÍ}•µ¥ÑÍ}‘É•…µ}½µÁ½Í•‘}Ý¡•¹}ÝÉ¥Ñ•É}ÁÉ•Í•¹Ð ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¸€ô¹½Ý}¹Ì ¤ì(€€€€€€€Í••‘}Ù¥•ÝÍ}‘ˆ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€€™l Ä°¸€´€ÄàÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰…¸•Ù•¹Ð¥¸Ñ¡”Ý¥¹‘½Üˆ¥t°(€€€€€€€€¤ì(€€€€€€€±•ÐÍ•}‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÍ•œ€ôÍ•}‘¥È¹Á…Ñ  ¤¹©½¥¸ ˆÀÀÀÀÀÄ¹Ý…°ˆ¤ì(€€€€€€€±•Ð€¡ÝÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéÝ…°èéÝÉ¥Ñ•ÈèéÍÁ…Ý¸¡Í•œ¹±½¹” ¤¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€U1Q}]%9=\°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€M½µ” ™ÝÉ¥Ñ•È¤°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹‘É•…µÍ}ÝÉ¥ÑÑ•¸°€Ä¤ì((€€€€€€€‘É½À¡ÝÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…Ý…¥Ð¹½¬ ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€½Õ¹Ñ}‘É•…µ}½µÁ½Í•‘}™É…µ•Ì ™Í•œ¤°(€€€€€€€€€€€€Ä°(€€€€€€€€€€€€‰„ÝÉ¥Ñ•Èµ‰…­•Á…ÍÌÑ¡…ÐÝÉ½Ñ”‘É•…µÌµÕÍÐ•µ¥Ð•á…Ñ±ä½¹”€ÁáÐˆ°(€€€€€€€€¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÉÕ¹}½¹•}Á…ÍÍ}¹½}™É…µ•}Ý¡•¹}ÝÉ¥Ñ•É}¹½¹” ¤ì(€€€€€€€€¼¼Q¡”1$½¹”µÍ¡½ÐÁ…Ñ Á…ÍÍ•ÌÝÉ¥Ñ•È€ô9½¹”€¡¥Ð…Õ‘¥ÑÌÍ•Á…É…Ñ•±ä¤¸(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¸€ô¹½Ý}¹Ì ¤ì(€€€€€€€Í••‘}Ù¥•ÝÍ}‘ˆ¡‘¥È¹Á…Ñ  ¤°€™l Ä°¸€´€ÄàÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰•Ù•¹Ðˆ¥t¤ì(€€€€€€€±•ÐÍ•}‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÍ•œ€ôÍ•}‘¥È¹Á…Ñ  ¤¹©½¥¸ ˆÀÀÀÀÀÄ¹Ý…°ˆ¤ì(€€€€€€€±•Ð€¡ÝÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéÝ…°èéÝÉ¥Ñ•ÈèéÍÁ…Ý¸¡Í•œ¹±½¹” ¤¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€U1Q}]%9=\°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹‘É•…µÍ}ÝÉ¥ÑÑ•¸°€Ä¤ì((€€€€€€€‘É½À¡ÝÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…Ý…¥Ð¹½¬ ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€½Õ¹Ñ}‘É•…µ}½µÁ½Í•‘}™É…µ•Ì ™Í•œ¤°(€€€€€€€€€€€€À°(€€€€€€€€€€€€‰ÝÉ¥Ñ•È€ô9½¹”µÕÍÐ¹½Ð•µ¥Ð„™É…µ”½¸Ñ¡¥ÌÍ•µ•¹Ðˆ°(€€€€€€€€¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÉÕ¹}½¹•}Á…ÍÍ}¹½}™É…µ•}Ý¡•¹}¹½}‘É•…µÌ ¤ì(€€€€€€€€¼¼µÁÑäÝ¥¹‘½Ü€¡¹¼Ù¥•ÝÌ¹‘ˆ¤ƒŠH€À‘É•…µÌƒŠH¹¼…Õ‘¥Ð™É…µ”•Ù•¸Ý¥Ñ „ÝÉ¥Ñ•È¸(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÍ•}‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÍ•œ€ôÍ•}‘¥È¹Á…Ñ  ¤¹©½¥¸ ˆÀÀÀÀÀÄ¹Ý…°ˆ¤ì(€€€€€€€±•Ð€¡ÝÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéÝ…°èéÝÉ¥Ñ•ÈèéÍÁ…Ý¸¡Í•œ¹±½¹” ¤¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€9½¹”°(€€€€€€€€€€€U1Q}]%9=\°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€M½µ” ™ÝÉ¥Ñ•È¤°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹‘É•…µÍ}ÝÉ¥ÑÑ•¸°€À¤ì((€€€€€€€‘É½À¡ÝÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…Ý…¥Ð¹½¬ ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡½Õ¹Ñ}‘É•…µ}½µÁ½Í•‘}™É…µ•Ì ™Í•œ¤°€À¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÉÕ¹}½¹•}Á…ÍÍ}Ñ¡É•…‘Í}¡…Ñ}±…‰•±}¥¹Ñ½}‘É•…µÌ ¤ì(€€€€€€€€¼¼•µ‰•É½ÕÁÌ•Ù•ÉåÑ¡¥¹œ¥¹Ñ¼½¹”±ÕÍÑ•ÈìÑ¡”¡…ÐÁÉ½Ù¥‘•È±…‰•±Ì¥Ð¸(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¸€ô¹½Ý}¹Ì ¤ì(€€€€€€€Í••‘}Ù¥•ÝÍ}‘ˆ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€€™l(€€€€€€€€€€€€€€€€ Ä°¸€´€ÄàÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰™¥ÉÍÐˆ¤°(€€€€€€€€€€€€€€€€ È°¸€´€äÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°€‰Í•½¹ˆ¤°(€€€€€€€€€€€t°(€€€€€€€€¤ì(€€€€€€€±•Ð•µ‰•€ô±Ý…åÍ]•…Ñ¡•Éµ‰•ì(€€€€€€€±•Ð¡…Ð€ôÕÑ¡½É¥é•‘AÉ½Ù¥‘•Èèé™É½µ}‰½à (€€€€€€€€€€€	½àèé¹•Ü¡¥á•‘1…‰•±¡…Ð¤°(€€€€€€€€€€€É…Ñ”èéÁÉ½Ù¥‘•ÉÌèé½ÍÑ}…ÕÑ¡½É¥é…Ñ¥½¸èéAÉ½Ù¥‘•É…±±ÕÑ¡½É¥é•ÈèéÑ•ÍÑ}½¹±ä (€€€€€€€€€€€€€€€É…Ñ”èéÁ•Éµ¥ÍÍ¥½¹ÌèéÕÑ½¹½µå1•Ù•°èéÕ±°°(€€€€€€€€€€€€¤°(€€€€€€€€€€€M½µ” ‰™¥á•‘}±…‰•±}¡…Ðˆ¹Ñ½}ÍÑÉ¥¹œ ¤¤°(€€€€€€€€€€€€‰‘É•…µ¥¹œ¹Ñ…Í¬¹Ñ•ÍÐˆ°(€€€€€€€€¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôÉÕ¹}½¹•}Á…ÍÌ (€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€M½µ” ™•µ‰•¤°(€€€€€€€€€€€M½µ” ™¡…Ð¤°(€€€€€€€€€€€U1Q}]%9=\°(€€€€€€€€€€€U1Q}5a}Y9QL°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉÐ¹Á…Ñ¡}Ñ…­•¸°É•…µ¥¹A…Ñ èéµ‰•‘‘¥¹œ¤ì((€€€€€€€±•Ð‘…ä€ôÉ•Á½ÉÐ¹‘…å}±…‰•° ¤ì(€€€€€€€±•Ð‘É•…µÌ€ôÉ…Ñ”èé‘…•µ½¸èé‘É•…µ¥¹œèé±½…‘}‘É•…µÍ}™½É}‘…ä¡‘¥È¹Á…Ñ  ¤°€™‘…ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡‘É•…µÌ¹±•¸ ¤°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€‘É•…µÍlÁt¹Ñ¡•µ•}±…‰•°°€‰Ý••­•¹ÑÉ¥ÀÁ±…¹¹¥¹œˆ°(€€€€€€€€€€€€‰Ñ¡”114±…‰•°µÕÍÐÉ•Á±…”Ñ¡”‘•Ñ•Éµ¥¹¥ÍÑ¥Œ±ÕÍÑ•Èµ8µÍ••µ¥ˆ°(€€€€€€€€¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸‘É•…µ}½µÁ½Í•‘}Á…å±½…‘}¡…Í}ÍÑ…‰±•}Í¡…Á” ¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôA…ÍÍI•Á½ÉÐì(€€€€€€€€€€€•Ù•¹ÑÍ}½¹Í¥‘•É•è€Ô°(€€€€€€€€€€€‘É•…µÍ}ÝÉ¥ÑÑ•¸è€È°(€€€€€€€€€€€Á…Ñ èA…Ñ¡	Õ˜èé™É½´ ˆ½¡½µ”½½À¼¹¹•½Ñ ½‘É•…µÌ¼ÈÀÈØ´ÀØ´ÀÌ¹©Í½¹°ˆ¤°(€€€€€€€€€€€Á…Ñ¡}Ñ…­•¸èÉ•…µ¥¹A…Ñ èéµ‰•‘‘¥¹œ°(€€€€€€€ôì(€€€€€€€±•Ð‰åÑ•Ì€ô‘É•…µ}½µÁ½Í•‘}Á…å±½… ™É•Á½ÉÐ°€Å|ÜÀÁ|ÀÀÁ|ÀÀÀ¤ì(€€€€€€€±•ÐØèÍ•É‘•}©Í½¸èéY…±Õ”€ôÍ•É‘•}©Í½¸èé™É½µ}Í±¥” ™‰åÑ•Ì¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ùl‰‘…ä‰t°€ˆÈÀÈØ´ÀØ´ÀÌˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ùl‰‘É•…µÌ‰t°€È¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ùl‰•Ù•¹ÑÍ}½¹Í¥‘•É•‰t°€Ô¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ùl‰Á…Ñ¡}Ñ…­•¸‰t°€‰µ‰•‘‘¥¹œˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ùl‰ÑÍ}Õ¹¥à‰t°€Å|ÜÀÁ|ÀÀÁ|ÀÀÁ}ÔØÐ¤ì(€€€ô)ô