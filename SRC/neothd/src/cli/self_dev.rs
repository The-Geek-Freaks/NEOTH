//! `neoth self-dev` â€” operator CLI for the P-04 proactive
//! self-development workflow. Mirrors the spec from the
//! user-adaptation specs:
//!
//!   - `neoth self-dev review`           â†’ list pending proposals
//!   - `neoth self-dev accept <id>`      â†’ accept a proposal (emits
//!                                          0x1D `SELF_DEV_ACCEPTED`)
//!   - `neoth self-dev decline <id>`     â†’ decline (emits 0x1E
//!                                          `SELF_DEV_DECLINED`)
//!   - `neoth self-dev propose --from-profile <path>` â†’ generate
//!     proposals from a recorded `BehaviouralProfile` JSON +
//!     emit `SELF_DEV_PROPOSED` (0x1C) frames for each. Operator-
//!     facing test path that does NOT require live behavioural data.
//!
//! Proposals live in `<home>/self_dev/proposals.json` â€” a JSON
//! file the proposal engine writes and accept/decline mutates.
//! Atomic-rename + per-proposal status (`pending` / `accepted` /
//! `declined`) so a crash mid-mutation never leaves the file
//! half-rewritten.
//!
//!   - `neoth self-dev scan`              â†’ one-shot: collector tick + evolver
//!                                          pass; prints signal + proposal counts.
//!                                          Bridge until HERMES-01 cron ships.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::profile::estimators::BehaviouralProfile;
use crate::profile::presets::{ProfilePreset, apply_preset};
use crate::profile::self_dev::{SelfDevProposal, propose_adjustments};
use crate::wal::events::{
    EVENT_TYPE_SELF_DEV_ACCEPTED, EVENT_TYPE_SELF_DEV_DECLINED, EVENT_TYPE_SELF_DEV_PROPOSED,
};
use crate::wal::writer::WalWriterHandle;

#[derive(Args, Debug, Clone)]
pub struct SelfDevArgs {
    #[command(subcommand)]
    pub action: SelfDevAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SelfDevAction {
    /// List every pending proposal. `--min-confidence` filters by
    /// the engine's confidence estimate (0.0..=1.0).
    Review {
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
    },
    /// Accept a proposal by id (operator types e.g.
    /// `neoth self-dev accept switch_preset-a1b2c3d4`). Emits
    /// `EVENT_TYPE_SELF_DEV_ACCEPTED` (0x1D) when a WAL writer is
    /// available; otherwise records the decision in the local
    /// proposals.json only + warns.
    Accept { id: String },
    /// Decline a proposal. Reason `"declined"` (explicit) or
    /// `"timeout"` (operator never reviewed).
    Decline {
        id: String,
        #[arg(long, default_value = "declined")]
        reason: String,
    },
    /// Generate proposals from a `BehaviouralProfile` JSON. Operator-
    /// facing demonstration command: write the JSON via
    /// `neoth profile stats > profile.json` (future) or hand-craft
    /// for testing, then `neoth self-dev propose --from-profile
    /// profile.json` materialises the proposals + emits
    /// `EVENT_TYPE_SELF_DEV_PROPOSED` (0x1C) per proposal.
    Propose {
        #[arg(long)]
        from_profile: PathBuf,
        /// Treat the operator as currently on this preset for the
        /// proposal engine. Defaults to "lowkey" per the
        /// recommended-default hard rule.
        #[arg(long, default_value = "lowkey")]
        current_preset: String,
    },
    /// One-shot self-development scan: runs a collector tick then the
    /// HERMES-06 GAP-B capability evolver pass, and prints the
    /// `CollectorReport` + `EvolverReport`. Bridging command until
    /// HERMES-01 cron scheduling ships. WAL frames are emitted via a
    /// temporary segment that is cleaned up on exit.
    Scan,
}

/// Per-proposal status in the local store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Accepted,
    Declined,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredProposal {
    pub proposal: SelfDevProposal,
    pub status: ProposalStatus,
    /// Unix epoch seconds at which the status was last updated.
    pub status_at_unix: i64,
    /// `declined` / `timeout` when status == Declined; empty otherwise.
    pub decline_reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProposalStore {
    pub entries: Vec<StoredProposal>,
}

pub fn proposals_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("proposals.json")
}

pub fn load_store(home: &Path) -> Result<ProposalStore> {
    let path = proposals_path(home);
    if !path.exists() {
        return Ok(ProposalStore::default());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    if bytes.is_empty() {
        return Ok(ProposalStore::default());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

pub fn save_store(home: &Path, store: &ProposalStore) -> Result<()> {
    let path = proposals_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir -p {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(store)?;
    std::fs::write(&tmp, &bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Operator entrypoint â€” no WAL writer required (CLI may run without
/// a live daemon). Pass `Some(writer)` when invoked from inside the
/// running daemon to also emit the matching WAL frames.
pub async fn run(
    home: &Path,
    args: SelfDevArgs,
    writer: Option<&WalWriterHandle>,
    output: crate::cli::OutputFormat,
) -> Result<()> {
    match args.action {
        SelfDevAction::Review { min_confidence } => run_review(home, min_confidence, output),
        SelfDevAction::Accept { id } => run_accept(home, &id, writer).await,
        SelfDevAction::Decline { id, reason } => run_decline(home, &id, &reason, writer).await,
        SelfDevAction::Propose {
            from_profile,
            current_preset,
        } => run_propose(home, &from_profile, &current_preset, writer).await,
        SelfDevAction::Scan => run_scan(home).await,
    }
}

/// GUI-DES-SELFDEV-APPLY-01 â€” JSON row-builder for the GUI Proposal-Review
/// tab. Returns pending AND accepted entries (declined excluded) so the
/// "Apply to Source" button can fire on accepted SourceEdit proposals.
///
/// `SourceEdit` entries carry `patch_path`, `diff_sha256`, and `target_paths`
/// as top-level JSON fields. All other proposal kinds leave those fields `null`
/// for forward-compat with panel_logic's kind-string lookup.
fn review_proposals_json(entries: &[&StoredProposal]) -> Vec<serde_json::Value> {
    use crate::profile::self_dev::ProposalKind;
    entries
        .iter()
        .map(|e| {
            let status_str = match e.status {
                ProposalStatus::Pending => "pending",
                ProposalStatus::Accepted => "accepted",
                ProposalStatus::Declined => "declined",
            };
            match &e.proposal.kind {
                ProposalKind::SourceEdit {
                    patch_path,
                    diff_sha256,
                    target_paths,
                } => serde_json::json!({
                    "id":           e.proposal.id,
                    "kind":         "source_edit",
                    "confidence":   e.proposal.confidence,
                    "target":       e.proposal.target,
                    "reason":       e.proposal.reason,
                    "status":       status_str,
                    "patch_path":   patch_path.to_string_lossy(),
                    "diff_sha256":  diff_sha256,
                    "target_paths": target_paths,
                }),
                _ => serde_json::json!({
                    "id":           e.proposal.id,
                    "kind":         e.proposal.kind.as_str(),
                    "confidence":   e.proposal.confidence,
                    "target":       e.proposal.target,
                    "reason":       e.proposal.reason,
                    "status":       status_str,
                    "patch_path":   serde_json::Value::Null,
                    "diff_sha256":  serde_json::Value::Null,
                    "target_paths": serde_json::Value::Null,
                }),
            }
        })
        .collect()
}

fn run_review(home: &Path, min_confidence: f64, output: crate::cli::OutputFormat) -> Result<()> {
    let store = load_store(home)?;
    // JSON mode: include pending + accepted (GUI "Apply" button needs accepted
    // SourceEdit entries). Declined entries are excluded.
    // Table mode stays pending-only â€” operator review flow doesn't need to re-
    // read accepted ones in human output.
    let active: Vec<&StoredProposal> = store
        .entries
        .iter()
        .filter(|e| e.status != ProposalStatus::Declined && e.proposal.confidence >= min_confidence)
        .collect();
    if matches!(
        output,
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl
    ) {
        let rows = review_proposals_json(&active);
        println!("{}", serde_json::to_string(&rows)?);
        return Ok(());
    }
    let mut shown = 0usize;
    for e in &store.entries {
        if e.status != ProposalStatus::Pending {
            continue;
        }
        if e.proposal.confidence < min_confidence {
            continue;
        }
        println!("â”€ id          {}", e.proposal.id);
        println!("  kind        {}", e.proposal.kind.as_str());
        println!("  confidence  {:.2}", e.proposal.confidence);
        println!("  target      {}", e.proposal.target);
        println!("  reason      {}", e.proposal.reason);
        println!();
        shown += 1;
    }
    if shown == 0 {
        println!(
            "(no pending proposals â€” run `neoth self-dev propose --from-profile <p>` to generate, or wait for the aggregation cron to ship)"
        );
    } else {
        println!("{shown} pending proposal(s). Accept via `neoth self-dev accept <id>`.");
    }
    Ok(())
}

async fn run_accept(home: &Path, id: &str, writer: Option<&WalWriterHandle>) -> Result<()> {
    let mut store = load_store(home)?;
    let entry = store
        .entries
        .iter_mut()
        .find(|e| e.proposal.id == id)
        .with_context(|| format!("proposal id `{id}` not found"))?;
    if entry.status == ProposalStatus::Accepted {
        println!("proposal `{id}` already accepted (no-op)");
        return Ok(());
    }
    if entry.status == ProposalStatus::Declined {
        anyhow::bail!(
            "proposal `{id}` was previously declined â€” re-propose via `neoth self-dev propose ...` to re-evaluate"
        );
    }
    let ts = now_unix();
    entry.status = ProposalStatus::Accepted;
    entry.status_at_unix = ts;
    entry.decline_reason.clear();
    save_store(home, &store)?;
    println!("âœ“ accepted proposal `{id}`");
    if let Some(w) = writer {
        emit_accepted(w, id, ts).await?;
        println!("  (WAL frame 0x1D SELF_DEV_ACCEPTED emitted)");
    } else {
        // No in-process writer (CLI invocation). Enqueue for the
        // daemon's drain task so the WAL frame STILL lands.
        super::self_dev_outbox::enqueue(
            home,
            &super::self_dev_outbox::PendingEvent::accepted(id, ts),
        )
        .await?;
        println!("  (queued for daemon WAL emit â€” lands within 5s on the live daemon)");
    }
    Ok(())
}

async fn run_decline(
    home: &Path,
    id: &str,
    reason: &str,
    writer: Option<&WalWriterHandle>,
) -> Result<()> {
    if reason != "declined" && reason != "timeout" {
        anyhow::bail!("--reason must be `declined` or `timeout`, got `{reason}`");
    }
    let mut store = load_store(home)?;
    let entry = store
        .entries
        .iter_mut()
        .find(|e| e.proposal.id == id)
        .with_context(|| format!("proposal id `{id}` not found"))?;
    if entry.status == ProposalStatus::Declined {
        println!("proposal `{id}` already declined (no-op)");
        return Ok(());
    }
    if entry.status == ProposalStatus::Accepted {
        anyhow::bail!(
            "proposal `{id}` was previously accepted â€” decline does not unwind the apply; revert manually"
        );
    }
    let ts = now_unix();
    entry.status = ProposalStatus::Declined;
    entry.status_at_unix = ts;
    entry.decline_reason = reason.to_string();
    save_store(home, &store)?;
    println!("âœ“ declined proposal `{id}` (reason: {reason})");
    if let Some(w) = writer {
        emit_declined(w, id, reason, ts).await?;
        println!("  (WAL frame 0x1E SELF_DEV_DECLINED emitted)");
    } else {
        super::self_dev_outbox::enqueue(
            home,
            &super::self_dev_outbox::PendingEvent::declined(id, reason, ts),
        )
        .await?;
        println!("  (queued for daemon WAL emit â€” lands within 5s on the live daemon)");
    }
    Ok(())
}

/// Shared proposal-generation core (SPEC-05 extracted this from
/// `run_propose` so the daemon's passive-adaptation cron
/// (`daemon::profile_adapt_cron`) reuses the EXACT dedup + store + WAL-emit
/// logic instead of duplicating it). Given an already-loaded behavioural
/// profile + the current preset name, runs `propose_adjustments`, keeps
/// only proposals whose stable id isn't already in the store (idempotent),
/// emits a `0x1C SELF_DEV_PROPOSED` frame per new proposal (direct when a
/// `writer` is present, else enqueued to the self-dev outbox for the daemon
/// to drain), and returns the count of NEW proposals.
///
/// ORDERING (Session 30 review-fix): the store is persisted to
/// `proposals.json` BEFORE any WAL frame is emitted. The earlier order
/// (emit-then-save) had a crash window â€” a kill between the last
/// `emit_proposed` and the single trailing `save_store` left `0x1C` frames
/// in the WAL for proposals absent from `proposals.json`; the next cron
/// tick's dedup (which reads the store) then missed them and re-emitted â†’
/// duplicate WAL frames the operator never saw in `neoth self-dev review`.
/// Persist-first inverts the failure mode to the benign one: a crash after
/// `save_store` but before emit leaves a proposal that IS in the store
/// (visible in review, dedup-safe) but lacks its audit frame â€” no
/// duplicates, no phantom frames.
pub(crate) async fn propose_and_store(
    home: &Path,
    profile: &BehaviouralProfile,
    current_preset_name: &str,
    writer: Option<&WalWriterHandle>,
) -> Result<usize> {
    let current = match ProfilePreset::parse(current_preset_name) {
        Some(p) => apply_preset(p),
        None => apply_preset(ProfilePreset::Lowkey),
    };
    let new_proposalsÛn»¶‰žËkºwµçQ¼ ¤°(€€€€€€€ô(€€€ô((€€€€mÑ•ÍÑt(€€€™¸ÁÉ½Á½Í…±Í}Á…Ñ¡}±…¹‘Í}Õ¹‘•É}Í•±™}‘•Ù}ÍÕ‰‘¥È ¤ì(€€€€€€€±•ÐÀ€ôÁÉ½Á½Í…±Í}Á…Ñ ¡A…Ñ èé¹•Ü ˆ½¡½µ”½àˆ¤¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡À°A…Ñ èé¹•Ü ˆ½¡½µ”½à½Í•±™}‘•Ø½ÁÉ½Á½Í…±Ì¹©Í½¸ˆ¤¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸±½…‘}ÍÑ½É•}É•ÑÕÉ¹Í}‘•™…Õ±Ñ}Ý¡•¹}™¥±•}µ¥ÍÍ¥¹œ ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÍÑ½É”€ô±½…‘}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡ÍÑ½É”¹•¹ÑÉ¥•Ì¹¥Í}•µÁÑä ¤¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸Í…Ù•}±½…‘}É½Õ¹‘}ÑÉ¥ÁÍ}ÍÑ½É” ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐµÕÐÍÑ½É”€ôAÉ½Á½Í…±MÑ½É”èé‘•™…Õ±Ð ¤ì(€€€€€€€ÍÑ½É”¹•¹ÑÉ¥•Ì¹ÁÕÍ ¡MÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°è™¥áÑÕÉ•}ÁÉ½Á½Í…° ‰ÍÝ¥Ñ¡}ÁÉ•Í•Ðµ……‰‰‘ˆ°€À¸à¤°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèéA•¹‘¥¹œ°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€Å|ÜÀÁ|ÀÀÁ|ÀÀÀ°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ô¤ì(€€€€€€€Í…Ù•}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤°€™ÍÑ½É”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð‰…¬€ô±½…‘}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡‰…¬°ÍÑ½É”¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸Í…Ù•}ÕÍ•Í}…Ñ½µ¥}É•¹…µ•}Ù¥…}ÑµÁ}•áÑ•¹Í¥½¸ ¤ì(€€€€€€€€¼¼Mµ½­”ƒŠP…™Ñ•ÈÍ…Ù”°Ñ¡”ÑµÀ™¥±”¥Ì½¹”€¬É•…°™¥±”(€€€€€€€€¼¼•á¥ÍÑÌ¸É…Í µ‘ÕÉ¥¹œµÍ…Ù”Ý½Õ±±•…Ù”€¹ÑµÀ€¬µ¥ÍÌÉ•…°¸(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€Í…Ù•}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤°€™AÉ½Á½Í…±MÑ½É”èé‘•™…Õ±Ð ¤¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÉ•…°€ôÁÉ½Á½Í…±Í}Á…Ñ ¡‘¥È¹Á…Ñ  ¤¤ì(€€€€€€€±•ÐÑµÀ€ôÉ•…°¹Ý¥Ñ¡}•áÑ•¹Í¥½¸ ‰©Í½¸¹ÑµÀˆ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡É•…°¹•á¥ÍÑÌ ¤¤ì(€€€€€€€…ÍÍ•ÉÐ„ …ÑµÀ¹•á¥ÍÑÌ ¤¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸É•Ù¥•Ý}Ý¥Ñ¡}¹½}Á•¹‘¥¹}ÁÉ¥¹ÑÍ}¡¥¹Ð ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð…ÉÌ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èéI•Ù¥•Üì(€€€€€€€€€€€€€€€µ¥¹}½¹™¥‘•¹”è€À¸À°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€ÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸É•Ù¥•Ý}ÁÉ½Á½Í…±Í}©Í½¹}Õ¹¥Ñ}Ù…É¥…¹Ñ}Í¡…Á” ¤ì(€€€€€€€€¼¼9½¸µM½ÕÉ•‘¥ÐÁÉ½Á½Í…±Ìè­¥¹¥Ì„Á±…¥¸ÍÑÉ¥¹œ°M½ÕÉ•‘¥Ð™¥•±‘Ì¹Õ±°¸(€€€€€€€±•ÐÀ€ô™¥áÑÕÉ•}ÁÉ½Á½Í…° ‰ÍÝ¥Ñ¡}ÁÉ•Í•Ðµ……‰‰‘ˆ°€À¸àÌ¤ì(€€€€€€€±•ÐÍÑ½É•€ôMÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°èÀ°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèéA•¹‘¥¹œ°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€À°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ôì(€€€€€€€±•ÐÉ½ÝÌ€ôÉ•Ù¥•Ý}ÁÉ½Á½Í…±Í}©Í½¸ ™l™ÍÑ½É•‘t¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É½ÝÌ¹±•¸ ¤°€Ä¤ì(€€€€€€€±•ÐÈ€ô€™É½ÝÍlÁtì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Él‰¥‰t°€‰ÍÝ¥Ñ¡}ÁÉ•Í•Ðµ……‰‰‘ˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Él‰ÍÑ…ÑÕÌ‰t°€‰Á•¹‘¥¹œˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Él‰½¹™¥‘•¹”‰t°€À¸àÌ¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€Él‰­¥¹‰t¹¥Í}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€€‰­¥¹µÕÍÐ‰”ÍÑÉ¥¹œ™½ÈÕ¹¥ÐÙ…É¥…¹ÑÌˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÐ„¡Él‰Ñ…É•Ð‰t¹¥Í}ÍÑÉ¥¹œ ¤¤ì(€€€€€€€…ÍÍ•ÉÐ„¡Él‰É•…Í½¸‰t¹¥Í}ÍÑÉ¥¹œ ¤¤ì(€€€€€€€…ÍÍ•ÉÐ„¡Él‰Á…Ñ¡}Á…Ñ ‰t¹¥Í}¹Õ±° ¤¤ì(€€€€€€€…ÍÍ•ÉÐ„¡Él‰‘¥™™}Í¡„ÈÔØ‰t¹¥Í}¹Õ±° ¤¤ì(€€€€€€€…ÍÍ•ÉÐ„¡Él‰Ñ…É•Ñ}Á…Ñ¡Ì‰t¹¥Í}¹Õ±° ¤¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸É•Ù¥•Ý}ÁÉ½Á½Í…±Í}©Í½¹}Í½ÕÉ•}•‘¥Ñ}Í¡…Á” ¤ì(€€€€€€€€¼¼M½ÕÉ•‘¥ÐÁÉ½Á½Í…±Ìè­¥¹ô‰Í½ÕÉ•}•‘¥Ðˆ°•áÑÉ„™¥•±‘ÌÁ½ÁÕ±…Ñ•¸(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½™¥±”èéÍ•±™}‘•ØèéAÉ½Á½Í…±-¥¹ì(€€€€€€€±•ÐÁÉ½Á½Í…°€ôM•±™•ÙAÉ½Á½Í…°ì(€€€€€€€€€€€¥è€‰Í½ÕÉ•}•‘¥Ðµ‘•…‘‰••˜ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€­¥¹èAÉ½Á½Í…±-¥¹èéM½ÕÉ•‘¥Ðì(€€€€€€€€€€€€€€€Á…Ñ¡}Á…Ñ èÍÑèéÁ…Ñ èéA…Ñ¡	Õ˜èé™É½´ ˆ½ÑµÀ½•‘¥Ð¹Á…Ñ ˆ¤°(€€€€€€€€€€€€€€€‘¥™™}Í¡„ÈÔØè€‰…‰ŒÄÈÌˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€Ñ…É•Ñ}Á…Ñ¡ÌèÙ•Œ…l‰ÍÉŒ½±¤½µ½¹ÉÌˆ¹¥¹Ñ¼ ¥t°(€€€€€€€€€€€ô°(€€€€€€€€€€€É•…Í½¸è€‰Á•É™½Éµ…¹”ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€½¹™¥‘•¹”è€À¸ä°(€€€€€€€€€€€Ñ…É•Ðè€‰ÍÉŒ½±¤½µ½¹ÉÌˆ¹¥¹Ñ¼ ¤°(€€€€€€€ôì(€€€€€€€±•ÐÍÑ½É•€ôMÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèé•ÁÑ•°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€À°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ôì(€€€€€€€±•ÐÉ½ÝÌ€ôÉ•Ù¥•Ý}ÁÉ½Á½Í…±Í}©Í½¸ ™l™ÍÑ½É•‘t¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É½ÝÌ¹±•¸ ¤°€Ä¤ì(€€€€€€€±•ÐÈ€ô€™É½ÝÍlÁtì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Él‰¥‰t°€‰Í½ÕÉ•}•‘¥Ðµ‘•…‘‰••˜ˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Él‰­¥¹‰t°€‰Í½ÕÉ•}•‘¥Ðˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Él‰ÍÑ…ÑÕÌ‰t°€‰…•ÁÑ•ˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Él‰‘¥™™}Í¡„ÈÔØ‰t°€‰…‰ŒÄÈÌˆ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡Él‰Á…Ñ¡}Á…Ñ ‰t¹¥Í}ÍÑÉ¥¹œ ¤°€‰Á…Ñ¡}Á…Ñ µÕÍÐ‰”ÍÑÉ¥¹œˆ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡Él‰Ñ…É•Ñ}Á…Ñ¡Ì‰t¹¥Í}…ÉÉ…ä ¤°€‰Ñ…É•Ñ}Á…Ñ¡ÌµÕÍÐ‰”…ÉÉ…äˆ¤ì(€€€€€€€…ÍÍ•ÉÐ„ …Él‰Á…Ñ¡}Á…Ñ ‰t¹¥Í}¹Õ±° ¤¤ì(€€€€€€€…ÍÍ•ÉÐ„ …Él‰‘¥™™}Í¡„ÈÔØ‰t¹¥Í}¹Õ±° ¤¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸É•Ù¥•Ý}ÁÉ½Á½Í…±Í}©Í½¹}•á±Õ‘•Í}‘•±¥¹• ¤ì(€€€€€€€±•ÐÀ€ô™¥áÑÕÉ•}ÁÉ½Á½Í…° ‰ÍÝ¥Ñ¡}ÁÉ•Í•Ðµ……‰‰‘ˆ°€À¸à¤ì(€€€€€€€±•ÐÍÑ½É•€ôMÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°èÀ°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèé•±¥¹•°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€À°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸è€‰‘•±¥¹•ˆ¹¥¹Ñ¼ ¤°(€€€€€€€ôì(€€€€€€€€¼¼É•Ù¥•Ý}ÁÉ½Á½Í…±Í}©Í½¸É••¥Ù•ÌÝ¡…ÐÉÕ¹}É•Ù¥•Ü™¥±Ñ•ÉÌƒŠP¥Ð‘½•Í¸Ð(€€€€€€€€¼¼¥ÑÍ•±˜™¥±Ñ•È¸Q¡”…±±•È½¹ÑÉ…Ð¥Ìè‘•±¥¹••¹ÑÉ¥•Ì…É”•á±Õ‘•(€€€€€€€€¼¼‰äÑ¡”…±±•È¸Y•É¥™ä…±±•È€¡…Ñ¥Ù”™¥±Ñ•È¤•á±Õ‘•Ì‘•±¥¹•¸(€€€€€€€€¼¼€¡Q¡”™¸¥ÑÍ•±˜Í•É¥…±¥é•ÌÝ¡…Ñ•Ù•È¥ÐÉ••¥Ù•Ì°¥¹±Õ‘¥¹œÍÑ…ÑÕÌ™¥•±¸¤(€€€€€€€±•ÐÉ½ÝÌ€ôÉ•Ù¥•Ý}ÁÉ½Á½Í…±Í}©Í½¸ ™l™ÍÑ½É•‘t¤ì(€€€€€€€€¼¼™¸É•¹‘•ÉÌÝ¡…Ð¥Ð•ÑÌì…±±•ÈÁÉ”µ™¥±Ñ•ÉÌ‘•±¥¹•½ÕÐ¸(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É½ÝÍlÁul‰ÍÑ…ÑÕÌ‰t°€‰‘•±¥¹•ˆ¤ì€¼¼™¸¥Ì¹½Ð„™¥±Ñ•È(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸…•ÁÑ}Õ¹­¹½Ý¹}¥‘}•ÉÉ½ÉÍ}Ý¥Ñ¡}…Ñ¥½¹…‰±•}µ•ÍÍ…” ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð…ÉÌ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èé•ÁÐì(€€€€€€€€€€€€€€€¥è€‰¡½ÍÐ´ÄÈÌÐÔØÜàˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€±•Ð•ÉÈ€ôÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…Á}•ÉÈ ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡•ÉÈ¹Ñ½}ÍÑÉ¥¹œ ¤¹½¹Ñ…¥¹Ì ‰¡½ÍÐˆ¤¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸…•ÁÑ}™±¥ÁÍ}ÍÑ…ÑÕÍ}Ñ½}…•ÁÑ• ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐµÕÐÍÑ½É”€ôAÉ½Á½Í…±MÑ½É”èé‘•™…Õ±Ð ¤ì(€€€€€€€ÍÑ½É”¹•¹ÑÉ¥•Ì¹ÁÕÍ ¡MÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°è™¥áÑÕÉ•}ÁÉ½Á½Í…° ‰ÍÝ¥Ñ¡}ÁÉ•Í•Ðµ……‰‰‘ˆ°€À¸à¤°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèéA•¹‘¥¹œ°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€À°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ô¤ì(€€€€€€€Í…Ù•}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤°€™ÍÑ½É”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð…ÉÌ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èé•ÁÐì(€€€€€€€€€€€€€€€¥è€‰ÍÝ¥Ñ¡}ÁÉ•Í•Ðµ……‰‰‘ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€ÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð‰…¬€ô±½…‘}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡‰…¬¹•¹ÑÉ¥•ÍlÁt¹ÍÑ…ÑÕÌ°AÉ½Á½Í…±MÑ…ÑÕÌèé•ÁÑ•¤ì(€€€€€€€…ÍÍ•ÉÐ„¡‰…¬¹•¹ÑÉ¥•ÍlÁt¹ÍÑ…ÑÕÍ}…Ñ}Õ¹¥à€ø€À¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸…•ÁÑ}¥Í}¥‘•µÁ½Ñ•¹Ñ}½¹}…±É•…‘å}…•ÁÑ• ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐµÕÐÍÑ½É”€ôAÉ½Á½Í…±MÑ½É”èé‘•™…Õ±Ð ¤ì(€€€€€€€ÍÑ½É”¹•¹ÑÉ¥•Ì¹ÁÕÍ ¡MÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°è™¥áÑÕÉ•}ÁÉ½Á½Í…° ‰àˆ°€À¸Ô¤°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèé•ÁÑ•°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€Å|ÜÀÁ|ÀÀÁ|ÀÀÀ°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ô¤ì(€€€€€€€Í…Ù•}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤°€™ÍÑ½É”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð…ÉÌ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èé•ÁÐì¥è€‰àˆ¹¥¹Ñ¼ ¤ô°(€€€€€€€ôì(€€€€€€€ÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸‘•±¥¹•}É•©•ÑÍ}Õ¹­¹½Ý¹}É•…Í½¹}ÍÑÉ¥¹œ ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐµÕÐÍÑ½É”€ôAÉ½Á½Í…±MÑ½É”èé‘•™…Õ±Ð ¤ì(€€€€€€€ÍÑ½É”¹•¹ÑÉ¥•Ì¹ÁÕÍ ¡MÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°è™¥áÑÕÉ•}ÁÉ½Á½Í…° ‰àˆ°€À¸Ô¤°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèéA•¹‘¥¹œ°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€À°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ô¤ì(€€€€€€€Í…Ù•}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤°€™ÍÑ½É”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð…ÉÌ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èé•±¥¹”ì(€€€€€€€€€€€€€€€¥è€‰àˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€É•…Í½¸è€‰…É‰…”ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€±•Ð•ÉÈ€ôÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…Á}•ÉÈ ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡•ÉÈ¹Ñ½}ÍÑÉ¥¹œ ¤¹½¹Ñ…¥¹Ì ‰‘•±¥¹•ˆ¤¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸‘•±¥¹•}É•½É‘Í}É•…Í½¹}ÍÑÉ¥¹}…¹‘}™±¥ÁÍ}ÍÑ…ÑÕÌ ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐµÕÐÍÑ½É”€ôAÉ½Á½Í…±MÑ½É”èé‘•™…Õ±Ð ¤ì(€€€€€€€ÍÑ½É”¹•¹ÑÉ¥•Ì¹ÁÕÍ ¡MÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°è™¥áÑÕÉ•}ÁÉ½Á½Í…° ‰àˆ°€À¸Ô¤°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèéA•¹‘¥¹œ°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€À°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ô¤ì(€€€€€€€Í…Ù•}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤°€™ÍÑ½É”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð…ÉÌ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èé•±¥¹”ì(€€€€€€€€€€€€€€€¥è€‰àˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€É•…Í½¸è€‰Ñ¥µ•½ÕÐˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€ÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð‰…¬€ô±½…‘}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡‰…¬¹•¹ÑÉ¥•ÍlÁt¹ÍÑ…ÑÕÌ°AÉ½Á½Í…±MÑ…ÑÕÌèé•±¥¹•¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡‰…¬¹•¹ÑÉ¥•ÍlÁt¹‘•±¥¹•}É•…Í½¸°€‰Ñ¥µ•½ÕÐˆ¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸‘•±¥¹•}…™Ñ•É}…•ÁÑ}•ÉÉ½ÉÌ ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐµÕÐÍÑ½É”€ôAÉ½Á½Í…±MÑ½É”èé‘•™…Õ±Ð ¤ì(€€€€€€€ÍÑ½É”¹•¹ÑÉ¥•Ì¹ÁÕÍ ¡MÑ½É•‘AÉ½Á½Í…°ì(€€€€€€€€€€€ÁÉ½Á½Í…°è™¥áÑÕÉ•}ÁÉ½Á½Í…° ‰àˆ°€À¸Ô¤°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèé•ÁÑ•°(€€€€€€€€€€€ÍÑ…ÑÕÍ}…Ñ}Õ¹¥àè€Å|ÜÀÁ|ÀÀÁ|ÀÀÀ°(€€€€€€€€€€€‘•±¥¹•}É•…Í½¸èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ô¤ì(€€€€€€€Í…Ù•}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤°€™ÍÑ½É”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð…ÉÌ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èé•±¥¹”ì(€€€€€€€€€€€€€€€¥è€‰àˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€É•…Í½¸è€‰‘•±¥¹•ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€±•Ð•ÉÈ€ôÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…Á}•ÉÈ ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡•ÉÈ¹Ñ½}ÍÑÉ¥¹œ ¤¹½¹Ñ…¥¹Ì ‰ÁÉ•Ù¥½ÕÍ±ä…•ÁÑ•ˆ¤¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÁÉ½Á½Í•}™É½µ}ÁÉ½™¥±•}ÝÉ¥Ñ•Í}ÁÉ½Á½Í…±Í}Ñ½}ÍÑ½É” ¤ì(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½™¥±”èé•ÍÑ¥µ…Ñ½ÉÌèéí1•¹Ñ¡ÍÑ¥µ…Ñ”°Q½¹•ÍÑ¥µ…Ñ•ôì((€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÁÉ½™¥±”€ô	•¡…Ù¥½ÕÉ…±AÉ½™¥±”ì(€€€€€€€€€€€±•¹Ñ è1•¹Ñ¡ÍÑ¥µ…Ñ”ì(€€€€€€€€€€€€€€€Í…µÁ±•}½Õ¹Ðè€ÔÀ°(€€€€€€€€€€€€€€€µ•…¹}¡…ÉÌè€ÈÔÀ¸À°(€€€€€€€€€€€€€€€µ•‘¥…¹}¡…ÉÌè€ÈÔÀ°(€€€€€€€€€€€€€€€ÀÄÁ}¡…ÉÌè€ÄÀÀ°(€€€€€€€€€€€€€€€ÀäÁ}¡…ÉÌè€ÐÀÀ°(€€€€€€€€€€€ô°(€€€€€€€€€€€Ñ½¹”èQ½¹•ÍÑ¥µ…Ñ”ì(€€€€€€€€€€€€€€€Í…µÁ±•}½Õ¹Ðè€ÔÀ°(€€€€€€€€€€€€€€€…ÍÕ…±}¡¥ÑÌè€À°(€€€€€€€€€€€€€€€™½Éµ…±}¡¥ÑÌè€ÌÀ°(€€€€€€€€€€€€€€€…ÍÕ…±}Í½É”è€´À¸Ø°(€€€€€€€€€€€ô°(€€€€€€€€€€€€¸¹•™…Õ±Ðèé‘•™…Õ±Ð ¤(€€€€€€€ôì(€€€€€€€±•ÐÁÉ½™¥±•}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰ÁÉ½™¥±”¹©Í½¸ˆ¤ì(€€€€€€€ÍÑèé™ÌèéÝÉ¥Ñ” ™ÁÉ½™¥±•}Á…Ñ °Í•É‘•}©Í½¸èéÑ½}Ù•Œ ™ÁÉ½™¥±”¤¹Õ¹ÝÉ…À ¤¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð…ÉÌ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èéAÉ½Á½Í”ì(€€€€€€€€€€€€€€€™É½µ}ÁÉ½™¥±”èÁÉ½™¥±•}Á…Ñ °(€€€€€€€€€€€€€€€ÕÉÉ•¹Ñ}ÁÉ•Í•Ðè€‰±½Ý­•äˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€ÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð‰…¬€ô±½…‘}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÐ„ …‰…¬¹•¹ÑÉ¥•Ì¹¥Í}•µÁÑä ¤¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€‰…¬¹•¹ÑÉ¥•Ì(€€€€€€€€€€€€€€€€¹¥Ñ•È ¤(€€€€€€€€€€€€€€€€¹…±°¡ñ•ð”¹ÍÑ…ÑÕÌ€ôôAÉ½Á½Í…±MÑ…ÑÕÌèéA•¹‘¥¹œ¤(€€€€€€€€¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÁÉ½Á½Í•}…¹‘}ÍÑ½É•}¡½¹½ÕÉÍ}Ñ¡•}‰…Í¥Í}ÁÉ•Í•Ð ¤ì(€€€€€€€€¼¼MA´ÀÔèÑ¡”ÁÉ½™¥±”µ…‘…ÁÐÉ½¸…±±ÌaQ1dÑ¡¥Ì°Á…ÍÍ¥¹œ¥ÑÌ(€€€€€€€€¼¼½¹™¥ÕÉ•‰…Í¥Í}ÁÉ•Í•Ð¹…Í}ÍÑÈ ¥€¸ÍÑÉ½¹±äµ…ÍÕ…°ÁÉ½™¥±”‘É¥™ÑÌ(€€€€€€€€¼¼]d™É½´„½Éµ…°‰…Í•±¥¹”€£ŠHÁÉ½Á½Í”ÍÝ¥Ñ µÑ¼µ±½Ý­•ä¤‰ÕÐ…±É•…‘ä(€€€€€€€€¼¼5Q!L„1½Ý­•ä‰…Í•±¥¹”€£ŠH¹¼Ñ½¹”ÁÉ½Á½Í…°¤¸‘¥™™•É•¹Ð‰…Í¥ÌƒŠH„(€€€€€€€€¼¼‘¥™™•É•¹Ð½ÕÑ½µ”ƒŠPÁÉ½Ù¥¹œÑ¡”¹½Üµ½¹™¥ÕÉ…‰±”‰…Í¥Ì¥Ì±½…µ‰•…É¥¹œ°(€€€€€€€€¼¼¹½Ð½Íµ•Ñ¥Œ¸€¡=¹±äÑ½¹•€¥ÌÍ•ÐìÑ¡”Ù•É‰½Í¥Ñä½Ñ•µÁ½É…°½Ñ½Á¥Œ‰±½­Ì(€€€€€€€€¼¼…±°…Ñ”½¸Ñ¡•¥È½Ý¸Í…µÁ±•}½Õ¹Ð€øô€ÈÁ€°Í¼Ñ¡•äÍÑ…äÍ¥±•¹Ð¡•É”¸¤(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½™¥±”èé•ÍÑ¥µ…Ñ½ÉÌèéQ½¹•ÍÑ¥µ…Ñ”ì(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½™¥±”èéÁÉ•Í•ÑÌèéAÉ½™¥±•AÉ•Í•Ðì((€€€€€€€±•ÐÁÉ½™¥±”€ô	•¡…Ù¥½ÕÉ…±AÉ½™¥±”ì(€€€€€€€€€€€Ñ½¹”èQ½¹•ÍÑ¥µ…Ñ”ì(€€€€€€€€€€€€€€€Í…µÁ±•}½Õ¹Ðè€ÈÀ°€¼¼µ••ÑÌÑ¡”€øô€ÈÀ…Ñ”¥¸ÁÉ½Á½Í•}…‘©ÕÍÑµ•¹ÑÌ(€€€€€€€€€€€€€€€…ÍÕ…±}¡¥ÑÌè€ÄØ°(€€€€€€€€€€€€€€€™½Éµ…±}¡¥ÑÌè€À°(€€€€€€€€€€€€€€€…ÍÕ…±}Í½É”è€À¸à°€¼¼€ø€À¸ÐƒŠHÍÑÉ½¹±ä…ÍÕ…°(€€€€€€€€€€€ô°(€€€€€€€€€€€€¸¹•™…Õ±Ðèé‘•™…Õ±Ð ¤(€€€€€€€ôì((€€€€€€€€¼¼M•Á…É…Ñ”¡½µ•ÌƒŠPÑ¡”Á•Èµ¡½µ”‘•‘ÕÀÍÑ½É”µÕÍÐ¹½ÐÉ½ÍÌµ½¹Ñ…µ¥¹…Ñ”¸(€€€€€€€±•Ð¡½µ•}™½Éµ…°€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¡½µ•}±½Ý­•ä€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€±•Ð……¥¹ÍÑ}™½Éµ…°€ôÁÉ½Á½Í•}…¹‘}ÍÑ½É” (€€€€€€€€€€€¡½µ•}™½Éµ…°¹Á…Ñ  ¤°(€€€€€€€€€€€€™ÁÉ½™¥±”°(€€€€€€€€€€€AÉ½™¥±•AÉ•Í•Ðèé½Éµ…°¹…Í}ÍÑÈ ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð……¥¹ÍÑ}±½Ý­•ä€ôÁÉ½Á½Í•}…¹‘}ÍÑ½É” (€€€€€€€€€€€¡½µ•}±½Ý­•ä¹Á…Ñ  ¤°(€€€€€€€€€€€€™ÁÉ½™¥±”°(€€€€€€€€€€€AÉ½™¥±•AÉ•Í•Ðèé1½Ý­•ä¹…Í}ÍÑÈ ¤°(€€€€€€€€€€€9½¹”°(€€€€€€€€¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…À ¤ì((€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€……¥¹ÍÑ}™½Éµ…°€øô€Ä°(€€€€€€€€€€€€‰…ÍÕ…°‰•¡…Ù¥½ÕÈÙÌ„½Éµ…°‰…Í•±¥¹”µÕÍÐÁÉ½Á½Í”„ÍÝ¥Ñ °½Ðí……¥¹ÍÑ}™½Éµ…±ôˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€……¥¹ÍÑ}±½Ý­•ä°€À°(€€€€€€€€€€€€‰…ÍÕ…°‰•¡…Ù¥½ÕÈ…±É•…‘ä5Q!LÑ¡”1½Ý­•ä‰…Í•±¥¹”ƒŠH¹¼ÁÉ½Á½Í…°°½Ðí……¥¹ÍÑ}±½Ý­•åôˆ(€€€€€€€€¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÁÉ½Á½Í•}¥Í}¥‘•µÁ½Ñ•¹Ñ}½¹}Í…µ•}ÁÉ½™¥±•}¥¹ÁÕÐ ¤ì(€€€€€€€€¼¼IÕ¸ÁÉ½Á½Í”ÑÝ¥”Ý¥Ñ Ñ¡”Í…µ”ÁÉ½™¥±”ƒŠHÍ•½¹ÉÕ¸(€€€€€€€€¼¼…‘‘Ìé•É¼¹•ÜÁÉ½Á½Í…±Ì€¡ÍÑ…‰±”¥‘Ì‘•‘ÕÁ”¤¸(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½™¥±”èé•ÍÑ¥µ…Ñ½ÉÌèéí1•¹Ñ¡ÍÑ¥µ…Ñ”°Q½¹•ÍÑ¥µ…Ñ•ôì((€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÁÉ½™¥±”€ô	•¡…Ù¥½ÕÉ…±AÉ½™¥±”ì(€€€€€€€€€€€±•¹Ñ è1•¹Ñ¡ÍÑ¥µ…Ñ”ì(€€€€€€€€€€€€€€€Í…µÁ±•}½Õ¹Ðè€ÔÀ°(€€€€€€€€€€€€€€€µ•…¹}¡…ÉÌè€ÈÔÀ¸À°(€€€€€€€€€€€€€€€µ•‘¥…¹}¡…ÉÌè€ÈÔÀ°(€€€€€€€€€€€€€€€ÀÄÁ}¡…ÉÌè€ÄÀÀ°(€€€€€€€€€€€€€€€ÀäÁ}¡…ÉÌè€ÐÀÀ°(€€€€€€€€€€€ô°(€€€€€€€€€€€Ñ½¹”èQ½¹•ÍÑ¥µ…Ñ”ì(€€€€€€€€€€€€€€€Í…µÁ±•}½Õ¹Ðè€ÔÀ°(€€€€€€€€€€€€€€€…ÍÕ…±}¡¥ÑÌè€À°(€€€€€€€€€€€€€€€™½Éµ…±}¡¥ÑÌè€ÌÀ°(€€€€€€€€€€€€€€€…ÍÕ…±}Í½É”è€´À¸Ø°(€€€€€€€€€€€ô°(€€€€€€€€€€€€¸¹•™…Õ±Ðèé‘•™…Õ±Ð ¤(€€€€€€€ôì(€€€€€€€±•ÐÁÉ½™¥±•}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰ÁÉ½™¥±”¹©Í½¸ˆ¤ì(€€€€€€€ÍÑèé™ÌèéÝÉ¥Ñ” ™ÁÉ½™¥±•}Á…Ñ °Í•É‘•}©Í½¸èéÑ½}Ù•Œ ™ÁÉ½™¥±”¤¹Õ¹ÝÉ…À ¤¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€±•Ð…ÉÌÄ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èéAÉ½Á½Í”ì(€€€€€€€€€€€€€€€™É½µ}ÁÉ½™¥±”èÁÉ½™¥±•}Á…Ñ ¹±½¹” ¤°(€€€€€€€€€€€€€€€ÕÉÉ•¹Ñ}ÁÉ•Í•Ðè€‰±½Ý­•äˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€ÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌÄ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð™¥ÉÍÐ€ô±½…‘}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€±•Ð…ÉÌÈ€ôM•±™•ÙÉÌì(€€€€€€€€€€€…Ñ¥½¸èM•±™•ÙÑ¥½¸èéAÉ½Á½Í”ì(€€€€€€€€€€€€€€€™É½µ}ÁÉ½™¥±”èÁÉ½™¥±•}Á…Ñ °(€€€€€€€€€€€€€€€ÕÉÉ•¹Ñ}ÁÉ•Í•Ðè€‰±½Ý­•äˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€ôì(€€€€€€€ÉÕ¸¡‘¥È¹Á…Ñ  ¤°…ÉÌÈ°9½¹”°É…Ñ”èé±¤èé=ÕÑÁÕÑ½Éµ…ÐèéQ…‰±”¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÍ•½¹€ô±½…‘}ÍÑ½É”¡‘¥È¹Á…Ñ  ¤¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€…ÍÍ•ÉÑ}•Ä„¡™¥ÉÍÐ¹•¹ÑÉ¥•Ì¹±•¸ ¤°Í•½¹¹•¹ÑÉ¥•Ì¹±•¸ ¤¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸ÁÉ½Á½Í…±}ÍÑ…ÑÕÍ}Í•É¥…±¥Í•Í}Í¹…­•}…Í” ¤ì(€€€€€€€±•ÐÀ€ôAÉ½Á½Í…±MÑ…ÑÕÌèé•ÁÑ•ì(€€€€€€€±•ÐÌ€ôÍ•É‘•}©Í½¸èéÑ½}ÍÑÉ¥¹œ ™À¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ì°€‰p‰…•ÁÑ•‘pˆˆ¤ì(€€€ô)ô(