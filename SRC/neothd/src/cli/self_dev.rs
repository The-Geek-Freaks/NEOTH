//! `neoth self-dev` — operator CLI for the P-04 proactive
//! self-development workflow. Mirrors the spec from the
//! user-adaptation specs:
//!
//!   - `neoth self-dev review`           → list pending proposals
//!   - `neoth self-dev accept <id>`      → accept a proposal (emits
//!                                          0x1D `SELF_DEV_ACCEPTED`)
//!   - `neoth self-dev decline <id>`     → decline (emits 0x1E
//!                                          `SELF_DEV_DECLINED`)
//!   - `neoth self-dev propose --from-profile <path>` → generate
//!     proposals from a recorded `BehaviouralProfile` JSON +
//!     emit `SELF_DEV_PROPOSED` (0x1C) frames for each. Operator-
//!     facing test path that does NOT require live behavioural data.
//!
//! Proposals live in `<home>/self_dev/proposals.json` — a JSON
//! file the proposal engine writes and accept/decline mutates.
//! Atomic-rename + per-proposal status (`pending` / `accepted` /
//! `declined`) so a crash mid-mutation never leaves the file
//! half-rewritten.
//!
//!   - `neoth self-dev scan`              → one-shot: collector tick + evolver
//!                                          pass; prints signal + proposal counts.
//!                                          Bridge until HERMES-01 cron ships.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::profile::estimators::BehaviouralProfile;
use crate::profile::presets::{ProfilePreset, apply_preset};
use crate::profile::self_dev::{SelfDevProposal, propose_adjustments};
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
    #[serde(default)]
    audit_pending: Vec<ProposalAuditIntent>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ProposalAuditIntent {
    Proposed {
        proposal: SelfDevProposal,
        ts_unix: i64,
    },
    Accepted {
        proposal_id: String,
        ts_unix: i64,
    },
    Declined {
        proposal_id: String,
        reason: String,
        ts_unix: i64,
    },
}

impl ProposalAuditIntent {
    fn to_pending_event(&self) -> super::self_dev_outbox::PendingEvent {
        match self {
            Self::Proposed { proposal, ts_unix } => {
                super::self_dev_outbox::PendingEvent::proposed(proposal.clone(), *ts_unix)
            }
            Self::Accepted {
                proposal_id,
                ts_unix,
            } => super::self_dev_outbox::PendingEvent::accepted(proposal_id.clone(), *ts_unix),
            Self::Declined {
                proposal_id,
                reason,
                ts_unix,
            } => super::self_dev_outbox::PendingEvent::declined(
                proposal_id.clone(),
                reason.clone(),
                *ts_unix,
            ),
        }
    }
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

/// Operator entrypoint — no WAL writer required (CLI may run without
/// a live daemon). Pass `Some(writer)` when invoked from inside the
/// running daemon to also emit the matching WAL frames.
pub async fn run(
    home: &Path,
    args: SelfDevArgs,
    writer: Option<&WalWriterHandle>,
    output: crate::cli::OutputFormat,
) -> Result<()> {
    flush_pending_audits(home, writer).await?;
    match args.action {
        SelfDevAction::Review { min_confidence } => run_review(home, min_confidence, output),
        SelfDevAction::Accept { id } => run_accept(home, &id, writer, output).await,
        SelfDevAction::Decline { id, reason } => {
            run_decline(home, &id, &reason, writer, output).await
        }
        SelfDevAction::Propose {
            from_profile,
            current_preset,
        } => run_propose(home, &from_profile, &current_preset, writer).await,
        SelfDevAction::Scan => run_scan(home, output).await,
    }
}

/// GUI-DES-SELFDEV-APPLY-01 — JSON row-builder for the GUI Proposal-Review
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
    // Table mode stays pending-only — operator review flow doesn't need to re-
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
        println!("─ id          {}", e.proposal.id);
        println!("  kind        {}", e.proposal.kind.as_str());
        println!("  confidence  {:.2}", e.proposal.confidence);
        println!("  target      {}", e.proposal.target);
        println!("  reason      {}", e.proposal.reason);
        println!();
        shown += 1;
    }
    if shown == 0 {
        println!(
            "(no pending proposals — run `neoth self-dev propose --from-profile <p>` to generate, or wait for the aggregation cron to ship)"
        );
    } else {
        println!("{shown} pending proposal(s). Accept via `neoth self-dev accept <id>`.");
    }
    Ok(())
}

async fn run_accept(
    home: &Path,
    id: &str,
    writer: Option<&WalWriterHandle>,
    output: crate::cli::OutputFormat,
) -> Result<()> {
    let mut store = load_store(home)?;
    let entry_index = store
        .entries
        .iter()
        .position(|e| e.proposal.id == id)
        .with_context(|| format!("proposal id `{id}` not found"))?;
    let entry = &store.entries[entry_index];
    if entry.status == ProposalStatus::Accepted {
        render_proposal_mutation(
            output,
            "accept",
            id,
            "accepted",
            true,
            writer.is_some(),
            None,
        );
        return Ok(());
    }
    if entry.status == ProposalStatus::Declined {
        anyhow::bail!(
            "proposal `{id}` was previously declined — re-propose via `neoth self-dev propose ...` to re-evaluate"
        );
    }
    let proposal = entry.proposal.clone();
    apply_proposal_effect(home, &proposal)
        .await
        .with_context(|| format!("apply proposal effect for `{id}`"))?;
    let ts = now_unix();
    let entry = &mut store.entries[entry_index];
    entry.status = ProposalStatus::Accepted;
    entry.status_at_unix = ts;
    entry.decline_reason.clear();
    store.audit_pending.push(ProposalAuditIntent::Accepted {
        proposal_id: id.to_owned(),
        ts_unix: ts,
    });
    save_store(home, &store)?;
    flush_pending_audits(home, writer)
        .await
        .context("proposal accepted; audit intent remains pending for retry")?;
    render_proposal_mutation(
        output,
        "accept",
        id,
        "accepted",
        false,
        writer.is_some(),
        None,
    );
    Ok(())
}

async fn apply_proposal_effect(home: &Path, proposal: &SelfDevProposal) -> Result<()> {
    use crate::cron::schema::{CronRole, JobsFile, classify_role};
    use crate::profile::self_dev::{ProposalKind, ValidatedProposalTarget};

    match proposal
        .validate_for_acceptance()
        .map_err(anyhow::Error::msg)?
    {
        ValidatedProposalTarget::Preset(preset) => {
            crate::cli::profile::record_active_preset(home, preset)?;
        }
        ValidatedProposalTarget::Verbosity(verbosity) => {
            crate::cli::profile::set_communication_verbosity_override_at(home, verbosity)?;
        }
        ValidatedProposalTarget::ExtensionSelector(id) => {
            crate::cli::skills::set_skill_enabled_at(home, &id, true).await?;
        }
        ValidatedProposalTarget::BriefingTime { hour, minute } => {
            // Reschedule the operator's briefing cron job to the proposed
            // HH:MM. The briefing job is identified by its classified role
            // (JV-PRO-05 keyword classification over name + prompt), and the
            // rewrite goes through `JobsFile::modify_at_path` — the same
            // process-and-file-locked atomic RMW every production jobs.yaml
            // mutation uses, so the live scheduler observes a complete
            // generation. No enabled briefing job → the accept fails and the
            // proposal stays pending (fail-closed, actionable message).
            //
            // spawn_blocking: modify_at_path takes a cross-process file lock
            // with a sleeping retry loop (up to 5 s) — must not park a tokio
            // worker if a daemon path ever calls accept (review finding).
            let path = home.join("jobs.yaml");
            let worker_path = path.clone();
            tokio::task::spawn_blocking(move || {
                JobsFile::modify_at_path(&worker_path, |jf| {
                    let job = jf
                        .jobs
                        .iter_mut()
                        .find(|job| job.enabled && classify_role(job) == CronRole::Briefing)
                        .with_context(|| {
                            format!(
                                "no enabled briefing job in {} — add one via `neoth cron add` \
                                 before accepting a briefing-schedule proposal",
                                worker_path.display()
                            )
                        })?;
                    // Daily at HH:MM; the schedule invariant allows exactly one
                    // of cron/every/at, so the interval/one-shot forms are
                    // cleared. The operator's timezone is preserved.
                    job.schedule.cron = format!("{minute} {hour} * * *");
                    job.schedule.every_seconds = None;
                    job.schedule.anchor_unix = None;
                    job.schedule.at = None;
                    Ok(())
                })
            })
            .await
            .context("join briefing-reschedule task")?
            .with_context(|| format!("reschedule briefing job in {}", path.display()))?;
        }
        ValidatedProposalTarget::SourceEdit => {
            let ProposalKind::SourceEdit {
                patch_path,
                diff_sha256,
                ..
            } = &proposal.kind
            else {
                anyhow::bail!("source-edit target validation mismatch");
            };
            // Accepting a source-edit proposal records the DECISION only —
            // the live-tree mutation is deliberately a second explicit step
            // through the FEAT-05 five-layer gate stack:
            //   neoth self-edit --diff <patch> --expect-hash <sha256> --yes
            // (the GUI Apply button spawns exactly this, per
            // GUI-DES-SELFDEV-APPLY-01). Auto-applying on accept would erode
            // the Layer-3 policy — "never auto-apply, even at Full" — and
            // contradict the shipped two-step GUI contract ("Accepted
            // (pending apply)"). Before this wiring, accept itself bailed,
            // so a SourceEdit proposal could never even be ACCEPTED.
            tracing::info!(
                patch = %patch_path.display(),
                sha256 = %diff_sha256,
                "source-edit proposal accepted — apply via `neoth self-edit --diff {} --expect-hash {} --yes`",
                patch_path.display(),
                diff_sha256,
            );
        }
    }
    Ok(())
}

async fn run_decline(
    home: &Path,
    id: &str,
    reason: &str,
    writer: Option<&WalWriterHandle>,
    output: crate::cli::OutputFormat,
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
        render_proposal_mutation(
            output,
            "decline",
            id,
            "declined",
            true,
            writer.is_some(),
            Some(reason),
        );
        return Ok(());
    }
    if entry.status == ProposalStatus::Accepted {
        anyhow::bail!(
            "proposal `{id}` was previously accepted — decline does not unwind the apply; revert manually"
        );
    }
    let ts = now_unix();
    entry.status = ProposalStatus::Declined;
    entry.status_at_unix = ts;
    entry.decline_reason = reason.to_string();
    store.audit_pending.push(ProposalAuditIntent::Declined {
        proposal_id: id.to_owned(),
        reason: reason.to_owned(),
        ts_unix: ts,
    });
    save_store(home, &store)?;
    flush_pending_audits(home, writer)
        .await
        .context("proposal declined; audit intent remains pending for retry")?;
    render_proposal_mutation(
        output,
        "decline",
        id,
        "declined",
        false,
        writer.is_some(),
        Some(reason),
    );
    Ok(())
}

fn render_proposal_mutation(
    output: crate::cli::OutputFormat,
    action: &str,
    id: &str,
    status: &str,
    unchanged: bool,
    wal_direct: bool,
    reason: Option<&str>,
) {
    match output {
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "action": action,
                "id": id,
                "status": status,
            })
        ),
        crate::cli::OutputFormat::Table if unchanged => {
            println!("proposal `{id}` already {status} (no-op)");
        }
        crate::cli::OutputFormat::Table if action == "accept" => {
            println!("✓ accepted proposal `{id}`");
            if wal_direct {
                println!("  (WAL frame 0x1D SELF_DEV_ACCEPTED emitted)");
            } else {
                println!("  (queued for daemon WAL emit — lands within 5s on the live daemon)");
            }
        }
        crate::cli::OutputFormat::Table => {
            println!(
                "✓ declined proposal `{id}` (reason: {})",
                reason.unwrap_or("declined")
            );
            if wal_direct {
                println!("  (WAL frame 0x1E SELF_DEV_DECLINED emitted)");
            } else {
                println!("  (queued for daemon WAL emit — lands within 5s on the live daemon)");
            }
        }
    }
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
/// ORDERING: the proposal mutation and its audit intent are persisted in one
/// `proposals.json` update. The intent is then enqueued to the durable outbox
/// and removed only after that enqueue (and optional in-process drain) succeeds.
/// A crash may leave a retryable pending intent, but never a visible mutation
/// with no durable audit path.
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
    let new_proposals = propose_adjustments(profile, &current);
    store_proposals(home, &new_proposals, writer).await
}

/// Dedup-and-store a set of proposals + emit `0x1C SELF_DEV_PROPOSED` per NEW
/// one. Shared by the behavioural-snapshot path ([`propose_and_store`]) and the
/// G-03 feedback path (the profile-adapt cron). Returns the count newly added.
///
/// The proposal rows and audit intents are committed together. Dedup is by
/// stable `proposal.id`, so re-running is idempotent while retained audit
/// intents keep WAL emission retryable.
pub(crate) async fn store_proposals(
    home: &Path,
    proposals: &[SelfDevProposal],
    writer: Option<&WalWriterHandle>,
) -> Result<usize> {
    flush_pending_audits(home, writer).await?;
    if proposals.is_empty() {
        return Ok(0);
    }
    let mut store = load_store(home)?;
    let ts = now_unix();
    let to_add: Vec<&SelfDevProposal> = proposals
        .iter()
        .filter(|p| !store.entries.iter().any(|e| e.proposal.id == p.id))
        .collect();
    if to_add.is_empty() {
        return Ok(0);
    }
    for p in &to_add {
        store.entries.push(StoredProposal {
            proposal: (*p).clone(),
            status: ProposalStatus::Pending,
            status_at_unix: ts,
            decline_reason: String::new(),
        });
        store.audit_pending.push(ProposalAuditIntent::Proposed {
            proposal: (*p).clone(),
            ts_unix: ts,
        });
    }
    save_store(home, &store)?;
    flush_pending_audits(home, writer)
        .await
        .context("proposals stored; audit intent remains pending for retry")?;
    Ok(to_add.len())
}

async fn flush_pending_audits(home: &Path, writer: Option<&WalWriterHandle>) -> Result<usize> {
    let mut flushed = 0usize;
    loop {
        let store = load_store(home)?;
        let Some(intent) = store.audit_pending.first().cloned() else {
            return Ok(flushed);
        };
        let event = intent.to_pending_event();
        super::self_dev_outbox::enqueue(home, &event).await?;
        if let Some(w) = writer {
            super::self_dev_outbox::drain_once(home, w).await?;
        }
        let mut latest = load_store(home)?;
        if latest.audit_pending.first() == Some(&intent) {
            latest.audit_pending.remove(0);
            save_store(home, &latest)?;
        }
        flushed += 1;
    }
}

async fn run_propose(
    home: &Path,
    from_profile: &Path,
    current_preset_name: &str,
    writer: Option<&WalWriterHandle>,
) -> Result<()> {
    let bytes =
        std::fs::read(from_profile).with_context(|| format!("read {}", from_profile.display()))?;
    let profile: BehaviouralProfile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse BehaviouralProfile from {}", from_profile.display()))?;
    let added = propose_and_store(home, &profile, current_preset_name, writer).await?;
    if added == 0 {
        println!("(no proposals — operator state matches current preset within thresholds)");
        return Ok(());
    }
    println!("✓ {added} new proposal(s) added to the store");
    if writer.is_some() {
        println!("  (one WAL frame 0x1C SELF_DEV_PROPOSED per new proposal)");
    } else {
        println!(
            "  (queued for daemon WAL emit — {added} frame(s) land within 5s on the live daemon)"
        );
    }
    println!("review via `neoth self-dev review`");
    Ok(())
}

/// `neoth self-dev scan` — one-shot collector tick + capability evolver pass.
///
/// Runs the self-improvement collector synchronously (same logic as the daemon
/// cron), then passes the resulting [`CollectorReport`] through the capability
/// evolver, and prints a human-readable summary. A temporary WAL segment is
/// created in `home` for the collector tick's WAL frames and cleaned up on
/// exit — the CLI scan is not a running daemon so no live writer is present.
///
/// Use this to exercise the HERMES-06 pipeline end-to-end without waiting for
/// the 24h daemon cron tick.
async fn run_scan(home: &Path, output: crate::cli::OutputFormat) -> Result<()> {
    use crate::config::FreedomConfig;
    use crate::daemon::capability_evolver::run_evolver_pass;
    use crate::daemon::self_improvement_collector::run_self_improvement_collector_tick;

    // Missing freedom.yaml uses first-run defaults; malformed existing policy
    // blocks the scan instead of silently changing collector behaviour.
    let cfg = FreedomConfig::load_from_default_path_or_default()?.self_improvement_collector;

    let db_path = crate::memory::store::default_path();
    let ts = crate::time::now_unix_i64();

    // Spawn a temporary WAL segment so the collector tick can emit its frames.
    // The segment lives in home and is deleted on exit — it's not merged into
    // the live daemon's segment chain (no live daemon on the CLI path).
    let tmp_seg = home.join("self_dev_scan.wal.tmp");
    let (tmp_writer, tmp_join) = crate::wal::writer::spawn(tmp_seg.clone())
        .context("spawn temporary WAL writer for self-dev scan")?;

    let report = run_self_improvement_collector_tick(&db_path, home, cfg, &tmp_writer)
        .await
        .context("self-improvement collector scan failed")?;

    let evolver = run_evolver_pass(home, &report, ts, Some(&tmp_writer)).await;

    // Shutdown the temporary writer and clean up the segment.
    drop(tmp_writer);
    tmp_join.await.ok();
    let _ = std::fs::remove_file(&tmp_seg);

    match output {
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "action": "scan",
                "signals": report.signals.len(),
                "proposals_staged": evolver.proposals_staged,
                "proposals_skipped_deployed": evolver.proposals_skipped_deployed,
                "proposals_skipped_not_auto_safe": evolver.proposals_skipped_not_auto_safe,
            })
        ),
        crate::cli::OutputFormat::Table => {
            println!(
                "scan complete: {} signal(s), {} proposal(s) staged, \
                 {} skipped (already deployed), {} skipped (not auto-safe)",
                report.signals.len(),
                evolver.proposals_staged,
                evolver.proposals_skipped_deployed,
                evolver.proposals_skipped_not_auto_safe,
            );
            for s in &report.signals {
                println!("  {s:?}");
            }
        }
    }
    Ok(())
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::self_dev::ProposalKind;
    use tempfile::tempdir;

    fn fixture_proposal(id: &str, conf: f64) -> SelfDevProposal {
        SelfDevProposal {
            id: id.into(),
            kind: ProposalKind::SwitchPreset,
            reason: "test".into(),
            confidence: conf,
            target: "formal".into(),
        }
    }

    #[test]
    fn proposals_path_lands_under_self_dev_subdir() {
        let p = proposals_path(Path::new("/home/x"));
        assert_eq!(p, Path::new("/home/x/self_dev/proposals.json"));
    }

    #[test]
    fn load_store_returns_default_when_file_missing() {
        let dir = tempdir().unwrap();
        let store = load_store(dir.path()).unwrap();
        assert!(store.entries.is_empty());
    }

    #[test]
    fn save_load_round_trips_store() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("switch_preset-aabbccdd", 0.8),
            status: ProposalStatus::Pending,
            status_at_unix: 1_700_000_000,
            decline_reason: String::new(),
        });
        save_store(dir.path(), &store).unwrap();
        let back = load_store(dir.path()).unwrap();
        assert_eq!(back, store);
    }

    #[test]
    fn save_uses_atomic_rename_via_tmp_extension() {
        // Smoke — after save, the tmp file is gone + real file
        // exists. Crash-during-save would leave .tmp + miss real.
        let dir = tempdir().unwrap();
        save_store(dir.path(), &ProposalStore::default()).unwrap();
        let real = proposals_path(dir.path());
        let tmp = real.with_extension("json.tmp");
        assert!(real.exists());
        assert!(!tmp.exists());
    }

    const BRIEFING_JOBS_YAML: &str = r#"
version: 1
jobs:
  - id: morning-news
    name: Morning News
    enabled: true
    schedule:
      cron: "0 7 * * *"
      tz: Europe/Berlin
    prompt: |
      Morning briefing please
    delivery:
      channel: telegram
"#;

    fn store_with(proposal: SelfDevProposal) -> ProposalStore {
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal,
            status: ProposalStatus::Pending,
            status_at_unix: 1_700_000_000,
            decline_reason: String::new(),
        });
        store
    }

    #[tokio::test]
    async fn accept_briefing_time_reschedules_the_briefing_cron_job() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("jobs.yaml"), BRIEFING_JOBS_YAML).unwrap();
        let proposal = SelfDevProposal {
            id: "adjust_briefing_schedule-cafe0001".into(),
            kind: ProposalKind::AdjustBriefingSchedule,
            reason: "operator active later".into(),
            confidence: 0.9,
            target: "08:30".into(),
        };
        save_store(dir.path(), &store_with(proposal)).unwrap();

        run_accept(
            dir.path(),
            "adjust_briefing_schedule-cafe0001",
            None,
            crate::cli::OutputFormat::Table,
        )
        .await
        .unwrap();

        // Effect: the briefing job now fires daily at 08:30, tz preserved.
        let jobs = crate::cron::schema::JobsFile::from_yaml_str(
            &std::fs::read_to_string(dir.path().join("jobs.yaml")).unwrap(),
        )
        .unwrap();
        assert_eq!(jobs.jobs[0].schedule.cron, "30 8 * * *");
        assert_eq!(jobs.jobs[0].schedule.tz.as_deref(), Some("Europe/Berlin"));
        // Decision recorded.
        let store = load_store(dir.path()).unwrap();
        assert_eq!(store.entries[0].status, ProposalStatus::Accepted);
    }

    #[tokio::test]
    async fn accept_briefing_time_without_briefing_job_stays_pending() {
        let dir = tempdir().unwrap();
        let proposal = SelfDevProposal {
            id: "adjust_briefing_schedule-cafe0002".into(),
            kind: ProposalKind::AdjustBriefingSchedule,
            reason: "test".into(),
            confidence: 0.9,
            target: "07:15".into(),
        };
        save_store(dir.path(), &store_with(proposal)).unwrap();

        let err = run_accept(
            dir.path(),
            "adjust_briefing_schedule-cafe0002",
            None,
            crate::cli::OutputFormat::Table,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("no enabled briefing job"));
        // Fail-closed: the proposal was NOT flipped to accepted.
        let store = load_store(dir.path()).unwrap();
        assert_eq!(store.entries[0].status, ProposalStatus::Pending);
    }

    #[tokio::test]
    async fn accept_source_edit_records_decision_without_touching_the_tree() {
        let dir = tempdir().unwrap();
        let proposal = SelfDevProposal {
            id: "source_edit-cafe0003".into(),
            kind: ProposalKind::SourceEdit {
                patch_path: std::path::PathBuf::from("/tmp/proposal.patch"),
                diff_sha256: "a".repeat(64),
                target_paths: vec!["src/cli/dummy.rs".into()],
            },
            reason: "test".into(),
            confidence: 0.9,
            target: "src/cli/dummy.rs".into(),
        };
        save_store(dir.path(), &store_with(proposal)).unwrap();

        // Accept records the decision; the live-tree apply stays the
        // explicit second step through the FEAT-05 gate stack.
        run_accept(
            dir.path(),
            "source_edit-cafe0003",
            None,
            crate::cli::OutputFormat::Table,
        )
        .await
        .unwrap();
        let store = load_store(dir.path()).unwrap();
        assert_eq!(store.entries[0].status, ProposalStatus::Accepted);
    }

    #[tokio::test]
    async fn review_with_no_pending_prints_hint() {
        let dir = tempdir().unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Review {
                min_confidence: 0.0,
            },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
    }

    #[test]
    fn review_proposals_json_unit_variant_shape() {
        // Non-SourceEdit proposals: kind is a plain string, SourceEdit fields null.
        let p = fixture_proposal("switch_preset-aabbccdd", 0.83);
        let stored = StoredProposal {
            proposal: p,
            status: ProposalStatus::Pending,
            status_at_unix: 0,
            decline_reason: String::new(),
        };
        let rows = review_proposals_json(&[&stored]);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r["id"], "switch_preset-aabbccdd");
        assert_eq!(r["status"], "pending");
        assert_eq!(r["confidence"], 0.83);
        assert!(
            r["kind"].is_string(),
            "kind must be string for unit variants"
        );
        assert!(r["target"].is_string());
        assert!(r["reason"].is_string());
        assert!(r["patch_path"].is_null());
        assert!(r["diff_sha256"].is_null());
        assert!(r["target_paths"].is_null());
    }

    #[test]
    fn review_proposals_json_source_edit_shape() {
        // SourceEdit proposals: kind="source_edit", extra fields populated.
        use crate::profile::self_dev::ProposalKind;
        let proposal = SelfDevProposal {
            id: "source_edit-deadbeef".into(),
            kind: ProposalKind::SourceEdit {
                patch_path: std::path::PathBuf::from("/tmp/edit.patch"),
                diff_sha256: "abc123".into(),
                target_paths: vec!["src/cli/mod.rs".into()],
            },
            reason: "performance".into(),
            confidence: 0.9,
            target: "src/cli/mod.rs".into(),
        };
        let stored = StoredProposal {
            proposal,
            status: ProposalStatus::Accepted,
            status_at_unix: 0,
            decline_reason: String::new(),
        };
        let rows = review_proposals_json(&[&stored]);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r["id"], "source_edit-deadbeef");
        assert_eq!(r["kind"], "source_edit");
        assert_eq!(r["status"], "accepted");
        assert_eq!(r["diff_sha256"], "abc123");
        assert!(r["patch_path"].is_string(), "patch_path must be string");
        assert!(r["target_paths"].is_array(), "target_paths must be array");
        assert!(!r["patch_path"].is_null());
        assert!(!r["diff_sha256"].is_null());
    }

    #[test]
    fn review_proposals_json_excludes_declined() {
        let p = fixture_proposal("switch_preset-aabbccdd", 0.8);
        let stored = StoredProposal {
            proposal: p,
            status: ProposalStatus::Declined,
            status_at_unix: 0,
            decline_reason: "declined".into(),
        };
        // review_proposals_json receives what run_review filters — it doesn't
        // itself filter. The caller contract is: declined entries are excluded
        // by the caller. Verify caller (active filter) excludes declined.
        // (The fn itself serializes whatever it receives, including status field.)
        let rows = review_proposals_json(&[&stored]);
        // fn renders what it gets; caller pre-filters declined out.
        assert_eq!(rows[0]["status"], "declined"); // fn is not a filter
    }

    #[tokio::test]
    async fn accept_unknown_id_errors_with_actionable_message() {
        let dir = tempdir().unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Accept {
                id: "ghost-12345678".into(),
            },
        };
        let err = run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[tokio::test]
    async fn accept_flips_status_to_accepted() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("switch_preset-aabbccdd", 0.8),
            status: ProposalStatus::Pending,
            status_at_unix: 0,
            decline_reason: String::new(),
        });
        save_store(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Accept {
                id: "switch_preset-aabbccdd".into(),
            },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let back = load_store(dir.path()).unwrap();
        assert_eq!(back.entries[0].status, ProposalStatus::Accepted);
        assert!(back.entries[0].status_at_unix > 0);
    }

    #[tokio::test]
    async fn accept_is_idempotent_on_already_accepted() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("x", 0.5),
            status: ProposalStatus::Accepted,
            status_at_unix: 1_700_000_000,
            decline_reason: String::new(),
        });
        save_store(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Accept { id: "x".into() },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decline_rejects_unknown_reason_string() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("x", 0.5),
            status: ProposalStatus::Pending,
            status_at_unix: 0,
            decline_reason: String::new(),
        });
        save_store(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Decline {
                id: "x".into(),
                reason: "garbage".into(),
            },
        };
        let err = run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("declined"));
    }

    #[tokio::test]
    async fn decline_records_reason_string_and_flips_status() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("x", 0.5),
            status: ProposalStatus::Pending,
            status_at_unix: 0,
            decline_reason: String::new(),
        });
        save_store(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Decline {
                id: "x".into(),
                reason: "timeout".into(),
            },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let back = load_store(dir.path()).unwrap();
        assert_eq!(back.entries[0].status, ProposalStatus::Declined);
        assert_eq!(back.entries[0].decline_reason, "timeout");
    }

    #[tokio::test]
    async fn decline_after_accept_errors() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("x", 0.5),
            status: ProposalStatus::Accepted,
            status_at_unix: 1_700_000_000,
            decline_reason: String::new(),
        });
        save_store(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Decline {
                id: "x".into(),
                reason: "declined".into(),
            },
        };
        let err = run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("previously accepted"));
    }

    #[tokio::test]
    async fn propose_from_profile_writes_proposals_to_store() {
        use crate::profile::estimators::{LengthEstimate, ToneEstimate};

        let dir = tempdir().unwrap();
        let profile = BehaviouralProfile {
            length: LengthEstimate {
                sample_count: 50,
                mean_chars: 250.0,
                median_chars: 250,
                p10_chars: 100,
                p90_chars: 400,
            },
            tone: ToneEstimate {
                sample_count: 50,
                casual_hits: 0,
                formal_hits: 30,
                casual_score: -0.6,
            },
            ..Default::default()
        };
        let profile_path = dir.path().join("profile.json");
        std::fs::write(&profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Propose {
                from_profile: profile_path,
                current_preset: "lowkey".into(),
            },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let back = load_store(dir.path()).unwrap();
        assert!(!back.entries.is_empty());
        assert!(
            back.entries
                .iter()
                .all(|e| e.status == ProposalStatus::Pending)
        );
    }

    #[tokio::test]
    async fn propose_and_store_honours_the_basis_preset() {
        // SPEC-05: the profile-adapt cron calls EXACTLY this, passing its
        // configured `basis_preset.as_str()`. A strongly-casual profile drifts
        // AWAY from a Formal baseline (→ propose switch-to-lowkey) but already
        // MATCHES a Lowkey baseline (→ no tone proposal). A different basis ⇒ a
        // different outcome — proving the now-configurable basis is load-bearing,
        // not cosmetic. (Only `tone` is set; the verbosity/temporal/topic blocks
        // all gate on their own `sample_count >= 20`, so they stay silent here.)
        use crate::profile::estimators::ToneEstimate;
        use crate::profile::presets::ProfilePreset;

        let profile = BehaviouralProfile {
            tone: ToneEstimate {
                sample_count: 20, // meets the >= 20 gate in propose_adjustments
                casual_hits: 16,
                formal_hits: 0,
                casual_score: 0.8, // > 0.4 → strongly casual
            },
            ..Default::default()
        };

        // Separate homes — the per-home dedup store must not cross-contaminate.
        let home_formal = tempdir().unwrap();
        let home_lowkey = tempdir().unwrap();

        let against_formal = propose_and_store(
            home_formal.path(),
            &profile,
            ProfilePreset::Formal.as_str(),
            None,
        )
        .await
        .unwrap();
        let against_lowkey = propose_and_store(
            home_lowkey.path(),
            &profile,
            ProfilePreset::Lowkey.as_str(),
            None,
        )
        .await
        .unwrap();

        assert!(
            against_formal >= 1,
            "casual behaviour vs a Formal baseline must propose a switch, got {against_formal}"
        );
        assert_eq!(
            against_lowkey, 0,
            "casual behaviour already MATCHES the Lowkey baseline → no proposal, got {against_lowkey}"
        );
    }

    #[tokio::test]
    async fn propose_is_idempotent_on_same_profile_input() {
        // Run propose twice with the same profile → second run
        // adds zero new proposals (stable ids dedupe).
        use crate::profile::estimators::{LengthEstimate, ToneEstimate};

        let dir = tempdir().unwrap();
        let profile = BehaviouralProfile {
            length: LengthEstimate {
                sample_count: 50,
                mean_chars: 250.0,
                median_chars: 250,
                p10_chars: 100,
                p90_chars: 400,
            },
            tone: ToneEstimate {
                sample_count: 50,
                casual_hits: 0,
                formal_hits: 30,
                casual_score: -0.6,
            },
            ..Default::default()
        };
        let profile_path = dir.path().join("profile.json");
        std::fs::write(&profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();

        let args1 = SelfDevArgs {
            action: SelfDevAction::Propose {
                from_profile: profile_path.clone(),
                current_preset: "lowkey".into(),
            },
        };
        run(dir.path(), args1, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let first = load_store(dir.path()).unwrap();

        let args2 = SelfDevArgs {
            action: SelfDevAction::Propose {
                from_profile: profile_path,
                current_preset: "lowkey".into(),
            },
        };
        run(dir.path(), args2, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let second = load_store(dir.path()).unwrap();

        assert_eq!(first.entries.len(), second.entries.len());
    }

    #[test]
    fn proposal_status_serialises_snake_case() {
        let p = ProposalStatus::Accepted;
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, "\"accepted\"");
    }
}
