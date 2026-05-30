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

/// Operator entrypoint — no WAL writer required (CLI may run without
/// a live daemon). Pass `Some(writer)` when invoked from inside the
/// running daemon to also emit the matching WAL frames.
pub async fn run(home: &Path, args: SelfDevArgs, writer: Option<&WalWriterHandle>) -> Result<()> {
    match args.action {
        SelfDevAction::Review { min_confidence } => run_review(home, min_confidence),
        SelfDevAction::Accept { id } => run_accept(home, &id, writer).await,
        SelfDevAction::Decline { id, reason } => run_decline(home, &id, &reason, writer).await,
        SelfDevAction::Propose {
            from_profile,
            current_preset,
        } => run_propose(home, &from_profile, &current_preset, writer).await,
    }
}

fn run_review(home: &Path, min_confidence: f64) -> Result<()> {
    let store = load_store(home)?;
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
            "proposal `{id}` was previously declined — re-propose via `neoth self-dev propose ...` to re-evaluate"
        );
    }
    let ts = now_unix();
    entry.status = ProposalStatus::Accepted;
    entry.status_at_unix = ts;
    entry.decline_reason.clear();
    save_store(home, &store)?;
    println!("✓ accepted proposal `{id}`");
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
        println!("  (queued for daemon WAL emit — lands within 5s on the live daemon)");
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
            "proposal `{id}` was previously accepted — decline does not unwind the apply; revert manually"
        );
    }
    let ts = now_unix();
    entry.status = ProposalStatus::Declined;
    entry.status_at_unix = ts;
    entry.decline_reason = reason.to_string();
    save_store(home, &store)?;
    println!("✓ declined proposal `{id}` (reason: {reason})");
    if let Some(w) = writer {
        emit_declined(w, id, reason, ts).await?;
        println!("  (WAL frame 0x1E SELF_DEV_DECLINED emitted)");
    } else {
        super::self_dev_outbox::enqueue(
            home,
            &super::self_dev_outbox::PendingEvent::declined(id, reason, ts),
        )
        .await?;
        println!("  (queued for daemon WAL emit — lands within 5s on the live daemon)");
    }
    Ok(())
}

/// Shared proposal-generation core (SPEC-05 extracted this from
/// `run_propose` so the daemon's passive-adaptation cron
/// (`daemon::profile_adapt_cron`) reuses the EXACT dedup + store + WAL-emit
/// logic instead of duplicating it). Given an already-loaded behavioural
/// profile + the current preset name, runs `propose_adjustments`, appends
/// only proposals whose stable id isn't already in the store (idempotent),
/// emits a `0x1C SELF_DEV_PROPOSED` frame per new proposal (direct when a
/// `writer` is present, else enqueued to the self-dev outbox for the daemon
/// to drain), persists the store, and returns the count of NEW proposals.
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
    if new_proposals.is_empty() {
        return Ok(0);
    }
    let mut store = load_store(home)?;
    let ts = now_unix();
    let mut added = 0usize;
    for p in &new_proposals {
        if store.entries.iter().any(|e| e.proposal.id == p.id) {
            continue;
        }
        store.entries.push(StoredProposal {
            proposal: p.clone(),
            status: ProposalStatus::Pending,
            status_at_unix: ts,
            decline_reason: String::new(),
        });
        added += 1;
        if let Some(w) = writer {
            emit_proposed(w, p, ts).await?;
        } else {
            super::self_dev_outbox::enqueue(
                home,
                &super::self_dev_outbox::PendingEvent::proposed(p.clone(), ts),
            )
            .await?;
        }
    }
    save_store(home, &store)?;
    Ok(added)
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

async fn emit_proposed(
    writer: &WalWriterHandle,
    proposal: &SelfDevProposal,
    ts_unix: i64,
) -> Result<()> {
    let payload = proposal.to_proposed_payload(ts_unix);
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_SELF_DEV_PROPOSED, &payload).build();
    writer.append(header, payload).await?;
    Ok(())
}

async fn emit_accepted(writer: &WalWriterHandle, id: &str, ts_unix: i64) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "proposal_id": id,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_SELF_DEV_ACCEPTED, &payload).build();
    writer.append(header, payload).await?;
    Ok(())
}

async fn emit_declined(
    writer: &WalWriterHandle,
    id: &str,
    reason: &str,
    ts_unix: i64,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "proposal_id": id,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_SELF_DEV_DECLINED, &payload).build();
    writer.append(header, payload).await?;
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
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

    #[tokio::test]
    async fn review_with_no_pending_prints_hint() {
        let dir = tempdir().unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Review {
                min_confidence: 0.0,
            },
        };
        run(dir.path(), args, None).await.unwrap();
    }

    #[tokio::test]
    async fn accept_unknown_id_errors_with_actionable_message() {
        let dir = tempdir().unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Accept {
                id: "ghost-12345678".into(),
            },
        };
        let err = run(dir.path(), args, None).await.unwrap_err();
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
        run(dir.path(), args, None).await.unwrap();
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
        run(dir.path(), args, None).await.unwrap();
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
        let err = run(dir.path(), args, None).await.unwrap_err();
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
        run(dir.path(), args, None).await.unwrap();
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
        let err = run(dir.path(), args, None).await.unwrap_err();
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
        run(dir.path(), args, None).await.unwrap();
        let back = load_store(dir.path()).unwrap();
        assert!(!back.entries.is_empty());
        assert!(
            back.entries
                .iter()
                .all(|e| e.status == ProposalStatus::Pending)
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
        run(dir.path(), args1, None).await.unwrap();
        let first = load_store(dir.path()).unwrap();

        let args2 = SelfDevArgs {
            action: SelfDevAction::Propose {
                from_profile: profile_path,
                current_preset: "lowkey".into(),
            },
        };
        run(dir.path(), args2, None).await.unwrap();
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
