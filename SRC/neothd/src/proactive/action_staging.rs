//! OB-03 (Session 24) — proactive action staging.
//!
//! NEOTH proposes a cron job, skill, hook, or config tweak. Rather
//! than applying it silently, the proposal is STAGED: written as a
//! human-readable markdown draft to the operator's Obsidian vault
//! under `<vault>/<subdir>/Proposals/<id>.md`, with the raw YAML
//! the operator would merge into the live config block embedded
//! inside the note. Approval flips the status; the actual config
//! mutation is the operator's call (drop the YAML into the live
//! file then `neoth config reload`) — NEOTH never edits operator
//! configuration files behind their back.
//!
//! Companion side-effect: every new proposal pushes one
//! [`crate::proactive::ProactiveItem`] into the shared G-01a
//! [`crate::proactive::ProactiveQueue`] so the operator's regular
//! drain path surfaces the proposal in the active channel.
//!
//! ## Storage
//!
//! One JSON file per proposal at
//! `~/.neoth/proposals/<id>.json`. Files are mutable in-place — the
//! status field flips between `Pending` → `Approved` / `Rejected`
//! and any operator note ends up in `operator_note`. JSONL was
//! considered + rejected: per-proposal files map cleanly to the
//! per-proposal vault `.md` files + let operators delete individual
//! rejected proposals without re-writing a log.
//!
//! ## Why the operator-approves-not-NEOTH-applies rule
//!
//! Auto-applying config changes is the single highest-risk pattern
//! for an autonomous agent. Even with a rollback button, a bad
//! cron run between propose-and-rollback can deliver a wrong
//! notification, charge a paid API, or surface poisoned memory to
//! a third party. Staging makes "did I see this?" the precondition
//! to any change.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::proactive::{ProactiveItem, ProactiveQueue};

/// Kinds of operator-config artefact NEOTH may propose. New variants
/// are non-breaking — operator vaults pin existing variants by
/// snake_case wire form so the JSON survives schema evolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// A cron job to append to `jobs.yaml`.
    CronJob,
    /// A skill definition to drop into `~/.neoth/skills/`.
    Skill,
    /// A hook to add under `freedom.yaml::hooks`.
    Hook,
    /// A scalar tweak to `freedom.yaml` (e.g. enable a feature flag).
    ConfigTweak,
}

impl ProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalKind::CronJob => "cron_job",
            ProposalKind::Skill => "skill",
            ProposalKind::Hook => "hook",
            ProposalKind::ConfigTweak => "config_tweak",
        }
    }
}

/// Operator's verdict on a proposal. Stays `Pending` until the
/// operator explicitly accepts or rejects via the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalStatus::Pending => "pending",
            ProposalStatus::Approved => "approved",
            ProposalStatus::Rejected => "rejected",
        }
    }
}

/// A staged proposal. Filename is `<id>.json`; `id` itself is the
/// `<unix-secs>-<kind>-<short-hash>` format `make_proposal_id`
/// produces so operators see proposals sorted oldest-first by
/// natural filesystem listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposedAction {
    pub id: String,
    pub kind: ProposalKind,
    /// One-line summary, e.g. `"Daily 09:00 morning briefing"`.
    pub title: String,
    /// Multi-paragraph operator-facing explanation of WHY NEOTH
    /// thinks this is useful. Renders verbatim into the vault note.
    pub rationale: String,
    /// The exact YAML / JSON block the operator would merge into
    /// the live config. Rendered inside a fenced code block in the
    /// vault note so operators copy-paste cleanly.
    pub draft_yaml: String,
    pub generated_ts_unix: i64,
    pub status: ProposalStatus,
    /// Operator's review note when accepting or rejecting. Empty
    /// while `Pending`.
    #[serde(default)]
    pub operator_note: String,
}

impl ProposedAction {
    /// Render the proposal as an operator-readable Obsidian note.
    /// YAML frontmatter exposes id / kind / status / generated_unix
    /// so Dataview can list `WHERE status = "pending"`.
    pub fn to_obsidian_md(&self) -> String {
        format!(
            "---\n\
             id: \"{id}\"\n\
             kind: \"{kind}\"\n\
             status: \"{status}\"\n\
             generated_unix: {ts}\n\
             ---\n\n\
             # Proposal — {title}\n\n\
             ## Why\n\n\
             {rationale}\n\n\
             ## Draft config\n\n\
             ```yaml\n\
             {draft}\n\
             ```\n\n\
             ## Operator action\n\n\
             - Approve: `neoth proactive accept {id}`\n\
             - Reject:  `neoth proactive reject {id}`\n",
            id = escape_yaml_string(&self.id),
            kind = self.kind.as_str(),
            status = self.status.as_str(),
            ts = self.generated_ts_unix,
            title = self.title,
            rationale = self.rationale,
            draft = self.draft_yaml.trim_end_matches('\n'),
        )
    }
}

fn escape_yaml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Construct a stable, time-sortable, kind-prefixed proposal id.
/// Format `<unix-secs>-<kind>-<short-hash>`. The short-hash is a
/// xxh3-64 of `(title, draft_yaml, generated_ts_unix)` so two
/// proposals with identical content produce the same id (idempotent
/// re-runs of the same producer don't double-stage).
pub fn make_proposal_id(
    kind: ProposalKind,
    title: &str,
    draft_yaml: &str,
    generated_ts_unix: i64,
) -> String {
    let hash_input = format!("{title}|{draft_yaml}|{generated_ts_unix}");
    let hash = xxhash_rust::xxh3::xxh3_64(hash_input.as_bytes());
    let short = format!("{:08x}", hash & 0xFFFF_FFFF);
    format!("{}-{}-{}", generated_ts_unix, kind.as_str(), short)
}

/// Directory under `home` that holds staged proposal JSON files.
pub fn proposals_dir(home: &Path) -> PathBuf {
    home.join("proposals")
}

/// Path to one proposal's JSON file.
pub fn proposal_path(home: &Path, id: &str) -> PathBuf {
    proposals_dir(home).join(format!("{id}.json"))
}

/// Persist a proposal to disk. Atomic — body lands in `.tmp` then
/// renames. Overwrites any existing file with the same id.
pub fn save_proposal(home: &Path, proposal: &ProposedAction) -> std::io::Result<PathBuf> {
    fs::create_dir_all(proposals_dir(home))?;
    let final_path = proposal_path(home, &proposal.id);
    let tmp_path = final_path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(proposal).map_err(std::io::Error::other)?;
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(&body)?;
        f.flush()?;
    }
    if final_path.exists() {
        fs::remove_file(&final_path)?;
    }
    fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Load one proposal by id. Returns `None` when the file is
/// missing or malformed (corrupted disk doesn't kill the read path).
pub fn load_proposal(home: &Path, id: &str) -> Option<ProposedAction> {
    let path = proposal_path(home, id);
    let body = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&body).ok()
}

/// Load every proposal in `proposals_dir`, optionally filtered by
/// status. Files that fail to parse are silently skipped — the
/// caller iterates whatever survived. Sorted ascending by id (which
/// starts with unix-seconds, so older proposals come first).
pub fn list_proposals(home: &Path, status_filter: Option<ProposalStatus>) -> Vec<ProposedAction> {
    let dir = proposals_dir(home);
    let Ok(read) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<ProposedAction> = read
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .filter_map(|b| serde_json::from_str::<ProposedAction>(&b).ok())
        .filter(|p| status_filter.map(|s| p.status == s).unwrap_or(true))
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Mark a proposal as `Approved` or `Rejected`. Returns the
/// updated `ProposedAction`. The actual config-file mutation is
/// the operator's responsibility — NEOTH never edits user config
/// behind their back; status flips just record the verdict.
pub fn set_proposal_status(
    home: &Path,
    id: &str,
    new_status: ProposalStatus,
    operator_note: &str,
) -> std::io::Result<ProposedAction> {
    let mut p = load_proposal(home, id).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("proposal {id} not found"),
        )
    })?;
    p.status = new_status;
    p.operator_note = operator_note.to_string();
    save_proposal(home, &p)?;
    Ok(p)
}

/// Outcome of [`sync_proposals_to_obsidian`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalSyncOutcome {
    pub written: usize,
    pub skipped: usize,
    /// Final paths of files actually written (skipped proposals not
    /// included). Sorted ascending by id.
    pub target_paths: Vec<PathBuf>,
}

/// OB-03 — render every proposal under `status_filter` (default
/// `Pending`) into `<vault>/<subdir>/Proposals/<id>.md`. Atomic
/// per-file write. Existing `.md` files are overwritten — the
/// proposal JSON is the source of truth; the markdown is a
/// renderable view of it.
pub fn sync_proposals_to_obsidian(
    neoth_home: &Path,
    vault_root: &Path,
    subdir: &str,
    status_filter: Option<ProposalStatus>,
) -> std::io::Result<ProposalSyncOutcome> {
    let proposals = list_proposals(neoth_home, status_filter);
    let dest_dir = vault_root.join(subdir).join("Proposals");
    if proposals.is_empty() {
        return Ok(ProposalSyncOutcome {
            written: 0,
            skipped: 0,
            target_paths: Vec::new(),
        });
    }
    fs::create_dir_all(&dest_dir)?;

    let mut target_paths = Vec::with_capacity(proposals.len());
    let mut written = 0usize;
    for p in &proposals {
        let final_path = dest_dir.join(format!("{}.md", p.id));
        let tmp_path = final_path.with_extension("md.tmp");
        let body = p.to_obsidian_md();
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(body.as_bytes())?;
            f.flush()?;
        }
        if final_path.exists() {
            fs::remove_file(&final_path)?;
        }
        fs::rename(&tmp_path, &final_path)?;
        target_paths.push(final_path);
        written += 1;
    }

    Ok(ProposalSyncOutcome {
        written,
        skipped: 0,
        target_paths,
    })
}

/// Build a [`ProactiveItem`] that nudges the operator about a new
/// proposal. Caller pushes the returned item into the shared
/// `ProactiveQueue`; dedup_key uses the proposal id so the same
/// proposal can never enqueue twice.
pub fn build_proposal_notification(proposal: &ProposedAction) -> ProactiveItem {
    ProactiveItem {
        priority: 40,
        dedup_key: format!("ob_03_proposal:{}", proposal.id),
        channel: String::new(),
        source: "ob_03".to_string(),
        body: format!(
            "Vorschlag bereit zur Sichtung: {} — siehe Obsidian-Vault unter Proposals/{}.md",
            proposal.title, proposal.id
        ),
        scheduled_for_unix: 0,
        is_failure: false,
    }
}

/// One-call helper for producer paths: save + enqueue + return the
/// item. Used by the cron path so producers don't have to remember
/// the two-step dance.
pub fn stage_and_enqueue(
    home: &Path,
    proposal: ProposedAction,
    queue: &mut ProactiveQueue,
) -> std::io::Result<(ProposedAction, bool)> {
    save_proposal(home, &proposal)?;
    let item = build_proposal_notification(&proposal);
    let enqueued = queue.enqueue(item);
    Ok((proposal, enqueued))
}

/// Convenience helper to capture wall-clock at proposal generation.
pub fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: ProposalKind, title: &str, ts: i64) -> ProposedAction {
        let draft =
            "schedule:\n  cron: \"0 9 * * *\"\n  tz: Europe/Berlin\nprompt: \"Morning briefing\"\n";
        let id = make_proposal_id(kind, title, draft, ts);
        ProposedAction {
            id,
            kind,
            title: title.to_string(),
            rationale: "Operator reads morning email at 09:00 most weekdays.".to_string(),
            draft_yaml: draft.to_string(),
            generated_ts_unix: ts,
            status: ProposalStatus::Pending,
            operator_note: String::new(),
        }
    }

    #[test]
    fn kind_status_as_str_pinned_for_audit() {
        assert_eq!(ProposalKind::CronJob.as_str(), "cron_job");
        assert_eq!(ProposalKind::Skill.as_str(), "skill");
        assert_eq!(ProposalKind::Hook.as_str(), "hook");
        assert_eq!(ProposalKind::ConfigTweak.as_str(), "config_tweak");
        assert_eq!(ProposalStatus::Pending.as_str(), "pending");
        assert_eq!(ProposalStatus::Approved.as_str(), "approved");
        assert_eq!(ProposalStatus::Rejected.as_str(), "rejected");
    }

    #[test]
    fn make_proposal_id_is_deterministic_for_same_inputs() {
        let a = make_proposal_id(ProposalKind::CronJob, "x", "yaml", 100);
        let b = make_proposal_id(ProposalKind::CronJob, "x", "yaml", 100);
        assert_eq!(a, b);
    }

    #[test]
    fn make_proposal_id_differs_for_different_drafts() {
        let a = make_proposal_id(ProposalKind::CronJob, "x", "yaml_a", 100);
        let b = make_proposal_id(ProposalKind::CronJob, "x", "yaml_b", 100);
        assert_ne!(a, b);
    }

    #[test]
    fn make_proposal_id_prefix_is_kind_and_timestamp() {
        let id = make_proposal_id(ProposalKind::Skill, "x", "y", 1_700_000_000);
        assert!(id.starts_with("1700000000-skill-"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let home = tempfile::tempdir().unwrap();
        let p = sample(ProposalKind::CronJob, "Morning briefing", 100);
        save_proposal(home.path(), &p).unwrap();
        let loaded = load_proposal(home.path(), &p.id).expect("load");
        assert_eq!(loaded, p);
    }

    #[test]
    fn load_missing_proposal_returns_none() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_proposal(home.path(), "nonexistent").is_none());
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let home = tempfile::tempdir().unwrap();
        let mut p = sample(ProposalKind::CronJob, "title", 100);
        save_proposal(home.path(), &p).unwrap();
        p.title = "new title".to_string();
        save_proposal(home.path(), &p).unwrap();
        let loaded = load_proposal(home.path(), &p.id).unwrap();
        assert_eq!(loaded.title, "new title");
        // No .tmp leaks.
        let dir = proposals_dir(home.path());
        let leftover_tmp_count = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .and_then(|x| x.to_str())
                    == Some("tmp")
            })
            .count();
        assert_eq!(leftover_tmp_count, 0);
    }

    #[test]
    fn list_proposals_sorted_by_id_ascending() {
        let home = tempfile::tempdir().unwrap();
        let earlier = sample(ProposalKind::CronJob, "earlier", 100);
        let later = sample(ProposalKind::Skill, "later", 200);
        save_proposal(home.path(), &later).unwrap();
        save_proposal(home.path(), &earlier).unwrap();
        let all = list_proposals(home.path(), None);
        assert_eq!(all.len(), 2);
        assert!(all[0].id < all[1].id);
    }

    #[test]
    fn list_proposals_status_filter_excludes_others() {
        let home = tempfile::tempdir().unwrap();
        let mut a = sample(ProposalKind::CronJob, "a", 100);
        let mut b = sample(ProposalKind::Skill, "b", 200);
        b.status = ProposalStatus::Approved;
        a.status = ProposalStatus::Pending;
        save_proposal(home.path(), &a).unwrap();
        save_proposal(home.path(), &b).unwrap();
        let pending = list_proposals(home.path(), Some(ProposalStatus::Pending));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, a.id);
    }

    #[test]
    fn set_proposal_status_flips_and_writes_note() {
        let home = tempfile::tempdir().unwrap();
        let p = sample(ProposalKind::CronJob, "x", 100);
        save_proposal(home.path(), &p).unwrap();
        let updated =
            set_proposal_status(home.path(), &p.id, ProposalStatus::Approved, "looks good")
                .unwrap();
        assert_eq!(updated.status, ProposalStatus::Approved);
        assert_eq!(updated.operator_note, "looks good");
        // Persisted.
        let again = load_proposal(home.path(), &p.id).unwrap();
        assert_eq!(again.status, ProposalStatus::Approved);
    }

    #[test]
    fn set_proposal_status_missing_id_errors() {
        let home = tempfile::tempdir().unwrap();
        let err =
            set_proposal_status(home.path(), "nope", ProposalStatus::Approved, "").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn to_obsidian_md_contains_frontmatter_and_yaml_block() {
        let p = sample(ProposalKind::CronJob, "Morning briefing", 1_700_000_000);
        let md = p.to_obsidian_md();
        assert!(md.starts_with("---\n"));
        assert!(md.contains(&format!("id: \"{}\"", p.id)));
        assert!(md.contains("kind: \"cron_job\""));
        assert!(md.contains("status: \"pending\""));
        assert!(md.contains("# Proposal — Morning briefing"));
        assert!(md.contains("```yaml"));
        assert!(md.contains("neoth proactive accept"));
        assert!(md.contains("neoth proactive reject"));
    }

    #[test]
    fn sync_empty_proposals_writes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let out = sync_proposals_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(ProposalStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 0);
        assert!(out.target_paths.is_empty());
    }

    #[test]
    fn sync_writes_one_md_per_proposal() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let a = sample(ProposalKind::CronJob, "a", 100);
        let b = sample(ProposalKind::Skill, "b", 200);
        save_proposal(home.path(), &a).unwrap();
        save_proposal(home.path(), &b).unwrap();
        let out = sync_proposals_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(ProposalStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 2);
        assert_eq!(out.target_paths.len(), 2);
        for path in &out.target_paths {
            assert!(path.exists());
            let body = std::fs::read_to_string(path).unwrap();
            assert!(body.contains("# Proposal"));
        }
    }

    #[test]
    fn sync_filter_skips_non_matching_status() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let mut approved = sample(ProposalKind::CronJob, "a", 100);
        approved.status = ProposalStatus::Approved;
        let pending = sample(ProposalKind::Skill, "b", 200);
        save_proposal(home.path(), &approved).unwrap();
        save_proposal(home.path(), &pending).unwrap();
        let out = sync_proposals_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(ProposalStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 1);
    }

    #[test]
    fn build_proposal_notification_dedup_key_includes_id() {
        let p = sample(ProposalKind::CronJob, "title", 100);
        let item = build_proposal_notification(&p);
        assert!(item.dedup_key.contains(&p.id));
        assert_eq!(item.source, "ob_03");
        assert_eq!(item.priority, 40);
    }

    #[test]
    fn stage_and_enqueue_persists_then_pushes() {
        let home = tempfile::tempdir().unwrap();
        let mut q = ProactiveQueue::new();
        let p = sample(ProposalKind::CronJob, "x", 100);
        let id = p.id.clone();
        let (returned, enqueued) = stage_and_enqueue(home.path(), p, &mut q).unwrap();
        assert!(enqueued);
        assert_eq!(returned.id, id);
        assert_eq!(q.len(), 1);
        assert!(load_proposal(home.path(), &id).is_some());
    }

    #[test]
    fn stage_and_enqueue_dedups_via_proposal_id() {
        let home = tempfile::tempdir().unwrap();
        let mut q = ProactiveQueue::new();
        let p1 = sample(ProposalKind::CronJob, "x", 100);
        let p2 = p1.clone(); // same id → ProactiveQueue dedupes
        let (_, e1) = stage_and_enqueue(home.path(), p1, &mut q).unwrap();
        let (_, e2) = stage_and_enqueue(home.path(), p2, &mut q).unwrap();
        assert!(e1);
        assert!(!e2, "duplicate proposal must not enqueue twice");
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn to_obsidian_md_escapes_quotes_in_id() {
        // Hypothetical id with a quote — the YAML frontmatter must escape it.
        let mut p = sample(ProposalKind::CronJob, "x", 100);
        p.id = "weird\"id".to_string();
        let md = p.to_obsidian_md();
        assert!(md.contains("id: \"weird\\\"id\""), "got {md}");
    }

    #[test]
    fn json_status_serialisation_is_snake_case() {
        let mut p = sample(ProposalKind::Skill, "x", 100);
        p.status = ProposalStatus::Approved;
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"status\":\"approved\""));
        assert!(json.contains("\"kind\":\"skill\""));
    }
}
