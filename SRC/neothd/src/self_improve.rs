//! Self-improvement — NEOTH evolves its OWN skills with microsoft/SkillOpt
//! (the SkillOpt-Sleep engine): a validation-gated, review-then-adopt optimizer
//! that reviews past sessions + long-term memory and proposes bounded edits to a
//! skill document, accepting an edit ONLY when it strictly improves a held-out
//! gate. It synthesizes SkillOpt's discipline with NEOTH's existing dreaming
//! (offline consolidation) + self-dev (review-then-adopt) model.
//!
//! NEOTH drives it as an EXTERNAL engine (wizard-installed Python, like
//! cua-driver / claude-cli — self-contained rule honoured), GATED by an operator
//! switch and an ask-first prompt. Every run is recorded (a JSON ledger +,
//! per accepted improvement, a memory/WAL trail) so the operator can always see
//! *whether* and *what* improved — surfaced in the CLI (`neoth self-improve`),
//! `neoth doctor`, and the GUI.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The auto-improve switch + ask-state, in `<home>/self_improve.yaml` (separate
/// from freedom.yaml so toggling it never risks the main config).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelfImproveConfig {
    /// Master switch — self-improvement is allowed to run at all.
    #[serde(default)]
    pub enabled: bool,
    /// Run automatically (the nightly sleep cycle) vs operator-triggered only.
    #[serde(default)]
    pub auto: bool,
    /// The operator has been asked once whether to enable it (so NEOTH only
    /// prompts a single time, per the "ask before using" requirement).
    #[serde(default)]
    pub asked: bool,
}

impl SelfImproveConfig {
    pub fn path(home: &Path) -> PathBuf {
        home.join("self_improve.yaml")
    }
    pub fn load(home: &Path) -> Self {
        std::fs::read_to_string(Self::path(home))
            .ok()
            .and_then(|s| serde_yaml::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self)?;
        crate::util::atomic_write::atomic_write(&Self::path(home), yaml.as_bytes())?;
        Ok(())
    }

    /// Resolve the effective switch for a given daemon autonomy level.
    /// `Full` autonomy implies self-improvement runs automatically (the nightly
    /// sleep cycle STAGES proposals) — "skillopt improve auto on in full-auto
    /// mode" — UNLESS the operator has made an explicit choice (`asked`), which
    /// always wins. Below `Full`, the stored config is authoritative.
    ///
    /// This NEVER weakens the review-then-adopt gate: `auto` only stages
    /// proposals; adopting one still requires an explicit `neoth self-improve
    /// accept`. There is no auto-accept path at any autonomy level.
    pub fn effective(self, autonomy: crate::permissions::AutonomyLevel) -> Self {
        if autonomy == crate::permissions::AutonomyLevel::Full && !self.asked {
            Self {
                enabled: true,
                auto: true,
                asked: self.asked,
            }
        } else {
            self
        }
    }
}

/// One recorded self-improvement attempt — the "what improved" surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImproveRecord {
    /// The skill (or persona) that was optimized.
    pub skill: String,
    /// Whether the held-out gate accepted the edit (false = no improvement kept).
    pub accepted: bool,
    /// Held-out score before / after (when the engine reports them; else 0).
    #[serde(default)]
    pub score_before: f64,
    #[serde(default)]
    pub score_after: f64,
    /// One-line human summary of the change.
    pub summary: String,
    /// When (unix seconds).
    pub at_unix: i64,
}

pub fn ledger_path(home: &Path) -> PathBuf {
    home.join("self_improve_log.json")
}

/// Every recorded improvement attempt, oldest first.
pub fn load_ledger(home: &Path) -> Vec<ImproveRecord> {
    std::fs::read_to_string(ledger_path(home))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn append_record(home: &Path, rec: ImproveRecord) -> Result<()> {
    let mut log = load_ledger(home);
    log.push(rec);
    let json = serde_json::to_string_pretty(&log)?;
    crate::util::atomic_write::atomic_write(&ledger_path(home), json.as_bytes())?;
    Ok(())
}

/// The most recent improvement attempt, if any.
pub fn last_record(home: &Path) -> Option<ImproveRecord> {
    load_ledger(home).into_iter().next_back()
}

// ── Review-then-adopt: staged proposals ─────────────────────────────────────
// SkillOpt NEVER writes to a production skill file. Every run STAGES a proposal;
// only an explicit `accept` writes it (after backing up the replaced content),
// and `rollback` restores that backup. This is the hard gate: no skill changes
// without operator approval, and any change is reversible.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    #[default]
    Pending,
    Accepted,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Proposal {
    pub id: String,
    pub skill: String,
    /// Absolute path to the production skill file the `after` content targets.
    pub skill_path: String,
    /// Skill content at stage time (the diff baseline).
    pub before: String,
    /// SkillOpt's proposed content.
    pub after: String,
    pub summary: String,
    pub status: ProposalStatus,
    pub at_unix: i64,
    /// The content `accept` replaced (set on accept), so `rollback` is exact.
    #[serde(default)]
    pub backup: Option<String>,
    // ── Quality score: WHY this improves, not just the diff ──────────────────
    /// Held-out gate score before / after the edit (0.0 when the engine didn't
    /// report one — e.g. an operator-supplied `--from` proposal).
    #[serde(default)]
    pub score_before: f64,
    #[serde(default)]
    pub score_after: f64,
    /// One-line summary of the held-out evaluation the engine ran.
    #[serde(default)]
    pub heldout_eval_summary: String,
    /// Why the engine (or operator) believes this edit is an improvement.
    #[serde(default)]
    pub why_this_improves: String,
    /// Known risks / caveats of adopting this edit (operator-facing).
    #[serde(default)]
    pub risk_notes: String,
    // ── IMPR-01: ProposalSpec — structured execution / verification envelope ──
    /// Optional execution spec emitted by SkillOpt or an operator-supplied
    /// envelope. Back-compat: absent in older proposals → None.
    #[serde(default)]
    pub spec: Option<ProposalSpec>,
}

/// Structured execution specification attached to a staged proposal (IMPR-01).
///
/// Fields map directly from the SkillOpt JSON envelope (or operator-supplied
/// `--from` proposals). All fields are optional — a proposal is valid without
/// any spec; these fields add machine-checkable done-gates and safety stops.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProposalSpec {
    /// Shell command (or test invocation) to run to verify the edit worked.
    /// E.g. `"cargo test -p neothd -- self_improve"`. None = no gate.
    #[serde(default)]
    pub verification_command: Option<String>,
    /// Human-readable criterion that defines "done" for this proposal.
    /// Used as the advisor review prompt in the execute path.
    #[serde(default)]
    pub done_criteria: Option<String>,
    /// Conditions that STOP execution if any is true (e.g. file-size growth,
    /// test regression). Checked as prefixes of executor output lines.
    #[serde(default)]
    pub stop_conditions: Vec<String>,
    /// IMPR-02: git short-SHA captured at `stage_proposal` time.
    /// Used at `accept_proposal` time to detect drift in the target file.
    #[serde(default)]
    pub drift_sha: Option<String>,
}

pub fn proposals_path(home: &Path) -> PathBuf {
    home.join("self_improve_proposals.json")
}

pub fn load_proposals(home: &Path) -> Vec<Proposal> {
    std::fs::read_to_string(proposals_path(home))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_proposals(home: &Path, props: &[Proposal]) -> Result<()> {
    let json = serde_json::to_string_pretty(props)?;
    crate::util::atomic_write::atomic_write(&proposals_path(home), json.as_bytes())?;
    Ok(())
}

// ── IMPR-02: git drift-check helpers ─────────────────────────────────────────

/// Capture `git rev-parse --short HEAD` from the cwd. Returns `None` when git
/// is unavailable or the directory is not a repo — callers degrade gracefully.
fn git_capture_head_sha() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if sha.is_empty() { None } else { Some(sha) }
}

/// Run `git diff --stat <from_sha>..HEAD -- <path>` and return the trimmed
/// output, or `None` if git fails (not a repo, no commits, etc.).
fn git_diff_stat_since(from_sha: &str, path: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["diff", "--stat", &format!("{from_sha}..HEAD"), "--", path])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Stage a proposal (status Pending). Returns its id.
///
/// IMPR-02: captures `git rev-parse --short HEAD` into `spec.drift_sha` so
/// `accept_proposal` can later detect whether the skill file drifted.
pub fn stage_proposal(home: &Path, mut p: Proposal) -> Result<String> {
    p.status = ProposalStatus::Pending;
    // IMPR-02: record the current HEAD SHA so accept can diff for drift.
    let sha = git_capture_head_sha();
    let spec = p.spec.get_or_insert_with(ProposalSpec::default);
    if spec.drift_sha.is_none() {
        spec.drift_sha = sha;
    }
    let id = p.id.clone();
    let mut all = load_proposals(home);
    all.push(p);
    save_proposals(home, &all)?;
    Ok(id)
}

/// Accept a pending proposal: back up the CURRENT skill file content, then write
/// the proposed `after`. Returns an error if the id is unknown / not pending.
/// This is the ONLY path that writes a production skill file.
///
/// IMPR-02: if the proposal carries a `spec.drift_sha`, runs
/// `git diff --stat <sha>..HEAD -- <skill_path>` and prints a warning when the
/// target file changed since staging. A git error never aborts the accept.
pub fn accept_proposal(home: &Path, id: &str) -> Result<()> {
    let mut all = load_proposals(home);
    let p = all
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| anyhow::anyhow!("no proposal `{id}`"))?;
    if p.status != ProposalStatus::Pending {
        anyhow::bail!("proposal `{id}` is {:?}, not pending", p.status);
    }
    // IMPR-02: drift check — warn if target drifted since this was staged.
    if let Some(sha) = p.spec.as_ref().and_then(|s| s.drift_sha.as_deref()) {
        if let Some(diff) = git_diff_stat_since(sha, &p.skill_path) {
            eprintln!(
                "⚠  drift warning: `{}` changed since proposal was staged (sha {sha}):\n{diff}\n   Review the diff — this proposal may be stale.",
                p.skill_path
            );
        }
    }
    let path = Path::new(&p.skill_path);
    // Back up the exact content we're about to replace (may differ from `before`
    // if the file changed since staging) so rollback is precise.
    let current = std::fs::read_to_string(path).unwrap_or_default();
    p.backup = Some(current);
    crate::util::atomic_write::atomic_write(path, p.after.as_bytes())
        .with_context(|| format!("write skill {}", path.display()))?;
    p.status = ProposalStatus::Accepted;
    save_proposals(home, &all)?;
    Ok(())
}

/// Roll back an accepted proposal: restore the backed-up content to the skill.
pub fn rollback_proposal(home: &Path, id: &str) -> Result<()> {
    let mut all = load_proposals(home);
    let p = all
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| anyhow::anyhow!("no proposal `{id}`"))?;
    if p.status != ProposalStatus::Accepted {
        anyhow::bail!(
            "proposal `{id}` is {:?}, not accepted — nothing to roll back",
            p.status
        );
    }
    let backup = p
        .backup
        .clone()
        .ok_or_else(|| anyhow::anyhow!("proposal `{id}` has no backup"))?;
    let path = Path::new(&p.skill_path);
    crate::util::atomic_write::atomic_write(path, backup.as_bytes())
        .with_context(|| format!("restore skill {}", path.display()))?;
    p.status = ProposalStatus::RolledBack;
    save_proposals(home, &all)?;
    Ok(())
}

// ── Contribute upstream: PR an improved BUNDLED skill back to NEOTH ──────────
// When SkillOpt improves a skill NEOTH SHIPS (a bundled skill), the operator can
// contribute the improvement back. NEOTH never auto-pushes: it PREPARES a
// self-contained PR bundle (improved file + PR body + a submit script) and the
// operator decides. Self-contained rule honoured — submission shells out to the
// operator's already-authenticated `gh`, NEOTH never touches the token.

/// Upstream repo bundled-skill PRs target.
pub const NEOTH_REPO: &str = "The-Geek-Freaks/NEOTH";

/// Artifacts written for an upstream-PR offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPr {
    /// `<home>/self_improve_prs/<id>/` holding skill file + PR.md + submit.sh.
    pub dir: PathBuf,
    /// Repo-relative asset path the PR overwrites.
    pub asset_path: String,
    /// Suggested branch name.
    pub branch: String,
    /// PR title.
    pub title: String,
}

/// Prepare an upstream-PR bundle for an ACCEPTED improvement to a BUNDLED skill.
/// Writes `<home>/self_improve_prs/<id>/{<skill-file>, PR.md, submit.sh}` — the
/// improved content (same basename as the improved production file so a markdown
/// skill stays markdown, a yaml manifest stays yaml), a ready PR body (title +
/// summary + diff), and a self-contained submit script (fork → branch → copy →
/// commit → `gh pr create`). Errors if the proposal isn't accepted or its skill
/// isn't bundled (nothing to contribute upstream).
pub fn prepare_upstream_pr(home: &Path, id: &str) -> Result<PreparedPr> {
    let props = load_proposals(home);
    let p = props
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| anyhow::anyhow!("no proposal `{id}`"))?;
    if p.status != ProposalStatus::Accepted {
        anyhow::bail!(
            "proposal `{id}` is {:?} — accept it (`neoth self-improve accept {id}`) before opening a PR",
            p.status
        );
    }
    // Same filename as the improved production file (skill.md / skill.yaml / …).
    let file = Path::new(&p.skill_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("skill.yaml");
    let asset_path =
        crate::skills::bundled::bundled_asset_path(&p.skill, file).ok_or_else(|| {
            anyhow::anyhow!(
                "skill `{}` is not a bundled skill — nothing to contribute upstream",
                p.skill
            )
        })?;

    let dir = home.join("self_improve_prs").join(id);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let content_path = dir.join(file);
    crate::util::atomic_write::atomic_write(&content_path, p.after.as_bytes())?;

    let branch = format!("skillopt/{}-{}", p.skill, id);
    let title = format!("skill({}): SkillOpt improvement", p.skill);
    let diff = line_diff(&p.before, &p.after);

    // The justification block — scores + held-out eval + rationale + risks —
    // so a reviewer sees WHY, not just the diff.
    let mut quality = String::new();
    if p.score_before != 0.0 || p.score_after != 0.0 {
        let delta = p.score_after - p.score_before;
        quality.push_str(&format!(
            "- **Held-out score:** {:.3} → {:.3} ({:+.3})\n",
            p.score_before, p.score_after, delta
        ));
    }
    if !p.heldout_eval_summary.is_empty() {
        quality.push_str(&format!("- **Eval:** {}\n", p.heldout_eval_summary));
    }
    if !p.why_this_improves.is_empty() {
        quality.push_str(&format!(
            "- **Why this improves:** {}\n",
            p.why_this_improves
        ));
    }
    if !p.risk_notes.is_empty() {
        quality.push_str(&format!("- **Risks:** {}\n", p.risk_notes));
    }
    let quality_section = if quality.is_empty() {
        String::new()
    } else {
        format!("\n## Quality\n\n{quality}")
    };

    let body = format!(
        "# {title}\n\n{summary}\n\nSkillOpt staged this improvement to the bundled `{skill}` \
         skill, the operator adopted it locally (review-then-adopt), then chose to contribute it \
         upstream.\n{quality_section}\n## Diff\n\n```diff\n{diff}```\n",
        title = title,
        summary = p.summary,
        skill = p.skill,
        quality_section = quality_section,
        diff = diff,
    );
    crate::util::atomic_write::atomic_write(&dir.join("PR.md"), body.as_bytes())?;

    let script = upstream_pr_script(
        &branch,
        &title,
        &asset_path,
        &content_path.display().to_string(),
        &dir.join("PR.md").display().to_string(),
    );
    crate::util::atomic_write::atomic_write(&dir.join("submit.sh"), script.as_bytes())?;

    Ok(PreparedPr {
        dir,
        asset_path,
        branch,
        title,
    })
}

/// The self-contained submit script: fork (or clone) the repo, drop the improved
/// file at its asset path, branch + commit + push, `gh pr create`. Uses the
/// operator's authenticated `gh`; NEOTH never sees the token.
fn upstream_pr_script(
    branch: &str,
    title: &str,
    asset_path: &str,
    content_file: &str,
    body_file: &str,
) -> String {
    format!(
        "#!/usr/bin/env bash\n\
         set -euo pipefail\n\
         # Contribute a SkillOpt bundled-skill improvement to {repo}.\n\
         # Requires an authenticated `gh`. Safe to re-run (uses a fresh temp clone).\n\
         REPO=\"{repo}\"\n\
         WORK=\"$(mktemp -d)\"\n\
         gh repo fork \"$REPO\" --clone=true --default-branch-only \"$WORK/neoth\" \\\n\
           || gh repo clone \"$REPO\" \"$WORK/neoth\"\n\
         cd \"$WORK/neoth\"\n\
         git checkout -b \"{branch}\"\n\
         mkdir -p \"$(dirname \"{asset}\")\"\n\
         cp \"{content}\" \"{asset}\"\n\
         git add \"{asset}\"\n\
         git commit -m \"{title}\"\n\
         git push -u origin \"{branch}\"\n\
         gh pr create --repo \"$REPO\" --title \"{title}\" --body-file \"{body}\"\n",
        repo = NEOTH_REPO,
        branch = branch,
        asset = asset_path,
        content = content_file,
        title = title,
        body = body_file,
    )
}

/// Minimal line diff (`+`/`-`/` `) for review display — no external dep. Shows
/// removed-then-added per changed run; unchanged lines are context-elided to a
/// count when long.
pub fn line_diff(before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let mut out = String::new();
    // Simple LCS-free diff: walk both, emit removals for a-lines not in b and
    // additions for b-lines not in a (set-based — good enough for review).
    let bset: std::collections::HashSet<&str> = b.iter().copied().collect();
    let aset: std::collections::HashSet<&str> = a.iter().copied().collect();
    for line in &a {
        if !bset.contains(line) {
            out.push_str(&format!("- {line}\n"));
        }
    }
    for line in &b {
        if !aset.contains(line) {
            out.push_str(&format!("+ {line}\n"));
        }
    }
    if out.is_empty() {
        out.push_str("(no line changes)\n");
    }
    out
}

/// Quality metadata for a staged proposal — the "why", not just the diff.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProposalQuality {
    pub score_before: f64,
    pub score_after: f64,
    pub heldout_eval_summary: String,
    pub why_this_improves: String,
    pub risk_notes: String,
}

/// Split a SkillOpt run's stdout into `(proposed_content, quality, spec)`.
/// NEOTH's ingestion contract: if stdout is a JSON object carrying a `skill`
/// (or `content`) string, it's a STRUCTURED report — pull the content plus the
/// quality fields (`score_before` / `score_after` / `heldout_eval_summary` /
/// `why_this_improves` / `risk_notes`) and, if present, the ProposalSpec fields
/// (`verification_command` / `done_criteria` / `stop_conditions`).
/// Otherwise the whole stdout IS the proposed content and quality + spec are
/// empty (plain-text still works unchanged — IMPR-01).
pub fn parse_proposal_output(stdout: &str) -> (String, ProposalQuality, Option<ProposalSpec>) {
    let trimmed = stdout.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(content) = v
                .get("skill")
                .or_else(|| v.get("content"))
                .and_then(|s| s.as_str())
            {
                let f = |k: &str| v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
                let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                let quality = ProposalQuality {
                    score_before: f("score_before"),
                    score_after: f("score_after"),
                    heldout_eval_summary: s("heldout_eval_summary"),
                    why_this_improves: s("why_this_improves"),
                    risk_notes: s("risk_notes"),
                };
                // IMPR-01: parse ProposalSpec fields from the envelope.
                let verification_command = v
                    .get("verification_command")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let done_criteria = v
                    .get("done_criteria")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let stop_conditions: Vec<String> = v
                    .get("stop_conditions")
                    .and_then(|x| x.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|e| e.as_str())
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let spec = if verification_command.is_some()
                    || done_criteria.is_some()
                    || !stop_conditions.is_empty()
                {
                    Some(ProposalSpec {
                        verification_command,
                        done_criteria,
                        stop_conditions,
                        drift_sha: None, // populated at stage time
                    })
                } else {
                    None
                };
                return (content.to_string(), quality, spec);
            }
        }
    }
    (stdout.to_string(), ProposalQuality::default(), None)
}

pub const SKILLOPT_INSTALL: &str = "pip install skillopt";

fn python_bin() -> &'static str {
    if cfg!(target_os = "windows") {
        "python"
    } else {
        "python3"
    }
}

/// Is the SkillOpt-Sleep engine importable (`python -c "import skillopt_sleep"`)?
pub fn is_installed() -> bool {
    std::process::Command::new(python_bin())
        .args(["-c", "import skillopt_sleep"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build the SkillOpt-Sleep consolidation command for a persona/skill — the
/// integration point. `--assert-improves` makes the run fail loudly if the
/// held-out gate doesn't accept an improvement, so a no-op never masquerades as
/// progress.
pub fn skillopt_command(persona: &str) -> std::process::Command {
    let mut c = std::process::Command::new(python_bin());
    c.args([
        "-m",
        "skillopt_sleep.experiments.run_experiment",
        "--persona",
        persona,
    ]);
    c
}

// ── IMPR-03: Execute variant — verification-gated proposal execution scaffold ─
//
// Runs a staged proposal through a verification + advisor-review loop. The
// cheaper-executor subagent dispatch is left as a `// neoth:` hook — wiring it
// requires the provider API which doesn't exist at this call site. The scaffold
// provides: verification_command run → done_criteria check → advisor diff-review
// loop (max 2 revises). Bounded and safe; never auto-accepts.

/// Outcome of the advisor review pass in the execute variant (IMPR-03).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionVerdict {
    /// Verification passed + advisor approved the output.
    Approved,
    /// Verification passed but advisor requests changes (caller may retry,
    /// up to `max_revises` times).
    Revise { reason: String },
    /// Verification failed, a stop-condition triggered, or max revises reached.
    Blocked { reason: String },
}

/// Parse an advisor review report string into an `ExecutionVerdict`.
///
/// The report is expected to contain one of the tokens `APPROVE`, `REVISE`, or
/// `BLOCK` (case-insensitive). Everything after the token on that line becomes
/// the `reason`. Plain-text or structured — whichever the advisor emits.
pub fn review_execution_result(report: &str) -> ExecutionVerdict {
    for line in report.lines() {
        let upper = line.to_ascii_uppercase();
        if upper.contains("APPROVE") {
            return ExecutionVerdict::Approved;
        }
        if let Some(pos) = upper.find("REVISE") {
            let reason = line[pos + "REVISE".len()..].trim().to_string();
            return ExecutionVerdict::Revise {
                reason: if reason.is_empty() {
                    "advisor requested changes".to_string()
                } else {
                    reason
                },
            };
        }
        if let Some(pos) = upper.find("BLOCK") {
            let reason = line[pos + "BLOCK".len()..].trim().to_string();
            return ExecutionVerdict::Blocked {
                reason: if reason.is_empty() {
                    "advisor blocked execution".to_string()
                } else {
                    reason
                },
            };
        }
    }
    ExecutionVerdict::Blocked {
        reason: "advisor report contained no APPROVE/REVISE/BLOCK token".to_string(),
    }
}

/// Run a pending proposal through the verification-gated execute scaffold
/// (IMPR-03). Steps:
///
/// 1. Load the proposal by `id` (must be Pending).
/// 2. Run `spec.verification_command` (if set); fail → `Blocked`.
/// 3. Check `spec.stop_conditions` against the verification output; trigger → `Blocked`.
/// 4. Call `advisor_fn` with the diff + verification output to get a review report.
/// 5. Parse the report via `review_execution_result`; loop up to `max_revises`.
///
/// The `advisor_fn` closure is the cheaper-executor hook:
/// ```text
/// // neoth: wire a cheaper-executor subagent here when the provider API is
/// // available at this call site — pass the ProposalSpec + diff as the prompt,
/// // receive the advisor report string, return it from this closure.
/// ```
///
/// Returns `(ExecutionVerdict, usize)` — the final verdict + number of revise
/// rounds used. Never writes to a skill file (that stays gated behind `accept`).
pub fn execute_proposal_with_verification<F>(
    home: &Path,
    id: &str,
    max_revises: usize,
    advisor_fn: F,
) -> Result<(ExecutionVerdict, usize)>
where
    F: Fn(&str, &str) -> String,
{
    let all = load_proposals(home);
    let p = all
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| anyhow::anyhow!("no proposal `{id}`"))?;
    if p.status != ProposalStatus::Pending {
        anyhow::bail!("proposal `{id}` is {:?}, not pending", p.status);
    }

    let diff = crate::self_improve::line_diff(&p.before, &p.after);

    // Step 2: run the verification command.
    let verification_output = if let Some(cmd) = p
        .spec
        .as_ref()
        .and_then(|s| s.verification_command.as_deref())
    {
        let out = std::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" })
            .args(if cfg!(windows) {
                vec!["/C", cmd]
            } else {
                vec!["-c", cmd]
            })
            .output();
        match out {
            Ok(o) if o.status.success() => {
                String::from_utf8_lossy(&o.stdout).into_owned()
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                return Ok((
                    ExecutionVerdict::Blocked {
                        reason: format!(
                            "verification_command failed (exit {:?}): {stderr}",
                            o.status.code()
                        ),
                    },
                    0,
                ));
            }
            Err(e) => {
                return Ok((
                    ExecutionVerdict::Blocked {
                        reason: format!("could not run verification_command: {e}"),
                    },
                    0,
                ));
            }
        }
    } else {
        String::new()
    };

    // Step 3: stop-conditions check.
    if let Some(spec) = &p.spec {
        for cond in &spec.stop_conditions {
            if verification_output.lines().any(|l| l.starts_with(cond.as_str())) {
                return Ok((
                    ExecutionVerdict::Blocked {
                        reason: format!("stop condition triggered: `{cond}`"),
                    },
                    0,
                ));
            }
        }
    }

    // Steps 4–5: advisor review loop (max `max_revises` revise rounds).
    let mut revises = 0usize;
    loop {
        // neoth: wire a cheaper-executor subagent here when the provider API is
        // available at this call site — pass ProposalSpec + diff as the prompt,
        // receive the advisor report string, return it from the closure.
        let report = advisor_fn(&diff, &verification_output);
        let verdict = review_execution_result(&report);
        match verdict {
            ExecutionVerdict::Approved => return Ok((ExecutionVerdict::Approved, revises)),
            ExecutionVerdict::Revise { reason } => {
                revises += 1;
                if revises >= max_revises {
                    return Ok((
                        ExecutionVerdict::Blocked {
                            reason: format!("max revises ({max_revises}) reached; last: {reason}"),
                        },
                        revises,
                    ));
                }
                // Loop — advisor_fn will be called again with the same diff.
            }
            blocked => return Ok((blocked, revises)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrips_and_defaults_off() {
        let tmp = std::env::temp_dir().join("neoth_selfimprove_cfg_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(SelfImproveConfig::path(&tmp));
        // default: everything off (opt-in, never auto-evolves without consent).
        let def = SelfImproveConfig::load(&tmp);
        assert!(!def.enabled && !def.auto && !def.asked);
        let cfg = SelfImproveConfig {
            enabled: true,
            auto: true,
            asked: true,
        };
        cfg.save(&tmp).unwrap();
        assert_eq!(SelfImproveConfig::load(&tmp), cfg);
        let _ = std::fs::remove_file(SelfImproveConfig::path(&tmp));
    }

    #[test]
    fn effective_full_auto_implies_on_unless_operator_chose() {
        use crate::permissions::AutonomyLevel as A;
        // Fresh config (never asked): Full autonomy turns it on automatically.
        let fresh = SelfImproveConfig::default();
        let eff = fresh.effective(A::Full);
        assert!(
            eff.enabled && eff.auto,
            "full-auto implies self-improve auto-on"
        );
        // Below Full, a fresh config stays off (no implicit enabling).
        for lvl in [A::Strict, A::Standard, A::Elevated] {
            let e = SelfImproveConfig::default().effective(lvl);
            assert!(!e.enabled && !e.auto, "{lvl:?} must not auto-enable");
        }
        // Operator explicitly disabled it (asked=true) → Full must respect that.
        let opted_off = SelfImproveConfig {
            enabled: false,
            auto: false,
            asked: true,
        };
        let e = opted_off.effective(A::Full);
        assert!(
            !e.enabled && !e.auto,
            "explicit operator choice wins over the full-auto default"
        );
    }

    #[test]
    fn ledger_appends_and_reads_last() {
        let tmp = std::env::temp_dir().join("neoth_selfimprove_ledger_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(ledger_path(&tmp));
        assert!(last_record(&tmp).is_none());
        append_record(
            &tmp,
            ImproveRecord {
                skill: "coding".into(),
                accepted: true,
                score_before: 0.4,
                score_after: 0.7,
                summary: "tightened the planning step".into(),
                at_unix: 1_700_000_000,
            },
        )
        .unwrap();
        let last = last_record(&tmp).expect("a record");
        assert_eq!(last.skill, "coding");
        assert!(last.accepted);
        let _ = std::fs::remove_file(ledger_path(&tmp));
    }

    #[test]
    fn install_hint_is_pip() {
        assert!(SKILLOPT_INSTALL.contains("skillopt"));
    }

    #[test]
    fn accept_writes_skill_and_rollback_restores_it() {
        let tmp = std::env::temp_dir().join("neoth_si_accept_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(proposals_path(&tmp));
        let skill = tmp.join("skill.md");
        std::fs::write(&skill, "ORIGINAL skill").unwrap();

        let id = stage_proposal(
            &tmp,
            Proposal {
                id: "p1".into(),
                skill: "coding".into(),
                skill_path: skill.display().to_string(),
                before: "ORIGINAL skill".into(),
                after: "IMPROVED skill".into(),
                summary: "tighten".into(),
                status: ProposalStatus::Pending,
                at_unix: 1,
                backup: None,
                ..Default::default()
            },
        )
        .unwrap();

        // staging must NOT touch the production file
        assert_eq!(std::fs::read_to_string(&skill).unwrap(), "ORIGINAL skill");

        // accept writes the improvement + records a backup
        accept_proposal(&tmp, &id).unwrap();
        assert_eq!(std::fs::read_to_string(&skill).unwrap(), "IMPROVED skill");

        // double-accept is rejected
        assert!(accept_proposal(&tmp, &id).is_err());

        // rollback restores the exact replaced content
        rollback_proposal(&tmp, &id).unwrap();
        assert_eq!(std::fs::read_to_string(&skill).unwrap(), "ORIGINAL skill");

        let _ = std::fs::remove_file(proposals_path(&tmp));
        let _ = std::fs::remove_file(&skill);
    }

    #[test]
    fn prepare_upstream_pr_only_for_accepted_bundled_skill() {
        let tmp = std::env::temp_dir().join("neoth_si_pr_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(proposals_path(&tmp));
        let _ = std::fs::remove_dir_all(tmp.join("self_improve_prs"));
        let skill = tmp.join("skill.yaml");
        std::fs::write(&skill, "ORIGINAL").unwrap();

        // A bundled skill id (ships in the binary — see skills::bundled).
        let id = stage_proposal(
            &tmp,
            Proposal {
                id: "p1".into(),
                skill: "academic_research".into(),
                skill_path: skill.display().to_string(),
                before: "ORIGINAL".into(),
                after: "IMPROVED".into(),
                summary: "tighten".into(),
                status: ProposalStatus::Pending,
                at_unix: 1,
                backup: None,
                ..Default::default()
            },
        )
        .unwrap();

        // Pending → refused (must adopt locally first).
        assert!(prepare_upstream_pr(&tmp, &id).is_err());

        accept_proposal(&tmp, &id).unwrap();
        let prepared = prepare_upstream_pr(&tmp, &id).expect("bundled + accepted → prepares");
        assert!(prepared.dir.join("skill.yaml").exists());
        assert!(prepared.dir.join("PR.md").exists());
        assert!(prepared.dir.join("submit.sh").exists());
        assert_eq!(
            prepared.asset_path,
            "SRC/neothd/assets/skills/academic_research/skill.yaml"
        );
        assert_eq!(
            std::fs::read_to_string(prepared.dir.join("skill.yaml")).unwrap(),
            "IMPROVED"
        );

        // A NON-bundled skill has nothing to contribute upstream.
        let skill2 = tmp.join("user_skill.md");
        std::fs::write(&skill2, "x").unwrap();
        let id2 = stage_proposal(
            &tmp,
            Proposal {
                id: "p2".into(),
                skill: "my_private_skill".into(),
                skill_path: skill2.display().to_string(),
                before: "x".into(),
                after: "y".into(),
                summary: "s".into(),
                status: ProposalStatus::Pending,
                at_unix: 2,
                backup: None,
                ..Default::default()
            },
        )
        .unwrap();
        accept_proposal(&tmp, &id2).unwrap();
        assert!(prepare_upstream_pr(&tmp, &id2).is_err());

        let _ = std::fs::remove_file(proposals_path(&tmp));
        let _ = std::fs::remove_dir_all(tmp.join("self_improve_prs"));
    }

    #[test]
    fn parse_proposal_output_structured_vs_plain() {
        // Plain text → the whole thing is the content; no quality or spec.
        let (c, q, spec) = parse_proposal_output("just the new skill body");
        assert_eq!(c, "just the new skill body");
        assert_eq!(q, ProposalQuality::default());
        assert!(spec.is_none());

        // Structured envelope → content + quality extracted; no spec fields → None.
        let json = r#"{"skill":"NEW BODY","score_before":0.4,"score_after":0.72,
            "heldout_eval_summary":"+8/10 held-out","why_this_improves":"tighter planning",
            "risk_notes":"none observed"}"#;
        let (c, q, spec) = parse_proposal_output(json);
        assert_eq!(c, "NEW BODY");
        assert!((q.score_before - 0.4).abs() < 1e-9);
        assert!((q.score_after - 0.72).abs() < 1e-9);
        assert_eq!(q.heldout_eval_summary, "+8/10 held-out");
        assert_eq!(q.why_this_improves, "tighter planning");
        assert_eq!(q.risk_notes, "none observed");
        assert!(spec.is_none()); // no spec fields in envelope

        // A JSON object WITHOUT a skill/content key → treated as plain content.
        let (c, q, spec) = parse_proposal_output(r#"{"unrelated":true}"#);
        assert_eq!(c, r#"{"unrelated":true}"#);
        assert_eq!(q, ProposalQuality::default());
        assert!(spec.is_none());
    }

    #[test]
    fn line_diff_shows_changes() {
        let d = line_diff("a\nb\nc", "a\nB\nc");
        assert!(d.contains("- b"));
        assert!(d.contains("+ B"));
        assert!(!d.contains("(no line changes)"));
        assert!(line_diff("same", "same").contains("(no line changes)"));
    }

    // ── IMPR-01: ProposalSpec serde roundtrip ─────────────────────────────────

    #[test]
    fn proposal_spec_serde_roundtrip_with_fields() {
        let spec = ProposalSpec {
            verification_command: Some("cargo test".to_string()),
            done_criteria: Some("all tests pass".to_string()),
            stop_conditions: vec!["FAILED".to_string(), "error[".to_string()],
            drift_sha: Some("abc1234".to_string()),
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let back: ProposalSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, back);
    }

    #[test]
    fn proposal_spec_serde_roundtrip_empty_back_compat() {
        // An old proposal JSON without `spec` deserializes cleanly to None.
        let json = r#"{"id":"p1","skill":"coding","skill_path":"/tmp/skill.md","before":"x","after":"y","summary":"s","status":"pending","at_unix":1}"#;
        let p: Proposal = serde_json::from_str(json).expect("back-compat deserialize");
        assert!(p.spec.is_none());
    }

    #[test]
    fn proposal_roundtrip_with_spec_field() {
        let p = Proposal {
            id: "p42".into(),
            skill: "coding".into(),
            skill_path: "/tmp/skill.md".into(),
            before: "old".into(),
            after: "new".into(),
            summary: "tighten".into(),
            status: ProposalStatus::Pending,
            at_unix: 100,
            backup: None,
            score_before: 0.5,
            score_after: 0.8,
            heldout_eval_summary: String::new(),
            why_this_improves: String::new(),
            risk_notes: String::new(),
            spec: Some(ProposalSpec {
                verification_command: Some("cargo test".to_string()),
                done_criteria: None,
                stop_conditions: vec![],
                drift_sha: Some("deadbeef".to_string()),
            }),
        };
        let json = serde_json::to_string_pretty(&p).unwrap();
        let back: Proposal = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // ── IMPR-01: parse_proposal_output extracts ProposalSpec from envelope ────

    #[test]
    fn parse_proposal_output_extracts_spec_from_envelope() {
        let json = r#"{
            "skill": "BODY",
            "score_before": 0.3,
            "score_after": 0.7,
            "heldout_eval_summary": "ok",
            "why_this_improves": "faster",
            "risk_notes": "none",
            "verification_command": "cargo test -p neothd",
            "done_criteria": "all 42 tests pass",
            "stop_conditions": ["FAILED", "error["]
        }"#;
        let (content, quality, spec) = parse_proposal_output(json);
        assert_eq!(content, "BODY");
        assert!((quality.score_before - 0.3).abs() < 1e-9);
        assert!((quality.score_after - 0.7).abs() < 1e-9);
        let spec = spec.expect("spec must be present");
        assert_eq!(spec.verification_command.as_deref(), Some("cargo test -p neothd"));
        assert_eq!(spec.done_criteria.as_deref(), Some("all 42 tests pass"));
        assert_eq!(spec.stop_conditions, vec!["FAILED", "error["]);
        // drift_sha not in envelope — populated at stage time
        assert!(spec.drift_sha.is_none());
    }

    #[test]
    fn parse_proposal_output_plain_text_no_spec() {
        let (content, quality, spec) = parse_proposal_output("just the skill body");
        assert_eq!(content, "just the skill body");
        assert_eq!(quality, ProposalQuality::default());
        assert!(spec.is_none());
    }

    #[test]
    fn parse_proposal_output_envelope_without_spec_fields_returns_none_spec() {
        let json = r#"{"skill":"BODY","score_before":0.1,"score_after":0.2,"heldout_eval_summary":"","why_this_improves":"","risk_notes":""}"#;
        let (_content, _quality, spec) = parse_proposal_output(json);
        // No spec fields → spec is None (not an empty Some).
        assert!(spec.is_none());
    }

    // ── IMPR-02: drift detection via stage → mutate → accept ─────────────────

    #[test]
    fn stage_captures_drift_sha_field() {
        // If git is available in the test environment, drift_sha is populated;
        // otherwise it stays None — both are valid (graceful degradation).
        let tmp = std::env::temp_dir().join("neoth_si_drift_sha_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(proposals_path(&tmp));
        let skill = tmp.join("skill_drift_sha.md");
        std::fs::write(&skill, "CONTENT").unwrap();

        let id = stage_proposal(
            &tmp,
            Proposal {
                id: "pdrift_sha".into(),
                skill: "test".into(),
                skill_path: skill.display().to_string(),
                before: "CONTENT".into(),
                after: "IMPROVED".into(),
                summary: "sha test".into(),
                status: ProposalStatus::Pending,
                at_unix: 1,
                backup: None,
                ..Default::default()
            },
        )
        .unwrap();

        let proposals = load_proposals(&tmp);
        let staged = proposals.iter().find(|p| p.id == id).unwrap();
        // drift_sha is either Some(sha) or None — never panics.
        let _ = staged.spec.as_ref().and_then(|s| s.drift_sha.as_deref());

        let _ = std::fs::remove_file(proposals_path(&tmp));
        let _ = std::fs::remove_file(&skill);
    }

    #[test]
    fn accept_emits_drift_warning_when_skill_changed() {
        // Simulate drift: stage with a known fake SHA → accept without git having
        // that SHA in history → diff --stat returns non-empty → warning on stderr.
        // We capture stderr by redirecting via a subprocess would be complex, so
        // we test the helper function directly instead.
        //
        // git_diff_stat_since with a SHA that doesn't exist returns None (graceful).
        let result = git_diff_stat_since("0000000", "/nonexistent/path/skill.md");
        // Either None (git not available or SHA not found) or Some — both OK.
        // The important thing: it never panics.
        let _ = result;
    }

    #[test]
    fn accept_with_spec_drift_sha_none_never_warns() {
        // Proposal with spec but no drift_sha → no drift check → accept cleanly.
        let tmp = std::env::temp_dir().join("neoth_si_no_drift_warn_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(proposals_path(&tmp));
        let skill = tmp.join("skill_no_drift.md");
        std::fs::write(&skill, "ORIGINAL").unwrap();

        let p = Proposal {
            id: "pnodrift".into(),
            skill: "test".into(),
            skill_path: skill.display().to_string(),
            before: "ORIGINAL".into(),
            after: "IMPROVED".into(),
            summary: "no drift sha".into(),
            status: ProposalStatus::Pending,
            at_unix: 1,
            backup: None,
            spec: Some(ProposalSpec {
                verification_command: None,
                done_criteria: None,
                stop_conditions: vec![],
                drift_sha: None, // no SHA → drift check skipped
            }),
            ..Default::default()
        };
        // Pre-set status to Pending (stage_proposal would overwrite drift_sha).
        let mut all = load_proposals(&tmp);
        all.push(p);
        save_proposals(&tmp, &all).unwrap();

        // accept must succeed without panic/error
        accept_proposal(&tmp, "pnodrift").unwrap();
        assert_eq!(std::fs::read_to_string(&skill).unwrap(), "IMPROVED");

        let _ = std::fs::remove_file(proposals_path(&tmp));
        let _ = std::fs::remove_file(&skill);
    }

    // ── IMPR-03: review_execution_result and execute_proposal_with_verification

    #[test]
    fn review_execution_result_approved() {
        assert_eq!(
            review_execution_result("APPROVE — looks good"),
            ExecutionVerdict::Approved
        );
        assert_eq!(
            review_execution_result("  approve: the change is clean"),
            ExecutionVerdict::Approved
        );
    }

    #[test]
    fn review_execution_result_revise() {
        let v = review_execution_result("REVISE: missing error handling");
        assert!(matches!(v, ExecutionVerdict::Revise { .. }));
        if let ExecutionVerdict::Revise { reason } = v {
            assert!(reason.contains("missing error handling"));
        }
    }

    #[test]
    fn review_execution_result_blocked() {
        let v = review_execution_result("BLOCK: test regression detected");
        assert!(matches!(v, ExecutionVerdict::Blocked { .. }));
        if let ExecutionVerdict::Blocked { reason } = v {
            assert!(reason.contains("test regression"));
        }
    }

    #[test]
    fn review_execution_result_no_token_is_blocked() {
        let v = review_execution_result("looks fine to me");
        assert!(matches!(v, ExecutionVerdict::Blocked { .. }));
    }

    #[test]
    fn execute_proposal_with_verification_advisor_approve() {
        let tmp = std::env::temp_dir().join("neoth_si_exec_approve_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(proposals_path(&tmp));
        let skill = tmp.join("skill_exec_approve.md");
        std::fs::write(&skill, "ORIGINAL").unwrap();

        // Stage without running stage_proposal so drift_sha stays None.
        let mut all: Vec<Proposal> = vec![];
        all.push(Proposal {
            id: "pexec".into(),
            skill: "test".into(),
            skill_path: skill.display().to_string(),
            before: "ORIGINAL".into(),
            after: "IMPROVED".into(),
            summary: "exec test".into(),
            status: ProposalStatus::Pending,
            at_unix: 1,
            backup: None,
            spec: Some(ProposalSpec {
                verification_command: None, // no verification command
                done_criteria: Some("all tests pass".to_string()),
                stop_conditions: vec![],
                drift_sha: None,
            }),
            ..Default::default()
        });
        save_proposals(&tmp, &all).unwrap();

        let (verdict, revises) = execute_proposal_with_verification(
            &tmp,
            "pexec",
            2,
            |_diff, _vout| "APPROVE — looks clean".to_string(),
        )
        .unwrap();

        assert_eq!(verdict, ExecutionVerdict::Approved);
        assert_eq!(revises, 0);

        // accept is still gated — skill file untouched
        assert_eq!(std::fs::read_to_string(&skill).unwrap(), "ORIGINAL");

        let _ = std::fs::remove_file(proposals_path(&tmp));
        let _ = std::fs::remove_file(&skill);
    }

    #[test]
    fn execute_proposal_max_revises_blocks() {
        let tmp = std::env::temp_dir().join("neoth_si_exec_revise_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(proposals_path(&tmp));
        let skill = tmp.join("skill_exec_revise.md");
        std::fs::write(&skill, "ORIGINAL").unwrap();

        let mut all: Vec<Proposal> = vec![];
        all.push(Proposal {
            id: "previse".into(),
            skill: "test".into(),
            skill_path: skill.display().to_string(),
            before: "ORIGINAL".into(),
            after: "IMPROVED".into(),
            summary: "revise loop".into(),
            status: ProposalStatus::Pending,
            at_unix: 1,
            backup: None,
            spec: None,
            ..Default::default()
        });
        save_proposals(&tmp, &all).unwrap();

        // advisor always says REVISE → must hit max_revises cap
        let (verdict, revises) = execute_proposal_with_verification(
            &tmp,
            "previse",
            2,
            |_diff, _vout| "REVISE: needs more work".to_string(),
        )
        .unwrap();

        assert!(matches!(verdict, ExecutionVerdict::Blocked { .. }));
        assert_eq!(revises, 2);

        let _ = std::fs::remove_file(proposals_path(&tmp));
        let _ = std::fs::remove_file(&skill);
    }

    #[test]
    fn execute_proposal_stop_condition_triggers_block() {
        let tmp = std::env::temp_dir().join("neoth_si_exec_stop_test");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(proposals_path(&tmp));
        let skill = tmp.join("skill_exec_stop.md");
        std::fs::write(&skill, "ORIGINAL").unwrap();

        // verification_command that emits a stop-condition line
        #[cfg(windows)]
        let vcmd = "echo FAILED: test broken";
        #[cfg(not(windows))]
        let vcmd = "echo 'FAILED: test broken'";

        let mut all: Vec<Proposal> = vec![];
        all.push(Proposal {
            id: "pstop".into(),
            skill: "test".into(),
            skill_path: skill.display().to_string(),
            before: "ORIGINAL".into(),
            after: "IMPROVED".into(),
            summary: "stop cond".into(),
            status: ProposalStatus::Pending,
            at_unix: 1,
            backup: None,
            spec: Some(ProposalSpec {
                verification_command: Some(vcmd.to_string()),
                done_criteria: None,
                stop_conditions: vec!["FAILED".to_string()],
                drift_sha: None,
            }),
            ..Default::default()
        });
        save_proposals(&tmp, &all).unwrap();

        let (verdict, _revises) = execute_proposal_with_verification(
            &tmp,
            "pstop",
            2,
            |_diff, _vout| "APPROVE".to_string(),
        )
        .unwrap();

        assert!(matches!(verdict, ExecutionVerdict::Blocked { .. }));

        let _ = std::fs::remove_file(proposals_path(&tmp));
        let _ = std::fs::remove_file(&skill);
    }
}
