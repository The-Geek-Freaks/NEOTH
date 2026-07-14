//! Self-improvement â€” NEOTH evolves its OWN skills with microsoft/SkillOpt
//! (the SkillOpt-Sleep engine): a validation-gated, review-then-adopt optimizer
//! that reviews past sessions + long-term memory and proposes bounded edits to a
//! skill document, accepting an edit ONLY when it strictly improves a held-out
//! gate. It synthesizes SkillOpt's discipline with NEOTH's existing dreaming
//! (offline consolidation) + self-dev (review-then-adopt) model.
//!
//! NEOTH drives it as an EXTERNAL engine (wizard-installed Python, like
//! cua-driver / claude-cli â€” self-contained rule honoured), GATED by an operator
//! switch and an ask-first prompt. Every run is recorded (a JSON ledger +,
//! per accepted improvement, a memory/WAL trail) so the operator can always see
//! *whether* and *what* improved â€” surfaced in the CLI (`neoth self-improve`),
//! `neoth doctor`, and the GUI.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The auto-improve switch + ask-state, in `<home>/self_improve.yaml` (separate
/// from freedom.yaml so toggling it never risks the main config).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelfImproveConfig {
    /// Master switch â€” self-improvement is allowed to run at all.
    #[serde(default)]
    pub enabled: bool,
    /// Run automatically (the nightly sleep cycle) vs operator-triggered only.
    #[serde(default)]
    pub auto: bool,
    /// The operator has been asked once whether to enable it (so NEOTH only
    /// prompts a single time, per the "ask before using" requirement).
    #[serde(default)]
    pub asked: bool,
    /// SELF-IMPROVE-SAFETY-01 â€” opt-in gate for the shell verifier path.
    /// Defaults to `false` (deny). When false, any `verification_command`
    /// present in a proposal is NEVER spawned; `execute_proposal_with_verification`
    /// returns `Blocked` immediately, keeping the proposal in `Pending` state.
    /// Set to `true` in `self_improve.yaml` only after the operator explicitly
    /// acknowledges that a child process may execute inside the sandbox.
    #[serde(default)]
    pub allow_shell_verify: bool,
}

impl SelfImproveConfig {
    pub fn path(home: &Path) -> PathBuf {
        home.join("self_improve.yaml")
    }
    /// Load the stored config. A missing file is the first-run default; every
    /// other read or parse failure is returned so callers cannot silently
    /// replace corrupt state with defaults.
    pub fn load(home: &Path) -> Result<Self> {
        Ok(Self::load_strict(home)?.unwrap_or_default())
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self)?;
        crate::util::atomic_write::atomic_write_private(&Self::path(home), yaml.as_bytes())?;
        Ok(())
    }

    /// B19: fail-closed config loader.
    /// - File absent (`NotFound`) â†’ `Ok(None)` (never-configured, first-time).
    /// - Any other I/O error or YAML parse error â†’ `Err` (corrupt â€” callers must
    ///   not fall back to a default that could re-enable a disabled master switch).
    pub fn load_strict(home: &Path) -> Result<Option<Self>> {
        let p = Self::path(home);
        match std::fs::read_to_string(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => {
                Err(anyhow::Error::from(e).context(format!("could not read {}", p.display())))
            }
            Ok(s) => serde_yaml::from_str(&s)
                .map(Some)
                .map_err(|e| anyhow::anyhow!("{}: YAML parse error: {e}", p.display())),
        }
    }

    /// Resolve the effective switch for a given daemon autonomy level.
    /// `Full` autonomy implies self-improvement runs automatically (the nightly
    /// sleep cycle STAGES proposals) â€” "skillopt improve auto on in full-auto
    /// mode" â€” UNLESS the operator has made an explicit choice (`asked`), which
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
                // SELF-IMPROVE-SAFETY-01: full-auto stages proposals but must NEVER
                // auto-enable the shell verifier â€” carry the stored opt-in through.
                allow_shell_verify: self.allow_shell_verify,
            }
        } else {
            self
        }
    }
}

/// B19: resolve effective config from `Option<SelfImproveConfig>`.
///
/// - `None` = file absent (never configured).  Under `Full` autonomy this implies
///   auto-on (same as the `Full && !asked` branch of the legacy `effective()`).
///   Below `Full`, defaults remain all-off until the operator enables explicitly.
/// - `Some(cfg)` = stored choice is always returned unchanged at every autonomy
///   level.  The corruption path never reaches here â€” callers abort on `Err`
///   before calling this function.
///
/// B15 safety: `allow_shell_verify` is never set to `true` by this function.
pub fn effective_from_option(
    opt: Option<SelfImproveConfig>,
    autonomy: crate::permissions::AutonomyLevel,
) -> SelfImproveConfig {
    match opt {
        None => {
            if autonomy == crate::permissions::AutonomyLevel::Full {
                SelfImproveConfig {
                    enabled: true,
                    auto: true,
                    asked: false,
                    // B15: never auto-enable the shell verifier for absent config.
                    allow_shell_verify: false,
                }
            } else {
                SelfImproveConfig::default()
            }
        }
        Some(cfg) => cfg, // stored choice always wins â€” no override
    }
}

/// One recorded self-improvement attempt â€” the "what improved" surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImproveRecord {
    /// Proposal this audit record belongs to. Absent only for legacy records
    /// and standalone non-proposal attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
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

/// Every recorded improvement attempt, oldest first. Missing is an empty
/// first-run store; malformed or unreadable existing state is a hard error.
fn load_ledger_raw(home: &Path) -> Result<Vec<ImproveRecord>> {
    let p = ledger_path(home);
    match std::fs::read_to_string(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(anyhow::Error::from(e).context(format!("ledger read: {}", p.display()))),
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| anyhow::anyhow!("{}: JSON parse error: {e}", p.display())),
    }
}

fn save_ledger_raw(home: &Path, records: &[ImproveRecord]) -> Result<()> {
    let json = serde_json::to_string_pretty(records)?;
    crate::util::atomic_write::atomic_write_private(&ledger_path(home), json.as_bytes())?;
    Ok(())
}

static SELF_IMPROVE_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn state_lock_path(home: &Path) -> PathBuf {
    home.join("self_improve_state.lock")
}

fn with_state_lock<T>(home: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = SELF_IMPROVE_STATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _oslock = crate::util::locked_file::lock_file_blocking(
        &state_lock_path(home),
        "self-improvement state",
    )?;
    recover_transactions_locked(home)?;
    f()
}

/// Pending cross-file transactions are recovered under the shared state lock
/// before any records become visible.
pub fn load_ledger(home: &Path) -> Result<Vec<ImproveRecord>> {
    with_state_lock(home, || load_ledger_raw(home))
}

pub fn append_record(home: &Path, rec: ImproveRecord) -> Result<()> {
    append_ledger_locked(home, rec)
}

/// The most recent improvement attempt, if any.
pub fn last_record(home: &Path) -> Result<Option<ImproveRecord>> {
    Ok(load_ledger(home)?.into_iter().next_back())
}

// B19: strict ledger loader + locked append â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Strict ledger loader: `NotFound` â†’ empty vec; corrupt JSON â†’ `Err`.
/// Append a record to the ledger under the write lock.
///
/// Returns `Err` if the ledger is corrupt or the write fails â€” callers must
/// propagate (never silently ignore). Mirrors `ProactiveQueue::modify` pattern.
pub fn append_ledger_locked(home: &Path, rec: ImproveRecord) -> Result<()> {
    with_state_lock(home, || {
        let mut log = load_ledger_raw(home)?;
        log.push(rec);
        save_ledger_raw(home, &log)
    })
}

// â”€â”€ Review-then-adopt: staged proposals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SkillOpt NEVER writes to a production skill file. Every run STAGES a proposal;
// only an explicit `accept` writes it (after backing up the replaced content),
// and `rollback` restores that backup. This is the hard gate: no skill changes
// without operator approval, and any change is reversible.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    #[default]
    Pending,
    /// NEOTH-AUDIT-SELF-IMPROVE-SAFETY-01 (residual 1): the proposal passed
    /// `execute_proposal_with_verification` and the advisor issued an `Approved`
    /// verdict that was **persisted to disk**. `accept_proposal` requires this
    /// state â€” a `Pending` proposal (not yet verified) cannot be accepted
    /// directly, even after a daemon restart.
    VerifiedApproved,
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
    // â”€â”€ Quality score: WHY this improves, not just the diff â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    /// Held-out gate score before / after the edit (0.0 when the engine didn't
    /// report one â€” e.g. an operator-supplied `--from` proposal).
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
    // â”€â”€ IMPR-01: ProposalSpec â€” structured execution / verification envelope â”€â”€
    /// Optional execution spec emitted by SkillOpt or an operator-supplied
    /// envelope. Back-compat: absent in older proposals â†’ None.
    #[serde(default)]
    pub spec: Option<ProposalSpec>,
}

/// Structured execution specification attached to a staged proposal (IMPR-01).
///
/// Fields map directly from the SkillOpt JSON envelope (or operator-supplied
/// `--from` proposals). All fields are optional â€” a proposal is valid without
/// any spec; these fields add machine-checkable done-gates and safety stops.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProposalSpec {
    /// Shell command (or test invocation) to run to verify the edit worked.
    /// E.g. `"cargo test -p neoth -- self_improve"`. None = no gate.
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

fn load_proposals_raw(home: &Path) -> Result<Vec<Proposal>> {
    let p = proposals_path(home);
    match std::fs::read_to_string(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(anyhow::Error::from(e).context(format!("proposals read: {}", p.display()))),
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| anyhow::anyhow!("{}: JSON parse error: {e}", p.display())),
    }
}

fn save_proposals_raw(home: &Path, props: &[Proposal]) -> Result<()> {
    let json = serde_json::to_string_pretty(props)?;
    crate::util::atomic_write::atomic_write_private(&proposals_path(home), json.as_bytes())?;
    Ok(())
}

pub fn load_proposals(home: &Path) -> Result<Vec<Proposal>> {
    with_state_lock(home, || load_proposals_raw(home))
}

#[cfg(test)]
fn save_proposals(home: &Path, props: &[Proposal]) -> Result<()> {
    with_state_lock(home, || save_proposals_raw(home, props))
}

// B19: proposals write lock + strict loader + transactional RMW â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Strict proposals loader: `NotFound` â†’ empty vec; corrupt JSON â†’ `Err`.
/// Transactional proposals read-modify-write under the shared state lock.
///
/// 1. Acquires the process-local lock.
/// 2. Reloads (strict) under the lock so concurrent wçtöÚ$z{-®éÜj×'6¶–ÆÂf–ÆR×W7B&RVæ6†ævVB ¢“°¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöF—%öÆÂ‚gF×“°¢Ğ ¢5·FW7EĞ¢fâ#•÷&V6÷fW%÷VæF–æuö¦÷W&æÅöW'&÷'5öæE÷&W6W'fW5÷v†Vå÷6¶–ÆÅ÷Vç&VF&ÆR‚’°¢òò#’f–ÂÖ6Æ÷6VC¢¦÷W&æÂW†—7G2'WBF†R6¶–ÆÂf–ÆR—2Ö—76–ær÷Vç&VF&ÆP¢òò(i"F†Rw&—FRÖÆæFVB7FFR—2Tä´äõtââ&V6÷fW'’×W7BäõBFVfVÇBF†R&VBFğ¢òòV×G’æBwVW72G&ç6—F–öã²—B×W7BW'&÷"æBÆVfRF†R¦÷W&æÂöâF—6²à¢ÆWBF×Ğ¢7FC£¦Vçc£§FV×öF—"‚’æ¦ö–â†f÷&ÖB‚&æV÷F…ö#•÷&V5÷Vç&VF&ÆU÷·Ò"Â7FC£§&ö6W73£¦–B‚’’“°¢ÆWBòÒ7FC£¦g3£¦7&VFUöF—%öÆÂ‚gF×“° ¢ÆWB6¶–ÆÅ÷F‚ÒF×æ¦ö–â‚&vöæRæÖB"“²òòFVÆ–&W&FVÇ’æWfW"7&VFV@¢ÆWB¦÷W&æÂÒ66WD¦÷W&æÂ°¢&÷÷6Åö–C¢'"çFõ÷7G&–ær‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢÷&–v–æÅö'—FW3¢&÷&–v–æÂ"çFõ÷7G&–ær‚’À¢–çFVæFVE÷7FGW3¢&÷÷6Å7FGW3£¤66WFVBÀ¢&6U÷6†#Sc¢6öÖR‡6†#Seö†W‚‚&÷&–v–æÂ"’’À¢F&vWE÷6†#Sc¢6öÖR‡6†#Seö†W‚‚&æWr6öçFVçB"’’À¢&6Uö†6ƒ¢æöæRÀ¢F&vWEö†6ƒ¢æöæRÀ¢Ó°¢7FC£¦g3£§w&—FR€¢¦÷W&æÅ÷F‚‚gF×’À¢6W&FUö§6öã£§Fõ÷7G&–æu÷&WGG’‚f¦÷W&æÂ’çVçw&‚’À¢¢çVçw&‚“° ¢ÆWB"Ò&V6÷fW%÷VæF–æuö¦÷W&æÂ‚gF×“°¢76W'B‡"æ—5öW'"‚’Â'Vç&VF&ÆR6¶–ÆÂ×W7Bf–Â&V6÷fW'’Âæ÷BwVW72"“°¢76W'B€¢¦÷W&æÅ÷F‚‚gF×’æW†—7G2‚’À¢&¦÷W&æÂ×W7B&R&W6W'fVBf÷"&WG'’ò÷W&F÷"–ç7V7F–öâ ¢“°¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöF—%öÆÂ‚gF×“°¢Ğ ¢5·FW7EĞ¢fâ#•÷WFFU÷&÷÷6Ç5ö7&VFW5ö÷6Æö6µ÷6–&Æ–ær‚’°¢òò#’7&÷72×&ö6W72F–W#¢WfW'’&÷÷6ÂöÆVFvW"G&ç67F–öâW6W2F†P¢òò6†&VB7FFRÆö6²æB7F–ÆÂ&÷VæB×G&—2F†R×WFF–öâà¢ÆWBF×Ò7FC£¦Vçc£§FV×öF—"‚’æ¦ö–â†f÷&ÖB‚&æV÷F…ö#•ö÷6Æö6µ÷·Ò"Â7FC£§&ö6W73£¦–B‚’’“°¢ÆWBòÒ7FC£¦g3£¦7&VFUöF—%öÆÂ‚gF×“° ¢WFFU÷&÷÷6Ç2‚gF×ÂÆÆÇÂ°¢ÆÂçW6‚…&÷÷6Â°¢–C¢'"çFõ÷7G&–ær‚’À¢6¶–ÆÃ¢'2"çFõ÷7G&–ær‚’À¢6¶–ÆÅ÷Fƒ¢'‚"çFõ÷7G&–ær‚’À¢&Vf÷&S¢7G&–æs£¦æWr‚’À¢gFW#¢7G&–æs£¦æWr‚’À¢7VÖÖ'“¢7G&–æs£¦æWr‚’À¢7FGW3¢&÷÷6Å7FGW3£¥VæF–ærÀ¢E÷Væ—ƒ¢À¢&6·W¢æöæRÀ¢66÷&Uö&Vf÷&S¢ãÀ¢66÷&UögFW#¢ãÀ¢†VÆF÷WEöWfÅ÷7VÖÖ'“¢7G&–æs£¦æWr‚’À¢v‡•÷F†—5ö–×&÷fW3¢7G&–æs£¦æWr‚’À¢&—6µöæ÷FW3¢7G&–æs£¦æWr‚’À¢7V3¢æöæRÀ¢Ò“°¢ö²‚‚’¢Ò¢çVçw&‚“° ¢76W'B€¢7FFUöÆö6µ÷F‚‚gF×’æW†—7G2‚’À¢'6†&VBõ2Æö6²×W7B&R7&VFVB ¢“°¢76W'EöW€¢ÆöE÷&÷÷6Ç2‚gF×’çVçw&‚’æÆVâ‚’À¢À¢&×WFF–öâ×W7BW'6—7B ¢“°¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöF—%öÆÂ‚gF×“°¢Ğ ¢5·FW7EĞ¢fâ#•÷&V6÷fW%÷VæF–æuö¦÷W&æÅö6öÖÖ—G5÷v†Vå÷6¶–ÆÅ÷w&—GFVå÷&÷÷6Ç5öæ÷E÷6fVB‚’°¢òò7&6‚66Væ&–ó¢6¶–ÆÂw&—GFVâÂ&÷÷6Ç2æ§6öâæ÷B–WBWFFVBà¢ÆWBF×Ò7FC£¦Vçc£§FV×öF—"‚’æ¦ö–â†f÷&ÖB‚&æV÷F…ö#•÷&V5ö6öÖÖ—E÷·Ò"Â7FC£§&ö6W73£¦–B‚’’“°¢ÆWBòÒ7FC£¦g3£¦7&VFUöF—%öÆÂ‚gF×“° ¢ÆWB÷&–v–æÂÒ&öÆB6öçFVçB#°¢ÆWBæWuö6öçFVçBÒ&æWr6öçFVçB#°¢ÆWB6¶–ÆÅ÷F‚ÒF×æ¦ö–â‚'6¶–ÆÂæÖB"“°¢òò6–×VÆFS¢6¶–ÆÂf–ÆRÇ&VG’†2F†RæWr6öçFVçBà¢7FC£¦g3£§w&—FR‚g6¶–ÆÅ÷F‚ÂæWuö6öçFVçB’çVçw&‚“° ¢òò&÷÷6Ç2æ§6öâ7F–ÆÂ6†÷w2fW&–f–VD&÷fVB†æ÷B66WFVB’à¢ÆWB&÷Ò&÷÷6Â°¢–C¢'"çFõ÷7G&–ær‚’À¢6¶–ÆÃ¢'FW7B"çFõ÷7G&–ær‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢&Vf÷&S¢÷&–v–æÂçFõ÷7G&–ær‚’À¢gFW#¢æWuö6öçFVçBçFõ÷7G&–ær‚’À¢7VÖÖ'“¢'FW7B"çFõ÷7G&–ær‚’À¢7FGW3¢&÷÷6Å7FGW3£¥fW&–f–VD&÷fVBÀ¢E÷Væ—ƒ¢À¢&6·W¢æöæRÀ¢66÷&Uö&Vf÷&S¢ãÀ¢66÷&UögFW#¢ãÀ¢†VÆF÷WEöWfÅ÷7VÖÖ'“¢""çFõ÷7G&–ær‚’À¢v‡•÷F†—5ö–×&÷fW3¢""çFõ÷7G&–ær‚’À¢&—6µöæ÷FW3¢""çFõ÷7G&–ær‚’À¢7V3¢æöæRÀ¢Ó°¢6fU÷&÷÷6Ç2‚gF×Âe·&÷Ò’çVçw&‚“° ¢òò¦÷W&æÂ&V6÷&G2&6Uö†6‚öbF†RôÄB6öçFVçBà¢ÆWB¦÷W&æÂÒ66WD¦÷W&æÂ°¢&÷÷6Åö–C¢'"çFõ÷7G&–ær‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢÷&–v–æÅö'—FW3¢÷&–v–æÂçFõ÷7G&–ær‚’À¢–çFVæFVE÷7FGW3¢&÷÷6Å7FGW3£¤66WFVBÀ¢&6U÷6†#Sc¢6öÖR‡6†#Seö†W‚†÷&–v–æÂ’’À¢F&vWE÷6†#Sc¢6öÖR‡6†#Seö†W‚†æWuö6öçFVçB’’À¢&6Uö†6ƒ¢æöæRÀ¢F&vWEö†6ƒ¢æöæRÀ¢Ó°¢7FC£¦g3£§w&—FR€¢¦÷W&æÅ÷F‚‚gF×’À¢6W&FUö§6öã£§Fõ÷7G&–æu÷&WGG’‚f¦÷W&æÂ’çVçw&‚’À¢¢çVçw&‚“° ¢òò7W'&VçEö†6‚†æWuö6öçFVçB’Ò&6Uö†6‚†÷&–v–æÂ’(i"&V6÷fW'’6öÖÖ—G2à¢&V6÷fW%÷VæF–æuö¦÷W&æÂ‚gF×’çVçw&‚“° ¢76W'B€¢¦÷W&æÅ÷F‚‚gF×’æW†—7G2‚’À¢&¦÷W&æÂ×W7B&R&VÖ÷fVBgFW"&V6÷fW'’ ¢“° ¢ÆWB&÷÷6Ç2ÒÆöE÷&÷÷6Ç2‚gF×’çVçw&‚“°¢ÆWBÒ&÷÷6Ç2æ—FW"‚’æf–æB‡ÇÂæ–BÓÒ'"’çVçw&‚“°¢76W'EöW€¢ç7FGW2À¢&÷÷6Å7FGW3£¤66WFVBÀ¢'&V6÷fW'’×W7B6öÖÖ—B66WFVB7FGW2 ¢“°¢76W'EöW€¢æ&6·Wæ5öFW&Vb‚’À¢6öÖR†÷&–v–æÂ’À¢'&V6÷fW'’×W7BW'6—7BF†R&RÖ66WB&6·W ¢“°¢ÆWBÆVFvW"ÒÆöEöÆVFvW"‚gF×’çVçw&‚“°¢ÆWB&V6÷&BÒÆVFvW ¢æ—FW"‚¢æf–æB‡Ç&V6÷&GÂ&V6÷&Bç&÷÷6Åö–Bæ5öFW&Vb‚’ÓÒ6öÖR‚'"’¢æW‡V7B‚'&V6÷fW'’×W7B7&VFR÷"&W—"F†R&÷VæBÆVFvW"&V6÷&B"“°¢76W'B‡&V6÷&Bæ66WFVB“°¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöF—%öÆÂ‚gF×“°¢Ğ ¢5·FW7EĞ¢fâ#•÷&V6÷fW'•÷&V¦V7G5öÖ&–wV÷W5÷F†—&E÷7FFUöæE÷&W6W'fW5ö¦÷W&æÂ‚’°¢ÆWBF×ÒFV×f–ÆS£§FV×F—"‚’çVçw&‚“°¢ÆWB÷&–v–æÂÒ&öÆB6öçFVçB#°¢ÆWBF&vWBÒ&–çFVæFVB6öçFVçB#°¢ÆWBf÷&V–vâÒ&f÷&V–vâ÷"'F–Â×WFF–öâ#°¢ÆWB6¶–ÆÅ÷F‚ÒF×çF‚‚’æ¦ö–â‚'6¶–ÆÂæÖB"“°¢7FC£¦g3£§w&—FR‚g6¶–ÆÅ÷F‚Âf÷&V–vâ’çVçw&‚“°¢6fU÷&÷÷6Ç2€¢F×çF‚‚’À¢eµ&÷÷6Â°¢–C¢'×F†—&B×7FFR"æ–çFò‚’À¢6¶–ÆÃ¢'FW7B"æ–çFò‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢&Vf÷&S¢÷&–v–æÂæ–çFò‚’À¢gFW#¢F&vWBæ–çFò‚’À¢7VÖÖ'“¢'F†—&B×7FFRwV&B"æ–çFò‚’À¢7FGW3¢&÷÷6Å7FGW3£¥fW&–f–VD&÷fVBÀ¢âäFVfVÇC£¦FVfVÇB‚¢ÕÒÀ¢¢çVçw&‚“°¢ÆWB¦÷W&æÂÒ66WD¦÷W&æÂ°¢&÷÷6Åö–C¢'×F†—&B×7FFR"æ–çFò‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢÷&–v–æÅö'—FW3¢÷&–v–æÂæ–çFò‚’À¢–çFVæFVE÷7FGW3¢&÷÷6Å7FGW3£¤66WFVBÀ¢&6U÷6†#Sc¢6öÖR‡6†#Seö†W‚†÷&–v–æÂ’’À¢F&vWE÷6†#Sc¢6öÖR‡6†#Seö†W‚‡F&vWB’’À¢&6Uö†6ƒ¢æöæRÀ¢F&vWEö†6ƒ¢æöæRÀ¢Ó°¢7FC£¦g3£§w&—FR€¢¦÷W&æÅ÷F‚‡F×çF‚‚’’À¢6W&FUö§6öã£§Fõ÷fV5÷&WGG’‚f¦÷W&æÂ’çVçw&‚’À¢¢çVçw&‚“° ¢ÆWBW'&÷"Ò&V6÷fW%÷VæF–æuö¦÷W&æÂ‡F×çF‚‚’’çVçw&öW'"‚“° ¢76W'B†f÷&ÖB‚'¶W'&÷#¢7Ò"’æ6öçF–ç2‚&Ö&–wV÷W2F†—&B×7FFR"’“°¢76W'B€¢¦÷W&æÅ÷F‚‡F×çF‚‚’’æW†—7G2‚’À¢&Ö&–wV÷W2&V6÷fW'’×W7B&W6W'fRF†R¦÷W&æÂ ¢“°¢76W'EöW€¢ÆöE÷&÷÷6Ç5÷&r‡F×çF‚‚’’çVçw&‚•³Òç7FGW2À¢&÷÷6Å7FGW3£¥fW&–f–VD&÷fVBÀ¢&Ö&–wV÷W2'—FW2×W7Bæ÷B6öÖÖ—BF†R7FGW2G&ç6—F–öâ ¢“°¢76W'EöW‡7FC£¦g3£§&VE÷Fõ÷7G&–ær‡6¶–ÆÅ÷F‚’çVçw&‚’Âf÷&V–vâ“°¢Ğ ¢5·FW7EĞ¢fâ#•÷&V6÷fW'•÷&V¦V7G5÷&÷÷6Å÷F&vWE÷F×W&VEögFW%ö¦÷W&æÂ‚’°¢ÆWBF×ÒFV×f–ÆS£§FV×F—"‚’çVçw&‚“°¢ÆWB÷&–v–æÂÒ&öÆB6öçFVçB#°¢ÆWB–çFVæFVBÒ&¦÷W&æÂÖ&÷VæB–çFVæFVB6öçFVçB#°¢ÆWBF×W&VBÒ'&÷÷6Â6†ævVBgFW"¦÷W&æÂw&—FR#°¢ÆWB6¶–ÆÅ÷F‚ÒF×çF‚‚’æ¦ö–â‚'6¶–ÆÂæÖB"“°¢òòF†—2ÖF6†W2F†RF×W&VB&÷÷6ÂW†7FÇ’âv—F†÷WBF†R¦÷W&æÂw0¢òò4„Ó#SbF&vWB&–æF–ærÂW†7B7W'&VçB×g2×&÷÷6Â6ö×&—6öâÆöæP¢òòv÷VÆB–æ6÷'&V7FÇ’6öÖÖ—B—Bà¢7FC£¦g3£§w&—FR‚g6¶–ÆÅ÷F‚ÂF×W&VB’çVçw&‚“°¢6fU÷&÷÷6Ç2€¢F×çF‚‚’À¢eµ&÷÷6Â°¢–C¢'×F×W&VB×F&vWB"æ–çFò‚’À¢6¶–ÆÃ¢'FW7B"æ–çFò‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢&Vf÷&S¢÷&–v–æÂæ–çFò‚’À¢gFW#¢F×W&VBæ–çFò‚’À¢7VÖÖ'“¢'F×W"wV&B"æ–çFò‚’À¢7FGW3¢&÷÷6Å7FGW3£¥fW&–f–VD&÷fVBÀ¢âäFVfVÇC£¦FVfVÇB‚¢ÕÒÀ¢¢çVçw&‚“°¢ÆWB¦÷W&æÂÒ66WD¦÷W&æÂ°¢&÷÷6Åö–C¢'×F×W&VB×F&vWB"æ–çFò‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢÷&–v–æÅö'—FW3¢÷&–v–æÂæ–çFò‚’À¢–çFVæFVE÷7FGW3¢&÷÷6Å7FGW3£¤66WFVBÀ¢&6U÷6†#Sc¢6öÖR‡6†#Seö†W‚†÷&–v–æÂ’’À¢F&vWE÷6†#Sc¢6öÖR‡6†#Seö†W‚†–çFVæFVB’’À¢&6Uö†6ƒ¢æöæRÀ¢F&vWEö†6ƒ¢æöæRÀ¢Ó°¢7FC£¦g3£§w&—FR€¢¦÷W&æÅ÷F‚‡F×çF‚‚’’À¢6W&FUö§6öã£§Fõ÷fV5÷&WGG’‚f¦÷W&æÂ’çVçw&‚’À¢¢çVçw&‚“° ¢ÆWBW'&÷"Ò&V6÷fW%÷VæF–æuö¦÷W&æÂ‡F×çF‚‚’’çVçw&öW'"‚“° ¢76W'B†f÷&ÖB‚'¶W'&÷#¢7Ò"’æ6öçF–ç2‚'F&vWB4„Ó#Sb"’“°¢76W'B†¦÷W&æÅ÷F‚‡F×çF‚‚’’æW†—7G2‚’“°¢76W'EöW€¢ÆöE÷&÷÷6Ç5÷&r‡F×çF‚‚’’çVçw&‚•³Òç7FGW2À¢&÷÷6Å7FGW3£¥fW&–f–VD&÷fV@¢“°¢76W'EöW‡7FC£¦g3£§&VE÷Fõ÷7G&–ær‡6¶–ÆÅ÷F‚’çVçw&‚’ÂF×W&VB“°¢76W'B†ÆöEöÆVFvW%÷&r‡F×çF‚‚’’çVçw&‚’æ—5öV×G’‚’“°¢Ğ ¢5·FW7EĞ¢fâ#•ö–æ¦V7FVE÷6fUöf–ÇW&U÷&WGW&ç5öW'"‚’°¢òòÖ¶R&÷÷6Ç5÷F‚D•$T5Dõ%’6òFöÖ–5÷w&—FRFò—Bf–Ç2à¢ÆWBF×Ò7FC£¦Vçc£§FV×öF—"‚’æ¦ö–â†f÷&ÖB‚&æV÷F…ö#•÷6fVf–Å÷·Ò"Â7FC£§&ö6W73£¦–B‚’’“°¢ÆWBòÒ7FC£¦g3£¦7&VFUöF—%öÆÂ‚gF×“°¢ÆWBÒ&÷÷6Ç5÷F‚‚gF×“°¢7FC£¦g3£¦7&VFUöF—%öÆÂ‚g’çVçw&‚“²òò&÷÷6Ç2æ§6öâ—2æ÷rF— ¢ÆWB&W7VÇBÒWFFU÷&÷÷6Ç3££Â‚“â‚gF×ÂÅ÷Âö²‚‚’’“°¢76W'B‡&W7VÇBæ—5öW'"‚’Â'6fRf–ÇW&R×W7B&÷vFR2W'""“°¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöF—%öÆÂ‚gF×“°¢Ğ ¢5·FW7EĞ¢fâ#•ö66WE÷&÷÷6Åö¦÷W&æÅöFVÆWFVEööå÷7V66W72‚’°¢ÆWBF×Ò7FC£¦Vçc£§FV×öF—"‚’æ¦ö–â†f÷&ÖB‚&æV÷F…ö#•ö§ö6ÆVå÷·Ò"Â7FC£§&ö6W73£¦–B‚’’“°¢ÆWBòÒ7FC£¦g3£¦7&VFUöF—%öÆÂ‚gF×“° ¢ÆWB6¶–ÆÅ÷F‚ÒF×æ¦ö–â‚'6¶–ÆÂæÖB"“°¢7FC£¦g3£§w&—FR‚g6¶–ÆÅ÷F‚Â&&Vf÷&R"’çVçw&‚“° ¢ÆWB&÷Ò&÷÷6Â°¢–C¢&§"çFõ÷7G&–ær‚’À¢6¶–ÆÃ¢'FW7B"çFõ÷7G&–ær‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢&Vf÷&S¢&&Vf÷&R"çFõ÷7G&–ær‚’À¢gFW#¢&gFW""çFõ÷7G&–ær‚’À¢7VÖÖ'“¢""çFõ÷7G&–ær‚’À¢7FGW3¢&÷÷6Å7FGW3£¥fW&–f–VD&÷fVBÀ¢E÷Væ—ƒ¢À¢&6·W¢æöæRÀ¢66÷&Uö&Vf÷&S¢ãÀ¢66÷&UögFW#¢ãÀ¢†VÆF÷WEöWfÅ÷7VÖÖ'“¢""çFõ÷7G&–ær‚’À¢v‡•÷F†—5ö–×&÷fW3¢""çFõ÷7G&–ær‚’À¢&—6µöæ÷FW3¢""çFõ÷7G&–ær‚’À¢7V3¢æöæRÀ¢Ó°¢6fU÷&÷÷6Ç2‚gF×Âe·&÷Ò’çVçw&‚“° ¢66WE÷&÷÷6Â‚gF×Â&§"’çVçw&‚“° ¢76W'B€¢¦÷W&æÅ÷F‚‚gF×’æW†—7G2‚’À¢&¦÷W&æÂ×W7B&R&VÖ÷fVBgFW"7V66W76gVÂ66WB ¢“°¢76W'EöW‡7FC£¦g3£§&VE÷Fõ÷7G&–ær‚g6¶–ÆÅ÷F‚’çVçw&‚’Â&gFW""“°¢ÆWBÆÂÒÆöE÷&÷÷6Ç2‚gF×’çVçw&‚“°¢ÆWBÒÆÂæ—FW"‚’æf–æB‡ÇÂæ–BÓÒ&§"’çVçw&‚“°¢76W'EöW‡ç7FGW2Â&÷÷6Å7FGW3£¤66WFVB“°¢76W'EöW‡æ&6·Wæ5öFW&Vb‚’Â6öÖR‚&&Vf÷&R"’“°¢ÆWBÆVFvW"ÒÆöEöÆVFvW"‚gF×’çVçw&‚“°¢ÆWB&V6÷&BÒÆVFvW ¢æ—FW"‚¢æf–æB‡Ç&V6÷&GÂ&V6÷&Bç&÷÷6Åö–Bæ5öFW&Vb‚’ÓÒ6öÖR‚&§"’¢æW‡V7B‚&66WB×W7B7&VFRF†R&÷÷6ÂÖ&÷VæBÆVFvW"&V6÷&B"“°¢76W'B‡&V6÷&Bæ66WFVB“°¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöF—%öÆÂ‚gF×“°¢Ğ ¢5·FW7EĞ¢fâ#•÷&öÆÆ&6µ÷&÷÷6Åö¦÷W&æÅöFVÆWFVEööå÷7V66W72‚’°¢ÆWBF×Ò7FC£¦Vçc£§FV×öF—"‚’æ¦ö–â†f÷&ÖB‚&æV÷F…ö#•÷&%ö§÷·Ò"Â7FC£§&ö6W73£¦–B‚’’“°¢ÆWBòÒ7FC£¦g3£¦7&VFUöF—%öÆÂ‚gF×“° ¢ÆWB6¶–ÆÅ÷F‚ÒF×æ¦ö–â‚'6¶–ÆÂæÖB"“°¢7FC£¦g3£§w&—FR‚g6¶–ÆÅ÷F‚Â&gFW""’çVçw&‚“° ¢ÆWB&÷Ò&÷÷6Â°¢–C¢'&#"çFõ÷7G&–ær‚’À¢6¶–ÆÃ¢'FW7B"çFõ÷7G&–ær‚’À¢6¶–ÆÅ÷Fƒ¢6¶–ÆÅ÷F‚æF—7Æ’‚’çFõ÷7G&–ær‚’À¢&Vf÷&S¢&&Vf÷&R"çFõ÷7G&–ær‚’À¢gFW#¢&gFW""çFõ÷7G&–ær‚’À¢7VÖÖ'“¢""çFõ÷7G&–ær‚’À¢7FGW3¢&÷÷6Å7FGW3£¤66WFVBÀ¢E÷Væ—ƒ¢À¢&6·W¢6öÖR‚&&Vf÷&R"çFõ÷7G&–ær‚’’À¢66÷&Uö&Vf÷&S¢ãÀ¢66÷&UögFW#¢ãÀ¢†VÆF÷WEöWfÅ÷7VÖÖ'“¢""çFõ÷7G&–ær‚’À¢v‡•÷F†—5ö–×&÷fW3¢""çFõ÷7G&–ær‚’À¢&—6µöæ÷FW3¢""çFõ÷7G&–ær‚’À¢7V3¢æöæRÀ¢Ó°¢6fU÷&÷÷6Ç2‚gF×Âe·&÷Ò’çVçw&‚“° ¢&öÆÆ&6µ÷&÷÷6Â‚gF×Â'&#"’çVçw&‚“° ¢76W'B€¢¦÷W&æÅ÷F‚‚gF×’æW†—7G2‚’À¢&¦÷W&æÂ×W7B&R&VÖ÷fVBgFW"7V66W76gVÂ&öÆÆ&6² ¢“°¢76W'EöW‡7FC£¦g3£§&VE÷Fõ÷7G&–ær‚g6¶–ÆÅ÷F‚’çVçw&‚’Â&&Vf÷&R"“°¢ÆWBÆÂÒÆöE÷&÷÷6Ç2‚gF×’çVçw&‚“°¢ÆWBÒÆÂæ—FW"‚’æf–æB‡ÇÂæ–BÓÒ'&#"’çVçw&‚“°¢76W'EöW‡ç7FGW2Â&÷÷6Å7FGW3£¥&öÆÆVD&6²“°¢ÆWBÆVFvW"ÒÆöEöÆVFvW"‚gF×’çVçw&‚“°¢ÆWB&V6÷&BÒÆVFvW ¢æ—FW"‚¢æf–æB‡Ç&V6÷&GÂ&V6÷&Bç&÷÷6Åö–Bæ5öFW&Vb‚’ÓÒ6öÖR‚'&#"’¢æW‡V7B‚'&öÆÆ&6²×W7B7&VFR÷"WFFRF†R&÷VæBÆVFvW"&V6÷&B"“°¢76W'B‚&V6÷&Bæ66WFVB“°¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöF—%öÆÂ‚gF×“°¢Ğ ¢5·FW7EĞ¢fâ#•öæ–v‡FÇ•öW'&÷'5ööåö6÷''WEö6öæf–r‚’°¢ÆWBF×Ò7FC£¦Vçc£§FV×öF—"‚’æ¦ö–â†f÷&ÖB‚&æV÷F…ö#•ö6fuöf–Å÷·Ò"Â7FC£§&ö6W73£¦–B‚’’“°¢ÆWBòÒ7FC£¦g3£¦7&VFUöF—%öÆÂ‚gF×“°¢7FC£¦g3£§w&—FR…6VÆd–×&÷fT6öæf–s£§F‚‚gF×’Â"#¢¢¢æ÷B–ÖÂ"’çVçw&‚“° ¢ÆWB÷WF6öÖRÒ'Våöæ–v‡FÇ•÷v—F…öVæv–æR€¢gF×À¢'FW7B"À¢"÷F×÷6¶–ÆÂæÖB"À¢7&FS£§W&Ö—76–öç3£¤WFöæö×”ÆWfVÃ£¥7FæF&BÀ¢ÅòÂ÷Âæ–2‚&Væv–æR×W7Bæ÷B'Vâv†Vâ6öæf–r—26÷''WB"’À¢“°¢76W'B€¢ÖF6†W2†÷WF6öÖRÂæ–v‡FÇ”÷WF6öÖS£¤W'&÷"²ââÒ’À¢&6÷''WB6öæf–r×W7B––VÆBæ–v‡FÇ”÷WF6öÖS£¤W'&÷"Âv÷B¶÷WF6öÖS£÷Ò ¢“°¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöF—%öÆÂ‚gF×“°¢Ğ§Ğ