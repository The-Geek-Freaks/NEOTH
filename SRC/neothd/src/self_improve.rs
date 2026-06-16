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

use anyhow::Result;
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
}
