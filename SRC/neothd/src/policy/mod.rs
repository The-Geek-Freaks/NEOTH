//! `~/.neoth/policy.yaml` reader — Phase 28b AU-6.
//!
//! The policy file enumerates operator-flagged targets and patterns that
//! `permissions::evaluate` treats as `DangerousTarget`. The file is
//! intentionally tiny and append-only from the operator's perspective:
//! adding a host to `dangerous_targets` means "always confirm even at
//! autonomy=full, deny outright at autonomy ≤ elevated".
//!
//! ## Schema
//!
//! ```yaml
//! # ~/.neoth/policy.yaml
//! dangerous_targets:
//!   - "100.68.210.50"          # Cube — no remote reboot
//!   - "192.168.178.117"        # Jarvis VM
//! dangerous_patterns:
//!   - "rm -rf"
//!   - "fuser -km"
//!   - "kill -9"
//! ```
//!
//! Missing file → empty config (no targets, no patterns). Bad YAML →
//! caller-visible error so misconfig fails loud at startup.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::FreedomConfig;

/// Top-level shape of policy.yaml.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Hostnames / IPs / fully-qualified targets the operator flagged as
    /// dangerous. Matched as case-insensitive exact string equality.
    pub dangerous_targets: Vec<String>,
    /// Substring patterns that mark a shell command dangerous. Matched as
    /// case-sensitive substring (not glob, not regex — operator readability
    /// trumps cleverness; regex landing later if a real need shows up).
    pub dangerous_patterns: Vec<String>,
    /// HO-06 (Session 28) — file paths the startup credential-pattern
    /// scanner walks looking for `ghp_` / `sk-` / `AKIA` / Bearer
    /// shapes. Each path can be a file OR a directory; directories
    /// are walked one level deep (operator who wants recursion lists
    /// the subdir explicitly — keeps the scan O(visible-files) at
    /// daemon boot). Empty default → the scanner is a no-op until
    /// the operator opts in.
    ///
    /// Typical contents: `~/.bashrc` / `~/.zshrc` / `~/.config/git/config` /
    /// project-specific `.env` paths.
    #[serde(default)]
    pub startup_audit_scan_paths: Vec<PathBuf>,
    /// HO-06 (Session 28) — when true, the credential scanner also
    /// checks every git remote URL in the current process's working
    /// directory for inline `https://user:token@host/...` patterns.
    /// Useful for catching the classic mistake where a token leaks
    /// into a remote URL via copy/paste from a setup tutorial.
    /// Default false (opt-in) so a fresh install doesn't shell out
    /// to git on every boot.
    #[serde(default)]
    pub forbid_inline_tokens_in_remotes: bool,
}

impl PolicyConfig {
    /// `~/.neoth/policy.yaml`.
    pub fn default_path() -> PathBuf {
        FreedomConfig::default_neoth_home().join("policy.yaml")
    }

    /// Load the policy. Missing file → `PolicyConfig::default()`. YAML
    /// parse error propagates so the operator sees the line/column.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read policy at {}", path.display()))?;
        let cfg: Self = serde_yaml::from_str(&body)
            .with_context(|| format!("parse policy YAML at {}", path.display()))?;
        Ok(cfg)
    }

    /// Convenience: load from the default `~/.neoth/policy.yaml` path.
    pub fn load() -> Result<Self> {
        Self::load_or_default(&Self::default_path())
    }

    /// Does `target` match any flagged dangerous target?
    /// Case-insensitive exact match.
    pub fn target_is_dangerous(&self, target: &str) -> bool {
        let needle = target.to_ascii_lowercase();
        self.dangerous_targets
            .iter()
            .any(|t| t.to_ascii_lowercase() == needle)
    }

    /// Does `command` contain any flagged dangerous pattern? Case-sensitive
    /// substring; `rm -rf` matches `rm -rf /tmp` but not `RM -RF`.
    pub fn command_is_dangerous(&self, command: &str) -> bool {
        self.dangerous_patterns.iter().any(|p| command.contains(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_file_returns_default() {
        let dir = tempdir().unwrap();
        let cfg = PolicyConfig::load_or_default(&dir.path().join("nope.yaml")).unwrap();
        assert!(cfg.dangerous_targets.is_empty());
        assert!(cfg.dangerous_patterns.is_empty());
    }

    #[test]
    fn parses_full_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            "dangerous_targets:\n  - 100.68.210.50\n  - jarvis.local\n\
             dangerous_patterns:\n  - 'rm -rf'\n  - 'kill -9'\n",
        )
        .unwrap();
        let cfg = PolicyConfig::load_or_default(&path).unwrap();
        assert_eq!(cfg.dangerous_targets.len(), 2);
        assert!(cfg.target_is_dangerous("100.68.210.50"));
        assert!(cfg.target_is_dangerous("JARVIS.LOCAL"));
        assert!(!cfg.target_is_dangerous("unrelated"));
        assert!(cfg.command_is_dangerous("sudo rm -rf /var/log"));
        assert!(cfg.command_is_dangerous("kill -9 1234"));
        assert!(!cfg.command_is_dangerous("ls -la"));
    }

    #[test]
    fn partial_yaml_uses_defaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "dangerous_targets:\n  - cube\n").unwrap();
        let cfg = PolicyConfig::load_or_default(&path).unwrap();
        assert_eq!(cfg.dangerous_targets, vec!["cube".to_string()]);
        assert!(cfg.dangerous_patterns.is_empty());
    }

    #[test]
    fn bad_yaml_returns_error_not_silent_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "not: [valid: yaml").unwrap();
        let r = PolicyConfig::load_or_default(&path);
        assert!(r.is_err(), "bad YAML must error, not silently default");
    }
}
