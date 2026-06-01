//! R-04 (Session 24) — wizard checkpoint persistence.
//!
//! Saves [`WizardState`] minus all secret fields to
//! `~/.neoth/wizard_checkpoint.json` after every step so a crash, kill,
//! reboot, or accidental Ctrl+C between step 1 and step 9 doesn't force
//! the operator to redo their answers. On the next `neoth init` invocation
//! the wizard offers `Resume from your previous wizard run? [Y/n]` when a
//! checkpoint is present.
//!
//! ## Why not just include secrets
//!
//! `provider_key`, `telegram_token`, `keet_seed_phrase`, and
//! `pears_bearer_token` are all wrapped in [`crate::secret::SecretString`]
//! with `mlock` + `zeroize` for in-memory protection. Persisting them to
//! `wizard_checkpoint.json` would defeat that — even with mode 0600 the
//! file lives on disk in plaintext until the wizard completes. Operators
//! re-enter credentials on resume; the rest of the state (operator id,
//! language, autonomy level, hemisphere topology, plugin activations,
//! vault path, etc.) round-trips losslessly.
//!
//! ## On-disk shape
//!
//! `~/.neoth/wizard_checkpoint.json` with mode 0600 (unix) / restricted
//! DACL (windows via `credentials::write_mode_0600`). Atomic write via
//! `.json.tmp` + rename so the wizard-on-startup reader can never observe
//! a partial write.
//!
//! ## Lifecycle
//!
//! 1. `neoth init` boots → [`load_checkpoint`] checks the file.
//! 2. If present + operator confirms resume → [`apply_to`] hydrates
//!    `WizardState`. If operator declines → [`clear_checkpoint`].
//! 3. After every step body returns Ok → [`save_checkpoint`] overwrites
//!    the file (atomic rename keeps the read side safe).
//! 4. After the final `write_initialized_marker` → [`clear_checkpoint`]
//!    removes the file. The `.initialized` marker now owns "wizard ran
//!    successfully" semantics.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::init::{OperatorRole, ProviderKind, WizardState};

/// Filename under `~/.neoth/` where the partial wizard state lives.
pub const CHECKPOINT_FILENAME: &str = "wizard_checkpoint.json";

/// Absolute path to the checkpoint file for the given neoth home dir.
pub fn checkpoint_path(neoth_dir: &Path) -> PathBuf {
    neoth_dir.join(CHECKPOINT_FILENAME)
}

/// Persisted, secret-free snapshot of [`WizardState`]. Mirrors the
/// non-`#[serde(skip)]` non-`SecretString` fields of `WizardState`. New
/// fields land here when the wizard adds a new non-secret step.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WizardCheckpoint {
    pub operator_id: Option<String>,
    pub language_primary: Option<String>,
    pub language_code: Option<String>,
    pub role: Option<OperatorRole>,
    pub role_custom: Option<String>,
    pub provider_kind: Option<ProviderKind>,
    pub provider_binary: Option<String>,
    pub provider_endpoint: Option<String>,
    pub provider_model: Option<String>,
    pub telegram_user_id: Option<u64>,
    pub autonomy: crate::permissions::AutonomyLevel,
    pub inference: crate::config::inference::InferenceTopology,
    pub auto_update: crate::config::AutoUpdateConfig,
    pub plugins: crate::config::PluginsConfig,
    pub download_qwen_weights: bool,
    pub install_obsidian: bool,
    pub bootstrap_vault: bool,
    pub vault_path: Option<PathBuf>,
    pub install_n8n: bool,
    pub import_jarvis: Option<PathBuf>,
    pub steps_completed: Vec<u8>,
    /// Unix-seconds wall clock at the most recent `save_checkpoint`.
    /// Surfaced in the resume prompt so the operator sees "your previous
    /// wizard from 2 hours ago" instead of an opaque file age.
    pub checkpoint_written_at_unix: i64,
}

impl WizardCheckpoint {
    /// Capture the non-secret fields of `state`. Secrets remain in
    /// `state` itself (in mlocked SecretString) but never reach disk.
    pub fn from_state(state: &WizardState) -> Self {
        Self {
            operator_id: state.operator_id.clone(),
            language_primary: state.language_primary.clone(),
            language_code: state.language_code.clone(),
            role: state.role,
            role_custom: state.role_custom.clone(),
            provider_kind: state.provider_kind,
            provider_binary: state.provider_binary.clone(),
            provider_endpoint: state.provider_endpoint.clone(),
            provider_model: state.provider_model.clone(),
            telegram_user_id: state.telegram_user_id,
            autonomy: state.autonomy,
            inference: state.inference.clone(),
            auto_update: state.auto_update.clone(),
            plugins: state.plugins.clone(),
            download_qwen_weights: state.download_qwen_weights,
            install_obsidian: state.install_obsidian,
            bootstrap_vault: state.bootstrap_vault,
            vault_path: state.vault_path.clone(),
            install_n8n: state.install_n8n,
            import_jarvis: state.import_jarvis.clone(),
            steps_completed: state.steps_completed.clone(),
            checkpoint_written_at_unix: now_unix(),
        }
    }

    /// Hydrate `state` from this checkpoint. Secrets fields on `state`
    /// remain `None` so the resume flow re-prompts for them.
    pub fn apply_to(self, state: &mut WizardState) {
        state.operator_id = self.operator_id;
        state.language_primary = self.language_primary;
        state.language_code = self.language_code;
        state.role = self.role;
        state.role_custom = self.role_custom;
        state.provider_kind = self.provider_kind;
        state.provider_binary = self.provider_binary;
        state.provider_endpoint = self.provider_endpoint;
        state.provider_model = self.provider_model;
        state.telegram_user_id = self.telegram_user_id;
        state.autonomy = self.autonomy;
        state.inference = self.inference;
        state.auto_update = self.auto_update;
        state.plugins = self.plugins;
        state.download_qwen_weights = self.download_qwen_weights;
        state.install_obsidian = self.install_obsidian;
        state.bootstrap_vault = self.bootstrap_vault;
        state.vault_path = self.vault_path;
        state.install_n8n = self.install_n8n;
        state.import_jarvis = self.import_jarvis;
        state.steps_completed = self.steps_completed;
    }
}

/// Atomic, mode-0600 write of the secret-free snapshot to disk. Same
/// `.json.tmp` + rename dance the rest of the credentials surface uses
/// so a concurrent reader can never observe a partial file.
pub fn save_checkpoint(neoth_dir: &Path, state: &WizardState) -> Result<()> {
    std::fs::create_dir_all(neoth_dir).with_context(|| {
        format!(
            "create neoth dir for wizard checkpoint: {}",
            neoth_dir.display(),
        )
    })?;
    let path = checkpoint_path(neoth_dir);
    let checkpoint = WizardCheckpoint::from_state(state);
    let bytes = serde_json::to_vec_pretty(&checkpoint).context("serialise wizard checkpoint")?;
    let tmp = path.with_extension("json.tmp");
    crate::config::credentials::write_mode_0600(&tmp, &bytes)
        .with_context(|| format!("write tmp checkpoint {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read the checkpoint file, if any. Returns `Ok(None)` for the common
/// "no file present" fresh-install case; reserves `Err` for real IO /
/// parse failures so the wizard can decide whether to abort or proceed.
pub fn load_checkpoint(neoth_dir: &Path) -> Result<Option<WizardCheckpoint>> {
    let path = checkpoint_path(neoth_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if bytes.is_empty() {
        // Atomic-rename window edge case: file present but zero-length.
        // Treat as "no checkpoint" rather than failing the boot.
        return Ok(None);
    }
    let parsed: WizardCheckpoint =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(parsed))
}

/// Remove the checkpoint file. No-op when absent. Used after a successful
/// `.initialized` marker write (the wizard finished) AND when an operator
/// declines the resume prompt (so the next boot starts clean).
pub fn clear_checkpoint(neoth_dir: &Path) -> Result<()> {
    let path = checkpoint_path(neoth_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_returns_none_when_file_missing() {
        let dir = tempdir().unwrap();
        let out = load_checkpoint(dir.path()).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn save_then_load_round_trips_non_secret_fields() {
        let dir = tempdir().unwrap();
        let mut state = WizardState::default();
        state.operator_id = Some("sam".into());
        state.language_primary = Some("German".into());
        state.language_code = Some("de".into());
        state.role = Some(OperatorRole::SecurityResearcher);
        state.steps_completed = vec![1, 2, 3];
        state.download_qwen_weights = true;
        state.install_n8n = true;

        save_checkpoint(dir.path(), &state).expect("save");
        let loaded = load_checkpoint(dir.path()).unwrap().expect("Some");
        assert_eq!(loaded.operator_id.as_deref(), Some("sam"));
        assert_eq!(loaded.language_primary.as_deref(), Some("German"));
        assert_eq!(loaded.language_code.as_deref(), Some("de"));
        assert_eq!(loaded.role, Some(OperatorRole::SecurityResearcher));
        assert_eq!(loaded.steps_completed, vec![1, 2, 3]);
        assert!(loaded.download_qwen_weights);
        assert!(loaded.install_n8n);
        assert!(loaded.checkpoint_written_at_unix > 0);
    }

    #[test]
    fn save_strips_provider_key_and_telegram_token() {
        // Pin the privacy contract: a SecretString in WizardState must
        // not show up in the on-disk JSON. Catches accidental
        // serde-skip-bypass via a future field rename.
        let dir = tempdir().unwrap();
        let mut state = WizardState::default();
        state.operator_id = Some("sam".into());
        state.provider_key = Some(crate::secret::SecretString::new(
            "PROVIDER-SECRET-DEADBEEF".into(),
        ));
        state.telegram_token = Some(crate::secret::SecretString::new(
            "TELEGRAM-TOKEN-BADBADBAD".into(),
        ));

        save_checkpoint(dir.path(), &state).expect("save");
        let raw = std::fs::read_to_string(checkpoint_path(dir.path())).unwrap();
        assert!(
            !raw.contains("PROVIDER-SECRET-DEADBEEF"),
            "provider_key must not reach disk: {raw}",
        );
        assert!(
            !raw.contains("TELEGRAM-TOKEN-BADBADBAD"),
            "telegram_token must not reach disk: {raw}",
        );
    }

    #[test]
    fn apply_to_hydrates_state_without_touching_secrets() {
        let dir = tempdir().unwrap();
        let mut original = WizardState::default();
        original.operator_id = Some("sam".into());
        original.language_code = Some("de".into());
        original.steps_completed = vec![1, 2, 3, 4, 5];
        original.bootstrap_vault = true;
        save_checkpoint(dir.path(), &original).expect("save");

        // Build a fresh state with a secret that must survive.
        let mut restored = WizardState::default();
        restored.provider_key = Some(crate::secret::SecretString::new("KEEP-IN-MEMORY".into()));

        let loaded = load_checkpoint(dir.path()).unwrap().expect("Some");
        loaded.apply_to(&mut restored);

        assert_eq!(restored.operator_id.as_deref(), Some("sam"));
        assert_eq!(restored.language_code.as_deref(), Some("de"));
        assert_eq!(restored.steps_completed, vec![1, 2, 3, 4, 5]);
        assert!(restored.bootstrap_vault);
        // Secret in fresh state must NOT be cleared by apply_to.
        assert!(
            restored.provider_key.is_some(),
            "apply_to must leave secret fields on the target alone",
        );
    }

    #[test]
    fn clear_checkpoint_removes_file() {
        let dir = tempdir().unwrap();
        let state = WizardState::default();
        save_checkpoint(dir.path(), &state).expect("save");
        assert!(checkpoint_path(dir.path()).exists());
        clear_checkpoint(dir.path()).expect("clear");
        assert!(!checkpoint_path(dir.path()).exists());
    }

    #[test]
    fn clear_checkpoint_is_idempotent_when_file_absent() {
        let dir = tempdir().unwrap();
        // No save first — clear must still succeed.
        clear_checkpoint(dir.path()).expect("clear on absent file");
    }

    #[test]
    fn load_returns_none_for_zero_length_file() {
        // Atomic-rename race window: file exists but is empty. The
        // wizard treats it as "no checkpoint" instead of erroring out.
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(checkpoint_path(dir.path()), b"").unwrap();
        let out = load_checkpoint(dir.path()).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn load_propagates_parse_error_for_corrupt_json() {
        let dir = tempdir().unwrap();
        std::fs::write(checkpoint_path(dir.path()), b"{ not real json }").unwrap();
        let r = load_checkpoint(dir.path());
        assert!(r.is_err(), "garbage JSON must Err (operator decides)");
    }

    #[test]
    fn save_is_atomic_against_partial_reader() {
        // We can't truly test atomicity without threads, but we can
        // verify the temp file is gone after save and only the final
        // path exists. Any future regression that drops the rename in
        // favour of `write(path)` would leave the .tmp behind.
        let dir = tempdir().unwrap();
        let state = WizardState::default();
        save_checkpoint(dir.path(), &state).expect("save");
        let tmp = checkpoint_path(dir.path()).with_extension("json.tmp");
        assert!(!tmp.exists(), "tmp file must be renamed away");
        assert!(checkpoint_path(dir.path()).exists());
    }
}
