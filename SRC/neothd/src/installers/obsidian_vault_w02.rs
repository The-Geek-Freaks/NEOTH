//! W-02 — obsidian_vault extensions.
//!
//! The base [`super::obsidian_vault`] module ships the default
//! vault path + bootstrap-plugin list. W-02 adds:
//!
//!   - [`VaultProbeOutcome`] — is the path a real Obsidian vault?
//!     (looks for `.obsidian/`, or `app.json`, or an empty dir).
//!   - [`probe_vault`] — pure-fn classifier from a path; tests
//!     against in-memory tempdirs (no Obsidian install needed).
//!   - [`SubfolderSpec`] — pinned list of the subdirs NEOTH writes
//!     under the operator's vault (Paperless / Proposals /
//!     EmailDrafts / Dreams / Reflections). The wizard pre-creates
//!     them after the install step so the operator's first
//!     `neoth paperless ingest` doesn't write into a non-existent
//!     dir.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Outcome of a vault probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultProbeOutcome {
    /// Path is an existing Obsidian vault (has `.obsidian/`
    /// directory).
    ExistingVault,
    /// Path exists + is a directory but doesn't look like a vault
    /// yet. Wizard offers to initialise it.
    EmptyOrPlainDirectory,
    /// Path doesn't exist on disk. Wizard offers to create it.
    Missing,
    /// Path exists but isn't a directory (a file). Operator must
    /// pick a different path.
    NotADirectory,
}

impl VaultProbeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExistingVault => "existing_vault",
            Self::EmptyOrPlainDirectory => "empty_or_plain_directory",
            Self::Missing => "missing",
            Self::NotADirectory => "not_a_directory",
        }
    }

    /// True when the wizard can write into this path immediately
    /// — both `ExistingVault` (operator-owned, OK) and
    /// `EmptyOrPlainDirectory` (about to be created as a vault)
    /// qualify.
    pub fn is_writable_target(&self) -> bool {
        matches!(self, Self::ExistingVault | Self::EmptyOrPlainDirectory)
    }
}

/// Classify a vault path. Pure-fn over filesystem state — no
/// network, no subprocess.
pub fn probe_vault(path: &Path) -> VaultProbeOutcome {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return VaultProbeOutcome::Missing,
    };
    if !meta.is_dir() {
        return VaultProbeOutcome::NotADirectory;
    }
    if path.join(".obsidian").is_dir() {
        return VaultProbeOutcome::ExistingVault;
    }
    VaultProbeOutcome::EmptyOrPlainDirectory
}

/// One subfolder NEOTH wants the operator's vault to carry.
/// Pinned exhaustively so a new module's vault writes go through
/// the wizard's pre-create pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubfolderSpec {
    /// PL-02 paperless OCR note destinations.
    Paperless,
    /// OB-03 proposal staging vault export.
    Proposals,
    /// EM-04 email-draft vault export.
    EmailDrafts,
    /// OB-01 daily dream compilations.
    Dreams,
    /// OB-02 weekly reflection notes.
    Reflections,
}

impl SubfolderSpec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Paperless => "paperless",
            Self::Proposals => "proposals",
            Self::EmailDrafts => "email_drafts",
            Self::Dreams => "dreams",
            Self::Reflections => "reflections",
        }
    }

    /// Folder name written under `<vault>/<subdir>/`. Matches the
    /// PascalCase shipped folder layout that the
    /// `paperless::sync_ocr_to_obsidian`,
    /// `proactive::action_staging::sync_proposals_to_obsidian` +
    /// peers write into.
    pub fn folder_name(self) -> &'static str {
        match self {
            Self::Paperless => "Paperless",
            Self::Proposals => "Proposals",
            Self::EmailDrafts => "EmailDrafts",
            Self::Dreams => "Dreams",
            Self::Reflections => "Reflections",
        }
    }
}

/// The full list of subfolders the wizard pre-creates under the
/// vault. Adding a new module that writes into the vault needs to
/// extend this list + the matching variant.
pub const NEOTH_VAULT_SUBFOLDERS: &[SubfolderSpec] = &[
    SubfolderSpec::Paperless,
    SubfolderSpec::Proposals,
    SubfolderSpec::EmailDrafts,
    SubfolderSpec::Dreams,
    SubfolderSpec::Reflections,
];

/// Pre-create every subfolder under `<vault>/<subdir>`. Idempotent
/// — existing dirs are left alone. Surfaces I/O errors so a RO
/// volume fails loudly.
pub fn ensure_subfolders(vault_root: &Path, subdir: &str) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut created = Vec::with_capacity(NEOTH_VAULT_SUBFOLDERS.len());
    for spec in NEOTH_VAULT_SUBFOLDERS {
        let p = vault_root.join(subdir).join(spec.folder_name());
        std::fs::create_dir_all(&p)?;
        created.push(p);
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_as_str_pinned() {
        assert_eq!(VaultProbeOutcome::ExistingVault.as_str(), "existing_vault");
        assert_eq!(
            VaultProbeOutcome::EmptyOrPlainDirectory.as_str(),
            "empty_or_plain_directory",
        );
        assert_eq!(VaultProbeOutcome::Missing.as_str(), "missing");
        assert_eq!(VaultProbeOutcome::NotADirectory.as_str(), "not_a_directory");
    }

    #[test]
    fn outcome_is_writable_target_correct() {
        assert!(VaultProbeOutcome::ExistingVault.is_writable_target());
        assert!(VaultProbeOutcome::EmptyOrPlainDirectory.is_writable_target());
        assert!(!VaultProbeOutcome::Missing.is_writable_target());
        assert!(!VaultProbeOutcome::NotADirectory.is_writable_target());
    }

    #[test]
    fn probe_missing_returns_missing() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("no-such-thing");
        assert_eq!(probe_vault(&bogus), VaultProbeOutcome::Missing);
    }

    #[test]
    fn probe_file_returns_not_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-file.txt");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(probe_vault(&file), VaultProbeOutcome::NotADirectory);
    }

    #[test]
    fn probe_empty_directory_returns_empty_or_plain() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            probe_vault(dir.path()),
            VaultProbeOutcome::EmptyOrPlainDirectory,
        );
    }

    #[test]
    fn probe_directory_with_obsidian_subdir_returns_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".obsidian")).unwrap();
        assert_eq!(probe_vault(dir.path()), VaultProbeOutcome::ExistingVault);
    }

    #[test]
    fn probe_directory_with_obsidian_as_file_does_not_match_vault() {
        // Operator parked an `.obsidian` FILE (rare; sanity-check
        // the `.is_dir()` discriminator).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".obsidian"), b"oops").unwrap();
        assert_eq!(
            probe_vault(dir.path()),
            VaultProbeOutcome::EmptyOrPlainDirectory,
        );
    }

    // ── subfolder spec ────────────────────────────────────────────

    #[test]
    fn subfolder_as_str_pinned() {
        assert_eq!(SubfolderSpec::Paperless.as_str(), "paperless");
        assert_eq!(SubfolderSpec::Proposals.as_str(), "proposals");
        assert_eq!(SubfolderSpec::EmailDrafts.as_str(), "email_drafts");
        assert_eq!(SubfolderSpec::Dreams.as_str(), "dreams");
        assert_eq!(SubfolderSpec::Reflections.as_str(), "reflections");
    }

    /// Drift guard: folder_name MUST match the actual on-disk
    /// names the sync_* functions write into. If a future refactor
    /// renames `<vault>/<subdir>/Paperless/` to anything else,
    /// this test catches the wizard pre-create going stale.
    #[test]
    fn subfolder_names_match_runtime_writers() {
        assert_eq!(SubfolderSpec::Paperless.folder_name(), "Paperless");
        assert_eq!(SubfolderSpec::Proposals.folder_name(), "Proposals");
        assert_eq!(SubfolderSpec::EmailDrafts.folder_name(), "EmailDrafts");
        assert_eq!(SubfolderSpec::Dreams.folder_name(), "Dreams");
        assert_eq!(SubfolderSpec::Reflections.folder_name(), "Reflections");
    }

    #[test]
    fn neoth_vault_subfolders_list_pinned_at_five() {
        assert_eq!(NEOTH_VAULT_SUBFOLDERS.len(), 5);
    }

    #[test]
    fn ensure_subfolders_creates_each_under_vault_subdir() {
        let vault = tempfile::tempdir().unwrap();
        let created = ensure_subfolders(vault.path(), "NEOTH").unwrap();
        assert_eq!(created.len(), 5);
        for spec in NEOTH_VAULT_SUBFOLDERS {
            let p = vault.path().join("NEOTH").join(spec.folder_name());
            assert!(p.exists(), "missing {p:?}");
            assert!(p.is_dir(), "{p:?} should be a directory");
        }
    }

    #[test]
    fn ensure_subfolders_is_idempotent() {
        let vault = tempfile::tempdir().unwrap();
        ensure_subfolders(vault.path(), "NEOTH").unwrap();
        // Drop a file inside one of the subfolders + ensure
        // re-running doesn't wipe it.
        let marker = vault.path().join("NEOTH").join("Paperless").join("doc.md");
        std::fs::write(&marker, b"x").unwrap();
        ensure_subfolders(vault.path(), "NEOTH").unwrap();
        assert!(marker.exists(), "re-run wiped existing content");
    }

    #[test]
    fn ensure_subfolders_respects_subdir() {
        let vault = tempfile::tempdir().unwrap();
        ensure_subfolders(vault.path(), "CUSTOM").unwrap();
        assert!(vault.path().join("CUSTOM").join("Dreams").is_dir());
        assert!(!vault.path().join("NEOTH").exists());
    }

    #[test]
    fn outcome_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&VaultProbeOutcome::ExistingVault).unwrap(),
            "\"existing_vault\"",
        );
    }

    #[test]
    fn subfolder_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&SubfolderSpec::EmailDrafts).unwrap(),
            "\"email_drafts\"",
        );
    }
}
