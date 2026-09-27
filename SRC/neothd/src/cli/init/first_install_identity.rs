//! First-install AEAD identity provisioning for `neoth init`.
//!
//! The Archive Bridge needs a stable WAL master key even when first setup does
//! not yet write encrypted credentials or WAL segments.  Creation is confined
//! to a narrowly recognised, pre-config fresh-init state.  Existing homes stay
//! load-only so an absent recovery key is never silently replaced.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};

const CONFIG_FILE: &str = "freedom.yaml";
const CREDENTIALS_FILE: &str = "credentials.yaml";
const INITIALIZED_MARKER: &str = ".initialized";
const FIRST_TOUR_MARKER: &str = "first_tour_pending";
const WAL_DIR: &str = "wal";
const MASTER_KEY_FILE: &str = "master.key";
const GUI_PENDING_DIR: &str = ".gui-init";
const GUI_PENDING_FILE: &str = "pending.json";
const GUI_LOCK_FILE: &str = ".gui-init.lock";
const INTERFACE_PREFERENCE_FILE: &str = "interface.json";

/// A positive inspection result binds the entry-time identity state. Callers
/// cannot turn a retained key into a create permission by re-inspecting later.
#[derive(Debug)]
pub(crate) struct FirstInstallIdentityCandidate {
    identity: InitialIdentityState,
}

#[derive(Debug, PartialEq, Eq)]
enum InitialIdentityState {
    Fresh,
    Retained { fingerprint: [u8; 32] },
}

/// Inspect the init home without creating it. `None` means an existing or
/// ambiguous state, for which init continues with its existing behavior but
/// never provisions a new encryption identity.
pub(crate) fn inspect_before_init(home: &Path) -> Result<Option<FirstInstallIdentityCandidate>> {
    match fs::symlink_metadata(home) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(Some(FirstInstallIdentityCandidate {
                identity: InitialIdentityState::Fresh,
            }))
        }
        Err(error) => Err(error).with_context(|| format!("inspect NEOTH home {}", home.display())),
        Ok(metadata) => {
            if !is_real_directory(&metadata) {
                return Ok(None);
            }
            // Reconfiguration is an existing-home path, including `--force`.
            // Preserve it exactly and keep master-key creation out of it.
            match fs::symlink_metadata(home.join(CONFIG_FILE)) {
                Ok(_) => return Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("inspect existing configuration under {}", home.display())
                    });
                }
            }
            Ok(Some(FirstInstallIdentityCandidate {
                identity: inspect_recognised_fresh_home(home)?,
            }))
        }
    }
}

/// Provision after explicit license acceptance and before the first wizard
/// checkpoint/configuration write.  Dry-runs retain their no-write contract.
pub(crate) fn provision_after_license(
    home: &Path,
    candidate: Option<&FirstInstallIdentityCandidate>,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    let Some(candidate) = candidate else {
        return Ok(());
    };

    // Re-read all direct children just before the identity decision. This
    // catches both wizard residue outside the allowlist and concurrent changes.
    let observed = inspect_recognised_fresh_home_after_create_if_absent(home, candidate)?;
    if observed != candidate.identity {
        anyhow::bail!(
            "first-install WAL identity changed after initial inspection; refusing to create or replace {}",
            crate::wal::master_key::master_key_path(home).display()
        );
    }

    let key_path = crate::wal::master_key::master_key_path(home);
    match &candidate.identity {
        InitialIdentityState::Retained { fingerprint } => {
            // Retained identity is load-only forever for this invocation. A
            // disappearing, substituted, malformed, linked, or reparse key
            // is an error; it can never fall through into fresh creation.
            let key = crate::wal::master_key::load_existing_master_key_at(home)?;
            if master_key_fingerprint(key.expose()) != *fingerprint {
                anyhow::bail!(
                    "retained first-install WAL identity changed before provisioning: {}",
                    key_path.display()
                );
            }
        }
        InitialIdentityState::Fresh => create_fresh_master_key_nofollow(home, &key_path)?,
    }
    Ok(())
}

fn inspect_recognised_fresh_home_after_create_if_absent(
    home: &Path,
    candidate: &FirstInstallIdentityCandidate,
) -> Result<InitialIdentityState> {
    match fs::symlink_metadata(home) {
        Ok(_) => inspect_recognised_fresh_home(home),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && candidate.identity == InitialIdentityState::Fresh =>
        {
            // Creation itself happens only in `create_fresh_master_key_nofollow`,
            // through an explicit trusted anchor and bound parent handles.
            Ok(InitialIdentityState::Fresh)
        }
        Err(error) => {
            Err(error).with_context(|| format!("reinspect NEOTH home {}", home.display()))
        }
    }
}

fn inspect_recognised_fresh_home(home: &Path) -> Result<InitialIdentityState> {
    let metadata = fs::symlink_metadata(home)
        .with_context(|| format!("inspect NEOTH home {}", home.display()))?;
    if !is_real_directory(&metadata) {
        anyhow::bail!("NEOTH home must be a real directory: {}", home.display());
    }

    let mut identity = InitialIdentityState::Fresh;
    for entry in
        fs::read_dir(home).with_context(|| format!("list NEOTH home {}", home.display()))?
    {
        let entry =
            entry.with_context(|| format!("read NEOTH home entry in {}", home.display()))?;
        let name = entry.file_name();
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect NEOTH home entry {}", path.display()))?;

        match name.to_string_lossy().as_ref() {
            CONFIG_FILE | CREDENTIALS_FILE | INITIALIZED_MARKER | FIRST_TOUR_MARKER => {
                anyhow::bail!(
                    "existing NEOTH state at {} is not eligible for first-install identity provisioning",
                    path.display()
                );
            }
            crate::cli::wizard_checkpoint::CHECKPOINT_FILENAME
            | INTERFACE_PREFERENCE_FILE
            | GUI_LOCK_FILE => require_real_file(&path, &metadata)?,
            GUI_PENDING_DIR => inspect_gui_pending_dir(&path, &metadata)?,
            WAL_DIR => identity = inspect_retained_wal(home, &path, &metadata)?,
            _ => anyhow::bail!(
                "unrecognised NEOTH home residue blocks first-install identity provisioning: {}",
                path.display()
            ),
        }
    }
    Ok(identity)
}

fn inspect_gui_pending_dir(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    require_real_directory(path, metadata)?;
    let mut entries =
        fs::read_dir(path).with_context(|| format!("list GUI init residue {}", path.display()))?;
    let Some(entry) = entries.next() else {
        return Ok(());
    };
    let entry = entry.with_context(|| format!("read GUI init residue in {}", path.display()))?;
    if entry.file_name().as_os_str() != std::ffi::OsStr::new(GUI_PENDING_FILE)
        || entries.next().is_some()
    {
        anyhow::bail!("unrecognised GUI init residue at {}", path.display());
    }
    let pending = entry.path();
    require_real_file(
        &pending,
        &fs::symlink_metadata(&pending)
            .with_context(|| format!("inspect GUI init residue {}", pending.display()))?,
    )
}

fn inspect_retained_wal(
    home: &Path,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<InitialIdentityState> {
    require_real_directory(path, metadata)?;
    let mut entries = fs::read_dir(path)
        .with_context(|| format!("list retained WAL directory {}", path.display()))?;
    let Some(entry) = entries.next() else {
        anyhow::bail!(
            "retained WAL directory is missing its master key: {}",
            path.display()
        );
    };
    let entry = entry.with_context(|| format!("read retained WAL entry in {}", path.display()))?;
    if entry.file_name().as_os_str() != std::ffi::OsStr::new(MASTER_KEY_FILE)
        || entries.next().is_some()
    {
        anyhow::bail!(
            "retained WAL directory has unexpected state: {}",
            path.display()
        );
    }
    let key_path = entry.path();
    require_real_file(
        &key_path,
        &fs::symlink_metadata(&key_path)
            .with_context(|| format!("inspect retained master key {}", key_path.display()))?,
    )?;
    // This no-follow reader also rejects malformed/oversized/DPAPI-invalid keys.
    let key = crate::wal::master_key::load_existing_master_key_at(home)?;
    Ok(InitialIdentityState::Retained {
        fingerprint: master_key_fingerprint(key.expose()),
    })
}

fn create_fresh_master_key_nofollow(home: &Path, key_path: &Path) -> Result<()> {
    let home_dir = open_private_first_install_home(home)?;
    inspect_bound_fresh_home_before_wal_create(&home_dir)?;
    let wal = create_private_bound_wal_directory(&home_dir)?;
    inspect_bound_fresh_home_before_key_publish(&home_dir, &wal)?;
    let key = crate::wal::crypto::WalMasterKey::generate()?;
    let payload = crate::wal::compaction::encode_key_for_storage(key_path, key.expose())?;
    crate::skills::store::atomic_write_private_child_create_new(
        &wal,
        OsStr::new(MASTER_KEY_FILE),
        key_path,
        &payload,
    )
    .with_context(|| format!("create first-install WAL master key {}", key_path.display()))
}

fn open_private_first_install_home(home: &Path) -> Result<crate::skills::store::BoundDirectory> {
    let absolute_home = std::path::absolute(home)
        .with_context(|| format!("resolve first-install NEOTH home {}", home.display()))?;
    let trusted_parent = absolute_home.parent().with_context(|| {
        format!(
            "first-install NEOTH home needs an existing parent anchor: {}",
            absolute_home.display()
        )
    })?;
    let home_dir = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_parent,
        &absolute_home,
        true,
        "first-install NEOTH home",
    )?
    .context("open or create first-install NEOTH home")?;
    harden_private_bound_directory(&home_dir.dir, &home_dir.display_path)?;
    Ok(home_dir)
}

/// Final fresh-state check through the already-bound home capability. The
/// normal CLI pre-license path may have persisted only `interface.json`; every
/// other direct child means the absent-home candidate has drifted and cannot
/// authorize master-key creation.
fn inspect_bound_fresh_home_before_wal_create(
    home: &crate::skills::store::BoundDirectory,
) -> Result<()> {
    for entry in home.dir.entries().with_context(|| {
        format!(
            "list bound first-install home {}",
            home.display_path.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "read bound first-install home entry in {}",
                home.display_path.display()
            )
        })?;
        let name = entry.file_name();
        if !inspect_bound_init_transient(home, &name)? {
            anyhow::bail!(
                "first-install home changed after final fresh-state inspection: {}",
                home.display_path.join(&name).display()
            );
        }
    }
    Ok(())
}

fn create_private_bound_wal_directory(
    home: &crate::skills::store::BoundDirectory,
) -> Result<cap_std::fs::Dir> {
    let name = OsStr::new(WAL_DIR);
    let wal_path = home.display_path.join(name);
    match home.dir.open_dir_nofollow(name) {
        Ok(_) => anyhow::bail!(
            "WAL directory appeared after final fresh-state inspection: {}",
            wal_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("open WAL directory {}", wal_path.display()));
        }
    }
    #[cfg(unix)]
    let builder = {
        use cap_std::fs::DirBuilderExt as _;
        let mut builder = cap_std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = cap_std::fs::DirBuilder::new();
    match home.dir.create_dir_with(name, &builder) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "WAL directory appeared during first-install creation: {}",
                wal_path.display()
            );
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("create WAL directory {}", wal_path.display()));
        }
    }
    crate::skills::store::sync_parent_directory(&home.dir, &home.display_path).with_context(
        || {
            format!(
                "sync first-install home after creating {}",
                wal_path.display()
            )
        },
    )?;
    let wal = home
        .dir
        .open_dir_nofollow(name)
        .with_context(|| format!("open created WAL directory {}", wal_path.display()))?;
    harden_private_bound_directory(&wal, &wal_path)?;
    Ok(wal)
}

/// Revalidate through the same home capability after WAL creation and directly
/// before master-key publication. Only the normal CLI interface preference and
/// the new empty real WAL directory are admissible at this point.
fn inspect_bound_fresh_home_before_key_publish(
    home: &crate::skills::store::BoundDirectory,
    wal: &cap_std::fs::Dir,
) -> Result<()> {
    for entry in home.dir.entries().with_context(|| {
        format!(
            "relist bound first-install home {}",
            home.display_path.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "read bound first-install home entry in {}",
                home.display_path.display()
            )
        })?;
        let name = entry.file_name();
        if inspect_bound_init_transient(home, &name)? {
            continue;
        }
        if name.as_os_str() == OsStr::new(WAL_DIR) {
            let metadata = wal
                .dir_metadata()
                .context("inspect bound fresh WAL directory")?;
            if !metadata.is_dir() || crate::skills::store::cap_metadata_is_link_like(&metadata) {
                anyhow::bail!("fresh WAL directory is not a real directory");
            }
            if wal.entries()?.next().is_some() {
                anyhow::bail!("fresh WAL directory changed before master-key publication");
            }
            continue;
        }
        anyhow::bail!(
            "first-install home changed before master-key publication: {}",
            home.display_path.join(&name).display()
        );
    }
    Ok(())
}

/// Validate the same narrow transient allowlist accepted by the entry-time
/// inspection, but through the bound home capability. Returns `false` only
/// for a name outside that allowlist; malformed/link-like allowed names fail.
fn inspect_bound_init_transient(
    home: &crate::skills::store::BoundDirectory,
    name: &OsStr,
) -> Result<bool> {
    let display = home.display_path.join(name);
    if name == OsStr::new(crate::cli::wizard_checkpoint::CHECKPOINT_FILENAME)
        || name == OsStr::new(INTERFACE_PREFERENCE_FILE)
        || name == OsStr::new(GUI_LOCK_FILE)
    {
        let metadata = home
            .dir
            .symlink_metadata(name)
            .with_context(|| format!("inspect bound init transient {}", display.display()))?;
        if !metadata.is_file() || crate::skills::store::cap_metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "init transient is not a real regular file: {}",
                display.display()
            );
        }
        return Ok(true);
    }
    if name != OsStr::new(GUI_PENDING_DIR) {
        return Ok(false);
    }

    let pending_dir = home
        .dir
        .open_dir_nofollow(name)
        .with_context(|| format!("open bound GUI init transient {}", display.display()))?;
    let metadata = pending_dir
        .dir_metadata()
        .with_context(|| format!("inspect bound GUI init transient {}", display.display()))?;
    if !metadata.is_dir() || crate::skills::store::cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "GUI init transient is not a real directory: {}",
            display.display()
        );
    }
    let mut entries = pending_dir.entries()?;
    let Some(entry) = entries.next() else {
        return Ok(true);
    };
    let entry = entry.with_context(|| format!("read GUI init transient {}", display.display()))?;
    let pending_name = entry.file_name();
    if pending_name.as_os_str() != OsStr::new(GUI_PENDING_FILE) || entries.next().is_some() {
        anyhow::bail!("unrecognised GUI init transient: {}", display.display());
    }
    let pending_metadata = pending_dir
        .symlink_metadata(&pending_name)
        .with_context(|| format!("inspect GUI pending transient {}", display.display()))?;
    if !pending_metadata.is_file()
        || crate::skills::store::cap_metadata_is_link_like(&pending_metadata)
    {
        anyhow::bail!(
            "GUI pending transient is not a real regular file: {}",
            display.display()
        );
    }
    Ok(true)
}

fn harden_private_bound_directory(directory: &cap_std::fs::Dir, display_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        directory
            .set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("set owner-private directory {}", display_path.display()))?;
        let metadata = directory.dir_metadata().with_context(|| {
            format!("inspect owner-private directory {}", display_path.display())
        })?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.mode() & 0o7777 == 0o700,
            "first-install directory is not owner-private mode 0700: {}",
            display_path.display()
        );
        // SAFETY: `geteuid` has no preconditions and retains no pointers.
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "first-install directory is not owned by the effective user: {}",
            display_path.display()
        );
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_directory_dacl_bound(
            display_path,
            directory,
        )
        .with_context(|| format!("set owner-private DACL on {}", display_path.display()))?;
        crate::wal::win_native::verify_private_directory_handle_dacl(directory)
            .with_context(|| format!("verify owner-private DACL on {}", display_path.display()))?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (directory, display_path);
        anyhow::bail!("private first-install directories are unsupported on this target");
    }
    Ok(())
}

fn master_key_fingerprint(key: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(key).into()
}

fn require_real_directory(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !is_real_directory(metadata) {
        anyhow::bail!(
            "{} must be a real directory, not a link or reparse point",
            path.display()
        );
    }
    Ok(())
}

fn require_real_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() || is_windows_reparse(metadata) {
        anyhow::bail!(
            "{} must be a real regular file, not a link or reparse point",
            path.display()
        );
    }
    Ok(())
}

fn is_real_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir() && !metadata.file_type().is_symlink() && !is_windows_reparse(metadata)
}

#[cfg(windows)]
fn is_windows_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(not(windows))]
fn is_windows_reparse(_: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(home: &Path) -> FirstInstallIdentityCandidate {
        inspect_before_init(home).unwrap().expect("fresh candidate")
    }

    #[test]
    fn missing_and_empty_home_provision_one_stable_identity() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("fresh");
        let candidate = inspect(&home);
        provision_after_license(&home, Some(&candidate), false).unwrap();
        let first = fs::read(crate::wal::master_key::master_key_path(&home)).unwrap();

        let candidate = inspect(&home);
        provision_after_license(&home, Some(&candidate), false).unwrap();
        assert_eq!(
            first,
            fs::read(crate::wal::master_key::master_key_path(&home)).unwrap()
        );
    }

    #[test]
    fn retained_valid_key_and_checkpoint_are_reused() {
        let home = tempfile::tempdir().unwrap();
        let first = crate::wal::master_key::load_or_init_master_key(
            &crate::wal::master_key::master_key_path(home.path()),
        )
        .unwrap();
        fs::write(
            home.path()
                .join(crate::cli::wizard_checkpoint::CHECKPOINT_FILENAME),
            b"{}",
        )
        .unwrap();

        let candidate = inspect(home.path());
        provision_after_license(home.path(), Some(&candidate), false).unwrap();
        assert_eq!(
            first.expose(),
            crate::wal::master_key::load_existing_master_key_at(home.path())
                .unwrap()
                .expose()
        );
    }

    #[test]
    fn fresh_checkpoint_resume_provisions_the_initial_identity() {
        let home = tempfile::tempdir().unwrap();
        fs::write(
            home.path()
                .join(crate::cli::wizard_checkpoint::CHECKPOINT_FILENAME),
            b"{}",
        )
        .unwrap();
        let candidate = inspect(home.path());

        provision_after_license(home.path(), Some(&candidate), false).unwrap();
        assert!(crate::wal::master_key::master_key_path(home.path()).exists());
    }

    #[test]
    fn configured_or_unknown_homes_never_receive_a_key() {
        let configured = tempfile::tempdir().unwrap();
        fs::write(configured.path().join(CONFIG_FILE), b"state").unwrap();
        assert!(inspect_before_init(configured.path()).unwrap().is_none());
        assert!(!crate::wal::master_key::master_key_path(configured.path()).exists());

        for name in [
            CREDENTIALS_FILE,
            INITIALIZED_MARKER,
            FIRST_TOUR_MARKER,
            "unknown",
        ] {
            let home = tempfile::tempdir().unwrap();
            fs::write(home.path().join(name), b"state").unwrap();
            assert!(inspect_before_init(home.path()).is_err());
            assert!(!crate::wal::master_key::master_key_path(home.path()).exists());
        }
    }

    #[test]
    fn malformed_or_incomplete_retained_wal_is_refused_without_replacement() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join(WAL_DIR);
        fs::create_dir(&wal).unwrap();
        let key = wal.join(MASTER_KEY_FILE);
        fs::write(&key, b"not-a-master-key").unwrap();
        assert!(inspect_before_init(home.path()).is_err());
        assert_eq!(fs::read(&key).unwrap(), b"not-a-master-key");

        let missing = tempfile::tempdir().unwrap();
        fs::create_dir(missing.path().join(WAL_DIR)).unwrap();
        assert!(inspect_before_init(missing.path()).is_err());
        assert!(!missing.path().join(WAL_DIR).join(MASTER_KEY_FILE).exists());
    }

    #[test]
    fn retained_identity_disappearing_after_inspection_never_regenerates() {
        let home = tempfile::tempdir().unwrap();
        let key_path = crate::wal::master_key::master_key_path(home.path());
        crate::wal::master_key::load_or_init_master_key(&key_path).unwrap();
        let candidate = inspect(home.path());
        fs::remove_file(&key_path).unwrap();

        assert!(provision_after_license(home.path(), Some(&candidate), false).is_err());
        assert!(
            !key_path.exists(),
            "a retained identity must never be replaced"
        );
    }

    #[test]
    fn retained_identity_substitution_after_inspection_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let key_path = crate::wal::master_key::master_key_path(home.path());
        crate::wal::master_key::load_or_init_master_key(&key_path).unwrap();
        let candidate = inspect(home.path());
        fs::remove_file(&key_path).unwrap();
        crate::wal::master_key::load_or_init_master_key(&key_path).unwrap();
        let substituted = fs::read(&key_path).unwrap();

        assert!(provision_after_license(home.path(), Some(&candidate), false).is_err());
        assert_eq!(substituted, fs::read(&key_path).unwrap());
    }

    #[test]
    fn fresh_candidate_refuses_key_added_after_initial_inspection() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("fresh");
        let candidate = inspect(&home);
        let key_path = crate::wal::master_key::master_key_path(&home);
        crate::wal::master_key::load_or_init_master_key(&key_path).unwrap();
        let injected = fs::read(&key_path).unwrap();

        assert!(provision_after_license(&home, Some(&candidate), false).is_err());
        assert_eq!(injected, fs::read(&key_path).unwrap());
    }

    #[test]
    fn bound_final_fresh_check_refuses_late_configuration_or_retained_wal() {
        let root = tempfile::tempdir().unwrap();

        let configured = root.path().join("configured");
        let bound = open_private_first_install_home(&configured).unwrap();
        fs::write(configured.join(CONFIG_FILE), b"late configuration").unwrap();
        assert!(inspect_bound_fresh_home_before_wal_create(&bound).is_err());
        assert!(!configured.join(WAL_DIR).exists());

        let retained = root.path().join("retained");
        let bound = open_private_first_install_home(&retained).unwrap();
        fs::create_dir(retained.join(WAL_DIR)).unwrap();
        assert!(inspect_bound_fresh_home_before_wal_create(&bound).is_err());
        assert!(!retained.join(WAL_DIR).join(MASTER_KEY_FILE).exists());
    }

    #[test]
    fn bound_prepublication_check_refuses_late_config_before_key_publish() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("fresh");
        let bound = open_private_first_install_home(&home).unwrap();
        inspect_bound_fresh_home_before_wal_create(&bound).unwrap();
        let wal = create_private_bound_wal_directory(&bound).unwrap();
        fs::write(home.join(CONFIG_FILE), b"late configuration").unwrap();

        assert!(inspect_bound_fresh_home_before_key_publish(&bound, &wal).is_err());
        assert!(!home.join(WAL_DIR).join(MASTER_KEY_FILE).exists());
    }

    #[test]
    fn failed_wal_parent_sync_never_publishes_a_master_key() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("fresh");
        let bound = open_private_first_install_home(&home).unwrap();
        inspect_bound_fresh_home_before_wal_create(&bound).unwrap();

        crate::skills::store::force_parent_sync_failure_for_test(true);
        let result = create_private_bound_wal_directory(&bound);
        crate::skills::store::force_parent_sync_failure_for_test(false);
        let error = match result {
            Ok(_) => panic!("a failed parent sync must stop before WAL descent"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("injected parent-directory sync failure"));
        assert!(!home.join(WAL_DIR).join(MASTER_KEY_FILE).exists());
    }

    #[test]
    fn dry_run_does_not_create_a_master_key() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("dry-run");
        let candidate = inspect(&home);
        provision_after_license(&home, Some(&candidate), true).unwrap();
        assert!(!home.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_home_or_master_key_is_refused() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        let home_link = root.path().join("home-link");
        symlink(&target, &home_link).unwrap();
        assert!(inspect_before_init(&home_link).unwrap().is_none());

        let home = root.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::create_dir(home.join(WAL_DIR)).unwrap();
        symlink(
            target.join("key-target"),
            home.join(WAL_DIR).join(MASTER_KEY_FILE),
        )
        .unwrap();
        assert!(inspect_before_init(&home).is_err());
    }
}
