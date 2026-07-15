//! `neoth interface` — inspect or change the instance-wide GUI/CLI default.

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::interface_preference::{self, InterfacePreference, PreferenceInspection};

const TERMINAL_LAUNCH_DIR: &str = ".terminal-launch";
const MAX_READY_TOKEN_BYTES: usize = 256;

#[derive(Args, Clone, Debug)]
pub struct InterfaceArgs {
    #[command(subcommand)]
    pub action: InterfaceAction,
}

#[derive(Clone, Debug, Subcommand)]
pub enum InterfaceAction {
    /// Show whether the one-time GUI/CLI choice has been recorded.
    Show,
    /// Set the default surface used by onboarding and future launchers.
    Set {
        #[arg(value_enum)]
        preferred: InterfaceValue,
        /// Internal GUI/terminal commit handshake. Both hidden arguments are
        /// required together; public callers use plain `interface set`.
        #[arg(long, hide = true, requires = "ready_token")]
        ready_file: Option<PathBuf>,
        #[arg(long, hide = true, requires = "ready_file")]
        ready_token: Option<String>,
    },
}

#[derive(Debug)]
struct ReadyCommit {
    path: PathBuf,
    token: Vec<u8>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum InterfaceValue {
    Gui,
    Cli,
}

impl From<InterfaceValue> for InterfacePreference {
    fn from(value: InterfaceValue) -> Self {
        match value {
            InterfaceValue::Gui => Self::Gui,
            InterfaceValue::Cli => Self::Cli,
        }
    }
}

pub fn run_interface(args: InterfaceArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        InterfaceAction::Show => {
            let preferred = interface_preference::load_at(&home)?;
            render(
                preferred,
                &interface_preference::path_at(&home),
                output,
                false,
            );
        }
        InterfaceAction::Set {
            preferred,
            ready_file,
            ready_token,
        } => {
            let preferred = InterfacePreference::from(preferred);
            let ready = prepare_ready_commit(&home, ready_file.as_deref(), ready_token.as_deref())?;
            let (path, changed) = set_preference_at(&home, preferred, ready.as_ref())?;
            render(Some(preferred), &path, output, changed);
        }
    }
    Ok(())
}

/// Persist one authoritative interface choice and report a truthful state
/// delta. This explicit repair path replaces invalid serialized state, while
/// genuine file-system failures still fail closed and an idempotent set
/// remains a successful operation with `changed: false`.
fn set_preference_at(
    home: &Path,
    preferred: InterfacePreference,
    ready: Option<&ReadyCommit>,
) -> Result<(PathBuf, bool)> {
    set_preference_at_with_writer(home, preferred, ready, publish_ready_token)
}

/// Publish a single-use readiness token with create-if-absent semantics.
///
/// Every operation that can invalidate the token is completed against a
/// private sibling first: permissions, Windows DACL verification, bytes and
/// file sync. The hard-link call is the sole visibility edge and cannot
/// replace a raced token. Once that call succeeds this function cannot report
/// failure; orphan-temp cleanup is deliberately best-effort.
fn publish_ready_token(path: &Path, token: &[u8]) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        return publish_ready_token_with(path, token, |file, target| {
            crate::wal::win_native::create_private_file_handle(file, target)
        });
    }
    #[cfg(not(windows))]
    publish_ready_token_with(path, token, |temporary, target| {
        std::fs::hard_link(temporary, target)
    })
}

fn publish_ready_token_with(
    path: &Path,
    token: &[u8],
    #[cfg(windows)] publish: impl FnOnce(&std::fs::File, &Path) -> std::io::Result<()>,
    #[cfg(not(windows))] publish: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    publish_ready_token_with_inner(path, token, publish)
}

#[cfg(not(windows))]
fn publish_ready_token_with_inner(
    path: &Path,
    token: &[u8],
    publish: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| std::io::Error::other(format!("ready temp RNG unavailable: {error}")))?;
    let mut temporary_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    temporary_name.push(format!(".{}.publish.tmp", hex::encode(nonce)));
    let temporary = path.with_file_name(temporary_name);

    #[cfg(windows)]
    let mut file = crate::wal::win_native::create_private_file_new(&temporary)?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options.open(&temporary)?
    };

    let result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        crate::wal::win_native::verify_private_file_handle(&file)?;

        file.write_all(token)?;
        file.flush()?;
        file.sync_all()?;

        // This is the exact commit point. `hard_link` creates the target only
        // when absent and the target immediately names the already-complete,
        // already-private file.
        publish(&temporary, path)?;
        Ok(())
    })();

    // On success the target is already final. On failure this only removes our
    // unpublished sibling; it must never touch a raced target we do not own.
    drop(file);
    let _ = std::fs::remove_file(&temporary);
    result
}

#[cfg(windows)]
fn publish_ready_token_with_inner(
    path: &Path,
    token: &[u8],
    publish: impl FnOnce(&std::fs::File, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| std::io::Error::other(format!("ready temp RNG unavailable: {error}")))?;
    let mut temporary_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    temporary_name.push(format!(".{}.publish.tmp", hex::encode(nonce)));
    let temporary = path.with_file_name(temporary_name);
    let mut file = crate::wal::win_native::create_private_file_new(&temporary)?;

    let result = (|| {
        crate::wal::win_native::verify_private_file_handle(&file)?;
        file.write_all(token)?;
        file.flush()?;
        file.sync_all()?;
        publish(&file, path)?;
        Ok(())
    })();

    drop(file);
    let _ = std::fs::remove_file(&temporary);
    result
}

fn set_preference_at_with_writer(
    home: &Path,
    preferred: InterfacePreference,
    ready: Option<&ReadyCommit>,
    write_ready: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
) -> Result<(PathBuf, bool)> {
    set_preference_at_with_writers(
        home,
        preferred,
        ready,
        |path, bytes| crate::util::atomic_write::atomic_write_private(path, bytes),
        write_ready,
    )
}

fn set_preference_at_with_writers(
    home: &Path,
    preferred: InterfacePreference,
    ready: Option<&ReadyCommit>,
    write_preference: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
    write_ready: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
) -> Result<(PathBuf, bool)> {
    let lock = interface_preference::lock_at(home)?;
    let Some(ready) = ready else {
        let changed = !matches!(
            interface_preference::inspect_locked(&lock)?,
            PreferenceInspection::Valid(previous) if previous == preferred
        );
        let write = interface_preference::prepare_write_locked(&lock, preferred)?;
        interface_preference::commit_write_locked_with(&lock, &write, write_preference)?;
        return Ok((write.path, changed));
    };

    let snapshot = interface_preference::snapshot_locked(&lock)?;
    let changed = !snapshot.represents(preferred);
    let write = interface_preference::prepare_write_locked(&lock, preferred)?;
    if let Err(write_error) =
        interface_preference::commit_write_locked_with(&lock, &write, write_preference)
    {
        return Err(preference_commit_failure(
            &lock,
            &snapshot,
            &write,
            write_error,
        ));
    }
    if let Err(ready_error) = write_ready(&ready.path, &ready.token) {
        let rollback_error = match interface_preference::write_is_current_locked(&lock, &write) {
            Ok(true) => interface_preference::restore_locked(&lock, &snapshot).err(),
            Ok(false) => Some(anyhow::anyhow!(
                "rollback skipped because interface.json changed outside the held interface lock"
            )),
            Err(error) => Some(error.context(
                "rollback skipped because the current interface generation could not be verified",
            )),
        };
        return Err(commit_failure(&ready.path, ready_error, rollback_error));
    }
    Ok((write.path, changed))
}

fn preference_commit_failure(
    lock: &interface_preference::PreferenceLock,
    snapshot: &interface_preference::PreferenceSnapshot,
    write: &interface_preference::PreferenceWrite,
    write_error: anyhow::Error,
) -> anyhow::Error {
    let mut message = format!("write interface preference failed: {write_error:#}");
    match interface_preference::write_is_current_locked(lock, write) {
        Ok(true) => match interface_preference::restore_locked(lock, snapshot) {
            Ok(()) => message.push_str("; previous interface preference restored"),
            Err(error) => message.push_str(&format!(
                "; interface preference rollback also failed: {error:#}"
            )),
        },
        Ok(false) => match interface_preference::snapshot_is_current_locked(lock, snapshot) {
            Ok(true) => message.push_str("; previous interface preference remained intact"),
            Ok(false) => message.push_str(
                "; rollback skipped because interface.json changed outside the held interface lock",
            ),
            Err(error) => message.push_str(&format!(
                "; rollback skipped because the prior interface generation could not be verified: {error:#}"
            )),
        },
        Err(error) => message.push_str(&format!(
            "; rollback skipped because the committed interface generation could not be verified: {error:#}"
        )),
    }
    anyhow::anyhow!(message)
}

fn commit_failure(
    ready_path: &Path,
    ready_error: std::io::Error,
    rollback_error: Option<anyhow::Error>,
) -> anyhow::Error {
    let mut message = format!(
        "write terminal ready token {} failed: {ready_error}",
        ready_path.display()
    );
    if let Some(error) = rollback_error {
        message.push_str(&format!(
            "; interface preference rollback also failed: {error:#}"
        ));
    } else {
        message.push_str("; previous interface preference restored");
    }
    anyhow::anyhow!(message)
}

fn prepare_ready_commit(
    home: &Path,
    ready_file: Option<&Path>,
    ready_token: Option<&str>,
) -> Result<Option<ReadyCommit>> {
    let (ready_file, ready_token) = match (ready_file, ready_token) {
        (None, None) => return Ok(None),
        (Some(file), Some(token)) => (file, token),
        _ => anyhow::bail!("--ready-file and --ready-token must be supplied together"),
    };
    if ready_token.is_empty()
        || ready_token.len() > MAX_READY_TOKEN_BYTES
        || !ready_token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        anyhow::bail!(
            "--ready-token must contain 1..={MAX_READY_TOKEN_BYTES} printable ASCII bytes"
        );
    }
    if !ready_file.is_absolute() {
        anyhow::bail!("--ready-file must be an absolute path");
    }

    let canonical_home = home
        .canonicalize()
        .map_err(anyhow::Error::new)
        .context(format!("canonicalize NEOTH_HOME {}", home.display()))?;
    let launch_root = canonical_home.join(TERMINAL_LAUNCH_DIR);
    let canonical_root = canonical_non_symlink_dir(&launch_root, "terminal launch root")?;
    if canonical_root != launch_root {
        anyhow::bail!(
            "terminal launch root {} escapes canonical NEOTH_HOME",
            launch_root.display()
        );
    }

    let parent = ready_file
        .parent()
        .ok_or_else(|| anyhow::anyhow!("--ready-file has no parent directory"))?;
    let canonical_parent = canonical_non_symlink_dir(parent, "terminal launch instance")?;
    let relative = canonical_parent
        .strip_prefix(&canonical_root)
        .map_err(|_| {
            anyhow::anyhow!(
                "--ready-file parent {} is outside {}",
                canonical_parent.display(),
                canonical_root.display()
            )
        })?;
    let mut components = relative.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        anyhow::bail!(
            "--ready-file parent must be one unique directory directly under {}",
            canonical_root.display()
        );
    }
    let file_name = ready_file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("--ready-file must name a file"))?;
    if file_name != std::ffi::OsStr::new("ready") {
        anyhow::bail!("--ready-file must use the canonical filename `ready`");
    }
    let canonical_ready = canonical_parent.join(file_name);
    match std::fs::symlink_metadata(&canonical_ready) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => anyhow::bail!(
            "--ready-file {} already exists; use a fresh launch directory",
            canonical_ready.display()
        ),
        Err(error) => {
            return Err(error).context(format!("inspect {}", canonical_ready.display()));
        }
    }

    Ok(Some(ReadyCommit {
        path: canonical_ready,
        token: ready_token.as_bytes().to_vec(),
    }))
}

fn canonical_non_symlink_dir(path: &Path, what: &str) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {what} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("{what} {} must be a real directory", path.display());
    }
    path.canonicalize()
        .with_context(|| format!("canonicalize {what} {}", path.display()))
}

fn render(
    preferred: Option<InterfacePreference>,
    path: &std::path::Path,
    output: OutputFormat,
    changed: bool,
) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "chosen": preferred.is_some(),
                "preferred": preferred.map(InterfacePreference::as_str),
                "changed": changed,
                "path": path,
            })
        ),
        OutputFormat::Table => match preferred {
            Some(value) if changed => {
                println!("Default interface set to {value} ({}).", path.display());
            }
            Some(value) => {
                println!("Default interface : {value}");
                println!("Preference file   : {}", path.display());
                println!("Switch anytime    : `neoth gui` or `neoth interface set cli`");
            }
            None => {
                println!("Default interface : not chosen yet");
                println!("Preference file   : {}", path.display());
                println!(
                    "Choose explicitly : `neoth interface set gui` or `neoth interface set cli`"
                );
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    fn ready_commit(home: &Path, unique: &str, token: &str) -> ReadyCommit {
        let parent = home.join(TERMINAL_LAUNCH_DIR).join(unique);
        std::fs::create_dir_all(&parent).unwrap();
        prepare_ready_commit(home, Some(&parent.join("ready")), Some(token))
            .unwrap()
            .unwrap()
    }

    fn injected_ready_failure(_: &Path, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::other("injected ready write failure"))
    }

    #[test]
    fn clap_values_map_to_domain_values() {
        assert_eq!(
            InterfacePreference::from(InterfaceValue::Gui),
            InterfacePreference::Gui
        );
        assert_eq!(
            InterfacePreference::from(InterfaceValue::Cli),
            InterfacePreference::Cli
        );
    }

    #[test]
    fn repeated_set_is_idempotent_and_reports_a_truthful_delta() {
        let home = tempfile::tempdir().unwrap();

        let (first_path, first_changed) =
            set_preference_at(home.path(), InterfacePreference::Cli, None).unwrap();
        let (second_path, second_changed) =
            set_preference_at(home.path(), InterfacePreference::Cli, None).unwrap();

        assert!(first_changed);
        assert!(!second_changed);
        assert_eq!(first_path, second_path);
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Cli)
        );
    }

    #[test]
    fn explicit_set_repairs_malformed_state() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(interface_preference::path_at(home.path()), b"not-json").unwrap();

        let (_, changed) = set_preference_at(home.path(), InterfacePreference::Gui, None).unwrap();

        assert!(changed);
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Gui)
        );
    }

    #[test]
    fn explicit_set_repairs_future_schema_state() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            interface_preference::path_at(home.path()),
            br#"{"schema_version":2,"preferred":"gui"}"#,
        )
        .unwrap();

        let (_, changed) = set_preference_at(home.path(), InterfacePreference::Cli, None).unwrap();

        assert!(changed);
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Cli)
        );
    }

    #[test]
    fn explicit_set_repairs_oversized_state() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            interface_preference::path_at(home.path()),
            vec![b'x'; 4 * 1024 + 1],
        )
        .unwrap();

        let (_, changed) = set_preference_at(home.path(), InterfacePreference::Gui, None).unwrap();

        assert!(changed);
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Gui)
        );
    }

    #[test]
    fn explicit_set_does_not_mask_file_system_errors() {
        let home = tempfile::tempdir().unwrap();
        let preference_path = interface_preference::path_at(home.path());
        std::fs::create_dir(&preference_path).unwrap();

        assert!(set_preference_at(home.path(), InterfacePreference::Gui, None).is_err());
        assert!(preference_path.is_dir());
    }

    #[test]
    fn hidden_ready_arguments_are_required_as_a_pair() {
        let home = tempfile::tempdir().unwrap();
        let ready = home.path().join("ready");
        let ready = ready.to_str().unwrap();

        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "interface",
                "set",
                "gui",
                "--ready-file",
                ready,
            ])
            .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "interface",
                "set",
                "gui",
                "--ready-token",
                "token",
            ])
            .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "interface",
                "set",
                "gui",
                "--ready-file",
                ready,
                "--ready-token",
                "token",
            ])
            .is_ok()
        );
    }

    #[test]
    fn ready_contract_requires_a_bounded_token_and_scoped_unique_parent() {
        let home = tempfile::tempdir().unwrap();
        let launch_root = home.path().join(TERMINAL_LAUNCH_DIR);
        let unique = launch_root.join("unique");
        std::fs::create_dir_all(&unique).unwrap();
        let outside = home.path().join("outside");
        let too_deep = unique.join("nested");
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&too_deep).unwrap();

        assert!(prepare_ready_commit(home.path(), Some(&unique.join("ready")), Some("")).is_err());
        assert!(
            prepare_ready_commit(
                home.path(),
                Some(&unique.join("ready")),
                Some(&"x".repeat(MAX_READY_TOKEN_BYTES + 1)),
            )
            .is_err()
        );
        assert!(
            prepare_ready_commit(home.path(), Some(&unique.join("ack")), Some("token"),).is_err()
        );
        let valid = prepare_ready_commit(home.path(), Some(&unique.join("ready")), Some("token"))
            .unwrap()
            .unwrap();
        std::fs::write(&valid.path, &valid.token).unwrap();
        assert!(
            prepare_ready_commit(home.path(), Some(&unique.join("ready")), Some("token"),).is_err(),
            "an existing ready token must not be replayed"
        );
        assert!(
            prepare_ready_commit(home.path(), Some(&outside.join("ready")), Some("token"),)
                .is_err()
        );
        assert!(
            prepare_ready_commit(home.path(), Some(&launch_root.join("ready")), Some("token"),)
                .is_err()
        );
        assert!(
            prepare_ready_commit(home.path(), Some(&too_deep.join("ready")), Some("token"),)
                .is_err()
        );
    }

    #[test]
    fn ready_failure_restores_missing_preference() {
        let home = tempfile::tempdir().unwrap();
        let ready = ready_commit(home.path(), "missing", "token-missing");

        let error = set_preference_at_with_writer(
            home.path(),
            InterfacePreference::Gui,
            Some(&ready),
            injected_ready_failure,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("previous interface preference restored")
        );
        assert_eq!(interface_preference::load_at(home.path()).unwrap(), None);
        assert!(!ready.path.exists());
    }

    #[test]
    fn ready_failure_restores_exact_malformed_preference_bytes() {
        let home = tempfile::tempdir().unwrap();
        let preference_path = interface_preference::path_at(home.path());
        let before = b"{malformed-but-operator-owned\r\n";
        std::fs::write(&preference_path, before).unwrap();
        let ready = ready_commit(home.path(), "malformed", "token-malformed");

        set_preference_at_with_writer(
            home.path(),
            InterfacePreference::Cli,
            Some(&ready),
            injected_ready_failure,
        )
        .unwrap_err();

        assert_eq!(std::fs::read(preference_path).unwrap(), before);
    }

    #[test]
    fn ready_failure_restores_exact_valid_preference_bytes() {
        let home = tempfile::tempdir().unwrap();
        interface_preference::save_at(home.path(), InterfacePreference::Gui).unwrap();
        let preference_path = interface_preference::path_at(home.path());
        let before = std::fs::read(&preference_path).unwrap();
        let ready = ready_commit(home.path(), "valid", "token-valid");

        set_preference_at_with_writer(
            home.path(),
            InterfacePreference::Cli,
            Some(&ready),
            injected_ready_failure,
        )
        .unwrap_err();

        assert_eq!(std::fs::read(preference_path).unwrap(), before);
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Gui)
        );
    }

    #[test]
    fn post_commit_preference_error_restores_before_ready_is_written() {
        let home = tempfile::tempdir().unwrap();
        interface_preference::save_at(home.path(), InterfacePreference::Gui).unwrap();
        let preference_path = interface_preference::path_at(home.path());
        let before = std::fs::read(&preference_path).unwrap();
        let ready = ready_commit(home.path(), "post-commit", "token-post-commit");

        let error = set_preference_at_with_writers(
            home.path(),
            InterfacePreference::Cli,
            Some(&ready),
            |path, bytes| {
                crate::util::atomic_write::atomic_write_private(path, bytes)?;
                Err(std::io::Error::other(
                    "injected error after committed rename",
                ))
            },
            |_, _| panic!("ready writer must not run after preference commit error"),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("previous interface preference restored")
        );
        assert_eq!(std::fs::read(preference_path).unwrap(), before);
        assert!(!ready.path.exists());
    }

    #[test]
    fn ready_commit_writes_exact_token_after_preference() {
        let home = tempfile::tempdir().unwrap();
        let ready = ready_commit(home.path(), "commit", "opaque-token_123");

        let (_, changed) =
            set_preference_at(home.path(), InterfacePreference::Cli, Some(&ready)).unwrap();

        assert!(changed);
        assert_eq!(std::fs::read(&ready.path).unwrap(), ready.token);
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Cli)
        );
    }

    #[test]
    fn ready_publication_finishes_private_preparation_before_visibility() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ready");
        let token = b"prepared-before-publication";
        let mut publication_observed = false;

        #[cfg(windows)]
        publish_ready_token_with(&target, token, |file, target| {
            assert!(!target.exists(), "ready became visible before commit");
            crate::wal::win_native::verify_private_file_handle(file)?;
            publication_observed = true;
            crate::wal::win_native::create_private_file_handle(file, target)
        })
        .unwrap();
        #[cfg(not(windows))]
        publish_ready_token_with(&target, token, |temporary, target| {
            assert!(!target.exists(), "ready became visible before commit");
            assert_eq!(std::fs::read(temporary).unwrap(), token);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(temporary).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            publication_observed = true;
            std::fs::hard_link(temporary, target)
        })
        .unwrap();

        assert!(publication_observed);
        assert_eq!(std::fs::read(&target).unwrap(), token);
        #[cfg(windows)]
        crate::wal::win_native::verify_private_dacl(&target).unwrap();
        assert!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| !entry.file_name().to_string_lossy().contains(".publish.tmp")),
            "ready publication left its private sibling behind"
        );
    }

    #[test]
    fn raced_ready_publication_preserves_winner_and_rolls_back_preference() {
        let home = tempfile::tempdir().unwrap();
        interface_preference::save_at(home.path(), InterfacePreference::Gui).unwrap();
        let ready = ready_commit(home.path(), "raced", "transaction-token");
        let winning_token = b"independent-winning-token";

        let error = set_preference_at_with_writer(
            home.path(),
            InterfacePreference::Cli,
            Some(&ready),
            |path, token| {
                #[cfg(windows)]
                {
                    publish_ready_token_with(path, token, |_file, target| {
                        std::fs::write(target, winning_token)?;
                        Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "injected raced ready target",
                        ))
                    })
                }
                #[cfg(not(windows))]
                publish_ready_token_with(path, token, |temporary, target| {
                    std::fs::write(target, winning_token)?;
                    std::fs::hard_link(temporary, target)
                })
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("previous interface preference restored")
        );
        assert_eq!(std::fs::read(&ready.path).unwrap(), winning_token);
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Gui)
        );
        assert!(
            std::fs::read_dir(ready.path.parent().unwrap())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| !entry.file_name().to_string_lossy().contains(".publish.tmp")),
            "failed publication left its private sibling behind"
        );
    }

    #[test]
    fn transactional_set_rejects_oversized_state_before_mutation() {
        let home = tempfile::tempdir().unwrap();
        let preference_path = interface_preference::path_at(home.path());
        let before = vec![b'x'; 4 * 1024 + 1];
        std::fs::write(&preference_path, &before).unwrap();
        let ready = ready_commit(home.path(), "oversized", "token-oversized");

        let error =
            set_preference_at(home.path(), InterfacePreference::Gui, Some(&ready)).unwrap_err();

        assert!(error.to_string().contains("transactional snapshot limit"));
        assert_eq!(std::fs::read(preference_path).unwrap(), before);
        assert!(!ready.path.exists());
    }

    #[test]
    fn rollback_generation_guard_preserves_an_external_edit() {
        let home = tempfile::tempdir().unwrap();
        let preference_path = interface_preference::path_at(home.path());
        let ready = ready_commit(home.path(), "generation", "token-generation");
        let external = br#"{
  "schema_version": 1,
  "preferred": "cli"
}
"#;

        let error = set_preference_at_with_writer(
            home.path(),
            InterfacePreference::Gui,
            Some(&ready),
            |_, _| {
                std::fs::write(&preference_path, external)?;
                Err(std::io::Error::other("injected after external edit"))
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("changed outside the held interface lock")
        );
        assert_eq!(std::fs::read(preference_path).unwrap(), external);
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Cli)
        );
    }

    #[test]
    fn interface_lock_covers_preference_and_ready_commit() {
        let home = tempfile::tempdir().unwrap();
        let transaction_home = home.path().to_path_buf();
        let concurrent_home = transaction_home.clone();
        let ready = ready_commit(home.path(), "concurrent", "token-concurrent");
        let (writer_entered_tx, writer_entered_rx) = std::sync::mpsc::channel();
        let (release_writer_tx, release_writer_rx) = std::sync::mpsc::channel();

        let transaction = std::thread::spawn(move || {
            set_preference_at_with_writer(
                &transaction_home,
                InterfacePreference::Gui,
                Some(&ready),
                |path, bytes| {
                    writer_entered_tx.send(()).unwrap();
                    release_writer_rx.recv().unwrap();
                    crate::util::atomic_write::atomic_write_private(path, bytes)
                },
            )
        });
        writer_entered_rx.recv().unwrap();

        let (concurrent_done_tx, concurrent_done_rx) = std::sync::mpsc::channel();
        let concurrent = std::thread::spawn(move || {
            let result = interface_preference::save_at(&concurrent_home, InterfacePreference::Cli);
            concurrent_done_tx.send(result).unwrap();
        });
        let raced = concurrent_done_rx.recv_timeout(std::time::Duration::from_millis(150));
        let blocked_until_commit =
            matches!(&raced, Err(std::sync::mpsc::RecvTimeoutError::Timeout));
        release_writer_tx.send(()).unwrap();

        assert!(transaction.join().unwrap().is_ok());
        let concurrent_result = match raced {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => concurrent_done_rx.recv().unwrap(),
            Err(error) => panic!("concurrent writer channel failed: {error}"),
        };
        concurrent.join().unwrap();
        assert!(
            blocked_until_commit,
            "a concurrent interface writer entered before the ready commit released its lock"
        );
        concurrent_result.unwrap();
        assert_eq!(
            interface_preference::load_at(home.path()).unwrap(),
            Some(InterfacePreference::Cli)
        );
    }
}
