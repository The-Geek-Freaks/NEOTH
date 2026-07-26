//! Authoritative GUI/CLI preference for one NEOTH instance.
//!
//! The first interactive launch asks once, then stores the answer under the
//! resolved `NEOTH_HOME`.  Explicit surface switches overwrite the same file;
//! no preference is hidden in GUI-local state or a platform registry.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u8 = 1;
const PREFERENCE_FILE: &str = "interface.json";
const MAX_PREFERENCE_BYTES: u64 = 4 * 1024;
const INTERFACE_ENV: &str = "NEOTH_INTERFACE";
static INTERFACE_PROCESS_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfacePreference {
    Gui,
    Cli,
}

impl InterfacePreference {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gui => "gui",
            Self::Cli => "cli",
        }
    }
}

impl fmt::Display for InterfacePreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InterfacePreference {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "gui" => Ok(Self::Gui),
            "cli" => Ok(Self::Cli),
            _ => anyhow::bail!("invalid interface `{raw}`; expected `gui` or `cli`"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreferenceRecord {
    schema_version: u8,
    preferred: InterfacePreference,
}

#[derive(Debug)]
pub(crate) enum PreferenceInspection {
    Missing,
    Valid(InterfacePreference),
    Invalid(InvalidPreferenceState),
}

#[derive(Debug)]
pub(crate) enum InvalidPreferenceState {
    Oversized,
    Malformed(serde_json::Error),
    UnsupportedSchema(u8),
}

#[derive(Debug)]
enum PreferenceBytes {
    Missing,
    Present(Vec<u8>),
    Oversized,
}

#[derive(Debug)]
pub(crate) enum PreferenceSnapshot {
    Missing,
    Present(Vec<u8>),
}

impl PreferenceSnapshot {
    pub(crate) fn represents(&self, preferred: InterfacePreference) -> bool {
        let Self::Present(bytes) = self else {
            return false;
        };
        serde_json::from_slice::<PreferenceRecord>(bytes).is_ok_and(|record| {
            record.schema_version == SCHEMA_VERSION && record.preferred == preferred
        })
    }
}

pub(crate) struct PreferenceLock {
    home: PathBuf,
    _process_guard: MutexGuard<'static, ()>,
    _file_guard: File,
}

pub(crate) struct PreferenceWrite {
    pub(crate) path: PathBuf,
    bytes: Vec<u8>,
}

impl InvalidPreferenceState {
    fn into_error(self, path: &Path) -> anyhow::Error {
        match self {
            Self::Oversized => anyhow::anyhow!(
                "{} is too large (maximum {MAX_PREFERENCE_BYTES} bytes); repair with `neoth interface set gui` or `neoth interface set cli`",
                path.display()
            ),
            Self::Malformed(error) => anyhow::Error::new(error).context(format!(
                "parse {}; repair with `neoth interface set gui` or `neoth interface set cli`",
                path.display()
            )),
            Self::UnsupportedSchema(schema_version) => anyhow::anyhow!(
                "unsupported interface preference schema {} in {}; expected {}; repair with `neoth interface set gui` or `neoth interface set cli`",
                schema_version,
                path.display(),
                SCHEMA_VERSION
            ),
        }
    }
}

pub fn path_at(neoth_home: &Path) -> PathBuf {
    neoth_home.join(PREFERENCE_FILE)
}

/// Serialize every interface mutation in this process and across cooperating
/// CLI/GUI processes. Transaction callers retain this guard from snapshot
/// through ready-signal commit or rollback.
pub(crate) fn lock_at(neoth_home: &Path) -> Result<PreferenceLock> {
    let process_guard = INTERFACE_PROCESS_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("interface preference process lock was poisoned"))?;
    let lock_path = path_at(neoth_home).with_extension("lock");
    let file_guard =
        crate::util::locked_file::lock_file_blocking(&lock_path, "interface preference")?;
    Ok(PreferenceLock {
        home: neoth_home.to_path_buf(),
        _process_guard: process_guard,
        _file_guard: file_guard,
    })
}

/// Read the explicit process-wide interface selection. Absence means no
/// override; every present value is parsed strictly so typos never fall back
/// to a stored preference or reopen the first-run chooser.
pub fn env_override() -> Result<Option<InterfacePreference>> {
    match std::env::var(INTERFACE_ENV) {
        Ok(raw) => match raw.as_str() {
            "gui" => Ok(Some(InterfacePreference::Gui)),
            "cli" => Ok(Some(InterfacePreference::Cli)),
            _ => anyhow::bail!(
                "invalid {INTERFACE_ENV} value `{raw}`; expected exactly `gui` or `cli`"
            ),
        },
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).context("read NEOTH_INTERFACE"),
    }
}

fn read_bytes_at(neoth_home: &Path) -> Result<PreferenceBytes> {
    let path = path_at(neoth_home);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PreferenceBytes::Missing);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("open {}", path.display()));
        }
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PREFERENCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_PREFERENCE_BYTES {
        Ok(PreferenceBytes::Oversized)
    } else {
        Ok(PreferenceBytes::Present(bytes))
    }
}

/// Inspect the persisted choice without conflating invalid serialized state
/// with genuine file-system failures. Normal launchers use [`load_at`] and
/// fail closed; the explicit repair command may replace only `Invalid` state.
pub(crate) fn inspect_at(neoth_home: &Path) -> Result<PreferenceInspection> {
    let bytes = match read_bytes_at(neoth_home)? {
        PreferenceBytes::Missing => return Ok(PreferenceInspection::Missing),
        PreferenceBytes::Oversized => {
            return Ok(PreferenceInspection::Invalid(
                InvalidPreferenceState::Oversized,
            ));
        }
        PreferenceBytes::Present(bytes) => bytes,
    };
    let record: PreferenceRecord = match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(error) => {
            return Ok(PreferenceInspection::Invalid(
                InvalidPreferenceState::Malformed(error),
            ));
        }
    };
    if record.schema_version != SCHEMA_VERSION {
        return Ok(PreferenceInspection::Invalid(
            InvalidPreferenceState::UnsupportedSchema(record.schema_version),
        ));
    }
    Ok(PreferenceInspection::Valid(record.preferred))
}

pub(crate) fn inspect_locked(lock: &PreferenceLock) -> Result<PreferenceInspection> {
    inspect_at(&lock.home)
}

/// Capture exact rollback bytes while rejecting an oversized state that
/// cannot be safely retained in the bounded transaction.
pub(crate) fn snapshot_locked(lock: &PreferenceLock) -> Result<PreferenceSnapshot> {
    match read_bytes_at(&lock.home)? {
        PreferenceBytes::Missing => Ok(PreferenceSnapshot::Missing),
        PreferenceBytes::Present(bytes) => Ok(PreferenceSnapshot::Present(bytes)),
        PreferenceBytes::Oversized => anyhow::bail!(
            "{} exceeds the {MAX_PREFERENCE_BYTES}-byte transactional snapshot limit; repair it first with a normal `neoth interface set gui` or `neoth interface set cli`",
            path_at(&lock.home).display()
        ),
    }
}

pub(crate) fn restore_locked(lock: &PreferenceLock, snapshot: &PreferenceSnapshot) -> Result<()> {
    let path = path_at(&lock.home);
    match snapshot {
        PreferenceSnapshot::Missing => {
            crate::util::atomic_write::durable_remove_file(&path)
                .with_context(|| format!("durably remove {}", path.display()))?;
        }
        PreferenceSnapshot::Present(bytes) => {
            crate::util::atomic_write::atomic_write_private(&path, bytes)
                .with_context(|| format!("restore exact bytes to {}", path.display()))?;
        }
    }
    Ok(())
}

/// Load the chosen interface. A genuinely missing file means the operator has
/// not answered yet; malformed, oversized, or unreadable existing state is a
/// hard error so first-run never silently asks again and overwrites evidence.
pub fn load_at(neoth_home: &Path) -> Result<Option<InterfacePreference>> {
    let path = path_at(neoth_home);
    match inspect_at(neoth_home)? {
        PreferenceInspection::Missing => Ok(None),
        PreferenceInspection::Valid(preferred) => Ok(Some(preferred)),
        PreferenceInspection::Invalid(invalid) => Err(invalid.into_error(&path)),
    }
}

/// Persist an explicit operator choice with the canonical private atomic writer.
pub fn save_at(neoth_home: &Path, preferred: InterfacePreference) -> Result<PathBuf> {
    let lock = lock_at(neoth_home)?;
    Ok(save_locked(&lock, preferred)?.path)
}

pub(crate) fn save_locked(
    lock: &PreferenceLock,
    preferred: InterfacePreference,
) -> Result<PreferenceWrite> {
    let write = prepare_write_locked(lock, preferred)?;
    commit_write_locked(lock, &write)?;
    Ok(write)
}

pub(crate) fn prepare_write_locked(
    lock: &PreferenceLock,
    preferred: InterfacePreference,
) -> Result<PreferenceWrite> {
    let path = path_at(&lock.home);
    let record = PreferenceRecord {
        schema_version: SCHEMA_VERSION,
        preferred,
    };
    let mut bytes = serde_json::to_vec_pretty(&record).context("serialize interface preference")?;
    bytes.push(b'\n');
    Ok(PreferenceWrite { path, bytes })
}

pub(crate) fn commit_write_locked(lock: &PreferenceLock, write: &PreferenceWrite) -> Result<()> {
    commit_write_locked_with(lock, write, |path, bytes| {
        crate::util::atomic_write::atomic_write_private(path, bytes)
    })
}

pub(crate) fn commit_write_locked_with(
    _lock: &PreferenceLock,
    write: &PreferenceWrite,
    writer: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
) -> Result<()> {
    writer(&write.path, &write.bytes).with_context(|| format!("write {}", write.path.display()))
}

/// Generation guard for rollback. Cooperative writers cannot enter while the
/// lock is held; this also detects an external/non-cooperating edit and avoids
/// overwriting it with an obsolete snapshot.
pub(crate) fn write_is_current_locked(
    lock: &PreferenceLock,
    write: &PreferenceWrite,
) -> Result<bool> {
    match read_bytes_at(&lock.home)? {
        PreferenceBytes::Present(bytes) => Ok(bytes == write.bytes),
        PreferenceBytes::Missing | PreferenceBytes::Oversized => Ok(false),
    }
}

pub(crate) fn snapshot_is_current_locked(
    lock: &PreferenceLock,
    snapshot: &PreferenceSnapshot,
) -> Result<bool> {
    match (read_bytes_at(&lock.home)?, snapshot) {
        (PreferenceBytes::Missing, PreferenceSnapshot::Missing) => Ok(true),
        (PreferenceBytes::Present(current), PreferenceSnapshot::Present(previous)) => {
            Ok(current.as_slice() == previous.as_slice())
        }
        (
            PreferenceBytes::Missing | PreferenceBytes::Present(_) | PreferenceBytes::Oversized,
            _,
        ) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_the_only_unanswered_state() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_at(dir.path()).unwrap(), None);
    }

    #[test]
    fn save_round_trips_and_explicit_switch_replaces_choice() {
        let dir = tempfile::tempdir().unwrap();
        let path = save_at(dir.path(), InterfacePreference::Gui).unwrap();
        assert_eq!(path, dir.path().join(PREFERENCE_FILE));
        assert_eq!(load_at(dir.path()).unwrap(), Some(InterfacePreference::Gui));

        save_at(dir.path(), InterfacePreference::Cli).unwrap();
        assert_eq!(load_at(dir.path()).unwrap(), Some(InterfacePreference::Cli));
    }

    #[test]
    fn generic_parser_remains_tolerant_for_non_environment_callers() {
        assert_eq!(
            " GUI ".parse::<InterfacePreference>().unwrap(),
            InterfacePreference::Gui
        );
        assert_eq!(
            "cLi".parse::<InterfacePreference>().unwrap(),
            InterfacePreference::Cli
        );
        for invalid in ["", "desktop", "auto"] {
            let error = invalid.parse::<InterfacePreference>().unwrap_err();
            assert!(error.to_string().contains("expected `gui` or `cli`"));
        }
    }

    #[test]
    fn environment_override_distinguishes_absent_valid_and_invalid() {
        let _env = crate::test_env::lock();
        let previous = std::env::var_os(INTERFACE_ENV);

        // SAFETY: the crate-wide test environment lock is held until every
        // mutation below has been restored.
        unsafe { std::env::remove_var(INTERFACE_ENV) };
        let absent = env_override();
        unsafe { std::env::set_var(INTERFACE_ENV, "cli") };
        let valid = env_override();
        unsafe { std::env::set_var(INTERFACE_ENV, "GUI") };
        let invalid_case = env_override();
        unsafe { std::env::set_var(INTERFACE_ENV, " gui") };
        let invalid_space = env_override();
        unsafe { std::env::set_var(INTERFACE_ENV, "") };
        let invalid_empty = env_override();

        match previous {
            Some(value) => unsafe { std::env::set_var(INTERFACE_ENV, value) },
            None => unsafe { std::env::remove_var(INTERFACE_ENV) },
        }

        assert_eq!(absent.unwrap(), None);
        assert_eq!(valid.unwrap(), Some(InterfacePreference::Cli));
        assert!(invalid_case.is_err());
        assert!(invalid_space.is_err());
        assert!(invalid_empty.is_err());
    }

    #[test]
    fn malformed_and_future_state_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(path_at(dir.path()), b"not-json").unwrap();
        assert!(
            load_at(dir.path())
                .unwrap_err()
                .to_string()
                .contains("parse")
        );

        std::fs::write(
            path_at(dir.path()),
            br#"{"schema_version":2,"preferred":"gui"}"#,
        )
        .unwrap();
        assert!(
            load_at(dir.path())
                .unwrap_err()
                .to_string()
                .contains("unsupported interface preference schema")
        );
    }

    #[test]
    fn unknown_fields_are_rejected_instead_of_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            path_at(dir.path()),
            br#"{"schema_version":1,"preferred":"gui","surprise":true}"#,
        )
        .unwrap();
        assert!(load_at(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn preference_is_private_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = save_at(dir.path(), InterfacePreference::Gui).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
