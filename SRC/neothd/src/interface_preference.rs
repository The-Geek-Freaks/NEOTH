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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u8 = 1;
const PREFERENCE_FILE: &str = "interface.json";
const MAX_PREFERENCE_BYTES: u64 = 4 * 1024;

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

pub fn path_at(neoth_home: &Path) -> PathBuf {
    neoth_home.join(PREFERENCE_FILE)
}

/// Load the chosen interface. A genuinely missing file means the operator has
/// not answered yet; malformed, oversized, or unreadable existing state is a
/// hard error so first-run never silently asks again and overwrites evidence.
pub fn load_at(neoth_home: &Path) -> Result<Option<InterfacePreference>> {
    let path = path_at(neoth_home);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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
        anyhow::bail!(
            "{} is too large (maximum {MAX_PREFERENCE_BYTES} bytes); repair with `neoth interface set gui|cli`",
            path.display()
        );
    }
    let record: PreferenceRecord = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse {}; repair with `neoth interface set gui|cli`",
            path.display()
        )
    })?;
    if record.schema_version != SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported interface preference schema {} in {}; expected {}; repair with `neoth interface set gui|cli`",
            record.schema_version,
            path.display(),
            SCHEMA_VERSION
        );
    }
    Ok(Some(record.preferred))
}

/// Persist an explicit operator choice with the canonical private atomic writer.
pub fn save_at(neoth_home: &Path, preferred: InterfacePreference) -> Result<PathBuf> {
    let path = path_at(neoth_home);
    let record = PreferenceRecord {
        schema_version: SCHEMA_VERSION,
        preferred,
    };
    let mut bytes = serde_json::to_vec_pretty(&record).context("serialize interface preference")?;
    bytes.push(b'\n');
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

pub fn load_default() -> Result<Option<InterfacePreference>> {
    load_at(&crate::config::FreedomConfig::default_neoth_home())
}

pub fn save_default(preferred: InterfacePreference) -> Result<PathBuf> {
    save_at(
        &crate::config::FreedomConfig::default_neoth_home(),
        preferred,
    )
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
