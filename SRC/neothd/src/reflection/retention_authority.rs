//! Daily-only retention authority v2 configuration and durable receipt schemas.

use std::ffi::OsStr;
use std::path::Path;

pub const DAILY_RETENTION_EXECUTION_VERSION: u16 = 2;
pub const DEFAULT_DAILY_RETENTION_GRACE_DAYS: u16 = 7;
pub const MAX_DAILY_RETENTION_GRACE_DAYS: u16 = 30;
const RECEIPT_SCHEMA_VERSION: u16 = 1;
const MAX_RETENTION_RECORD_BYTES: usize = 32 * 1024;
/// Durable terminal receipts accumulate; scan is bounded independently from
/// the per-tick 64-effect execution batch.
pub const MAX_RETENTION_EFFECT_RECORDS: usize = 4_096;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DailyRetentionExecutionConfig {
    pub version: u16,
    pub enabled: bool,
    pub quarantine_grace_days: u16,
}
impl Default for DailyRetentionExecutionConfig {
    fn default() -> Self {
        Self {
            version: DAILY_RETENTION_EXECUTION_VERSION,
            enabled: false,
            quarantine_grace_days: DEFAULT_DAILY_RETENTION_GRACE_DAYS,
        }
    }
}
impl DailyRetentionExecutionConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != DAILY_RETENTION_EXECUTION_VERSION {
            return Err("unsupported Daily retention execution version");
        }
        if !(1..=MAX_DAILY_RETENTION_GRACE_DAYS).contains(&self.quarantine_grace_days) {
            return Err("invalid Daily retention quarantine grace");
        }
        Ok(())
    }
    #[must_use]
    pub fn status(&self) -> &'static str {
        if self.enabled {
            "quarantine/purge enabled"
        } else {
            "off"
        }
    }
}

/// Settlement-only proof. Retention never creates this from historical bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DailyNoteReceiptV1 {
    pub schema_version: u16,
    pub tag: String,
    pub archive_sha256: String,
    pub note_sha256: String,
    pub note_object_identity: String,
    pub vault_root_identity: String,
    pub daily_leaf_identity: String,
    pub note_leaf: String,
    pub marker_generation: String,
}
impl DailyNoteReceiptV1 {
    #[must_use]
    pub fn new(
        tag: String,
        archive_sha256: String,
        note_sha256: String,
        note_object_identity: String,
        vault_root_identity: String,
        daily_leaf_identity: String,
    ) -> Self {
        Self {
            schema_version: RECEIPT_SCHEMA_VERSION,
            note_leaf: format!("{tag}.md"),
            marker_generation: tag.clone(),
            tag,
            archive_sha256,
            note_sha256,
            note_object_identity,
            vault_root_identity,
            daily_leaf_identity,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetentionEffectPhaseV2 {
    Prepared,
    ArchiveQuarantined,
    NoteQuarantined,
    Committed,
    Abandoned,
    RecoveryBlocked,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionEffectJournalV2 {
    pub schema_version: u16,
    pub tag: String,
    pub lease_sha256: String,
    pub archive_sha256: String,
    /// Present only when a settlement-owned note was revalidated before this
    /// candidate began.  Legacy matching bytes never populate this field.
    pub note_sha256: Option<String>,
    pub archive_quarantine_run: String,
    pub archive_quarantine_run_identity: String,
    pub archive_source_identity: String,
    pub archive_quarantine_identity: Option<String>,
    pub note_quarantine_run: Option<String>,
    pub note_quarantine_run_identity: Option<String>,
    pub note_source_identity: Option<String>,
    pub note_quarantine_identity: Option<String>,
    /// Immutable admission facts retained so recovery never consults a later
    /// configuration or lease to continue this already-journalled effect.
    pub config_sha256: String,
    pub period_input_sha256: String,
    pub quarantined_at_unix: i64,
    pub recoverable_until_unix: i64,
    pub phase: RetentionEffectPhaseV2,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionEffectReceiptV2 {
    pub schema_version: u16,
    pub tag: String,
    pub source_sha256: String,
    pub quarantine_sha256: String,
    pub archive_quarantine_identity: String,
    pub note_sha256: Option<String>,
    pub note_quarantine_run: Option<String>,
    pub note_quarantine_identity: Option<String>,
    pub lease_sha256: String,
    pub config_sha256: String,
    pub period_input_sha256: String,
    pub archive_quarantine_run: String,
    pub quarantined_at_unix: i64,
    pub recoverable_until_unix: i64,
    pub purged_at_unix: Option<i64>,
}
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPurgePhaseV2 {
    PurgePrepared,
    UnlinkAttempted,
    PurgedCompleted,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionPurgeJournalV2 {
    pub schema_version: u16,
    pub receipt_sha256: String,
    pub phase: RetentionPurgePhaseV2,
}

fn state_dir(home: &Path, child: &str) -> std::io::Result<(cap_std::fs::Dir, std::path::PathBuf)> {
    crate::reflection::hygiene_store::prepare_daily_admission_namespace(home)
        .map_err(|_| std::io::Error::other("retention namespace unavailable"))?;
    let home_dir =
        crate::skills::store::open_absolute_bound_directory(home, false, "retention home")
            .map_err(std::io::Error::other)?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "retention home missing")
            })?;
    let reflections_path = home.join("reflections");
    let reflections = crate::skills::store::open_or_create_private_child_dir(
        &home_dir.dir,
        OsStr::new("reflections"),
        &reflections_path,
    )
    .map_err(std::io::Error::other)?;
    let root_path = reflections_path.join("retention-v2");
    let root = crate::skills::store::open_or_create_private_child_dir(
        &reflections,
        OsStr::new("retention-v2"),
        &root_path,
    )
    .map_err(std::io::Error::other)?;
    let path = root_path.join(child);
    let dir =
        crate::skills::store::open_or_create_private_child_dir(&root, OsStr::new(child), &path)
            .map_err(std::io::Error::other)?;
    Ok((dir, path))
}
fn write_record<T: serde::Serialize>(
    home: &Path,
    child: &str,
    tag: &str,
    value: &T,
) -> std::io::Result<()> {
    let (dir, path) = state_dir(home, child)?;
    let name = format!("{tag}.json");
    let bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    if bytes.len() > MAX_RETENTION_RECORD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "retention record too large",
        ));
    }
    match crate::skills::store::atomic_write_private_child_reported(
        &dir,
        OsStr::new(&name),
        &path.join(&name),
        &bytes,
    )
    .map_err(std::io::Error::other)?
    {
        crate::skills::store::PrivateChildCommit::PublishedAndSynced => Ok(()),
        crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_) => {
            Err(std::io::Error::other("retention record durability unknown"))
        }
    }
}
fn read_record<T: serde::de::DeserializeOwned>(
    home: &Path,
    child: &str,
    tag: &str,
) -> std::io::Result<Option<T>> {
    let (dir, path) = state_dir(home, child)?;
    let name = format!("{tag}.json");
    match crate::skills::store::read_regular_file_bounded(
        &dir,
        OsStr::new(&name),
        &path.join(&name),
        MAX_RETENTION_RECORD_BYTES,
    ) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid retention record")
        }),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(std::io::Error::other(error)),
    }
}
pub(crate) fn save_daily_note_receipt(
    home: &Path,
    receipt: &DailyNoteReceiptV1,
) -> std::io::Result<()> {
    write_record(home, "note-receipts", &receipt.tag, receipt)
}
pub(crate) fn load_daily_note_receipt(
    home: &Path,
    tag: &str,
) -> std::io::Result<Option<DailyNoteReceiptV1>> {
    read_record(home, "note-receipts", tag)
}
pub(crate) fn save_effect_journal(
    home: &Path,
    journal: &RetentionEffectJournalV2,
) -> std::io::Result<()> {
    write_record(home, "journals", &journal.tag, journal)
}
pub(crate) fn save_effect_receipt(
    home: &Path,
    receipt: &RetentionEffectReceiptV2,
) -> std::io::Result<()> {
    write_record(home, "receipts", &receipt.tag, receipt)
}

pub(crate) fn load_effect_journal(
    home: &Path,
    tag: &str,
) -> std::io::Result<Option<RetentionEffectJournalV2>> {
    read_record(home, "journals", tag)
}
pub(crate) fn list_effect_journals(home: &Path) -> std::io::Result<Vec<RetentionEffectJournalV2>> {
    let (dir, path) = state_dir(home, "journals")?;
    let mut records: Vec<RetentionEffectJournalV2> = Vec::new();
    for entry in dir.entries()? {
        if records.len() == MAX_RETENTION_EFFECT_RECORDS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "retention journal inventory exceeds batch limit",
            ));
        }
        let name = entry?.file_name();
        let Some(stem) = name.to_str().and_then(|value| value.strip_suffix(".json")) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid retention journal leaf",
            ));
        };
        if stem.len() != 10 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid retention journal tag",
            ));
        }
        if let Some(record) = read_record(home, "journals", stem)? {
            records.push(record);
        }
    }
    records.sort_by(|left, right| left.tag.cmp(&right.tag));
    Ok(records)
}
pub(crate) fn save_purge_journal(
    home: &Path,
    tag: &str,
    journal: &RetentionPurgeJournalV2,
) -> std::io::Result<()> {
    write_record(home, "purges", tag, journal)
}
pub(crate) fn load_purge_journal(
    home: &Path,
    tag: &str,
) -> std::io::Result<Option<RetentionPurgeJournalV2>> {
    read_record(home, "purges", tag)
}
pub(crate) fn list_effect_receipts(home: &Path) -> std::io::Result<Vec<RetentionEffectReceiptV2>> {
    let (dir, _) = state_dir(home, "receipts")?;
    let mut records: Vec<RetentionEffectReceiptV2> = Vec::new();
    for entry in dir.entries()? {
        if records.len() == MAX_RETENTION_EFFECT_RECORDS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "retention receipt inventory exceeds batch limit",
            ));
        }
        let name = entry?.file_name();
        let Some(tag) = name.to_str().and_then(|value| value.strip_suffix(".json")) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid retention receipt leaf",
            ));
        };
        if let Some(record) = read_record(home, "receipts", tag)? {
            records.push(record);
        }
    }
    records.sort_by(|left, right| left.tag.cmp(&right.tag));
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_execution_fixture_is_explicitly_off_and_does_not_inherit_v1_horizon() {
        let config = DailyRetentionExecutionConfig::default();
        assert_eq!(config.version, DAILY_RETENTION_EXECUTION_VERSION);
        assert!(!config.enabled);
        assert_eq!(
            config.quarantine_grace_days,
            DEFAULT_DAILY_RETENTION_GRACE_DAYS
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn settlement_note_fixture_has_an_explicit_ownership_boundary() {
        let receipt = DailyNoteReceiptV1::new(
            "2026-09-01".into(),
            "a".repeat(64),
            "b".repeat(64),
            "windows:00000003-0000000000000003".into(),
            "windows:00000001-0000000000000001".into(),
            "windows:00000002-0000000000000002".into(),
        );
        let json = serde_json::to_value(&receipt).unwrap();
        assert_eq!(json["note_leaf"], "2026-09-01.md");
        assert_eq!(json["marker_generation"], "2026-09-01");
        // A look-alike legacy document has no receipt fields to deserialize
        // into and therefore cannot be upgraded by byte equality alone.
        assert!(
            serde_json::from_value::<DailyNoteReceiptV1>(serde_json::json!({
                "schema_version": 1, "tag": "2026-09-01", "note_sha256": "b"
            }))
            .is_err()
        );
    }
}
