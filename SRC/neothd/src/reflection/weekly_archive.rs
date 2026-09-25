//! Crash-safe, canonical weekly-reflection archive foundation.
//!
//! The legacy weekly JSONL reader remains intentionally tolerant for operator
//! history. This module is the producer boundary: it holds a dedicated
//! capability-bound lock, freezes one intent, and replaces the complete JSONL
//! atomically when adding its one producer-keyed record.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::proactive::ProactiveItem;
use crate::skills::store::{
    BoundChildObject, PrivateChildCommit, atomic_write_private_child_create_new_reported,
    atomic_write_private_child_reported, open_absolute_bound_directory,
    open_or_create_bound_lockfile, open_or_create_private_child_dir, read_regular_file_bounded,
};

use super::WeeklyReflection;

const INTENT_SCHEMA_VERSION: u16 = 1;
const INTENTS_DIR: &str = "weekly-intents";
const ARCHIVE_LOCK_FILE: &str = "weekly-archive-v1.lock";
const MAX_INTENT_BYTES: usize = 128 * 1024;
const MAX_INTENT_INVENTORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_INTENT_INVENTORY_RECORDS: usize = 4096;
const MAX_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ARCHIVE_LINE_BYTES: usize = 256 * 1024;
const MAX_ARCHIVE_RECORDS: usize = 1024;
const MAX_TOPICS: usize = 16;
const MAX_TOPIC_BYTES: usize = 4 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const PRODUCER_KEY_HEX_LEN: usize = 64;

// Advisory locking is platform-dependent for repeated handles in one process.
// This guard precedes the retained no-follow OS lock and spans the caller's
// archive/queue/tick-state sequence.
static WEEKLY_ARCHIVE_PROCESS_LOCK: Mutex<()> = Mutex::new(());

/// Frozen input offered only when no prior intent exists for a canonical week.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WeeklyArchiveCandidate {
    pub(crate) generated_ts_unix: i64,
    pub(crate) topics: Vec<String>,
    pub(crate) body: String,
}

/// Immutable recovery authority for one weekly producer run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WeeklyArchiveIntent {
    pub(crate) schema_version: u16,
    pub(crate) iso_week_tag: String,
    pub(crate) generated_ts_unix: i64,
    pub(crate) topics: Vec<String>,
    pub(crate) body: String,
    pub(crate) queue_dedup_key: String,
    pub(crate) producer_key: String,
}

/// Exact archive result. A durability-unknown publication has happened and
/// must be reconciled by a later strict scan, never blindly retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WeeklyArchiveAppendOutcome {
    AlreadyArchived,
    ArchivedAndSynced,
    ArchivedDurabilityUnknown,
}

/// Retained session for one canonical week. It is intentionally non-consuming
/// so cron can keep it over intent recovery, archive settlement, same-key
/// queue reconciliation, and tick-state publication.
pub(crate) struct WeeklyArchiveSession {
    process_lock: Option<MutexGuard<'static, ()>>,
    reflections: cap_std::fs::Dir,
    reflections_display: PathBuf,
    intents: cap_std::fs::Dir,
    intents_display: PathBuf,
    lock_file: Option<std::fs::File>,
    lock_binding: Option<BoundChildObject>,
    iso_week_tag: String,
}

/// Open the dedicated per-home weekly archive guard for one canonical ISO week.
pub(crate) fn open_weekly_archive_session(
    home: &Path,
    iso_week_tag: &str,
) -> Result<WeeklyArchiveSession> {
    anyhow::ensure!(
        home.is_absolute(),
        "weekly archive home must be an explicit absolute path"
    );
    validate_iso_week_tag(iso_week_tag)?;
    let process_lock = WEEKLY_ARCHIVE_PROCESS_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("weekly archive process lock is poisoned"))?;
    let home = open_absolute_bound_directory(home, true, "weekly archive home")?
        .context("open explicit weekly archive home")?;
    let reflections_display = home.display_path.join("reflections");
    let reflections = open_or_create_private_child_dir(
        &home.dir,
        OsStr::new("reflections"),
        &reflections_display,
    )?;
    let intents_display = reflections_display.join(INTENTS_DIR);
    let intents =
        open_or_create_private_child_dir(&reflections, OsStr::new(INTENTS_DIR), &intents_display)?;
    let lock_display = reflections_display.join(ARCHIVE_LOCK_FILE);
    let (lock_file, lock_binding) =
        open_or_create_bound_lockfile(&reflections, OsStr::new(ARCHIVE_LOCK_FILE), &lock_display)?;
    lock_file.lock().context("lock weekly archive session")?;
    Ok(WeeklyArchiveSession {
        process_lock: Some(process_lock),
        reflections,
        reflections_display,
        intents,
        intents_display,
        lock_file: Some(lock_file),
        lock_binding: Some(lock_binding),
        iso_week_tag: iso_week_tag.to_owned(),
    })
}

impl Drop for WeeklyArchiveSession {
    fn drop(&mut self) {
        let unlock = self.lock_file.as_ref().map(std::fs::File::unlock);
        drop(self.lock_binding.take());
        drop(self.lock_file.take());
        drop(unlock);
        drop(self.process_lock.take());
    }
}

impl WeeklyArchiveSession {
    /// Read an established intent before consulting views or current topics.
    pub(crate) fn load_existing_intent(&mut self) -> Result<Option<WeeklyArchiveIntent>> {
        self.ensure_lock()?;
        self.load_intent_for_week(&self.iso_week_tag)
    }

    /// Inventory every owned, canonical intent through `current_week` under
    /// this one retained session lock. Future intents are still strictly read
    /// and validated so corruption cannot be hidden behind a calendar filter,
    /// but they are not returned for recovery.
    pub(crate) fn list_established_intents_through(
        &mut self,
        current_week: &str,
    ) -> Result<Vec<WeeklyArchiveIntent>> {
        validate_iso_week_tag(current_week)?;
        self.ensure_lock()?;
        let mut aggregate_bytes = 0usize;
        let mut intents = Vec::new();
        for entry in self
            .intents
            .entries()
            .context("enumerate weekly archive intents")?
        {
            let entry = entry.context("read weekly archive intent directory entry")?;
            let name = entry.file_name();
            let Some(week) = owned_week_from_intent_leaf(&name)? else {
                continue;
            };
            anyhow::ensure!(
                intents.len() < MAX_INTENT_INVENTORY_RECORDS,
                "weekly archive intent inventory exceeds the {MAX_INTENT_INVENTORY_RECORDS}-record limit"
            );
            let display = self.intents_display.join(&name);
            let bytes = read_regular_file_bounded(&self.intents, &name, &display, MAX_INTENT_BYTES)
                .context("read owned weekly archive intent fail closed")?;
            aggregate_bytes = aggregate_bytes
                .checked_add(bytes.len())
                .context("weekly archive intent inventory byte count overflow")?;
            anyhow::ensure!(
                aggregate_bytes <= MAX_INTENT_INVENTORY_BYTES,
                "weekly archive intent inventory exceeds the {}-byte aggregate limit",
                MAX_INTENT_INVENTORY_BYTES
            );
            intents.push(parse_intent(&bytes, &week)?);
        }
        intents.sort_by(|left, right| left.iso_week_tag.cmp(&right.iso_week_tag));
        Ok(intents
            .into_iter()
            .filter(|intent| intent.iso_week_tag.as_str() <= current_week)
            .collect())
    }

    /// Select one established intent without opening a second process or OS
    /// lock. The leaf is re-read and validated before the session moves its
    /// archive target to the selected week.
    pub(crate) fn select_established_week_through(
        &mut self,
        iso_week_tag: &str,
        current_week: &str,
    ) -> Result<WeeklyArchiveIntent> {
        validate_iso_week_tag(iso_week_tag)?;
        validate_iso_week_tag(current_week)?;
        anyhow::ensure!(
            iso_week_tag <= current_week,
            "weekly archive recovery must not select a future week"
        );
        self.ensure_lock()?;
        let intent = self
            .load_intent_for_week(iso_week_tag)?
            .context("selected weekly archive intent is absent")?;
        self.iso_week_tag = iso_week_tag.to_owned();
        Ok(intent)
    }

    fn load_intent_for_week(&self, week: &str) -> Result<Option<WeeklyArchiveIntent>> {
        let leaf = intent_leaf_for(week);
        let display = self.intents_display.join(&leaf);
        let bytes = match read_regular_file_bounded(
            &self.intents,
            OsStr::new(&leaf),
            &display,
            MAX_INTENT_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error) if error_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error).context("read weekly archive intent fail closed"),
        };
        Ok(Some(parse_intent(&bytes, week)?))
    }

    /// Persist a new valid candidate exactly once, or return the established
    /// immutable intent verbatim. The session lock closes the normal producer
    /// race; an unexpected competing create is re-read and validated.
    pub(crate) fn load_or_create_intent(
        &mut self,
        candidate: WeeklyArchiveCandidate,
    ) -> Result<WeeklyArchiveIntent> {
        if let Some(existing) = self.load_existing_intent()? {
            return Ok(existing);
        }
        let intent = WeeklyArchiveIntent::from_candidate(&self.iso_week_tag, candidate)?;
        let bytes = serialize_intent(&intent)?;
        self.ensure_lock()?;
        let leaf = self.intent_leaf();
        let intent_path = self.intents_display.join(&leaf);
        match atomic_write_private_child_create_new_reported(
            &self.intents,
            OsStr::new(&leaf),
            &intent_path,
            &bytes,
        ) {
            Ok(PrivateChildCommit::PublishedAndSynced) => Ok(intent),
            Ok(PrivateChildCommit::PublishedDurabilityUnknown(reason)) => {
                tracing::warn!(%reason, intent = %intent_path.display(), "weekly archive intent published with unknown durability");
                // The canonical intent may already be live. Do not hand an
                // unconfirmed in-memory candidate to the queue/archive path.
                Err(anyhow::anyhow!(
                    "weekly archive intent publication durability is unknown; recover by reloading the intent"
                ))
            }
            Err(error) => {
                let error = anyhow::Error::new(error);
                if error_is_already_exists(&error) {
                    self.load_existing_intent()?
                        .context("weekly archive intent appeared but could not be read")
                } else {
                    Err(error).context(
                        "weekly archive intent was not published before the reported failure",
                    )
                }
            }
        }
    }

    /// Strictly scan and atomically add the one canonical producer record.
    /// Historical keyless lines are retained byte-for-byte and never count as
    /// this producer's receipt.
    pub(crate) fn append_once(
        &mut self,
        intent: &WeeklyArchiveIntent,
    ) -> Result<WeeklyArchiveAppendOutcome> {
        self.ensure_intent(intent)?;
        let leaf = self.archive_leaf();
        let archive_path = self.reflections_display.join(&leaf);
        let existing = match read_regular_file_bounded(
            &self.reflections,
            OsStr::new(&leaf),
            &archive_path,
            MAX_ARCHIVE_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error) if error_is_not_found(&error) => Vec::new(),
            Err(error) => return Err(error).context("read weekly reflection archive fail closed"),
        };
        let expected = intent.to_reflection();
        let scan = scan_archive(&existing, &self.iso_week_tag, &expected)?;
        if scan.already_archived {
            return Ok(WeeklyArchiveAppendOutcome::AlreadyArchived);
        }
        anyhow::ensure!(
            scan.record_count < MAX_ARCHIVE_RECORDS,
            "weekly archive has reached the {MAX_ARCHIVE_RECORDS}-record limit"
        );
        let mut replacement = existing;
        let record =
            serde_json::to_vec(&expected).context("serialize canonical weekly reflection")?;
        anyhow::ensure!(
            record.len() <= MAX_ARCHIVE_LINE_BYTES,
            "canonical weekly reflection exceeds per-line archive budget"
        );
        let replacement_len = replacement
            .len()
            .checked_add(record.len())
            .and_then(|length| length.checked_add(1))
            .context("weekly archive length overflow")?;
        anyhow::ensure!(
            replacement_len <= MAX_ARCHIVE_BYTES,
            "weekly archive exceeds the {}-byte budget",
            MAX_ARCHIVE_BYTES
        );
        replacement.extend_from_slice(&record);
        replacement.push(b'\n');
        self.ensure_lock()?;
        match atomic_write_private_child_reported(
            &self.reflections,
            OsStr::new(&leaf),
            &archive_path,
            &replacement,
        )? {
            PrivateChildCommit::PublishedAndSynced => {
                Ok(WeeklyArchiveAppendOutcome::ArchivedAndSynced)
            }
            PrivateChildCommit::PublishedDurabilityUnknown(reason) => {
                tracing::warn!(%reason, archive = %archive_path.display(), "weekly archive publication durability is unknown");
                Ok(WeeklyArchiveAppendOutcome::ArchivedDurabilityUnknown)
            }
        }
    }

    fn ensure_lock(&self) -> Result<()> {
        let binding = self
            .lock_binding
            .as_ref()
            .context("weekly archive session lock is unavailable")?;
        anyhow::ensure!(
            binding.matches_regular_file_child_readonly(
                &self.reflections,
                OsStr::new(ARCHIVE_LOCK_FILE),
                &self.reflections_display.join(ARCHIVE_LOCK_FILE),
            )?,
            "weekly archive lock changed before publication"
        );
        Ok(())
    }

    fn ensure_intent(&mut self, intent: &WeeklyArchiveIntent) -> Result<()> {
        validate_intent(intent, &self.iso_week_tag)?;
        let established = self
            .load_existing_intent()?
            .context("weekly archive intent must be persisted before archive settlement")?;
        anyhow::ensure!(
            established == *intent,
            "weekly archive append input does not match the persisted canonical intent"
        );
        Ok(())
    }

    fn intent_leaf(&self) -> String {
        intent_leaf_for(&self.iso_week_tag)
    }

    fn archive_leaf(&self) -> String {
        format!("{}.jsonl", self.iso_week_tag)
    }
}

fn intent_leaf_for(iso_week_tag: &str) -> String {
    format!("{iso_week_tag}.json")
}

fn owned_week_from_intent_leaf(name: &OsStr) -> Result<Option<String>> {
    let Some(name) = name.to_str() else {
        return Ok(None);
    };
    let Some(week) = name.strip_suffix(".json") else {
        return Ok(None);
    };
    let bytes = week.as_bytes();
    let looks_owned = bytes.len() == 8
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5] == b'W';
    if !looks_owned {
        return Ok(None);
    }
    validate_iso_week_tag(week)
        .with_context(|| format!("owned weekly archive intent leaf is not canonical: {name:?}"))?;
    Ok(Some(week.to_owned()))
}

impl WeeklyArchiveIntent {
    fn from_candidate(iso_week_tag: &str, candidate: WeeklyArchiveCandidate) -> Result<Self> {
        validate_iso_week_tag(iso_week_tag)?;
        validate_candidate(&candidate)?;
        let queue_dedup_key = format!("reflection:weekly:{iso_week_tag}");
        let producer_key = producer_key(iso_week_tag, &candidate.topics, &candidate.body);
        Ok(Self {
            schema_version: INTENT_SCHEMA_VERSION,
            iso_week_tag: iso_week_tag.to_owned(),
            generated_ts_unix: candidate.generated_ts_unix,
            topics: candidate.topics,
            body: candidate.body,
            queue_dedup_key,
            producer_key,
        })
    }

    /// Build the queue item from the frozen body rather than recomputing it
    /// from later topic samples.
    pub(crate) fn to_proactive_item(&self, scheduled_for_unix: i64) -> ProactiveItem {
        ProactiveItem {
            priority: 50,
            dedup_key: self.queue_dedup_key.clone(),
            channel: String::new(),
            account_id: None,
            account_binding: None,
            source: "g_01_mini".to_owned(),
            body: self.body.clone(),
            scheduled_for_unix,
            is_failure: false,
            expires_unix: 0,
        }
    }

    pub(crate) fn to_reflection(&self) -> WeeklyReflection {
        WeeklyReflection {
            iso_week_tag: self.iso_week_tag.clone(),
            generated_ts_unix: self.generated_ts_unix,
            topics: self.topics.clone(),
            body: self.body.clone(),
            tags: Vec::new(),
            producer_key: Some(self.producer_key.clone()),
        }
    }
}

fn serialize_intent(intent: &WeeklyArchiveIntent) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(intent).context("serialize weekly archive intent")?;
    anyhow::ensure!(
        bytes.len() <= MAX_INTENT_BYTES,
        "weekly archive intent exceeds the {}-byte budget",
        MAX_INTENT_BYTES
    );
    Ok(bytes)
}

fn parse_intent(bytes: &[u8], expected_week: &str) -> Result<WeeklyArchiveIntent> {
    let intent = serde_json::from_slice::<WeeklyArchiveIntent>(bytes)
        .context("parse weekly archive intent fail closed")?;
    validate_intent(&intent, expected_week)?;
    Ok(intent)
}

/// Check a producer-owned archive record against its persisted immutable
/// intent. This read-only consumer boundary never creates producer state.
pub(crate) fn validate_archived_weekly_intent(
    bytes: &[u8],
    record: &WeeklyReflection,
) -> Result<()> {
    anyhow::ensure!(
        bytes.len() <= MAX_INTENT_BYTES,
        "weekly intent exceeds its byte limit"
    );
    let intent = parse_intent(bytes, &record.iso_week_tag)?;
    anyhow::ensure!(
        intent.to_reflection() == *record,
        "weekly archive record differs from its established intent"
    );
    Ok(())
}

fn validate_intent(intent: &WeeklyArchiveIntent, expected_week: &str) -> Result<()> {
    anyhow::ensure!(
        intent.schema_version == INTENT_SCHEMA_VERSION,
        "unsupported weekly archive intent schema version {}",
        intent.schema_version
    );
    validate_iso_week_tag(&intent.iso_week_tag)?;
    anyhow::ensure!(
        intent.iso_week_tag == expected_week,
        "weekly archive intent week {:?} does not match requested week {:?}",
        intent.iso_week_tag,
        expected_week
    );
    validate_candidate(&WeeklyArchiveCandidate {
        generated_ts_unix: intent.generated_ts_unix,
        topics: intent.topics.clone(),
        body: intent.body.clone(),
    })?;
    anyhow::ensure!(
        intent.queue_dedup_key == format!("reflection:weekly:{expected_week}"),
        "weekly archive intent queue dedup key does not bind its week"
    );
    anyhow::ensure!(
        intent.producer_key == producer_key(expected_week, &intent.topics, &intent.body),
        "weekly archive intent producer key does not bind its canonical content"
    );
    Ok(())
}

fn validate_candidate(candidate: &WeeklyArchiveCandidate) -> Result<()> {
    anyhow::ensure!(
        !candidate.topics.is_empty() && candidate.topics.len() <= MAX_TOPICS,
        "weekly archive intent must contain 1..={MAX_TOPICS} topics"
    );
    let mut topic_total = 0usize;
    for topic in &candidate.topics {
        anyhow::ensure!(
            !topic.is_empty() && topic.len() <= MAX_TOPIC_BYTES,
            "weekly archive topic exceeds its bounded schema"
        );
        topic_total = topic_total
            .checked_add(topic.len())
            .context("weekly archive topic length overflow")?;
    }
    anyhow::ensure!(
        topic_total <= MAX_BODY_BYTES,
        "weekly archive topics exceed aggregate budget"
    );
    anyhow::ensure!(
        !candidate.body.is_empty() && candidate.body.len() <= MAX_BODY_BYTES,
        "weekly archive body exceeds its bounded schema"
    );
    Ok(())
}

pub(crate) fn validate_iso_week_tag(iso_week_tag: &str) -> Result<()> {
    let bytes = iso_week_tag.as_bytes();
    anyhow::ensure!(
        bytes.len() == 8
            && bytes[4] == b'-'
            && bytes[5] == b'W'
            && bytes[..4].iter().all(u8::is_ascii_digit)
            && bytes[6..].iter().all(u8::is_ascii_digit),
        "weekly archive tag must be canonical YYYY-Www: {iso_week_tag:?}"
    );
    let year = iso_week_tag[..4]
        .parse::<i32>()
        .context("parse weekly archive ISO year")?;
    let week = iso_week_tag[6..]
        .parse::<u32>()
        .context("parse weekly archive ISO week")?;
    anyhow::ensure!(
        chrono::NaiveDate::from_isoywd_opt(year, week, chrono::Weekday::Mon).is_some(),
        "weekly archive tag is not a real ISO week: {iso_week_tag:?}"
    );
    Ok(())
}

/// Validate the self-binding of an archived record without creating or
/// recovering a producer intent. Legacy records have no producer key.
pub(crate) fn validate_weekly_reflection_producer_key(record: &WeeklyReflection) -> Result<()> {
    if let Some(key) = record.producer_key.as_deref() {
        anyhow::ensure!(
            valid_producer_key(key)
                && key == producer_key(&record.iso_week_tag, &record.topics, &record.body),
            "weekly reflection producer key does not match its archived content"
        );
    }
    Ok(())
}

fn producer_key(iso_week_tag: &str, topics: &[String], body: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.weekly-reflection.producer-key.v1\0");
    update_length_prefixed(&mut digest, iso_week_tag.as_bytes());
    for topic in topics {
        update_length_prefixed(&mut digest, topic.as_bytes());
    }
    digest.update((topics.len() as u64).to_be_bytes());
    update_length_prefixed(&mut digest, body.as_bytes());
    hex::encode(digest.finalize())
}

fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

struct ArchiveScan {
    record_count: usize,
    already_archived: bool,
}

fn scan_archive(
    bytes: &[u8],
    expected_week: &str,
    expected: &WeeklyReflection,
) -> Result<ArchiveScan> {
    if bytes.is_empty() {
        return Ok(ArchiveScan {
            record_count: 0,
            already_archived: false,
        });
    }
    anyhow::ensure!(
        bytes.ends_with(b"\n"),
        "weekly archive has a truncated final JSONL record"
    );
    let body = std::str::from_utf8(bytes).context("weekly archive must be valid UTF-8")?;
    let mut producer_keys = HashSet::new();
    let mut found = false;
    for (index, raw) in body.split_inclusive('\n').enumerate() {
        let line = raw
            .strip_suffix('\n')
            .expect("split_inclusive retains delimiter");
        let line = line.strip_suffix('\r').unwrap_or(line);
        anyhow::ensure!(
            !line.is_empty() && line.len() <= MAX_ARCHIVE_LINE_BYTES,
            "weekly archive line {} is blank or exceeds the bounded line limit",
            index + 1
        );
        anyhow::ensure!(
            index < MAX_ARCHIVE_RECORDS,
            "weekly archive exceeds the {MAX_ARCHIVE_RECORDS}-record limit"
        );
        let reflection = serde_json::from_str::<WeeklyReflection>(line)
            .with_context(|| format!("parse weekly archive line {} fail closed", index + 1))?;
        anyhow::ensure!(
            reflection.iso_week_tag == expected_week,
            "weekly archive line {} belongs to a different week",
            index + 1
        );
        if let Some(key) = reflection.producer_key.as_deref() {
            anyhow::ensure!(
                valid_producer_key(key),
                "weekly archive line {} has invalid producer key",
                index + 1
            );
            anyhow::ensure!(
                producer_keys.insert(key.to_owned()),
                "weekly archive contains duplicate producer key at line {}",
                index + 1
            );
            anyhow::ensure!(
                key == expected
                    .producer_key
                    .as_deref()
                    .expect("canonical producer key"),
                "weekly archive contains an incompatible producer-keyed record"
            );
            anyhow::ensure!(
                reflection == *expected,
                "weekly archive producer receipt does not match canonical intent"
            );
            found = true;
        }
    }
    Ok(ArchiveScan {
        record_count: body.lines().count(),
        already_archived: found,
    })
}

fn valid_producer_key(key: &str) -> bool {
    key.len() == PRODUCER_KEY_HEX_LEN
        && key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn error_is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

fn error_is_already_exists(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::canonical_tempdir as tempdir;

    fn candidate() -> WeeklyArchiveCandidate {
        WeeklyArchiveCandidate {
            generated_ts_unix: 1_700_000_000,
            topics: vec!["rust".into(), "memory".into()],
            body: "Du hast diese Woche an rust und memory gearbeitet.".into(),
        }
    }

    fn prepare_intent_directory(home: &Path) {
        drop(open_weekly_archive_session(home, "2026-W21").unwrap());
    }

    fn write_owned_intent(home: &Path, week: &str, candidate: WeeklyArchiveCandidate) {
        let intent = WeeklyArchiveIntent::from_candidate(week, candidate).unwrap();
        std::fs::write(
            home.join("reflections/weekly-intents")
                .join(intent_leaf_for(week)),
            serialize_intent(&intent).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn freezes_once_and_archives_once_with_legacy_records_preserved() {
        let home = tempdir().unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let intent = session.load_or_create_intent(candidate()).unwrap();
        let legacy = WeeklyReflection {
            iso_week_tag: "2026-W21".into(),
            generated_ts_unix: 1,
            topics: vec!["old".into()],
            body: "old".into(),
            tags: vec![],
            producer_key: None,
        };
        let archive = home.path().join("reflections/2026-W21.jsonl");
        std::fs::write(
            &archive,
            format!("{}\n", serde_json::to_string(&legacy).unwrap()),
        )
        .unwrap();

        assert_eq!(
            session.append_once(&intent).unwrap(),
            WeeklyArchiveAppendOutcome::ArchivedAndSynced
        );
        assert_eq!(
            session.append_once(&intent).unwrap(),
            WeeklyArchiveAppendOutcome::AlreadyArchived
        );
        let records = std::fs::read_to_string(archive).unwrap();
        assert!(records.starts_with(&serde_json::to_string(&legacy).unwrap()));
        assert_eq!(records.lines().count(), 2);
    }

    #[test]
    fn preexisting_intent_is_recovery_authority() {
        let home = tempdir().unwrap();
        let mut first = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let intent = first.load_or_create_intent(candidate()).unwrap();
        drop(first);
        let mut retry = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let recovered = retry.load_existing_intent().unwrap().unwrap();
        assert_eq!(recovered, intent);
        let changed = WeeklyArchiveCandidate {
            body: "changed".into(),
            ..candidate()
        };
        assert_eq!(retry.load_or_create_intent(changed).unwrap(), intent);
    }

    #[test]
    fn malformed_or_truncated_archive_fails_closed_without_rewrite() {
        let home = tempdir().unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let intent = session.load_or_create_intent(candidate()).unwrap();
        let archive = home.path().join("reflections/2026-W21.jsonl");
        let original = b"{bad json";
        std::fs::write(&archive, original).unwrap();
        assert!(session.append_once(&intent).is_err());
        assert_eq!(std::fs::read(archive).unwrap(), original);
    }

    #[test]
    fn wrong_week_and_duplicate_producer_key_fail_closed() {
        let home = tempdir().unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let intent = session.load_or_create_intent(candidate()).unwrap();
        let archive = home.path().join("reflections/2026-W21.jsonl");
        let mut wrong = intent.to_reflection();
        wrong.iso_week_tag = "2026-W22".into();
        std::fs::write(
            &archive,
            format!("{}\n", serde_json::to_string(&wrong).unwrap()),
        )
        .unwrap();
        assert!(session.append_once(&intent).is_err());
        let exact = intent.to_reflection();
        std::fs::write(
            &archive,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&exact).unwrap(),
                serde_json::to_string(&exact).unwrap()
            ),
        )
        .unwrap();
        assert!(session.append_once(&intent).is_err());
    }

    #[test]
    fn archive_record_cap_allows_replay_at_limit_but_rejects_a_new_line() {
        let home = tempdir().unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let intent = session.load_or_create_intent(candidate()).unwrap();
        let legacy = WeeklyReflection {
            iso_week_tag: "2026-W21".into(),
            generated_ts_unix: 1,
            topics: vec!["old".into()],
            body: "old".into(),
            tags: vec![],
            producer_key: None,
        };
        let line = format!("{}\n", serde_json::to_string(&legacy).unwrap());
        let archive = home.path().join("reflections/2026-W21.jsonl");
        let at_limit = line.repeat(MAX_ARCHIVE_RECORDS);
        std::fs::write(&archive, &at_limit).unwrap();
        assert!(session.append_once(&intent).is_err());
        assert_eq!(std::fs::read_to_string(&archive).unwrap(), at_limit);

        let canonical = serde_json::to_string(&intent.to_reflection()).unwrap();
        let replayable = format!("{}{}\n", line.repeat(MAX_ARCHIVE_RECORDS - 1), canonical);
        std::fs::write(&archive, replayable).unwrap();
        assert_eq!(
            session.append_once(&intent).unwrap(),
            WeeklyArchiveAppendOutcome::AlreadyArchived
        );
    }

    #[test]
    fn published_unknowns_recover_by_reading_canonical_bytes() {
        let home = tempdir().unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let intent_path = home.path().join("reflections/weekly-intents/2026-W21.json");
        crate::skills::store::fail_private_child_post_commit_validation_for_test(&intent_path);
        assert!(session.load_or_create_intent(candidate()).is_err());
        let intent = session.load_existing_intent().unwrap().unwrap();

        let archive_path = home.path().join("reflections/2026-W21.jsonl");
        crate::skills::store::fail_private_child_post_commit_validation_for_test(&archive_path);
        assert_eq!(
            session.append_once(&intent).unwrap(),
            WeeklyArchiveAppendOutcome::ArchivedDurabilityUnknown
        );
        assert_eq!(
            session.append_once(&intent).unwrap(),
            WeeklyArchiveAppendOutcome::AlreadyArchived
        );
    }

    #[cfg(unix)]
    #[test]
    fn intent_and_archive_links_are_refused() {
        let home = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let intent = session.load_or_create_intent(candidate()).unwrap();
        let archive = home.path().join("reflections/2026-W21.jsonl");
        let sentinel = outside.path().join("sentinel");
        std::fs::write(&sentinel, "keep").unwrap();
        std::os::unix::fs::symlink(&sentinel, &archive).unwrap();
        assert!(session.append_once(&intent).is_err());
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "keep");

        drop(session);
        let intent_link = home.path().join("reflections/weekly-intents/2026-W22.json");
        std::os::unix::fs::symlink(&sentinel, &intent_link).unwrap();
        let mut second = open_weekly_archive_session(home.path(), "2026-W22").unwrap();
        assert!(second.load_existing_intent().is_err());
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "keep");
    }

    #[test]
    fn invalid_weeks_and_bounded_candidates_are_rejected() {
        let home = tempdir().unwrap();
        assert!(open_weekly_archive_session(home.path(), "2026-W54").is_err());
        assert!(open_weekly_archive_session(home.path(), "+2026-W21").is_err());
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        let too_large = WeeklyArchiveCandidate {
            body: "x".repeat(MAX_BODY_BYTES + 1),
            ..candidate()
        };
        assert!(session.load_or_create_intent(too_large).is_err());
    }

    #[test]
    fn inventory_is_oldest_first_ignores_foreign_and_selects_without_relocking() {
        let home = tempdir().unwrap();
        prepare_intent_directory(home.path());
        write_owned_intent(home.path(), "2026-W20", candidate());
        write_owned_intent(home.path(), "2026-W21", candidate());
        write_owned_intent(home.path(), "2026-W22", candidate());
        std::fs::write(
            home.path()
                .join("reflections/weekly-intents/operator-note.json"),
            b"foreign",
        )
        .unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();

        let weeks = session
            .list_established_intents_through("2026-W21")
            .unwrap()
            .into_iter()
            .map(|intent| intent.iso_week_tag)
            .collect::<Vec<_>>();
        assert_eq!(weeks, vec!["2026-W20", "2026-W21"]);
        assert_eq!(
            session
                .select_established_week_through("2026-W20", "2026-W21")
                .unwrap()
                .iso_week_tag,
            "2026-W20"
        );
    }

    #[test]
    fn inventory_rejects_malformed_owned_intent_and_oversized_read() {
        let home = tempdir().unwrap();
        prepare_intent_directory(home.path());
        let intents = home.path().join("reflections/weekly-intents");
        std::fs::write(intents.join("2026-W20.json"), b"{bad json}").unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        assert!(
            session
                .list_established_intents_through("2026-W21")
                .is_err()
        );
        drop(session);

        std::fs::write(
            intents.join("2026-W20.json"),
            vec![b'x'; MAX_INTENT_BYTES + 1],
        )
        .unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        assert!(
            session
                .list_established_intents_through("2026-W21")
                .is_err()
        );
    }

    #[test]
    fn inventory_enforces_aggregate_budget() {
        let home = tempdir().unwrap();
        prepare_intent_directory(home.path());
        let mut written = 0usize;
        for year in 2026..=2032 {
            for week in 1..=53 {
                if chrono::NaiveDate::from_isoywd_opt(year, week, chrono::Weekday::Mon).is_none() {
                    continue;
                }
                let tag = format!("{year:04}-W{week:02}");
                write_owned_intent(
                    home.path(),
                    &tag,
                    WeeklyArchiveCandidate {
                        body: "x".repeat(MAX_BODY_BYTES),
                        ..candidate()
                    },
                );
                written += 1;
                if written > MAX_INTENT_INVENTORY_BYTES / MAX_BODY_BYTES + 1 {
                    break;
                }
            }
            if written > MAX_INTENT_INVENTORY_BYTES / MAX_BODY_BYTES + 1 {
                break;
            }
        }
        let mut session = open_weekly_archive_session(home.path(), "2032-W52").unwrap();
        assert!(
            session
                .list_established_intents_through("2032-W52")
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn inventory_rejects_owned_intent_link() {
        let home = tempdir().unwrap();
        let outside = tempdir().unwrap();
        prepare_intent_directory(home.path());
        let sentinel = outside.path().join("intent.json");
        std::fs::write(&sentinel, b"keep").unwrap();
        std::os::unix::fs::symlink(
            &sentinel,
            home.path().join("reflections/weekly-intents/2026-W20.json"),
        )
        .unwrap();
        let mut session = open_weekly_archive_session(home.path(), "2026-W21").unwrap();
        assert!(
            session
                .list_established_intents_through("2026-W21")
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "keep");
    }
}
