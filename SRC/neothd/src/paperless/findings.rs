//! W1163 — private, home-bound Paperless threat-finding evidence.
//!
//! This store deliberately retains only the metadata needed by the scoped
//! recent-findings reader. OCR bodies and sanitizer marker patterns may contain
//! hostile document text, so neither is represented in the durable schema.

use std::{
    cmp::Ordering,
    ffi::OsStr,
    path::Path,
    sync::Mutex,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    security::{
        ingress_sanitizer::Finding,
        paperless_ingest::OcrSource,
    },
    skills::store,
};

const STORE_DIRECTORY: &str = "paperless_findings";
const STATE_FILE: &str = "findings-v1.json";
const LOCK_FILE: &str = "findings-v1.lock";
const SCHEMA_VERSION: u8 = 1;
const MAX_RECORDS: usize = 1_000;
const MAX_STORE_BYTES: usize = 1024 * 1024;
const MAX_DOCUMENT_ID_BYTES: usize = 256;
const MAX_RECENT_LIMIT: usize = 100;

// OS locks serialize independent processes. This guard also makes the
// read-modify-write transaction unambiguous for concurrent callers in one
// process on platforms whose advisory locks are process-scoped.
static PROCESS_STORE_LOCK: Mutex<()> = Mutex::new(());

/// A redacted threat category. Marker patterns never cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    PromptInjectionMarker,
    PersonaOverrideAttempt,
}

/// One privacy-minimal, durable Paperless quarantine record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingRecord {
    pub occurred_unix: u64,
    pub document_id: String,
    #[serde(rename = "ocr_source")]
    pub source: OcrSource,
    pub raw_input_hash: String,
    pub finding_kinds: Vec<FindingKind>,
}

/// A bounded newest-first view of records at or after a requested timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecentFindings {
    pub findings: Vec<FindingRecord>,
    pub total: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingStore {
    schema_version: u8,
    records: Vec<FindingRecord>,
}

impl Default for FindingStore {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            records: Vec::new(),
        }
    }
}

/// Persist threat-only quarantine evidence beneath the explicitly supplied
/// instance home.
///
/// A clean sanitizer result, or findings limited to normalization/control
/// diagnostics, is a successful no-op. The early return happens before any
/// directory or file is opened, so it cannot create store state.
pub fn record_quarantine_at(
    home: &Path,
    source: OcrSource,
    document_id: &str,
    raw_input_hash: &str,
    findings: &[Finding],
    occurred_unix: u64,
) -> Result<()> {
    let finding_kinds = redacted_finding_kinds(findings);
    if finding_kinds.is_empty() {
        return Ok(());
    }
    validate_document_id(document_id)?;
    validate_raw_input_hash(raw_input_hash)?;

    let _process_guard = PROCESS_STORE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("paperless findings process lock is poisoned"))?;
    let home = store::open_absolute_bound_directory(home, true, "paperless findings home")?
        .context("paperless findings home could not be opened")?;
    let store_path = home.display_path.join(STORE_DIRECTORY);
    let directory = store::open_or_create_private_child_dir(
        &home.dir,
        OsStr::new(STORE_DIRECTORY),
        &store_path,
    )?;
    let lock_path = store_path.join(LOCK_FILE);
    let (lock, lock_binding) =
        store::open_or_create_bound_lockfile(&directory, OsStr::new(LOCK_FILE), &lock_path)?;
    lock.lock().context("lock paperless findings store")?;

    let mut state = load_store(&directory, &store_path)?.unwrap_or_default();
    anyhow::ensure!(
        state.records.len() < MAX_RECORDS,
        "paperless findings store reached its {MAX_RECORDS}-record evidence cap"
    );
    state.records.push(FindingRecord {
        occurred_unix,
        document_id: document_id.to_owned(),
        source,
        raw_input_hash: raw_input_hash.to_owned(),
        finding_kinds,
    });
    validate_store(&state)?;
    anyhow::ensure!(
        lock_binding.matches_regular_file_child_readonly(
            &directory,
            OsStr::new(LOCK_FILE),
            &lock_path,
        )?,
        "paperless findings store lock changed before commit"
    );
    persist_store(&directory, &store_path, &state)
}

/// Return a bounded, deterministic, redacted view from the explicitly
/// supplied instance home. A missing home, store directory, or state file is
/// an empty store; any recognised existing state that is malformed or invalid
/// fails closed.
pub fn recent_at(home: &Path, since_unix: u64, limit: usize) -> Result<RecentFindings> {
    anyhow::ensure!(
        (1..=MAX_RECENT_LIMIT).contains(&limit),
        "paperless findings limit must be in 1..={MAX_RECENT_LIMIT}"
    );
    let Some(home) = store::open_absolute_bound_directory(home, false, "paperless findings home")?
    else {
        return Ok(empty_recent_findings());
    };
    let store_path = home.display_path.join(STORE_DIRECTORY);
    let Some(directory) = store::open_real_child_dir_if_present(
        &home.dir,
        OsStr::new(STORE_DIRECTORY),
        &store_path,
    )?
    else {
        return Ok(empty_recent_findings());
    };
    let Some(state) = load_store(&directory, &store_path)? else {
        return Ok(empty_recent_findings());
    };

    let mut findings: Vec<FindingRecord> = state
        .records
        .into_iter()
        .filter(|record| record.occurred_unix >= since_unix)
        .collect();
    findings.sort_by(compare_newest_first);
    let total = findings.len();
    let truncated = total > limit;
    findings.truncate(limit);
    Ok(RecentFindings {
        findings,
        total,
        truncated,
    })
}

fn empty_recent_findings() -> RecentFindings {
    RecentFindings {
        findings: Vec::new(),
        total: 0,
        truncated: false,
    }
}

fn redacted_finding_kinds(findings: &[Finding]) -> Vec<FindingKind> {
    let mut kinds: Vec<FindingKind> = findings
        .iter()
        .filter_map(|finding| match finding {
            Finding::PromptInjectionMarker { .. } => Some(FindingKind::PromptInjectionMarker),
            Finding::PersonaOverrideAttempt { .. } => Some(FindingKind::PersonaOverrideAttempt),
            Finding::OversizeInput { .. }
            | Finding::NeededNfkcNormalization
            | Finding::BadControlChar { .. } => None,
        })
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

fn load_store(directory: &cap_std::fs::Dir, store_path: &Path) -> Result<Option<FindingStore>> {
    let state_path = store_path.join(STATE_FILE);
    let bytes = match store::read_regular_file_bounded(
        directory,
        OsStr::new(STATE_FILE),
        &state_path,
        MAX_STORE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error_chain_has_io_kind(&error, std::io::ErrorKind::NotFound) => {
            return Ok(None);
        }
        Err(error) => return Err(error).context("read paperless findings store fail closed"),
    };
    let state: FindingStore =
        serde_json::from_slice(&bytes).context("parse paperless findings store fail closed")?;
    validate_store(&state)?;
    Ok(Some(state))
}

fn persist_store(directory: &cap_std::fs::Dir, store_path: &Path, state: &FindingStore) -> Result<()> {
    validate_store(state)?;
    let bytes = serde_json::to_vec(state).context("serialize paperless findings store")?;
    anyhow::ensure!(
        bytes.len() <= MAX_STORE_BYTES,
        "paperless findings store exceeds its byte cap"
    );
    store::atomic_write_private_child(
        directory,
        OsStr::new(STATE_FILE),
        &store_path.join(STATE_FILE),
        &bytes,
    )
    .context("atomically publish paperless findings store")
}

fn validate_store(state: &FindingStore) -> Result<()> {
    anyhow::ensure!(
        state.schema_version == SCHEMA_VERSION && state.records.len() <= MAX_RECORDS,
        "invalid paperless findings store schema or record count"
    );
    for record in &state.records {
        validate_document_id(&record.document_id)?;
        validate_raw_input_hash(&record.raw_input_hash)?;
        anyhow::ensure!(
            !record.finding_kinds.is_empty()
                && record
                    .finding_kinds
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]),
            "invalid paperless findings record categories"
        );
    }
    Ok(())
}

fn validate_document_id(document_id: &str) -> Result<()> {
    anyhow::ensure!(
        !document_id.is_empty()
            && document_id.len() <= MAX_DOCUMENT_ID_BYTES
            && !document_id.chars().any(char::is_control),
        "invalid paperless findings document id"
    );
    Ok(())
}

fn validate_raw_input_hash(raw_input_hash: &str) -> Result<()> {
    anyhow::ensure!(
        raw_input_hash.len() == 16
            && raw_input_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "paperless findings raw input hash must be exactly 16 lowercase hex characters"
    );
    Ok(())
}

fn compare_newest_first(left: &FindingRecord, right: &FindingRecord) -> Ordering {
    right
        .occurred_unix
        .cmp(&left.occurred_unix)
        .then_with(|| left.document_id.cmp(&right.document_id))
        .then_with(|| left.source.as_str().cmp(right.source.as_str()))
        .then_with(|| left.raw_input_hash.cmp(&right.raw_input_hash))
        .then_with(|| left.finding_kinds.cmp(&right.finding_kinds))
}

fn error_chain_has_io_kind(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == kind)
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    const HASH: &str = "0123456789abcdef";

    fn marker(pattern: &str) -> Finding {
        Finding::PromptInjectionMarker {
            pattern: pattern.to_owned(),
        }
    }

    fn state_path(home: &Path) -> std::path::PathBuf {
        home.join(STORE_DIRECTORY).join(STATE_FILE)
    }

    #[test]
    fn clean_and_non_threat_findings_do_not_create_a_store() {
        let home = tempfile::tempdir().unwrap();
        record_quarantine_at(
            home.path(),
            OcrSource::ManualUpload,
            "doc-1",
            HASH,
            &[Finding::NeededNfkcNormalization],
            1,
        )
        .unwrap();
        assert!(!home.path().join(STORE_DIRECTORY).exists());
    }

    #[test]
    fn durable_bytes_and_response_are_redacted() {
        let home = tempfile::tempdir().unwrap();
        let marker_pattern = "RAW-OCR-SECRET-MUST-NOT-PERSIST";
        record_quarantine_at(
            home.path(),
            OcrSource::PaperlessNgx,
            "doc-42",
            HASH,
            &[marker(marker_pattern)],
            42,
        )
        .unwrap();

        let bytes = fs::read(state_path(home.path())).unwrap();
        let durable = String::from_utf8(bytes).unwrap();
        assert!(durable.contains("prompt_injection_marker"));
        assert!(!durable.contains(marker_pattern));
        let recent = recent_at(home.path(), 0, 20).unwrap();
        let response = serde_json::to_string(&recent).unwrap();
        assert!(!response.contains(marker_pattern));
        assert_eq!(recent.findings[0].finding_kinds, vec![FindingKind::PromptInjectionMarker]);
    }

    #[test]
    fn records_are_isolated_by_explicit_home() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        record_quarantine_at(
            first.path(),
            OcrSource::PaperlessNgx,
            "first",
            HASH,
            &[marker("first")],
            1,
        )
        .unwrap();
        record_quarantine_at(
            second.path(),
            OcrSource::PaperlessNgx,
            "second",
            HASH,
            &[marker("second")],
            2,
        )
        .unwrap();
        assert_eq!(recent_at(first.path(), 0, 20).unwrap().findings[0].document_id, "first");
        assert_eq!(recent_at(second.path(), 0, 20).unwrap().findings[0].document_id, "second");
    }

    #[test]
    fn concurrent_writers_do_not_lose_records() {
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().to_owned();
        let writers = 16;
        let barrier = Arc::new(Barrier::new(writers));
        let joins: Vec<_> = (0..writers)
            .map(|index| {
                let barrier = Arc::clone(&barrier);
                let home = home_path.clone();
                thread::spawn(move || {
                    barrier.wait();
                    record_quarantine_at(
                        &home,
                        OcrSource::ManualUpload,
                        &format!("doc-{index}"),
                        &format!("{index:016x}"),
                        &[marker("never persisted")],
                        index as u64,
                    )
                })
            })
            .collect();
        for join in joins {
            join.join().unwrap().unwrap();
        }
        let recent = recent_at(&home_path, 0, 100).unwrap();
        assert_eq!(recent.total, writers);
        assert_eq!(
            recent
                .findings
                .iter()
                .map(|record| record.document_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            writers
        );
    }

    #[test]
    fn corrupt_or_unknown_store_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(STORE_DIRECTORY)).unwrap();
        fs::write(state_path(home.path()), b"not-json").unwrap();
        assert!(recent_at(home.path(), 0, 20).is_err());
        fs::write(
            state_path(home.path()),
            br#"{"schema_version":1,"records":[],"unexpected":true}"#,
        )
        .unwrap();
        assert!(recent_at(home.path(), 0, 20).is_err());
    }

    #[test]
    fn enforces_cap_and_query_limits_without_eviction() {
        let home = tempfile::tempdir().unwrap();
        let records: Vec<FindingRecord> = (0..MAX_RECORDS)
            .map(|index| FindingRecord {
                occurred_unix: index as u64,
                document_id: format!("doc-{index}"),
                source: OcrSource::ManualUpload,
                raw_input_hash: format!("{index:016x}"),
                finding_kinds: vec![FindingKind::PromptInjectionMarker],
            })
            .collect();
        let state = FindingStore {
            schema_version: SCHEMA_VERSION,
            records,
        };
        fs::create_dir_all(home.path().join(STORE_DIRECTORY)).unwrap();
        fs::write(state_path(home.path()), serde_json::to_vec(&state).unwrap()).unwrap();

        assert!(record_quarantine_at(
            home.path(),
            OcrSource::ManualUpload,
            "over-cap",
            HASH,
            &[marker("pattern")],
            2_000,
        )
        .is_err());
        assert_eq!(recent_at(home.path(), 0, 100).unwrap().total, MAX_RECORDS);
        assert!(recent_at(home.path(), 0, 0).is_err());
        assert!(recent_at(home.path(), 0, MAX_RECENT_LIMIT + 1).is_err());
    }

    #[test]
    fn recent_filter_is_inclusive_and_newest_first_with_a_stable_tie_breaker() {
        let home = tempfile::tempdir().unwrap();
        for (document_id, hash, occurred_unix) in [
            ("z-tie", "0000000000000001", 10),
            ("a-tie", "0000000000000002", 10),
            ("old", "0000000000000003", 9),
        ] {
            record_quarantine_at(
                home.path(),
                OcrSource::ManualUpload,
                document_id,
                hash,
                &[marker("pattern")],
                occurred_unix,
            )
            .unwrap();
        }
        let recent = recent_at(home.path(), 10, 1).unwrap();
        assert_eq!(recent.total, 2);
        assert!(recent.truncated);
        assert_eq!(recent.findings[0].document_id, "a-tie");
    }
}
