//! Durable audit sidecar for `neoth-migrate apply`.
//!
//! The migrator is a separate process and therefore cannot borrow the
//! daemon's single WAL writer. It records one fsynced JSONL lifecycle stream
//! under `~/.neoth/neoth-migrate-audit.jsonl`. Audit writes are fail-closed:
//! an apply never starts when its intent cannot be persisted.

use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result};
use serde::Serialize;

#[derive(Debug)]
pub struct OperatorWalEmitter {
    audit_path: PathBuf,
    operation_id: String,
    file: Mutex<File>,
}

impl OperatorWalEmitter {
    /// Open and permission-check the append-only audit stream. The NEOTH home
    /// must already exist because the target database was opened before this.
    pub fn open(home: &Path) -> Result<Self> {
        let audit_path = home.join(".neoth").join("neoth-migrate-audit.jsonl");
        let parent = audit_path.parent().expect("audit path has parent");
        anyhow::ensure!(
            parent.is_dir(),
            "migration audit directory does not exist: {}",
            parent.display()
        );
        let file = open_append(&audit_path)
            .with_context(|| format!("open migration audit at {}", audit_path.display()))?;
        file.sync_data()
            .with_context(|| format!("sync migration audit at {}", audit_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| {
                    format!("chmod 0600 migration audit at {}", audit_path.display())
                })?;
        }

        let operation_id = format!("migration-{}", now_ns());
        Ok(Self {
            audit_path,
            operation_id,
            file: Mutex::new(file),
        })
    }

    pub fn emit_migration_started(&self, sources_total: usize, target_db: &Path) -> Result<()> {
        self.append_line(&serde_json::json!({
            "kind": "MIGRATION_STARTED",
            "operation_id": self.operation_id,
            "sources_total": sources_total,
            "target_db": target_db.display().to_string(),
            "atomic": true,
            "ts_ns": now_ns(),
        }))
    }

    pub fn emit_migration_batch(
        &self,
        source_name: &str,
        claims_seen: usize,
        inserted: usize,
    ) -> Result<()> {
        self.append_line(&serde_json::json!({
            "kind": "MIGRATION_BATCH",
            "operation_id": self.operation_id,
            "source_name": source_name,
            "claims_seen": claims_seen,
            "inserted": inserted,
            "skipped_duplicates": claims_seen.saturating_sub(inserted),
            "ts_ns": now_ns(),
        }))
    }

    pub fn emit_migration_complete(&self, inserted: usize) -> Result<()> {
        self.append_line(&serde_json::json!({
            "kind": "MIGRATION_COMPLETE",
            "operation_id": self.operation_id,
            // Compatibility with the original one-line summary.
            "event": "GROUNDTRUTH_IMPORTED",
            "event_type": 0x99u8,
            "inserted": inserted,
            "skipped_sources": 0,
            "ts_ns": now_ns(),
        }))
    }

    pub fn emit_migration_failed(
        &self,
        stage: &str,
        error: &anyhow::Error,
        rolled_back: bool,
    ) -> Result<()> {
        let mut detail = format!("{error:#}");
        detail.truncate(2_048);
        self.append_line(&serde_json::json!({
            "kind": "MIGRATION_FAILED",
            "operation_id": self.operation_id,
            "stage": stage,
            "error": detail,
            "rolled_back": rolled_back,
            "ts_ns": now_ns(),
        }))
    }

    fn append_line(&self, value: &serde_json::Value) -> Result<()> {
        let serialised = serde_json::to_string(value).context("serialize migration audit event")?;
        let mut file = self.file.lock().map_err(|_| {
            anyhow::anyhow!(
                "migration audit lock poisoned at {}",
                self.audit_path.display()
            )
        })?;
        writeln!(&mut *file, "{serialised}")
            .with_context(|| format!("write migration audit at {}", self.audit_path.display()))?;
        file.sync_data()
            .with_context(|| format!("sync migration audit at {}", self.audit_path.display()))
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new().create(true).append(true).open(path)
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MigrationAuditStatus {
    pub audit_path: String,
    pub state: String,
    pub operation_id: Option<String>,
    pub sources_total: usize,
    pub batches_completed: usize,
    pub claims_seen: usize,
    pub inserted: usize,
    pub started_ns: Option<i64>,
    pub finished_ns: Option<i64>,
    pub error: Option<String>,
    pub rolled_back: Option<bool>,
}

impl MigrationAuditStatus {
    fn empty(path: &Path) -> Self {
        Self {
            audit_path: path.display().to_string(),
            state: "never_started".to_string(),
            operation_id: None,
            sources_total: 0,
            batches_completed: 0,
            claims_seen: 0,
            inserted: 0,
            started_ns: None,
            finished_ns: None,
            error: None,
            rolled_back: None,
        }
    }
}

/// Read the latest lifecycle from the append-only audit stream. Old events
/// without operation ids remain readable; a new STARTED line resets the view.
pub fn load_status(home: &Path) -> Result<MigrationAuditStatus> {
    let path = home.join(".neoth").join("neoth-migrate-audit.jsonl");
    if !path.exists() {
        return Ok(MigrationAuditStatus::empty(&path));
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read migration audit at {}", path.display()))?;
    let mut status = MigrationAuditStatus::empty(&path);
    for (line_index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(line).with_context(|| {
            format!(
                "parse migration audit {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        match event.get("kind").and_then(serde_json::Value::as_str) {
            Some("MIGRATION_STARTED") => {
                status = MigrationAuditStatus::empty(&path);
                status.state = "in_progress".to_string();
                status.operation_id = event
                    .get("operation_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);
                status.sources_total = event
                    .get("sources_total")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as usize;
                status.started_ns = event.get("ts_ns").and_then(serde_json::Value::as_i64);
            }
            Some("MIGRATION_BATCH")
                if status.state == "in_progress" && event_matches_current(&status, &event) =>
            {
                status.batches_completed += 1;
                status.claims_seen += event
                    .get("claims_seen")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as usize;
                status.inserted += event
                    .get("inserted")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as usize;
            }
            Some("MIGRATION_COMPLETE")
                if status.state == "in_progress" && event_matches_current(&status, &event) =>
            {
                status.state = "complete".to_string();
                status.inserted = event
                    .get("inserted")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(status.inserted as u64) as usize;
                status.finished_ns = event.get("ts_ns").and_then(serde_json::Value::as_i64);
            }
            Some("MIGRATION_FAILED")
                if status.state == "in_progress" && event_matches_current(&status, &event) =>
            {
                status.state = "failed".to_string();
                status.finished_ns = event.get("ts_ns").and_then(serde_json::Value::as_i64);
                status.error = event
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);
                status.rolled_back = event
                    .get("rolled_back")
                    .and_then(serde_json::Value::as_bool);
            }
            _ => {}
        }
    }
    Ok(status)
}

fn event_matches_current(status: &MigrationAuditStatus, event: &serde_json::Value) -> bool {
    status.operation_id.as_deref().is_none_or(|operation_id| {
        event
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            == Some(operation_id)
    })
}

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn lifecycle_is_durable_and_status_reports_latest_run() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".neoth")).unwrap();
        let emitter = OperatorWalEmitter::open(dir.path()).unwrap();
        emitter
            .emit_migration_started(2, &dir.path().join(".neoth/views.db"))
            .unwrap();
        emitter.emit_migration_batch("a", 3, 3).unwrap();
        emitter.emit_migration_batch("b", 2, 1).unwrap();
        emitter.emit_migration_complete(4).unwrap();

        let status = load_status(dir.path()).unwrap();
        assert_eq!(status.state, "complete");
        assert_eq!(status.sources_total, 2);
        assert_eq!(status.batches_completed, 2);
        assert_eq!(status.claims_seen, 5);
        assert_eq!(status.inserted, 4);
        assert!(status.operation_id.is_some());
    }

    #[test]
    fn failure_is_visible_and_records_rollback() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".neoth")).unwrap();
        let emitter = OperatorWalEmitter::open(dir.path()).unwrap();
        emitter
            .emit_migration_started(1, &dir.path().join(".neoth/views.db"))
            .unwrap();
        emitter
            .emit_migration_failed("preflight", &anyhow::anyhow!("bad source"), true)
            .unwrap();

        let status = load_status(dir.path()).unwrap();
        assert_eq!(status.state, "failed");
        assert_eq!(status.rolled_back, Some(true));
        assert!(status.error.unwrap().contains("bad source"));
    }

    #[test]
    fn missing_audit_reports_never_started_without_creating_files() {
        let dir = tempdir().unwrap();
        let status = load_status(dir.path()).unwrap();
        assert_eq!(status.state, "never_started");
        assert!(!dir.path().join(".neoth").exists());
    }

    #[test]
    fn open_fails_when_neoth_directory_is_missing() {
        let dir = tempdir().unwrap();
        let error = OperatorWalEmitter::open(dir.path()).unwrap_err();
        assert!(error.to_string().contains("does not exist"));
    }
}
