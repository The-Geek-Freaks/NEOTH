//! Durable, content-free snapshots of the capability-quality observation.
//!
//! The snapshot producer always derives its data from the authenticated WAL
//! scanner in the parent module. This store never accepts caller supplied
//! operational observations and readers never repair missing or bad state.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{CapabilityDecayReport, CapabilityTrend};
use crate::daemon::usage_log::{WorkflowKey, WorkflowKind};

const HISTORY_DIR: &str = "capability_quality";
const HISTORY_FILE: &str = "history-v1.json";
const LOCK_FILE: &str = "history-v1.lock";
const HISTORY_VERSION: u8 = 1;
const MAX_HISTORY_BYTES: usize = 256 * 1024;
const MAX_SNAPSHOTS: usize = 32;
const MAX_IDENTITIES_PER_SNAPSHOT: usize = 128;
const ALGORITHM_VERSION: &str = "terminal-v1";
const SOURCE_PROVENANCE: &str = "authenticated_terminal_wal_prefix";

static CAPABILITY_HISTORY_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilitySnapshot {
    pub(crate) version: u8,
    pub(crate) captured_at_unix: i64,
    pub(crate) algorithm: String,
    pub(crate) source: String,
    pub(crate) recent_since_unix: i64,
    pub(crate) baseline_since_unix: i64,
    pub(crate) input_receipt_sha256: String,
    pub(crate) authenticated_terminal_sample_count: u64,
    pub(crate) unattributed_terminal_rows: u64,
    pub(crate) legacy_terminal_rows: u64,
    pub(crate) observations: Vec<SnapshotObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotObservation {
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) workflow: WorkflowKey,
    pub(crate) trend: CapabilityTrend,
    pub(crate) recent_samples: u64,
    pub(crate) baseline_samples: u64,
    pub(crate) recent_failures: u64,
    pub(crate) baseline_failures: u64,
    pub(crate) recent_p90_latency_ms: u64,
    pub(crate) baseline_p90_latency_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CapabilityHistory {
    version: u8,
    snapshots: Vec<CapabilitySnapshot>,
}

impl Default for CapabilityHistory {
    fn default() -> Self {
        Self {
            version: HISTORY_VERSION,
            snapshots: Vec::new(),
        }
    }
}

/// Derive an observation from authenticated history and publish it atomically.
/// The source scan happens before the store is opened, so a failed scan cannot
/// create a directory, lock or empty snapshot.
pub(crate) fn capture(home: &Path, now_unix: i64) -> Result<CapabilitySnapshot> {
    let snapshot = snapshot_from_report(
        super::inspect_authenticated_terminal_history(home, now_unix)?,
        now_unix,
    )?;
    let _guard = CAPABILITY_HISTORY_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("capability history mutex is poisoned"))?;
    let home_directory =
        crate::skills::store::open_bound_directory(home, false, "capability quality home")?
            .context("capability quality home does not exist")?;
    let namespace_path = home_directory.physical_display_path.join(HISTORY_DIR);
    let namespace = crate::skills::store::open_or_create_private_child_dir(
        &home_directory.dir,
        OsStr::new(HISTORY_DIR),
        &namespace_path,
    )?;
    let (namespace, namespace_binding) = crate::skills::store::bind_retained_real_child_dir(
        &home_directory.dir,
        OsStr::new(HISTORY_DIR),
        &namespace_path,
        namespace,
    )?;
    crate::skills::store::ensure_cap_directory_is_owner_private(
        &namespace,
        "capability quality directory",
        &namespace_path,
    )?;
    let lock_path = namespace_path.join(LOCK_FILE);
    let (lock, binding) = crate::skills::store::open_or_create_bound_lockfile(
        &namespace,
        OsStr::new(LOCK_FILE),
        &lock_path,
    )?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            anyhow::bail!("capability quality snapshot capture is already active")
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let state_path = namespace_path.join(HISTORY_FILE);
    let mut history = read_existing(&namespace, &state_path)?.unwrap_or_default();
    if let Some(last) = history.snapshots.last() {
        anyhow::ensure!(
            last.captured_at_unix <= snapshot.captured_at_unix,
            "capability snapshot clock moved backwards"
        );
        if last.captured_at_unix == snapshot.captured_at_unix {
            anyhow::ensure!(
                last == &snapshot,
                "capability snapshot timestamp conflicts with existing data"
            );
            anyhow::ensure!(
                namespace_binding.matches_directory_child(
                    &home_directory.dir,
                    OsStr::new(HISTORY_DIR),
                    &namespace_path,
                )?,
                "capability history directory changed before capture return"
            );
            return Ok(snapshot);
        }
    }
    history.snapshots.push(snapshot.clone());
    if history.snapshots.len() > MAX_SNAPSHOTS {
        history.snapshots.remove(0);
    }
    validate_history(&history)?;
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(
            &namespace,
            OsStr::new(LOCK_FILE),
            &lock_path,
        )?,
        "capability history lock changed during capture"
    );
    write_history(&namespace, &state_path, &history)?;
    anyhow::ensure!(
        namespace_binding.matches_directory_child(
            &home_directory.dir,
            OsStr::new(HISTORY_DIR),
            &namespace_path,
        )?,
        "capability history directory changed after capture publication"
    );
    Ok(snapshot)
}

/// Read history without creating any directory, lock file or replacement.
pub(crate) fn read(home: &Path) -> Result<Vec<CapabilitySnapshot>> {
    let Some(home_directory) =
        crate::skills::store::open_bound_directory(home, false, "capability quality read home")?
    else {
        return Ok(Vec::new());
    };
    let namespace_path = home_directory.physical_display_path.join(HISTORY_DIR);
    let Some(namespace) = crate::skills::store::open_real_child_dir_if_present(
        &home_directory.dir,
        OsStr::new(HISTORY_DIR),
        &namespace_path,
    )?
    else {
        return Ok(Vec::new());
    };
    let (namespace, namespace_binding) = crate::skills::store::bind_retained_real_child_dir(
        &home_directory.dir,
        OsStr::new(HISTORY_DIR),
        &namespace_path,
        namespace,
    )?;
    crate::skills::store::ensure_cap_directory_is_owner_private(
        &namespace,
        "capability quality read directory",
        &namespace_path,
    )?;
    let snapshots = read_existing(&namespace, &namespace_path.join(HISTORY_FILE))?
        .unwrap_or_default()
        .snapshots;
    anyhow::ensure!(
        namespace_binding.matches_directory_child(
            &home_directory.dir,
            OsStr::new(HISTORY_DIR),
            &namespace_path,
        )?,
        "capability history directory changed before read return"
    );
    Ok(snapshots)
}

fn snapshot_from_report(
    report: CapabilityDecayReport,
    captured_at_unix: i64,
) -> Result<CapabilitySnapshot> {
    anyhow::ensure!(
        captured_at_unix >= 0,
        "capability snapshot clock is before Unix epoch"
    );
    let observations = report
        .observations
        .into_iter()
        .map(|observation| SnapshotObservation {
            provider: observation.identity.provider,
            model: observation.identity.model,
            workflow: observation.identity.workflow,
            trend: observation.trend,
            recent_samples: observation.recent_samples,
            baseline_samples: observation.baseline_samples,
            recent_failures: observation.recent_failures,
            baseline_failures: observation.baseline_failures,
            recent_p90_latency_ms: observation.recent_p90_latency_ms,
            baseline_p90_latency_ms: observation.baseline_p90_latency_ms,
        })
        .collect();
    let snapshot = CapabilitySnapshot {
        version: HISTORY_VERSION,
        captured_at_unix,
        algorithm: ALGORITHM_VERSION.to_owned(),
        source: SOURCE_PROVENANCE.to_owned(),
        recent_since_unix: report.recent_since_unix,
        baseline_since_unix: report.baseline_since_unix,
        input_receipt_sha256: report.input_receipt_sha256,
        authenticated_terminal_sample_count: report.authenticated_terminal_sample_count,
        unattributed_terminal_rows: report.unattributed_terminal_rows,
        legacy_terminal_rows: report.legacy_terminal_rows,
        observations,
    };
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn read_existing(parent: &cap_std::fs::Dir, path: &Path) -> Result<Option<CapabilityHistory>> {
    let name = path
        .file_name()
        .context("capability history has no file name")?;
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let bytes =
        crate::skills::store::read_regular_file_bounded(parent, name, path, MAX_HISTORY_BYTES)?;
    let history: CapabilityHistory =
        serde_json::from_slice(&bytes).context("decode capability history")?;
    validate_history(&history)?;
    Ok(Some(history))
}

fn write_history(
    parent: &cap_std::fs::Dir,
    path: &Path,
    history: &CapabilityHistory,
) -> Result<()> {
    let bytes = serde_json::to_vec(history).context("encode capability history")?;
    anyhow::ensure!(
        bytes.len() <= MAX_HISTORY_BYTES,
        "capability history exceeds bounded storage"
    );
    let name = path
        .file_name()
        .context("capability history has no file name")?;
    crate::skills::store::atomic_write_private_child(parent, name, path, &bytes)?;
    Ok(())
}

fn validate_history(history: &CapabilityHistory) -> Result<()> {
    anyhow::ensure!(
        history.version == HISTORY_VERSION,
        "unsupported capability history schema"
    );
    anyhow::ensure!(
        history.snapshots.len() <= MAX_SNAPSHOTS,
        "capability history exceeds snapshot limit"
    );
    let mut previous = None;
    for snapshot in &history.snapshots {
        validate_snapshot(snapshot)?;
        if let Some(previous) = previous {
            anyhow::ensure!(
                previous < snapshot.captured_at_unix,
                "capability history timestamps are not strictly monotonic"
            );
        }
        previous = Some(snapshot.captured_at_unix);
    }
    Ok(())
}

fn validate_snapshot(snapshot: &CapabilitySnapshot) -> Result<()> {
    anyhow::ensure!(
        snapshot.version == HISTORY_VERSION,
        "unsupported capability snapshot schema"
    );
    anyhow::ensure!(
        snapshot.captured_at_unix >= 0,
        "capability snapshot timestamp is invalid"
    );
    anyhow::ensure!(
        snapshot
            .recent_since_unix
            .checked_sub(snapshot.baseline_since_unix)
            == Some(super::BASELINE_WINDOW_SECONDS)
            && snapshot
                .captured_at_unix
                .checked_sub(snapshot.recent_since_unix)
                == Some(super::RECENT_WINDOW_SECONDS),
        "capability snapshot has invalid windows"
    );
    anyhow::ensure!(
        snapshot.algorithm == ALGORITHM_VERSION && snapshot.source == SOURCE_PROVENANCE,
        "unsupported capability snapshot provenance"
    );
    anyhow::ensure!(
        snapshot.input_receipt_sha256.len() == 64
            && snapshot.input_receipt_sha256.bytes().all(|byte| {
                byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
            }),
        "capability snapshot has invalid input receipt"
    );
    anyhow::ensure!(
        snapshot.authenticated_terminal_sample_count <= 4_096,
        "capability snapshot exceeds terminal sample bound"
    );
    anyhow::ensure!(
        snapshot.observations.len() <= MAX_IDENTITIES_PER_SNAPSHOT,
        "capability snapshot exceeds identity limit"
    );
    let mut identities = std::collections::BTreeSet::new();
    let mut counted = 0u64;
    for row in &snapshot.observations {
        anyhow::ensure!(
            safe_label(&row.provider) && safe_label(&row.model),
            "capability snapshot has unsafe label"
        );
        anyhow::ensure!(
            row.workflow.0 != WorkflowKind::Unclassified,
            "capability snapshot has unclassified workflow"
        );
        anyhow::ensure!(
            row.recent_failures <= row.recent_samples
                && row.baseline_failures <= row.baseline_samples,
            "capability snapshot has impossible failure counts"
        );
        let recent = super::WindowSamples {
            completed: row.recent_samples,
            failed: row.recent_failures,
            latencies: vec![row.recent_p90_latency_ms],
        };
        let baseline = super::WindowSamples {
            completed: row.baseline_samples,
            failed: row.baseline_failures,
            latencies: vec![row.baseline_p90_latency_ms],
        };
        anyhow::ensure!(
            row.trend
                == super::classify(
                    &recent,
                    &baseline,
                    row.recent_p90_latency_ms,
                    row.baseline_p90_latency_ms,
                ),
            "capability snapshot has inconsistent trend"
        );
        anyhow::ensure!(
            identities.insert((&row.provider, &row.model, row.workflow)),
            "capability snapshot has duplicate identity"
        );
        counted = counted
            .checked_add(row.recent_samples)
            .and_then(|value| value.checked_add(row.baseline_samples))
            .context("capability snapshot sample counter overflow")?;
    }
    anyhow::ensure!(
        counted == snapshot.authenticated_terminal_sample_count,
        "capability snapshot receipt count does not match rows"
    );
    Ok(())
}

fn safe_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    use crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE;
    use crate::wal::writer::WalWriterHandle;

    async fn writer(
        home: &Path,
    ) -> (
        std::path::PathBuf,
        WalWriterHandle,
        tokio::task::JoinHandle<std::result::Result<(), String>>,
    ) {
        let wal = home.join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), home.to_path_buf()).unwrap();
        ready.wait().await.unwrap();
        (segment, writer, join)
    }

    async fn terminal(writer: &WalWriterHandle, id: u8, ts: i64) {
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema":"neoth.provider-lifecycle.v1",
            "usage_projection_schema":"neoth.provider-usage.v2",
            "invocation_id":format!("{id:064x}"),
            "request_binding_sha256":"1".repeat(64),
            "call_scope":"chat_provider_round",
            "provider":"openai_api", "wire_model":"gpt-5", "model":"gpt-5",
            "streaming":false, "automated":false, "ts_unix":ts, "ok":true,
            "latency_ms":100, "terminal_kind":"complete", "source":"chat",
            "call_type":"chat_provider_round"
        }))
        .unwrap();
        writer
            .append_authenticated(
                crate::wal::HeaderBuilder::new(EVENT_TYPE_PROVIDER_RESPONSE, &payload).build(),
                payload,
            )
            .await
            .unwrap();
    }

    async fn complete_history_home() -> (tempfile::TempDir, std::path::PathBuf, i64) {
        let home = tempfile::tempdir().unwrap();
        let now = crate::time::now_unix_i64();
        let (segment, writer, join) = writer(home.path()).await;
        for id in 0..12 {
            terminal(&writer, id, now - super::super::RECENT_WINDOW_SECONDS - 10).await;
        }
        for id in 20..28 {
            terminal(&writer, id, now - 10).await;
        }
        drop(writer);
        join.await.unwrap().unwrap();
        (home, segment, now)
    }

    #[tokio::test]
    async fn authenticated_terminal_snapshot_persists_and_reopens() {
        let (home, _, now) = complete_history_home().await;
        let captured = capture(home.path(), now).unwrap();
        let reopened = read(home.path()).unwrap();
        assert_eq!(reopened, vec![captured]);
        assert_eq!(reopened[0].source, SOURCE_PROVENANCE);
        assert_eq!(reopened[0].authenticated_terminal_sample_count, 20);
    }

    #[tokio::test]
    async fn torn_wal_refuses_capture_without_overwrite() {
        let (home, segment, now) = complete_history_home().await;
        let first = capture(home.path(), now).unwrap();
        let before = serde_json::to_vec(&first).unwrap();
        let mut tail = std::fs::OpenOptions::new()
            .append(true)
            .open(segment)
            .unwrap();
        tail.write_all(&[0x4e, 0x45]).unwrap();
        tail.sync_all().unwrap();
        assert!(capture(home.path(), now + 1).is_err());
        assert_eq!(
            serde_json::to_vec(&read(home.path()).unwrap()[0]).unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn empty_authenticated_history_persists_no_false_sample() {
        let home = tempfile::tempdir().unwrap();
        let (_, writer, join) = writer(home.path()).await;
        drop(writer);
        join.await.unwrap().unwrap();
        let snapshot = capture(home.path(), crate::time::now_unix_i64()).unwrap();
        assert_eq!(snapshot.authenticated_terminal_sample_count, 0);
        assert!(snapshot.observations.is_empty());
    }

    #[test]
    fn capture_refuses_a_missing_home_without_creating_it() {
        let parent = tempfile::tempdir().unwrap();
        let home = parent.path().join("missing-home");
        assert!(capture(&home, crate::time::now_unix_i64()).is_err());
        assert!(!home.exists());
    }

    #[tokio::test]
    async fn history_retains_the_newest_32_captured_snapshots() {
        let (home, _, now) = complete_history_home().await;
        for offset in 0..=32 {
            capture(home.path(), now + offset).unwrap();
        }
        let reopened = read(home.path()).unwrap();
        assert_eq!(reopened.len(), MAX_SNAPSHOTS);
        assert_eq!(reopened[0].captured_at_unix, now + 1);
        assert_eq!(reopened.last().unwrap().captured_at_unix, now + 32);
    }

    #[tokio::test]
    async fn corrupt_or_future_store_refuses_read_and_capture_without_repair() {
        let (home, _, now) = complete_history_home().await;
        capture(home.path(), now).unwrap();
        let state_path = home.path().join(HISTORY_DIR).join(HISTORY_FILE);

        for invalid in [
            b"{ not json".as_slice(),
            br#"{"version":2,"snapshots":[]}"#.as_slice(),
            br#"{"version":1,"snapshots":[],"unknown":true}"#.as_slice(),
            br#"{"version":1,"snapshots":[{"version":1,"captured_at_unix":9223372036854775807,"algorithm":"terminal-v1","source":"authenticated_terminal_wal_prefix","recent_since_unix":-9223372036854775808,"baseline_since_unix":0,"input_receipt_sha256":"0000000000000000000000000000000000000000000000000000000000000000","authenticated_terminal_sample_count":0,"unattributed_terminal_rows":0,"legacy_terminal_rows":0,"observations":[]}]}"#.as_slice(),
        ] {
            std::fs::write(&state_path, invalid).unwrap();
            let before = std::fs::read(&state_path).unwrap();
            assert!(read(home.path()).is_err());
            assert!(capture(home.path(), now + 1).is_err());
            assert_eq!(std::fs::read(&state_path).unwrap(), before);
        }
    }

    #[tokio::test]
    async fn held_store_lock_refuses_capture_without_repair() {
        let (home, _, now) = complete_history_home().await;
        capture(home.path(), now).unwrap();
        let state_path = home.path().join(HISTORY_DIR).join(HISTORY_FILE);
        let before = std::fs::read(&state_path).unwrap();
        let lock_path = home.path().join(HISTORY_DIR).join(LOCK_FILE);
        let held =
            crate::util::locked_file::try_lock_file_once(&lock_path, "capability history test")
                .unwrap()
                .expect("test lock is acquired");
        assert!(capture(home.path(), now + 1).is_err());
        assert_eq!(std::fs::read(&state_path).unwrap(), before);
        drop(held);
    }
}
