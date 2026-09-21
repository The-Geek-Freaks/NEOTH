//! W164 — private, bounded response-feedback projection.
//!
//! This is intentionally not a WAL event family. It persists only opaque ids,
//! their explicit terminal session binding, revision, fixed signal, and time.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Deserializer, Serialize};

const MAX_TARGETS: usize = 128;
const MAX_STORE_BYTES: usize = 128 * 1024;
const MAX_SESSION_ID_BYTES: usize = 512;
const STORE_DIR: &str = "feedback";
const STORE_FILE: &str = "response-feedback.json";
const LOCK_FILE: &str = "response-feedback.lock";

static RESPONSE_FEEDBACK_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct ResponseId(String);

impl ResponseId {
    pub(crate) fn parse(value: &str) -> Result<Self, ResponseFeedbackRejection> {
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ResponseFeedbackRejection::Malformed);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub(crate) fn as_str(&self) -> &str { &self.0 }
}

impl<'de> Deserialize<'de> for ResponseId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResponseSignal { NeedsCorrection, NotHelpful }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseFeedbackOperation { Set(ResponseSignal), Remove }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResponseFeedbackRejection { Malformed, Missing, Foreign, Stale, Unavailable }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResponseTargetStatus {
    pub(crate) response_id: ResponseId,
    pub(crate) session_id: String,
    pub(crate) revision: u64,
    pub(crate) active_signal: Option<ResponseSignal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResponseFeedbackOutcome {
    Set { signal: ResponseSignal, revision: u64 },
    Replaced { previous: ResponseSignal, signal: ResponseSignal, revision: u64 },
    Removed { revision: u64 },
    Unchanged { revision: u64 },
    Rejected(ResponseFeedbackRejection),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ActiveResponseFeedbackSummary {
    pub(crate) needs_correction: u32,
    pub(crate) not_helpful: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTarget {
    response_id: ResponseId,
    session_id: String,
    issued_at_unix: i64,
    updated_at_unix: i64,
    revision: u64,
    active_signal: Option<ResponseSignal>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProjection { targets: Vec<StoredTarget> }

fn store_path(home: &Path) -> PathBuf { home.join(STORE_DIR).join(STORE_FILE) }

/// Register only after the producer's real writer-drain completion. Incognito
/// short-circuits before path creation or file IO.
pub(crate) fn register_drained_terminal_response(
    home: &Path, session_id: &str, incognito: bool, completed_at_unix: i64,
) -> Result<Option<ResponseTargetStatus>, ResponseFeedbackRejection> {
    if incognito { return Ok(None); }
    validate_session_id(session_id)?;
    with_projection(home, |projection| {
        if projection.targets.len() >= MAX_TARGETS {
            let Some(index) = projection.targets.iter().position(|target| target.active_signal.is_none()) else {
                return Err(ResponseFeedbackRejection::Unavailable);
            };
            projection.targets.remove(index);
        }
        let response_id = random_response_id()?;
        projection.targets.push(StoredTarget {
            response_id: response_id.clone(), session_id: session_id.to_owned(),
            issued_at_unix: completed_at_unix, updated_at_unix: completed_at_unix,
            revision: 0, active_signal: None,
        });
        Ok((Some(ResponseTargetStatus { response_id, session_id: session_id.to_owned(), revision: 0, active_signal: None }), true))
    })
}

pub(crate) fn read_response_feedback_status(
    home: &Path, response_id: &ResponseId, expected_session_id: &str,
) -> Result<ResponseTargetStatus, ResponseFeedbackRejection> {
    validate_session_id(expected_session_id)?;
    with_projection(home, |projection| {
        let target = find_target(projection, response_id, expected_session_id)?;
        Ok((ResponseTargetStatus { response_id: target.response_id.clone(), session_id: target.session_id.clone(), revision: target.revision, active_signal: target.active_signal }, false))
    })
}

pub(crate) fn apply_response_feedback(
    home: &Path, response_id: &ResponseId, expected_session_id: &str, expected_revision: u64,
    operation: ResponseFeedbackOperation, now_unix: i64,
) -> Result<ResponseFeedbackOutcome, ResponseFeedbackRejection> {
    validate_session_id(expected_session_id)?;
    with_projection(home, |projection| {
        let target = find_target_mut(projection, response_id, expected_session_id)?;
        if target.revision != expected_revision { return Ok((ResponseFeedbackOutcome::Rejected(ResponseFeedbackRejection::Stale), false)); }
        let outcome = match (operation, target.active_signal) {
            (ResponseFeedbackOperation::Set(signal), Some(current)) if current == signal => ResponseFeedbackOutcome::Unchanged { revision: target.revision },
            (ResponseFeedbackOperation::Set(signal), Some(previous)) => { target.active_signal = Some(signal); target.revision = next_revision(target.revision)?; target.updated_at_unix = now_unix; ResponseFeedbackOutcome::Replaced { previous, signal, revision: target.revision } }
            (ResponseFeedbackOperation::Set(signal), None) => { target.active_signal = Some(signal); target.revision = next_revision(target.revision)?; target.updated_at_unix = now_unix; ResponseFeedbackOutcome::Set { signal, revision: target.revision } }
            (ResponseFeedbackOperation::Remove, None) => ResponseFeedbackOutcome::Unchanged { revision: target.revision },
            (ResponseFeedbackOperation::Remove, Some(_)) => { target.active_signal = None; target.revision = next_revision(target.revision)?; target.updated_at_unix = now_unix; ResponseFeedbackOutcome::Removed { revision: target.revision } }
        };
        let changed = !matches!(outcome, ResponseFeedbackOutcome::Unchanged { .. });
        Ok((outcome, changed))
    })
}

pub(crate) fn active_response_feedback_summary(home: &Path) -> Result<ActiveResponseFeedbackSummary, ResponseFeedbackRejection> {
    with_projection(home, |projection| {
        let mut summary = ActiveResponseFeedbackSummary::default();
        for target in &projection.targets { match target.active_signal { Some(ResponseSignal::NeedsCorrection) => summary.needs_correction += 1, Some(ResponseSignal::NotHelpful) => summary.not_helpful += 1, None => {} } }
        Ok((summary, false))
    })
}

fn validate_session_id(session_id: &str) -> Result<(), ResponseFeedbackRejection> {
    if session_id.is_empty() || session_id.len() > MAX_SESSION_ID_BYTES { return Err(ResponseFeedbackRejection::Malformed); }
    Ok(())
}

fn validate_projection(projection: &StoredProjection) -> Result<(), ResponseFeedbackRejection> {
    if projection.targets.len() > MAX_TARGETS { return Err(ResponseFeedbackRejection::Unavailable); }
    for (index, target) in projection.targets.iter().enumerate() {
        validate_session_id(&target.session_id)?;
        if projection.targets[..index].iter().any(|prior| prior.response_id == target.response_id) { return Err(ResponseFeedbackRejection::Unavailable); }
    }
    Ok(())
}

fn next_revision(revision: u64) -> Result<u64, ResponseFeedbackRejection> {
    revision.checked_add(1).ok_or(ResponseFeedbackRejection::Unavailable)
}

fn find_target<'a>(projection: &'a StoredProjection, id: &ResponseId, session: &str) -> Result<&'a StoredTarget, ResponseFeedbackRejection> {
    let target = projection.targets.iter().find(|target| target.response_id == *id).ok_or(ResponseFeedbackRejection::Missing)?;
    if target.session_id != session { return Err(ResponseFeedbackRejection::Foreign); }
    Ok(target)
}
fn find_target_mut<'a>(projection: &'a mut StoredProjection, id: &ResponseId, session: &str) -> Result<&'a mut StoredTarget, ResponseFeedbackRejection> {
    let target = projection.targets.iter_mut().find(|target| target.response_id == *id).ok_or(ResponseFeedbackRejection::Missing)?;
    if target.session_id != session { return Err(ResponseFeedbackRejection::Foreign); }
    Ok(target)
}

fn with_projection<T>(home: &Path, mutate: impl FnOnce(&mut StoredProjection) -> Result<(T, bool), ResponseFeedbackRejection>) -> Result<T, ResponseFeedbackRejection> {
    let _guard = RESPONSE_FEEDBACK_MUTEX.get_or_init(|| Mutex::new(())).lock().map_err(|_| ResponseFeedbackRejection::Unavailable)?;
    let home_directory = crate::skills::store::open_bound_directory(home, true, "response feedback home")
        .map_err(|_| ResponseFeedbackRejection::Unavailable)?
        .ok_or(ResponseFeedbackRejection::Unavailable)?;
    let namespace_path = home_directory.physical_display_path.join(STORE_DIR);
    let namespace = crate::skills::store::open_or_create_private_child_dir(
        &home_directory.dir, OsStr::new(STORE_DIR), &namespace_path,
    ).map_err(|_| ResponseFeedbackRejection::Unavailable)?;
    let lock_display = namespace_path.join(LOCK_FILE);
    let (file_lock, lock_binding) = crate::skills::store::open_or_create_bound_lockfile(
        &namespace, OsStr::new(LOCK_FILE), &lock_display,
    ).map_err(|_| ResponseFeedbackRejection::Unavailable)?;
    if !try_lock_response_file(&file_lock)? { return Err(ResponseFeedbackRejection::Unavailable); }
    let path = namespace_path.join(STORE_FILE);
    let mut projection = read_projection(&namespace, &path)?;
    let (result, changed) = mutate(&mut projection)?;
    if changed {
        if !lock_binding.matches_regular_file_child_readonly(&namespace, OsStr::new(LOCK_FILE), &lock_display)
            .map_err(|_| ResponseFeedbackRejection::Unavailable)? { return Err(ResponseFeedbackRejection::Unavailable); }
        write_projection(&namespace, &path, &projection)?;
    }
    Ok(result)
}

fn read_projection(parent: &cap_std::fs::Dir, path: &Path) -> Result<StoredProjection, ResponseFeedbackRejection> {
    use crate::skills::store::read_regular_file_bounded;
    let name = path.file_name().ok_or(ResponseFeedbackRejection::Unavailable)?;
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(StoredProjection::default()),
        Err(_) => return Err(ResponseFeedbackRejection::Unavailable),
        Ok(_) => {}
    }
    let bytes = read_regular_file_bounded(parent, name, path, MAX_STORE_BYTES).map_err(|_| ResponseFeedbackRejection::Unavailable)?;
    let projection: StoredProjection = serde_json::from_slice(&bytes).map_err(|_| ResponseFeedbackRejection::Unavailable)?;
    validate_projection(&projection)?;
    Ok(projection)
}
fn write_projection(parent: &cap_std::fs::Dir, path: &Path, projection: &StoredProjection) -> Result<(), ResponseFeedbackRejection> {
    validate_projection(projection)?;
    let bytes = serde_json::to_vec(projection).map_err(|_| ResponseFeedbackRejection::Unavailable)?;
    if bytes.len() > MAX_STORE_BYTES { return Err(ResponseFeedbackRejection::Unavailable); }
    let name = path.file_name().ok_or(ResponseFeedbackRejection::Unavailable)?;
    crate::skills::store::atomic_write_private_child(parent, name, path, &bytes).map_err(|_| ResponseFeedbackRejection::Unavailable)
}

fn try_lock_response_file(file: &std::fs::File) -> Result<bool, ResponseFeedbackRejection> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(_)) => Err(ResponseFeedbackRejection::Unavailable),
    }
}
fn random_response_id() -> Result<ResponseId, ResponseFeedbackRejection> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| ResponseFeedbackRejection::Unavailable)?;
    ResponseId::parse(&hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    const SESSION: &str = "session-a";

    #[test]
    fn incognito_registration_is_zero_io() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(register_drained_terminal_response(home.path(), SESSION, true, 10).unwrap(), None);
        assert!(!home.path().join(STORE_DIR).exists());
    }

    #[test]
    fn fresh_home_registration_creates_the_private_projection_namespace() {
        let home = tempfile::tempdir().unwrap();
        let target = register_drained_terminal_response(home.path(), SESSION, false, 10).unwrap();
        assert!(target.is_some());
        assert!(store_path(home.path()).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn redirected_feedback_parent_and_data_leaf_fail_closed() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let redirected = tempfile::tempdir().unwrap();
        symlink(redirected.path(), home.path().join(STORE_DIR)).unwrap();
        assert_eq!(register_drained_terminal_response(home.path(), SESSION, false, 10), Err(ResponseFeedbackRejection::Unavailable));
        assert!(!redirected.path().join(STORE_FILE).exists());

        let clean_home = tempfile::tempdir().unwrap();
        let target = register_drained_terminal_response(clean_home.path(), SESSION, false, 10).unwrap().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let data = store_path(clean_home.path());
        std::fs::remove_file(&data).unwrap();
        symlink(outside.path().join("redirected.json"), &data).unwrap();
        assert_eq!(read_response_feedback_status(clean_home.path(), &target.response_id, SESSION), Err(ResponseFeedbackRejection::Unavailable));
        assert!(!outside.path().join("redirected.json").exists());

        let lock_home = tempfile::tempdir().unwrap();
        let lock_target = register_drained_terminal_response(lock_home.path(), SESSION, false, 10).unwrap().unwrap();
        let lock = lock_home.path().join(STORE_DIR).join(LOCK_FILE);
        std::fs::remove_file(&lock).unwrap();
        symlink(outside.path().join("redirected.lock"), &lock).unwrap();
        assert_eq!(read_response_feedback_status(lock_home.path(), &lock_target.response_id, SESSION), Err(ResponseFeedbackRejection::Unavailable));
        assert!(!outside.path().join("redirected.lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn nonprivate_feedback_parent_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let feedback = home.path().join(STORE_DIR);
        std::fs::create_dir(&feedback).unwrap();
        std::fs::set_permissions(&feedback, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(register_drained_terminal_response(home.path(), SESSION, false, 10), Err(ResponseFeedbackRejection::Unavailable));
    }

    #[test]
    fn set_replace_remove_is_revision_cas() {
        let home = tempfile::tempdir().unwrap();
        let target = register_drained_terminal_response(home.path(), SESSION, false, 10).unwrap().unwrap();
        assert_eq!(target.revision, 0);
        assert!(matches!(apply_response_feedback(home.path(), &target.response_id, SESSION, 0, ResponseFeedbackOperation::Set(ResponseSignal::NeedsCorrection), 11).unwrap(), ResponseFeedbackOutcome::Set { revision: 1, .. }));
        assert_eq!(apply_response_feedback(home.path(), &target.response_id, SESSION, 1, ResponseFeedbackOperation::Set(ResponseSignal::NeedsCorrection), 12).unwrap(), ResponseFeedbackOutcome::Unchanged { revision: 1 });
        assert!(matches!(apply_response_feedback(home.path(), &target.response_id, SESSION, 1, ResponseFeedbackOperation::Set(ResponseSignal::NotHelpful), 13).unwrap(), ResponseFeedbackOutcome::Replaced { revision: 2, .. }));
        assert_eq!(apply_response_feedback(home.path(), &target.response_id, SESSION, 1, ResponseFeedbackOperation::Remove, 14).unwrap(), ResponseFeedbackOutcome::Rejected(ResponseFeedbackRejection::Stale));
        assert!(matches!(apply_response_feedback(home.path(), &target.response_id, SESSION, 2, ResponseFeedbackOperation::Remove, 15).unwrap(), ResponseFeedbackOutcome::Removed { revision: 3 }));
        assert_eq!(apply_response_feedback(home.path(), &target.response_id, SESSION, 3, ResponseFeedbackOperation::Remove, 16).unwrap(), ResponseFeedbackOutcome::Unchanged { revision: 3 });
    }

    #[test]
    fn foreign_and_missing_pairs_reject_before_write() {
        let home = tempfile::tempdir().unwrap();
        let target = register_drained_terminal_response(home.path(), SESSION, false, 10).unwrap().unwrap();
        let path = store_path(home.path());
        let before = std::fs::read(&path).unwrap();
        assert_eq!(apply_response_feedback(home.path(), &target.response_id, "session-b", 0, ResponseFeedbackOperation::Remove, 11), Err(ResponseFeedbackRejection::Foreign));
        let missing = ResponseId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(apply_response_feedback(home.path(), &missing, SESSION, 0, ResponseFeedbackOperation::Remove, 11), Err(ResponseFeedbackRejection::Missing));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn inactive_eviction_never_recreates_evicted_target() {
        let home = tempfile::tempdir().unwrap();
        let first = register_drained_terminal_response(home.path(), SESSION, false, 1).unwrap().unwrap();
        for timestamp in 2..=MAX_TARGETS as i64 { register_drained_terminal_response(home.path(), SESSION, false, timestamp).unwrap(); }
        register_drained_terminal_response(home.path(), SESSION, false, 999).unwrap();
        assert_eq!(read_response_feedback_status(home.path(), &first.response_id, SESSION), Err(ResponseFeedbackRejection::Missing));
        assert_eq!(apply_response_feedback(home.path(), &first.response_id, SESSION, 0, ResponseFeedbackOperation::Set(ResponseSignal::NeedsCorrection), 1000), Err(ResponseFeedbackRejection::Missing));
    }

    #[test]
    fn full_active_projection_refuses_new_issuance() {
        let home = tempfile::tempdir().unwrap();
        for timestamp in 0..MAX_TARGETS as i64 {
            let target = register_drained_terminal_response(home.path(), SESSION, false, timestamp).unwrap().unwrap();
            apply_response_feedback(home.path(), &target.response_id, SESSION, 0, ResponseFeedbackOperation::Set(ResponseSignal::NeedsCorrection), timestamp).unwrap();
        }
        assert_eq!(register_drained_terminal_response(home.path(), SESSION, false, 999), Err(ResponseFeedbackRejection::Unavailable));
    }

    #[test]
    fn projection_is_content_free_and_invalid_loaded_projection_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        register_drained_terminal_response(home.path(), SESSION, false, 10).unwrap();
        let path = store_path(home.path());
        let serialized = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        for forbidden in ["prompt", "reply", "provider", "model", "freeform"] { assert!(!serialized.contains(forbidden)); }
        assert!(serialized.contains("updated_at_unix"));
        std::fs::write(&path, r#"{"targets":[{"response_id":"bad","session_id":"s","issued_at_unix":0,"updated_at_unix":0,"revision":0,"active_signal":null}]}"#).unwrap();
        assert_eq!(active_response_feedback_summary(home.path()), Err(ResponseFeedbackRejection::Unavailable));
        std::fs::write(&path, vec![b'x'; MAX_STORE_BYTES + 1]).unwrap();
        assert_eq!(active_response_feedback_summary(home.path()), Err(ResponseFeedbackRejection::Unavailable));
    }

    #[test]
    fn same_revision_concurrent_apply_has_one_winner() {
        let home = Arc::new(tempfile::tempdir().unwrap());
        let target = register_drained_terminal_response(home.path(), SESSION, false, 10).unwrap().unwrap();
        let first_home = Arc::clone(&home);
        let first_id = target.response_id.clone();
        let one = thread::spawn(move || apply_response_feedback(first_home.path(), &first_id, SESSION, 0, ResponseFeedbackOperation::Set(ResponseSignal::NeedsCorrection), 11));
        let second_home = Arc::clone(&home);
        let second_id = target.response_id;
        let two = thread::spawn(move || apply_response_feedback(second_home.path(), &second_id, SESSION, 0, ResponseFeedbackOperation::Set(ResponseSignal::NotHelpful), 12));
        let outcomes = [one.join().unwrap().unwrap(), two.join().unwrap().unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| matches!(outcome, ResponseFeedbackOutcome::Set { .. })).count(), 1);
        assert_eq!(outcomes.iter().filter(|outcome| matches!(outcome, ResponseFeedbackOutcome::Rejected(ResponseFeedbackRejection::Stale))).count(), 1);
    }
}
