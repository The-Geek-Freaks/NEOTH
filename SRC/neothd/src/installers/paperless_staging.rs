//! Deterministic, local-only Paperless Compose preparation.
//!
//! This owns only a marker, compose file, and secret-free template. It never
//! pulls or starts images, creates secrets, or treats preparation as artifact
//! or runtime verification.

use std::{ffi::OsStr, fmt, fs, io, path::Path};

use serde::Serialize;

pub const RELEASE: &str = "3.2.1";
pub const RECEIPT_SHA256: &str = "3c8cabbaae8b77ae48e707447fe6440c9511711f199ff924bda1094801309931";
pub const PAPERLESS_IMAGE: &str = "ghcr.io/paperless-ngx/paperless-ngx@sha256:5fa76604a81df6945086e0837b14b56543d137e8ce4f311cc5d9ebe907e74e79";
pub const VALKEY_IMAGE: &str = "registry-1.docker.io/valkey/valkey@sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11";
pub const POSTGRES_IMAGE: &str = "registry-1.docker.io/library/postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae";
/// Stable identity of the exact provenance contract rendered into Compose.
///
/// This changes whenever the admitted receipt or a selected OCI index pin
/// changes. It is intentionally distinct from an installed-image claim.
pub const OCI_CONTRACT_ID: &str = "paperless-oci-v1-3c8cabbaae8b77ae";
/// The currently admitted receipt contains index and child-manifest metadata,
/// but no config or layer bytes. A later receipt may lift this only after its
/// own admission and a matching contract update.
pub const OCI_PROVENANCE_COVERAGE: &str = "index_and_child_metadata_only";

const MARKER: &str = "ownership.json";
const COMPOSE: &str = "compose.yaml";
const ENV_EXAMPLE: &str = "paperless.env.example";
const OWNED_FILE_MAX_BYTES: usize = 16 * 1024;

#[cfg(test)]
thread_local! {
    static BEFORE_PUBLICATION_FOR_TEST: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static BEFORE_INSPECTION_REBIND_FOR_TEST: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static LAST_PREPARE_IO_DIAGNOSTIC_FOR_TEST: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_before_publication_for_test(hook: impl FnOnce() + 'static) {
    BEFORE_PUBLICATION_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_publication_for_test() {
    BEFORE_PUBLICATION_FOR_TEST.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn set_before_inspection_rebind_for_test(hook: impl FnOnce() + 'static) {
    BEFORE_INSPECTION_REBIND_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_inspection_rebind_for_test() {
    BEFORE_INSPECTION_REBIND_FOR_TEST.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
pub(crate) fn last_prepare_io_diagnostic_for_test() -> Option<String> {
    LAST_PREPARE_IO_DIAGNOSTIC_FOR_TEST.with(|slot| slot.borrow().clone())
}

#[cfg(test)]
fn clear_prepare_io_diagnostic_for_test() {
    LAST_PREPARE_IO_DIAGNOSTIC_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn record_prepare_io_diagnostic_for_test(stage: &'static str, error: &anyhow::Error) {
    let detail = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .map(|error| format!("kind={:?};raw={:?}", error.kind(), error.raw_os_error()))
        .unwrap_or_else(|| "kind=unavailable;raw=unavailable".to_owned());
    LAST_PREPARE_IO_DIAGNOSTIC_FOR_TEST.with(|slot| {
        *slot.borrow_mut() = Some(format!("stage={stage};{detail}"));
    });
}

fn prepare_io(stage: &'static str, error: anyhow::Error) -> PaperlessStagingError {
    #[cfg(test)]
    record_prepare_io_diagnostic_for_test(stage, &error);
    let _ = (stage, error);
    PaperlessStagingError::Io
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaperlessStagingStatus {
    NotPrepared,
    PreparedPinned,
    AlreadyPrepared,
    UnownedOrMismatch,
}

#[derive(Clone, Debug, Serialize)]
pub struct PaperlessStagingView {
    pub status: PaperlessStagingStatus,
    pub receipt_id: &'static str,
    pub contract_id: &'static str,
    pub provenance_coverage: &'static str,
    pub prepared: bool,
}

#[derive(Debug)]
pub enum PaperlessStagingError {
    UnsafePath,
    UnownedOrMismatch,
    Io,
}
impl fmt::Display for PaperlessStagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsafePath => "unsafe_path",
            Self::UnownedOrMismatch => "unowned_or_mismatch",
            Self::Io => "io_error",
        })
    }
}
impl std::error::Error for PaperlessStagingError {}

pub fn inspect_at(root: &Path) -> PaperlessStagingView {
    match inspect_owned(root) {
        Ok(true) => view(PaperlessStagingStatus::AlreadyPrepared),
        Ok(false) => view(PaperlessStagingStatus::NotPrepared),
        Err(_) => view(PaperlessStagingStatus::UnownedOrMismatch),
    }
}

pub fn prepare_at(root: &Path) -> Result<PaperlessStagingView, PaperlessStagingError> {
    #[cfg(test)]
    clear_prepare_io_diagnostic_for_test();
    validate_existing_ancestors(root)?;
    match inspect_owned(root) {
        Ok(true) => return Ok(view(PaperlessStagingStatus::AlreadyPrepared)),
        Ok(false) => {}
        Err(error) => return Err(error),
    }
    let parent_path = root.parent().ok_or(PaperlessStagingError::UnsafePath)?;
    let root_name = root.file_name().ok_or(PaperlessStagingError::UnsafePath)?;
    let parent = match crate::skills::store::open_absolute_bound_directory(
        parent_path,
        false,
        "paperless",
    ) {
        Ok(Some(parent)) => parent,
        Ok(None) => return Err(PaperlessStagingError::Io),
        Err(error) => return Err(prepare_io("open_parent", error)),
    };
    let stage_name = staging_child_name(root_name);
    let stage_display = parent.physical_display_path.join(&stage_name);
    parent
        .dir
        .create_dir(&stage_name)
        .map_err(|error| prepare_io("create_stage", error.into()))?;
    let stage_binding =
        crate::skills::store::bind_child_object(&parent.dir, &stage_name, &stage_display)
            .map_err(|error| prepare_io("bind_stage", error))?;
    let stage_dir = crate::skills::store::open_bound_real_child_dir_for_read(
        &parent.dir,
        &stage_binding,
        &stage_name,
        &stage_display,
    )
    .map_err(|error| prepare_io("open_stage", error))?;
    for (name, bytes) in expected_files() {
        let file_display = stage_display.join(name);
        if let Err(error) = crate::skills::store::atomic_write_private_child_create_new(
            &stage_dir,
            OsStr::new(name),
            &file_display,
            bytes,
        ) {
            let _ = crate::skills::store::remove_bound_real_directory_tree(
                &parent.dir,
                &stage_name,
                &stage_display,
                stage_binding.identity_token(),
            );
            return Err(prepare_io("write_owned_file", error));
        }
    }
    #[cfg(test)]
    run_before_publication_for_test();
    if crate::skills::store::rename_bound_child(
        &stage_binding,
        &parent.dir,
        &stage_name,
        &parent.dir,
        root_name,
        &stage_display,
        root,
    )
    .is_err()
    {
        let _ = crate::skills::store::remove_bound_real_directory_tree(
            &parent.dir,
            &stage_name,
            &stage_display,
            stage_binding.identity_token(),
        );
        return Err(PaperlessStagingError::UnownedOrMismatch);
    }
    if !requested_namespace_still_names_stage(root, stage_binding.identity_token()) {
        return Err(PaperlessStagingError::UnownedOrMismatch);
    }
    Ok(view(PaperlessStagingStatus::PreparedPinned))
}

fn requested_namespace_still_names_stage(root: &Path, expected_identity: &str) -> bool {
    let Some(parent_path) = root.parent() else {
        return false;
    };
    let Some(root_name) = root.file_name() else {
        return false;
    };
    let Ok(Some(parent)) =
        crate::skills::store::open_absolute_bound_directory(parent_path, false, "paperless")
    else {
        return false;
    };
    let display = parent.physical_display_path.join(root_name);
    let Ok((_root_dir, binding)) =
        crate::skills::store::open_bound_real_child_dir(&parent.dir, root_name, &display)
    else {
        return false;
    };
    binding.identity_token() == expected_identity
}

fn view(status: PaperlessStagingStatus) -> PaperlessStagingView {
    let prepared = matches!(
        status,
        PaperlessStagingStatus::PreparedPinned | PaperlessStagingStatus::AlreadyPrepared
    );
    PaperlessStagingView {
        status,
        receipt_id: RECEIPT_SHA256,
        contract_id: OCI_CONTRACT_ID,
        provenance_coverage: OCI_PROVENANCE_COVERAGE,
        prepared,
    }
}
fn expected_files() -> [(&'static str, &'static [u8]); 3] {
    [
        (MARKER, ownership_bytes()),
        (COMPOSE, compose_bytes()),
        (ENV_EXAMPLE, env_example_bytes()),
    ]
}
fn ownership_bytes() -> &'static [u8] {
    b"{\"schema\":2,\"release\":\"3.2.1\",\"receipt_sha256\":\"3c8cabbaae8b77ae48e707447fe6440c9511711f199ff924bda1094801309931\",\"contract_id\":\"paperless-oci-v1-3c8cabbaae8b77ae\",\"provenance_coverage\":\"index_and_child_metadata_only\",\"source_commit\":\"96f86a92c526275a97b2c1e44c3040ba3af55f43\"}\n"
}
fn env_example_bytes() -> &'static [u8] {
    b"# Copy to paperless.env and set every value outside NEOTH.\nPAPERLESS_SECRET_KEY=\nPAPERLESS_DB_NAME=\nPAPERLESS_DB_USER=\nPAPERLESS_DB_PASSWORD=\nPAPERLESS_ADMIN_USER=\nPAPERLESS_ADMIN_PASSWORD=\nPAPERLESS_BIND_PORT=\n"
}
fn compose_bytes() -> &'static [u8] {
    b"services:\n  webserver:\n    image: ghcr.io/paperless-ngx/paperless-ngx@sha256:5fa76604a81df6945086e0837b14b56543d137e8ce4f311cc5d9ebe907e74e79\n    env_file:\n      - ./paperless.env\n    environment:\n      PAPERLESS_SECRET_KEY: ${PAPERLESS_SECRET_KEY:?PAPERLESS_SECRET_KEY is required}\n      PAPERLESS_DBNAME: ${PAPERLESS_DB_NAME:?PAPERLESS_DB_NAME is required}\n      PAPERLESS_DBUSER: ${PAPERLESS_DB_USER:?PAPERLESS_DB_USER is required}\n      PAPERLESS_DBPASS: ${PAPERLESS_DB_PASSWORD:?PAPERLESS_DB_PASSWORD is required}\n      PAPERLESS_ADMIN_USER: ${PAPERLESS_ADMIN_USER:?PAPERLESS_ADMIN_USER is required}\n      PAPERLESS_ADMIN_PASSWORD: ${PAPERLESS_ADMIN_PASSWORD:?PAPERLESS_ADMIN_PASSWORD is required}\n      PAPERLESS_REDIS: redis://broker:6379\n      PAPERLESS_DBHOST: db\n    ports:\n      - \"127.0.0.1:${PAPERLESS_BIND_PORT:?PAPERLESS_BIND_PORT is required}:8000\"\n    volumes:\n      - ./state/data:/usr/src/paperless/data\n      - ./state/media:/usr/src/paperless/media\n  broker:\n    image: registry-1.docker.io/valkey/valkey@sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11\n    volumes:\n      - ./state/valkey:/data\n  db:\n    image: registry-1.docker.io/library/postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae\n    env_file:\n      - ./paperless.env\n    environment:\n      POSTGRES_DB: ${PAPERLESS_DB_NAME:?PAPERLESS_DB_NAME is required}\n      POSTGRES_USER: ${PAPERLESS_DB_USER:?PAPERLESS_DB_USER is required}\n      POSTGRES_PASSWORD: ${PAPERLESS_DB_PASSWORD:?PAPERLESS_DB_PASSWORD is required}\n    volumes:\n      - ./state/postgres:/var/lib/postgresql\n"
}

#[cfg(windows)]
pub(crate) fn expected_compose_bytes() -> &'static [u8] {
    compose_bytes()
}

/// A byte-validated, capability-bound Paperless root. It is crate-internal so
/// lifecycle code can retain one identity across external Docker operations.
pub(crate) struct OwnedPaperlessRoot {
    pub(crate) parent: cap_std::fs::Dir,
    pub(crate) root: cap_std::fs::Dir,
    pub(crate) binding: crate::skills::store::BoundDirectoryChild,
    pub(crate) display: std::path::PathBuf,
    pub(crate) root_name: std::ffi::OsString,
}
impl OwnedPaperlessRoot {
    pub(crate) fn still_bound(&self) -> Result<bool, PaperlessStagingError> {
        self.binding
            .matches_directory_child(&self.parent, &self.root_name, &self.display)
            .map_err(|_| PaperlessStagingError::Io)
    }
}

/// Revalidate the original namespace binding and the exact staged payload
/// after an external operation.  Callers retain `OwnedPaperlessRoot` across
/// awaits; this prevents a same-named replacement from becoming trusted.
pub(crate) fn still_exactly_owned(
    root: &OwnedPaperlessRoot,
) -> Result<bool, PaperlessStagingError> {
    if !root.still_bound()?
        || !requested_namespace_still_names_stage(&root.display, root.binding.identity_token())
    {
        return Ok(false);
    }
    match open_owned_root_at(&root.display) {
        Ok(reopened) => Ok(reopened.binding.identity_token() == root.binding.identity_token()),
        Err(PaperlessStagingError::UnownedOrMismatch | PaperlessStagingError::UnsafePath) => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn open_owned_root_at(root: &Path) -> Result<OwnedPaperlessRoot, PaperlessStagingError> {
    validate_existing_ancestors(root)?;
    let parent_path = root.parent().ok_or(PaperlessStagingError::UnsafePath)?;
    let root_name = root
        .file_name()
        .ok_or(PaperlessStagingError::UnsafePath)?
        .to_os_string();
    let parent =
        crate::skills::store::open_absolute_bound_directory(parent_path, false, "paperless")
            .map_err(|_| PaperlessStagingError::Io)?
            .ok_or(PaperlessStagingError::Io)?;
    let (root_dir, binding) =
        crate::skills::store::open_bound_real_child_dir(&parent.dir, &root_name, root)
            .map_err(|_| PaperlessStagingError::UnsafePath)?;
    for (name, expected) in expected_files() {
        let bytes = crate::skills::store::read_regular_file_bounded(
            &root_dir,
            OsStr::new(name),
            &root.join(name),
            OWNED_FILE_MAX_BYTES,
        )
        .map_err(|_| PaperlessStagingError::UnownedOrMismatch)?;
        if bytes != expected {
            return Err(PaperlessStagingError::UnownedOrMismatch);
        }
    }
    for entry in root_dir.entries().map_err(|_| PaperlessStagingError::Io)? {
        let name = entry.map_err(|_| PaperlessStagingError::Io)?.file_name();
        match name.to_str() {
            Some(MARKER | COMPOSE | ENV_EXAMPLE) => {}
            Some("paperless.env") => {
                crate::skills::store::open_regular_file(&root_dir, &name, &root.join(&name))
                    .map_err(|_| PaperlessStagingError::UnownedOrMismatch)?;
            }
            Some("state") => {
                crate::skills::store::open_real_child_dir(&root_dir, &name, &root.join(&name))
                    .map_err(|_| PaperlessStagingError::UnownedOrMismatch)?;
            }
            _ => return Err(PaperlessStagingError::UnownedOrMismatch),
        }
    }
    let owned = OwnedPaperlessRoot {
        parent: parent.dir,
        root: root_dir,
        binding,
        display: root.to_path_buf(),
        root_name,
    };
    if !owned.still_bound()? {
        return Err(PaperlessStagingError::UnownedOrMismatch);
    }
    Ok(owned)
}
fn inspect_owned(root: &Path) -> Result<bool, PaperlessStagingError> {
    validate_existing_ancestors(root)?;
    let parent_path = root.parent().ok_or(PaperlessStagingError::UnsafePath)?;
    let root_name = root.file_name().ok_or(PaperlessStagingError::UnsafePath)?;
    let parent = match crate::skills::store::open_absolute_bound_directory(
        parent_path,
        false,
        "paperless",
    ) {
        Ok(Some(parent)) => parent,
        Ok(None) => return Ok(false),
        Err(error) => return Err(prepare_io("inspect_open_parent", error)),
    };
    let (root_dir, root_binding) =
        match crate::skills::store::open_bound_real_child_dir(&parent.dir, root_name, root) {
            Ok(bound) => bound,
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<io::Error>()
                    .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(false);
            }
            Err(_) => return Err(PaperlessStagingError::UnsafePath),
        };
    for (name, expected) in expected_files() {
        let bytes = crate::skills::store::read_regular_file_bounded(
            &root_dir,
            OsStr::new(name),
            &root.join(name),
            OWNED_FILE_MAX_BYTES,
        )
        .map_err(|_| PaperlessStagingError::UnownedOrMismatch)?;
        if bytes != expected {
            return Err(PaperlessStagingError::UnownedOrMismatch);
        }
    }
    for entry in root_dir.entries().map_err(|_| PaperlessStagingError::Io)? {
        let entry = entry.map_err(|_| PaperlessStagingError::Io)?;
        let name = entry.file_name();
        match name.to_str() {
            Some(MARKER | COMPOSE | ENV_EXAMPLE) => {}
            Some("paperless.env") => {
                crate::skills::store::open_regular_file(&root_dir, &name, &root.join(&name))
                    .map_err(|_| PaperlessStagingError::UnownedOrMismatch)?;
            }
            Some("state") => {
                crate::skills::store::open_real_child_dir(&root_dir, &name, &root.join(&name))
                    .map_err(|_| PaperlessStagingError::UnownedOrMismatch)?;
            }
            _ => return Err(PaperlessStagingError::UnownedOrMismatch),
        }
    }
    #[cfg(test)]
    run_before_inspection_rebind_for_test();
    if !root_binding
        .matches_directory_child(&parent.dir, root_name, root)
        .map_err(|_| PaperlessStagingError::Io)?
    {
        return Err(PaperlessStagingError::UnownedOrMismatch);
    }
    if !requested_namespace_still_names_stage(root, root_binding.identity_token()) {
        return Err(PaperlessStagingError::UnownedOrMismatch);
    }
    Ok(true)
}
fn staging_child_name(root_name: &OsStr) -> std::ffi::OsString {
    let mut staged = root_name.to_os_string();
    staged.push(format!(".neoth-stage-{}", std::process::id()));
    staged
}
fn validate_existing_ancestors(root: &Path) -> Result<(), PaperlessStagingError> {
    for ancestor in root.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.is_dir() && !unsafe_metadata(&metadata) => {}
            Ok(_) => return Err(PaperlessStagingError::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(prepare_io("validate_ancestor", error.into())),
        }
    }
    Ok(())
}
fn unsafe_metadata(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return metadata.file_attributes() & 0x400 != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_temp_root(temp: &tempfile::TempDir) -> std::path::PathBuf {
        fs::canonicalize(temp.path()).unwrap()
    }
    #[test]
    fn renderer_is_pinned_loopback_and_secret_free() {
        let compose = std::str::from_utf8(compose_bytes()).unwrap();
        for image in [PAPERLESS_IMAGE, VALKEY_IMAGE, POSTGRES_IMAGE] {
            assert!(compose.contains(image));
        }
        assert!(compose.contains("127.0.0.1:"));
        assert!(compose.contains("- ./paperless.env"));
        assert!(compose.contains("./state/postgres:/var/lib/postgresql"));
        assert!(!compose.contains("/var/lib/postgresql/data"));
        assert!(
            !compose.contains("latest")
                && !compose.contains("curl")
                && !compose.contains("password=")
        );
    }

    #[test]
    fn ownership_binds_the_exact_receipt_contract_and_coverage_boundary() {
        let ownership = std::str::from_utf8(ownership_bytes()).unwrap();
        assert!(ownership.contains(RECEIPT_SHA256));
        assert!(ownership.contains(OCI_CONTRACT_ID));
        assert!(ownership.contains(OCI_PROVENANCE_COVERAGE));
        assert!(!ownership.contains("artifact_verified"));
    }
    #[test]
    fn prepare_is_deterministic_and_preserves_operator_env_and_state() {
        let parent = tempfile::tempdir().unwrap();
        let root = canonical_temp_root(&parent).join("paperless");
        assert_eq!(
            prepare_at(&root).unwrap().status,
            PaperlessStagingStatus::PreparedPinned
        );
        let env = root.join("paperless.env");
        let state = root.join("state").join("data").join("retained");
        fs::write(&env, b"operator-secret").unwrap();
        fs::create_dir_all(state.parent().unwrap()).unwrap();
        fs::write(&state, b"retained-state").unwrap();
        assert_eq!(
            prepare_at(&root).unwrap().status,
            PaperlessStagingStatus::AlreadyPrepared
        );
        assert_eq!(fs::read(&env).unwrap(), b"operator-secret");
        assert_eq!(fs::read(&state).unwrap(), b"retained-state");
    }
    #[test]
    fn foreign_entry_after_prepare_is_rejected_without_touching_operator_env() {
        let parent = tempfile::tempdir().unwrap();
        let root = canonical_temp_root(&parent).join("paperless");
        prepare_at(&root).unwrap();
        fs::write(root.join("foreign"), b"keep").unwrap();
        fs::write(root.join("paperless.env"), b"operator-secret").unwrap();
        assert!(matches!(
            prepare_at(&root),
            Err(PaperlessStagingError::UnownedOrMismatch)
        ));
        assert_eq!(fs::read(root.join("foreign")).unwrap(), b"keep");
        assert_eq!(
            fs::read(root.join("paperless.env")).unwrap(),
            b"operator-secret"
        );
    }
    #[test]
    fn changed_owned_file_is_rejected_without_touching_operator_env() {
        let parent = tempfile::tempdir().unwrap();
        let root = canonical_temp_root(&parent).join("paperless");
        prepare_at(&root).unwrap();
        fs::write(root.join(COMPOSE), b"changed").unwrap();
        fs::write(root.join("paperless.env"), b"operator-secret").unwrap();
        assert!(matches!(
            prepare_at(&root),
            Err(PaperlessStagingError::UnownedOrMismatch)
        ));
        assert_eq!(fs::read(root.join(COMPOSE)).unwrap(), b"changed");
        assert_eq!(
            fs::read(root.join("paperless.env")).unwrap(),
            b"operator-secret"
        );
    }

    #[test]
    fn stale_contract_marker_is_rejected_without_touching_operator_env_or_state() {
        let parent = tempfile::tempdir().unwrap();
        let root = canonical_temp_root(&parent).join("paperless");
        prepare_at(&root).unwrap();
        fs::write(
            root.join(MARKER),
            b"{\"schema\":1,\"contract_id\":\"stale\"}\n",
        )
        .unwrap();
        fs::write(root.join("paperless.env"), b"operator-secret").unwrap();
        let retained = root.join("state").join("data").join("retained");
        fs::create_dir_all(retained.parent().unwrap()).unwrap();
        fs::write(&retained, b"retained-state").unwrap();

        assert!(matches!(
            prepare_at(&root),
            Err(PaperlessStagingError::UnownedOrMismatch)
        ));
        assert!(
            fs::read_to_string(root.join(MARKER))
                .unwrap()
                .contains("stale")
        );
        assert_eq!(
            fs::read(root.join("paperless.env")).unwrap(),
            b"operator-secret"
        );
        assert_eq!(fs::read(&retained).unwrap(), b"retained-state");
    }
    #[cfg(unix)]
    #[test]
    fn symlink_root_is_rejected_without_following_target() {
        use std::os::unix::fs::symlink;
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"unchanged").unwrap();
        let root = canonical_temp_root(&parent).join("paperless");
        symlink(&target, &root).unwrap();
        assert!(matches!(
            prepare_at(&root),
            Err(PaperlessStagingError::UnsafePath)
        ));
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"unchanged");
    }

    #[test]
    fn competing_root_before_publication_is_preserved() {
        let parent = tempfile::tempdir().unwrap();
        let root = canonical_temp_root(&parent).join("paperless");
        let competing_root = root.clone();
        let parent_path = root.parent().unwrap().to_path_buf();
        let competitor_identity = std::rc::Rc::new(std::cell::RefCell::new(None));
        let captured_identity = competitor_identity.clone();
        set_before_publication_for_test(move || {
            fs::create_dir(&competing_root).unwrap();
            let bound_parent = crate::skills::store::open_absolute_bound_directory(
                &parent_path,
                false,
                "test paperless parent",
            )
            .unwrap()
            .unwrap();
            let (_competitor, binding) = crate::skills::store::open_bound_real_child_dir(
                &bound_parent.dir,
                OsStr::new("paperless"),
                &competing_root,
            )
            .unwrap();
            *captured_identity.borrow_mut() = Some(binding.identity_token().to_owned());
        });

        assert!(matches!(
            prepare_at(&root),
            Err(PaperlessStagingError::UnownedOrMismatch)
        ));
        let bound_parent = crate::skills::store::open_absolute_bound_directory(
            root.parent().unwrap(),
            false,
            "test paperless parent",
        )
        .unwrap()
        .unwrap();
        let (_competitor, binding) = crate::skills::store::open_bound_real_child_dir(
            &bound_parent.dir,
            OsStr::new("paperless"),
            &root,
        )
        .unwrap();
        assert_eq!(
            Some(binding.identity_token().to_owned()),
            *competitor_identity.borrow()
        );
        assert!(fs::read_dir(&root).unwrap().next().is_none());
        assert!(
            !root
                .parent()
                .unwrap()
                .join(staging_child_name(OsStr::new("paperless")))
                .exists()
        );
    }

    #[test]
    fn stage_source_swap_before_bound_publish_is_refused() {
        let parent = tempfile::tempdir().unwrap();
        let parent_root = canonical_temp_root(&parent);
        let root = parent_root.join("paperless");
        let stage = parent_root.join(staging_child_name(OsStr::new("paperless")));
        let displaced = parent_root.join("displaced-stage");
        let swapped_stage = stage.clone();
        let displaced_by_swap = displaced.clone();
        set_before_publication_for_test(move || {
            fs::rename(&swapped_stage, &displaced_by_swap).unwrap();
            fs::create_dir(&swapped_stage).unwrap();
            fs::write(swapped_stage.join("attacker"), b"preserve").unwrap();
        });

        assert!(matches!(
            prepare_at(&root),
            Err(PaperlessStagingError::UnownedOrMismatch)
        ));
        assert!(!root.exists());
        assert_eq!(fs::read(stage.join("attacker")).unwrap(), b"preserve");
        assert!(displaced.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_swap_does_not_publish_into_replacement() {
        use std::os::unix::fs::symlink;

        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("bound-parent");
        let moved_parent = base.path().join("moved-parent");
        let replacement = base.path().join("replacement");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&replacement).unwrap();
        let root = parent.join("paperless");
        let swap_parent = parent.clone();
        let swap_moved = moved_parent.clone();
        let swap_replacement = replacement.clone();
        set_before_publication_for_test(move || {
            fs::rename(&swap_parent, &swap_moved).unwrap();
            symlink(&swap_replacement, &swap_parent).unwrap();
        });

        assert!(matches!(
            prepare_at(&root),
            Err(PaperlessStagingError::UnownedOrMismatch)
        ));
        assert!(moved_parent.join("paperless").is_dir());
        assert!(!replacement.join("paperless").exists());
    }

    #[cfg(unix)]
    #[test]
    fn inspection_parent_swap_reports_mismatch() {
        use std::os::unix::fs::symlink;

        let base = tempfile::tempdir().unwrap();
        let base_root = fs::canonicalize(base.path()).unwrap();
        let parent = base_root.join("parent");
        let moved = base_root.join("moved");
        let replacement = base_root.join("replacement");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&replacement).unwrap();
        let root = parent.join("paperless");
        prepare_at(&root).unwrap();
        let swap_parent = parent.clone();
        let swap_moved = moved.clone();
        let swap_replacement = replacement.clone();
        set_before_inspection_rebind_for_test(move || {
            fs::rename(&swap_parent, &swap_moved).unwrap();
            symlink(&swap_replacement, &swap_parent).unwrap();
        });
        assert_eq!(
            inspect_at(&root).status,
            PaperlessStagingStatus::UnownedOrMismatch
        );
        assert!(moved.join("paperless").is_dir());
        assert!(!replacement.join("paperless").exists());
    }
}
