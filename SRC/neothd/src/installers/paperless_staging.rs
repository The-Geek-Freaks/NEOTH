//! Deterministic, local-only Paperless Compose preparation.
//!
//! This owns only a marker, compose file, and secret-free template. It never
//! pulls or starts images, creates secrets, or treats preparation as artifact
//! or runtime verification.

use std::{
    fmt, fs,
    io::{self, Read},
    path::Path,
};

use serde::Serialize;

pub const RELEASE: &str = "3.2.1";
pub const RECEIPT_SHA256: &str = "3c8cabbaae8b77ae48e707447fe6440c9511711f199ff924bda1094801309931";
pub const PAPERLESS_IMAGE: &str = "ghcr.io/paperless-ngx/paperless-ngx@sha256:5fa76604a81df6945086e0837b14b56543d137e8ce4f311cc5d9ebe907e74e79";
pub const VALKEY_IMAGE: &str = "registry-1.docker.io/valkey/valkey@sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11";
pub const POSTGRES_IMAGE: &str = "registry-1.docker.io/library/postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae";

const MARKER: &str = "ownership.json";
const COMPOSE: &str = "compose.yaml";
const ENV_EXAMPLE: &str = "paperless.env.example";
const OWNED_FILE_MAX_BYTES: usize = 16 * 1024;

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
    validate_existing_ancestors(root)?;
    match inspect_owned(root) {
        Ok(true) => return Ok(view(PaperlessStagingStatus::AlreadyPrepared)),
        Ok(false) => {}
        Err(error) => return Err(error),
    }
    let stage = staging_sibling(root)?;
    fs::create_dir(&stage).map_err(|_| PaperlessStagingError::Io)?;
    for (name, bytes) in expected_files() {
        let path = stage.join(name);
        if crate::util::atomic_write::write_private_create_new_durable(&path, bytes).is_err() {
            let _ = fs::remove_dir_all(&stage);
            return Err(PaperlessStagingError::Io);
        }
    }
    if let Err(error) = fs::rename(&stage, root) {
        let _ = fs::remove_dir_all(&stage);
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            PaperlessStagingError::UnownedOrMismatch
        } else {
            PaperlessStagingError::Io
        });
    }
    Ok(view(PaperlessStagingStatus::PreparedPinned))
}

fn view(status: PaperlessStagingStatus) -> PaperlessStagingView {
    let prepared = matches!(
        status,
        PaperlessStagingStatus::PreparedPinned | PaperlessStagingStatus::AlreadyPrepared
    );
    PaperlessStagingView {
        status,
        receipt_id: RECEIPT_SHA256,
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
    b"{\"schema\":1,\"release\":\"3.2.1\",\"receipt_sha256\":\"3c8cabbaae8b77ae48e707447fe6440c9511711f199ff924bda1094801309931\",\"source_commit\":\"96f86a92c526275a97b2c1e44c3040ba3af55f43\"}\n"
}
fn env_example_bytes() -> &'static [u8] {
    b"# Copy to paperless.env and set every value outside NEOTH.\nPAPERLESS_SECRET_KEY=\nPAPERLESS_DB_NAME=\nPAPERLESS_DB_USER=\nPAPERLESS_DB_PASSWORD=\nPAPERLESS_ADMIN_USER=\nPAPERLESS_ADMIN_PASSWORD=\nPAPERLESS_BIND_PORT=\n"
}
fn compose_bytes() -> &'static [u8] {
    b"services:\n  webserver:\n    image: ghcr.io/paperless-ngx/paperless-ngx@sha256:5fa76604a81df6945086e0837b14b56543d137e8ce4f311cc5d9ebe907e74e79\n    env_file:\n      - ./paperless.env\n    environment:\n      PAPERLESS_SECRET_KEY: ${PAPERLESS_SECRET_KEY:?PAPERLESS_SECRET_KEY is required}\n      PAPERLESS_DBNAME: ${PAPERLESS_DB_NAME:?PAPERLESS_DB_NAME is required}\n      PAPERLESS_DBUSER: ${PAPERLESS_DB_USER:?PAPERLESS_DB_USER is required}\n      PAPERLESS_DBPASS: ${PAPERLESS_DB_PASSWORD:?PAPERLESS_DB_PASSWORD is required}\n      PAPERLESS_ADMIN_USER: ${PAPERLESS_ADMIN_USER:?PAPERLESS_ADMIN_USER is required}\n      PAPERLESS_ADMIN_PASSWORD: ${PAPERLESS_ADMIN_PASSWORD:?PAPERLESS_ADMIN_PASSWORD is required}\n      PAPERLESS_REDIS: redis://broker:6379\n      PAPERLESS_DBHOST: db\n    ports:\n      - \"127.0.0.1:${PAPERLESS_BIND_PORT:?PAPERLESS_BIND_PORT is required}:8000\"\n    volumes:\n      - ./state/data:/usr/src/paperless/data\n      - ./state/media:/usr/src/paperless/media\n  broker:\n    image: registry-1.docker.io/valkey/valkey@sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11\n    volumes:\n      - ./state/valkey:/data\n  db:\n    image: registry-1.docker.io/library/postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae\n    env_file:\n      - ./paperless.env\n    environment:\n      POSTGRES_DB: ${PAPERLESS_DB_NAME:?PAPERLESS_DB_NAME is required}\n      POSTGRES_USER: ${PAPERLESS_DB_USER:?PAPERLESS_DB_USER is required}\n      POSTGRES_PASSWORD: ${PAPERLESS_DB_PASSWORD:?PAPERLESS_DB_PASSWORD is required}\n    volumes:\n      - ./state/postgres:/var/lib/postgresql\n"
}

fn inspect_owned(root: &Path) -> Result<bool, PaperlessStagingError> {
    validate_existing_ancestors(root)?;
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(PaperlessStagingError::Io),
        Ok(metadata) => {
            if !metadata.is_dir() || unsafe_metadata(&metadata) {
                return Err(PaperlessStagingError::UnsafePath);
            }
        }
    }
    for (name, expected) in expected_files() {
        let path = root.join(name);
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| PaperlessStagingError::UnownedOrMismatch)?;
        if !metadata.is_file()
            || unsafe_metadata(&metadata)
            || metadata.len() != expected.len() as u64
            || metadata.len() > OWNED_FILE_MAX_BYTES as u64
        {
            return Err(PaperlessStagingError::UnownedOrMismatch);
        }
        if !read_owned_exact(&path, expected)? {
            return Err(PaperlessStagingError::UnownedOrMismatch);
        }
    }
    for entry in fs::read_dir(root).map_err(|_| PaperlessStagingError::Io)? {
        let entry = entry.map_err(|_| PaperlessStagingError::Io)?;
        let name = entry.file_name();
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| PaperlessStagingError::Io)?;
        match name.to_str() {
            Some(MARKER | COMPOSE | ENV_EXAMPLE) => {
                if !metadata.is_file() || unsafe_metadata(&metadata) {
                    return Err(PaperlessStagingError::UnownedOrMismatch);
                }
            }
            Some("paperless.env") => {
                if !metadata.is_file() || unsafe_metadata(&metadata) {
                    return Err(PaperlessStagingError::UnownedOrMismatch);
                }
            }
            Some("state") => {
                if !metadata.is_dir() || unsafe_metadata(&metadata) {
                    return Err(PaperlessStagingError::UnownedOrMismatch);
                }
            }
            _ => return Err(PaperlessStagingError::UnownedOrMismatch),
        }
    }
    Ok(true)
}
fn read_owned_exact(path: &Path, expected: &[u8]) -> Result<bool, PaperlessStagingError> {
    let mut bounded = fs::File::open(path)
        .map_err(|_| PaperlessStagingError::Io)?
        .take(expected.len() as u64 + 1);
    let mut bytes = Vec::with_capacity(expected.len() + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| PaperlessStagingError::Io)?;
    Ok(bytes == expected)
}
fn staging_sibling(root: &Path) -> Result<std::path::PathBuf, PaperlessStagingError> {
    let name = root.file_name().ok_or(PaperlessStagingError::UnsafePath)?;
    let mut staged = name.to_os_string();
    staged.push(format!(".neoth-stage-{}", std::process::id()));
    Ok(root.with_file_name(staged))
}
fn validate_existing_ancestors(root: &Path) -> Result<(), PaperlessStagingError> {
    for ancestor in root.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.is_dir() && !unsafe_metadata(&metadata) => {}
            Ok(_) => return Err(PaperlessStagingError::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(PaperlessStagingError::Io),
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
    fn prepare_is_deterministic_and_preserves_operator_env_and_state() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("paperless");
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
        let root = parent.path().join("paperless");
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
        let root = parent.path().join("paperless");
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
    #[cfg(unix)]
    #[test]
    fn symlink_root_is_rejected_without_following_target() {
        use std::os::unix::fs::symlink;
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"unchanged").unwrap();
        let root = parent.path().join("paperless");
        symlink(&target, &root).unwrap();
        assert!(matches!(
            prepare_at(&root),
            Err(PaperlessStagingError::UnsafePath)
        ));
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"unchanged");
    }
}
