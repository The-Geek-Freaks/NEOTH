//! Deterministic, capability-bound local-file import planning.
//!
//! This module stops before persistence, WAL, projection, model invocation,
//! or background work. A connector control plane first approves one local
//! directory, then issues a non-forgeable operator capability. Import paths
//! are relative to the open root handle and every component is traversed
//! without following links. Returned text remains explicitly untrusted data.

use std::{
    fmt,
    path::{Component, Path},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::{
    ffi::CString,
    fs::{File, Metadata},
    io::Read,
};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::control_plane::{
    ContextImportCapabilityBinding, ContextImportOperationLease, ContextImportRuntimeBinding,
};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_IMPORT_BYTES: usize = 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_RECORDS_PER_PLAN: usize = 4_096;
pub const LOCAL_IMPORT_PARSER_REVISION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalImportPolicy {
    revision: u64,
    max_bytes: usize,
    max_record_bytes: usize,
}

impl LocalImportPolicy {
    pub fn new(
        revision: u64,
        max_bytes: usize,
        max_record_bytes: usize,
    ) -> Result<Self, LocalImportError> {
        if revision == 0
            || max_bytes == 0
            || max_bytes > MAX_IMPORT_BYTES
            || max_record_bytes == 0
            || max_record_bytes > MAX_RECORD_BYTES
        {
            return Err(LocalImportError::InvalidPolicy);
        }
        Ok(Self {
            revision,
            max_bytes,
            max_record_bytes,
        })
    }

    pub fn default_bounded(revision: u64) -> Result<Self, LocalImportError> {
        Self::new(revision, MAX_IMPORT_BYTES, MAX_RECORD_BYTES)
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }
}

/// An approved physical import root. Private fields and parent-only issuance
/// prevent arbitrary path strings from forging approval.
pub struct ApprovedImportRoot {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    handle: File,
    identity: PhysicalFileId,
}

impl fmt::Debug for ApprovedImportRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovedImportRoot(<redacted-handle>)")
    }
}

/// Operator authority for exactly one approved root. It is neither cloneable
/// nor serializable; its identifier key is zeroized on drop.
pub struct OperatorImportCapability {
    root: ApprovedImportRoot,
    plan_key: Zeroizing<[u8; 32]>,
    /// Non-cloneable, control-plane-issued binding. A root cannot be reused
    /// under a different subject/instance/revision or lease generation.
    runtime_binding: Option<ContextImportCapabilityBinding>,
}

impl fmt::Debug for OperatorImportCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorImportCapability(<redacted>)")
    }
}

pub(crate) fn approve_import_root(path: &Path) -> Result<ApprovedImportRoot, LocalImportError> {
    validate_approved_root_path(path)?;
    open_approved_root(path)
}

pub(crate) fn issue_operator_import_capability(
    root: ApprovedImportRoot,
    plan_key: [u8; 32],
    runtime_binding: ContextImportCapabilityBinding,
) -> OperatorImportCapability {
    OperatorImportCapability {
        root,
        plan_key: Zeroizing::new(plan_key),
        runtime_binding: Some(runtime_binding),
    }
}

impl OperatorImportCapability {
    pub(crate) fn binding_matches_runtime(
        &self,
        runtime_binding: &ContextImportRuntimeBinding,
    ) -> bool {
        self.runtime_binding
            .as_ref()
            .is_some_and(|binding| binding.matches_runtime_binding(runtime_binding))
    }

    pub(crate) fn binding_matches(
        &self,
        runtime_binding: &ContextImportRuntimeBinding,
        lease: &ContextImportOperationLease,
    ) -> bool {
        self.binding_matches_runtime(runtime_binding)
            && self
                .runtime_binding
                .as_ref()
                .is_some_and(|binding| binding.matches_operation_lease(lease))
    }
}

#[cfg(test)]
fn issue_operator_import_capability_for_test(
    root: ApprovedImportRoot,
    plan_key: [u8; 32],
) -> OperatorImportCapability {
    OperatorImportCapability {
        root,
        plan_key: Zeroizing::new(plan_key),
        runtime_binding: None,
    }
}

/// One capability-bound, operator-selected relative file.
pub struct LocalImportRequest<'a> {
    capability: &'a OperatorImportCapability,
    selected_relative_path: &'a Path,
    policy: LocalImportPolicy,
}

impl<'a> LocalImportRequest<'a> {
    pub(crate) fn new(
        capability: &'a OperatorImportCapability,
        selected_relative_path: &'a Path,
        policy: LocalImportPolicy,
    ) -> Result<Self, LocalImportError> {
        validate_relative_selection(selected_relative_path)?;
        validate_policy(policy)?;
        Ok(Self {
            capability,
            selected_relative_path,
            policy,
        })
    }
}

/// Opaque identity derived from approved-root and opened-file identities,
/// never raw path spelling or content.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceObjectId([u8; 32]);

impl SourceObjectId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SourceObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceObjectId(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalImportPlanId([u8; 32]);

impl LocalImportPlanId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LocalImportPlanId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalImportPlanId(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImportVersionFingerprint([u8; 32]);

impl ImportVersionFingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ImportVersionFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImportVersionFingerprint(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSpan {
    pub normalized_byte_start: u32,
    pub normalized_byte_end: u32,
    pub line_start: u32,
    pub line_end: u32,
}

/// File-derived text with no instruction, policy, tool, or trust authority.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedImportRecord {
    text: String,
    pub source_span: SourceSpan,
}

impl UntrustedImportRecord {
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for UntrustedImportRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedImportRecord")
            .field("text", &"<redacted-untrusted-data>")
            .field("source_span", &self.source_span)
            .finish()
    }
}

pub struct LocalImportPlan {
    id: LocalImportPlanId,
    source_object_id: SourceObjectId,
    version_fingerprint: ImportVersionFingerprint,
    policy_revision: u64,
    parser_revision: u32,
    records: Vec<UntrustedImportRecord>,
    evidence_binding: Option<ContextImportCapabilityBinding>,
}

// The non-cloneable runtime witness deliberately does not participate in
// parser-plan equality: this comparison is used only by parser tests, while
// evidence persistence separately verifies the witness against its runtime.
impl PartialEq for LocalImportPlan {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.source_object_id == other.source_object_id
            && self.version_fingerprint == other.version_fingerprint
            && self.policy_revision == other.policy_revision
            && self.parser_revision == other.parser_revision
            && self.records == other.records
    }
}

impl Eq for LocalImportPlan {}

impl LocalImportPlan {
    pub const fn id(&self) -> LocalImportPlanId {
        self.id
    }
    pub const fn source_object_id(&self) -> SourceObjectId {
        self.source_object_id
    }
    pub const fn version_fingerprint(&self) -> ImportVersionFingerprint {
        self.version_fingerprint
    }
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub const fn parser_revision(&self) -> u32 {
        self.parser_revision
    }
    pub fn records(&self) -> &[UntrustedImportRecord] {
        &self.records
    }

    pub(crate) fn evidence_binding(&self) -> Option<&ContextImportCapabilityBinding> {
        self.evidence_binding.as_ref()
    }
}

impl fmt::Debug for LocalImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalImportPlan")
            .field("id", &self.id)
            .field("source_object_id", &self.source_object_id)
            .field("version_fingerprint", &self.version_fingerprint)
            .field("policy_revision", &self.policy_revision)
            .field("parser_revision", &self.parser_revision)
            .field(
                "records",
                &format_args!("<{} redacted records>", self.records.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocalImportError {
    #[error("the approved import root must be an unambiguous absolute local path")]
    AmbiguousRoot,
    #[error("filesystem roots cannot be approved as import roots")]
    RootTooBroad,
    #[error("UNC, device, and verbatim paths are forbidden for local import")]
    ForbiddenPathPrefix,
    #[error("the selected path must be a non-empty relative descendant")]
    OutsideApprovedRoot,
    #[error("the selected import path is unavailable")]
    Unavailable,
    #[error("an import path component is a symbolic link or reparse point")]
    SymlinkOrReparsePoint,
    #[error("the selected import path is not a regular file")]
    NotRegularFile,
    #[error("remote, layered, FUSE, and unknown filesystems are forbidden")]
    RemoteOrUnknownFilesystem,
    #[error("files with multiple hard links are forbidden for local import")]
    MultipleHardLinks,
    #[error("the import path crosses a mount or filesystem boundary")]
    MountBoundaryCrossed,
    #[error("the selected import file exceeds the configured byte limit")]
    SizeLimitExceeded,
    #[error("the selected import file or its binding changed while being read")]
    ChangedDuringRead,
    #[error("the local import policy is invalid")]
    InvalidPolicy,
    #[error("the selected import data is not valid UTF-8")]
    InvalidUtf8,
    #[error("the selected import data contains a forbidden control character")]
    ForbiddenControlCharacter,
    #[error("a normalized import record exceeds the configured byte limit")]
    RecordTooLarge,
    #[error("the selected import produces too many records")]
    TooManyRecords,
    #[error("secure local import is not implemented on this platform")]
    PlatformUnsupported,
    #[error("identifier authentication could not be initialized")]
    IdentifierAuthenticationUnavailable,
}

pub fn plan_operator_selected_file(
    request: LocalImportRequest<'_>,
) -> Result<LocalImportPlan, LocalImportError> {
    validate_policy(request.policy)?;
    let (raw, identity) = read_bound_source(
        &request.capability.root,
        request.selected_relative_path,
        request.policy.max_bytes,
    )?;
    build_plan_from_snapshot(
        &request.capability.plan_key,
        identity,
        request.policy,
        &raw,
        request
            .capability
            .runtime_binding
            .as_ref()
            .map(ContextImportCapabilityBinding::for_evidence),
    )
}

fn validate_policy(policy: LocalImportPolicy) -> Result<(), LocalImportError> {
    LocalImportPolicy::new(policy.revision, policy.max_bytes, policy.max_record_bytes).map(|_| ())
}

fn validate_approved_root_path(path: &Path) -> Result<(), LocalImportError> {
    if !path.is_absolute() || path.to_str().is_none() {
        return Err(LocalImportError::AmbiguousRoot);
    }
    validate_platform_root_prefix(path)?;
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => normal_components += 1,
            Component::CurDir | Component::ParentDir => {
                return Err(LocalImportError::AmbiguousRoot);
            }
            Component::Prefix(_) | Component::RootDir => {}
        }
    }
    if normal_components == 0 {
        return Err(LocalImportError::RootTooBroad);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_platform_root_prefix(path: &Path) -> Result<(), LocalImportError> {
    use std::path::Prefix;

    match path.components().next() {
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)) => Ok(()),
        _ => Err(LocalImportError::ForbiddenPathPrefix),
    }
}

#[cfg(not(windows))]
fn validate_platform_root_prefix(_: &Path) -> Result<(), LocalImportError> {
    Ok(())
}

fn validate_relative_selection(path: &Path) -> Result<(), LocalImportError> {
    if path.as_os_str().is_empty() || path.is_absolute() || path.to_str().is_none() {
        return Err(LocalImportError::OutsideApprovedRoot);
    }
    let mut count = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => count += 1,
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(LocalImportError::OutsideApprovedRoot),
        }
    }
    if count == 0 {
        return Err(LocalImportError::OutsideApprovedRoot);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PhysicalFileId {
    volume: u64,
    object: u64,
}

impl PhysicalFileId {
    fn encode(self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&self.volume.to_be_bytes());
        bytes[8..].copy_from_slice(&self.object.to_be_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BoundSourceIdentity {
    root: PhysicalFileId,
    source: PhysicalFileId,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileSnapshot {
    identity: PhysicalFileId,
    length: u64,
    link_count: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn snapshot(metadata: &Metadata) -> FileSnapshot {
    use std::os::unix::fs::MetadataExt;

    FileSnapshot {
        identity: PhysicalFileId {
            volume: metadata.dev(),
            object: metadata.ino(),
        },
        length: metadata.len(),
        link_count: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(target_os = "linux")]
fn open_approved_root(path: &Path) -> Result<ApprovedImportRoot, LocalImportError> {
    use std::os::unix::ffi::OsStrExt;

    let mut current = open_unix_absolute_root()?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name =
                    CString::new(name.as_bytes()).map_err(|_| LocalImportError::AmbiguousRoot)?;
                current = openat2_root_component(&current, &name, directory_open_flags())?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(LocalImportError::AmbiguousRoot);
            }
        }
    }
    let metadata = current
        .metadata()
        .map_err(|_| LocalImportError::Unavailable)?;
    if !metadata.is_dir() {
        return Err(LocalImportError::NotRegularFile);
    }
    ensure_local_filesystem(&current)?;
    Ok(ApprovedImportRoot {
        identity: snapshot(&metadata).identity,
        handle: current,
    })
}

#[cfg(target_os = "macos")]
fn open_approved_root(path: &Path) -> Result<ApprovedImportRoot, LocalImportError> {
    use std::os::unix::ffi::OsStrExt;

    // Darwin has no `openat2(RESOLVE_BENEATH)`.  Build the approved root one
    // component at a time from a pinned handle for `/` instead.  Every open
    // has Darwin's whole-path `O_NOFOLLOW_ANY`; XNU rejects combining it with
    // the weaker final-component-only `O_NOFOLLOW`. A kernel without the
    // stronger flag is deliberately unsupported rather than silently
    // accepting a weaker path-resolution contract.
    let mut current = open_macos_absolute_root()?;
    ensure_macos_local_filesystem(&current)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name =
                    CString::new(name.as_bytes()).map_err(|_| LocalImportError::AmbiguousRoot)?;
                current = open_macos_component(&current, &name, macos_directory_open_flags())?;
                ensure_macos_local_filesystem(&current)?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(LocalImportError::AmbiguousRoot);
            }
        }
    }
    let metadata = current
        .metadata()
        .map_err(|_| LocalImportError::Unavailable)?;
    if !metadata.is_dir() {
        return Err(LocalImportError::NotRegularFile);
    }
    Ok(ApprovedImportRoot {
        identity: snapshot(&metadata).identity,
        handle: current,
    })
}

#[cfg(windows)]
fn open_approved_root(_: &Path) -> Result<ApprovedImportRoot, LocalImportError> {
    // Intentional fail-closed boundary until reparse-safe handle traversal and
    // volume/file-ID binding are implemented for Windows.
    Err(LocalImportError::PlatformUnsupported)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn open_approved_root(_: &Path) -> Result<ApprovedImportRoot, LocalImportError> {
    Err(LocalImportError::PlatformUnsupported)
}

#[cfg(target_os = "linux")]
fn open_unix_absolute_root() -> Result<File, LocalImportError> {
    openat_raw(libc::AT_FDCWD, c"/", directory_open_flags())
        .map_err(|_| LocalImportError::Unavailable)
}

#[cfg(target_os = "linux")]
fn directory_open_flags() -> libc::c_int {
    // `openat2` rejects flag combinations which `openat` would merely
    // ignore.  With `O_PATH`, only `O_CLOEXEC`, `O_DIRECTORY`, and
    // `O_NOFOLLOW` are meaningful; the object itself is never opened, so
    // omitting `O_NONBLOCK` cannot make a FIFO or device lookup block.
    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

#[cfg(target_os = "linux")]
fn leaf_open_flags() -> libc::c_int {
    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

#[cfg(target_os = "linux")]
fn openat2_root_component(
    parent: &File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> Result<File, LocalImportError> {
    use std::os::fd::AsRawFd;

    openat2_raw(
        parent.as_raw_fd(),
        name,
        flags,
        SECURE_ROOT_COMPONENT_RESOLVE,
    )
    .map_err(map_secure_resolution_error)
}

#[cfg(target_os = "linux")]
fn openat2_descendant(
    parent: &File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> Result<File, LocalImportError> {
    use std::os::fd::AsRawFd;

    openat2_raw(parent.as_raw_fd(), name, flags, SECURE_DESCENDANT_RESOLVE)
        .map_err(map_secure_resolution_error)
}

#[cfg(target_os = "linux")]
const RESOLVE_NO_XDEV: u64 = 0x01;
#[cfg(target_os = "linux")]
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
#[cfg(target_os = "linux")]
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
#[cfg(target_os = "linux")]
const RESOLVE_BENEATH: u64 = 0x08;
#[cfg(target_os = "linux")]
const SECURE_ROOT_COMPONENT_RESOLVE: u64 =
    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
#[cfg(target_os = "linux")]
const SECURE_DESCENDANT_RESOLVE: u64 = SECURE_ROOT_COMPONENT_RESOLVE | RESOLVE_NO_XDEV;

#[cfg(target_os = "linux")]
fn openat2_raw(
    parent_fd: libc::c_int,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    resolve: u64,
) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use std::os::fd::BorrowedFd;

    // SAFETY: both callers borrow the descriptor from a live `File` for only
    // this call; rustix returns a separately owned descriptor on success.
    let parent = unsafe { BorrowedFd::borrow_raw(parent_fd) };
    openat2(
        parent,
        name,
        OFlags::from_bits_retain(flags as u32),
        Mode::empty(),
        ResolveFlags::from_bits_retain(resolve),
    )
    .map(File::from)
    .map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn map_secure_resolution_error(error: std::io::Error) -> LocalImportError {
    match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG) => LocalImportError::PlatformUnsupported,
        Some(libc::EXDEV) => LocalImportError::MountBoundaryCrossed,
        Some(libc::ELOOP) => LocalImportError::SymlinkOrReparsePoint,
        _ => LocalImportError::Unavailable,
    }
}

#[cfg(target_os = "linux")]
fn ensure_local_filesystem(handle: &File) -> Result<(), LocalImportError> {
    let magic = filesystem_magic(handle)?;
    if is_explicitly_local_filesystem_magic(magic) {
        Ok(())
    } else {
        Err(LocalImportError::RemoteOrUnknownFilesystem)
    }
}

#[cfg(target_os = "linux")]
fn filesystem_magic(handle: &File) -> Result<u64, LocalImportError> {
    use std::{mem::MaybeUninit, os::fd::AsRawFd};

    let mut status = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `status` points to writable storage for one `statfs`; `handle`
    // owns a live descriptor for the duration of the call.
    if unsafe { libc::fstatfs(handle.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(LocalImportError::RemoteOrUnknownFilesystem);
    }
    // SAFETY: successful `fstatfs` initialized the complete structure.
    Ok((unsafe { status.assume_init() }.f_type as u64) & 0xffff_ffff)
}

#[cfg(target_os = "linux")]
fn is_explicitly_local_filesystem_magic(magic: u64) -> bool {
    matches!(
        magic,
        0x0000_ef53 // ext2/3/4
            | 0x5846_5342 // XFS
            | 0x9123_683e // Btrfs
            | 0x2fc1_2fc1 // ZFS
            | 0xf2f5_2010 // F2FS
            | 0x8584_58f6 // ramfs
            | 0x7371_7368 // SquashFS
            | 0x2405_1905 // UBIFS
            | 0x3153_464a // JFS
            | 0x5265_4973 // ReiserFS
            | 0x0000_3434 // NILFS
            | 0xca45_1a4e // bcachefs
            | 0x7366_746e // NTFS3
    )
}

#[cfg(target_os = "linux")]
fn openat_raw(
    parent_fd: libc::c_int,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> std::io::Result<File> {
    use std::os::fd::FromRawFd;

    // SAFETY: `name` is live and NUL terminated. A returned descriptor is
    // immediately transferred into exactly one owning `File`.
    let descriptor = unsafe { libc::openat(parent_fd, name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "macos")]
fn macos_directory_open_flags() -> libc::c_int {
    libc::O_RDONLY
        | libc::O_DIRECTORY
        | libc::O_NOFOLLOW_ANY
        | libc::O_NONBLOCK
        | libc::O_CLOEXEC
}

#[cfg(target_os = "macos")]
fn macos_leaf_open_flags() -> libc::c_int {
    libc::O_RDONLY | libc::O_NOFOLLOW_ANY | libc::O_NONBLOCK | libc::O_CLOEXEC
}

#[cfg(target_os = "macos")]
fn open_macos_absolute_root() -> Result<File, LocalImportError> {
    openat_macos_raw(libc::AT_FDCWD, c"/", macos_directory_open_flags())
}

#[cfg(target_os = "macos")]
fn open_macos_component(
    parent: &File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> Result<File, LocalImportError> {
    use std::os::fd::AsRawFd;

    openat_macos_raw(parent.as_raw_fd(), name, flags)
}

#[cfg(target_os = "macos")]
fn openat_macos_raw(
    parent_fd: libc::c_int,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> Result<File, LocalImportError> {
    use std::os::fd::FromRawFd;

    // SAFETY: `name` is live and NUL terminated. A successful `openat`
    // returns one owned descriptor, immediately wrapped by exactly one File.
    let descriptor = unsafe { libc::openat(parent_fd, name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(map_macos_resolution_error(std::io::Error::last_os_error()));
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "macos")]
fn map_macos_resolution_error(error: std::io::Error) -> LocalImportError {
    match error.raw_os_error() {
        // `O_NOFOLLOW_ANY` reports a link-like path component with ELOOP.
        // This includes Darwin firmlink/symlink resolution cases which must
        // never escape the handle-relative traversal.
        Some(libc::ELOOP) => LocalImportError::SymlinkOrReparsePoint,
        Some(libc::EXDEV) => LocalImportError::MountBoundaryCrossed,
        // `O_NOFOLLOW_ANY` is a required Darwin capability. Older kernels or
        // filesystems which do not honor it fail closed instead of falling
        // back to final-component-only `O_NOFOLLOW` semantics.
        Some(libc::EINVAL | libc::ENOTSUP) => LocalImportError::PlatformUnsupported,
        _ => LocalImportError::Unavailable,
    }
}

#[cfg(target_os = "macos")]
fn ensure_macos_local_filesystem(handle: &File) -> Result<(), LocalImportError> {
    use std::{mem::MaybeUninit, os::fd::AsRawFd};

    let mut status = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `status` is writable storage for one statfs and `handle` owns a
    // live descriptor for this call.
    if unsafe { libc::fstatfs(handle.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(LocalImportError::RemoteOrUnknownFilesystem);
    }
    // SAFETY: successful fstatfs initialized the complete structure.
    let status = unsafe { status.assume_init() };
    let bytes: Vec<u8> = status.f_fstypename.iter().map(|byte| *byte as u8).collect();
    let Some(nul) = bytes.iter().position(|byte| *byte == 0) else {
        return Err(LocalImportError::RemoteOrUnknownFilesystem);
    };
    // Restrict to APFS. HFS+ has only second-granularity mutation timestamps,
    // which cannot support the before/after identity binding below for an
    // in-place same-length modification. Network, FUSE, synthetic, HFS, and
    // unknown mounts do not get a best-effort path through this boundary.
    if is_explicitly_local_macos_filesystem_name(&bytes[..nul]) {
        Ok(())
    } else {
        Err(LocalImportError::RemoteOrUnknownFilesystem)
    }
}

#[cfg(target_os = "macos")]
fn is_explicitly_local_macos_filesystem_name(name: &[u8]) -> bool {
    name == b"apfs"
}

#[cfg(target_os = "macos")]
fn ensure_macos_descendant(
    handle: &File,
    approved_root: PhysicalFileId,
) -> Result<Metadata, LocalImportError> {
    ensure_macos_local_filesystem(handle)?;
    let metadata = handle
        .metadata()
        .map_err(|_| LocalImportError::Unavailable)?;
    if !is_within_macos_approved_volume(snapshot(&metadata).identity, approved_root) {
        return Err(LocalImportError::MountBoundaryCrossed);
    }
    Ok(metadata)
}

#[cfg(target_os = "macos")]
fn is_within_macos_approved_volume(
    candidate: PhysicalFileId,
    approved_root: PhysicalFileId,
) -> bool {
    candidate.volume == approved_root.volume
}

#[cfg(target_os = "macos")]
fn open_macos_relative_leaf(
    root: &ApprovedImportRoot,
    path: &Path,
) -> Result<File, LocalImportError> {
    use std::os::unix::ffi::OsStrExt;

    validate_relative_selection(path)?;
    let mut current = root
        .handle
        .try_clone()
        .map_err(|_| LocalImportError::Unavailable)?;
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LocalImportError::OutsideApprovedRoot);
        };
        let name =
            CString::new(name.as_bytes()).map_err(|_| LocalImportError::OutsideApprovedRoot)?;
        let is_leaf = components.peek().is_none();
        let next = open_macos_component(
            &current,
            &name,
            if is_leaf {
                macos_leaf_open_flags()
            } else {
                macos_directory_open_flags()
            },
        )?;
        let metadata = ensure_macos_descendant(&next, root.identity)?;
        if !is_leaf && !metadata.is_dir() {
            return Err(LocalImportError::NotRegularFile);
        }
        current = next;
    }
    let metadata = ensure_macos_descendant(&current, root.identity)?;
    if !metadata.is_file() {
        return Err(LocalImportError::NotRegularFile);
    }
    if snapshot(&metadata).link_count != 1 {
        return Err(LocalImportError::MultipleHardLinks);
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn open_relative_leaf(root: &File, path: &Path) -> Result<File, LocalImportError> {
    use std::os::unix::ffi::OsStrExt;

    validate_relative_selection(path)?;
    let relative = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| LocalImportError::OutsideApprovedRoot)?;
    let handle = openat2_descendant(root, &relative, leaf_open_flags())?;
    ensure_local_filesystem(&handle)?;
    let metadata = handle
        .metadata()
        .map_err(|_| LocalImportError::Unavailable)?;
    if metadata.file_type().is_symlink() {
        return Err(LocalImportError::SymlinkOrReparsePoint);
    }
    if !metadata.is_file() {
        return Err(LocalImportError::NotRegularFile);
    }
    if snapshot(&metadata).link_count != 1 {
        return Err(LocalImportError::MultipleHardLinks);
    }
    Ok(handle)
}

#[cfg(target_os = "linux")]
fn open_read_handle(classified: &File) -> Result<File, LocalImportError> {
    use std::os::fd::AsRawFd;

    let proc_fd_directory = open_verified_proc_fd_directory()?;
    let descriptor_name = CString::new(classified.as_raw_fd().to_string())
        .map_err(|_| LocalImportError::Unavailable)?;
    let reader = openat_raw(
        proc_fd_directory.as_raw_fd(),
        &descriptor_name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
    )
    .map_err(|_| LocalImportError::Unavailable)?;
    ensure_local_filesystem(&reader)?;
    let classified_snapshot = snapshot(
        &classified
            .metadata()
            .map_err(|_| LocalImportError::Unavailable)?,
    );
    let reader_snapshot = snapshot(
        &reader
            .metadata()
            .map_err(|_| LocalImportError::Unavailable)?,
    );
    if reader_snapshot.identity != classified_snapshot.identity || reader_snapshot.link_count != 1 {
        return Err(LocalImportError::ChangedDuringRead);
    }
    Ok(reader)
}

#[cfg(target_os = "linux")]
fn open_verified_proc_fd_directory() -> Result<File, LocalImportError> {
    use std::os::fd::AsRawFd;

    const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;
    let root = openat_raw(libc::AT_FDCWD, c"/", directory_open_flags())
        .map_err(|_| LocalImportError::Unavailable)?;
    let proc = openat_raw(root.as_raw_fd(), c"proc", directory_open_flags())
        .map_err(|_| LocalImportError::Unavailable)?;
    if filesystem_magic(&proc)? != PROC_SUPER_MAGIC {
        return Err(LocalImportError::Unavailable);
    }
    // `self` is a kernel-owned procfs magic link. Following it only after the
    // parent descriptor has proved `PROC_SUPER_MAGIC` binds the lookup to the
    // calling task even when numeric PID namespaces differ.
    let process = openat_raw(
        proc.as_raw_fd(),
        c"self",
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC,
    )
    .map_err(|_| LocalImportError::Unavailable)?;
    if filesystem_magic(&process)? != PROC_SUPER_MAGIC {
        return Err(LocalImportError::Unavailable);
    }
    let descriptors = openat_raw(process.as_raw_fd(), c"fd", directory_open_flags())
        .map_err(|_| LocalImportError::Unavailable)?;
    if filesystem_magic(&descriptors)? != PROC_SUPER_MAGIC {
        return Err(LocalImportError::Unavailable);
    }
    Ok(descriptors)
}

#[cfg(target_os = "linux")]
fn read_bound_source(
    root: &ApprovedImportRoot,
    path: &Path,
    max_bytes: usize,
) -> Result<(Vec<u8>, BoundSourceIdentity), LocalImportError> {
    read_bound_source_with_hook(root, path, max_bytes, || {})
}

#[cfg(target_os = "linux")]
fn read_bound_source_with_hook(
    root: &ApprovedImportRoot,
    path: &Path,
    max_bytes: usize,
    after_read: impl FnOnce(),
) -> Result<(Vec<u8>, BoundSourceIdentity), LocalImportError> {
    let classified = open_relative_leaf(&root.handle, path)?;
    let mut file = open_read_handle(&classified)?;
    let before_metadata = file.metadata().map_err(|_| LocalImportError::Unavailable)?;
    if !before_metadata.is_file() {
        return Err(LocalImportError::NotRegularFile);
    }
    let before = snapshot(&before_metadata);
    let expected_len = checked_len(before.length, max_bytes)?;
    let mut raw = Vec::with_capacity(expected_len);
    file.by_ref()
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|_| LocalImportError::Unavailable)?;
    if raw.len() > max_bytes {
        return Err(LocalImportError::SizeLimitExceeded);
    }
    if raw.len() != expected_len {
        return Err(LocalImportError::ChangedDuringRead);
    }
    after_read();
    let after = snapshot(&file.metadata().map_err(|_| LocalImportError::Unavailable)?);
    if after != before {
        return Err(LocalImportError::ChangedDuringRead);
    }
    let rebound = open_relative_leaf(&root.handle, path)?;
    let rebound_metadata = rebound
        .metadata()
        .map_err(|_| LocalImportError::Unavailable)?;
    if !rebound_metadata.is_file() || snapshot(&rebound_metadata).identity != before.identity {
        return Err(LocalImportError::ChangedDuringRead);
    }
    Ok((
        raw,
        BoundSourceIdentity {
            root: root.identity,
            source: before.identity,
        },
    ))
}

#[cfg(target_os = "macos")]
fn read_bound_source(
    root: &ApprovedImportRoot,
    path: &Path,
    max_bytes: usize,
) -> Result<(Vec<u8>, BoundSourceIdentity), LocalImportError> {
    read_macos_bound_source_with_hook(root, path, max_bytes, || {})
}

#[cfg(target_os = "macos")]
fn read_macos_bound_source_with_hook(
    root: &ApprovedImportRoot,
    path: &Path,
    max_bytes: usize,
    after_read: impl FnOnce(),
) -> Result<(Vec<u8>, BoundSourceIdentity), LocalImportError> {
    // The reader is the exact O_NOFOLLOW_ANY descriptor that was classified;
    // no path is reopened before the bounded read. The final handle-relative
    // rebind detects a same-size replacement between open and commit.
    let mut file = open_macos_relative_leaf(root, path)?;
    let before_metadata = ensure_macos_descendant(&file, root.identity)?;
    if !before_metadata.is_file() {
        return Err(LocalImportError::NotRegularFile);
    }
    let before = snapshot(&before_metadata);
    if before.link_count != 1 {
        return Err(LocalImportError::MultipleHardLinks);
    }
    let expected_len = checked_len(before.length, max_bytes)?;
    let mut raw = Vec::with_capacity(expected_len);
    file.by_ref()
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|_| LocalImportError::Unavailable)?;
    if raw.len() > max_bytes {
        return Err(LocalImportError::SizeLimitExceeded);
    }
    if raw.len() != expected_len {
        return Err(LocalImportError::ChangedDuringRead);
    }
    after_read();
    let after_metadata = ensure_macos_descendant(&file, root.identity)?;
    let after = snapshot(&after_metadata);
    if after != before {
        return Err(LocalImportError::ChangedDuringRead);
    }
    let rebound = open_macos_relative_leaf(root, path)?;
    let rebound_metadata = ensure_macos_descendant(&rebound, root.identity)?;
    if !rebound_metadata.is_file() || snapshot(&rebound_metadata).identity != before.identity {
        return Err(LocalImportError::ChangedDuringRead);
    }
    Ok((
        raw,
        BoundSourceIdentity {
            root: root.identity,
            source: before.identity,
        },
    ))
}

#[cfg(windows)]
fn read_bound_source(
    _: &ApprovedImportRoot,
    _: &Path,
    _: usize,
) -> Result<(Vec<u8>, BoundSourceIdentity), LocalImportError> {
    Err(LocalImportError::PlatformUnsupported)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn read_bound_source(
    _: &ApprovedImportRoot,
    _: &Path,
    _: usize,
) -> Result<(Vec<u8>, BoundSourceIdentity), LocalImportError> {
    Err(LocalImportError::PlatformUnsupported)
}

fn checked_len(length: u64, max_bytes: usize) -> Result<usize, LocalImportError> {
    let length = usize::try_from(length).map_err(|_| LocalImportError::SizeLimitExceeded)?;
    if length > max_bytes {
        return Err(LocalImportError::SizeLimitExceeded);
    }
    Ok(length)
}

/// Private fixture/parser seam: production cannot bypass capability-bound IO.
fn build_plan_from_snapshot(
    plan_key: &[u8; 32],
    source_identity: BoundSourceIdentity,
    policy: LocalImportPolicy,
    raw: &[u8],
    evidence_binding: Option<ContextImportCapabilityBinding>,
) -> Result<LocalImportPlan, LocalImportError> {
    validate_policy(policy)?;
    if raw.len() > policy.max_bytes {
        return Err(LocalImportError::SizeLimitExceeded);
    }
    let input = std::str::from_utf8(raw).map_err(|_| LocalImportError::InvalidUtf8)?;
    let normalized = normalize_text(input)?;
    if normalized.len() > policy.max_bytes {
        return Err(LocalImportError::SizeLimitExceeded);
    }
    let records = parse_normalized_records(&normalized, policy.max_record_bytes)?;
    let root_identity = source_identity.root.encode();
    let file_identity = source_identity.source.encode();
    let source_object_id = SourceObjectId(authenticated_identifier(
        plan_key,
        IdentifierDomain::SourceObject,
        &[&root_identity, &file_identity],
    )?);
    let version_fingerprint = ImportVersionFingerprint(authenticated_identifier(
        plan_key,
        IdentifierDomain::VersionFingerprint,
        &[
            source_object_id.as_bytes(),
            &LOCAL_IMPORT_PARSER_REVISION.to_be_bytes(),
            &policy.revision.to_be_bytes(),
            raw,
            normalized.as_bytes(),
        ],
    )?);
    let id = LocalImportPlanId(authenticated_identifier(
        plan_key,
        IdentifierDomain::Plan,
        &[
            source_object_id.as_bytes(),
            version_fingerprint.as_bytes(),
            &policy.max_bytes.to_be_bytes(),
            &policy.max_record_bytes.to_be_bytes(),
        ],
    )?);
    Ok(LocalImportPlan {
        id,
        source_object_id,
        version_fingerprint,
        policy_revision: policy.revision,
        parser_revision: LOCAL_IMPORT_PARSER_REVISION,
        records,
        evidence_binding,
    })
}

fn normalize_text(input: &str) -> Result<String, LocalImportError> {
    let mut normalized = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\0' => return Err(LocalImportError::ForbiddenControlCharacter),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                normalized.push('\n');
            }
            '\n' => normalized.push('\n'),
            '\t' => normalized.push_str("    "),
            _ if character.is_control() => return Err(LocalImportError::ForbiddenControlCharacter),
            _ => normalized.push(character),
        }
    }
    Ok(normalized)
}

fn parse_normalized_records(
    normalized: &str,
    max_record_bytes: usize,
) -> Result<Vec<UntrustedImportRecord>, LocalImportError> {
    let mut records = Vec::new();
    let mut line = 1_u32;
    let mut offset = 0_usize;
    for item in normalized.split_inclusive('\n') {
        let text = item.strip_suffix('\n').unwrap_or(item);
        let end = offset
            .checked_add(text.len())
            .ok_or(LocalImportError::RecordTooLarge)?;
        if !text.is_empty() {
            if text.len() > max_record_bytes {
                return Err(LocalImportError::RecordTooLarge);
            }
            if records.len() == MAX_RECORDS_PER_PLAN {
                return Err(LocalImportError::TooManyRecords);
            }
            records.push(UntrustedImportRecord {
                text: text.to_owned(),
                source_span: SourceSpan {
                    normalized_byte_start: u32::try_from(offset)
                        .map_err(|_| LocalImportError::RecordTooLarge)?,
                    normalized_byte_end: u32::try_from(end)
                        .map_err(|_| LocalImportError::RecordTooLarge)?,
                    line_start: line,
                    line_end: line,
                },
            });
        }
        offset = offset
            .checked_add(item.len())
            .ok_or(LocalImportError::RecordTooLarge)?;
        line = line
            .checked_add(1)
            .ok_or(LocalImportError::TooManyRecords)?;
    }
    Ok(records)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentifierDomain {
    SourceObject = 1,
    VersionFingerprint = 2,
    Plan = 3,
}

fn authenticated_identifier(
    key: &[u8; 32],
    domain: IdentifierDomain,
    fields: &[&[u8]],
) -> Result<[u8; 32], LocalImportError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| LocalImportError::IdentifierAuthenticationUnavailable)?;
    mac.update(b"NEOTH\0LOCAL_IMPORT\0HMAC_SHA256\0V1");
    mac.update(&[domain as u8]);
    mac.update(&(fields.len() as u32).to_be_bytes());
    for field in fields {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::fs;

    use super::*;

    fn key() -> [u8; 32] {
        [9; 32]
    }
    fn policy(revision: u64) -> LocalImportPolicy {
        LocalImportPolicy::new(revision, 1_024, 256).unwrap()
    }
    fn fixture_root(name: &str) -> PathBuf {
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join("neoth-local-import-tests")
            .join(format!("{name}-{}", std::process::id()))
    }
    fn identity(object: u64) -> BoundSourceIdentity {
        BoundSourceIdentity {
            root: PhysicalFileId {
                volume: 1,
                object: 2,
            },
            source: PhysicalFileId { volume: 1, object },
        }
    }
    fn plan_bytes(
        revision: u64,
        source: BoundSourceIdentity,
        bytes: &[u8],
    ) -> Result<LocalImportPlan, LocalImportError> {
        build_plan_from_snapshot(&key(), source, policy(revision), bytes, None)
    }

    #[test]
    fn exact_bytes_are_stable_and_all_version_inputs_are_bound() {
        let first = plan_bytes(7, identity(3), b"alpha\nbeta\n").unwrap();
        let same = plan_bytes(7, identity(3), b"alpha\nbeta\n").unwrap();
        let content = plan_bytes(7, identity(3), b"alpha\ngamma\n").unwrap();
        let policy = plan_bytes(8, identity(3), b"alpha\nbeta\n").unwrap();
        let object = plan_bytes(7, identity(4), b"alpha\nbeta\n").unwrap();
        assert_eq!(first.id(), same.id());
        assert_eq!(first.source_object_id(), content.source_object_id());
        assert_ne!(first.version_fingerprint(), content.version_fingerprint());
        assert_ne!(first.version_fingerprint(), policy.version_fingerprint());
        assert_ne!(first.source_object_id(), object.source_object_id());
    }

    #[test]
    fn normalization_spans_and_byte_boundaries_are_deterministic() {
        let plan = plan_bytes(1, identity(3), b"a\r\nb\tc\rd").unwrap();
        assert_eq!(plan.records()[0].text(), "a");
        assert_eq!(plan.records()[0].source_span.normalized_byte_start, 0);
        assert_eq!(plan.records()[0].source_span.normalized_byte_end, 1);
        assert_eq!(plan.records()[1].text(), "b    c");
        assert_eq!(plan.records()[1].source_span.normalized_byte_start, 2);
        assert_eq!(plan.records()[1].source_span.normalized_byte_end, 8);
        assert_eq!(plan.records()[2].source_span.line_start, 3);
        let exact = LocalImportPolicy::new(1, 8, 8).unwrap();
        assert!(build_plan_from_snapshot(&key(), identity(3), exact, b"12345678", None).is_ok());
        assert_eq!(
            build_plan_from_snapshot(&key(), identity(3), exact, b"123456789", None),
            Err(LocalImportError::SizeLimitExceeded)
        );
    }

    #[test]
    fn malformed_record_and_count_limits_fail_closed() {
        assert_eq!(
            plan_bytes(1, identity(3), b"hello\0world"),
            Err(LocalImportError::ForbiddenControlCharacter)
        );
        assert_eq!(
            plan_bytes(1, identity(3), &[0xff]),
            Err(LocalImportError::InvalidUtf8)
        );
        let narrow = LocalImportPolicy::new(1, 1_024, 3).unwrap();
        assert_eq!(
            build_plan_from_snapshot(&key(), identity(3), narrow, b"four", None),
            Err(LocalImportError::RecordTooLarge)
        );
        let too_many = "x\n".repeat(MAX_RECORDS_PER_PLAN + 1);
        let broad = LocalImportPolicy::new(1, MAX_IMPORT_BYTES, MAX_RECORD_BYTES).unwrap();
        assert_eq!(
            build_plan_from_snapshot(&key(), identity(3), broad, too_many.as_bytes(), None),
            Err(LocalImportError::TooManyRecords)
        );
    }

    #[test]
    fn hmac_domains_and_field_boundaries_are_distinct() {
        let fields = [b"same".as_slice()];
        let source =
            authenticated_identifier(&key(), IdentifierDomain::SourceObject, &fields).unwrap();
        let version =
            authenticated_identifier(&key(), IdentifierDomain::VersionFingerprint, &fields)
                .unwrap();
        let plan = authenticated_identifier(&key(), IdentifierDomain::Plan, &fields).unwrap();
        assert_ne!(source, version);
        assert_ne!(version, plan);
        assert_ne!(
            authenticated_identifier(&key(), IdentifierDomain::Plan, &[b"a", b"bc"]).unwrap(),
            authenticated_identifier(&key(), IdentifierDomain::Plan, &[b"ab", b"c"]).unwrap()
        );
    }

    #[test]
    fn relative_selection_cannot_escape() {
        for invalid in ["", ".", "..", "../secret", "child/../secret"] {
            assert_eq!(
                validate_relative_selection(Path::new(invalid)),
                Err(LocalImportError::OutsideApprovedRoot)
            );
        }
        assert_eq!(
            validate_relative_selection(fixture_root("absolute").as_path()),
            Err(LocalImportError::OutsideApprovedRoot)
        );
    }

    #[cfg(target_os = "linux")]
    fn capability(root: &Path) -> OperatorImportCapability {
        issue_operator_import_capability_for_test(approve_import_root(root).unwrap(), key())
    }

    #[cfg(target_os = "macos")]
    fn capability(root: &Path) -> OperatorImportCapability {
        issue_operator_import_capability_for_test(approve_import_root(root).unwrap(), key())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn approved_root_and_selected_parents_never_follow_links() {
        use std::os::unix::fs::symlink;

        let outside = fixture_root("outside");
        let root = fixture_root("root-link-check");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        symlink(&outside, root.join("linked-parent")).unwrap();
        let authority = capability(&root);
        let request =
            LocalImportRequest::new(&authority, Path::new("linked-parent/secret.txt"), policy(1))
                .unwrap();
        assert_eq!(
            plan_operator_selected_file(request),
            Err(LocalImportError::SymlinkOrReparsePoint)
        );
        symlink(outside.join("secret.txt"), root.join("linked-leaf.txt")).unwrap();
        let request =
            LocalImportRequest::new(&authority, Path::new("linked-leaf.txt"), policy(1)).unwrap();
        assert_eq!(
            plan_operator_selected_file(request),
            Err(LocalImportError::SymlinkOrReparsePoint)
        );
        let linked_root = fixture_root("linked-root");
        symlink(&root, &linked_root).unwrap();
        assert!(matches!(
            approve_import_root(&linked_root),
            Err(LocalImportError::SymlinkOrReparsePoint)
        ));
        fs::remove_file(linked_root).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_is_rejected_without_a_blocking_open() {
        use std::os::unix::ffi::OsStrExt;

        let root = fixture_root("fifo");
        fs::create_dir_all(&root).unwrap();
        let fifo = root.join("pipe");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `name` is a live NUL-terminated pathname.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let authority = capability(&root);
        let request = LocalImportRequest::new(&authority, Path::new("pipe"), policy(1)).unwrap();
        assert_eq!(
            plan_operator_selected_file(request),
            Err(LocalImportError::NotRegularFile)
        );
        fs::remove_file(fifo).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn devtmpfs_root_is_rejected_before_any_device_leaf_can_open() {
        assert!(matches!(
            approve_import_root(Path::new("/dev")),
            Err(LocalImportError::RemoteOrUnknownFilesystem)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hard_linked_leaves_are_rejected() {
        let root = fixture_root("hard-link");
        fs::create_dir_all(&root).unwrap();
        let original = root.join("original.txt");
        fs::write(&original, b"data").unwrap();
        fs::hard_link(&original, root.join("alias.txt")).unwrap();
        let authority = capability(&root);
        let request =
            LocalImportRequest::new(&authority, Path::new("alias.txt"), policy(1)).unwrap();
        assert_eq!(
            plan_operator_selected_file(request),
            Err(LocalImportError::MultipleHardLinks)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filesystem_classification_rejects_remote_layered_and_unknown_magic() {
        for local in [0x0000_ef53, 0x5846_5342, 0x9123_683e] {
            assert!(is_explicitly_local_filesystem_magic(local));
        }
        for forbidden in [
            0x0000_6969, // NFS
            0xff53_4d42, // CIFS
            0xfe53_4d42, // SMB2
            0x6573_5546, // FUSE (may be sshfs)
            0x794c_7630, // overlay may have a remote lower layer
            0x0000_f15f, // eCryptfs may stack over a remote lower layer
            0x0102_1994, // tmpfs and devtmpfs share weak change semantics
            0x0000_4d44, // FAT has weak timestamp/change tokens
            0x2011_bab0, // exFAT has weak timestamp/change tokens
            0_u64,
        ] {
            assert!(!is_explicitly_local_filesystem_magic(forbidden));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openat2_resolution_contract_is_complete_and_fail_closed() {
        let allowed_path_flags = libc::O_PATH
            | libc::O_DIRECTORY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC;
        assert_eq!(directory_open_flags(), allowed_path_flags);
        assert_eq!(leaf_open_flags(), allowed_path_flags & !libc::O_DIRECTORY);
        assert_eq!(directory_open_flags() & libc::O_NONBLOCK, 0);
        assert_eq!(leaf_open_flags() & libc::O_NONBLOCK, 0);
        assert_eq!(
            SECURE_ROOT_COMPONENT_RESOLVE,
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
        );
        assert_eq!(SECURE_ROOT_COMPONENT_RESOLVE & RESOLVE_NO_XDEV, 0);
        assert_eq!(
            SECURE_DESCENDANT_RESOLVE,
            SECURE_ROOT_COMPONENT_RESOLVE | RESOLVE_NO_XDEV
        );
        for unsupported in [libc::ENOSYS, libc::EINVAL, libc::E2BIG] {
            assert_eq!(
                map_secure_resolution_error(std::io::Error::from_raw_os_error(unsupported)),
                LocalImportError::PlatformUnsupported
            );
        }
        assert_eq!(
            map_secure_resolution_error(std::io::Error::from_raw_os_error(libc::EXDEV)),
            LocalImportError::MountBoundaryCrossed
        );
        assert_eq!(
            map_secure_resolution_error(std::io::Error::from_raw_os_error(libc::ELOOP)),
            LocalImportError::SymlinkOrReparsePoint
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_proc_self_duplication_preserves_the_preclassified_identity() {
        let root = fixture_root("proc-self");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("selected.txt"), b"data").unwrap();
        let authority = capability(&root);
        let classified =
            open_relative_leaf(&authority.root.handle, Path::new("selected.txt")).unwrap();
        let reader = open_read_handle(&classified).unwrap();
        assert_eq!(
            snapshot(&classified.metadata().unwrap()).identity,
            snapshot(&reader.metadata().unwrap()).identity
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_size_leaf_swap_and_in_place_mutation_are_detected() {
        let root = fixture_root("race");
        fs::create_dir_all(&root).unwrap();
        let leaf = root.join("selected.txt");
        let replacement = root.join("replacement.txt");
        fs::write(&leaf, b"aaaa").unwrap();
        fs::write(&replacement, b"bbbb").unwrap();
        let authority = capability(&root);
        assert_eq!(
            read_bound_source_with_hook(&authority.root, Path::new("selected.txt"), 16, || {
                fs::rename(&replacement, &leaf).unwrap();
            }),
            Err(LocalImportError::ChangedDuringRead)
        );
        fs::write(&leaf, b"cccc").unwrap();
        assert_eq!(
            read_bound_source_with_hook(&authority.root, Path::new("selected.txt"), 16, || {
                fs::write(&leaf, b"dddd").unwrap();
            }),
            Err(LocalImportError::ChangedDuringRead)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_component_traversal_rejects_links_and_hard_linked_leaves() {
        use std::os::unix::fs::symlink;

        let outside = fixture_root("macos-outside");
        let root = fixture_root("macos-link-check");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        symlink(&outside, root.join("linked-parent")).unwrap();
        let authority = capability(&root);
        let request =
            LocalImportRequest::new(&authority, Path::new("linked-parent/secret.txt"), policy(1))
                .unwrap();
        assert_eq!(
            plan_operator_selected_file(request),
            Err(LocalImportError::SymlinkOrReparsePoint)
        );
        symlink(outside.join("secret.txt"), root.join("linked-leaf.txt")).unwrap();
        let request =
            LocalImportRequest::new(&authority, Path::new("linked-leaf.txt"), policy(1)).unwrap();
        assert_eq!(
            plan_operator_selected_file(request),
            Err(LocalImportError::SymlinkOrReparsePoint)
        );
        let original = root.join("original.txt");
        fs::write(&original, b"data").unwrap();
        fs::hard_link(&original, root.join("alias.txt")).unwrap();
        let request =
            LocalImportRequest::new(&authority, Path::new("alias.txt"), policy(1)).unwrap();
        assert_eq!(
            plan_operator_selected_file(request),
            Err(LocalImportError::MultipleHardLinks)
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reader_binds_the_opened_handle_and_rejects_a_same_size_swap() {
        let root = fixture_root("macos-race");
        fs::create_dir_all(&root).unwrap();
        let leaf = root.join("selected.txt");
        let replacement = root.join("replacement.txt");
        fs::write(&leaf, b"aaaa").unwrap();
        fs::write(&replacement, b"bbbb").unwrap();
        let authority = capability(&root);
        assert_eq!(
            read_macos_bound_source_with_hook(
                &authority.root,
                Path::new("selected.txt"),
                16,
                || {
                    fs::rename(&replacement, &leaf).unwrap();
                }
            ),
            Err(LocalImportError::ChangedDuringRead)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_resolution_contract_requires_whole_path_nofollow_and_local_filesystems() {
        assert_ne!(libc::O_NOFOLLOW_ANY, 0);
        assert_ne!(macos_directory_open_flags() & libc::O_NOFOLLOW_ANY, 0);
        assert_ne!(macos_leaf_open_flags() & libc::O_NOFOLLOW_ANY, 0);
        assert_eq!(macos_directory_open_flags() & libc::O_NOFOLLOW, 0);
        assert_eq!(macos_leaf_open_flags() & libc::O_NOFOLLOW, 0);
        assert!(is_explicitly_local_macos_filesystem_name(b"apfs"));
        for forbidden in [
            b"hfs".as_slice(),
            b"nfs",
            b"smbfs",
            b"osxfuse",
            b"autofs",
            b"devfs",
            b"",
        ] {
            assert!(!is_explicitly_local_macos_filesystem_name(forbidden));
        }
        assert_eq!(
            map_macos_resolution_error(std::io::Error::from_raw_os_error(libc::ELOOP)),
            LocalImportError::SymlinkOrReparsePoint
        );
        assert_eq!(
            map_macos_resolution_error(std::io::Error::from_raw_os_error(libc::EXDEV)),
            LocalImportError::MountBoundaryCrossed
        );
        assert!(is_within_macos_approved_volume(
            PhysicalFileId {
                volume: 7,
                object: 9,
            },
            PhysicalFileId {
                volume: 7,
                object: 10,
            }
        ));
        assert!(!is_within_macos_approved_volume(
            PhysicalFileId {
                volume: 7,
                object: 9,
            },
            PhysicalFileId {
                volume: 8,
                object: 9,
            }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn unc_device_and_verbatim_paths_are_rejected_and_windows_is_fail_closed() {
        for forbidden in [
            r"\\server\share\root",
            r"\\?\UNC\server\share\root",
            r"\\.\PhysicalDrive0",
            r"\\?\C:\root",
        ] {
            assert_eq!(
                validate_approved_root_path(Path::new(forbidden)),
                Err(LocalImportError::ForbiddenPathPrefix)
            );
        }
        assert!(matches!(
            approve_import_root(Path::new(r"C:\approved")),
            Err(LocalImportError::PlatformUnsupported)
        ));
    }

    #[test]
    fn debug_output_never_contains_content_or_key() {
        let plan = plan_bytes(1, identity(3), b"very-secret-content").unwrap();
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains("very-secret-content"));
        assert!(!rendered.contains("09090909"));
        assert!(rendered.contains("redacted"));
    }
}
