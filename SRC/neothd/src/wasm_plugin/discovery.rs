//! `~/.neoth/plugins/<id>/` discovery — V10-04 plugin enumeration.
//!
//! Walks `~/.neoth/plugins/` at daemon startup, surfaces every
//! subdirectory that carries a parseable `plugin.toml` + a
//! `plugin.wasm` alongside. Returns a `Vec<DiscoveredPlugin>` ready
//! for the load pipeline (engine compile → linker → dispatch register).
//!
//! Discovery is read-only: never writes, never deletes. A malformed
//! plugin directory yields a `DiscoveryError` row in the report
//! instead of getting silently skipped or crashing the daemon — the
//! operator sees exactly what was rejected and why via `neoth plugins
//! list`.
//!
//! Compiled in BOTH feature configurations. Without
//! `wasm-plugin-host` the discovery still runs + reports what would
//! load if the feature were on; the daemon just doesn't try to
//! compile the bytes. Helps a slim-build operator decide whether to
//! rebuild with the feature.

use std::ffi::OsStr;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

use super::manifest::{ManifestError, PluginManifest, RequestedPermission, parse_manifest};
use crate::skills::store::{
    BoundDirectory, cap_metadata_is_link_like, open_bound_directory, open_real_child_dir,
    read_regular_file_bounded,
};

/// `plugin.toml` is declarative metadata, not a payload. 256 KiB leaves ample
/// room for descriptions, hook declarations, and future fields while bounding
/// attacker-controlled startup allocation.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// Maximum on-disk `plugin.wasm` artifact accepted during discovery. Artifact
/// size and guest linear memory are separate limits; 128 MiB is deliberately
/// generous relative to the documented 64 MiB default / 256 MiB maximum guest
/// memory budget while still bounding the per-plugin startup read.
pub(crate) const MAX_WASM_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum aggregate `plugin.wasm` payload retained by one daemon discovery
/// pass. Per-plugin limits alone are insufficient: thousands of individually
/// valid pending/disabled plugins would otherwise be read and retained before
/// activation policy is applied. Keep the startup snapshot bounded even when
/// the plugin namespace is controlled by a hostile same-user writer.
pub(crate) const MAX_DISCOVERED_WASM_BYTES: u64 = 256 * 1024 * 1024;

/// SC-03 — a minisign detached signature is tiny (~300 bytes); cap the
/// read so a HOSTILE multi-GB `plugin.wasm.minisig` can't OOM the daemon
/// at discovery (the plugin dir is attacker-controlled — that IS SC-03's
/// threat model, and this read happens for every subdir before any
/// manifest/activation filter).
pub(crate) const MAX_MINISIG_BYTES: u64 = 4096;

/// Bound startup/probe work even when a same-user writer floods the plugin
/// namespace. The per-artifact byte limits below remain independently active.
pub(crate) const MAX_PLUGIN_DIRECTORIES: usize = 4096;

/// Test helper for the legacy ambient-path reader. Production discovery uses
/// [`read_bound_minisig`] so the directory handle remains authoritative.
#[cfg(test)]
pub(crate) fn read_capped_minisig(path: &Path) -> Result<Option<String>, ()> {
    use std::io::Read;
    if !path.exists() {
        return Ok(None);
    }
    // GR-089 — open without following a symlink (O_NOFOLLOW on Unix), then size
    // it on the SAME fd. The old code did `fs::metadata(path)` then a separate
    // `fs::File::open(path)`, both of which follow a symlink and race each other.
    let Ok(file) = open_no_follow(path) else {
        return Ok(None); // symlink (ELOOP) / unreadable → treat as absent
    };
    let Ok(meta) = file.metadata() else {
        return Ok(None);
    };
    if !meta.file_type().is_file() || metadata_is_link_like(&meta) {
        return Ok(None);
    }
    if meta.len() > MAX_MINISIG_BYTES {
        return Err(()); // over the cap — caller refuses the plugin
    }
    let mut buf = String::new();
    if file
        .take(MAX_MINISIG_BYTES)
        .read_to_string(&mut buf)
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// GR-089 — open a file for reading, refusing to follow a symlink AT OPEN time
/// (`O_NOFOLLOW` on Unix). Closes the check-then-read TOCTOU window a
/// `symlink_metadata` pre-check + a later `fs::read` leaves: even if the path is
/// swapped to a symlink between the check and here, the open fails with `ELOOP`
/// rather than reading the link target. On non-Unix platforms (where creating a
/// symlink needs privilege) it falls back to a plain open — the `symlink_metadata`
/// loop in `discover_one` is the guard there.
#[cfg(test)]
fn open_no_follow(path: &Path) -> std::io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            // Open the reparse point itself. `read_no_follow` rejects the
            // resulting handle from its metadata, so a leaf swap cannot turn
            // a plugin read into a traversal through a symlink or junction.
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
        }
        #[cfg(not(windows))]
        {
            fs::File::open(path)
        }
    }
}

#[cfg(test)]
fn metadata_is_link_like(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
#[derive(Debug)]
enum ReadNoFollowError {
    Io,
    NotRegular,
    TooLarge { observed_bytes: u64 },
}

/// Read a regular file via [`open_no_follow`] (GR-089), bounded at
/// `max_bytes`. Metadata comes from the same open handle used for the read, so
/// a path swap cannot substitute a special file between stat and read. The
/// `max + 1` read limit also catches a regular file that grows after metadata.
#[cfg(test)]
fn read_no_follow(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ReadNoFollowError> {
    use std::io::Read;

    let file = open_no_follow(path).map_err(|_| ReadNoFollowError::Io)?;
    let metadata = file.metadata().map_err(|_| ReadNoFollowError::Io)?;
    if !metadata.file_type().is_file() || metadata_is_link_like(&metadata) {
        return Err(ReadNoFollowError::NotRegular);
    }
    if metadata.len() > max_bytes {
        return Err(ReadNoFollowError::TooLarge {
            observed_bytes: metadata.len(),
        });
    }

    let mut buf = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|_| ReadNoFollowError::Io)?;
    if buf.len() as u64 > max_bytes {
        return Err(ReadNoFollowError::TooLarge {
            observed_bytes: buf.len() as u64,
        });
    }
    Ok(buf)
}

/// One discovered plugin directory + its parsed manifest + the WASM
/// bytes pre-loaded so the engine can compile without a second I/O
/// hop. Bytes are owned; the `PluginManifest` is cloneable so the
/// host can stash the metadata in a `BTreeMap` for `plugins list`.
#[derive(Clone, Debug)]
pub struct DiscoveredPlugin {
    pub dir: PathBuf,
    pub manifest: PluginManifest,
    /// SHA-256 of the canonical, parsed manifest representation. Unlike the
    /// optional plugin.wasm pin this binds every authority-bearing manifest
    /// field (especially `requested_permissions`) to the operator's activation
    /// decision. Whitespace/comment-only TOML edits do not change this digest.
    pub manifest_hash: String,
    pub wasm_bytes: Vec<u8>,
    /// SC-03 — lowercase-hex SHA-256 of `wasm_bytes`, computed at load.
    /// The operator pins the value they trust in
    /// `freedom.yaml::plugins.wasm.pinned_hashes[<id>]`; the daemon's
    /// [`verify_integrity`] gate refuses to instantiate a plugin whose
    /// on-disk bytes don't match the pin (tamper / supply-chain swap
    /// detection). Surfaced by `neoth plugin list` so the operator
    /// knows what to pin. Mirrors the skills `content_hash` (ARCH-07).
    pub content_hash: String,
    /// SC-03 — raw text of the `plugin.wasm.minisig` companion (minisign
    /// detached signature), read at discovery; `None` when absent. The
    /// [`verify_integrity`] gate checks it against the operator's
    /// configured `author_pubkey` to prove plugin AUTHORSHIP — the hash
    /// pin only proves the bytes didn't change, not WHO produced them.
    pub signature: Option<String>,
}

/// D-102 (Session 21, 2026-05-23, 6/6 agent panel) — per-plugin operator
/// activation state. Persisted in `freedom.yaml::plugins.wasm.activations`
/// keyed by manifest id. Newly-discovered ids default to [`Pending`]:
/// the daemon does not instantiate them until the operator explicitly
/// opts in via `neoth plugin enable <id>` or the first-run wizard
/// multiselect.
///
/// The state machine:
/// ```text
///   first discovery → Pending
///   `neoth plugin enable <id>`   → Pending|Disabled → Active
///   `neoth plugin disable <id>`  → Pending|Active   → Disabled
///   manifest id missing from disk → entry persisted; ignored on next boot
/// ```
///
/// Only `Active` plugins reach the compile + invoker bootstrap. `Pending`
/// + `Disabled` are skipped, but the operator sees them in
/// `neoth plugin list` so they're not invisible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginActivation {
    /// Newly discovered, operator hasn't decided. Default for any id
    /// not in `freedom.yaml::plugins.wasm.activations`.
    Pending,
    /// Operator opted in — the bootstrap compiles + registers.
    Active,
    /// Operator opted out — the bootstrap skips, the entry stays in
    /// `plugin list` so flipping back is one command away.
    Disabled,
}

impl PluginActivation {
    /// Bootstrap gate: only `Active` plugins instantiate.
    pub fn is_active(self) -> bool {
        matches!(self, PluginActivation::Active)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PluginActivation::Pending => "pending",
            PluginActivation::Active => "active",
            PluginActivation::Disabled => "disabled",
        }
    }
}

impl Default for PluginActivation {
    fn default() -> Self {
        PluginActivation::Pending
    }
}

/// The exact authority and artifact identity the operator approved when a
/// plugin was enabled. This is deliberately separate from the mutable
/// `plugin.toml`: startup must compare the current plugin against this record,
/// never derive a fresh grant from whatever the manifest says today.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PluginApproval {
    pub approved_permission: RequestedPermission,
    pub manifest_sha256: String,
    pub wasm_sha256: String,
}

/// Persisted activation plus its approval binding.
///
/// The custom deserializer accepts the historical scalar wire form
/// (`plugin_id: active`) as a legacy record with no approval. Such a record is
/// readable for migration/diagnostics but can never instantiate a plugin; the
/// operator must explicitly run `neoth plugin enable <id>` again.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PluginActivationRecord {
    pub state: PluginActivation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<PluginApproval>,
}

impl PluginActivationRecord {
    pub fn from_state(state: PluginActivation) -> Self {
        Self {
            state,
            approval: None,
        }
    }

    /// Create the only form of Active record startup is allowed to execute.
    pub fn active_for(plugin: &DiscoveredPlugin) -> Self {
        Self {
            state: PluginActivation::Active,
            approval: Some(PluginApproval {
                approved_permission: plugin.manifest.requested_permissions,
                manifest_sha256: plugin.manifest_hash.clone(),
                wasm_sha256: plugin.content_hash.clone(),
            }),
        }
    }

    /// Re-validate the current on-disk plugin against the exact operator
    /// approval. No min-grant or silent downgrade is allowed: any change needs
    /// an explicit re-enable so the operator sees the new capability/artifact.
    pub fn validate_for(
        &self,
        plugin: &DiscoveredPlugin,
    ) -> Result<RequestedPermission, PluginApprovalError> {
        if self.state != PluginActivation::Active {
            return Err(PluginApprovalError::NotActive);
        }
        let approval = self
            .approval
            .as_ref()
            .ok_or(PluginApprovalError::MissingApproval)?;
        if approval.approved_permission != plugin.manifest.requested_permissions {
            return Err(PluginApprovalError::PermissionChanged {
                approved: approval.approved_permission,
                current: plugin.manifest.requested_permissions,
            });
        }
        if approval.manifest_sha256 != plugin.manifest_hash {
            return Err(PluginApprovalError::ManifestChanged);
        }
        if approval.wasm_sha256 != plugin.content_hash {
            return Err(PluginApprovalError::WasmChanged);
        }
        Ok(approval.approved_permission)
    }
}

impl Default for PluginActivationRecord {
    fn default() -> Self {
        Self::from_state(PluginActivation::Pending)
    }
}

impl<'de> serde::Deserialize<'de> for PluginActivationRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Legacy(PluginActivation),
            Bound {
                state: PluginActivation,
                #[serde(default)]
                approval: Option<PluginApproval>,
            },
        }

        Ok(
            match <Wire as serde::Deserialize>::deserialize(deserializer)? {
                Wire::Legacy(state) => Self::from_state(state),
                Wire::Bound { state, approval } => Self { state, approval },
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PluginApprovalError {
    #[error("plugin is not active")]
    NotActive,
    #[error("legacy active record has no bound approval; run `neoth plugin enable <id>` again")]
    MissingApproval,
    #[error(
        "requested permission changed from approved {approved:?} to {current:?}; explicit re-enable required"
    )]
    PermissionChanged {
        approved: RequestedPermission,
        current: RequestedPermission,
    },
    #[error("canonical plugin manifest changed after approval; explicit re-enable required")]
    ManifestChanged,
    #[error("plugin.wasm changed after approval; explicit re-enable required")]
    WasmChanged,
}

/// What went wrong for one plugin subdirectory. Operator-readable;
/// the WAL `PLUGIN_REJECTED` (0xC3) frame carries the same shape.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum DiscoveryError {
    #[error("plugin store {root:?} exceeds the {max_entries}-entry discovery limit")]
    StoreEntryLimit { root: PathBuf, max_entries: usize },
    #[error(
        "plugin {dir:?}: retaining its {candidate_bytes}-byte plugin.wasm would exceed the aggregate discovery budget ({retained_bytes} bytes already retained, {max_bytes} bytes maximum)"
    )]
    AggregateWasmBudgetExceeded {
        dir: PathBuf,
        retained_bytes: u64,
        candidate_bytes: u64,
        max_bytes: u64,
    },
    #[error("plugin directory {dir:?}: io error: {kind:?}")]
    PluginDirIo {
        dir: PathBuf,
        kind: std::io::ErrorKind,
    },
    #[error("plugin path {dir:?} is not a real directory")]
    PluginPathNotDirectory { dir: PathBuf },
    #[error("plugin dir {dir:?} missing plugin.toml")]
    MissingManifest { dir: PathBuf },
    #[error("plugin dir {dir:?} missing plugin.wasm")]
    MissingWasm { dir: PathBuf },
    #[error("plugin {dir:?}: io error reading plugin.toml: {kind:?}")]
    TomlIo {
        dir: PathBuf,
        kind: std::io::ErrorKind,
    },
    #[error("plugin {dir:?}: io error reading plugin.wasm: {kind:?}")]
    WasmIo {
        dir: PathBuf,
        kind: std::io::ErrorKind,
    },
    #[error(
        "plugin {dir:?}: plugin.toml is at least {observed_bytes} bytes, exceeds the {max_bytes}-byte discovery limit"
    )]
    ManifestTooLarge {
        dir: PathBuf,
        observed_bytes: u64,
        max_bytes: u64,
    },
    #[error(
        "plugin {dir:?}: plugin.wasm is at least {observed_bytes} bytes, exceeds the {max_bytes}-byte discovery limit"
    )]
    WasmTooLarge {
        dir: PathBuf,
        observed_bytes: u64,
        max_bytes: u64,
    },
    #[error("plugin {dir:?}: {file} is not a regular file — refusing")]
    PathNotRegular { dir: PathBuf, file: &'static str },
    /// A-56 / GOLD-SEC-20 — a plugin file is a symlink. The plugin dir is
    /// attacker-controlled (SC-03 threat model); following a symlink would
    /// let `plugin.wasm` point at an arbitrary file so the hash/signature
    /// would cover the symlink TARGET, not the declared plugin. Refuse.
    #[error("plugin {dir:?}: {file} is a symlink — refusing (symlink-redirect guard)")]
    PathIsSymlink { dir: PathBuf, file: &'static str },
    #[error("plugin {dir:?}: manifest validation failed: {source}")]
    ManifestInvalid { dir: PathBuf, source: ManifestError },
    #[error("plugin {dir:?}: manifest id {got:?} does not match directory name {expected:?}")]
    IdDirectoryMismatch {
        dir: PathBuf,
        got: String,
        expected: String,
    },
    /// SC-03 — the on-disk `plugin.wasm` SHA-256 doesn't match the
    /// operator's pinned hash. Tamper / supply-chain swap.
    #[error(
        "plugin {dir:?}: plugin.wasm hash mismatch — pinned {expected}, got {got} \
         (tamper? re-pin in freedom.yaml::plugins.wasm.pinned_hashes if intentional)"
    )]
    HashMismatch {
        dir: PathBuf,
        expected: String,
        got: String,
    },
    /// SC-03 — `require_all_pinned` is set and this plugin has no pin.
    #[error(
        "plugin {dir:?}: no pinned hash and plugins.wasm.require_all_pinned=true — \
         pin {got} in freedom.yaml::plugins.wasm.pinned_hashes to allow it"
    )]
    HashUnpinned { dir: PathBuf, got: String },
    /// SC-03 — plugin id appears in `freedom.yaml::plugins.wasm.revoked_ids`.
    /// The operator's kill switch: a known-bad plugin is refused regardless
    /// of hash pin or signature state.
    #[error("plugin {dir:?}: id {id:?} is revoked (plugins.wasm.revoked_ids) — refusing to load")]
    Revoked { dir: PathBuf, id: String },
    /// SC-03 — an author pubkey is configured with `require_signature=true`
    /// but this plugin ships no `plugin.wasm.minisig` companion.
    #[error(
        "plugin {dir:?}: no signature companion (plugin.wasm.minisig) and \
         plugins.wasm.require_signature=true — sign it with the operator's \
         minisign key (`minisign -Sm plugin.wasm`) to allow it"
    )]
    SignatureMissing { dir: PathBuf },
    /// SC-03 — signature verification failed: wrong author key, malformed
    /// key/signature, or tampered bytes.
    #[error("plugin {dir:?}: signature verification failed — {reason}")]
    SignatureInvalid { dir: PathBuf, reason: String },
    /// SC-03 — `plugins.wasm.require_signature=true` but no
    /// `plugins.wasm.author_pubkey` is configured. A CONFIG mistake, not a
    /// bad signature — distinct so the operator is pointed at the right fix.
    #[error(
        "plugin {dir:?}: plugins.wasm.require_signature=true but no \
         plugins.wasm.author_pubkey is set — add the plugin author's minisign \
         public key to freedom.yaml::plugins.wasm.author_pubkey (or disable \
         require_signature)"
    )]
    AuthorKeyNotConfigured { dir: PathBuf },
    /// SC-03 — a symlink in the plugin root is refused (the operator must
    /// place real plugin directories under `~/.neoth/plugins/`).
    #[error("plugin {dir:?}: symlinks are not allowed in the plugin root — place a real directory")]
    SymlinkRejected { dir: PathBuf },
}

/// Aggregate report of one discovery pass.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryReport {
    pub loaded: Vec<DiscoveredPlugin>,
    pub rejected: Vec<DiscoveryError>,
}

impl DiscoveryReport {
    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty() && self.rejected.is_empty()
    }
    pub fn loaded_ids(&self) -> Vec<String> {
        self.loaded.iter().map(|p| p.manifest.id.clone()).collect()
    }
}

/// Walk `plugins_root` (typically `~/.neoth/plugins/`). For every
/// immediate subdirectory, attempt to load `<dir>/plugin.toml` +
/// `<dir>/plugin.wasm`. Returns a report — never errors at the
/// top level (a missing `plugins_root` simply yields an empty report). Store
/// open/enumeration/read failures are rejected diagnostics rather than being
/// indistinguishable from a legitimately empty store.
pub fn discover(plugins_root: &Path) -> DiscoveryReport {
    discover_with_wasm_budget(plugins_root, MAX_DISCOVERED_WASM_BYTES)
}

fn discover_with_wasm_budget(plugins_root: &Path, max_wasm_bytes: u64) -> DiscoveryReport {
    let mut report = DiscoveryReport::default();
    let root = match open_bound_directory(plugins_root, false, "plugins root") {
        Ok(Some(root)) => root,
        Ok(None) => return report,
        Err(error) => {
            report.rejected.push(DiscoveryError::PluginDirIo {
                dir: plugins_root.to_path_buf(),
                kind: anyhow_io_kind(&error),
            });
            return report;
        }
    };
    let entries = match root.dir.entries() {
        Ok(entries) => entries,
        Err(error) => {
            report.rejected.push(DiscoveryError::PluginDirIo {
                dir: root.display_path.clone(),
                kind: error.kind(),
            });
            return report;
        }
    };
    let mut observed_entries = 0usize;
    let mut retained_wasm_bytes = 0u64;
    for entry in entries {
        observed_entries = observed_entries.checked_add(1).unwrap_or(usize::MAX);
        if observed_entries > MAX_PLUGIN_DIRECTORIES {
            report.rejected.push(DiscoveryError::StoreEntryLimit {
                root: root.display_path.clone(),
                max_entries: MAX_PLUGIN_DIRECTORIES,
            });
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.rejected.push(DiscoveryError::PluginDirIo {
                    dir: root.display_path.clone(),
                    kind: error.kind(),
                });
                continue;
            }
        };
        let name = entry.file_name();
        let metadata = match root.dir.symlink_metadata(&name) {
            Ok(metadata) => metadata,
            Err(error) => {
                report.rejected.push(DiscoveryError::PluginDirIo {
                    dir: root.display_path.join(&name),
                    kind: error.kind(),
                });
                continue;
            }
        };
        if !metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
            continue;
        }
        match discover_one_in_root(&root, &name, Some((retained_wasm_bytes, max_wasm_bytes))) {
            Ok(plugin) => retain_discovered_plugin(
                &mut report,
                plugin,
                &mut retained_wasm_bytes,
                max_wasm_bytes,
            ),
            Err(e) => report.rejected.push(e),
        }
    }
    // Stable ordering so `plugins list` reads the same on every boot.
    report
        .loaded
        .sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    report
}

fn retain_discovered_plugin(
    report: &mut DiscoveryReport,
    plugin: DiscoveredPlugin,
    retained_wasm_bytes: &mut u64,
    max_wasm_bytes: u64,
) {
    let candidate_bytes = u64::try_from(plugin.wasm_bytes.len()).unwrap_or(u64::MAX);
    let next_total = match retained_wasm_bytes.checked_add(candidate_bytes) {
        Some(total) if total <= max_wasm_bytes => total,
        _ => {
            report
                .rejected
                .push(DiscoveryError::AggregateWasmBudgetExceeded {
                    dir: plugin.dir,
                    retained_bytes: *retained_wasm_bytes,
                    candidate_bytes,
                    max_bytes: max_wasm_bytes,
                });
            return;
        }
    };
    *retained_wasm_bytes = next_total;
    report.loaded.push(plugin);
}

/// Load one plugin directory through the same bounded, no-follow discovery
/// path used by daemon bootstrap. Updater probes call this exact entry point
/// again at their resolver sink so approval applies to the bytes about to
/// trigger egress, not to an earlier manifest-only scan.
#[cfg(test)]
pub(crate) fn discover_one(dir: &Path) -> Result<DiscoveredPlugin, DiscoveryError> {
    let Some(parent) = dir.parent() else {
        return Err(DiscoveryError::PluginDirIo {
            dir: dir.to_path_buf(),
            kind: std::io::ErrorKind::InvalidInput,
        });
    };
    let Some(name) = dir.file_name() else {
        return Err(DiscoveryError::PluginDirIo {
            dir: dir.to_path_buf(),
            kind: std::io::ErrorKind::InvalidInput,
        });
    };
    discover_one_bound(parent, name)
}

/// Inspect an arbitrary plugin bundle directory without requiring its
/// filesystem name to equal the manifest id. This is the capability-bound
/// pre-install/verification entry point for checkouts and private staging
/// directories whose names are intentionally unrelated to the plugin id.
pub(crate) fn inspect_bundle(dir: &Path) -> Result<DiscoveredPlugin, DiscoveryError> {
    let bundle = open_bound_directory(dir, false, "plugin bundle")
        .map_err(|error| DiscoveryError::PluginDirIo {
            dir: dir.to_path_buf(),
            kind: anyhow_io_kind(&error),
        })?
        .ok_or_else(|| DiscoveryError::PluginDirIo {
            dir: dir.to_path_buf(),
            kind: std::io::ErrorKind::NotFound,
        })?;
    load_one_bound(&bundle.dir, &bundle.display_path, None, None)
}

/// Discover one exact child below an already-selected plugin root. The root
/// ambient path is opened once; the component directory and every artifact
/// leaf are then resolved through stable directory capabilities.
pub(crate) fn discover_one_bound(
    plugins_root: &Path,
    name: &OsStr,
) -> Result<DiscoveredPlugin, DiscoveryError> {
    let root = open_bound_directory(plugins_root, false, "plugins root")
        .map_err(|error| DiscoveryError::PluginDirIo {
            dir: plugins_root.join(name),
            kind: anyhow_io_kind(&error),
        })?
        .ok_or_else(|| DiscoveryError::PluginDirIo {
            dir: plugins_root.join(name),
            kind: std::io::ErrorKind::NotFound,
        })?;
    discover_one_in_root(&root, name, None)
}

fn discover_one_in_root(
    root: &BoundDirectory,
    name: &OsStr,
    aggregate_wasm_budget: Option<(u64, u64)>,
) -> Result<DiscoveredPlugin, DiscoveryError> {
    let dir = root.display_path.join(name);
    let metadata =
        root.dir
            .symlink_metadata(name)
            .map_err(|error| DiscoveryError::PluginDirIo {
                dir: dir.clone(),
                kind: error.kind(),
            })?;
    if cap_metadata_is_link_like(&metadata) {
        return Err(DiscoveryError::SymlinkRejected { dir });
    }
    if !metadata.is_dir() {
        return Err(DiscoveryError::PluginPathNotDirectory { dir });
    }
    let plugin_dir = open_real_child_dir(&root.dir, name, &dir).map_err(|error| {
        DiscoveryError::PluginDirIo {
            dir: dir.clone(),
            kind: anyhow_io_kind(&error),
        }
    })?;
    load_one_bound(&plugin_dir, &dir, Some(name), aggregate_wasm_budget)
}

fn load_one_bound(
    plugin_dir: &cap_std::fs::Dir,
    dir: &Path,
    expected_directory_name: Option<&OsStr>,
    aggregate_wasm_budget: Option<(u64, u64)>,
) -> Result<DiscoveredPlugin, DiscoveryError> {
    let toml_bytes = read_bound_required_plugin_file(
        plugin_dir,
        dir,
        "plugin.toml",
        MAX_MANIFEST_BYTES,
        PluginArtifact::Manifest,
        None,
    )?;
    let manifest = parse_manifest(&toml_bytes).map_err(|e| DiscoveryError::ManifestInvalid {
        dir: dir.to_path_buf(),
        source: e,
    })?;
    let manifest_hash = canonical_manifest_sha256(&manifest);
    // Enforce id matches directory name so `~/.neoth/plugins/<id>/`
    // is a reliable lookup key. Without this, two plugins with the
    // same manifest id but different directory names would silently
    // collide in `plugins list`.
    if let Some(directory_name) = expected_directory_name {
        let dir_name = directory_name.to_str().unwrap_or("").to_string();
        if manifest.id != dir_name {
            return Err(DiscoveryError::IdDirectoryMismatch {
                dir: dir.to_path_buf(),
                got: manifest.id,
                expected: dir_name,
            });
        }
    }
    let wasm_bytes = read_bound_required_plugin_file(
        plugin_dir,
        dir,
        "plugin.wasm",
        MAX_WASM_BYTES,
        PluginArtifact::Wasm,
        aggregate_wasm_budget,
    )?;
    let content_hash = sha256_hex(&wasm_bytes);
    // SC-03 — optional minisign detached signature. minisign's `-Sm
    // plugin.wasm` writes `plugin.wasm.minisig`; absence is fine (the
    // signature gate is opt-in via freedom.yaml::plugins.wasm.author_pubkey).
    // Capped read — a hostile over-size companion is refused, not OOM'd.
    let signature = read_bound_minisig(plugin_dir, dir)?;
    Ok(DiscoveredPlugin {
        dir: dir.to_path_buf(),
        manifest,
        manifest_hash,
        wasm_bytes,
        content_hash,
        signature,
    })
}

#[derive(Clone, Copy)]
enum PluginArtifact {
    Manifest,
    Wasm,
}

fn read_bound_required_plugin_file(
    plugin_dir: &cap_std::fs::Dir,
    dir: &Path,
    file_name: &'static str,
    max_bytes: u64,
    artifact: PluginArtifact,
    aggregate_wasm_budget: Option<(u64, u64)>,
) -> Result<Vec<u8>, DiscoveryError> {
    let display = dir.join(file_name);
    let metadata = match plugin_dir.symlink_metadata(file_name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(match artifact {
                PluginArtifact::Manifest => DiscoveryError::MissingManifest {
                    dir: dir.to_path_buf(),
                },
                PluginArtifact::Wasm => DiscoveryError::MissingWasm {
                    dir: dir.to_path_buf(),
                },
            });
        }
        Err(error) => {
            return Err(plugin_artifact_io_error(artifact, dir, error.kind()));
        }
    };
    if cap_metadata_is_link_like(&metadata) {
        return Err(DiscoveryError::PathIsSymlink {
            dir: dir.to_path_buf(),
            file: file_name,
        });
    }
    if !metadata.is_file() {
        return Err(DiscoveryError::PathNotRegular {
            dir: dir.to_path_buf(),
            file: file_name,
        });
    }
    if metadata.len() > max_bytes {
        return Err(plugin_artifact_too_large(
            artifact,
            dir,
            metadata.len(),
            max_bytes,
        ));
    }
    let aggregate_remaining = match (artifact, aggregate_wasm_budget) {
        (PluginArtifact::Wasm, Some((retained_bytes, aggregate_max_bytes))) => {
            let remaining = aggregate_max_bytes.checked_sub(retained_bytes).unwrap_or(0);
            if metadata.len() > remaining {
                return Err(DiscoveryError::AggregateWasmBudgetExceeded {
                    dir: dir.to_path_buf(),
                    retained_bytes,
                    candidate_bytes: metadata.len(),
                    max_bytes: aggregate_max_bytes,
                });
            }
            Some((retained_bytes, aggregate_max_bytes, remaining))
        }
        _ => None,
    };
    let read_max_bytes = aggregate_remaining
        .map(|(_, _, remaining)| remaining.min(max_bytes))
        .unwrap_or(max_bytes);
    read_regular_file_bounded(
        plugin_dir,
        OsStr::new(file_name),
        &display,
        usize::try_from(read_max_bytes).unwrap_or(usize::MAX),
    )
    .map_err(|error| {
        if anyhow_io_kind(&error) == std::io::ErrorKind::InvalidData {
            if let Some((retained_bytes, aggregate_max_bytes, remaining)) = aggregate_remaining
                && remaining < max_bytes
            {
                DiscoveryError::AggregateWasmBudgetExceeded {
                    dir: dir.to_path_buf(),
                    retained_bytes,
                    candidate_bytes: remaining.saturating_add(1),
                    max_bytes: aggregate_max_bytes,
                }
            } else {
                plugin_artifact_too_large(artifact, dir, max_bytes.saturating_add(1), max_bytes)
            }
        } else {
            plugin_artifact_io_error(artifact, dir, anyhow_io_kind(&error))
        }
    })
}

fn read_bound_minisig(
    plugin_dir: &cap_std::fs::Dir,
    dir: &Path,
) -> Result<Option<String>, DiscoveryError> {
    const NAME: &str = "plugin.wasm.minisig";
    let display = dir.join(NAME);
    let metadata = match plugin_dir.symlink_metadata(NAME) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(DiscoveryError::SignatureInvalid {
                dir: dir.to_path_buf(),
                reason: format!("cannot inspect signature companion: {:?}", error.kind()),
            });
        }
    };
    if cap_metadata_is_link_like(&metadata) {
        return Err(DiscoveryError::PathIsSymlink {
            dir: dir.to_path_buf(),
            file: NAME,
        });
    }
    if !metadata.is_file() {
        return Err(DiscoveryError::PathNotRegular {
            dir: dir.to_path_buf(),
            file: NAME,
        });
    }
    if metadata.len() > MAX_MINISIG_BYTES {
        return Err(DiscoveryError::SignatureInvalid {
            dir: dir.to_path_buf(),
            reason: format!("plugin.wasm.minisig exceeds {MAX_MINISIG_BYTES} bytes — refusing"),
        });
    }
    let bytes = read_regular_file_bounded(
        plugin_dir,
        OsStr::new(NAME),
        &display,
        MAX_MINISIG_BYTES as usize,
    )
    .map_err(|error| DiscoveryError::SignatureInvalid {
        dir: dir.to_path_buf(),
        reason: if anyhow_io_kind(&error) == std::io::ErrorKind::InvalidData {
            format!("plugin.wasm.minisig exceeds {MAX_MINISIG_BYTES} bytes — refusing")
        } else {
            "cannot read signature companion".to_string()
        },
    })?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| DiscoveryError::SignatureInvalid {
            dir: dir.to_path_buf(),
            reason: "plugin.wasm.minisig is not UTF-8".to_string(),
        })
}

fn plugin_artifact_io_error(
    artifact: PluginArtifact,
    dir: &Path,
    kind: std::io::ErrorKind,
) -> DiscoveryError {
    match artifact {
        PluginArtifact::Manifest => DiscoveryError::TomlIo {
            dir: dir.to_path_buf(),
            kind,
        },
        PluginArtifact::Wasm => DiscoveryError::WasmIo {
            dir: dir.to_path_buf(),
            kind,
        },
    }
}

fn plugin_artifact_too_large(
    artifact: PluginArtifact,
    dir: &Path,
    observed_bytes: u64,
    max_bytes: u64,
) -> DiscoveryError {
    match artifact {
        PluginArtifact::Manifest => DiscoveryError::ManifestTooLarge {
            dir: dir.to_path_buf(),
            observed_bytes,
            max_bytes,
        },
        PluginArtifact::Wasm => DiscoveryError::WasmTooLarge {
            dir: dir.to_path_buf(),
            observed_bytes,
            max_bytes,
        },
    }
}

fn anyhow_io_kind(error: &anyhow::Error) -> std::io::ErrorKind {
    error
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .map_or(std::io::ErrorKind::Other, std::io::Error::kind)
}

/// Stable digest of the parsed manifest rather than its raw TOML bytes.
/// Struct-field serialization order is deterministic, so comments and
/// formatting do not force re-consent while every semantic field does.
pub fn canonical_manifest_sha256(manifest: &PluginManifest) -> String {
    let canonical = serde_json::to_vec(manifest)
        .expect("PluginManifest contains no fallible serde value types");
    sha256_hex(&canonical)
}

/// Lowercase-hex SHA-256 of a byte slice. Shared by load + the
/// integrity gate so the pinned-vs-computed comparison is over an
/// identical encoding.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        hex.push(TABLE[(b >> 4) as usize] as char);
        hex.push(TABLE[(b & 0x0f) as usize] as char);
    }
    hex
}

/// SC-03 — operator policy for plugin-binary integrity, sourced from
/// `freedom.yaml::plugins.wasm`. Opt-in-secure: an empty `pinned` map
/// with `require_all_pinned = false` (the default) imposes NO gate, so
/// existing unsigned plugins keep loading. The operator opts into
/// tamper-protection by pinning the hashes they trust.
#[derive(Clone, Copy, Debug)]
pub struct IntegrityPolicy<'a> {
    /// plugin id → expected lowercase-hex SHA-256 of `plugin.wasm`.
    pub pinned: &'a std::collections::BTreeMap<String, String>,
    /// When true, a plugin with NO pin is rejected (`HashUnpinned`)
    /// instead of loaded — "deny anything I haven't explicitly trusted".
    pub require_all_pinned: bool,
    /// SC-03 — operator's trusted plugin-author minisign PUBLIC key
    /// (base64). `None` → signature checking is off (hash-pin-only, the
    /// pre-signature behaviour). When `Some`, each plugin's
    /// `plugin.wasm.minisig` is verified against it. Borrowed (not owned)
    /// so `IntegrityPolicy` stays `Copy`.
    pub author_pubkey: Option<&'a str>,
    /// SC-03 — when true AND `author_pubkey` is set, a plugin with NO
    /// signature companion is refused (`SignatureMissing`). A PRESENT-
    /// but-invalid signature is ALWAYS refused regardless of this flag.
    pub require_signature: bool,
    /// SC-03 — revoked plugin ids (the operator's kill switch). A linear
    /// scan is fine: revocation lists are a handful of ids. Borrowed to
    /// keep `Copy`.
    pub revoked: &'a [String],
}

impl<'a> IntegrityPolicy<'a> {
    /// Project the operator's WASM config into the exact integrity policy used
    /// by runtime admission. Keeping this mapping here prevents updater and
    /// bootstrap callers from accidentally omitting a newly-added gate.
    pub fn from_config(config: &'a crate::config::WasmPluginsConfig) -> Self {
        Self {
            pinned: &config.pinned_hashes,
            require_all_pinned: config.require_all_pinned,
            author_pubkey: config.author_pubkey.as_deref(),
            require_signature: config.require_signature,
            revoked: &config.revoked_ids,
        }
    }
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum RuntimePluginAdmissionError {
    #[error("plugin host is disabled")]
    HostDisabled,
    #[error("plugin activation approval rejected: {0}")]
    Approval(#[from] PluginApprovalError),
    #[error("plugin integrity policy rejected artifact: {0}")]
    Integrity(DiscoveryError),
}

/// Apply daemon runtime admission to one exact discovered generation: host
/// switch, active approval binding (permission + manifest + WASM digests),
/// revocation, pins, and author signature policy. The approved grant is
/// returned only after every gate passes.
pub fn validate_runtime_admission(
    plugin: &DiscoveredPlugin,
    config: &crate::config::WasmPluginsConfig,
) -> Result<PluginApproval, RuntimePluginAdmissionError> {
    if !config.enabled {
        return Err(RuntimePluginAdmissionError::HostDisabled);
    }
    let record = config
        .activations
        .get(&plugin.manifest.id)
        .cloned()
        .unwrap_or_default();
    record.validate_for(plugin)?;
    verify_integrity(plugin, &IntegrityPolicy::from_config(config))
        .map_err(RuntimePluginAdmissionError::Integrity)?;
    record.approval.ok_or(RuntimePluginAdmissionError::Approval(
        PluginApprovalError::MissingApproval,
    ))
}

/// SC-03 — verify one discovered plugin against the operator's integrity
/// policy. Called by the daemon BEFORE instantiating the plugin (the
/// hostcall surface is the attack vector, so the gate fires at
/// instantiation, not at the read-only `plugins list`). Three layered
/// checks, fail-closed in order:
///
///   1. **Revocation** — id in `revoked` → `Revoked` (kill switch first).
///   2. **Hash pin** (tamper/swap): present+mismatch → `HashMismatch`;
///      no pin + `require_all_pinned` → `HashUnpinned`; else pass-through.
///   3. **Author signature** (authenticity, when `author_pubkey` set):
///      valid `.minisig` → pass; missing + `require_signature` →
///      `SignatureMissing`; invalid/wrong-key/tamper → `SignatureInvalid`.
///
/// The hash compare is plain string equality over SHA-256 of PUBLIC plugin
/// bytes (no secret → no timing channel). The signature check proves
/// AUTHORSHIP, which the hash pin alone cannot.
pub fn verify_integrity(
    plugin: &DiscoveredPlugin,
    policy: &IntegrityPolicy<'_>,
) -> Result<(), DiscoveryError> {
    // 1. Revocation — refuse a known-bad plugin regardless of hash/sig.
    if policy.revoked.iter().any(|id| id == &plugin.manifest.id) {
        return Err(DiscoveryError::Revoked {
            dir: plugin.dir.clone(),
            id: plugin.manifest.id.clone(),
        });
    }
    // 2. SHA-256 pin (tamper / supply-chain swap). `eq_ignore_ascii_case`
    //    is intentional: `content_hash` is always lowercase, but the
    //    operator-supplied pin may be pasted uppercase — tolerate it.
    match policy.pinned.get(&plugin.manifest.id) {
        Some(expected) if !expected.eq_ignore_ascii_case(&plugin.content_hash) => {
            return Err(DiscoveryError::HashMismatch {
                dir: plugin.dir.clone(),
                expected: expected.clone(),
                got: plugin.content_hash.clone(),
            });
        }
        None if policy.require_all_pinned => {
            return Err(DiscoveryError::HashUnpinned {
                dir: plugin.dir.clone(),
                got: plugin.content_hash.clone(),
            });
        }
        // pin matched, or no pin and not required — continue to the
        // signature stage.
        _ => {}
    }
    // 3. ed25519 author authenticity (only when a key is configured).
    match verify_plugin_signature(
        &plugin.wasm_bytes,
        plugin.signature.as_deref(),
        policy.author_pubkey,
        policy.require_signature,
    ) {
        Ok(PluginSigOutcome::UnsignedAllowed) => {
            // author_pubkey IS set but this plugin shipped no signature and
            // require_signature is off → it loads UNVERIFIED. Surface the
            // soft-gate so an operator who set a key isn't lulled into
            // thinking every plugin is authenticated.
            if policy.author_pubkey.is_some() {
                tracing::warn!(
                    id = %plugin.manifest.id,
                    "plugin loaded WITHOUT signature verification — author_pubkey is \
                     configured but plugins.wasm.require_signature=false; set it true to \
                     enforce authorship on every plugin"
                );
            }
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(PluginSigError::MissingSignature) => Err(DiscoveryError::SignatureMissing {
            dir: plugin.dir.clone(),
        }),
        // require_signature=true but no author_pubkey → a CONFIG mistake, not
        // a bad signature; point the operator at the right knob.
        Err(PluginSigError::NoKeyConfigured) => Err(DiscoveryError::AuthorKeyNotConfigured {
            dir: plugin.dir.clone(),
        }),
        Err(e) => Err(DiscoveryError::SignatureInvalid {
            dir: plugin.dir.clone(),
            reason: e.to_string(),
        }),
    }
}

/// SC-03 — outcome of a plugin signature check that did NOT hard-fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginSigOutcome {
    /// `plugin.wasm.minisig` present + verified against `author_pubkey`.
    Verified,
    /// No signature companion; allowed only because `require == false`.
    UnsignedAllowed,
    /// No author key configured; signature checking is off. Allowed only
    /// because `require == false`.
    NoKeyConfigured,
}

/// SC-03 — why a plugin signature check hard-failed. Mapped to a
/// `DiscoveryError` by [`verify_integrity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginSigError {
    /// `require == true` but no author key is configured.
    NoKeyConfigured,
    /// `require == true` but the plugin has no `.minisig` companion.
    MissingSignature,
    /// The configured `author_pubkey` is not a valid minisign public key.
    MalformedKey(String),
    /// The `.minisig` companion text is malformed.
    MalformedSignature(String),
    /// The signature did not verify (wrong author key / tampered bytes).
    VerificationFailed(String),
}

impl std::fmt::Display for PluginSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginSigError::NoKeyConfigured => {
                write!(f, "no author public key configured")
            }
            PluginSigError::MissingSignature => write!(f, "no signature companion"),
            PluginSigError::MalformedKey(e) => {
                write!(f, "configured author_pubkey is malformed: {e}")
            }
            PluginSigError::MalformedSignature(e) => {
                write!(f, "plugin.wasm.minisig is malformed: {e}")
            }
            PluginSigError::VerificationFailed(e) => {
                write!(f, "signature did not verify against author_pubkey: {e}")
            }
        }
    }
}

/// SC-03 — verify a minisign signature over `data` against the
/// operator-configured author public key. Unlike
/// [`crate::updater::sig_verify::check_signature`] (which uses the
/// COMPILE-TIME pinned NEOTH release key), `pubkey_b64` here comes from
/// `freedom.yaml::plugins.wasm.author_pubkey` at RUNTIME — an operator
/// can trust a third-party plugin author without rebuilding NEOTH.
///
/// Two-tier gate (mirrors `check_signature`):
///   - no key  → `NoKeyConfigured` unless `require` → `Err`
///   - no sig  → `UnsignedAllowed` unless `require` → `Err`
///   - present + valid   → `Verified`
///   - present + invalid → `Err` (always, regardless of `require`)
pub fn verify_plugin_signature(
    data: &[u8],
    signature: Option<&str>,
    pubkey_b64: Option<&str>,
    require: bool,
) -> Result<PluginSigOutcome, PluginSigError> {
    let Some(pubkey_b64) = pubkey_b64 else {
        if require {
            return Err(PluginSigError::NoKeyConfigured);
        }
        return Ok(PluginSigOutcome::NoKeyConfigured);
    };
    let Some(sig_text) = signature else {
        if require {
            return Err(PluginSigError::MissingSignature);
        }
        return Ok(PluginSigOutcome::UnsignedAllowed);
    };
    let pubkey = minisign_verify::PublicKey::from_base64(pubkey_b64.trim())
        .map_err(|e| PluginSigError::MalformedKey(e.to_string()))?;
    // Trim like the pubkey — defends a hand-edited `.minisig` with a
    // leading/trailing blank line (symmetry with `pubkey_b64.trim()`).
    let sig = minisign_verify::Signature::decode(sig_text.trim())
        .map_err(|e| PluginSigError::MalformedSignature(e.to_string()))?;
    // `false` = allow_legacy off → reject legacy non-prehashed (Ed) sigs;
    // NEOTH requires prehashed (ED) mode, the strictly stronger choice
    // (matches updater::sig_verify::check_signature).
    pubkey.verify(data, &sig, false).map_err(|e| {
        let raw = e.to_string();
        // minisign-verify surfaces a generic "algorithm not supported" for
        // a legacy `.minisig` produced without prehashing — give the
        // operator the actual fix instead of a key-mismatch red herring.
        if raw.to_lowercase().contains("algorithm") {
            PluginSigError::VerificationFailed(
                "legacy non-prehashed signature — re-sign with `minisign -Sm plugin.wasm` \
                 (current minisign uses prehashed mode by default)"
                    .to_string(),
            )
        } else {
            PluginSigError::VerificationFailed(raw)
        }
    })?;
    Ok(PluginSigOutcome::Verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const MINIMAL_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    fn write_plugin(root: &Path, id: &str, toml: &str, wasm: &[u8]) {
        let dir = root.join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("plugin.toml"), toml).unwrap();
        fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    }

    fn create_sparse_file(path: &Path, len: u64) {
        fs::File::create(path).unwrap().set_len(len).unwrap();
    }

    #[test]
    fn missing_plugin_dir_yields_empty_report() {
        let dir = tempdir().unwrap();
        let r = discover(&dir.path().join("nope"));
        assert!(r.is_empty());
    }

    #[test]
    fn empty_plugin_dir_yields_empty_report() {
        let dir = tempdir().unwrap();
        let r = discover(dir.path());
        assert!(r.is_empty());
    }

    #[test]
    fn unreadable_store_root_is_not_reported_as_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("not_a_directory");
        fs::write(&root, b"not a plugin store").unwrap();

        let report = discover(&root);

        assert!(report.loaded.is_empty());
        assert!(matches!(
            report.rejected.as_slice(),
            [DiscoveryError::PluginDirIo { dir, .. }] if dir == &root
        ));
    }

    #[test]
    fn well_formed_plugin_loads() {
        let dir = tempdir().unwrap();
        write_plugin(
            dir.path(),
            "indexer_v1",
            "id = \"indexer_v1\"\nname = \"Indexer\"\nversion = \"0.1.0\"\n",
            MINIMAL_WASM,
        );
        let r = discover(dir.path());
        assert_eq!(r.loaded.len(), 1);
        assert_eq!(r.rejected.len(), 0);
        assert_eq!(r.loaded[0].manifest.id, "indexer_v1");
        assert_eq!(r.loaded[0].wasm_bytes, MINIMAL_WASM);
    }

    #[test]
    fn missing_manifest_rejected() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("orphan");
        fs::create_dir_all(&plugin_dir).unwrap();
        fs::write(plugin_dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();
        let r = discover(dir.path());
        assert_eq!(r.loaded.len(), 0);
        assert_eq!(r.rejected.len(), 1);
        assert!(matches!(
            &r.rejected[0],
            DiscoveryError::MissingManifest { .. }
        ));
    }

    #[test]
    fn missing_wasm_rejected() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("nowasm");
        fs::create_dir_all(&plugin_dir).unwrap();
        fs::write(
            plugin_dir.join("plugin.toml"),
            "id = \"nowasm\"\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let r = discover(dir.path());
        assert_eq!(r.rejected.len(), 1);
        assert!(matches!(&r.rejected[0], DiscoveryError::MissingWasm { .. }));
    }

    #[test]
    fn malformed_manifest_rejected_with_actionable_error() {
        let dir = tempdir().unwrap();
        write_plugin(
            dir.path(),
            "bad",
            "id = \"bad\"\nname = \"x\"\nversion = \"not-a-version\"\n",
            MINIMAL_WASM,
        );
        let r = discover(dir.path());
        assert_eq!(r.loaded.len(), 0);
        assert_eq!(r.rejected.len(), 1);
        assert!(matches!(
            &r.rejected[0],
            DiscoveryError::ManifestInvalid { .. }
        ));
    }

    #[test]
    fn id_directory_mismatch_rejected() {
        let dir = tempdir().unwrap();
        write_plugin(
            dir.path(),
            "indexer_v1",
            // Manifest claims a different id than the directory.
            "id = \"recall_rerank\"\nname = \"x\"\nversion = \"0.1.0\"\n",
            MINIMAL_WASM,
        );
        let r = discover(dir.path());
        assert_eq!(r.rejected.len(), 1);
        assert!(matches!(
            &r.rejected[0],
            DiscoveryError::IdDirectoryMismatch { .. }
        ));
    }

    #[test]
    fn inspect_bundle_allows_arbitrary_checkout_directory_name() {
        let root = tempdir().unwrap();
        write_plugin(
            root.path(),
            "arbitrary_checkout_name",
            "id = \"verified_plugin\"\nname = \"Verified\"\nversion = \"0.1.0\"\n",
            MINIMAL_WASM,
        );

        let plugin = inspect_bundle(&root.path().join("arbitrary_checkout_name")).unwrap();
        assert_eq!(plugin.manifest.id, "verified_plugin");
        assert_eq!(plugin.wasm_bytes, MINIMAL_WASM);
    }

    #[test]
    fn discovery_sorts_loaded_by_id_for_stable_ordering() {
        let dir = tempdir().unwrap();
        for id in ["z_last", "a_first", "m_middle"] {
            write_plugin(
                dir.path(),
                id,
                &format!("id = \"{id}\"\nname = \"x\"\nversion = \"0.1.0\"\n"),
                MINIMAL_WASM,
            );
        }
        let r = discover(dir.path());
        assert_eq!(r.loaded_ids(), vec!["a_first", "m_middle", "z_last"]);
    }

    #[test]
    fn mixed_loaded_and_rejected_in_one_pass() {
        let dir = tempdir().unwrap();
        // Good plugin.
        write_plugin(
            dir.path(),
            "good_one",
            "id = \"good_one\"\nname = \"x\"\nversion = \"0.1.0\"\n",
            MINIMAL_WASM,
        );
        // Bad plugin: id mismatch.
        write_plugin(
            dir.path(),
            "bad_one",
            "id = \"wrong\"\nname = \"x\"\nversion = \"0.1.0\"\n",
            MINIMAL_WASM,
        );
        let r = discover(dir.path());
        assert_eq!(r.loaded.len(), 1);
        assert_eq!(r.rejected.len(), 1);
        assert_eq!(r.loaded[0].manifest.id, "good_one");
    }

    #[test]
    fn non_directory_entries_are_skipped() {
        let dir = tempdir().unwrap();
        // A bare file at plugins-root level (operator dropped a
        // README there) must be ignored, not rejected.
        fs::write(dir.path().join("README.md"), "ignored").unwrap();
        write_plugin(
            dir.path(),
            "real_plugin",
            "id = \"real_plugin\"\nname = \"x\"\nversion = \"0.1.0\"\n",
            MINIMAL_WASM,
        );
        let r = discover(dir.path());
        assert_eq!(r.loaded.len(), 1);
        assert_eq!(r.rejected.len(), 0);
    }

    // ── SC-03 integrity gate ───────────────────────────────────────

    use std::collections::BTreeMap;

    fn discovered(id: &str, wasm: &[u8]) -> DiscoveredPlugin {
        let dir = tempdir().unwrap();
        write_plugin(
            dir.path(),
            id,
            &format!("id = \"{id}\"\nname = \"x\"\nversion = \"0.1.0\"\n"),
            wasm,
        );
        let mut r = discover(dir.path());
        r.loaded.pop().expect("one loaded plugin")
    }

    #[test]
    fn aggregate_wasm_budget_rejects_before_retaining_every_plugin() {
        let root = tempdir().unwrap();
        for id in ["first", "second"] {
            write_plugin(
                root.path(),
                id,
                &format!("id = \"{id}\"\nname = \"x\"\nversion = \"0.1.0\"\n"),
                MINIMAL_WASM,
            );
        }

        let report = discover_with_wasm_budget(root.path(), MINIMAL_WASM.len() as u64);

        assert_eq!(report.loaded.len(), 1);
        assert_eq!(report.loaded[0].wasm_bytes.len(), MINIMAL_WASM.len());
        assert!(matches!(
            report.rejected.as_slice(),
            [DiscoveryError::AggregateWasmBudgetExceeded {
                retained_bytes,
                candidate_bytes,
                max_bytes,
                ..
            }] if *retained_bytes == MINIMAL_WASM.len() as u64
                && *candidate_bytes == MINIMAL_WASM.len() as u64
                && *max_bytes == MINIMAL_WASM.len() as u64
        ));
    }

    #[test]
    fn aggregate_wasm_accounting_rejects_integer_overflow() {
        let plugin = discovered("overflow", MINIMAL_WASM);
        let plugin_dir = plugin.dir.clone();
        let mut report = DiscoveryReport::default();
        let mut retained_bytes = u64::MAX;

        retain_discovered_plugin(&mut report, plugin, &mut retained_bytes, u64::MAX);

        assert!(report.loaded.is_empty());
        assert_eq!(retained_bytes, u64::MAX);
        assert!(matches!(
            report.rejected.as_slice(),
            [DiscoveryError::AggregateWasmBudgetExceeded {
                dir,
                retained_bytes: u64::MAX,
                candidate_bytes,
                max_bytes: u64::MAX,
            }] if dir == &plugin_dir && *candidate_bytes == MINIMAL_WASM.len() as u64
        ));
    }

    #[test]
    fn sha256_hex_is_64_lowercase_hex_and_stable() {
        let h = sha256_hex(MINIMAL_WASM);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(h, sha256_hex(MINIMAL_WASM), "stable for identical input");
        assert_ne!(h, sha256_hex(b"different"), "differs for different input");
    }

    #[test]
    fn load_populates_content_hash() {
        let p = discovered("hashme", MINIMAL_WASM);
        assert_eq!(p.content_hash, sha256_hex(MINIMAL_WASM));
    }

    #[test]
    fn canonical_manifest_hash_ignores_toml_layout_and_comments() {
        let compact = parse_manifest(
            b"id='same'\nname='Same'\nversion='1.0.0'\nrequested_permissions='read_only'\n",
        )
        .unwrap();
        let reformatted = parse_manifest(
            b"# operator note\nname = 'Same'\n\nversion = '1.0.0'\nid = 'same'\nrequested_permissions = 'read_only' # same authority\n",
        )
        .unwrap();

        assert_eq!(
            canonical_manifest_sha256(&compact),
            canonical_manifest_sha256(&reformatted)
        );
    }

    #[test]
    fn bound_activation_survives_unchanged_restart() {
        let plugin = discovered("approved", MINIMAL_WASM);
        let record = PluginActivationRecord::active_for(&plugin);

        assert_eq!(record.validate_for(&plugin), Ok(RequestedPermission::None));
    }

    #[test]
    fn post_enable_permission_escalation_requires_reconsent() {
        let plugin = discovered("escalated", MINIMAL_WASM);
        let record = PluginActivationRecord::active_for(&plugin);
        let mut changed = plugin.clone();
        changed.manifest.requested_permissions = RequestedPermission::Write;
        changed.manifest_hash = canonical_manifest_sha256(&changed.manifest);

        assert!(matches!(
            record.validate_for(&changed),
            Err(PluginApprovalError::PermissionChanged {
                approved: RequestedPermission::None,
                current: RequestedPermission::Write,
            })
        ));
    }

    #[test]
    fn post_enable_permission_change_never_silently_degrades() {
        let mut plugin = discovered("permission_changed", MINIMAL_WASM);
        plugin.manifest.requested_permissions = RequestedPermission::Write;
        plugin.manifest_hash = canonical_manifest_sha256(&plugin.manifest);
        let record = PluginActivationRecord::active_for(&plugin);
        let mut changed = plugin.clone();
        changed.manifest.requested_permissions = RequestedPermission::ReadOnly;
        changed.manifest_hash = canonical_manifest_sha256(&changed.manifest);

        assert!(matches!(
            record.validate_for(&changed),
            Err(PluginApprovalError::PermissionChanged {
                approved: RequestedPermission::Write,
                current: RequestedPermission::ReadOnly,
            })
        ));
    }

    #[test]
    fn post_enable_manifest_mutation_requires_reconsent() {
        let plugin = discovered("mutated", MINIMAL_WASM);
        let record = PluginActivationRecord::active_for(&plugin);
        let mut changed = plugin.clone();
        changed.manifest.name = "new manifest name".to_string();
        changed.manifest_hash = canonical_manifest_sha256(&changed.manifest);

        assert_eq!(
            record.validate_for(&changed),
            Err(PluginApprovalError::ManifestChanged)
        );
    }

    #[test]
    fn post_enable_wasm_mutation_requires_reconsent() {
        let plugin = discovered("wasm_changed", MINIMAL_WASM);
        let record = PluginActivationRecord::active_for(&plugin);
        let mut changed = plugin.clone();
        changed.wasm_bytes = b"different wasm bytes".to_vec();
        changed.content_hash = sha256_hex(&changed.wasm_bytes);

        assert_eq!(
            record.validate_for(&changed),
            Err(PluginApprovalError::WasmChanged)
        );
    }

    #[test]
    fn legacy_active_record_is_readable_but_never_grants_authority() {
        let mut plugin = discovered("legacy", MINIMAL_WASM);
        plugin.manifest.requested_permissions = RequestedPermission::Dangerous;
        plugin.manifest_hash = canonical_manifest_sha256(&plugin.manifest);
        let record: PluginActivationRecord = serde_yaml::from_str("active").unwrap();

        assert_eq!(record.state, PluginActivation::Active);
        assert!(record.approval.is_none());
        assert_eq!(
            record.validate_for(&plugin),
            Err(PluginApprovalError::MissingApproval)
        );
    }

    /// A hash-pin-only policy (no signature key, no revocations) — the
    /// pre-SC-03-signature default. Keeps the existing pin tests terse.
    fn pin_policy(pinned: &BTreeMap<String, String>, require_all: bool) -> IntegrityPolicy<'_> {
        IntegrityPolicy {
            pinned,
            require_all_pinned: require_all,
            author_pubkey: None,
            require_signature: false,
            revoked: &[],
        }
    }

    #[test]
    fn verify_integrity_no_pin_default_allows() {
        let p = discovered("free", MINIMAL_WASM);
        let pinned = BTreeMap::new();
        assert!(verify_integrity(&p, &pin_policy(&pinned, false)).is_ok());
    }

    #[test]
    fn verify_integrity_no_pin_require_all_rejects() {
        let p = discovered("free", MINIMAL_WASM);
        let pinned = BTreeMap::new();
        assert!(matches!(
            verify_integrity(&p, &pin_policy(&pinned, true)),
            Err(DiscoveryError::HashUnpinned { .. })
        ));
    }

    #[test]
    fn verify_integrity_pin_match_allows_mismatch_rejects() {
        let p = discovered("pinned", MINIMAL_WASM);
        let good = sha256_hex(MINIMAL_WASM);

        let mut ok_map = BTreeMap::new();
        ok_map.insert("pinned".to_string(), good.clone());
        assert!(
            verify_integrity(&p, &pin_policy(&ok_map, true)).is_ok(),
            "matching pin loads even under require_all_pinned"
        );

        let mut bad_map = BTreeMap::new();
        bad_map.insert("pinned".to_string(), "deadbeef".to_string());
        assert!(matches!(
            verify_integrity(&p, &pin_policy(&bad_map, false)),
            Err(DiscoveryError::HashMismatch { .. })
        ));
    }

    // --- SC-03 revocation + signature gate ---

    #[test]
    fn verify_integrity_revoked_id_rejected_first() {
        let p = discovered("bad_plugin", MINIMAL_WASM);
        let pinned = BTreeMap::new();
        let revoked = vec!["bad_plugin".to_string()];
        let policy = IntegrityPolicy {
            pinned: &pinned,
            require_all_pinned: false,
            author_pubkey: None,
            require_signature: false,
            revoked: &revoked,
        };
        assert!(matches!(
            verify_integrity(&p, &policy),
            Err(DiscoveryError::Revoked { .. })
        ));
    }

    #[test]
    fn verify_integrity_signature_missing_under_require_rejected() {
        let p = discovered("unsigned", MINIMAL_WASM); // discover sets signature=None
        let pinned = BTreeMap::new();
        let policy = IntegrityPolicy {
            pinned: &pinned,
            require_all_pinned: false,
            author_pubkey: Some("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"),
            require_signature: true,
            revoked: &[],
        };
        assert!(matches!(
            verify_integrity(&p, &policy),
            Err(DiscoveryError::SignatureMissing { .. })
        ));
    }

    #[test]
    fn verify_integrity_present_but_invalid_signature_rejected() {
        let mut p = discovered("signed", MINIMAL_WASM);
        p.signature = Some("untrusted comment: x\nGARBAGE-not-a-real-sig\n".to_string());
        let pinned = BTreeMap::new();
        let policy = IntegrityPolicy {
            pinned: &pinned,
            require_all_pinned: false,
            // Malformed key → MalformedKey → SignatureInvalid (a present-
            // but-invalid signature is refused regardless of require).
            author_pubkey: Some("not-a-valid-minisign-key"),
            require_signature: false,
            revoked: &[],
        };
        assert!(matches!(
            verify_integrity(&p, &policy),
            Err(DiscoveryError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn verify_plugin_signature_two_tier_gate() {
        // No key configured.
        assert_eq!(
            verify_plugin_signature(b"x", None, None, false),
            Ok(PluginSigOutcome::NoKeyConfigured)
        );
        assert_eq!(
            verify_plugin_signature(b"x", None, None, true),
            Err(PluginSigError::NoKeyConfigured)
        );
        // Key set, no signature companion.
        assert_eq!(
            verify_plugin_signature(b"x", None, Some("RWQabc"), false),
            Ok(PluginSigOutcome::UnsignedAllowed)
        );
        assert_eq!(
            verify_plugin_signature(b"x", None, Some("RWQabc"), true),
            Err(PluginSigError::MissingSignature)
        );
        // Malformed key with a signature present → MalformedKey.
        assert!(matches!(
            verify_plugin_signature(b"x", Some("sig"), Some("not-base64-!!"), false),
            Err(PluginSigError::MalformedKey(_))
        ));
        // NOTE: the Verified path needs a real keypair + signature, which
        // a unit test can't mint without embedding a private key — same
        // documented limitation as updater::sig_verify.
    }

    #[test]
    fn read_no_follow_accepts_exact_boundary_and_rejects_limit_plus_one() {
        // GR-089 — the symlink-safe reader accepts exactly the cap and rejects
        // cap+1. The same helper protects both manifest and WASM reads.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.bin");
        const TEST_LIMIT: u64 = 11;
        std::fs::write(&p, b"hello-bytes").unwrap();
        assert_eq!(read_no_follow(&p, TEST_LIMIT).unwrap(), b"hello-bytes");

        std::fs::write(&p, b"hello-bytes!").unwrap();
        assert!(matches!(
            read_no_follow(&p, TEST_LIMIT),
            Err(ReadNoFollowError::TooLarge { observed_bytes: 12 })
        ));
        assert!(matches!(
            read_no_follow(&dir.path().join("absent"), TEST_LIMIT),
            Err(ReadNoFollowError::Io)
        ));
    }

    #[test]
    fn discovery_reports_sparse_oversize_manifest() {
        let root = tempdir().unwrap();
        let plugin_dir = root.path().join("oversize_manifest");
        fs::create_dir(&plugin_dir).unwrap();
        create_sparse_file(&plugin_dir.join("plugin.toml"), MAX_MANIFEST_BYTES + 1);
        fs::write(plugin_dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();

        let report = discover(root.path());
        assert!(report.loaded.is_empty());
        assert!(matches!(
            report.rejected.as_slice(),
            [DiscoveryError::ManifestTooLarge {
                observed_bytes,
                max_bytes,
                ..
            }] if *observed_bytes == MAX_MANIFEST_BYTES + 1
                && *max_bytes == MAX_MANIFEST_BYTES
        ));
    }

    #[test]
    fn discovery_reports_sparse_oversize_wasm() {
        let root = tempdir().unwrap();
        let plugin_dir = root.path().join("oversize_wasm");
        fs::create_dir(&plugin_dir).unwrap();
        fs::write(
            plugin_dir.join("plugin.toml"),
            "id = \"oversize_wasm\"\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        create_sparse_file(&plugin_dir.join("plugin.wasm"), MAX_WASM_BYTES + 1);

        let report = discover(root.path());
        assert!(report.loaded.is_empty());
        assert!(matches!(
            report.rejected.as_slice(),
            [DiscoveryError::WasmTooLarge {
                observed_bytes,
                max_bytes,
                ..
            }] if *observed_bytes == MAX_WASM_BYTES + 1 && *max_bytes == MAX_WASM_BYTES
        ));
    }

    #[test]
    fn verify_integrity_require_signature_without_key_is_config_error() {
        // require_signature=true but no author_pubkey → a CONFIG mistake,
        // surfaced as AuthorKeyNotConfigured (not SignatureInvalid).
        let p = discovered("needsconfig", MINIMAL_WASM);
        let pinned = BTreeMap::new();
        let policy = IntegrityPolicy {
            pinned: &pinned,
            require_all_pinned: false,
            author_pubkey: None,
            require_signature: true,
            revoked: &[],
        };
        assert!(matches!(
            verify_integrity(&p, &policy),
            Err(DiscoveryError::AuthorKeyNotConfigured { .. })
        ));
    }

    #[test]
    fn read_capped_minisig_rejects_oversize_allows_small() {
        let dir = tempdir().unwrap();
        // Over the cap → Err (caller refuses the plugin, no OOM).
        let big = dir.path().join("big.minisig");
        fs::write(&big, vec![b'x'; (MAX_MINISIG_BYTES + 1) as usize]).unwrap();
        assert!(read_capped_minisig(&big).is_err());
        // Absent → Ok(None).
        assert_eq!(read_capped_minisig(&dir.path().join("nope")), Ok(None));
        // Small → Ok(Some).
        let small = dir.path().join("ok.minisig");
        fs::write(&small, b"untrusted comment\nRWQabc\n").unwrap();
        assert!(matches!(read_capped_minisig(&small), Ok(Some(_))));
    }
}
