//! Lifecycle for the deliberately read-only Obsidian Archive Bridge.
//!
//! This module owns one fixed plugin slot only. The plugin has no pairing or
//! sync capability; installation merely makes its local inspector available.
//! All vault traversal and publication is capability-relative so a changed
//! vault namespace cannot redirect a write into a different directory.

use std::{
    ffi::{OsStr, OsString},
    fmt,
    io::{self, Read},
    path::{Path, PathBuf},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

pub const PLUGIN_ID: &str = "neoth-archive-bridge";
pub const VERSION: &str = "0.2.0";
const MARKER: &str = "ownership.json";
const MANIFEST: &str = "manifest.json";
const MAIN: &str = "main.js";
const MAX_FILE_BYTES: usize = 256 * 1024;

const MANIFEST_BYTES: &[u8] = include_bytes!("../../assets/obsidian_archive_bridge/manifest.json");
const MAIN_BYTES: &[u8] = include_bytes!("../../assets/obsidian_archive_bridge/main.js");
const PREVIOUS_MANIFEST_BYTES: &[u8] =
    include_bytes!("../../assets/obsidian_archive_bridge/releases/0.1.0/manifest.json");
const PREVIOUS_MAIN_BYTES: &[u8] =
    include_bytes!("../../assets/obsidian_archive_bridge/releases/0.1.0/main.js");
const PREVIOUS_OWNERSHIP_BYTES: &[u8] =
    include_bytes!("../../assets/obsidian_archive_bridge/releases/0.1.0/ownership.json");
const PREDECESSOR_MANIFEST_BYTES: &[u8] =
    include_bytes!("../../assets/obsidian_archive_bridge/releases/0.1.1/manifest.json");
const PREDECESSOR_MAIN_BYTES: &[u8] =
    include_bytes!("../../assets/obsidian_archive_bridge/releases/0.1.1/main.js");
const PREDECESSOR_OWNERSHIP_BYTES: &[u8] =
    include_bytes!("../../assets/obsidian_archive_bridge/releases/0.1.1/ownership.json");

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeStatus {
    Absent,
    InstalledDisabled,
    UpdateAvailable,
    Drifted,
    Foreign,
    Residual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Generation {
    Current,
    Previous,
    Legacy,
}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeView {
    pub status: BridgeStatus,
    pub pairing_live: bool,
    pub plugin_id: &'static str,
    pub version: &'static str,
}

#[derive(Debug)]
pub enum BridgeError {
    VaultMissing,
    UnsafePath,
    ForeignOrMismatch,
    Io,
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::VaultMissing => "vault_missing",
            Self::UnsafePath => "unsafe_path",
            Self::ForeignOrMismatch => "foreign_or_mismatch",
            Self::Io => "io_error",
        })
    }
}

impl std::error::Error for BridgeError {}

/// Read-only inspection. A missing vault/plugin parent is absence; a broken
/// link or inaccessible object is never silently treated as absence.
pub fn status(vault: &Path) -> Result<BridgeView, BridgeError> {
    match inspect(vault) {
        Ok(Inspection::Absent) => Ok(view(BridgeStatus::Absent)),
        Ok(Inspection::Current) => Ok(view(BridgeStatus::InstalledDisabled)),
        Ok(Inspection::Previous) => Ok(view(BridgeStatus::UpdateAvailable)),
        Ok(Inspection::Drifted) => Ok(view(BridgeStatus::Drifted)),
        Ok(Inspection::Foreign) => Ok(view(BridgeStatus::Foreign)),
        Ok(Inspection::Residual) => Ok(view(BridgeStatus::Residual)),
        Err(error) => Err(error),
    }
}

/// Create a complete private generation, then atomically publish it to the
/// fixed slot. An existing owned generation is an idempotent success; any
/// other occupant is preserved and rejected.
pub fn install(vault: &Path) -> Result<BridgeView, BridgeError> {
    match inspect(vault)? {
        Inspection::Current => {
            return Ok(view(BridgeStatus::InstalledDisabled));
        }
        Inspection::Absent => {}
        Inspection::Previous | Inspection::Drifted | Inspection::Foreign | Inspection::Residual => {
            return Err(BridgeError::ForeignOrMismatch);
        }
    }

    let parent = plugin_parent(vault, true)?;
    let slot_name = OsStr::new(PLUGIN_ID);
    let slot_display = parent.display.join(PLUGIN_ID);
    if crate::skills::store::open_real_child_dir_if_present(&parent.dir, slot_name, &slot_display)
        .map_err(|_| BridgeError::UnsafePath)?
        .is_some()
    {
        return Err(BridgeError::ForeignOrMismatch);
    }

    let stage_name = stage_name();
    let stage_display = parent.display.join(&stage_name);
    parent
        .dir
        .create_dir(&stage_name)
        .map_err(|_| BridgeError::Io)?;
    let binding = crate::skills::store::bind_child_object(&parent.dir, &stage_name, &stage_display)
        .map_err(|_| BridgeError::UnsafePath)?;
    let stage = crate::skills::store::open_bound_real_child_dir_for_read(
        &parent.dir,
        &binding,
        &stage_name,
        &stage_display,
    )
    .map_err(|_| BridgeError::UnsafePath)?;

    for (name, bytes) in owned_files(Generation::Current) {
        if crate::skills::store::atomic_write_private_child_create_new(
            &stage,
            OsStr::new(name),
            &stage_display.join(name),
            &bytes,
        )
        .is_err()
        {
            let _ = crate::skills::store::remove_bound_real_directory_tree(
                &parent.dir,
                &stage_name,
                &stage_display,
                binding.identity_token(),
            );
            return Err(BridgeError::Io);
        }
    }

    #[cfg(test)]
    run_before_publish_for_test();
    if crate::skills::store::rename_bound_child(
        &binding,
        &parent.dir,
        &stage_name,
        &parent.dir,
        slot_name,
        &stage_display,
        &slot_display,
    )
    .is_err()
    {
        let _ = crate::skills::store::remove_bound_real_directory_tree(
            &parent.dir,
            &stage_name,
            &stage_display,
            binding.identity_token(),
        );
        return Err(BridgeError::ForeignOrMismatch);
    }
    if !requested_slot_still_names(vault, binding.identity_token()) {
        return Err(BridgeError::ForeignOrMismatch);
    }
    Ok(view(BridgeStatus::InstalledDisabled))
}

/// Repair only a generation whose ownership marker still authenticates this
/// exact release. Known payload files may be restored; `data.json` and every
/// extension remain untouched. A foreign marker or unsafe child fails closed.
pub fn repair(vault: &Path) -> Result<BridgeView, BridgeError> {
    match inspect(vault)? {
        Inspection::Absent => install(vault),
        Inspection::Current => Ok(view(BridgeStatus::InstalledDisabled)),
        Inspection::Previous => update(vault),
        // `Residual` is an interrupted authenticated uninstall. It is left
        // resumable rather than recreating payloads or touching user data.
        Inspection::Residual => Ok(view(BridgeStatus::Residual)),
        Inspection::Foreign => Err(BridgeError::ForeignOrMismatch),
        Inspection::Drifted => repair_owned_payloads(vault),
    }
}

/// Upgrade only the exact retained predecessor generation. Each owned leaf is
/// atomically replaced through the bound slot; an interruption is classified
/// as drift and `repair` first restores the authenticated predecessor before
/// resuming this transition. Operator settings and unknown additions are never
/// read for rewriting or removed.
pub fn update(vault: &Path) -> Result<BridgeView, BridgeError> {
    match inspect(vault)? {
        Inspection::Current => return Ok(view(BridgeStatus::InstalledDisabled)),
        Inspection::Previous => {}
        Inspection::Absent | Inspection::Drifted | Inspection::Foreign | Inspection::Residual => {
            return Err(BridgeError::ForeignOrMismatch);
        }
    }
    update_exact_predecessor(vault)
}

fn update_exact_predecessor(vault: &Path) -> Result<BridgeView, BridgeError> {
    let parent = plugin_parent(vault, false)?;
    let slot_display = parent.display.join(PLUGIN_ID);
    let (slot, binding) = crate::skills::store::open_bound_real_child_dir(
        &parent.dir,
        OsStr::new(PLUGIN_ID),
        &slot_display,
    )
    .map_err(|_| BridgeError::UnsafePath)?;
    let generation = marker_generation(&slot, &slot_display)?;
    if !matches!(generation, Some(Generation::Previous | Generation::Legacy)) {
        return Err(BridgeError::ForeignOrMismatch);
    }
    // Authenticate every predecessor byte before changing a known leaf. This
    // deliberately leaves additions such as data.json untouched.
    for (name, expected) in owned_files(generation.expect("checked predecessor generation")) {
        let actual = crate::skills::store::read_regular_file_bounded(
            &slot,
            OsStr::new(name),
            &slot_display.join(name),
            MAX_FILE_BYTES,
        )
        .map_err(|_| BridgeError::ForeignOrMismatch)?;
        if actual != expected {
            return Err(BridgeError::ForeignOrMismatch);
        }
    }
    // Write the marker last. A restart before that point still authenticates
    // the predecessor; repair restores its bytes and then resumes the update.
    for (name, expected) in owned_files(Generation::Current)
        .into_iter()
        .filter(|(name, _)| *name != MARKER)
    {
        crate::skills::store::atomic_write_private_child(
            &slot,
            OsStr::new(name),
            &slot_display.join(name),
            &expected,
        )
        .map_err(|_| BridgeError::ForeignOrMismatch)?;
    }
    #[cfg(test)]
    run_before_update_marker_for_test();
    crate::skills::store::atomic_write_private_child(
        &slot,
        OsStr::new(MARKER),
        &slot_display.join(MARKER),
        &ownership_bytes(),
    )
    .map_err(|_| BridgeError::ForeignOrMismatch)?;
    if !binding
        .matches_directory_child(&parent.dir, OsStr::new(PLUGIN_ID), &slot_display)
        .map_err(|_| BridgeError::UnsafePath)?
    {
        return Err(BridgeError::ForeignOrMismatch);
    }
    // Reinspect the requested namespace only after releasing both handles, so
    // Windows does not retain a conflicting share while the slot is reopened.
    drop(slot);
    drop(binding);
    match inspect(vault)? {
        Inspection::Current => Ok(view(BridgeStatus::InstalledDisabled)),
        _ => Err(BridgeError::ForeignOrMismatch),
    }
}

/// Remove only known payload leaves of an authenticated slot. The directory is
/// removed only when it becomes empty, preserving `data.json` and extensions.
pub fn uninstall(vault: &Path) -> Result<BridgeView, BridgeError> {
    match inspect(vault)? {
        Inspection::Absent => return Ok(view(BridgeStatus::Absent)),
        Inspection::Foreign => return Ok(view(BridgeStatus::Foreign)),
        Inspection::Drifted | Inspection::Residual | Inspection::Current | Inspection::Previous => {
        }
    }
    let parent = plugin_parent(vault, false)?;
    let slot_display = parent.display.join(PLUGIN_ID);
    let (slot, _slot_binding) = crate::skills::store::open_bound_real_child_dir(
        &parent.dir,
        OsStr::new(PLUGIN_ID),
        &slot_display,
    )
    .map_err(|_| BridgeError::UnsafePath)?;
    let Some(generation) = marker_generation(&slot, &slot_display)? else {
        return Ok(view(BridgeStatus::Foreign));
    };
    // Keep the marker until the last leaf: an interrupted cleanup still has a
    // verifiable owner and can never turn a partly removed slot into a foreign
    // directory that later code might mistake for ours.
    let mut removable = owned_files(generation);
    removable.sort_by_key(|(name, _)| *name == MARKER);
    for (name, expected) in removable {
        if name == MARKER && slot_has_additions(&slot)? {
            // Retain the authenticated marker when user data remains. It makes
            // an interrupted/uninstall-with-settings state explicit and lets a
            // later uninstall safely resume without classifying it as foreign.
            return status(vault);
        }
        let target = slot_display.join(name);
        let (file, read_binding) =
            match crate::skills::store::open_bound_regular_file(&slot, OsStr::new(name), &target) {
                Ok(bound) => bound,
                Err(error) if is_not_found(&error) && name != MARKER => continue,
                Err(_) => return Ok(view(BridgeStatus::Residual)),
            };
        let mut actual = Vec::new();
        let mut bounded = file.take(MAX_FILE_BYTES as u64 + 1);
        if bounded.read_to_end(&mut actual).is_err()
            || actual.len() > MAX_FILE_BYTES
            || actual != expected
        {
            return Ok(view(BridgeStatus::Residual));
        }
        #[cfg(test)]
        run_before_payload_removal_bind_for_test();
        let binding = match crate::skills::store::bind_regular_file_for_removal(
            &slot,
            OsStr::new(name),
            &target,
            &read_binding,
        ) {
            Ok(binding) => binding,
            Err(_) => return Ok(view(BridgeStatus::Residual)),
        };
        binding
            .remove_bound_file(&slot, OsStr::new(name), &target)
            .map_err(|_| BridgeError::ForeignOrMismatch)?;
    }
    // Never recursively remove the slot after an emptiness observation: a
    // concurrent extension could otherwise become an unintended descendant.
    drop(slot);
    let _removed = crate::skills::store::remove_empty_real_child_dir_if_present(
        &parent.dir,
        OsStr::new(PLUGIN_ID),
        &slot_display,
    )
    .map_err(|_| BridgeError::Io)?;
    // Re-inspect through the requested vault path. The retained parent may
    // have been moved after its original binding, so it cannot describe the
    // operator-visible namespace on its own.
    status(vault)
}

fn repair_owned_payloads(vault: &Path) -> Result<BridgeView, BridgeError> {
    let parent = plugin_parent(vault, false)?;
    let slot_display = parent.display.join(PLUGIN_ID);
    let (slot, binding) = crate::skills::store::open_bound_real_child_dir(
        &parent.dir,
        OsStr::new(PLUGIN_ID),
        &slot_display,
    )
    .map_err(|_| BridgeError::UnsafePath)?;
    let generation =
        marker_generation(&slot, &slot_display)?.ok_or(BridgeError::ForeignOrMismatch)?;
    for (name, expected) in owned_files(generation)
        .into_iter()
        .filter(|(name, _)| *name != MARKER)
    {
        let target = slot_display.join(name);
        match crate::skills::store::read_regular_file_bounded(
            &slot,
            OsStr::new(name),
            &target,
            MAX_FILE_BYTES,
        ) {
            Ok(actual) if actual == expected => {}
            Ok(_) => crate::skills::store::atomic_write_private_child(
                &slot,
                OsStr::new(name),
                &target,
                &expected,
            )
            .map_err(|_| BridgeError::ForeignOrMismatch)?,
            Err(error) if is_not_found(&error) => {
                crate::skills::store::atomic_write_private_child_create_new(
                    &slot,
                    OsStr::new(name),
                    &target,
                    &expected,
                )
                .map_err(|_| BridgeError::ForeignOrMismatch)?;
            }
            Err(_) => return Err(BridgeError::ForeignOrMismatch),
        }
    }
    if !binding
        .matches_directory_child(&parent.dir, OsStr::new(PLUGIN_ID), &slot_display)
        .map_err(|_| BridgeError::UnsafePath)?
    {
        return Err(BridgeError::ForeignOrMismatch);
    }
    // A repaired predecessor immediately transitions to `update`; release
    // both handles before that new lifecycle operation reopens the slot.
    drop(slot);
    drop(binding);
    match inspect(vault)? {
        Inspection::Current => Ok(view(BridgeStatus::InstalledDisabled)),
        Inspection::Previous => update(vault),
        Inspection::Residual => Ok(view(BridgeStatus::Residual)),
        _ => Err(BridgeError::ForeignOrMismatch),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inspection {
    Absent,
    Current,
    Previous,
    Drifted,
    Foreign,
    Residual,
}

fn inspect(vault: &Path) -> Result<Inspection, BridgeError> {
    let parent = match plugin_parent(vault, false) {
        Ok(parent) => parent,
        Err(BridgeError::VaultMissing) => return Ok(Inspection::Absent),
        Err(error) => return Err(error),
    };
    let slot_display = parent.display.join(PLUGIN_ID);
    let (slot, binding) = match crate::skills::store::open_bound_real_child_dir(
        &parent.dir,
        OsStr::new(PLUGIN_ID),
        &slot_display,
    ) {
        Ok(value) => value,
        Err(error) if is_not_found(&error) => return Ok(Inspection::Absent),
        Err(_) => match parent.dir.symlink_metadata(OsStr::new(PLUGIN_ID)) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                return Err(BridgeError::Io);
            }
            Ok(_) => return Ok(Inspection::Foreign),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Inspection::Absent);
            }
            Err(_) => return Err(BridgeError::Io),
        },
    };
    let Some(generation) = marker_generation(&slot, &slot_display)? else {
        return Ok(Inspection::Foreign);
    };
    let mut drifted = false;
    let mut missing_payload = false;
    let mut has_additions = false;
    for (name, expected) in owned_files(generation) {
        let actual = crate::skills::store::read_regular_file_bounded(
            &slot,
            OsStr::new(name),
            &slot_display.join(name),
            MAX_FILE_BYTES,
        );
        match actual {
            Ok(actual) if actual == expected => {}
            Err(error) if is_not_found(&error) && name != MARKER => {
                missing_payload = true;
            }
            Ok(_) | Err(_) => {
                drifted = true;
            }
        }
    }
    for entry in slot.entries().map_err(|_| BridgeError::Io)? {
        let name = entry.map_err(|_| BridgeError::Io)?.file_name();
        if name != OsStr::new(MARKER) && name != OsStr::new(MANIFEST) && name != OsStr::new(MAIN) {
            has_additions = true;
        }
    }
    if !binding
        .matches_directory_child(&parent.dir, OsStr::new(PLUGIN_ID), &slot_display)
        .map_err(|_| BridgeError::UnsafePath)?
    {
        return Ok(Inspection::Foreign);
    }
    Ok(if missing_payload && has_additions && !drifted {
        Inspection::Residual
    } else if drifted || missing_payload {
        Inspection::Drifted
    } else if generation == Generation::Current {
        Inspection::Current
    } else {
        Inspection::Previous
    })
}

struct PluginParent {
    dir: cap_std::fs::Dir,
    display: PathBuf,
}

fn plugin_parent(vault: &Path, create: bool) -> Result<PluginParent, BridgeError> {
    let vault = crate::skills::store::open_absolute_bound_directory(vault, false, "Obsidian vault")
        .map_err(|_| BridgeError::UnsafePath)?
        .ok_or(BridgeError::VaultMissing)?;
    let obsidian_display = vault.physical_display_path.join(".obsidian");
    let obsidian = if create {
        crate::skills::store::open_or_create_private_child_dir(
            &vault.dir,
            OsStr::new(".obsidian"),
            &obsidian_display,
        )
    } else {
        crate::skills::store::open_real_child_dir(
            &vault.dir,
            OsStr::new(".obsidian"),
            &obsidian_display,
        )
    }
    .map_err(|error| {
        if is_not_found(&error) {
            BridgeError::VaultMissing
        } else {
            BridgeError::UnsafePath
        }
    })?;
    let display = obsidian_display.join("plugins");
    let dir = if create {
        crate::skills::store::open_or_create_private_child_dir(
            &obsidian,
            OsStr::new("plugins"),
            &display,
        )
    } else {
        crate::skills::store::open_real_child_dir(&obsidian, OsStr::new("plugins"), &display)
    }
    .map_err(|error| {
        if is_not_found(&error) {
            BridgeError::VaultMissing
        } else {
            BridgeError::UnsafePath
        }
    })?;
    Ok(PluginParent { dir, display })
}

fn marker_generation(
    slot: &cap_std::fs::Dir,
    slot_display: &Path,
) -> Result<Option<Generation>, BridgeError> {
    let bytes = match crate::skills::store::read_regular_file_bounded(
        slot,
        OsStr::new(MARKER),
        &slot_display.join(MARKER),
        MAX_FILE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if is_not_found(&error) => return Ok(None),
        Err(_) => return Err(BridgeError::Io),
    };
    Ok(if bytes == ownership_bytes() {
        Some(Generation::Current)
    } else if bytes == PREDECESSOR_OWNERSHIP_BYTES {
        Some(Generation::Previous)
    } else if bytes == PREVIOUS_OWNERSHIP_BYTES {
        Some(Generation::Legacy)
    } else {
        None
    })
}

fn slot_has_additions(slot: &cap_std::fs::Dir) -> Result<bool, BridgeError> {
    for entry in slot.entries().map_err(|_| BridgeError::Io)? {
        let name = entry.map_err(|_| BridgeError::Io)?.file_name();
        if name != OsStr::new(MARKER) && name != OsStr::new(MANIFEST) && name != OsStr::new(MAIN) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn owned_files(generation: Generation) -> Vec<(&'static str, Vec<u8>)> {
    match generation {
        Generation::Current => vec![
            (MARKER, ownership_bytes()),
            (MANIFEST, MANIFEST_BYTES.to_vec()),
            (MAIN, MAIN_BYTES.to_vec()),
        ],
        Generation::Previous => vec![
            (MARKER, PREDECESSOR_OWNERSHIP_BYTES.to_vec()),
            (MANIFEST, PREDECESSOR_MANIFEST_BYTES.to_vec()),
            (MAIN, PREDECESSOR_MAIN_BYTES.to_vec()),
        ],
        Generation::Legacy => vec![
            (MARKER, PREVIOUS_OWNERSHIP_BYTES.to_vec()),
            (MANIFEST, PREVIOUS_MANIFEST_BYTES.to_vec()),
            (MAIN, PREVIOUS_MAIN_BYTES.to_vec()),
        ],
    }
}

fn ownership_bytes() -> Vec<u8> {
    format!(
        "{{\"schema\":1,\"plugin_id\":\"{PLUGIN_ID}\",\"version\":\"{VERSION}\",\"pairing\":\"disabled\",\"artifacts\":{{\"manifest.json\":\"{}\",\"main.js\":\"{}\"}}}}\n",
        sha256(MANIFEST_BYTES),
        sha256(MAIN_BYTES),
    )
    .into_bytes()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn view(status: BridgeStatus) -> BridgeView {
    BridgeView {
        status,
        pairing_live: false,
        plugin_id: PLUGIN_ID,
        version: VERSION,
    }
}

fn stage_name() -> OsString {
    OsString::from(format!(
        ".{PLUGIN_ID}.stage-{}",
        uuid::Uuid::new_v4().simple()
    ))
}

fn requested_slot_still_names(vault: &Path, identity: &str) -> bool {
    let Ok(parent) = plugin_parent(vault, false) else {
        return false;
    };
    let display = parent.display.join(PLUGIN_ID);
    crate::skills::store::open_bound_real_child_dir(&parent.dir, OsStr::new(PLUGIN_ID), &display)
        .map(|(_, binding)| binding.identity_token() == identity)
        .unwrap_or(false)
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .root_cause()
        .downcast_ref::<io::Error>()
        .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)
}

#[cfg(test)]
thread_local! {
    static BEFORE_PUBLISH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static BEFORE_PAYLOAD_REMOVAL_BIND: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static BEFORE_UPDATE_MARKER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_before_publish_for_test(hook: impl FnOnce() + 'static) {
    BEFORE_PUBLISH.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_publish_for_test() {
    BEFORE_PUBLISH.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn set_before_payload_removal_bind_for_test(hook: impl FnOnce() + 'static) {
    BEFORE_PAYLOAD_REMOVAL_BIND.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_payload_removal_bind_for_test() {
    BEFORE_PAYLOAD_REMOVAL_BIND.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn set_before_update_marker_for_test(hook: impl FnOnce() + 'static) {
    BEFORE_UPDATE_MARKER.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_update_marker_for_test() {
    BEFORE_UPDATE_MARKER.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn vault() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let vault = fs::canonicalize(temp.path()).unwrap().join("vault");
        fs::create_dir(&vault).unwrap();
        (temp, vault)
    }

    fn install_predecessor(vault: &Path) {
        install_generation(vault, Generation::Legacy);
    }

    fn install_0_1_1_predecessor(vault: &Path) {
        install_generation(vault, Generation::Previous);
    }

    fn install_generation(vault: &Path, generation: Generation) {
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::create_dir_all(&root).unwrap();
        for (name, bytes) in owned_files(generation) {
            fs::write(root.join(name), bytes).unwrap();
        }
    }

    #[test]
    fn install_is_atomic_idempotent_and_disabled() {
        let (_temp, vault) = vault();
        assert_eq!(
            install(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(
            install(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        assert_eq!(fs::read(root.join(MANIFEST)).unwrap(), MANIFEST_BYTES);
        assert_eq!(fs::read(root.join(MAIN)).unwrap(), MAIN_BYTES);
        assert_eq!(
            status(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
    }

    #[test]
    fn update_exact_predecessor_preserves_settings_extensions_and_vault() {
        let (_temp, vault) = vault();
        let note = vault.join("NEOTH-sessions/operator.md");
        fs::create_dir_all(note.parent().unwrap()).unwrap();
        fs::write(&note, b"operator note").unwrap();
        install_predecessor(&vault);
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join("data.json"), b"operator settings").unwrap();
        fs::write(root.join("extension.js"), b"extension").unwrap();
        assert_eq!(
            status(&vault).unwrap().status,
            BridgeStatus::UpdateAvailable
        );
        assert_eq!(
            update(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(
            update(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(fs::read(root.join(MANIFEST)).unwrap(), MANIFEST_BYTES);
        assert_eq!(fs::read(root.join(MAIN)).unwrap(), MAIN_BYTES);
        assert_eq!(
            fs::read(root.join("data.json")).unwrap(),
            b"operator settings"
        );
        assert_eq!(fs::read(root.join("extension.js")).unwrap(), b"extension");
        assert_eq!(fs::read(note).unwrap(), b"operator note");
    }

    #[test]
    fn update_exact_0_1_1_predecessor_recovery_preserves_unknown_files() {
        let (_temp, vault) = vault();
        install_0_1_1_predecessor(&vault);
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join("data.json"), b"operator settings").unwrap();
        assert_eq!(fs::read(root.join(MAIN)).unwrap(), PREDECESSOR_MAIN_BYTES);
        set_before_update_marker_for_test(|| {
            panic!("test crash before publishing the current marker");
        });
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| update(&vault)));
        assert!(interrupted.is_err());
        assert_eq!(
            fs::read(root.join(MARKER)).unwrap(),
            PREDECESSOR_OWNERSHIP_BYTES
        );
        assert_eq!(
            repair(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(
            fs::read(root.join("data.json")).unwrap(),
            b"operator settings"
        );
        assert_eq!(fs::read(root.join(MARKER)).unwrap(), ownership_bytes());
    }

    #[test]
    fn update_exact_0_1_1_predecessor_preserves_settings_extensions_and_vault() {
        let (_temp, vault) = vault();
        install_0_1_1_predecessor(&vault);
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join("data.json"), b"operator settings").unwrap();
        fs::write(root.join("extension.js"), b"extension").unwrap();
        assert_eq!(
            status(&vault).unwrap().status,
            BridgeStatus::UpdateAvailable
        );
        assert_eq!(
            update(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(
            fs::read(root.join("data.json")).unwrap(),
            b"operator settings"
        );
        assert_eq!(fs::read(root.join("extension.js")).unwrap(), b"extension");
        assert_eq!(fs::read(root.join(MARKER)).unwrap(), ownership_bytes());
    }

    #[test]
    fn update_rejects_tampered_predecessor_without_mutating_any_file() {
        let (_temp, vault) = vault();
        install_predecessor(&vault);
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join(MAIN), b"tampered predecessor").unwrap();
        fs::write(root.join("data.json"), b"operator settings").unwrap();
        assert_eq!(status(&vault).unwrap().status, BridgeStatus::Drifted);
        assert!(matches!(
            update(&vault),
            Err(BridgeError::ForeignOrMismatch)
        ));
        assert_eq!(fs::read(root.join(MAIN)).unwrap(), b"tampered predecessor");
        assert_eq!(
            fs::read(root.join("data.json")).unwrap(),
            b"operator settings"
        );
    }

    #[test]
    fn repair_resumes_panic_interrupted_predecessor_update_without_losing_additions() {
        let (_temp, vault) = vault();
        install_predecessor(&vault);
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join("data.json"), b"operator settings").unwrap();
        set_before_update_marker_for_test(|| {
            panic!("test crash before publishing the current marker");
        });
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| update(&vault)));
        assert!(
            interrupted.is_err(),
            "the failpoint must interrupt before marker publish"
        );
        assert_eq!(
            fs::read(root.join(MARKER)).unwrap(),
            PREVIOUS_OWNERSHIP_BYTES,
            "the predecessor receipt survives an interrupted update"
        );
        assert_eq!(status(&vault).unwrap().status, BridgeStatus::Drifted);
        assert_eq!(
            repair(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(
            fs::read(root.join("data.json")).unwrap(),
            b"operator settings"
        );
        assert_eq!(fs::read(root.join(MAIN)).unwrap(), MAIN_BYTES);
    }

    #[test]
    fn repair_recovers_concurrent_payload_replacement_during_update() {
        let (_temp, vault) = vault();
        install_predecessor(&vault);
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join("data.json"), b"operator settings").unwrap();
        let competing_main = root.join(MAIN);
        set_before_update_marker_for_test(move || {
            fs::write(competing_main, b"competing payload replacement").unwrap();
        });
        assert!(matches!(
            update(&vault),
            Err(BridgeError::ForeignOrMismatch)
        ));
        assert_eq!(status(&vault).unwrap().status, BridgeStatus::Drifted);
        assert_eq!(
            repair(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(
            fs::read(root.join("data.json")).unwrap(),
            b"operator settings"
        );
    }

    #[test]
    fn missing_vault_or_plugins_reports_absent() {
        let (_temp, vault) = vault();
        fs::remove_dir(&vault).unwrap();
        assert_eq!(status(&vault).unwrap().status, BridgeStatus::Absent);
    }

    #[test]
    fn drift_repairs_known_payload_and_preserves_settings() {
        let (_temp, vault) = vault();
        install(&vault).unwrap();
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join(MAIN), b"changed").unwrap();
        fs::write(root.join("data.json"), b"operator-settings").unwrap();
        assert_eq!(status(&vault).unwrap().status, BridgeStatus::Drifted);
        assert_eq!(
            repair(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(fs::read(root.join(MAIN)).unwrap(), MAIN_BYTES);
        assert_eq!(
            fs::read(root.join("data.json")).unwrap(),
            b"operator-settings"
        );
    }

    #[test]
    fn foreign_slot_is_never_overwritten() {
        let (_temp, vault) = vault();
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("foreign"), b"keep").unwrap();
        assert_eq!(status(&vault).unwrap().status, BridgeStatus::Foreign);
        assert!(matches!(
            install(&vault),
            Err(BridgeError::ForeignOrMismatch)
        ));
        assert_eq!(fs::read(root.join("foreign")).unwrap(), b"keep");
    }

    #[test]
    fn uninstall_keeps_data_and_foreign_extensions() {
        let (_temp, vault) = vault();
        install(&vault).unwrap();
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join("data.json"), b"settings").unwrap();
        fs::write(root.join("extension.js"), b"keep").unwrap();
        assert_eq!(uninstall(&vault).unwrap().status, BridgeStatus::Residual);
        assert_eq!(uninstall(&vault).unwrap().status, BridgeStatus::Residual);
        assert_eq!(fs::read(root.join("data.json")).unwrap(), b"settings");
        assert_eq!(fs::read(root.join("extension.js")).unwrap(), b"keep");
    }

    #[test]
    fn uninstall_removes_an_empty_authenticated_slot() {
        let (_temp, vault) = vault();
        install(&vault).unwrap();
        assert_eq!(uninstall(&vault).unwrap().status, BridgeStatus::Absent);
        assert!(!vault.join(".obsidian/plugins").join(PLUGIN_ID).exists());
    }

    #[test]
    fn healthy_owned_slot_with_settings_is_idempotent_for_install_and_repair() {
        let (_temp, vault) = vault();
        install(&vault).unwrap();
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::write(root.join("data.json"), b"settings").unwrap();
        assert_eq!(
            status(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(
            install(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(
            repair(&vault).unwrap().status,
            BridgeStatus::InstalledDisabled
        );
        assert_eq!(fs::read(root.join("data.json")).unwrap(), b"settings");
    }

    #[test]
    fn interrupted_uninstall_resumes_after_missing_payload_and_later_empty_slot() {
        let (_temp, vault) = vault();
        install(&vault).unwrap();
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        fs::remove_file(root.join(MAIN)).unwrap();
        fs::write(root.join("data.json"), b"settings").unwrap();
        assert_eq!(uninstall(&vault).unwrap().status, BridgeStatus::Residual);
        assert!(
            root.join(MARKER).is_file(),
            "marker retains cleanup ownership"
        );
        fs::remove_file(root.join("data.json")).unwrap();
        assert_eq!(uninstall(&vault).unwrap().status, BridgeStatus::Absent);
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn requested_vault_parent_swap_before_publish_is_not_reported_as_success() {
        let (_temp, vault) = vault();
        let obsidian = vault.join(".obsidian");
        let displaced = vault.join(".obsidian-displaced");
        let displaced_by_swap = displaced.clone();
        let requested_plugins = vault.join(".obsidian/plugins");
        set_before_publish_for_test(move || {
            fs::rename(&obsidian, &displaced_by_swap).unwrap();
            fs::create_dir_all(&requested_plugins).unwrap();
        });
        assert!(matches!(
            install(&vault),
            Err(BridgeError::ForeignOrMismatch)
        ));
        assert!(!vault.join(".obsidian/plugins").join(PLUGIN_ID).exists());
        assert!(displaced.join("plugins").join(PLUGIN_ID).is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn replacement_after_payload_read_is_not_removed_by_uninstall() {
        let (_temp, vault) = vault();
        install(&vault).unwrap();
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        // The first non-marker payload is the manifest. Swap that exact
        // already-read leaf, rather than a later file not read by the caller.
        let manifest = root.join(MANIFEST);
        let displaced = root.join("displaced-manifest.json");
        set_before_payload_removal_bind_for_test(move || {
            fs::rename(&manifest, &displaced).unwrap();
            fs::write(&manifest, b"foreign replacement").unwrap();
        });
        assert_eq!(uninstall(&vault).unwrap().status, BridgeStatus::Residual);
        assert_eq!(
            fs::read(root.join(MANIFEST)).unwrap(),
            b"foreign replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_plugin_slot_is_foreign_without_following_target() {
        use std::os::unix::fs::symlink;
        let (_temp, vault) = vault();
        let plugins = vault.join(".obsidian/plugins");
        let target = vault.join("target");
        fs::create_dir_all(&plugins).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"unchanged").unwrap();
        symlink(&target, plugins.join(PLUGIN_ID)).unwrap();
        assert_eq!(status(&vault).unwrap().status, BridgeStatus::Foreign);
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn malformed_obsidian_parent_surfaces_an_unsafe_path_error() {
        use std::os::unix::fs::symlink;
        let (_temp, vault) = vault();
        let target = vault.join("outside");
        fs::create_dir(&target).unwrap();
        symlink(&target, vault.join(".obsidian")).unwrap();
        assert!(matches!(status(&vault), Err(BridgeError::UnsafePath)));
    }

    #[test]
    fn competing_slot_before_publish_is_preserved() {
        let (_temp, vault) = vault();
        let root = vault.join(".obsidian/plugins").join(PLUGIN_ID);
        set_before_publish_for_test(move || {
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("keep"), b"competitor").unwrap();
        });
        assert!(matches!(
            install(&vault),
            Err(BridgeError::ForeignOrMismatch)
        ));
        assert_eq!(
            fs::read(vault.join(".obsidian/plugins").join(PLUGIN_ID).join("keep")).unwrap(),
            b"competitor"
        );
    }
}
