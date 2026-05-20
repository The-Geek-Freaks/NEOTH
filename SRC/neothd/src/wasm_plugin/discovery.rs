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

use std::fs;
use std::path::{Path, PathBuf};

use super::manifest::{ManifestError, PluginManifest, parse_manifest};

/// One discovered plugin directory + its parsed manifest + the WASM
/// bytes pre-loaded so the engine can compile without a second I/O
/// hop. Bytes are owned; the `PluginManifest` is cloneable so the
/// host can stash the metadata in a `BTreeMap` for `plugins list`.
#[derive(Clone, Debug)]
pub struct DiscoveredPlugin {
    pub dir: PathBuf,
    pub manifest: PluginManifest,
    pub wasm_bytes: Vec<u8>,
}

/// What went wrong for one plugin subdirectory. Operator-readable;
/// the WAL `PLUGIN_REJECTED` (0xC3) frame carries the same shape.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum DiscoveryError {
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
    #[error("plugin {dir:?}: manifest validation failed: {source}")]
    ManifestInvalid { dir: PathBuf, source: ManifestError },
    #[error("plugin {dir:?}: manifest id {got:?} does not match directory name {expected:?}")]
    IdDirectoryMismatch {
        dir: PathBuf,
        got: String,
        expected: String,
    },
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
/// top level (a missing `plugins_root` simply yields an empty report).
pub fn discover(plugins_root: &Path) -> DiscoveryReport {
    let mut report = DiscoveryReport::default();
    let Ok(entries) = fs::read_dir(plugins_root) else {
        return report; // No plugin dir → no plugins; not an error.
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        match load_one(&dir) {
            Ok(plugin) => report.loaded.push(plugin),
            Err(e) => report.rejected.push(e),
        }
    }
    // Stable ordering so `plugins list` reads the same on every boot.
    report
        .loaded
        .sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    report
}

fn load_one(dir: &Path) -> Result<DiscoveredPlugin, DiscoveryError> {
    let toml_path = dir.join("plugin.toml");
    let wasm_path = dir.join("plugin.wasm");
    if !toml_path.exists() {
        return Err(DiscoveryError::MissingManifest {
            dir: dir.to_path_buf(),
        });
    }
    if !wasm_path.exists() {
        return Err(DiscoveryError::MissingWasm {
            dir: dir.to_path_buf(),
        });
    }
    let toml_bytes = fs::read(&toml_path).map_err(|e| DiscoveryError::TomlIo {
        dir: dir.to_path_buf(),
        kind: e.kind(),
    })?;
    let manifest = parse_manifest(&toml_bytes).map_err(|e| DiscoveryError::ManifestInvalid {
        dir: dir.to_path_buf(),
        source: e,
    })?;
    // Enforce id matches directory name so `~/.neoth/plugins/<id>/`
    // is a reliable lookup key. Without this, two plugins with the
    // same manifest id but different directory names would silently
    // collide in `plugins list`.
    let dir_name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    if manifest.id != dir_name {
        return Err(DiscoveryError::IdDirectoryMismatch {
            dir: dir.to_path_buf(),
            got: manifest.id,
            expected: dir_name,
        });
    }
    let wasm_bytes = fs::read(&wasm_path).map_err(|e| DiscoveryError::WasmIo {
        dir: dir.to_path_buf(),
        kind: e.kind(),
    })?;
    Ok(DiscoveredPlugin {
        dir: dir.to_path_buf(),
        manifest,
        wasm_bytes,
    })
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
}
