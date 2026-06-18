//! OS-tool surface configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// PC-01 OS-tool surface config. Default-safe: every sub-surface is
/// deny-all until the operator explicitly opts in.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ToolsConfig {
    pub os: OsToolsConfig,
}

/// PC-01 OS file-access config. `allowed_paths` is the operator's allowlist
/// of absolute path PREFIXES the daemon may read under; empty = deny-all
/// (the default). A read is permitted only when the canonical target path
/// is under one of these (canonical) prefixes - see `os_tools::allowlist`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct OsToolsConfig {
    /// Allowlisted absolute path prefixes. Empty = deny-all (default).
    /// Example: `["/home/alice/workspace", "/tmp/neoth-scratch"]`.
    pub allowed_paths: Vec<PathBuf>,
    /// Max bytes a single `OsFileRead` may return. Default 1 MiB - a guard
    /// against pulling a multi-GB file into memory / a provider prompt.
    pub max_read_bytes: usize,
    /// PC-01 (write slice): allowlisted absolute path prefixes the daemon may
    /// WRITE under. SEPARATE from `allowed_paths` ON PURPOSE - a readable path
    /// is NOT automatically writable. Empty = deny-all (the default). A write is
    /// permitted only when the target's canonical PARENT dir is under one of
    /// these (canonical) prefixes - see `os_tools::allowlist::resolve_write_target`.
    pub allowed_write_paths: Vec<PathBuf>,
    /// Max bytes a single `OsFileWrite` may write. Default 1 MiB - bounds how
    /// much a gated write (or a delegated one) can put on the operator's disk.
    pub max_write_bytes: usize,
    /// PC-01 (app-launch slice): allowlisted absolute EXECUTABLE paths the
    /// daemon may launch. SEPARATE from the file allowlists ON PURPOSE - a
    /// readable/writable path is NOT runnable. Empty = deny-all (the default).
    /// Matched by EXACT canonical path (not a directory prefix): an entry
    /// `/usr/bin/firefox` authorises launching exactly that binary, never the
    /// rest of `/usr/bin`. See `os_tools::allowlist::resolve_exec_program`.
    ///
    /// TOCTOU note: prefer binaries in non-world-writable directories
    /// (`/usr/bin`, `~/bin`). On Unix the resolver REFUSES to launch from a
    /// world-writable dir (e.g. `/tmp`), where another local user could swap
    /// the binary between resolution and exec; entries in user-private dirs are
    /// safe, system dirs are safest.
    pub allowed_exec_paths: Vec<PathBuf>,
    /// PC-01 (clipboard slice): OS clipboard read/write policy. Default = fully
    /// OFF. Compiled unconditionally (pure data, no `arboard` dependency); the
    /// `os-clipboard` cargo feature only gates the backend + the gate functions
    /// that consume this config.
    #[serde(default)]
    pub clipboard: ClipboardConfig,
}

impl Default for OsToolsConfig {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            max_read_bytes: 1024 * 1024,
            allowed_write_paths: Vec::new(),
            max_write_bytes: 1024 * 1024,
            allowed_exec_paths: Vec::new(),
            clipboard: ClipboardConfig::default(),
        }
    }
}

/// PC-01 (clipboard slice) - OS clipboard policy. Default is the MOST
/// RESTRICTIVE posture: every toggle OFF, so a fresh install (or any
/// `freedom.yaml` missing the `tools.os.clipboard` key) can neither read nor
/// write the operator's clipboard. The operator opts in PER DIRECTION
/// (`read_enabled` / `write_enabled` are SEPARATE ON PURPOSE - mirroring the
/// `allowed_paths` vs `allowed_write_paths` split: reading is not writing).
///
/// Security rationale: the OS clipboard is an UNSCOPED ambient secret store
/// (read can capture a just-copied password) and a passive injection sink
/// (write enables pastejacking). Both directions are also autonomy-gated and
/// WAL-audited downstream; these flags are the upstream master switches.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ClipboardConfig {
    /// Master switch. `false` (default) means neither read nor write is possible.
    pub enabled: bool,
    /// Allow `OsClipboardRead`. `false` (default) means reads denied even if
    /// `enabled`.
    pub read_enabled: bool,
    /// Allow `OsClipboardWrite`. `false` (default) means writes denied even if
    /// `enabled`.
    pub write_enabled: bool,
    /// Max bytes a clipboard READ may surface (default 4 KiB) - caps how much
    /// ambient content a single read can pull.
    pub max_clipboard_read_bytes: usize,
    /// Max bytes a clipboard WRITE may place (default 4 KiB).
    pub max_clipboard_write_bytes: usize,
    /// Permit newline/CR characters in a WRITE. `false` (default) means the gate
    /// STRUCTURALLY rejects newline-bearing content (the terminal auto-execute
    /// precondition of a pastejacking attack). Set `true` only for deliberate
    /// multi-line clipboard use; the gate then logs a warning per write.
    pub allow_newlines_in_write: bool,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            read_enabled: false,
            write_enabled: false,
            max_clipboard_read_bytes: 4096,
            max_clipboard_write_bytes: 4096,
            allow_newlines_in_write: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::FreedomConfig;

    #[test]
    fn tools_os_defaults_to_deny_all() {
        // PC-01: a fresh config (or a freedom.yaml with no `tools:` block)
        // must read as deny-all - empty allowed_paths, 1 MiB read cap.
        let cfg = ToolsConfig::default();
        assert!(
            cfg.os.allowed_paths.is_empty(),
            "default OS allowlist must be empty (deny-all)"
        );
        assert_eq!(cfg.os.max_read_bytes, 1024 * 1024);
        // Round-trips through YAML with the field absent.
        let parsed: FreedomConfig =
            serde_yaml::from_str("operator_id: alice\n").expect("parse minimal freedom.yaml");
        assert!(parsed.tools.os.allowed_paths.is_empty());
    }
}
