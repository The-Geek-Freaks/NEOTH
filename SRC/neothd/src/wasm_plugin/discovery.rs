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

/// SC-03 — a minisign detached signature is tiny (~300 bytes); cap the
/// read so a HOSTILE multi-GB `plugin.wasm.minisig` can't OOM the daemon
/// at discovery (the plugin dir is attacker-controlled — that IS SC-03's
/// threat model, and this read happens for every subdir before any
/// manifest/activation filter).
pub(crate) const MAX_MINISIG_BYTES: u64 = 4096;

/// Read a `plugin.wasm.minisig` companion, capped at [`MAX_MINISIG_BYTES`].
/// `None` when the file is absent OR unreadable; `Some(Err(..))` shape is
/// avoided — an over-size file is reported by the caller (`load_one` /
/// `run_verify`) so the operator sees WHY it was refused rather than a
/// silently-dropped signature that would degrade to "unsigned".
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
        fs::File::open(path)
    }
}

/// Read a whole file via [`open_no_follow`] (GR-089) — the symlink-safe
/// replacement for `fs::read` on the plugin-discovery path.
fn read_no_follow(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = open_no_follow(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
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
/// top level (a missing `plugins_root` simply yields an empty report).
pub fn discover(plugins_root: &Path) -> DiscoveryReport {
    let mut report = DiscoveryReport::default();
    let Ok(entries) = fs::read_dir(plugins_root) else {
        return report; // No plugin dir → no plugins; not an error.
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        // SC-03 — refuse symlinks in the plugin root. `is_dir()` follows
        // symlinks, so without this an attacker who can write the plugin
        // root could alias `<id>/` to an arbitrary path (its `plugin.wasm`
        // bytes + the giant-`.minisig` OOM vector would come from the
        // symlink target, and the dir-name the id-locality check keys on
        // would be attacker-chosen). The operator places REAL dirs here.
        if dir.is_symlink() {
            report
                .rejected
                .push(DiscoveryError::SymlinkRejected { dir });
            continue;
        }
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
    // GOLD-SEC-20 / A-56: refuse symlinked plugin files. The top-level dir is
    // already symlink-checked by `discover`, but the files INSIDE were read
    // via `fs::read` with no check — a symlinked plugin.wasm would make the
    // SHA-256 / signature cover the symlink target rather than the declared
    // file. `symlink_metadata` does NOT follow the link.
    let minisig_path = dir.join("plugin.wasm.minisig");
    for (p, name) in [
        (&toml_path, "plugin.toml"),
        (&wasm_path, "plugin.wasm"),
        // GOLD-SEC-20 — the minisig was read (read_capped_minisig) with NO
        // symlink check, so a symlinked `plugin.wasm.minisig` could point the
        // signature at an arbitrary file. A missing minisig makes
        // `symlink_metadata` error → `unwrap_or(false)` lets it through to the
        // optional read; only a real symlink is refused.
        (&minisig_path, "plugin.wasm.minisig"),
    ] {
        if std::fs::symlink_metadata(p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(DiscoveryError::PathIsSymlink {
                dir: dir.to_path_buf(),
                file: name,
            });
        }
    }
    // GR-089 — read via O_NOFOLLOW (open_no_follow) so even a post-check symlink
    // swap can't redirect the read: the check above + the open here are no longer
    // a check-then-read TOCTOU on Unix (the open itself refuses a symlink).
    let toml_bytes = read_no_follow(&toml_path).map_err(|e| DiscoveryError::TomlIo {
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
    let wasm_bytes = read_no_follow(&wasm_path).map_err(|e| DiscoveryError::WasmIo {
        dir: dir.to_path_buf(),
        kind: e.kind(),
    })?;
    let content_hash = sha256_hex(&wasm_bytes);
    // SC-03 — optional minisign detached signature. minisign's `-Sm
    // plugin.wasm` writes `plugin.wasm.minisig`; absence is fine (the
    // signature gate is opt-in via freedom.yaml::plugins.wasm.author_pubkey).
    // Capped read — a hostile over-size companion is refused, not OOM'd.
    let signature = read_capped_minisig(&minisig_path).map_err(|()| {
        DiscoveryError::SignatureInvalid {
            dir: dir.to_path_buf(),
            reason: format!("plugin.wasm.minisig exceeds {MAX_MINISIG_BYTES} bytes — refusing"),
        }
    })?;
    Ok(DiscoveredPlugin {
        dir: dir.to_path_buf(),
        manifest,
        wasm_bytes,
        content_hash,
        signature,
    })
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

/// Full-auto operating mode — is this discovered, currently-`Pending` plugin
/// eligible for AUTOMATIC activation without an explicit `neoth plugin enable`?
///
/// The bar is deliberately HIGHER than [`verify_integrity`] (which only gates
/// what may run once Active): full-auto auto-activation requires TWO
/// independent operator trust signals, so flipping into full-auto can never
/// silently run untrusted third-party WASM. Eligible iff ALL hold:
///
///   1. Clears the full integrity gate (not revoked, pin matches if present,
///      `require_all_pinned` honoured) — [`verify_integrity`] returns `Ok`.
///   2. Has an EXPLICIT hash pin for its own id — `policy.pinned` contains it
///      (merely "no pin and pins not required" is NOT enough; the operator must
///      have pinned exactly this binary).
///   3. Carries a signature that VERIFIES against the configured trusted author
///      key — `verify_plugin_signature(.., require=true) == Ok(Verified)`. An
///      unsigned plugin, a missing author key, or a soft "UnsignedAllowed"
///      outcome all fail here.
///
/// Anything not eligible stays `Pending` even in full-auto — the operator
/// activates it with `neoth plugin enable <id>`. Revoked / invalid-signature
/// plugins are refused by the integrity gate as always.
pub fn auto_activation_eligible(plugin: &DiscoveredPlugin, policy: &IntegrityPolicy<'_>) -> bool {
    // 1. Must clear the standard integrity gate first.
    if verify_integrity(plugin, policy).is_err() {
        return false;
    }
    // 2. Trust signal #1 — an explicit pin for THIS plugin id.
    if !policy.pinned.contains_key(&plugin.manifest.id) {
        return false;
    }
    // 3. Trust signal #2 — a real, verified author signature. `require=true`
    //    makes unsigned / no-key return Err (not a permissive Ok), so only a
    //    genuine `Verified` passes.
    matches!(
        verify_plugin_signature(
            &plugin.wasm_bytes,
            plugin.signature.as_deref(),
            policy.author_pubkey,
            true,
        ),
        Ok(PluginSigOutcome::Verified)
    )
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
    fn auto_activation_rejects_unsigned_even_when_pinned() {
        // Full-auto floor: a pinned-but-UNSIGNED plugin is NOT auto-activated.
        // A hash pin proves the bytes didn't change; it does NOT prove who
        // produced them. Without a verified author signature it stays Pending.
        let p = discovered("pinnedunsigned", MINIMAL_WASM);
        let mut pinned = BTreeMap::new();
        pinned.insert("pinnedunsigned".to_string(), p.content_hash.clone());
        let policy = IntegrityPolicy {
            pinned: &pinned,
            require_all_pinned: false,
            author_pubkey: Some("RWQabc"), // key configured, but plugin is unsigned
            require_signature: false,
            revoked: &[],
        };
        assert!(
            !auto_activation_eligible(&p, &policy),
            "an unsigned plugin must never auto-activate, even pinned"
        );
    }

    #[test]
    fn auto_activation_rejects_unpinned_plugin() {
        // Passes a permissive integrity gate (no pin required, no key) yet is
        // NOT auto-activated: no explicit pin = no trust signal #1.
        let p = discovered("loose", MINIMAL_WASM);
        let empty = BTreeMap::new();
        let policy = IntegrityPolicy {
            pinned: &empty,
            require_all_pinned: false,
            author_pubkey: None,
            require_signature: false,
            revoked: &[],
        };
        assert!(
            verify_integrity(&p, &policy).is_ok(),
            "precondition: a loose plugin clears the standard integrity gate"
        );
        assert!(
            !auto_activation_eligible(&p, &policy),
            "an unpinned plugin must never auto-activate"
        );
    }

    #[test]
    fn auto_activation_rejects_revoked_plugin() {
        let p = discovered("badactor", MINIMAL_WASM);
        let mut pinned = BTreeMap::new();
        pinned.insert("badactor".to_string(), p.content_hash.clone());
        let revoked = vec!["badactor".to_string()];
        let policy = IntegrityPolicy {
            pinned: &pinned,
            require_all_pinned: false,
            author_pubkey: Some("RWQabc"),
            require_signature: false,
            revoked: &revoked,
        };
        assert!(
            !auto_activation_eligible(&p, &policy),
            "a revoked plugin must never auto-activate (integrity gate refuses it)"
        );
    }

    #[test]
    fn auto_activation_rejects_when_no_author_key_configured() {
        // Pinned but no author key to verify against → can't establish trust
        // signal #2, so it stays Pending.
        let p = discovered("pinnednokey", MINIMAL_WASM);
        let mut pinned = BTreeMap::new();
        pinned.insert("pinnednokey".to_string(), p.content_hash.clone());
        let policy = IntegrityPolicy {
            pinned: &pinned,
            require_all_pinned: false,
            author_pubkey: None,
            require_signature: false,
            revoked: &[],
        };
        assert!(
            !auto_activation_eligible(&p, &policy),
            "without a configured author key no plugin can auto-activate"
        );
    }

    #[test]
    fn read_no_follow_reads_a_regular_file_and_errors_on_missing() {
        // GR-089 — the symlink-safe reader returns a regular file's bytes and
        // errors (no panic) on a missing path. The O_NOFOLLOW symlink-refusal
        // itself is Unix-only (CI-verified) + mirrors the existing
        // symlink_metadata loop pattern.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.bin");
        std::fs::write(&p, b"hello-bytes").unwrap();
        assert_eq!(read_no_follow(&p).unwrap(), b"hello-bytes");
        assert!(read_no_follow(&dir.path().join("absent")).is_err());
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
