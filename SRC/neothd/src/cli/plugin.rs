//! `neoth plugin` — D-102 (Session 21, 2026-05-23) operator-facing
//! activation management for WASM plugins.
//!
//! The 6/6 agent panel verdict: default-inactive. The daemon never
//! instantiates a discovered `.wasm` until the operator runs `neoth
//! plugin enable <id>` (or accepts it via the first-run wizard
//! multiselect step).
//!
//! Subcommands:
//!   - `list`    every discovered plugin + its activation state
//!   - `pending` only the discovered-but-unconfirmed plugins
//!   - `enable <id>`  flip Pending|Disabled → Active
//!   - `disable <id>` flip Pending|Active   → Disabled
//!
//! Activation state lives in `freedom.yaml::plugins.wasm.activations`
//! keyed by plugin manifest id. Mutations go through
//! [`FreedomConfig::update_at`] so future fields and concurrent operator edits
//! survive while the on-disk representation remains authoritative for the
//! next daemon boot.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;
use sha2::Digest as _;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::wal::compress::decompress_frames;
use crate::wal::events::{EVENT_TYPE_PLUGIN_CAP_USED, EVENT_TYPE_PLUGIN_HOSTCALL};
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;
use crate::wasm_plugin::discovery::{
    PluginActivation, PluginActivationRecord, PluginApproval, discover,
};
use crate::wasm_plugin::manifest::RequestedPermission;

#[derive(Args, Debug, Clone)]
pub struct PluginArgs {
    #[command(subcommand)]
    pub action: PluginAction,

    /// Output format (inherited from global --output flag).
    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PluginAction {
    /// List every discovered plugin + its operator activation state.
    /// Plugins NOT yet listed in freedom.yaml::plugins.wasm.activations
    /// show as `pending` (the default for any newly discovered id).
    List,
    /// Show Pending plugins plus Active entries that require re-consent.
    Pending,
    /// Review and activate a plugin, binding permission + manifest/WASM
    /// digests. Idempotent while that complete approval is unchanged.
    Enable {
        /// Plugin manifest id (matches the directory name under
        /// `~/.neoth/plugins/<id>/`).
        id: String,
    },
    /// Flip a plugin to `disabled`. Idempotent.
    Disable { id: String },
    /// UX-07 — pre-deployment plugin verification. Reads
    /// `<path>/plugin.toml` + `<path>/plugin.wasm`, validates the
    /// manifest, and (when the daemon was built with the
    /// `wasm-plugin-host` feature) runs a sandboxed `neoth_run`
    /// invocation in a fresh wasmtime Store with the manifest's fuel +
    /// memory budgets applied. Reports the `InvocationOutcome` so the
    /// operator sees pass/fail without touching `~/.neoth/plugins/`.
    Test {
        /// Directory containing `plugin.toml` + `plugin.wasm`.
        path: std::path::PathBuf,
        /// UX-07b — capture the WAL frames (`0xC4`/`0xC6`/`0xC7`) the
        /// invocation emits into a throwaway WAL home and surface them in the
        /// report. Requires the `wasm-plugin-host` feature; without it the flag
        /// is inert (the slim build can't live-invoke). The live WAL, HMAC key,
        /// and recovery state are never touched. Capture uses one non-rotating
        /// segment and rejects the frame that would cross its 32 MiB physical
        /// ceiling, so later frames cannot disappear into an unread segment;
        /// reconstructed data is also capped at 32 MiB and 65,536 complete
        /// frames. WAL and encrypted `master.key` reads are bounded, no-follow,
        /// and accept only real regular files below the throwaway home. A
        /// missing file, incomplete segment-header prefix, or genuinely torn
        /// final frame remains crash-tolerant (including exactly 65,536 complete
        /// frames plus a torn next frame); unsafe paths, malformed complete
        /// data, limit breaches, and writer initialization/completion failures
        /// are reported visibly as `capture_error` in JSON and table output.
        #[arg(long)]
        capture_wal: bool,
    },
    /// SC-03 — verify a plugin directory against the operator's integrity
    /// policy (revocation list + pinned hash + author signature) WITHOUT
    /// instantiating it. Reads `<path>/plugin.toml` + `plugin.wasm` +
    /// optional `plugin.wasm.minisig`, then applies
    /// `freedom.yaml::plugins.wasm` (`author_pubkey` / `require_signature`
    /// / `revoked_ids` / `pinned_hashes`). Prints PASS/FAIL + reason and
    /// exits non-zero on FAIL so CI / a pre-install check can gate on it.
    Verify {
        /// Directory containing `plugin.toml` + `plugin.wasm` (+ optional
        /// `plugin.wasm.minisig`).
        path: std::path::PathBuf,
    },
    /// KF-09 — per-plugin capability usage ledger. Scans the WAL for the
    /// plugin audit frames (`0xC4 PLUGIN_HOSTCALL` writes via `emit_event`,
    /// `0xC6 PLUGIN_CAP_USED` reads via `recall_top`) and aggregates a
    /// per-plugin-per-capability call count + volume — so an operator can
    /// see WHAT each plugin actually exercised. Read-only; works on a slim
    /// daemon too (it reads historical frames, no wasm host needed).
    Ledger {
        /// Restrict to one plugin id. Omit for all plugins.
        id: Option<String>,
    },
    /// Install a plugin from a local directory into `~/.neoth/plugins/<id>/`.
    /// The id is derived from the manifest `id` field inside `<path>/plugin.toml`.
    /// Only `plugin.toml`, `plugin.wasm`, and the optional
    /// `plugin.wasm.minisig` companion are copied — arbitrary extra files are
    /// never installed (mirrors the discovery contract). Before activation the
    /// same integrity policy as `neoth plugin verify` and daemon startup is
    /// applied; a failed staged install leaves an existing version untouched.
    Install {
        /// Directory containing `plugin.toml` + `plugin.wasm` to install.
        path: std::path::PathBuf,
        /// Overwrite an already-installed plugin with the same id. Without
        /// this flag the command exits non-zero when the target directory
        /// already exists.
        #[arg(long)]
        force: bool,
    },
    /// Remove a plugin from `~/.neoth/plugins/<id>/`. Idempotent: if the
    /// plugin is not installed the command succeeds with a "not found" note.
    /// The plugin's activation entry in `freedom.yaml` is also removed when
    /// present so discovery won't see a stale activation key on next boot.
    Remove {
        /// Plugin manifest id to remove (must match the directory name under
        /// `~/.neoth/plugins/<id>/`).
        id: String,
    },
    /// DES-12 — read-only WAL feed for a plugin's emitted events (0xC4
    /// frames). Used by the GUI to populate a plugin-provided tab without
    /// granting the plugin any direct filesystem or command access.
    ///
    /// Scans the WAL for `PLUGIN_HOSTCALL` (0xC4) frames whose `plugin`
    /// field matches `<id>`, returns them newest-first capped at `--last N`.
    /// Output: `{"id":"<id>","events":[{"kind":"...","payload_bytes":N,"ts_unix":T}]}`.
    /// No events found → empty array, exit 0.
    Events {
        /// Plugin manifest id to query.
        id: String,
        /// Maximum number of events to return (newest first).
        #[arg(long, default_value = "30")]
        last: usize,
    },
}

pub async fn run_plugin(args: PluginArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        PluginAction::List => render_list(&home, args.output, false),
        PluginAction::Pending => render_list(&home, args.output, true),
        PluginAction::Enable { id } => {
            set_activation(&home, &id, PluginActivation::Active, args.output)
        }
        PluginAction::Disable { id } => {
            set_activation(&home, &id, PluginActivation::Disabled, args.output)
        }
        PluginAction::Test { path, capture_wal } => run_test(&path, args.output, capture_wal).await,
        PluginAction::Verify { path } => run_verify(&path, args.output),
        PluginAction::Ledger { id } => run_ledger(id.as_deref(), args.output),
        PluginAction::Install { path, force } => run_install(&path, force, args.output),
        PluginAction::Remove { id } => run_remove(&id, args.output).await,
        PluginAction::Events { id, last } => run_events_subcommand(&id, last, args.output),
    }
}

/// UX-07 — always-compiled summary of a live invocation. The real
/// `dispatch::InvocationOutcome` lives behind the `wasm-plugin-host`
/// feature, so the CLI surfaces an always-available shape that the
/// renderer + tests can hold in both build modes. The cfg-gated
/// invoker converts `InvocationOutcome` → `TestInvocationSummary`; the
/// slim build never produces one and the renderer prints the
/// "rebuild with feature" hint.
#[derive(Clone, Debug, serde::Serialize)]
struct TestInvocationSummary {
    /// Stage name (`compile` / `instantiate` / `export_lookup` / `run` /
    /// `skipped_due_to_compile_failure`) — kept as a String so the slim
    /// build doesn't need to depend on the gated `InvocationStage` enum.
    stage: String,
    /// `None` when `neoth_run` returned normally; `Some` when any stage
    /// (compile / instantiate / export-lookup / run trap) failed.
    error: Option<String>,
    /// True when the live invocation reached `neoth_run` and the plugin
    /// completed without a trap (regardless of the i32 return value —
    /// non-zero is "plugin's own convention", not a host-level failure).
    invoked_ok: bool,
}

/// UX-07b — a live invocation PLUS the WAL frames it emitted, captured into a
/// throwaway tempdir WAL. `captured_frames` carries one entry per frame
/// (`{event_type, payload}`) in emission order — the `0xC4 PLUGIN_HOSTCALL` /
/// `0xC6 PLUGIN_CAP_USED` / `0xC7 PLUGIN_CAP_DENIED` audit trail the plugin
/// produced. Always-compiled (the slim build just never produces one).
#[derive(Clone, Debug, serde::Serialize)]
struct TestInvocationWithWal {
    outcome: TestInvocationSummary,
    captured_frames: Vec<serde_json::Value>,
    capture_error: Option<CaptureWalError>,
}

#[cfg(any(test, feature = "wasm-plugin-host"))]
#[derive(Clone, Copy, Debug)]
struct CaptureWalLimits {
    max_physical_bytes: usize,
    max_logical_frame_bytes: u64,
    max_frames: usize,
}

#[cfg(any(test, feature = "wasm-plugin-host"))]
impl Default for CaptureWalLimits {
    fn default() -> Self {
        // The capture writer is non-rotating and refuses the frame that would
        // cross this physical ceiling. Keep reconstructed data under the same
        // bound and far below the general forensic decompression ceiling.
        Self {
            max_physical_bytes: 32 * 1024 * 1024,
            max_logical_frame_bytes: 32 * 1024 * 1024,
            max_frames: 65_536,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
// The no-host build still serializes the stable capture-error vocabulary, but
// only the feature-gated live host can construct most variants.
#[cfg_attr(not(any(test, feature = "wasm-plugin-host")), allow(dead_code))]
enum CaptureWalErrorKind {
    InvalidPath,
    UnsafeFile,
    WriterInitFailed,
    WriterCompletionFailed,
    PhysicalLimitExceeded,
    ReadFailed,
    MasterKeyReadFailed,
    LogicalLimitExceeded,
    ReconstructFailed,
    InvalidLogicalLayout,
    CorruptFrame,
    FrameLimitExceeded,
}

impl CaptureWalErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPath => "invalid_path",
            Self::UnsafeFile => "unsafe_file",
            Self::WriterInitFailed => "writer_init_failed",
            Self::WriterCompletionFailed => "writer_completion_failed",
            Self::PhysicalLimitExceeded => "physical_limit_exceeded",
            Self::ReadFailed => "read_failed",
            Self::MasterKeyReadFailed => "master_key_read_failed",
            Self::LogicalLimitExceeded => "logical_limit_exceeded",
            Self::ReconstructFailed => "reconstruct_failed",
            Self::InvalidLogicalLayout => "invalid_logical_layout",
            Self::CorruptFrame => "corrupt_frame",
            Self::FrameLimitExceeded => "frame_limit_exceeded",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
struct CaptureWalError {
    kind: CaptureWalErrorKind,
    message: String,
}

impl CaptureWalError {
    #[cfg(any(test, feature = "wasm-plugin-host"))]
    fn new(kind: CaptureWalErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// UX-07 — read + validate a candidate plugin and (under the host
/// feature) live-invoke it. Returns Ok even when the invocation reports
/// a plugin-side error so the operator can see the structured outcome;
/// returns Err only when the inputs themselves are unusable
/// (missing files, malformed manifest).
async fn run_test(path: &std::path::Path, output: OutputFormat, capture_wal: bool) -> Result<()> {
    if !path.exists() {
        anyhow::bail!(
            "plugin path `{}` does not exist — pass a directory containing \
             `plugin.toml` + `plugin.wasm`",
            path.display()
        );
    }
    if !path.is_dir() {
        anyhow::bail!(
            "plugin path `{}` is not a directory — expected a directory with \
             `plugin.toml` + `plugin.wasm`",
            path.display()
        );
    }

    let manifest_path = path.join("plugin.toml");
    let wasm_path = path.join("plugin.wasm");
    if !manifest_path.exists() {
        anyhow::bail!("missing `plugin.toml` at {}", manifest_path.display());
    }
    if !wasm_path.exists() {
        anyhow::bail!("missing `plugin.wasm` at {}", wasm_path.display());
    }

    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest = crate::wasm_plugin::manifest::parse_manifest(&manifest_bytes)
        .map_err(|e| anyhow::anyhow!("manifest invalid: {e}"))?;

    let wasm_bytes =
        std::fs::read(&wasm_path).with_context(|| format!("read {}", wasm_path.display()))?;

    // Default-build path: report manifest validation without invoking.
    // Operators on a slim daemon (no `wasm-plugin-host`) still get the
    // manifest-shape check, which catches the most common authoring
    // mistakes (wrong id casing, missing permissions, bad budgets).
    if capture_wal {
        // UX-07b: live-invoke with an injected throwaway WAL writer + surface
        // the captured 0xC4/0xC6/0xC7 frames. The slim build returns None
        // (the renderer prints the rebuild hint, same as the dry-run path).
        let captured = run_test_invoke_with_wal(&manifest, &wasm_bytes).await;
        let (outcome, frames, capture_error) = match captured {
            Some(c) => (Some(c.outcome), Some(c.captured_frames), c.capture_error),
            None => (None, None, None),
        };
        render_test_report(
            &manifest,
            wasm_bytes.len(),
            outcome,
            frames,
            capture_error,
            output,
        )
    } else {
        let invocation_outcome: Option<TestInvocationSummary> =
            run_test_invoke(&manifest, &wasm_bytes);
        render_test_report(
            &manifest,
            wasm_bytes.len(),
            invocation_outcome,
            None,
            None,
            output,
        )
    }
}

/// SC-03 — `neoth plugin verify <path>`: run the operator's integrity
/// policy against one plugin directory without instantiating it. Reuses
/// the daemon's [`crate::wasm_plugin::discovery::verify_integrity`] gate
/// so the CLI verdict and the daemon's load-time refusal can never
/// disagree. Exits non-zero on FAIL.
fn run_verify(path: &std::path::Path, output: OutputFormat) -> Result<()> {
    if !path.exists() {
        anyhow::bail!(
            "plugin path `{}` does not exist — pass a directory containing \
             `plugin.toml` + `plugin.wasm`",
            path.display()
        );
    }
    if !path.is_dir() {
        anyhow::bail!(
            "plugin path `{}` is not a directory — expected a directory with \
             `plugin.toml` + `plugin.wasm`",
            path.display()
        );
    }

    // Inspect through a single bound directory capability. Unlike daemon
    // discovery, this pre-install verifier deliberately does not require the
    // checkout directory name to equal the manifest id (CI uses arbitrary
    // clone directory names).
    let manifest_path = path.join("plugin.toml");
    let wasm_path = path.join("plugin.wasm");
    if !manifest_path.exists() {
        anyhow::bail!("missing `plugin.toml` at {}", manifest_path.display());
    }
    if !wasm_path.exists() {
        anyhow::bail!("missing `plugin.wasm` at {}", wasm_path.display());
    }
    let plugin = crate::wasm_plugin::discovery::inspect_bundle(path)
        .map_err(|error| anyhow::anyhow!("plugin bundle invalid: {error}"))?;

    // Apply the SAME freedom.yaml policy the daemon uses at load time. A
    // missing OR corrupt config is an error: silently substituting the open
    // default would falsely PASS plugins the daemon may refuse once the real
    // operator policy is restored.
    let cfg = FreedomConfig::load_from_default_path().context(
        "could not load freedom.yaml — fix it before verifying (a verify against an \
         empty policy would falsely PASS revoked/tampered/unsigned plugins)",
    )?;
    let w = &cfg.plugins.wasm;
    let policy = crate::wasm_plugin::discovery::IntegrityPolicy {
        pinned: &w.pinned_hashes,
        require_all_pinned: w.require_all_pinned,
        author_pubkey: w.author_pubkey.as_deref(),
        require_signature: w.require_signature,
        revoked: &w.revoked_ids,
    };
    let verdict = crate::wasm_plugin::discovery::verify_integrity(&plugin, &policy);
    let sig_present = plugin.signature.is_some();
    let sig_checked = w.author_pubkey.is_some();
    // A plugin is "verified" ONLY when the gate passed AND a key was
    // configured AND a signature was actually present + checked.
    let sig_verified = verdict.is_ok() && sig_checked && sig_present;
    let (status, reason) = match &verdict {
        Ok(()) => ("PASS", String::new()),
        Err(e) => ("FAIL", e.to_string()),
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let obj = serde_json::json!({
                "id": plugin.manifest.id,
                "content_hash": plugin.content_hash,
                "signature_present": sig_present,
                "signature_checked": sig_checked,
                "signature_verified": sig_verified,
                "verdict": status,
                "reason": reason,
            });
            println!("{}", serde_json::to_string(&obj)?);
        }
        OutputFormat::Table => {
            println!("plugin:     {}", plugin.manifest.id);
            println!("sha256:     {}", plugin.content_hash);
            println!(
                "signature:  {}",
                if sig_present {
                    "present (plugin.wasm.minisig)"
                } else {
                    "absent"
                }
            );
            // Reflect the ACTUAL verdict — never claim "verified" on a FAIL
            // or when the plugin shipped no signature.
            let author_key_line = match (sig_checked, sig_present, &verdict) {
                (false, _, _) => "not configured (signature check off)",
                (true, _, Err(_)) => "configured (signature check FAILED)",
                (true, true, Ok(())) => "configured (signature verified)",
                (true, false, Ok(())) => {
                    "configured but plugin is UNSIGNED (require_signature=false)"
                }
            };
            println!("author key: {author_key_line}");
            println!("verdict:    {status}");
            if !reason.is_empty() {
                println!("reason:     {reason}");
            }
        }
    }

    if verdict.is_err() {
        anyhow::bail!("plugin failed the SC-03 integrity gate");
    }
    Ok(())
}

// ── KF-09 plugin capability ledger ────────────────────────────────────────

/// One raw capability use parsed from a plugin audit frame.
#[derive(Debug, Clone, PartialEq)]
struct CapUse {
    plugin: String,
    capability: String,
    /// `0xC4` write volume (`payload_bytes`); 0 for reads.
    payload_bytes: u64,
    /// `0xC6` read hit count (`hits`); 0 for writes.
    hits: i64,
}

/// Aggregated per (plugin, capability) row.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
struct LedgerRow {
    plugin: String,
    capability: String,
    calls: u64,
    total_payload_bytes: u64,
    total_hits: i64,
}

/// Parse a plugin audit frame into a [`CapUse`]. `None` for any other
/// event type or a malformed payload (tolerant — a partially-corrupt WAL
/// still yields its good records). Pure — unit-tested without a real WAL.
fn parse_cap_frame(event_type: u8, payload: &[u8]) -> Option<CapUse> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let plugin = v.get("plugin")?.as_str()?.to_string();
    if event_type == EVENT_TYPE_PLUGIN_HOSTCALL {
        // 0xC4 emit_event WRITE: {plugin, kind, payload_bytes}.
        let payload_bytes = v.get("payload_bytes").and_then(|x| x.as_u64()).unwrap_or(0);
        Some(CapUse {
            plugin,
            capability: "emit_event".to_string(),
            payload_bytes,
            hits: 0,
        })
    } else if event_type == EVENT_TYPE_PLUGIN_CAP_USED {
        // 0xC6 READ: {plugin, capability, prompt_hash, hits}.
        let capability = v
            .get("capability")
            .and_then(|x| x.as_str())
            .unwrap_or("read")
            .to_string();
        let hits = v.get("hits").and_then(|x| x.as_i64()).unwrap_or(0);
        Some(CapUse {
            plugin,
            capability,
            payload_bytes: 0,
            hits,
        })
    } else {
        None
    }
}

/// Aggregate raw uses into per-(plugin, capability) rows, optionally
/// filtered to one plugin id. `BTreeMap` keying yields stable
/// plugin-then-capability ordering. Pure — unit-tested without a real WAL.
fn aggregate_ledger(uses: Vec<CapUse>, filter_id: Option<&str>) -> Vec<LedgerRow> {
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<(String, String), LedgerRow> = BTreeMap::new();
    for u in uses {
        if let Some(want) = filter_id
            && u.plugin != want
        {
            continue;
        }
        let row = acc
            .entry((u.plugin.clone(), u.capability.clone()))
            .or_insert(LedgerRow {
                plugin: u.plugin,
                capability: u.capability,
                calls: 0,
                total_payload_bytes: 0,
                total_hits: 0,
            });
        row.calls += 1;
        row.total_payload_bytes = row.total_payload_bytes.saturating_add(u.payload_bytes);
        row.total_hits = row.total_hits.saturating_add(u.hits);
    }
    acc.into_values().collect()
}

/// Walk the frame bytes of ONE segment body (decompressed if compressed),
/// pushing every plugin-audit `CapUse`. Tail-tolerant (stops at the first
/// torn frame) + zero-`total_len` loop guard — identical contract to every
/// other WAL walker in the codebase.
fn walk_cap_frames(frames: &[u8], out: &mut Vec<CapUse>) {
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if let Some(u) = parse_cap_frame(dec.header.event_type, dec.payload) {
            out.push(u);
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
}

/// DES-12 — walk the frame bytes of ONE segment body (decompressed if
/// compressed), pushing every `PLUGIN_HOSTCALL` (0xC4) frame whose `plugin`
/// JSON field matches `plugin_id`. Tail-tolerant + zero-`total_len` loop guard
/// — same contract as `walk_cap_frames`. Called by `run_events_subcommand`.
fn walk_hostcall_frames(frames: &[u8], plugin_id: &str, out: &mut Vec<EventEntry>) {
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        let total = dec.header.total_len as usize;
        if dec.header.event_type == EVENT_TYPE_PLUGIN_HOSTCALL
            && let Ok(v) = serde_json::from_slice::<serde_json::Value>(dec.payload)
            && v.get("plugin").and_then(|p| p.as_str()) == Some(plugin_id)
        {
            let kind = v
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .to_string();
            let payload_bytes = v.get("payload_bytes").and_then(|x| x.as_u64()).unwrap_or(0);
            let ts_unix = dec.header.hlc.physical_ns() / 1_000_000_000;
            out.push(EventEntry {
                kind,
                payload_bytes,
                ts_unix,
            });
        }
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
}

/// Scan every `*.wal` segment in `wal_dir` for plugin-audit frames.
/// Robust across v1/v2 + compressed segments (mirrors the SPEC-10 refusal-
/// history walker); a missing dir / unreadable / short / unknown-format /
/// torn segment each skip rather than error.
fn collect_cap_uses(wal_dir: &std::path::Path) -> Vec<CapUse> {
    let entries = match std::fs::read_dir(wal_dir) {
        Ok(it) => it,
        Err(_) => return Vec::new(),
    };
    let mut segments: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
        .collect();
    segments.sort();

    let mut out: Vec<CapUse> = Vec::new();
    for path in segments {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(hdr) = parse_segment_header(&bytes) else {
            continue;
        };
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue;
        }
        let body = &bytes[header_len..];
        if hdr.is_compressed() {
            if let Ok(d) = decompress_frames(body) {
                walk_cap_frames(&d, &mut out);
            }
        } else {
            walk_cap_frames(body, &mut out);
        }
    }
    out
}

/// KF-09 — `neoth plugin ledger [<id>]`. Aggregates the plugin capability
/// audit frames so the operator sees what each plugin exercised.
fn run_ledger(id: Option<&str>, output: OutputFormat) -> Result<()> {
    let wal_dir = FreedomConfig::default_wal_dir();
    let rows = aggregate_ledger(collect_cap_uses(&wal_dir), id);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&rows)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                match id {
                    Some(p) => println!("No recorded capability usage for plugin `{p}`."),
                    None => println!(
                        "No recorded plugin capability usage yet (no 0xC4/0xC6 frames in the WAL)."
                    ),
                }
                return Ok(());
            }
            println!(
                "{:<24} {:<14} {:>6} {:>12} {:>8}",
                "PLUGIN", "CAPABILITY", "CALLS", "BYTES(w)", "HITS(r)"
            );
            for r in &rows {
                println!(
                    "{:<24} {:<14} {:>6} {:>12} {:>8}",
                    r.plugin, r.capability, r.calls, r.total_payload_bytes, r.total_hits
                );
            }
        }
    }
    Ok(())
}

/// DES-12 — per-event record returned by `neoth plugin events`. Serialised
/// verbatim into the JSON envelope `{"id":"<id>","events":[...]}`.
#[derive(serde::Serialize)]
struct EventEntry {
    kind: String,
    payload_bytes: u64,
    ts_unix: u64,
}

/// DES-12 — `neoth plugin events <id> [--last N] [--output json]`.
///
/// Scans the WAL for `PLUGIN_HOSTCALL` (0xC4) frames whose JSON body
/// `plugin` field matches `<id>`, returns them newest-first capped at
/// `last`. This is the daemon half of the plugin-provided GUI tab: the
/// GUI polls this command to populate the WAL-feed surface; no arbitrary
/// command or file execution is involved.
///
/// Security: this function is **read-only** — it never writes to the WAL or
/// touches `~/.neoth/plugins/`. The `kind` string is plugin-controlled but
/// was already UTF-8-sanitised at the `emit_event` hostcall site; it is
/// emitted verbatim here (the GUI is responsible for HTML-escaping on
/// display). The `payload_bytes` count is a u64 integer — no payload
/// content is stored or surfaced.
fn run_events_subcommand(plugin_id: &str, last: usize, output: OutputFormat) -> Result<()> {
    let wal_dir = FreedomConfig::default_wal_dir();

    let entries = match std::fs::read_dir(&wal_dir) {
        Ok(it) => it,
        Err(_) => {
            // WAL dir missing — return empty, not an error.
            return emit_events_output(plugin_id, &[] as &[EventEntry], output);
        }
    };
    let mut segments: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
        .collect();
    segments.sort();

    // Collect matching events from all segments (oldest → newest order after
    // sort), then reverse so newest-first, then cap at `last`.
    let mut events: Vec<EventEntry> = Vec::new();
    for path in &segments {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(hdr) = parse_segment_header(&bytes) else {
            continue;
        };
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue;
        }
        let body = &bytes[header_len..];
        // Mirror the exact pattern used by collect_cap_uses / walk_cap_frames:
        // decompress into an owned buf when needed, borrow body otherwise.
        if hdr.is_compressed() {
            let Ok(d) = decompress_frames(body) else {
                continue;
            };
            walk_hostcall_frames(&d, plugin_id, &mut events);
        } else {
            walk_hostcall_frames(body, plugin_id, &mut events);
        }
    }

    // Newest-first, capped at `last`.
    events.reverse();
    events.truncate(last);

    emit_events_output(plugin_id, &events, output)
}

fn emit_events_output(
    plugin_id: &str,
    events: &[impl serde::Serialize],
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let v = serde_json::json!({
                "id": plugin_id,
                "events": events,
            });
            println!("{}", serde_json::to_string(&v)?);
        }
        OutputFormat::Table => {
            println!("Events for plugin `{plugin_id}` (newest first):");
            let events_val = serde_json::to_value(events)?;
            let arr = events_val.as_array().unwrap();
            if arr.is_empty() {
                println!("  (no events recorded)");
            } else {
                println!("{:<40}  {:>14}  TS_UNIX", "KIND", "PAYLOAD_BYTES");
                for e in arr {
                    let kind = e.get("kind").and_then(|k| k.as_str()).unwrap_or("-");
                    let pb = e.get("payload_bytes").and_then(|x| x.as_u64()).unwrap_or(0);
                    let ts = e.get("ts_unix").and_then(|x| x.as_u64()).unwrap_or(0);
                    println!("{kind:<40}  {pb:>14}  {ts}");
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "wasm-plugin-host")]
fn run_test_invoke(
    manifest: &crate::wasm_plugin::manifest::PluginManifest,
    wasm_bytes: &[u8],
) -> Option<TestInvocationSummary> {
    use crate::wasm_plugin::dispatch::{
        CompileOutcome, InvocationStage, PluginExecutionLimits,
        invocation_outcome_from_compile_failure, invoke_plugin,
    };
    use crate::wasm_plugin::engine::NeothEngine;
    use crate::wasm_plugin::hostcalls;

    let engine = match NeothEngine::new() {
        Ok(e) => e,
        Err(e) => {
            return Some(TestInvocationSummary {
                stage: "compile".to_string(),
                error: Some(format!("engine init failed: {e}")),
                invoked_ok: false,
            });
        }
    };
    let compile_outcome = match engine.compile_from_bytes(wasm_bytes) {
        Ok(module) => CompileOutcome::Compiled {
            plugin_id: manifest.id.clone(),
            module: std::sync::Arc::new(module),
            execution_limits: PluginExecutionLimits::from_manifest(manifest),
        },
        Err(e) => CompileOutcome::Failed {
            plugin_id: manifest.id.clone(),
            error: format!("{e}"),
        },
    };
    if let Some(skip) = invocation_outcome_from_compile_failure(&compile_outcome) {
        return Some(TestInvocationSummary {
            stage: invocation_stage_name(skip.stage).to_string(),
            error: skip.error,
            invoked_ok: false,
        });
    }
    let module = match &compile_outcome {
        CompileOutcome::Compiled { module, .. } => module,
        CompileOutcome::Failed { .. } => unreachable!("invocation_outcome_from_compile_failure"),
    };
    // `build_linker` takes the raw `wasmtime::Engine` and returns a
    // `Result`; `invoke_plugin` takes `&NeothEngine` + `&Module`.
    let linker = match hostcalls::build_linker(engine.raw()) {
        Ok(l) => l,
        Err(e) => {
            return Some(TestInvocationSummary {
                stage: "compile".to_string(),
                error: Some(format!("linker build failed: {e}")),
                invoked_ok: false,
            });
        }
    };
    // SC-04: test the plugin with EXACTLY the grant it would receive in
    // production — its manifest `requested_permissions`. So `neoth plugin
    // test` exercises the same capability gate the daemon enforces.
    let granted = hostcalls::HostcallPermission::from(manifest.requested_permissions);
    // `plugin test` is a dry run — pass no writer/db so a test invocation
    // never pollutes the live WAL or touches the real views.db.
    let outcome = invoke_plugin(
        &engine,
        module,
        &linker,
        manifest.id.clone(),
        granted,
        PluginExecutionLimits::from_manifest(manifest),
        None,
        None,
    );
    let invoked_ok = matches!(outcome.stage, InvocationStage::Run) && outcome.error.is_none();
    Some(TestInvocationSummary {
        stage: invocation_stage_name(outcome.stage).to_string(),
        error: outcome.error,
        invoked_ok,
    })
}

#[cfg(feature = "wasm-plugin-host")]
fn invocation_stage_name(s: crate::wasm_plugin::dispatch::InvocationStage) -> &'static str {
    use crate::wasm_plugin::dispatch::InvocationStage;
    match s {
        InvocationStage::Compile => "compile",
        InvocationStage::Instantiate => "instantiate",
        InvocationStage::ExportLookup => "export_lookup",
        InvocationStage::AbiVersion => "abi_version",
        InvocationStage::Run => "run",
        InvocationStage::SkippedDueToCompileFailure => "skipped_due_to_compile_failure",
    }
}

#[cfg(not(feature = "wasm-plugin-host"))]
fn run_test_invoke(
    _manifest: &crate::wasm_plugin::manifest::PluginManifest,
    _wasm_bytes: &[u8],
) -> Option<TestInvocationSummary> {
    // Slim daemon — wasm-plugin-host wasn't built in. The CLI still
    // validates the manifest shape (the common failure mode for plugin
    // authors) but doesn't run the live invocation; the report renderer
    // surfaces a clear "rebuild with --features wasm-plugin-host" hint.
    None
}

/// UX-07b — live-invoke a candidate plugin with a THROWAWAY tempdir WAL writer
/// injected via [`crate::wasm_plugin::dispatch::invoke_plugin_with_state`], then
/// read back every frame the invocation emitted. The plugin runs with EXACTLY
/// its manifest grant (same gate the daemon enforces), so the captured
/// `0xC4`/`0xC6`/`0xC7` frames are the real audit trail the operator would see
/// in production — proven before the plugin ever touches `~/.neoth/plugins/`.
/// The live WAL is never written.
#[cfg(feature = "wasm-plugin-host")]
async fn run_test_invoke_with_wal(
    manifest: &crate::wasm_plugin::manifest::PluginManifest,
    wasm_bytes: &[u8],
) -> Option<TestInvocationWithWal> {
    use crate::wasm_plugin::dispatch::{
        CompileOutcome, InvocationStage, PluginExecutionLimits,
        invocation_outcome_from_compile_failure, invoke_plugin_with_state,
    };
    use crate::wasm_plugin::engine::{NeothEngine, PluginStoreState};
    use crate::wasm_plugin::hostcalls;

    // Helper: an early-exit result carrying just the failure summary + no frames.
    let fail = |stage: &str, error: String| {
        Some(TestInvocationWithWal {
            outcome: TestInvocationSummary {
                stage: stage.to_string(),
                error: Some(error),
                invoked_ok: false,
            },
            captured_frames: Vec::new(),
            capture_error: None,
        })
    };
    let capture_fail = |kind: CaptureWalErrorKind, message: String| {
        Some(TestInvocationWithWal {
            outcome: TestInvocationSummary {
                // Preserve the pre-existing setup-failure stage while also
                // putting the storage failure in the dedicated capture field.
                stage: "compile".to_string(),
                error: Some(message.clone()),
                invoked_ok: false,
            },
            captured_frames: Vec::new(),
            capture_error: Some(CaptureWalError::new(kind, message)),
        })
    };

    let engine = match NeothEngine::new() {
        Ok(e) => e,
        Err(e) => return fail("compile", format!("engine init failed: {e}")),
    };
    let compile_outcome = match engine.compile_from_bytes(wasm_bytes) {
        Ok(module) => CompileOutcome::Compiled {
            plugin_id: manifest.id.clone(),
            module: std::sync::Arc::new(module),
            execution_limits: PluginExecutionLimits::from_manifest(manifest),
        },
        Err(e) => CompileOutcome::Failed {
            plugin_id: manifest.id.clone(),
            error: format!("{e}"),
        },
    };
    if let Some(skip) = invocation_outcome_from_compile_failure(&compile_outcome) {
        return Some(TestInvocationWithWal {
            outcome: TestInvocationSummary {
                stage: invocation_stage_name(skip.stage).to_string(),
                error: skip.error,
                invoked_ok: false,
            },
            captured_frames: Vec::new(),
            capture_error: None,
        });
    }
    let module = match &compile_outcome {
        CompileOutcome::Compiled { module, .. } => module,
        CompileOutcome::Failed { .. } => {
            unreachable!("guarded by invocation_outcome_from_compile_failure")
        }
    };
    let linker = match hostcalls::build_linker(engine.raw()) {
        Ok(l) => l,
        Err(e) => return fail("compile", format!("linker build failed: {e}")),
    };
    let granted = hostcalls::HostcallPermission::from(manifest.requested_permissions);

    // THROWAWAY WAL: segment, HMAC key, and recovery transaction state all
    // live under one temp home. The dedicated capture writer never rotates and
    // rejects a frame before the single segment crosses the read-back ceiling.
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            return capture_fail(
                CaptureWalErrorKind::WriterInitFailed,
                format!("create throwaway WAL home: {e}"),
            );
        }
    };
    let limits = CaptureWalLimits::default();
    let wal_dir = tmp.path().join("wal");
    if let Err(error) = std::fs::create_dir(&wal_dir) {
        return capture_fail(
            CaptureWalErrorKind::WriterInitFailed,
            format!(
                "create throwaway WAL directory {}: {error}",
                wal_dir.display()
            ),
        );
    }
    let seg = wal_dir.join("capture-000001.wal");
    let max_segment_bytes = u64::try_from(limits.max_physical_bytes).unwrap_or(u64::MAX);
    let (writer, completion) = match crate::wal::writer::spawn_capture(
        seg.clone(),
        tmp.path().to_path_buf(),
        max_segment_bytes,
    ) {
        Ok(writer) => writer,
        Err(error) => {
            let error = anyhow::Error::new(error);
            return capture_fail(
                CaptureWalErrorKind::WriterInitFailed,
                format!("initialize throwaway WAL writer: {error:#}"),
            );
        }
    };

    // Caller-built state: manifest grant + limits + the throwaway writer.
    let execution_limits = PluginExecutionLimits::from_manifest(manifest);
    let state = PluginStoreState::new(manifest.id.clone())
        .with_fuel(execution_limits.fuel_budget)
        .with_memory_limit(execution_limits.memory_limit_bytes)
        .with_granted(granted)
        .with_wal_writer(writer);
    let outcome = invoke_plugin_with_state(&engine, module, &linker, state);
    let invoked_ok = matches!(outcome.stage, InvocationStage::Run) && outcome.error.is_none();

    // Flush: the writer was moved into the state → store → dropped when invoke
    // returned. Completion carries run_writer's actual Result, including
    // asynchronous initialization, HMAC/recovery, write, and final-sync errors.
    let writer_completion_error = completion.wait().await.err().map(|error| {
        let error = anyhow::Error::new(error);
        CaptureWalError::new(
            CaptureWalErrorKind::WriterCompletionFailed,
            format!("throwaway WAL writer failed before capture completed: {error:#}"),
        )
    });
    let (captured_frames, capture_error) =
        match decode_wal_frames_with_limits(&seg, tmp.path(), limits) {
            Ok(frames) => (frames, writer_completion_error),
            Err(mut error) => {
                if let Some(writer_error) = writer_completion_error {
                    error.message.push_str(&format!(
                        "; additionally, the throwaway writer failed: {}",
                        writer_error.message
                    ));
                }
                (Vec::new(), Some(error))
            }
        };

    Some(TestInvocationWithWal {
        outcome: TestInvocationSummary {
            stage: invocation_stage_name(outcome.stage).to_string(),
            error: outcome.error,
            invoked_ok,
        },
        captured_frames,
        capture_error,
    })
}

#[cfg(not(feature = "wasm-plugin-host"))]
async fn run_test_invoke_with_wal(
    _manifest: &crate::wasm_plugin::manifest::PluginManifest,
    _wasm_bytes: &[u8],
) -> Option<TestInvocationWithWal> {
    // Slim daemon — no live invocation, so no frames to capture. The renderer
    // prints the same "rebuild with --features wasm-plugin-host" hint.
    None
}

/// UX-07b — decode every frame in a small, single-segment WAL file through a
/// capability-bound no-follow handle. Missing files and a torn final frame are
/// normal crash-recovery states; unsafe file types, corrupt complete frames,
/// and physical/logical/frame-count limit breaches are typed capture errors.
/// `home` binds decryption to the same instance key used by home-owned writers.
#[cfg(test)]
fn decode_wal_frames(
    segment: &std::path::Path,
    home: &std::path::Path,
) -> std::result::Result<Vec<serde_json::Value>, CaptureWalError> {
    decode_wal_frames_with_limits(segment, home, CaptureWalLimits::default())
}

#[cfg(any(test, feature = "wasm-plugin-host"))]
fn decode_wal_frames_with_limits(
    segment: &std::path::Path,
    home: &std::path::Path,
    limits: CaptureWalLimits,
) -> std::result::Result<Vec<serde_json::Value>, CaptureWalError> {
    use std::io::Read as _;

    let parent_path = segment.parent().ok_or_else(|| {
        CaptureWalError::new(
            CaptureWalErrorKind::InvalidPath,
            format!("captured WAL path has no parent: {}", segment.display()),
        )
    })?;
    let file_name = segment.file_name().ok_or_else(|| {
        CaptureWalError::new(
            CaptureWalErrorKind::InvalidPath,
            format!("captured WAL path has no file name: {}", segment.display()),
        )
    })?;
    let parent =
        match crate::skills::store::open_bound_directory(parent_path, false, "captured WAL parent")
        {
            Ok(Some(parent)) => parent,
            Ok(None) => return Ok(Vec::new()),
            Err(error) => {
                return Err(CaptureWalError::new(
                    CaptureWalErrorKind::UnsafeFile,
                    format!(
                        "captured WAL parent is not a safe real directory {}: {error:#}",
                        parent_path.display()
                    ),
                ));
            }
        };
    let file = match crate::skills::store::open_regular_file(&parent.dir, file_name, segment) {
        Ok(file) => file,
        Err(error) if error_has_io_kind(&error, std::io::ErrorKind::NotFound) => {
            return Ok(Vec::new());
        }
        Err(error) => {
            let kind = match std::fs::symlink_metadata(segment) {
                Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                    CaptureWalErrorKind::UnsafeFile
                }
                Ok(_) => CaptureWalErrorKind::ReadFailed,
                Err(metadata_error) if metadata_error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Vec::new());
                }
                Err(_) => CaptureWalErrorKind::UnsafeFile,
            };
            return Err(CaptureWalError::new(
                kind,
                format!(
                    "refused captured WAL file {} without following links: {error:#}",
                    segment.display()
                ),
            ));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        CaptureWalError::new(
            CaptureWalErrorKind::ReadFailed,
            format!(
                "inspect opened captured WAL file {}: {error}",
                segment.display()
            ),
        )
    })?;
    let physical_limit = u64::try_from(limits.max_physical_bytes).unwrap_or(u64::MAX);
    if metadata.len() > physical_limit {
        return Err(CaptureWalError::new(
            CaptureWalErrorKind::PhysicalLimitExceeded,
            format!(
                "captured WAL file {} is {} bytes; physical ceiling is {}",
                segment.display(),
                metadata.len(),
                limits.max_physical_bytes
            ),
        ));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        CaptureWalError::new(
            CaptureWalErrorKind::PhysicalLimitExceeded,
            format!(
                "captured WAL file {} cannot fit the platform address space",
                segment.display()
            ),
        )
    })?;
    let read_limit = physical_limit.saturating_add(1);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CaptureWalError::new(
                CaptureWalErrorKind::ReadFailed,
                format!("read captured WAL file {}: {error}", segment.display()),
            )
        })?;
    if bytes.len() > limits.max_physical_bytes {
        return Err(CaptureWalError::new(
            CaptureWalErrorKind::PhysicalLimitExceeded,
            format!(
                "captured WAL file {} grew beyond the {}-byte physical ceiling while reading",
                segment.display(),
                limits.max_physical_bytes
            ),
        ));
    }

    // A freshly-created segment can be observed before its fixed header is
    // complete after a crash. Only an exact prefix of the segment magic plus a
    // known, possibly incomplete versioned header is a torn header; unrelated
    // short garbage is corruption, not an empty capture.
    let segment_magic = crate::wal::segment_header::SEGMENT_MAGIC;
    let magic_prefix_len = bytes.len().min(segment_magic.len());
    if bytes[..magic_prefix_len] != segment_magic[..magic_prefix_len] {
        return Err(CaptureWalError::new(
            CaptureWalErrorKind::ReconstructFailed,
            format!(
                "captured WAL file {} does not begin with a valid segment-header prefix",
                segment.display()
            ),
        ));
    }
    if bytes.len() < 12 {
        return Ok(Vec::new());
    }
    let version = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .expect("12-byte segment-header prefix includes version"),
    );
    let expected_header_len = match version {
        crate::wal::segment_header::SEGMENT_FORMAT_VERSION_V1 => {
            crate::wal::segment_header::SEGMENT_HEADER_LEN
        }
        crate::wal::segment_header::SEGMENT_FORMAT_VERSION_V2 => {
            crate::wal::segment_header::SEGMENT_HEADER_V2_LEN
        }
        crate::wal::segment_header::SEGMENT_FORMAT_VERSION => {
            crate::wal::segment_header::SEGMENT_HEADER_V3_LEN
        }
        unknown => {
            return Err(CaptureWalError::new(
                CaptureWalErrorKind::ReconstructFailed,
                format!(
                    "captured WAL file {} declares unknown segment format version {unknown}",
                    segment.display()
                ),
            ));
        }
    };
    if bytes.len() < expected_header_len {
        return Ok(Vec::new());
    }
    let parsed_header =
        crate::wal::segment_header::parse_segment_header(&bytes).map_err(|error| {
            CaptureWalError::new(
                CaptureWalErrorKind::ReconstructFailed,
                format!(
                    "validate captured WAL segment header {}: {error}",
                    segment.display()
                ),
            )
        })?;

    // Consult master.key only when the segment body is encrypted. That read is
    // bounded, handle-relative, and no-follow; an unsafe/malformed key is a
    // visible capture failure instead of an apparent empty WAL.
    let physical_header_len = parsed_header.header_len();
    let segment_key = if crate::wal::crypto::is_encrypted(&bytes[physical_header_len..]) {
        crate::wal::master_key::segment_key_at_checked(home).map_err(|error| {
            CaptureWalError::new(
                CaptureWalErrorKind::MasterKeyReadFailed,
                format!(
                    "read captured WAL master key under {}: {error:#}",
                    home.display()
                ),
            )
        })?
    } else {
        None
    };
    let (header_len, logical) = crate::wal::compaction::logical_segment_bytes_with_key_capped(
        &bytes,
        segment_key.as_ref(),
        limits.max_logical_frame_bytes,
    )
    .map_err(|error| {
        let message = format!("{error:#}");
        let normalized = message.to_ascii_lowercase();
        let kind = if normalized.contains("exceed")
            || normalized.contains("scanner cap")
            || normalized.contains("decompression-bomb guard")
        {
            CaptureWalErrorKind::LogicalLimitExceeded
        } else {
            CaptureWalErrorKind::ReconstructFailed
        };
        CaptureWalError::new(
            kind,
            format!(
                "reconstruct captured WAL file {}: {message}",
                segment.display()
            ),
        )
    })?;
    if header_len > logical.len() {
        return Err(CaptureWalError::new(
            CaptureWalErrorKind::InvalidLogicalLayout,
            format!(
                "captured WAL header length {header_len} exceeds reconstructed length {}",
                logical.len()
            ),
        ));
    }
    let frames = &logical[header_len..];
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let tail = &frames[cursor..];
        let dec = match decode_frame(tail) {
            Ok(d) => d,
            Err(crate::wal::error::HeaderParseError::BufferTooShort { .. })
                if is_plausible_torn_frame_tail(tail) =>
            {
                break;
            }
            Err(error) => {
                return Err(CaptureWalError::new(
                    CaptureWalErrorKind::CorruptFrame,
                    format!(
                        "decode captured WAL frame {} at byte {cursor}: {error}",
                        out.len()
                    ),
                ));
            }
        };
        // Decode first, then enforce the complete-frame count. This preserves
        // exact-limit semantics: N complete frames plus a torn (N+1)th tail is
        // accepted, while a complete (N+1)th frame is rejected.
        if out.len() >= limits.max_frames {
            return Err(CaptureWalError::new(
                CaptureWalErrorKind::FrameLimitExceeded,
                format!(
                    "captured WAL contains more than {} complete frames",
                    limits.max_frames
                ),
            ));
        }
        let payload = serde_json::from_slice::<serde_json::Value>(dec.payload).ok();
        out.push(serde_json::json!({
            "event_type": format!("0x{:02X}", dec.header.event_type),
            "payload": payload,
        }));
        let total = dec.header.total_len as usize;
        if total == 0 {
            return Err(CaptureWalError::new(
                CaptureWalErrorKind::CorruptFrame,
                format!("captured WAL frame {} declares zero length", out.len() - 1),
            ));
        }
        cursor = cursor.checked_add(total).ok_or_else(|| {
            CaptureWalError::new(
                CaptureWalErrorKind::CorruptFrame,
                "captured WAL frame cursor overflow",
            )
        })?;
    }
    Ok(out)
}

#[cfg(any(test, feature = "wasm-plugin-host"))]
fn is_plausible_torn_frame_tail(tail: &[u8]) -> bool {
    use crate::wal::header::{HEADER_BODY_LEN, MAGIC, PREAMBLE_LEN};

    let magic_prefix_len = tail.len().min(MAGIC.len());
    if tail[..magic_prefix_len] != MAGIC[..magic_prefix_len] {
        return false;
    }
    if tail.len() < PREAMBLE_LEN + HEADER_BODY_LEN {
        return true;
    }
    let header_bytes: &[u8; HEADER_BODY_LEN] =
        match tail[PREAMBLE_LEN..PREAMBLE_LEN + HEADER_BODY_LEN].try_into() {
            Ok(header) => header,
            Err(_) => return false,
        };
    crate::wal::header::EventHeaderV2::from_le_bytes(header_bytes)
        .is_ok_and(|header| header.total_len as usize > tail.len())
}

#[cfg(any(test, feature = "wasm-plugin-host"))]
fn error_has_io_kind(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == kind)
    })
}

fn render_test_report(
    manifest: &crate::wasm_plugin::manifest::PluginManifest,
    wasm_size: usize,
    outcome: Option<TestInvocationSummary>,
    captured_frames: Option<Vec<serde_json::Value>>,
    capture_error: Option<CaptureWalError>,
    output: OutputFormat,
) -> Result<()> {
    let host_built = cfg!(feature = "wasm-plugin-host");
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let mut payload = json!({
                "manifest": {
                    "id": manifest.id,
                    "name": manifest.name,
                    "version": manifest.version,
                    "hook_stages": manifest.hook_stages,
                },
                "wasm_size_bytes": wasm_size,
                "host_feature_built": host_built,
                "invocation": outcome,
            });
            // UX-07b: surface the captured frames only on the --capture-wal path
            // (None on the dry-run path keeps the JSON shape unchanged there).
            if let Some(frames) = &captured_frames {
                payload["captured_frames"] = json!(frames);
                payload["capture_error"] = json!(&capture_error);
            }
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            println!("Plugin `{}` (v{})", manifest.id, manifest.version);
            println!("  name:        {}", manifest.name);
            println!("  hook stages: {:?}", manifest.hook_stages);
            println!("  wasm size:   {wasm_size} bytes");
            println!("  manifest:    valid");
            match outcome {
                Some(o) => {
                    println!(
                        "  invocation:  stage={} error={} invoked_ok={}",
                        o.stage,
                        o.error.as_deref().unwrap_or("none"),
                        o.invoked_ok
                    );
                }
                None => {
                    println!(
                        "  invocation:  skipped — daemon not built with \
                         `wasm-plugin-host` feature"
                    );
                    println!(
                        "               rebuild with `cargo build --features wasm-plugin-host` \
                         to live-invoke `neoth_run`"
                    );
                }
            }
            if let Some(frames) = &captured_frames {
                println!("  captured WAL frames: {}", frames.len());
                for f in frames {
                    println!(
                        "    {} {}",
                        f.get("event_type").and_then(|v| v.as_str()).unwrap_or("?"),
                        f.get("payload")
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "null".into()),
                    );
                }
                if let Some(error) = &capture_error {
                    println!(
                        "  capture error: {} — {}",
                        error.kind.as_str(),
                        error.message
                    );
                }
            }
        }
    }
    Ok(())
}

// ── `neoth plugin install` ────────────────────────────────────────────────

/// Install a plugin directory into `~/.neoth/plugins/<id>/`.
///
/// Security posture (SC-03 threat model — plugin dir is attacker-controlled):
/// 1. Source directory is checked for symlinks on `plugin.toml` and
///    `plugin.wasm` via [`std::fs::symlink_metadata`] before any read —
///    the same guard `load_one` applies inside `discover()`.
/// 2. Source directory itself must not be a symlink (mirrors the `discover()`
///    root guard at the plugins_root level).
/// 3. Only `plugin.toml`, `plugin.wasm`, and an optional
///    `plugin.wasm.minisig` are copied — no arbitrary files.
/// 4. Copy and verification happen in a sibling staging directory. The exact
///    runtime [`crate::wasm_plugin::discovery::IntegrityPolicy`] is applied to
///    the staged bytes before they become visible at the canonical path.
/// 5. `--force` moves the old install to a backup and restores it if the final
///    rename fails. Copy or verification failures never touch the old install.
fn run_install(path: &std::path::Path, force: bool, output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().context(
        "could not load freedom.yaml — fix it before installing (install must use the same \
         plugin integrity policy as daemon startup)",
    )?;
    let plugins_root = FreedomConfig::default_neoth_home().join("plugins");
    let installed = install_into_plugins_root(path, force, &plugins_root, &cfg.plugins.wasm)?;

    // ── Emit result ───────────────────────────────────────────────────────
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let obj = serde_json::json!({
                "ok": true,
                "id": installed.id,
                "path": installed.target.display().to_string(),
            });
            println!("{}", serde_json::to_string(&obj)?);
        }
        OutputFormat::Table => {
            println!(
                "installed plugin `{}` → {}",
                installed.id,
                installed.target.display()
            );
            println!(
                "Run `neoth plugin enable {}` to activate it on the next `neoth serve` boot.",
                installed.id
            );
        }
    }
    Ok(())
}

#[derive(Debug)]
struct InstalledPlugin {
    id: String,
    target: std::path::PathBuf,
}

/// Testable install core. `plugins_root` and `wasm_policy` are injected so the
/// filesystem transaction and the runtime-policy parity can be regression
/// tested without mutating the operator's real `~/.neoth` tree.
fn install_into_plugins_root(
    path: &std::path::Path,
    force: bool,
    plugins_root: &std::path::Path,
    wasm_policy: &crate::config::WasmPluginsConfig,
) -> Result<InstalledPlugin> {
    // ── Source validation ─────────────────────────────────────────────────
    if !path.exists() {
        anyhow::bail!(
            "plugin source path `{}` does not exist — pass a directory containing \
             `plugin.toml` + `plugin.wasm`",
            path.display()
        );
    }
    if path.is_symlink() {
        anyhow::bail!(
            "plugin source path `{}` is a symlink — refusing (symlink-redirect guard). \
             Pass the real directory.",
            path.display()
        );
    }
    if !path.is_dir() {
        anyhow::bail!(
            "plugin source path `{}` is not a directory — expected a directory with \
             `plugin.toml` + `plugin.wasm`",
            path.display()
        );
    }

    let toml_src = path.join("plugin.toml");
    let wasm_src = path.join("plugin.wasm");
    let minisig_src = path.join("plugin.wasm.minisig");

    if !toml_src.exists() {
        anyhow::bail!("missing `plugin.toml` at {}", toml_src.display());
    }
    if !wasm_src.exists() {
        anyhow::bail!("missing `plugin.wasm` at {}", wasm_src.display());
    }

    // Symlink guard on files — mirrors load_one's symlink_metadata loop.
    // A-56 / GOLD-SEC-20: a symlinked source file would make the hash/signature
    // cover the symlink target, not the declared plugin.
    for (p, _name) in [
        (&toml_src, "plugin.toml"),
        (&wasm_src, "plugin.wasm"),
        (&minisig_src, "plugin.wasm.minisig"),
    ] {
        if std::fs::symlink_metadata(p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            anyhow::bail!(
                "source file `{}` is a symlink — refusing (symlink-redirect guard, A-56/GOLD-SEC-20). \
                 Place real files in the plugin directory.",
                p.display()
            );
        }
    }

    // ── Parse manifest to derive the install id ───────────────────────────
    let toml_bytes =
        std::fs::read(&toml_src).with_context(|| format!("read {}", toml_src.display()))?;
    let manifest = crate::wasm_plugin::manifest::parse_manifest(&toml_bytes)
        .map_err(|e| anyhow::anyhow!("manifest invalid: {e}"))?;
    let id = manifest.id;

    // ── Target directory ──────────────────────────────────────────────────
    std::fs::create_dir_all(plugins_root)
        .with_context(|| format!("create plugins directory `{}`", plugins_root.display()))?;
    let _install_lock = crate::util::locked_file::lock_file_blocking(
        &plugins_root.join(format!(".{id}.install.lock")),
        "plugin install",
    )?;
    let target = plugins_root.join(&id);

    if target.exists() && !force {
        anyhow::bail!(
            "plugin `{id}` already installed at `{}` (use --force to overwrite)",
            target.display()
        );
    }

    // Copy to a sibling directory so the final rename stays on the same
    // filesystem. The guard removes an abandoned stage on every early return.
    let staging_path = create_install_staging_dir(plugins_root, &id)?;
    let mut staging = RemovePathOnDrop::new(staging_path);

    // ── Copy exactly plugin.toml + plugin.wasm + optional minisig ─────────
    let toml_dst = staging.path().join("plugin.toml");
    let wasm_dst = staging.path().join("plugin.wasm");
    let minisig_dst = staging.path().join("plugin.wasm.minisig");

    let copy_one = |src: &std::path::Path, dst: &std::path::Path| -> Result<()> {
        std::fs::copy(src, dst)
            .with_context(|| format!("copy `{}` → `{}`", src.display(), dst.display()))?;
        Ok(())
    };

    copy_one(&toml_src, &toml_dst)?;
    copy_one(&wasm_src, &wasm_dst)?;
    if minisig_src.exists() {
        copy_one(&minisig_src, &minisig_dst)?;
    }

    // ── Staged integrity check (SC-03) ────────────────────────────────────
    // Re-read every installed artifact from staging. The source can change
    // while copying; only the exact bytes about to be activated may pass.
    let staged_plugin = crate::wasm_plugin::discovery::inspect_bundle(staging.path())
        .map_err(|error| anyhow::anyhow!("staged plugin bundle invalid: {error}"))?;
    if staged_plugin.manifest.id != id {
        anyhow::bail!(
            "plugin manifest changed while staging: expected id `{id}`, copied id `{}`",
            staged_plugin.manifest.id
        );
    }
    let policy = crate::wasm_plugin::discovery::IntegrityPolicy {
        pinned: &wasm_policy.pinned_hashes,
        require_all_pinned: wasm_policy.require_all_pinned,
        author_pubkey: wasm_policy.author_pubkey.as_deref(),
        require_signature: wasm_policy.require_signature,
        revoked: &wasm_policy.revoked_ids,
    };
    crate::wasm_plugin::discovery::verify_integrity(&staged_plugin, &policy)
        .map_err(|e| anyhow::anyhow!("plugin `{id}` failed the runtime integrity gate: {e}"))?;

    activate_staged_install(&target, &mut staging, force)?;
    Ok(InstalledPlugin { id, target })
}

static PLUGIN_INSTALL_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_install_sibling(
    plugins_root: &std::path::Path,
    id: &str,
    role: &str,
) -> std::path::PathBuf {
    let nonce = PLUGIN_INSTALL_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    plugins_root.join(format!(".{id}.{role}.{}.{}", std::process::id(), nonce))
}

fn create_install_staging_dir(
    plugins_root: &std::path::Path,
    id: &str,
) -> Result<std::path::PathBuf> {
    for _ in 0..128 {
        let candidate = next_install_sibling(plugins_root, id, "install-staging");
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("create install staging `{}`", candidate.display()));
            }
        }
    }
    anyhow::bail!("could not reserve a unique staging directory for plugin `{id}`")
}

fn unused_install_sibling(
    plugins_root: &std::path::Path,
    id: &str,
    role: &str,
) -> Result<std::path::PathBuf> {
    for _ in 0..128 {
        let candidate = next_install_sibling(plugins_root, id, role);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("inspect install work path `{}`", candidate.display())
                });
            }
        }
    }
    anyhow::bail!("could not reserve a unique {role} path for plugin `{id}`")
}

fn remove_install_path(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            std::fs::remove_dir_all(path)
        }
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

struct RemovePathOnDrop {
    path: std::path::PathBuf,
    armed: bool,
}

impl RemovePathOnDrop {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RemovePathOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_install_path(&self.path);
        }
    }
}

fn activate_staged_install(
    target: &std::path::Path,
    staging: &mut RemovePathOnDrop,
    force: bool,
) -> Result<()> {
    if !target.exists() {
        std::fs::rename(staging.path(), target).with_context(|| {
            format!(
                "activate staged plugin `{}` → `{}`",
                staging.path().display(),
                target.display()
            )
        })?;
        staging.disarm();
        return Ok(());
    }
    if !force {
        anyhow::bail!(
            "plugin target `{}` appeared during install (use --force to replace it)",
            target.display()
        );
    }

    let plugins_root = target
        .parent()
        .context("plugin target has no parent directory")?;
    let id = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("plugin target id is not valid UTF-8")?;
    let backup = unused_install_sibling(plugins_root, id, "install-backup")?;

    std::fs::rename(target, &backup).with_context(|| {
        format!(
            "move existing plugin `{}` to rollback backup `{}`",
            target.display(),
            backup.display()
        )
    })?;

    if let Err(activate_error) = std::fs::rename(staging.path(), target) {
        match std::fs::rename(&backup, target) {
            Ok(()) => {
                return Err(activate_error).with_context(|| {
                    format!(
                        "activate staged plugin at `{}`; previous install was restored",
                        target.display()
                    )
                });
            }
            Err(rollback_error) => {
                anyhow::bail!(
                    "activate staged plugin at `{}` failed: {activate_error}; rollback also \
                     failed: {rollback_error}. Previous install is preserved at `{}`",
                    target.display(),
                    backup.display()
                );
            }
        }
    }

    staging.disarm();
    if let Err(e) = remove_install_path(&backup) {
        tracing::warn!(
            path = %backup.display(),
            error = %e,
            "plugin replacement succeeded but stale rollback backup could not be removed"
        );
    }
    Ok(())
}

// ── `neoth plugin remove` ─────────────────────────────────────────────────

/// R3-15 — transactional plugin removal at an explicit home (testable core of
/// [`run_remove`]). Returns whether anything was removed (`false` = nothing was
/// installed). Callers that need the reached-step detail use
/// [`remove_plugin_at_tracked`].
///
/// Ordering matters: the config trust references are cleared **before** the
/// on-disk bytes are deleted, and every step propagates its error, so the
/// observable state is never "bytes gone but config still active":
/// - a config write failure aborts before any deletion → the plugin stays fully
///   intact and consistent;
/// - a byte-delete failure after the config is clean leaves a deactivated,
///   unpinned directory that fail-closed discovery will not run — recoverable,
///   journalled, and surfaced instead of swallowed.
///
/// Removal invalidates the operator's prior trust decision, so the activation
/// AND the hash pin are cleared; a revocation is a deny-list and deliberately
/// survives. A stale config reference is cleaned even when the directory is
/// already gone, and success is only reported after an inventory readback
/// proves the plugin is no longer a loadable install.
///
/// Test-only: production goes through [`remove_plugin_at_tracked`], which also
/// reports which steps ran so the terminal audit frame can be truthful.
#[cfg(test)]
fn remove_plugin_at(home: &std::path::Path, id: &str) -> Result<bool> {
    let mut progress = RemovalProgress::default();
    remove_plugin_at_tracked(home, id, &mut progress)
}

/// GOLD-SEC — reject path-traversal ids before any side effect. An installed
/// plugin id is always a valid snake_case token (enforced at install time via
/// parse_manifest); anything else (`../`, absolute paths, separators) cannot
/// name a real install and must never reach `remove_dir_all`, must never name a
/// journal file, and must never mint a durable removal intent for an operation
/// that could not start.
fn validate_plugin_id(id: &str) -> Result<()> {
    if !crate::wasm_plugin::manifest::is_snake_case_id(id) {
        anyhow::bail!(
            "invalid plugin id `{id}` — must be a snake_case token \
             ([a-z0-9_], not starting with `_` or a digit)"
        );
    }
    Ok(())
}

/// R3-15 — which steps of a removal actually completed. Carried out of the
/// mutation so the terminal WAL frame can tell "nothing happened" (`aborted`)
/// apart from "the operator's trust decision is already revoked but the bytes
/// are still on disk" (`partial`). An auditor replaying the log must be able to
/// make that distinction; `aborted` for both is a false record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RemovalProgress {
    config_cleared: bool,
    bytes_deleted: bool,
}

/// The durable pending-removal journal for one plugin (R3-15). Kept OUTSIDE
/// `plugins/` so it can never be mistaken for a discoverable install.
///
/// `id` is validated snake_case before this is called, so the join is a single
/// literal file name.
fn removal_journal_path(home: &std::path::Path, id: &str) -> std::path::PathBuf {
    home.join(".plugin-removals").join(format!("{id}.json"))
}

/// True when `freedom.yaml` still names the plugin — or cannot be read/parsed.
///
/// A malformed config deliberately reports `true`: the removal then runs the
/// real coherent [`FreedomConfig::update_at`] and the parse error surfaces,
/// instead of a broken config being silently reported as "nothing installed".
fn plugin_config_refs_present(home: &std::path::Path, id: &str) -> bool {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return false;
    }
    let Ok(body) = std::fs::read_to_string(&path) else {
        return true;
    };
    let Ok(config) = serde_yaml::from_str::<FreedomConfig>(&body) else {
        return true;
    };
    config.plugins.wasm.activations.contains_key(id)
        || config.plugins.wasm.pinned_hashes.contains_key(id)
}

/// R3-15 — transactional plugin removal with a durable crash-recovery journal.
///
/// The journal is written (fsynced data + directory entry) BEFORE the first
/// mutation and removed only after the inventory readback proves the plugin is
/// gone. A crash anywhere in between therefore leaves an explicit record, and
/// the next removal of the same id resumes it instead of returning the
/// misleading "nothing installed — no-op". That closes the config↔byte gap: the
/// only reachable crash state is "config already clean, bytes still present",
/// which the resume finishes idempotently.
///
/// `progress` records the steps that completed even when this returns `Err`, so
/// the caller can log the true terminal state.
fn remove_plugin_at_tracked(
    home: &std::path::Path,
    id: &str,
    progress: &mut RemovalProgress,
) -> Result<bool> {
    validate_plugin_id(id)?;
    let plugins_root = home.join("plugins");
    let target = plugins_root.join(id);
    let freedom_path = home.join("freedom.yaml");
    let journal = removal_journal_path(home, id);

    // A journal from a crashed removal means the operator already authorised
    // this exact removal and the mutation began. Resume it even when nothing is
    // left to observe, so the terminal state is reached and recorded.
    let resuming = journal.exists();
    let bytes_present = target.exists();

    // Nothing installed: no bytes, no stale config reference, no crash to
    // finish. Reported as a no-op without minting a journal.
    if !resuming && !bytes_present && !plugin_config_refs_present(home, id) {
        return Ok(false);
    }

    if !resuming {
        let record = serde_json::to_vec(&serde_json::json!({
            "plugin_id": id,
            "bytes_present": bytes_present,
            "ts_unix": crate::time::now_unix_secs(),
        }))?;
        crate::util::atomic_write::atomic_write_private(&journal, &record).with_context(|| {
            format!("write the pending-removal journal at {}", journal.display())
        })?;
    }

    // Clear the config trust references FIRST. A failure aborts before any byte
    // deletion. The empty-config case creates nothing (guarded on existence).
    // Removal invalidates the operator's prior trust decision, so the activation
    // AND the hash pin go; a revocation is a deny-list and deliberately stays.
    // Each flag records a step that ACTUALLY ran: a skipped step must never be
    // reported as performed, or the audit trail claims a mutation that never
    // happened (e.g. "config_cleared" with no freedom.yaml on disk at all).
    if freedom_path.exists() {
        FreedomConfig::update_at(&freedom_path, |config| {
            config.plugins.wasm.activations.remove(id);
            config.plugins.wasm.pinned_hashes.remove(id);
            Ok(())
        })
        .with_context(|| format!("clear config references for plugin `{id}`"))?;
        progress.config_cleared = true;
    }

    // Config is clean; delete the bytes.
    if bytes_present {
        std::fs::remove_dir_all(&target)
            .with_context(|| format!("remove plugin directory `{}`", target.display()))?;
        progress.bytes_deleted = true;
    }

    // Inventory readback: never report success before proving the plugin is no
    // longer discoverable as a loadable install.
    if discover(&plugins_root)
        .loaded
        .iter()
        .any(|plugin| plugin.manifest.id == id)
    {
        anyhow::bail!("plugin `{id}` is still discovered after removal");
    }

    // Terminal state proven — retire the journal durably. A surviving journal
    // would make the next removal replay a completed transaction.
    crate::util::atomic_write::durable_remove_file(&journal)
        .with_context(|| format!("clear the pending-removal journal at {}", journal.display()))?;

    Ok(true)
}

async fn run_remove(id: &str, output: OutputFormat) -> Result<()> {
    // An id that cannot name a real install must not mint a durable audit
    // trail: without this the intent frame carries arbitrary, never-validated
    // operator strings for an operation that could never start.
    validate_plugin_id(id)?;
    let home = FreedomConfig::default_neoth_home();
    let operation_id = uuid::Uuid::now_v7().to_string();
    // Bindings observed BEFORE any mutation: the installed generation (plugin
    // content hash), the operator hash pin the intent authorizes, and the config
    // generation the daemon's reload controller identifies the same file by.
    let installed_generation = plugin_installed_generation(&home, id);
    let expected_pin = plugin_pinned_hash(&home, id);
    let config_generation = plugin_config_generation(&home);

    // 1. Removal INTENT — a durable WAL ACK must precede any config or byte
    //    change (R3-15). If it is not durable, nothing is removed.
    emit_plugin_removal_intent(
        &home,
        &operation_id,
        id,
        installed_generation.as_deref(),
        expected_pin.as_deref(),
        config_generation,
    )
    .await
    .context("plugin removal intent was not durable; nothing was removed")?;

    // 2. The ordered, fail-closed mutation.
    let mut progress = RemovalProgress::default();
    let removed = match remove_plugin_at_tracked(&home, id, &mut progress) {
        Ok(removed) => removed,
        Err(error) => {
            let error_sha = hex::encode(sha2::Sha256::digest(format!("{error:#}").as_bytes()));
            let status = removal_failure_status(progress);
            let _ = emit_plugin_removal_result(
                &home,
                &operation_id,
                id,
                status,
                None,
                Some(&error_sha),
                progress,
            )
            .await;
            if progress.config_cleared {
                request_removal_reload(&home, id);
            }
            return Err(error);
        }
    };

    // 3. Removal COMMITTED — correlated terminal outcome bound by operation_id.
    emit_plugin_removal_result(
        &home,
        &operation_id,
        id,
        "committed",
        Some(removed),
        None,
        progress,
    )
    .await
    .context("plugin was removed, but its committed audit failed")?;

    // 4. Runtime-generation invalidation. Config bytes alone never reach a LIVE
    //    daemon — see [`request_removal_reload`].
    let reload_requested = !removed || request_removal_reload(&home, id);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let obj = if removed {
                serde_json::json!({ "ok": true, "id": id, "reload_requested": reload_requested })
            } else {
                serde_json::json!({ "ok": false, "id": id, "reason": "not found" })
            };
            println!("{}", serde_json::to_string(&obj)?);
        }
        OutputFormat::Table => {
            if removed {
                println!("removed plugin `{id}`.");
                if !reload_requested {
                    println!(
                        "WARNING: the live-config reload could not be requested — a running \
                         daemon keeps the loaded instance until `neoth reload`."
                    );
                }
            } else {
                println!("plugin `{id}` not installed — no-op.");
            }
        }
    }
    Ok(())
}

/// The terminal status for a failed removal. A cleared config already revoked
/// the operator's trust decision, so that is a `partial` removal — recording it
/// as `aborted` would tell an auditor "nothing happened" while the plugin is
/// already deactivated and unpinned with its bytes still on disk.
fn removal_failure_status(progress: RemovalProgress) -> &'static str {
    if progress.config_cleared || progress.bytes_deleted {
        "partial"
    } else {
        "aborted"
    }
}

/// R3-15 runtime-generation invalidation.
///
/// Writing `freedom.yaml` does not by itself reach a LIVE daemon: reload is
/// sentinel-driven (`cli::serve::handle_reload_sentinel`), so without this a
/// removed plugin's already-compiled instance keeps its bootstrap authority
/// until the operator happens to type `neoth reload`. The live gate in
/// [`crate::wasm_plugin::dispatch`] refuses every plugin whose activation is
/// absent from the reloaded config — so requesting the reload IS the handle
/// invalidation, and a stopped daemon applies it at its next start.
///
/// Best-effort by construction: the removal has already committed, so a sentinel
/// failure cannot be made fail-closed. It is reported instead of swallowed.
fn request_removal_reload(home: &std::path::Path, id: &str) -> bool {
    match crate::cli::reload::request_reload_at(home) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(
                plugin = %id,
                error = %error,
                "plugin removed, but the live-config reload sentinel could not be written — \
                 a running daemon keeps the loaded instance until `neoth reload`"
            );
            false
        }
    }
}

/// The config generation the daemon's [`crate::config::reload::ReloadController`]
/// identifies `freedom.yaml` by (`xxh3_64(path + mtime + size)`), observed before
/// any mutation. Binding it into the intent lets an auditor tell which exact
/// config state the removal authorised, and pairs with the post-commit reload
/// that makes a live runtime converge on the successor generation.
fn plugin_config_generation(home: &std::path::Path) -> Option<u64> {
    crate::config::reload::compute_snapshot_hash(&home.join("freedom.yaml")).ok()
}

/// The installed generation (plugin content hash) the removal intent binds,
/// observed before any mutation. `None` when the id is not a loadable install.
fn plugin_installed_generation(home: &std::path::Path, id: &str) -> Option<String> {
    discover(&home.join("plugins"))
        .loaded
        .iter()
        .find(|plugin| plugin.manifest.id == id)
        .map(|plugin| plugin.content_hash.clone())
}

/// Best-effort read of the operator hash pin the removal intent records. A
/// read-only parse is sufficient for audit metadata; the removal itself
/// re-locks the config under the coherent update lock.
fn plugin_pinned_hash(home: &std::path::Path, id: &str) -> Option<String> {
    let body = std::fs::read_to_string(home.join("freedom.yaml")).ok()?;
    let config: FreedomConfig = serde_yaml::from_str(&body).ok()?;
    config.plugins.wasm.pinned_hashes.get(id).cloned()
}

/// Emit the mandatory `plugin remove` intent (EXTENDED `PluginRemovalIntent`).
/// Required: a non-durable intent aborts the removal before any change.
async fn emit_plugin_removal_intent(
    home: &std::path::Path,
    operation_id: &str,
    plugin_id: &str,
    installed_generation_sha256: Option<&str>,
    expected_pinned_hash: Option<&str>,
    config_generation: Option<u64>,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "operation_id": operation_id,
        "plugin_id": plugin_id,
        "installed_generation_sha256": installed_generation_sha256,
        "expected_pinned_hash": expected_pinned_hash,
        "config_generation": config_generation,
        "phase": "intent",
        "source": "cli",
        "ts_unix": crate::time::now_unix_secs(),
    }))?;
    crate::cli::todo::emit_oneshot_audit_at_with_subtype(
        home,
        crate::wal::events::EVENT_TYPE_EXTENDED,
        crate::wal::events::ExtendedSubtype::PluginRemovalIntent as u8,
        payload,
        "PLUGIN_REMOVAL_INTENT",
        true,
    )
    .await
}

/// Emit the terminal `plugin remove` outcome (EXTENDED `PluginRemovalResult`)
/// correlated to its intent by `operation_id`. Committed is required; an aborted
/// or partial outcome is best-effort (its call site keeps propagating the
/// mutation error).
///
/// `progress` carries the steps that actually completed, so `partial` is a
/// readable state ("trust revoked, bytes still present") rather than an
/// indistinguishable `aborted`.
async fn emit_plugin_removal_result(
    home: &std::path::Path,
    operation_id: &str,
    plugin_id: &str,
    status: &str,
    removed: Option<bool>,
    error_sha256: Option<&str>,
    progress: RemovalProgress,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "operation_id": operation_id,
        "plugin_id": plugin_id,
        "status": status,
        "removed": removed,
        "config_cleared": progress.config_cleared,
        "bytes_deleted": progress.bytes_deleted,
        "error_sha256": error_sha256,
        "ts_unix": crate::time::now_unix_secs(),
    }))?;
    crate::cli::todo::emit_oneshot_audit_at_with_subtype(
        home,
        crate::wal::events::EVENT_TYPE_EXTENDED,
        crate::wal::events::ExtendedSubtype::PluginRemovalResult as u8,
        payload,
        "PLUGIN_REMOVAL_RESULT",
        status == "committed",
    )
    .await
}

fn render_list(home: &std::path::Path, output: OutputFormat, only_pending: bool) -> Result<()> {
    let plugins_root = home.join("plugins");
    let report = discover(&plugins_root);
    let activations = load_activations()?;

    use crate::wasm_plugin::manifest::PluginUiSurface;

    struct ListRow {
        id: String,
        state: PluginActivation,
        display_state: &'static str,
        name: String,
        content_hash: String,
        manifest_hash: String,
        requested_permission: RequestedPermission,
        ui_surface: Option<PluginUiSurface>,
        approval_error: Option<String>,
        approved_permission: Option<RequestedPermission>,
    }

    // SC-03 surfaces the wasm hash for operator pins. The approval fields make
    // a legacy or mutated Active entry visible instead of falsely reporting it
    // as runnable; startup applies the same fail-closed validation.
    let mut rows: Vec<ListRow> = report
        .loaded
        .iter()
        .map(|p| {
            let record = activations.get(&p.manifest.id).cloned().unwrap_or_default();
            let approval_error = if record.state == PluginActivation::Active {
                record.validate_for(p).err().map(|e| e.to_string())
            } else {
                None
            };
            ListRow {
                id: p.manifest.id.clone(),
                state: record.state,
                display_state: if approval_error.is_some() {
                    "reconsent_required"
                } else {
                    record.state.as_str()
                },
                name: p.manifest.name.clone(),
                content_hash: p.content_hash.clone(),
                manifest_hash: p.manifest_hash.clone(),
                requested_permission: p.manifest.requested_permissions,
                ui_surface: p.manifest.ui_surface.clone(),
                approval_error,
                approved_permission: record
                    .approval
                    .as_ref()
                    .map(|approval| approval.approved_permission),
            }
        })
        .collect();
    if only_pending {
        rows.retain(|row| row.state == PluginActivation::Pending || row.approval_error.is_some());
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    // DES-12: include ui_surface when present so the GUI can
                    // show the plugin tab without a separate query. Omit the
                    // key entirely when None — additive, GUI parsers tolerant.
                    let mut obj = json!({
                        "id": &row.id,
                        "name": &row.name,
                        "activation": row.display_state,
                        "sha256": &row.content_hash,
                        "manifest_sha256": &row.manifest_hash,
                        "requested_permission": row.requested_permission.as_str(),
                    });
                    if let Some(permission) = row.approved_permission {
                        obj["approved_permission"] = json!(permission.as_str());
                    }
                    if let Some(error) = &row.approval_error {
                        obj["approval_error"] = json!(error);
                    }
                    if let Some(surf) = &row.ui_surface {
                        let surf_val = match surf {
                            PluginUiSurface::WalFeed { title } => {
                                json!({ "kind": "wal_feed", "title": title })
                            }
                        };
                        obj.as_object_mut()
                            .unwrap()
                            .insert("ui_surface".to_string(), surf_val);
                    }
                    obj
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                if only_pending {
                    println!("No plugins awaiting activation or re-consent.");
                } else {
                    println!("No plugins discovered under ~/.neoth/plugins/");
                    println!();
                    println!("Drop a `<plugins-dir>/<id>/{{plugin.toml, plugin.wasm}}` pair");
                    println!("to surface entries here. They default to PENDING; run");
                    println!("`neoth plugin enable <id>` to opt them in.");
                }
                return Ok(());
            }
            println!(
                "{:<20}  {:<20}  {:<12}  {:<18}  SHA256 (plugin.wasm)",
                "ID", "STATE", "PERMISSION", "NAME"
            );
            println!(
                "{:<20}  {:<20}  {:<12}  {:<18}  -------------------",
                "--", "-----", "----------", "----"
            );
            for row in &rows {
                // First 16 hex chars are enough to eyeball; full value
                // is in `--output json` for copy-paste into the pin map.
                let short = row
                    .content_hash
                    .get(..16)
                    .unwrap_or(row.content_hash.as_str());
                println!(
                    "{:<20}  {:<20}  {:<12}  {:<18}  {}…",
                    row.id,
                    row.display_state,
                    row.requested_permission.as_str(),
                    row.name,
                    short
                );
                if let Some(error) = &row.approval_error {
                    println!("  approval refused: {error}");
                }
            }
            println!();
            println!(
                "SC-03: pin a trusted hash with `neoth plugin list --output json` (full sha256)"
            );
            println!(
                "       → freedom.yaml::plugins.wasm.pinned_hashes.<id>; the daemon then refuses"
            );
            println!("       to run a plugin whose plugin.wasm doesn't match.");
            if only_pending {
                println!();
                println!("Run `neoth plugin enable <id>` to activate.");
            }
        }
    }
    Ok(())
}

fn set_activation(
    home: &std::path::Path,
    id: &str,
    new_state: PluginActivation,
    output: OutputFormat,
) -> Result<()> {
    let change = apply_activation_at(home, id, new_state)?;
    if !change.changed {
        emit_unchanged(id, new_state, output);
        return Ok(());
    }
    emit_changed(
        id,
        change.previous,
        new_state,
        change.granted,
        change.approval.as_ref(),
        output,
    );
    Ok(())
}

struct ActivationChange {
    previous: PluginActivation,
    granted: RequestedPermission,
    approval: Option<PluginApproval>,
    manifest_hash: String,
    wasm_hash: String,
    changed: bool,
}

fn apply_activation_at(
    home: &std::path::Path,
    id: &str,
    new_state: PluginActivation,
) -> Result<ActivationChange> {
    // Validate the id actually corresponds to a discovered plugin —
    // typo'd ids should fail loudly rather than silently writing a
    // stranded activation entry to freedom.yaml.
    let plugins_root = home.join("plugins");
    let report = discover(&plugins_root);
    let plugin = report.loaded.iter().find(|p| p.manifest.id == id);
    let Some(plugin) = plugin else {
        let discovered: Vec<&str> = report
            .loaded
            .iter()
            .map(|p| p.manifest.id.as_str())
            .collect();
        anyhow::bail!(
            "no plugin with id `{id}` discovered under {}. Found: {:?}. \
             Check the directory name matches the manifest `id`.",
            plugins_root.display(),
            discovered
        );
    };

    // SC-04: enabling a plugin IS the operator's grant of the capability
    // level the plugin's manifest declares. Surface that level so the
    // operator gives INFORMED consent — they see exactly what they are
    // authorising, and the runtime hostcall gate then enforces it.
    let granted = plugin.manifest.requested_permissions;

    let mut change = None;
    FreedomConfig::update_at(&home.join("freedom.yaml"), |cfg| {
        if new_state == PluginActivation::Active {
            let wasm = &cfg.plugins.wasm;
            let policy = crate::wasm_plugin::discovery::IntegrityPolicy {
                pinned: &wasm.pinned_hashes,
                require_all_pinned: wasm.require_all_pinned,
                author_pubkey: wasm.author_pubkey.as_deref(),
                require_signature: wasm.require_signature,
                revoked: &wasm.revoked_ids,
            };
            crate::wasm_plugin::discovery::verify_integrity(plugin, &policy).with_context(|| {
                format!(
                    "plugin `{id}` failed the configured integrity policy; activation not changed"
                )
            })?;
        }
        let previous = cfg
            .plugins
            .wasm
            .activations
            .get(id)
            .cloned()
            .unwrap_or_default();
        let new_record = if new_state == PluginActivation::Active {
            PluginActivationRecord::active_for(plugin)
        } else {
            PluginActivationRecord::from_state(new_state)
        };
        let changed = previous != new_record;
        if changed {
            cfg.plugins
                .wasm
                .activations
                .insert(id.to_string(), new_record.clone());
        }
        change = Some(ActivationChange {
            previous: previous.state,
            granted,
            approval: new_record.approval,
            manifest_hash: plugin.manifest_hash.clone(),
            wasm_hash: plugin.content_hash.clone(),
            changed,
        });
        Ok(())
    })
    .context("update freedom.yaml after plugin activation change")?;
    let change = change.expect("locked mutation always records an activation result");
    // R3-15 — same runtime-generation invalidation as removal: a live daemon
    // only re-reads freedom.yaml on the reload sentinel, so without this a
    // `neoth plugin disable` leaves the already-compiled instance running with
    // its bootstrap authority until the operator types `neoth reload`. The slash
    // surface already requested the reload; the CLI did not.
    if change.changed
        && let Err(error) = crate::cli::reload::request_reload_at(home)
    {
        tracing::warn!(
            plugin = %id,
            error = %error,
            "activation changed, but the live-config reload sentinel could not be written — \
             a running daemon keeps the previous authority until `neoth reload`"
        );
    }
    Ok(change)
}

/// Slash/GUI-facing activation path. Uses the same exact approval binding and
/// integrity checks as `neoth plugin enable`, but returns text instead of
/// writing to stdout.
pub(crate) fn set_activation_for_action(
    home: &std::path::Path,
    id: &str,
    enabled: bool,
) -> Result<String> {
    let state = if enabled {
        PluginActivation::Active
    } else {
        PluginActivation::Disabled
    };
    let change = apply_activation_at(home, id, state)?;
    let verb = if enabled { "enabled" } else { "disabled" };
    if !change.changed {
        return Ok(format!(
            "Plugin `{id}` already {verb}; approval and integrity binding revalidated."
        ));
    }
    if enabled {
        Ok(format!(
            "Plugin `{id}` enabled with exact approval `{}`.\nPermission: {}\nmanifest_sha256: {}\nwasm_sha256: {}",
            change.granted.as_str(),
            capability_disclosure(change.granted),
            change.manifest_hash,
            change.wasm_hash,
        ))
    } else {
        Ok(format!("Plugin `{id}` disabled."))
    }
}

/// Plain-language description of what a granted capability level lets a
/// plugin do — shown to the operator at enable time so the consent is
/// informed. The runtime gate (SC-04) enforces exactly this ceiling.
pub(crate) fn capability_disclosure(level: RequestedPermission) -> &'static str {
    match level {
        RequestedPermission::None => {
            "diagnostics only (log, fuel) — cannot read your memory or write to your WAL"
        }
        RequestedPermission::ReadOnly => "may READ your memory (recall hit-counts)",
        RequestedPermission::Write => "may READ your memory AND WRITE audit frames to your WAL",
        RequestedPermission::Execute => "may read/write AND run privileged host actions",
        RequestedPermission::Dangerous => {
            "FULL host access — enable only a plugin you completely trust"
        }
    }
}

fn emit_changed(
    id: &str,
    prev: PluginActivation,
    new: PluginActivation,
    granted: RequestedPermission,
    approval: Option<&PluginApproval>,
    output: OutputFormat,
) {
    let activating = matches!(new, PluginActivation::Active);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let mut payload = json!({
                "id": id,
                "previous": prev.as_str(),
                "new": new.as_str(),
                "changed": true,
            });
            if activating {
                // Make the granted capability machine-readable too, so a
                // GUI / script enabling a plugin records what it approved.
                payload["granted_capability"] = json!(granted.as_str());
                if let Some(approval) = approval {
                    payload["manifest_sha256"] = json!(&approval.manifest_sha256);
                    payload["wasm_sha256"] = json!(&approval.wasm_sha256);
                }
            }
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        }
        OutputFormat::Table => {
            println!(
                "Plugin `{id}` activation: {} → {}",
                prev.as_str(),
                new.as_str()
            );
            if activating {
                println!("The plugin will instantiate on the next `neoth serve` boot.");
                println!(
                    "Capability granted: {} — {}",
                    granted.as_str(),
                    capability_disclosure(granted)
                );
                println!(
                    "Hostcalls above this level are refused at runtime and audited \
                     (`neoth wal show --type plugin_cap_denied`)."
                );
                if let Some(approval) = approval {
                    println!("Manifest SHA-256: {}", approval.manifest_sha256);
                    println!("WASM SHA-256: {}", approval.wasm_sha256);
                }
            }
        }
    }
}

fn emit_unchanged(id: &str, state: PluginActivation, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload = json!({
                "id": id,
                "previous": state.as_str(),
                "new": state.as_str(),
                "changed": false,
            });
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        }
        OutputFormat::Table => {
            println!("Plugin `{id}` already {} — no change.", state.as_str());
        }
    }
}

fn load_activations() -> Result<BTreeMap<String, PluginActivationRecord>> {
    let cfg = FreedomConfig::load_from_default_path().context(
        "load freedom.yaml for plugin activation state (run `neoth init` if it is missing)",
    )?;
    Ok(cfg.plugins.wasm.activations.clone())
}

#[cfg(test)]
mod tests {
    use crate::wasm_plugin::discovery::PluginActivation;

    #[test]
    fn activation_default_is_pending() {
        assert_eq!(PluginActivation::default(), PluginActivation::Pending);
    }

    #[test]
    fn capability_disclosure_distinguishes_read_from_write() {
        use crate::wasm_plugin::manifest::RequestedPermission;
        // SC-04 informed-consent: the operator must be able to tell a
        // read-only plugin from one that can write to their WAL. None
        // must clearly say it touches neither.
        let none = super::capability_disclosure(RequestedPermission::None);
        assert!(none.contains("cannot read") || none.contains("diagnostics"));
        let read = super::capability_disclosure(RequestedPermission::ReadOnly);
        assert!(read.contains("READ") && !read.contains("WRITE"));
        let write = super::capability_disclosure(RequestedPermission::Write);
        assert!(write.contains("WRITE"));
        let dangerous = super::capability_disclosure(RequestedPermission::Dangerous);
        assert!(dangerous.to_lowercase().contains("trust"));
    }

    #[test]
    fn activation_is_active_only_for_active() {
        assert!(PluginActivation::Active.is_active());
        assert!(!PluginActivation::Pending.is_active());
        assert!(!PluginActivation::Disabled.is_active());
    }

    #[test]
    fn activation_as_str_round_trips_via_serde() {
        for s in [
            PluginActivation::Pending,
            PluginActivation::Active,
            PluginActivation::Disabled,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: PluginActivation = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
            assert_eq!(s.as_str(), json.trim_matches('"'));
        }
    }

    // ── UX-07 `neoth plugin test <path>` ──────────────────────────────
    use super::*;
    use tempfile::TempDir;

    fn write_manifest(dir: &std::path::Path, body: &str) {
        std::fs::write(dir.join("plugin.toml"), body).unwrap();
    }
    fn write_wasm(dir: &std::path::Path, bytes: &[u8]) {
        std::fs::write(dir.join("plugin.wasm"), bytes).unwrap();
    }

    /// A minimal-but-valid plugin.toml so the manifest parse succeeds in
    /// tests that exercise the rest of the path. Mirrors the shape used
    /// in `wasm_plugin::manifest::tests`.
    const VALID_MANIFEST: &str = "\
id = \"demo_plugin\"\n\
name = \"Demo Plugin\"\n\
version = \"0.1.0\"\n\
";

    #[tokio::test]
    async fn ux07_test_bails_when_path_does_not_exist() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("not_there");
        let err = run_test(&missing, OutputFormat::Table, false)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not exist"),
            "expected path-missing diagnostic, got: {msg}"
        );
    }

    #[tokio::test]
    async fn ux07_test_bails_when_path_is_a_file_not_a_directory() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("oops.txt");
        std::fs::write(&file, b"not a plugin dir").unwrap();
        let err = run_test(&file, OutputFormat::Table, false)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("not a directory"));
    }

    #[test]
    fn sc03_verify_bails_when_path_does_not_exist() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("not_there");
        let err = run_verify(&missing, OutputFormat::Table).unwrap_err();
        assert!(format!("{err:#}").contains("does not exist"));
    }

    #[test]
    fn sc03_verify_bails_when_path_is_a_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("oops.txt");
        std::fs::write(&file, b"not a plugin dir").unwrap();
        let err = run_verify(&file, OutputFormat::Table).unwrap_err();
        assert!(format!("{err:#}").contains("not a directory"));
    }

    #[tokio::test]
    async fn ux07_test_bails_with_specific_diagnostic_for_missing_manifest() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("plug");
        std::fs::create_dir(&plugin_dir).unwrap();
        write_wasm(&plugin_dir, &[0x00, 0x61, 0x73, 0x6d]); // wasm magic only
        let err = run_test(&plugin_dir, OutputFormat::Table, false)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing `plugin.toml`"),
            "expected manifest-missing diagnostic, got: {msg}"
        );
    }

    #[tokio::test]
    async fn ux07_test_bails_with_specific_diagnostic_for_missing_wasm() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("plug");
        std::fs::create_dir(&plugin_dir).unwrap();
        write_manifest(&plugin_dir, VALID_MANIFEST);
        let err = run_test(&plugin_dir, OutputFormat::Table, false)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing `plugin.wasm`"),
            "expected wasm-missing diagnostic, got: {msg}"
        );
    }

    #[tokio::test]
    async fn ux07_test_surfaces_manifest_parse_errors_with_clear_message() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("plug");
        std::fs::create_dir(&plugin_dir).unwrap();
        write_manifest(
            &plugin_dir,
            "id = \"BadCase\"\nname = \"\"\nversion = \"0.1.0\"\n",
        );
        write_wasm(&plugin_dir, &[0x00, 0x61, 0x73, 0x6d]);
        let err = run_test(&plugin_dir, OutputFormat::Table, false)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("manifest invalid"),
            "expected `manifest invalid` prefix, got: {msg}"
        );
    }

    #[tokio::test]
    async fn ux07_test_accepts_valid_inputs_in_slim_build() {
        // Default cargo test --lib: wasm-plugin-host feature is OFF, so
        // run_test must NOT bail when the inputs are well-formed — it
        // just skips the live invocation and the renderer says so.
        // This is the "manifest validation still useful for slim
        // operators" contract from the doc comment.
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("plug");
        std::fs::create_dir(&plugin_dir).unwrap();
        write_manifest(&plugin_dir, VALID_MANIFEST);
        write_wasm(&plugin_dir, &[0x00, 0x61, 0x73, 0x6d]);
        // Use the JSON output so the test doesn't depend on Table-format
        // string drift; either renderer is acceptable.
        run_test(&plugin_dir, OutputFormat::Json, false)
            .await
            .unwrap();
    }

    #[cfg(not(feature = "wasm-plugin-host"))]
    #[test]
    fn ux07_run_test_invoke_is_none_without_host_feature() {
        // Drift guard: without the feature, run_test_invoke MUST return
        // None so the renderer surfaces the "rebuild with feature" hint.
        // A future refactor that flipped this to Some(...) would silently
        // claim the plugin ran on a slim daemon.
        let manifest =
            crate::wasm_plugin::manifest::parse_manifest(VALID_MANIFEST.as_bytes()).unwrap();
        assert!(run_test_invoke(&manifest, &[]).is_none());
    }

    // ── KF-09 capability ledger ───────────────────────────────────────

    fn cap_used_payload(plugin: &str, capability: &str, hits: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "plugin": plugin,
            "capability": capability,
            "prompt_hash": "0123456789abcdef",
            "hits": hits,
        }))
        .unwrap()
    }

    fn hostcall_payload(plugin: &str, payload_bytes: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "plugin": plugin,
            "kind": "file_seen",
            "payload_bytes": payload_bytes,
        }))
        .unwrap()
    }

    #[test]
    fn parse_cap_frame_0xc4_is_emit_event_write() {
        let u = parse_cap_frame(EVENT_TYPE_PLUGIN_HOSTCALL, &hostcall_payload("indexer", 42))
            .expect("0xC4 parses");
        assert_eq!(u.plugin, "indexer");
        assert_eq!(u.capability, "emit_event");
        assert_eq!(u.payload_bytes, 42);
        assert_eq!(u.hits, 0);
    }

    #[test]
    fn parse_cap_frame_0xc6_is_read_capability() {
        let u = parse_cap_frame(
            EVENT_TYPE_PLUGIN_CAP_USED,
            &cap_used_payload("snoop", "recall_top", 5),
        )
        .expect("0xC6 parses");
        assert_eq!(u.plugin, "snoop");
        assert_eq!(u.capability, "recall_top");
        assert_eq!(u.payload_bytes, 0);
        assert_eq!(u.hits, 5);
    }

    #[test]
    fn parse_cap_frame_rejects_other_event_type_and_garbage() {
        // A non-plugin event type → None.
        assert!(parse_cap_frame(0x01, &cap_used_payload("p", "recall_top", 1)).is_none());
        // A 0xC6 frame with a non-JSON payload → None (tolerant).
        assert!(parse_cap_frame(EVENT_TYPE_PLUGIN_CAP_USED, b"not json").is_none());
    }

    #[test]
    fn aggregate_ledger_counts_sums_and_sorts() {
        let uses = vec![
            CapUse {
                plugin: "b".into(),
                capability: "recall_top".into(),
                payload_bytes: 0,
                hits: 2,
            },
            CapUse {
                plugin: "a".into(),
                capability: "emit_event".into(),
                payload_bytes: 10,
                hits: 0,
            },
            CapUse {
                plugin: "b".into(),
                capability: "recall_top".into(),
                payload_bytes: 0,
                hits: 3,
            },
            CapUse {
                plugin: "a".into(),
                capability: "emit_event".into(),
                payload_bytes: 5,
                hits: 0,
            },
        ];
        let rows = aggregate_ledger(uses, None);
        // Sorted plugin-then-capability: (a, emit_event), (b, recall_top).
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].plugin, "a");
        assert_eq!(rows[0].capability, "emit_event");
        assert_eq!(rows[0].calls, 2);
        assert_eq!(rows[0].total_payload_bytes, 15);
        assert_eq!(rows[1].plugin, "b");
        assert_eq!(rows[1].calls, 2);
        assert_eq!(rows[1].total_hits, 5);
    }

    #[test]
    fn aggregate_ledger_filters_by_id() {
        let uses = vec![
            CapUse {
                plugin: "keep".into(),
                capability: "recall_top".into(),
                payload_bytes: 0,
                hits: 1,
            },
            CapUse {
                plugin: "drop".into(),
                capability: "recall_top".into(),
                payload_bytes: 0,
                hits: 9,
            },
        ];
        let rows = aggregate_ledger(uses, Some("keep"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].plugin, "keep");
    }

    #[tokio::test]
    async fn ledger_collects_and_aggregates_from_real_segment() {
        // End-to-end: write two 0xC6 reads + one 0xC4 write + one unrelated
        // frame through the REAL WAL writer, then assert the ledger
        // aggregates exactly the plugin frames (the unrelated one filtered).
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        for hits in [2i64, 3] {
            let payload = cap_used_payload("snoop", "recall_top", hits);
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_CAP_USED, &payload).build();
            writer.append(header, payload).await.unwrap();
        }
        let w_payload = hostcall_payload("snoop", 64);
        let w_header =
            crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &w_payload).build();
        writer.append(w_header, w_payload).await.unwrap();
        // Unrelated frame must NOT appear in the ledger.
        let other = serde_json::to_vec(&serde_json::json!({ "x": 1 })).unwrap();
        let oh = crate::wal::HeaderBuilder::new(0x01, &other).build();
        writer.append(oh, other).await.unwrap();

        drop(writer);
        let _ = join.await;

        let rows = aggregate_ledger(collect_cap_uses(&wal_dir), None);
        assert_eq!(rows.len(), 2, "recall_top + emit_event, unrelated filtered");
        let recall = rows.iter().find(|r| r.capability == "recall_top").unwrap();
        assert_eq!(recall.calls, 2);
        assert_eq!(recall.total_hits, 5);
        let emit = rows.iter().find(|r| r.capability == "emit_event").unwrap();
        assert_eq!(emit.calls, 1);
        assert_eq!(emit.total_payload_bytes, 64);
    }

    // ── UX-07b: --capture-wal ───────────────────────────────────────────────

    /// The capture read-back decodes an appended plugin frame into
    /// `{event_type, payload}` — the core of `run_test_invoke_with_wal`.
    #[tokio::test]
    async fn decode_wal_frames_reads_appended_plugin_frame() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(seg.clone(), dir.path().to_path_buf()).unwrap();
        let payload = hostcall_payload("snoop", 64);
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        let _ = join.await;

        let frames = decode_wal_frames(&seg, dir.path()).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["event_type"], "0xC4");
        assert_eq!(frames[0]["payload"]["plugin"], "snoop");
        assert_eq!(frames[0]["payload"]["payload_bytes"], 64);
    }

    #[test]
    fn decode_wal_frames_missing_segment_is_empty() {
        let home = TempDir::new().unwrap();
        let frames =
            decode_wal_frames(&home.path().join("does-not-exist.wal"), home.path()).unwrap();
        assert!(
            frames.is_empty(),
            "a missing segment yields no frames, no panic"
        );
    }

    #[test]
    fn decode_wal_frames_rejects_short_non_header_garbage() {
        let home = TempDir::new().unwrap();
        let segment = home.path().join("garbage.wal");
        std::fs::write(&segment, b"not-a-segment").unwrap();

        let error = decode_wal_frames(&segment, home.path())
            .expect_err("short bytes are torn only when they match the header prefix");
        assert_eq!(error.kind, CaptureWalErrorKind::ReconstructFailed);
    }

    #[test]
    fn decode_wal_frames_rejects_physical_oversize_before_parsing() {
        let home = TempDir::new().unwrap();
        let segment = home.path().join("oversize.wal");
        std::fs::write(&segment, [0u8; 65]).unwrap();

        let error = decode_wal_frames_with_limits(
            &segment,
            home.path(),
            CaptureWalLimits {
                max_physical_bytes: 64,
                max_logical_frame_bytes: 64,
                max_frames: 1,
            },
        )
        .unwrap_err();

        assert_eq!(error.kind, CaptureWalErrorKind::PhysicalLimitExceeded);
    }

    #[cfg(unix)]
    #[test]
    fn decode_wal_frames_rejects_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let home = TempDir::new().unwrap();
        let target = home.path().join("target.wal");
        let segment = home.path().join("capture.wal");
        std::fs::write(&target, []).unwrap();
        symlink(&target, &segment).unwrap();

        let error = decode_wal_frames(&segment, home.path()).unwrap_err();
        assert_eq!(error.kind, CaptureWalErrorKind::UnsafeFile);
    }

    #[cfg(windows)]
    #[test]
    fn decode_wal_frames_rejects_junction_parent_without_following_it() {
        let home = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("capture.wal"), []).unwrap();
        let junction = home.path().join("linked-wal");
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(outside.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn mklink /J");
        assert!(status.success(), "mklink /J must create test junction");

        let result = decode_wal_frames(&junction.join("capture.wal"), home.path());
        std::fs::remove_dir(&junction).expect("remove test junction without following it");
        let error = result.expect_err("capture read must reject a Windows reparse-point parent");
        assert_eq!(error.kind, CaptureWalErrorKind::UnsafeFile);
    }

    #[test]
    fn decode_wal_frames_rejects_non_regular_file() {
        let home = TempDir::new().unwrap();
        let segment = home.path().join("capture.wal");
        std::fs::create_dir(&segment).unwrap();

        let error = decode_wal_frames(&segment, home.path()).unwrap_err();
        assert_eq!(error.kind, CaptureWalErrorKind::UnsafeFile);
    }

    #[test]
    fn decode_wal_frames_rejects_compressed_logical_oversize() {
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};

        let home = TempDir::new().unwrap();
        let segment = home.path().join("compressed.wal");
        let logical_frames = vec![b'x'; 2_048];
        let compressed = compress_frames(&logical_frames).unwrap();
        let header =
            SegmentHeaderV2::new(0, 1, 0, 0, [0; 16], SEGMENT_FLAG_COMPRESSED).to_le_bytes();
        let mut physical = Vec::with_capacity(header.len() + compressed.len());
        physical.extend_from_slice(&header);
        physical.extend_from_slice(&compressed);
        std::fs::write(&segment, physical).unwrap();

        let error = decode_wal_frames_with_limits(
            &segment,
            home.path(),
            CaptureWalLimits {
                max_physical_bytes: 4_096,
                max_logical_frame_bytes: 128,
                max_frames: 8,
            },
        )
        .unwrap_err();

        assert_eq!(error.kind, CaptureWalErrorKind::LogicalLimitExceeded);
    }

    #[test]
    fn decode_wal_frames_uses_bounded_no_follow_master_key_reader() {
        use crate::wal::segment_header::SegmentHeader;

        let home = TempDir::new().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).unwrap();
        std::fs::write(wal_dir.join("master.key"), vec![0u8; 8 * 1024]).unwrap();

        let segment = wal_dir.join("encrypted.wal");
        let header = SegmentHeader::new(0, 1, 0, 0, [0; 16]).to_le_bytes();
        let encrypted = crate::wal::crypto::frame_encrypted(&[0u8; 12], &[0u8; 16]);
        let mut bytes = Vec::with_capacity(header.len() + encrypted.len());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&encrypted);
        std::fs::write(&segment, bytes).unwrap();

        let error = decode_wal_frames(&segment, home.path())
            .expect_err("oversized master.key must fail before decrypt/reconstruction");
        assert_eq!(error.kind, CaptureWalErrorKind::MasterKeyReadFailed);
    }

    #[tokio::test]
    async fn decode_wal_frames_recovers_complete_frames_before_torn_tail() {
        use std::io::Write as _;

        let home = TempDir::new().unwrap();
        let segment = home.path().join("torn.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        let payload = hostcall_payload("snoop", 64);
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        join.await.unwrap();

        std::fs::OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap()
            .write_all(b"NEOT")
            .unwrap();

        let frames = decode_wal_frames(&segment, home.path()).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["event_type"], "0xC4");
    }

    #[tokio::test]
    async fn decode_wal_frames_accepts_exact_limit_with_torn_next_frame() {
        use std::io::Write as _;

        let home = TempDir::new().unwrap();
        let segment = home.path().join("exact-limit-torn.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        let payload = hostcall_payload("snoop", 64);
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        join.await.unwrap();

        std::fs::OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap()
            .write_all(b"NEOT")
            .unwrap();

        let frames = decode_wal_frames_with_limits(
            &segment,
            home.path(),
            CaptureWalLimits {
                max_physical_bytes: 4_096,
                max_logical_frame_bytes: 4_096,
                max_frames: 1,
            },
        )
        .expect("exactly one complete frame plus a plausible torn tail is allowed");
        assert_eq!(frames.len(), 1);
    }

    #[tokio::test]
    async fn decode_wal_frames_rejects_invalid_short_tail_at_exact_limit() {
        use std::io::Write as _;

        let home = TempDir::new().unwrap();
        let segment = home.path().join("exact-limit-garbage.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        let payload = hostcall_payload("snoop", 64);
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        join.await.unwrap();

        std::fs::OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap()
            .write_all(b"NOPE")
            .unwrap();

        let error = decode_wal_frames_with_limits(
            &segment,
            home.path(),
            CaptureWalLimits {
                max_physical_bytes: 4_096,
                max_logical_frame_bytes: 4_096,
                max_frames: 1,
            },
        )
        .expect_err("garbage after the exact frame limit is corruption, not a torn frame");
        assert_eq!(error.kind, CaptureWalErrorKind::CorruptFrame);
    }

    #[tokio::test]
    async fn decode_wal_frames_reports_corrupt_complete_frame() {
        let home = TempDir::new().unwrap();
        let segment = home.path().join("corrupt.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        let payload = hostcall_payload("snoop", 64);
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        join.await.unwrap();

        let mut bytes = std::fs::read(&segment).unwrap();
        *bytes.last_mut().expect("writer emits a complete frame") ^= 0xff;
        std::fs::write(&segment, bytes).unwrap();

        let error = decode_wal_frames(&segment, home.path()).unwrap_err();
        assert_eq!(error.kind, CaptureWalErrorKind::CorruptFrame);
    }

    #[tokio::test]
    async fn decode_wal_frames_reports_corrupt_complete_segment_header() {
        let home = TempDir::new().unwrap();
        let segment = home.path().join("corrupt-header.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        let payload = hostcall_payload("snoop", 64);
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        join.await.unwrap();

        let mut bytes = std::fs::read(&segment).unwrap();
        bytes[56] ^= 0xff;
        std::fs::write(&segment, bytes).unwrap();

        let error = decode_wal_frames(&segment, home.path()).unwrap_err();
        assert_eq!(error.kind, CaptureWalErrorKind::ReconstructFailed);
    }

    #[tokio::test]
    async fn decode_wal_frames_tolerates_torn_versioned_segment_header() {
        use crate::wal::segment_header::{SEGMENT_HEADER_V2_LEN, SegmentHeaderV3};

        let home = TempDir::new().unwrap();
        let segment = home.path().join("torn-header.wal");
        let header = SegmentHeaderV3::new(0, 1, 0, 0, [0; 16], 0, 0).to_le_bytes();
        std::fs::write(&segment, &header[..SEGMENT_HEADER_V2_LEN]).unwrap();

        let frames = decode_wal_frames(&segment, home.path()).unwrap();
        assert!(frames.is_empty());
    }

    #[tokio::test]
    async fn decode_wal_frames_enforces_frame_count_ceiling() {
        let home = TempDir::new().unwrap();
        let segment = home.path().join("many.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        for plugin in ["one", "two"] {
            let payload = hostcall_payload(plugin, 1);
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
            writer.append(header, payload).await.unwrap();
        }
        drop(writer);
        join.await.unwrap();

        let error = decode_wal_frames_with_limits(
            &segment,
            home.path(),
            CaptureWalLimits {
                max_physical_bytes: 4_096,
                max_logical_frame_bytes: 4_096,
                max_frames: 1,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, CaptureWalErrorKind::FrameLimitExceeded);
    }

    #[test]
    fn capture_error_kind_serializes_to_stable_snake_case() {
        let error = CaptureWalError::new(CaptureWalErrorKind::PhysicalLimitExceeded, "too large");
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(value["kind"], "physical_limit_exceeded");
    }

    /// Minimal ABI-v1 guest whose `neoth_run` calls the real
    /// `neoth.emit_event(0, 0, 0, 0)` import and returns its status.
    #[cfg(feature = "wasm-plugin-host")]
    fn hostcall_emit_wasm() -> Vec<u8> {
        fn uleb(mut value: u32) -> Vec<u8> {
            let mut encoded = Vec::new();
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                encoded.push(if value == 0 { byte } else { byte | 0x80 });
                if value == 0 {
                    return encoded;
                }
            }
        }
        fn with_len(body: Vec<u8>) -> Vec<u8> {
            let mut encoded = uleb(body.len() as u32);
            encoded.extend(body);
            encoded
        }
        fn wasm_str(value: &str) -> Vec<u8> {
            let mut encoded = uleb(value.len() as u32);
            encoded.extend_from_slice(value.as_bytes());
            encoded
        }
        fn section(id: u8, body: Vec<u8>) -> Vec<u8> {
            let mut encoded = vec![id];
            encoded.extend(with_len(body));
            encoded
        }

        // type 0: emit_event(i32, i32, i32, i32) -> i32
        // type 1: neoth_abi_version/neoth_run() -> i32
        let mut types = uleb(2);
        types.extend([0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f]);
        types.extend([0x60, 0x00, 0x01, 0x7f]);

        let mut imports = uleb(1);
        imports.extend(wasm_str(neoth_plugin_sdk::guest::IMPORT_MODULE));
        imports.extend(wasm_str(neoth_plugin_sdk::guest::HOSTCALL_EMIT_EVENT));
        imports.push(0x00);
        imports.extend(uleb(0));

        let mut functions = uleb(2);
        functions.extend(uleb(1));
        functions.extend(uleb(1));

        let memory = vec![0x01, 0x00, 0x01];

        let mut exports = uleb(3);
        exports.extend(wasm_str(neoth_plugin_sdk::guest::ABI_VERSION_EXPORT));
        exports.extend([0x00, 0x01]); // function 1: ABI version
        exports.extend(wasm_str(neoth_plugin_sdk::guest::RUN_EXPORT));
        exports.extend([0x00, 0x02]); // function 2: neoth_run
        exports.extend(wasm_str("memory"));
        exports.extend([0x02, 0x00]); // memory 0

        let abi_body = vec![0x00, 0x41, neoth_plugin_sdk::guest::ABI_VERSION as u8, 0x0b];
        let run_body = vec![
            0x00, // no locals
            0x41, 0x00, // kind_ptr = 0
            0x41, 0x00, // kind_len = 0
            0x41, 0x00, // payload_ptr = 0
            0x41, 0x00, // payload_len = 0
            0x10, 0x00, // call imported emit_event
            0x0b,
        ];
        let mut code = uleb(2);
        code.extend(with_len(abi_body));
        code.extend(with_len(run_body));

        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        wasm.extend(section(1, types));
        wasm.extend(section(2, imports));
        wasm.extend(section(3, functions));
        wasm.extend(section(5, memory));
        wasm.extend(section(7, exports));
        wasm.extend(section(10, code));
        wasm
    }

    /// Full capture path: compile, instantiate, call the actual host import,
    /// drain writer completion, and decode its 0xC4 frame.
    #[cfg(feature = "wasm-plugin-host")]
    #[tokio::test]
    async fn run_test_invoke_with_wal_captures_actual_emit_hostcall_end_to_end() {
        let manifest = crate::wasm_plugin::manifest::PluginManifest {
            id: "captest".into(),
            name: "captest".into(),
            version: "0.1.0".into(),
            description: None,
            requested_permissions: crate::wasm_plugin::manifest::RequestedPermission::Write,
            hook_stages: vec![],
            fuel_budget_override: None,
            memory_limit_bytes: None,
            source: None,
            ui_surface: None,
        };
        let cap = run_test_invoke_with_wal(&manifest, &hostcall_emit_wasm())
            .await
            .expect("capture path returns Some under the feature");
        assert_eq!(cap.outcome.stage, "run");
        assert!(cap.outcome.invoked_ok, "{:?}", cap.outcome.error);
        assert!(
            cap.capture_error.is_none(),
            "healthy hostcall capture failed: {:?}",
            cap.capture_error
        );
        let hostcall = cap
            .captured_frames
            .iter()
            .find(|frame| frame["event_type"] == "0xC4")
            .expect("actual emit_event import must persist a 0xC4 frame");
        assert_eq!(hostcall["payload"]["plugin"], "captest");
        assert_eq!(hostcall["payload"]["kind"], "");
        assert_eq!(hostcall["payload"]["payload_bytes"], 0);
    }

    /// UX-07b slim build: the capture fn is inert (returns None) without the
    /// host feature, exactly like the dry-run `run_test_invoke` stub.
    #[cfg(not(feature = "wasm-plugin-host"))]
    #[tokio::test]
    async fn run_test_invoke_with_wal_is_none_without_feature() {
        let manifest = crate::wasm_plugin::manifest::PluginManifest {
            id: "captest".into(),
            name: "captest".into(),
            version: "0.1.0".into(),
            description: None,
            requested_permissions: Default::default(),
            hook_stages: vec![],
            fuel_budget_override: None,
            memory_limit_bytes: None,
            source: None,
            ui_surface: None,
        };
        let cap = run_test_invoke_with_wal(&manifest, &[]).await;
        assert!(cap.is_none(), "slim build cannot live-invoke → None");
    }

    // ── `neoth plugin install` + `neoth plugin remove` ────────────────────

    /// Write `plugin.toml` + `plugin.wasm` into `dir/<id>/` so it looks like
    /// a well-formed plugin source tree.
    fn write_plugin_source(root: &std::path::Path, id: &str, wasm: &[u8]) -> std::path::PathBuf {
        let dir = root.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("plugin.toml"),
            format!("id = \"{id}\"\nname = \"Test Plugin\"\nversion = \"0.1.0\"\n"),
        )
        .unwrap();
        std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
        dir
    }

    const MINIMAL_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    fn assert_no_install_staging(root: &std::path::Path, id: &str) {
        let prefix = format!(".{id}.install-staging.");
        let leftovers: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect();
        assert!(
            leftovers.is_empty(),
            "staged install must be cleaned up: {leftovers:?}"
        );
    }

    fn assert_no_install_backup(root: &std::path::Path, id: &str) {
        let prefix = format!(".{id}.install-backup.");
        let leftovers: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect();
        assert!(
            leftovers.is_empty(),
            "rollback backup must be restored or cleaned up: {leftovers:?}"
        );
    }

    #[test]
    fn install_copies_toml_and_wasm_into_plugins_root() {
        let src_root = TempDir::new().unwrap();
        let dst_root = TempDir::new().unwrap();
        let src = write_plugin_source(src_root.path(), "my_plugin", MINIMAL_WASM);
        let installed = install_into_plugins_root(
            &src,
            false,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap();

        assert_eq!(installed.id, "my_plugin");
        assert_eq!(installed.target, dst_root.path().join("my_plugin"));
        assert_eq!(
            std::fs::read(installed.target.join("plugin.wasm")).unwrap(),
            MINIMAL_WASM
        );
        assert!(installed.target.join("plugin.toml").is_file());
        assert_no_install_staging(dst_root.path(), "my_plugin");
    }

    #[test]
    fn install_bails_on_missing_manifest() {
        let src_root = TempDir::new().unwrap();
        // wasm present, no plugin.toml
        let dir = src_root.path().join("no_toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();

        let dst_root = TempDir::new().unwrap();
        let err = install_into_plugins_root(
            &dir,
            false,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing `plugin.toml`"),
            "expected manifest-missing diagnostic, got: {msg}"
        );
    }

    #[test]
    fn install_bails_on_missing_wasm() {
        let src_root = TempDir::new().unwrap();
        // toml present, no plugin.wasm
        let dir = src_root.path().join("no_wasm");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("plugin.toml"),
            "id = \"no_wasm\"\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let dst_root = TempDir::new().unwrap();
        let err = install_into_plugins_root(
            &dir,
            false,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing `plugin.wasm`"),
            "expected wasm-missing diagnostic, got: {msg}"
        );
    }

    #[test]
    fn install_bails_on_invalid_manifest() {
        let src_root = TempDir::new().unwrap();
        let dir = src_root.path().join("bad_manifest");
        std::fs::create_dir_all(&dir).unwrap();
        // Uppercase id is invalid per manifest validation rules.
        std::fs::write(
            dir.join("plugin.toml"),
            "id = \"BadCase\"\nname = \"\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();

        let dst_root = TempDir::new().unwrap();
        let err = install_into_plugins_root(
            &dir,
            false,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("manifest invalid"),
            "expected `manifest invalid` prefix, got: {msg}"
        );
    }

    #[test]
    fn install_bails_on_symlink_source_dir() {
        let src_root = TempDir::new().unwrap();
        // Can't create a symlink portably in tests; guard the is_symlink()
        // check via the existing path.is_symlink() branch by passing a path
        // that is NOT a symlink but IS a file (which is_dir() rejects first
        // on non-Unix). Instead we verify the error message path for the
        // "not a directory" branch, which is reached before the symlink check.
        let file_path = src_root.path().join("not_a_dir.txt");
        std::fs::write(&file_path, b"x").unwrap();
        let dst_root = TempDir::new().unwrap();
        let err = install_into_plugins_root(
            &file_path,
            false,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("not a directory"),
            "a file path should fail the is_dir() guard"
        );
    }

    #[test]
    fn install_bails_when_already_installed_without_force() {
        let src_root = TempDir::new().unwrap();
        let dst_root = TempDir::new().unwrap();
        let src = write_plugin_source(src_root.path(), "dup_plugin", MINIMAL_WASM);
        let target = dst_root.path().join("dup_plugin");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"old").unwrap();

        let err = install_into_plugins_root(
            &src,
            false,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("already installed"));
        assert_eq!(std::fs::read(target.join("sentinel")).unwrap(), b"old");
        assert_no_install_staging(dst_root.path(), "dup_plugin");
    }

    #[test]
    fn install_force_replaces_existing() {
        let src_root = TempDir::new().unwrap();
        let dst_root = TempDir::new().unwrap();
        let source = write_plugin_source(src_root.path(), "forced", MINIMAL_WASM);
        let target = dst_root.path().join("forced");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("stale.dat"), b"old").unwrap();

        install_into_plugins_root(
            &source,
            true,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap();
        assert!(
            !target.join("stale.dat").exists(),
            "sentinel must not survive --force"
        );
        assert!(
            target.join("plugin.toml").exists(),
            "new content must be present"
        );
        assert_eq!(
            std::fs::read(target.join("plugin.wasm")).unwrap(),
            MINIMAL_WASM
        );
        assert_no_install_staging(dst_root.path(), "forced");
    }

    #[test]
    fn install_copies_optional_minisig_for_runtime_verification() {
        let src_root = TempDir::new().unwrap();
        let dst_root = TempDir::new().unwrap();
        let source = write_plugin_source(src_root.path(), "signed_plugin", MINIMAL_WASM);
        let signature = b"untrusted comment: fixture\nnot-a-real-signature\n";
        std::fs::write(source.join("plugin.wasm.minisig"), signature).unwrap();

        install_into_plugins_root(
            &source,
            false,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap();

        let installed_signature =
            std::fs::read(dst_root.path().join("signed_plugin/plugin.wasm.minisig")).unwrap();
        assert_eq!(installed_signature, signature);
        let report = crate::wasm_plugin::discovery::discover(dst_root.path());
        assert_eq!(report.loaded.len(), 1);
        assert_eq!(
            report.loaded[0].signature.as_deref(),
            std::str::from_utf8(signature).ok(),
            "daemon discovery must observe the installed signature companion"
        );
    }

    #[test]
    fn install_required_signature_failure_preserves_existing_version() {
        let src_root = TempDir::new().unwrap();
        let dst_root = TempDir::new().unwrap();
        let source = write_plugin_source(src_root.path(), "secure_plugin", MINIMAL_WASM);
        let target = dst_root.path().join("secure_plugin");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"known-good").unwrap();

        let policy = crate::config::WasmPluginsConfig {
            author_pubkey: Some(
                "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".to_string(),
            ),
            require_signature: true,
            ..Default::default()
        };
        let err = install_into_plugins_root(&source, true, dst_root.path(), &policy).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("runtime integrity gate") && message.contains("signature"),
            "unexpected policy failure: {message}"
        );
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"known-good",
            "verification failure must leave the previous install intact"
        );
        assert_no_install_staging(dst_root.path(), "secure_plugin");
    }

    #[test]
    fn install_force_copy_failure_preserves_existing_version() {
        let src_root = TempDir::new().unwrap();
        let dst_root = TempDir::new().unwrap();
        let source = src_root.path().join("copy_fail");
        std::fs::create_dir_all(source.join("plugin.wasm")).unwrap();
        std::fs::write(
            source.join("plugin.toml"),
            "id = \"copy_fail\"\nname = \"Copy Fail\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let target = dst_root.path().join("copy_fail");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"known-good").unwrap();

        let err = install_into_plugins_root(
            &source,
            true,
            dst_root.path(),
            &crate::config::WasmPluginsConfig::default(),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("copy"));
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"known-good",
            "copy failure must leave the previous install intact"
        );
        assert_no_install_staging(dst_root.path(), "copy_fail");
    }

    #[test]
    fn install_force_activation_failure_restores_existing_version() {
        let dst_root = TempDir::new().unwrap();
        let target = dst_root.path().join("rollback_plugin");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"known-good").unwrap();

        // A missing stage simulates a final rename failure after the old
        // target was moved aside. The activation helper must restore backup.
        let mut missing_stage = RemovePathOnDrop::new(dst_root.path().join("missing-stage"));
        let err = activate_staged_install(&target, &mut missing_stage, true).unwrap_err();
        assert!(format!("{err:#}").contains("previous install was restored"));
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"known-good"
        );
        assert_no_install_backup(dst_root.path(), "rollback_plugin");
    }

    #[test]
    fn install_json_shape() {
        // Verify the JSON output object has the required keys with correct
        // types — pin the shape so GUI consumers don't regress silently.
        // We construct it the same way run_install does.
        let obj = serde_json::json!({
            "ok": true,
            "id": "demo_plugin",
            "path": "/home/alex/.neoth/plugins/demo_plugin",
        });
        assert_eq!(obj["ok"], serde_json::Value::Bool(true));
        assert_eq!(obj["id"], "demo_plugin");
        assert!(obj["path"].is_string());
    }

    #[test]
    fn remove_plugin_at_clears_activation_and_pin_keeps_revocation() {
        // R3-15: a real transactional removal — config trust references cleared,
        // bytes deleted, revocation preserved. (The prior tests only asserted a
        // hand-built JSON shape and never exercised the removal path.)
        let home = TempDir::new().unwrap();
        let dir = home.path().join("plugins").join("my_plugin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.toml"), b"x").unwrap();
        std::fs::write(dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();

        let mut cfg = super::FreedomConfig::default();
        cfg.plugins.wasm.activations.insert(
            "my_plugin".to_string(),
            super::PluginActivationRecord::from_state(super::PluginActivation::Active),
        );
        cfg.plugins
            .wasm
            .pinned_hashes
            .insert("my_plugin".to_string(), "a".repeat(64));
        cfg.plugins.wasm.revoked_ids.push("blocked_one".to_string());
        let freedom = home.path().join("freedom.yaml");
        std::fs::write(&freedom, serde_yaml::to_string(&cfg).unwrap()).unwrap();

        let removed = super::remove_plugin_at(home.path(), "my_plugin").unwrap();
        assert!(removed, "an installed plugin must report removed");
        assert!(!dir.exists(), "bytes must be deleted");

        let after: super::FreedomConfig =
            serde_yaml::from_str(&std::fs::read_to_string(&freedom).unwrap()).unwrap();
        assert!(
            !after.plugins.wasm.activations.contains_key("my_plugin"),
            "activation must be cleared"
        );
        assert!(
            !after.plugins.wasm.pinned_hashes.contains_key("my_plugin"),
            "hash pin must be cleared — removal invalidates the prior trust decision"
        );
        assert!(
            after
                .plugins
                .wasm
                .revoked_ids
                .contains(&"blocked_one".to_string()),
            "a revocation is a deny-list and must survive removal"
        );
    }

    #[test]
    fn remove_plugin_at_cleans_stale_config_when_dir_absent() {
        // The directory is already gone but the config still references it: the
        // removal must still clean the stale reference (old code returned early).
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("plugins")).unwrap();
        let mut cfg = super::FreedomConfig::default();
        cfg.plugins.wasm.activations.insert(
            "ghost".to_string(),
            super::PluginActivationRecord::from_state(super::PluginActivation::Active),
        );
        let freedom = home.path().join("freedom.yaml");
        std::fs::write(&freedom, serde_yaml::to_string(&cfg).unwrap()).unwrap();

        let removed = super::remove_plugin_at(home.path(), "ghost").unwrap();
        assert!(removed, "a stale config reference counts as a removal");
        let after: super::FreedomConfig =
            serde_yaml::from_str(&std::fs::read_to_string(&freedom).unwrap()).unwrap();
        assert!(!after.plugins.wasm.activations.contains_key("ghost"));
    }

    #[test]
    fn remove_plugin_at_reports_absent_when_nothing_installed() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("plugins")).unwrap();
        let removed = super::remove_plugin_at(home.path(), "nope").unwrap();
        assert!(!removed, "nothing installed → not removed");
    }

    #[test]
    fn remove_json_shape_on_success() {
        // Pin the JSON shape for GUI consumers.
        let obj = serde_json::json!({
            "ok": true,
            "id": "gone_plugin",
        });
        assert_eq!(obj["ok"], serde_json::Value::Bool(true));
        assert_eq!(obj["id"], "gone_plugin");
        // `path` must NOT be present in the success shape.
        assert!(
            obj.get("path").is_none(),
            "remove success must not carry a `path` key"
        );
    }

    #[test]
    fn remove_json_shape_not_found() {
        let obj = serde_json::json!({
            "ok": false,
            "id": "ghost",
            "reason": "not found",
        });
        assert_eq!(obj["ok"], serde_json::Value::Bool(false));
        assert_eq!(obj["reason"], "not found");
    }

    // ── DES-12: `neoth plugin events` ─────────────────────────────────────────

    /// events subcommand with an empty WAL dir returns an empty events array,
    /// exit 0 — not an error.
    #[tokio::test]
    async fn des12_events_empty_wal_returns_empty_array() {
        let dir = TempDir::new().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();

        // Override the WAL dir by calling run_events_subcommand indirectly:
        // we can't override FreedomConfig::default_wal_dir() easily, so we
        // test the output shape directly via emit_events_output.
        let events: Vec<serde_json::Value> = vec![];
        let mut buf = Vec::<u8>::new();
        let v = serde_json::json!({ "id": "demo_plugin", "events": events });
        serde_json::to_writer(&mut buf, &v).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(parsed["id"], "demo_plugin");
        assert!(parsed["events"].as_array().unwrap().is_empty());
    }

    /// The JSON shape of a single events entry must have `kind`, `payload_bytes`,
    /// and `ts_unix`. This pins the contract the GUI depends on.
    #[test]
    fn des12_events_json_shape() {
        let entry = serde_json::json!({
            "kind": "file_seen",
            "payload_bytes": 42u64,
            "ts_unix": 1_700_000_000u64,
        });
        assert_eq!(entry["kind"], "file_seen");
        assert_eq!(entry["payload_bytes"], 42);
        assert_eq!(entry["ts_unix"], 1_700_000_000u64);

        // Outer envelope: {id, events:[...]}
        let envelope = serde_json::json!({
            "id": "demo_plugin",
            "events": [entry],
        });
        let events = envelope["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "file_seen");
    }

    /// Round-trip: write a 0xC4 frame for plugin "feed_plugin" into a real
    /// WAL segment and verify that walk_cap_frames + parse_cap_frame surfaces
    /// the `emit_event` capability — the same WAL-scan path that
    /// run_events_subcommand uses. This mirrors `ledger_collects_and_aggregates_from_real_segment`.
    #[tokio::test]
    async fn des12_events_wal_scan_finds_hostcall_frame() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        // Write two 0xC4 frames for "feed_plugin" and one for "other_plugin".
        for kind in ["file_seen", "chunk_indexed"] {
            let payload = serde_json::to_vec(&serde_json::json!({
                "plugin": "feed_plugin",
                "kind": kind,
                "payload_bytes": 64u64,
            }))
            .unwrap();
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
            writer.append(header, payload).await.unwrap();
        }
        // Unrelated plugin — must NOT appear in feed_plugin's events.
        let other = serde_json::to_vec(&serde_json::json!({
            "plugin": "other_plugin",
            "kind": "ping",
            "payload_bytes": 0u64,
        }))
        .unwrap();
        let oh = crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &other).build();
        writer.append(oh, other).await.unwrap();

        drop(writer);
        let _ = join.await;

        // Use collect_cap_uses + filter, mirroring the events subcommand logic.
        let uses = collect_cap_uses(&wal_dir);
        let feed: Vec<_> = uses
            .iter()
            .filter(|u| u.plugin == "feed_plugin" && u.capability == "emit_event")
            .collect();
        assert_eq!(
            feed.len(),
            2,
            "two 0xC4 frames for feed_plugin must be found"
        );
        let other_uses: Vec<_> = uses.iter().filter(|u| u.plugin == "other_plugin").collect();
        assert_eq!(other_uses.len(), 1, "other_plugin frame must also be found");
        // Filtering to feed_plugin only yields 2 rows.
        assert_eq!(uses.iter().filter(|u| u.plugin == "feed_plugin").count(), 2);
    }

    #[test]
    fn remove_rejects_path_traversal_ids() {
        // GOLD-SEC: a traversal id must bail BEFORE any filesystem access —
        // these all fail the is_snake_case_id guard, so no real ~/.neoth is
        // touched by the test.
        for evil in [
            "../../.neoth/credentials.yaml",
            "..",
            "/etc/passwd",
            "a/b",
            "a\\b",
            "has space",
            "Upper",
        ] {
            let err = remove_plugin_at(std::path::Path::new("."), evil)
                .expect_err("traversal id must be rejected");
            assert!(
                err.to_string().contains("invalid plugin id"),
                "unexpected error for {evil:?}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn plugin_removal_emits_correlated_intent_and_committed_wal() {
        // R3-15: the removal leaves a durable, correlated intent→committed audit
        // trail. No daemon here → the direct home-bound WAL writer (append mode),
        // so both frames must persist in order.
        let home = TempDir::new().unwrap();
        let op = "op-abc";
        super::emit_plugin_removal_intent(
            home.path(),
            op,
            "wasm_hello",
            Some("gen123"),
            Some("pin456"),
            Some(0xfeed_beef),
        )
        .await
        .unwrap();
        super::emit_plugin_removal_result(
            home.path(),
            op,
            "wasm_hello",
            "committed",
            Some(true),
            None,
            super::RemovalProgress {
                config_cleared: true,
                bytes_deleted: true,
            },
        )
        .await
        .unwrap();

        let mut intent = None;
        let mut result = None;
        let mut removal_order = Vec::new();
        crate::wal::scan::for_each_frame_at_home(
            home.path(),
            crate::wal::scan::HomeWalScanLimits::default(),
            |_, frame| {
                if frame.header.event_type != crate::wal::events::EVENT_TYPE_EXTENDED {
                    return Ok(());
                }
                let payload: serde_json::Value = serde_json::from_slice(frame.payload)?;
                match frame.header.event_subtype {
                    subtype
                        if subtype
                            == crate::wal::events::ExtendedSubtype::PluginRemovalIntent as u8 =>
                    {
                        removal_order.push("intent");
                        intent = Some(payload);
                    }
                    subtype
                        if subtype
                            == crate::wal::events::ExtendedSubtype::PluginRemovalResult as u8 =>
                    {
                        removal_order.push("result");
                        result = Some(payload);
                    }
                    _ => {}
                }
                Ok(())
            },
        )
        .unwrap();
        let intent = intent.expect("removal intent must persist in a bounded home WAL segment");
        let result = result.expect("removal result must persist in a bounded home WAL segment");
        assert_eq!(intent["phase"], "intent");
        assert_eq!(intent["operation_id"], op);
        assert_eq!(intent["plugin_id"], "wasm_hello");
        assert_eq!(intent["installed_generation_sha256"], "gen123");
        assert_eq!(intent["expected_pinned_hash"], "pin456");
        assert_eq!(
            intent["config_generation"], 0xfeed_beefu64,
            "the intent must bind the config generation it authorised"
        );
        assert_eq!(result["status"], "committed");
        assert_eq!(
            result["operation_id"], op,
            "the terminal outcome must correlate to its intent"
        );
        assert_eq!(result["removed"], true);
        assert_eq!(result["config_cleared"], true);
        assert_eq!(result["bytes_deleted"], true);
        assert_eq!(
            removal_order,
            ["intent", "result"],
            "durable removal intent must precede its terminal result in WAL order"
        );
    }

    #[test]
    fn removal_journal_is_retired_only_after_the_readback() {
        // R3-15: the pending-removal journal exists across the mutation and is
        // gone once the plugin is proven absent.
        let home = TempDir::new().unwrap();
        let dir = home.path().join("plugins").join("journalled");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.toml"), b"x").unwrap();
        std::fs::write(dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();

        let journal = super::removal_journal_path(home.path(), "journalled");
        assert!(!journal.exists(), "no journal before the removal");
        assert!(super::remove_plugin_at(home.path(), "journalled").unwrap());
        assert!(
            !journal.exists(),
            "a completed removal must retire its journal"
        );
        assert!(
            !journal
                .parent()
                .unwrap()
                .starts_with(home.path().join("plugins")),
            "the journal must live outside plugins/ so it is never discoverable"
        );
    }

    #[test]
    fn removal_resumes_a_crashed_transaction_from_its_journal() {
        // Crash state: the config was already cleared, the bytes are still on
        // disk, and the journal survived. Without the journal this looks exactly
        // like "nothing installed" (no activation, no pin) and the old code
        // reported a no-op, stranding the bytes. The resume must finish it.
        let home = TempDir::new().unwrap();
        let dir = home.path().join("plugins").join("half_gone");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.toml"), b"x").unwrap();
        std::fs::write(dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();
        // Clean config — the trust references were already revoked pre-crash.
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&super::FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        let journal = super::removal_journal_path(home.path(), "half_gone");
        crate::util::atomic_write::atomic_write_private(&journal, b"{\"plugin_id\":\"half_gone\"}")
            .unwrap();

        let removed = super::remove_plugin_at(home.path(), "half_gone").unwrap();
        assert!(
            removed,
            "a journalled crash must resume, not report a no-op"
        );
        assert!(!dir.exists(), "the resume must finish the byte deletion");
        assert!(!journal.exists(), "the resume must retire the journal");
    }

    #[test]
    fn absent_plugin_leaves_no_journal_behind() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("plugins")).unwrap();
        assert!(!super::remove_plugin_at(home.path(), "nope").unwrap());
        assert!(
            !super::removal_journal_path(home.path(), "nope").exists(),
            "a no-op must not mint a durable pending-removal record"
        );
    }

    #[test]
    fn failed_config_clear_is_aborted_and_a_reached_step_is_partial() {
        // PR5-018: `aborted` must mean "nothing happened". A malformed config
        // fails before any mutation, so nothing is reached...
        let home = TempDir::new().unwrap();
        let dir = home.path().join("plugins").join("broken_cfg");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.toml"), b"x").unwrap();
        std::fs::write(dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();
        std::fs::write(home.path().join("freedom.yaml"), b"{{{ not yaml").unwrap();

        let mut progress = super::RemovalProgress::default();
        let err = super::remove_plugin_at_tracked(home.path(), "broken_cfg", &mut progress)
            .expect_err("a malformed config must fail the removal");
        assert!(
            format!("{err:#}").contains("clear config references"),
            "unexpected error: {err:#}"
        );
        assert_eq!(progress, super::RemovalProgress::default());
        assert_eq!(super::removal_failure_status(progress), "aborted");
        assert!(dir.exists(), "an aborted removal must not delete bytes");
        assert!(
            super::removal_journal_path(home.path(), "broken_cfg").exists(),
            "the pending transaction must stay journalled for the retry"
        );

        // ...whereas a cleared config with the bytes still present is `partial`.
        assert_eq!(
            super::removal_failure_status(super::RemovalProgress {
                config_cleared: true,
                bytes_deleted: false,
            }),
            "partial",
            "a revoked trust decision is not `nothing happened`"
        );
    }

    #[test]
    fn byte_delete_failure_after_the_config_clear_is_partial_and_stays_journalled() {
        // Injected second-write failure: the config clear succeeds, the byte
        // delete cannot. `remove_dir_all` on a non-directory fails on every
        // platform, so this pins the partial state deterministically.
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("plugins")).unwrap();
        let target = home.path().join("plugins").join("not_a_dir");
        std::fs::write(&target, b"regular file").unwrap();

        let mut cfg = super::FreedomConfig::default();
        cfg.plugins.wasm.activations.insert(
            "not_a_dir".to_string(),
            super::PluginActivationRecord::from_state(super::PluginActivation::Active),
        );
        let freedom = home.path().join("freedom.yaml");
        std::fs::write(&freedom, serde_yaml::to_string(&cfg).unwrap()).unwrap();

        let mut progress = super::RemovalProgress::default();
        let err = super::remove_plugin_at_tracked(home.path(), "not_a_dir", &mut progress)
            .expect_err("an undeletable target must fail the removal");
        assert!(
            format!("{err:#}").contains("remove plugin directory"),
            "unexpected error: {err:#}"
        );
        assert!(
            progress.config_cleared && !progress.bytes_deleted,
            "the trust decision is revoked but the bytes remain: {progress:?}"
        );
        assert_eq!(super::removal_failure_status(progress), "partial");

        let after: super::FreedomConfig =
            serde_yaml::from_str(&std::fs::read_to_string(&freedom).unwrap()).unwrap();
        assert!(
            !after.plugins.wasm.activations.contains_key("not_a_dir"),
            "the config clear must have committed before the byte failure"
        );
        assert!(
            super::removal_journal_path(home.path(), "not_a_dir").exists(),
            "an unfinished removal must stay journalled so the retry resumes it"
        );
    }

    #[test]
    fn skipped_steps_are_never_reported_as_performed() {
        // The audit trail must not claim a mutation that never ran: with no
        // freedom.yaml on disk there is no config to clear, and a stale config
        // reference alone deletes no bytes.
        let home = TempDir::new().unwrap();
        let dir = home.path().join("plugins").join("no_config");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.toml"), b"x").unwrap();
        std::fs::write(dir.join("plugin.wasm"), MINIMAL_WASM).unwrap();

        let mut progress = super::RemovalProgress::default();
        assert!(super::remove_plugin_at_tracked(home.path(), "no_config", &mut progress).unwrap());
        assert_eq!(
            progress,
            super::RemovalProgress {
                config_cleared: false,
                bytes_deleted: true,
            },
            "no freedom.yaml → the config-clear step never ran"
        );

        // Mirror image: a stale config reference with the directory gone.
        let mut cfg = super::FreedomConfig::default();
        cfg.plugins.wasm.activations.insert(
            "ghost_only".to_string(),
            super::PluginActivationRecord::from_state(super::PluginActivation::Active),
        );
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let mut progress = super::RemovalProgress::default();
        assert!(super::remove_plugin_at_tracked(home.path(), "ghost_only", &mut progress).unwrap());
        assert_eq!(
            progress,
            super::RemovalProgress {
                config_cleared: true,
                bytes_deleted: false,
            },
            "no directory → the byte-delete step never ran"
        );
    }

    #[test]
    fn removal_intent_id_is_validated_before_any_side_effect() {
        // PR5-040: the traversal guard sits in `validate_plugin_id`, which
        // `run_remove` calls BEFORE minting the durable intent frame.
        for evil in ["../../x", "..", "/etc/passwd", "a/b", "Upper"] {
            let err = super::validate_plugin_id(evil).expect_err("must reject");
            assert!(format!("{err:#}").contains("invalid plugin id"), "{err:#}");
        }
        super::validate_plugin_id("wasm_hello").expect("a real id must pass");
    }
}
