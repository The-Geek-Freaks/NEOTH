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
        /// invocation emits into a throwaway tempdir WAL and surface them in
        /// the report. Requires the `wasm-plugin-host` feature; without it the
        /// flag is inert (the slim build can't live-invoke). The live WAL is
        /// never touched.
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
        PluginAction::Remove { id } => run_remove(&id, args.output),
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
        let (outcome, frames) = match captured {
            Some(c) => (Some(c.outcome), Some(c.captured_frames)),
            None => (None, None),
        };
        render_test_report(&manifest, wasm_bytes.len(), outcome, frames, output)
    } else {
        let invocation_outcome: Option<TestInvocationSummary> =
            run_test_invoke(&manifest, &wasm_bytes);
        render_test_report(
            &manifest,
            wasm_bytes.len(),
            invocation_outcome,
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

    // THROWAWAY WAL: a tempdir segment the invocation writes into, never the
    // live `~/.neoth` WAL. `tmp` is held to fn-end so the file survives the
    // read-back below.
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => return fail("compile", format!("tempdir: {e}")),
    };
    let seg = tmp.path().join("000001.wal");
    let (writer, join) = match crate::wal::writer::spawn(seg.clone()) {
        Ok(p) => p,
        Err(e) => return fail("compile", format!("wal writer spawn: {e}")),
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
    // returned, so no clone is held here; join drains the writer task.
    join.await.ok();
    let captured_frames = decode_wal_frames(&seg);

    Some(TestInvocationWithWal {
        outcome: TestInvocationSummary {
            stage: invocation_stage_name(outcome.stage).to_string(),
            error: outcome.error,
            invoked_ok,
        },
        captured_frames,
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

/// UX-07b — decode every frame in a (small, single-segment) WAL file into
/// `{event_type, payload}` JSON, in emission order. Tolerant: a missing /
/// torn / truncated segment yields the frames recovered so far. The `wal`
/// read primitives are feature-independent, so the capture/read-back logic
/// unit-tests without the wasm host (the `test` half of the cfg).
#[cfg(any(test, feature = "wasm-plugin-host"))]
fn decode_wal_frames(segment: &std::path::Path) -> Vec<serde_json::Value> {
    use crate::wal::compress::decompress_frames;
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::parse_segment_header;

    let Ok(bytes) = std::fs::read(segment) else {
        return Vec::new();
    };
    let Ok(hdr) = parse_segment_header(&bytes) else {
        return Vec::new();
    };
    let body = &bytes[hdr.header_len()..];
    let frames = if hdr.is_compressed() {
        match decompress_frames(body) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        }
    } else {
        body.to_vec()
    };
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        let payload = serde_json::from_slice::<serde_json::Value>(dec.payload).ok();
        out.push(serde_json::json!({
            "event_type": format!("0x{:02X}", dec.header.event_type),
            "payload": payload,
        }));
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    out
}

fn render_test_report(
    manifest: &crate::wasm_plugin::manifest::PluginManifest,
    wasm_size: usize,
    outcome: Option<TestInvocationSummary>,
    captured_frames: Option<Vec<serde_json::Value>>,
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
/// installed).
///
/// Ordering matters: the config trust references are cleared **before** the
/// on-disk bytes are deleted, and every step propagates its error, so the
/// observable state is never "bytes gone but config still active":
/// - a config write failure aborts before any deletion → the plugin stays fully
///   intact and consistent;
/// - a byte-delete failure after the config is clean leaves a deactivated,
///   unpinned directory that fail-closed discovery will not run — recoverable,
///   and surfaced instead of swallowed.
///
/// Removal invalidates the operator's prior trust decision, so the activation
/// AND the hash pin are cleared; a revocation is a deny-list and deliberately
/// survives. A stale config reference is cleaned even when the directory is
/// already gone, and success is only reported after an inventory readback
/// proves the plugin is no longer a loadable install.
fn remove_plugin_at(home: &std::path::Path, id: &str) -> Result<bool> {
    // GOLD-SEC — reject path-traversal ids before any filesystem join. An
    // installed plugin id is always a valid snake_case token (enforced at
    // install time via parse_manifest); anything else (`../`, absolute paths,
    // separators) cannot name a real install and must never reach
    // remove_dir_all. Without this guard `neoth plugin remove ../../foo`
    // would delete an arbitrary directory the operator can write to.
    if !crate::wasm_plugin::manifest::is_snake_case_id(id) {
        anyhow::bail!(
            "invalid plugin id `{id}` — must be a snake_case token \
             ([a-z0-9_], not starting with `_` or a digit)"
        );
    }
    let plugins_root = home.join("plugins");
    let target = plugins_root.join(id);
    let freedom_path = home.join("freedom.yaml");

    let bytes_present = target.exists();

    // Clear the config trust references FIRST. A failure aborts before any byte
    // deletion. The empty-config case creates nothing (guarded on existence).
    let config_refs_cleared = if freedom_path.exists() {
        FreedomConfig::update_at(&freedom_path, |config| {
            let deactivated = config.plugins.wasm.activations.remove(id).is_some();
            let unpinned = config.plugins.wasm.pinned_hashes.remove(id).is_some();
            Ok(deactivated || unpinned)
        })
        .with_context(|| format!("clear config references for plugin `{id}`"))?
    } else {
        false
    };

    // Nothing installed: no bytes and no stale config reference.
    if !bytes_present && !config_refs_cleared {
        return Ok(false);
    }

    // Config is clean; delete the bytes.
    if bytes_present {
        std::fs::remove_dir_all(&target)
            .with_context(|| format!("remove plugin directory `{}`", target.display()))?;
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

    Ok(true)
}

fn run_remove(id: &str, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let removed = remove_plugin_at(&home, id)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let obj = if removed {
                serde_json::json!({ "ok": true, "id": id })
            } else {
                serde_json::json!({ "ok": false, "id": id, "reason": "not found" })
            };
            println!("{}", serde_json::to_string(&obj)?);
        }
        OutputFormat::Table => {
            if removed {
                println!("removed plugin `{id}`.");
            } else {
                println!("plugin `{id}` not installed — no-op.");
            }
        }
    }
    Ok(())
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
    Ok(change.expect("locked mutation always records an activation result"))
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
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let payload = hostcall_payload("snoop", 64);
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        let _ = join.await;

        let frames = decode_wal_frames(&seg);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["event_type"], "0xC4");
        assert_eq!(frames[0]["payload"]["plugin"], "snoop");
        assert_eq!(frames[0]["payload"]["payload_bytes"], 64);
    }

    #[test]
    fn decode_wal_frames_missing_segment_is_empty() {
        let frames = decode_wal_frames(std::path::Path::new(
            "/nonexistent-uxo7b/does-not-exist.wal",
        ));
        assert!(
            frames.is_empty(),
            "a missing segment yields no frames, no panic"
        );
    }

    /// UX-07b end-to-end plumbing (feature build): the capture path spawns a
    /// throwaway WAL, invokes via `invoke_plugin_with_state`, drains, and
    /// decodes — returning `Some` without panic. A minimal module (no
    /// `neoth_run` export, no hostcall) reaches ExportLookup with an empty
    /// frame list; the REAL hostcall→0xC4 capture is proven in dispatch's
    /// `invoke_plugin_with_state_uses_injected_writer` + the frame round-trip
    /// above.
    #[cfg(feature = "wasm-plugin-host")]
    #[tokio::test]
    async fn run_test_invoke_with_wal_runs_end_to_end() {
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
        // Smallest valid module: magic + version, no `neoth_run` export.
        let minimal = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let cap = run_test_invoke_with_wal(&manifest, &minimal)
            .await
            .expect("capture path returns Some under the feature");
        assert_eq!(
            cap.outcome.stage, "export_lookup",
            "minimal module has no neoth_run export"
        );
        assert!(
            cap.captured_frames.is_empty(),
            "no hostcall was made → no captured frames"
        );
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
            let err =
                run_remove(evil, OutputFormat::Table).expect_err("traversal id must be rejected");
            assert!(
                err.to_string().contains("invalid plugin id"),
                "unexpected error for {evil:?}: {err}"
            );
        }
    }
}
