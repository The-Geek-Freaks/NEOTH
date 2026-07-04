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
//! [`FreedomConfig::save_public_to_default_path`] so the on-disk
//! representation is the authoritative source for the next daemon
//! boot.

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
use crate::wasm_plugin::discovery::{PluginActivation, discover};
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
    /// Show only the discovered-but-not-yet-decided plugins. Operator
    /// review queue.
    Pending,
    /// Flip a plugin to `active`. Idempotent — already-active plugins
    /// return success without rewriting freedom.yaml.
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

    // Read manifest + wasm + optional signature DIRECTLY (like run_test),
    // NOT via discovery::load_one — so `neoth plugin verify` works on an
    // out-of-tree checkout whose directory name doesn't match the plugin
    // id (CI clones into arbitrary dirs). The daemon's load path keeps the
    // id==dirname locality check; this is a pre-install INTEGRITY gate.
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
    let content_hash = crate::wasm_plugin::discovery::sha256_hex(&wasm_bytes);
    let signature =
        crate::wasm_plugin::discovery::read_capped_minisig(&path.join("plugin.wasm.minisig"))
            .map_err(|()| {
                anyhow::anyhow!(
                    "plugin.wasm.minisig exceeds {} bytes — refusing to parse",
                    crate::wasm_plugin::discovery::MAX_MINISIG_BYTES
                )
            })?;
    let plugin = crate::wasm_plugin::discovery::DiscoveredPlugin {
        dir: path.to_path_buf(),
        manifest,
        wasm_bytes,
        content_hash,
        signature,
    };

    // Apply the SAME freedom.yaml policy the daemon uses at load time. A
    // MISSING freedom.yaml yields Ok(default) (open policy — correct on a
    // fresh install); a CORRUPT one is an Err → BAIL rather than silently
    // verify against an empty (all-gates-off) policy, which would print
    // PASS for plugins the daemon would actually refuse.
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
        if let Some(want) = filter_id {
            if u.plugin != want {
                continue;
            }
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

#[cfg(feature = "wasm-plugin-host")]
fn run_test_invoke(
    manifest: &crate::wasm_plugin::manifest::PluginManifest,
    wasm_bytes: &[u8],
) -> Option<TestInvocationSummary> {
    use crate::wasm_plugin::dispatch::{
        CompileOutcome, InvocationStage, invocation_outcome_from_compile_failure, invoke_plugin,
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
        CompileOutcome, InvocationStage, invocation_outcome_from_compile_failure,
        invoke_plugin_with_state,
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

    // Caller-built state: manifest grant + the throwaway writer.
    let state = PluginStoreState::new(manifest.id.clone())
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
            println!("  wasm size:   {} bytes", wasm_size);
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

fn render_list(home: &std::path::Path, output: OutputFormat, only_pending: bool) -> Result<()> {
    let plugins_root = home.join("plugins");
    let report = discover(&plugins_root);
    let activations = load_activations()?;

    // (id, state, name, content_hash) — SC-03 surfaces the sha256 so
    // the operator can pin it in freedom.yaml::plugins.wasm.pinned_hashes.
    let mut rows: Vec<(String, PluginActivation, String, String)> = report
        .loaded
        .iter()
        .map(|p| {
            let state = activations.get(&p.manifest.id).copied().unwrap_or_default();
            (
                p.manifest.id.clone(),
                state,
                p.manifest.name.clone(),
                p.content_hash.clone(),
            )
        })
        .collect();
    if only_pending {
        rows.retain(|(_, s, _, _)| *s == PluginActivation::Pending);
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload: Vec<serde_json::Value> = rows
                .iter()
                .map(|(id, state, name, hash)| {
                    json!({
                        "id": id,
                        "name": name,
                        "activation": state.as_str(),
                        "sha256": hash,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                if only_pending {
                    println!("No plugins awaiting activation.");
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
                "{:<20}  {:<9}  {:<18}  SHA256 (plugin.wasm)",
                "ID", "STATE", "NAME"
            );
            println!(
                "{:<20}  {:<9}  {:<18}  -------------------",
                "--", "-----", "----"
            );
            for (id, state, name, hash) in &rows {
                // First 16 hex chars are enough to eyeball; full value
                // is in `--output json` for copy-paste into the pin map.
                let short = hash.get(..16).unwrap_or(hash.as_str());
                println!(
                    "{:<20}  {:<9}  {:<18}  {}…",
                    id,
                    state.as_str(),
                    name,
                    short
                );
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
    // Validate the id actually corresponds to a discovered plugin —
    // typo'd ids should fail loudly rather than silently writing a
    // stranded activation entry to freedom.yaml.
    let plugins_root = home.join("plugins");
    let report = discover(&plugins_root);
    let id_known = report.loaded.iter().any(|p| p.manifest.id == id);
    if !id_known {
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
    }

    // SC-04: enabling a plugin IS the operator's grant of the capability
    // level the plugin's manifest declares. Surface that level so the
    // operator gives INFORMED consent — they see exactly what they are
    // authorising, and the runtime hostcall gate then enforces it.
    let granted = report
        .loaded
        .iter()
        .find(|p| p.manifest.id == id)
        .map(|p| p.manifest.requested_permissions)
        .unwrap_or_default();

    let mut cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml to update plugin activation")?;
    let prev = cfg
        .plugins
        .wasm
        .activations
        .get(id)
        .copied()
        .unwrap_or_default();
    if prev == new_state {
        emit_unchanged(id, new_state, output);
        return Ok(());
    }
    cfg.plugins
        .wasm
        .activations
        .insert(id.to_string(), new_state);
    cfg.save_public_to_default_path()
        .context("save freedom.yaml after plugin activation change")?;

    emit_changed(id, prev, new_state, granted, output);
    Ok(())
}

/// Plain-language description of what a granted capability level lets a
/// plugin do — shown to the operator at enable time so the consent is
/// informed. The runtime gate (SC-04) enforces exactly this ceiling.
fn capability_disclosure(level: RequestedPermission) -> &'static str {
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

fn load_activations() -> Result<BTreeMap<String, PluginActivation>> {
    match FreedomConfig::load_from_default_path() {
        Ok(cfg) => Ok(cfg.plugins.wasm.activations.clone()),
        Err(_) => Ok(BTreeMap::new()),
    }
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
        };
        let cap = run_test_invoke_with_wal(&manifest, &[]).await;
        assert!(cap.is_none(), "slim build cannot live-invoke → None");
    }
}
