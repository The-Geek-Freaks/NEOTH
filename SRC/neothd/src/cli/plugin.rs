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
use crate::wasm_plugin::discovery::{PluginActivation, discover};

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
        PluginAction::Test { path } => run_test(&path, args.output),
        PluginAction::Verify { path } => run_verify(&path, args.output),
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

/// UX-07 — read + validate a candidate plugin and (under the host
/// feature) live-invoke it. Returns Ok even when the invocation reports
/// a plugin-side error so the operator can see the structured outcome;
/// returns Err only when the inputs themselves are unusable
/// (missing files, malformed manifest).
fn run_test(path: &std::path::Path, output: OutputFormat) -> Result<()> {
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
    let invocation_outcome: Option<TestInvocationSummary> = run_test_invoke(&manifest, &wasm_bytes);

    render_test_report(&manifest, wasm_bytes.len(), invocation_outcome, output)
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
    let outcome = invoke_plugin(&engine, module, &linker, manifest.id.clone());
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

fn render_test_report(
    manifest: &crate::wasm_plugin::manifest::PluginManifest,
    wasm_size: usize,
    outcome: Option<TestInvocationSummary>,
    output: OutputFormat,
) -> Result<()> {
    let host_built = cfg!(feature = "wasm-plugin-host");
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload = json!({
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

    emit_changed(id, prev, new_state, output);
    Ok(())
}

fn emit_changed(id: &str, prev: PluginActivation, new: PluginActivation, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload = json!({
                "id": id,
                "previous": prev.as_str(),
                "new": new.as_str(),
                "changed": true,
            });
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        }
        OutputFormat::Table => {
            println!(
                "Plugin `{id}` activation: {} → {}",
                prev.as_str(),
                new.as_str()
            );
            if matches!(new, PluginActivation::Active) {
                println!("The plugin will instantiate on the next `neoth serve` boot.");
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

    #[test]
    fn ux07_test_bails_when_path_does_not_exist() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("not_there");
        let err = run_test(&missing, OutputFormat::Table).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not exist"),
            "expected path-missing diagnostic, got: {msg}"
        );
    }

    #[test]
    fn ux07_test_bails_when_path_is_a_file_not_a_directory() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("oops.txt");
        std::fs::write(&file, b"not a plugin dir").unwrap();
        let err = run_test(&file, OutputFormat::Table).unwrap_err();
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

    #[test]
    fn ux07_test_bails_with_specific_diagnostic_for_missing_manifest() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("plug");
        std::fs::create_dir(&plugin_dir).unwrap();
        write_wasm(&plugin_dir, &[0x00, 0x61, 0x73, 0x6d]); // wasm magic only
        let err = run_test(&plugin_dir, OutputFormat::Table).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing `plugin.toml`"),
            "expected manifest-missing diagnostic, got: {msg}"
        );
    }

    #[test]
    fn ux07_test_bails_with_specific_diagnostic_for_missing_wasm() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("plug");
        std::fs::create_dir(&plugin_dir).unwrap();
        write_manifest(&plugin_dir, VALID_MANIFEST);
        let err = run_test(&plugin_dir, OutputFormat::Table).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing `plugin.wasm`"),
            "expected wasm-missing diagnostic, got: {msg}"
        );
    }

    #[test]
    fn ux07_test_surfaces_manifest_parse_errors_with_clear_message() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("plug");
        std::fs::create_dir(&plugin_dir).unwrap();
        write_manifest(
            &plugin_dir,
            "id = \"BadCase\"\nname = \"\"\nversion = \"0.1.0\"\n",
        );
        write_wasm(&plugin_dir, &[0x00, 0x61, 0x73, 0x6d]);
        let err = run_test(&plugin_dir, OutputFormat::Table).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("manifest invalid"),
            "expected `manifest invalid` prefix, got: {msg}"
        );
    }

    #[test]
    fn ux07_test_accepts_valid_inputs_in_slim_build() {
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
        run_test(&plugin_dir, OutputFormat::Json).unwrap();
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
}
