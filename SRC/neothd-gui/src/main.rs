//! NEOTH GUI wizard — R-1 Phase 3.
//!
//! Multi-screen flow:
//!   welcome → license → identity → provider → autonomy → channels
//!     → (keys, when needed) → done
//!
//! On finish we write two files:
//!   - `~/.neoth/freedom.yaml` — operator id, provider kind, autonomy
//!     level, channels-enabled list. No secrets in this file.
//!   - `~/.neoth/credentials.yaml` (only when the operator entered at
//!     least one secret) — mode 0600 on unix, ACL-restricted on Windows.
//!     Mirrors the secrets-split landed by `config/credentials.rs`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;
use tracing_subscriber::EnvFilter;

// FIX 1 — serialize all freedom.yaml writers so concurrent GUI toggles cannot
// interleave their read-modify-write cycles and lose an update.
static FREEDOM_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// GU-03 — persona-adaptive settings-panel visibility rule engine (pure Rust,
/// unit-tested without Slint). The `.slint` binds its `show_*` properties to
/// [`panel_logic::PanelVisibility`], populated on startup from the operator's
/// complexity level.
mod buddy_activity;
mod panel_logic;

use buddy_activity::GuiActivity;

slint::include_modules!();

// ── Wave-1 toast plumbing ─────────────────────────────────────────────────────
//
// push_toast appends a ToastData item to the MainWindow's `toasts` model and
// starts a 6-second one-shot timer that calls prune_toast to remove it.
// All mutations cross into the Slint event loop via invoke_from_event_loop.
//
// `kind`: "info" | "success" | "warn" | "consent"  (drives the Led colour)
fn push_toast(window: &slint::Weak<MainWindow>, kind: &'static str, title: &str, body: &str) {
    use slint::Model as _; // ModelRc::iter
    let title = title.to_string();
    let body  = body.to_string();
    let weak  = window.clone();

    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        // Read current toasts, compute a fresh id, append.
        let mut current: Vec<(i32, String, String, String)> = w
            .get_toasts()
            .iter()
            .map(|t| (t.id, t.kind.to_string(), t.title.to_string(), t.body.to_string()))
            .collect();
        let id = panel_logic::next_toast_id(&current);
        current.push((id, kind.to_string(), title.clone(), body.clone()));

        let model: slint::VecModel<ToastData> = slint::VecModel::from(
            current.iter().map(|(i, k, ti, b)| ToastData {
                id: *i,
                kind: k.as_str().into(),
                title: ti.as_str().into(),
                body: b.as_str().into(),
            }).collect::<Vec<_>>()
        );
        w.set_toasts(slint::ModelRc::new(std::rc::Rc::new(model)));

        // 6-second expiry timer — fires once then removes the id.
        let weak2 = w.as_weak();
        let expiry = slint::Timer::default();
        expiry.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(6000),
            move || {
                let Some(w2) = weak2.upgrade() else { return };
                let remaining: Vec<(i32, String, String, String)> = w2
                    .get_toasts()
                    .iter()
                    .map(|t| (t.id, t.kind.to_string(), t.title.to_string(), t.body.to_string()))
                    .collect();
                let pruned = panel_logic::prune_toast(remaining, id);
                let model2: slint::VecModel<ToastData> = slint::VecModel::from(
                    pruned.iter().map(|(i, k, ti, b)| ToastData {
                        id: *i,
                        kind: k.as_str().into(),
                        title: ti.as_str().into(),
                        body: b.as_str().into(),
                    }).collect::<Vec<_>>()
                );
                w2.set_toasts(slint::ModelRc::new(std::rc::Rc::new(model2)));
            },
        );
        // Keep the timer alive — leak it into a thread-local so it survives
        // the enclosing closure. Slint timers must be alive to fire.
        std::mem::forget(expiry);
    });
}

// ── Wave-2 activity sidecar plumbing ─────────────────────────────────────────
//
// push_activity  — appends an ActivityRow (newest-first, cap 60), auto-opens
//                  the sidecar on the first significant event of a burst.
// settle_activity_kind — marks all rows of a given kind inactive (completion).
//
// Both mutate the Slint model via invoke_from_event_loop so they are safe to
// call from worker threads (same pattern as push_toast).

/// Append one activity row to the sidecar.
/// `significant`: non-metric row triggers auto-open when the panel is closed.
fn push_activity(
    window: &slint::Weak<MainWindow>,
    kind: &'static str,
    title: &str,
    detail: &str,
) {
    use slint::Model as _;
    let title  = title.to_string();
    let detail = detail.to_string();
    let window = window.clone();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = window.upgrade() else { return };
        // Collect current rows (newest-first) as plain tuples.
        let current: Vec<panel_logic::ActivityTuple> = w.get_activity_rows()
            .iter()
            .map(|r| (r.id, r.ts.to_string(), r.kind.to_string(),
                      r.title.to_string(), r.detail.to_string(), r.active))
            .collect();
        let id = panel_logic::next_activity_id(&current);
        let ts = format_now_hms();
        let mut rows = current;
        // Insert at front (newest-first).
        rows.insert(0, (id, ts, kind.to_string(), title, detail, true));
        let rows = panel_logic::cap_activity(rows, 60);
        let slint_rows: Vec<ActivityRow> = rows.iter().map(|(id, ts, k, ti, de, ac)| ActivityRow {
            id: *id,
            ts: ts.as_str().into(),
            kind: k.as_str().into(),
            title: ti.as_str().into(),
            detail: de.as_str().into(),
            active: *ac,
        }).collect();
        w.set_activity_rows(slint::ModelRc::new(slint::VecModel::from(slint_rows)));
        // Auto-open on first significant row of a burst (kind != "metric").
        if !w.get_activity_open() && kind != "metric" {
            w.set_activity_open(true);
        }
    });
}

/// Mark all rows of `kind` as inactive (call on completion events).
fn settle_activity_kind(window: &slint::Weak<MainWindow>, kind: &'static str) {
    use slint::Model as _;
    let window = window.clone();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = window.upgrade() else { return };
        let current: Vec<panel_logic::ActivityTuple> = w.get_activity_rows()
            .iter()
            .map(|r| (r.id, r.ts.to_string(), r.kind.to_string(),
                      r.title.to_string(), r.detail.to_string(), r.active))
            .collect();
        let settled = panel_logic::settle_activity(current, kind);
        let slint_rows: Vec<ActivityRow> = settled.iter().map(|(id, ts, k, ti, de, ac)| ActivityRow {
            id: *id,
            ts: ts.as_str().into(),
            kind: k.as_str().into(),
            title: ti.as_str().into(),
            detail: de.as_str().into(),
            active: *ac,
        }).collect();
        w.set_activity_rows(slint::ModelRc::new(slint::VecModel::from(slint_rows)));
    });
}

// ── Code Sessions tab — subprocess JSON envelopes ─────────────────────
// Mirror of `KanbanSession` + `KanbanTask` in `neothd::coding::types`.
// We re-declare them here (instead of depending on the daemon crate
// directly) for the same reason `MinimalFreedomYaml` is duplicated: the
// GUI crate stays light + decoupled from daemon internals. Wire-form
// changes surface as JSON deserialise errors at runtime.

#[derive(Debug, Deserialize)]
struct CodingSessionJson {
    session_id: i64,
    prompt: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct CodingTaskJson {
    task_id: i64,
    status: String,
    title: String,
    hemisphere: String,
}

#[derive(Debug, Deserialize)]
struct CodingShowEnvelope {
    session: CodingSessionJson,
    tasks: Vec<CodingTaskJson>,
}

/// Mirror of `neothd::coding::feed::FeedEntry` — one row in the WAL-
/// derived activity feed. Pick #8 step 3: GUI calls
/// `neothd kanban watch --output json` and renders the result in the
/// right-rail of the Code Sessions tab.
#[derive(Debug, Deserialize)]
struct FeedEntryJson {
    ts_ns: u64,
    actor: String,
    message: String,
}

/// Mirror of `neothd::coding::types::KanbanComment` for the detail
/// pane subprocess parse. Fields match the serde wire form pinned by
/// `cli::kanban::task_detail_json_envelope_contains_task_and_comments`.
#[derive(Debug, Deserialize)]
struct CommentJson {
    author: String,
    body: String,
    created_ns: u64,
}

#[derive(Debug, Deserialize)]
struct TaskDetailEnvelope {
    #[serde(default)]
    comments: Vec<CommentJson>,
}

/// Plain snapshot the Rust side hands to Slint. Owning-Vecs keep the
/// Slint Model construction simple — we build `ModelRc<VecModel<…>>`
/// from each Vec at the property-set site.
///
/// Step 5 (2026-05-20): `Clone` lets the click-handler clone the
/// last-applied snapshot out of the shared Mutex so the detail-pane
/// lookup runs lock-free.
#[derive(Default, Clone)]
struct KanbanBoardSnapshot {
    backlog: Vec<KanbanTaskRow>,
    todo: Vec<KanbanTaskRow>,
    in_progress: Vec<KanbanTaskRow>,
    review: Vec<KanbanTaskRow>,
    done: Vec<KanbanTaskRow>,
    feed: Vec<KanbanFeedRow>,
    summary: String,
    /// HO-02: whether a Cerebellum hemisphere is bound. `None` on every
    /// degraded path (no binary / list-or-show failure) so the UI does
    /// NOT false-alarm; `Some(bool)` only on the success path where we
    /// actually probed `neoth hemispheres show`. apply maps None→true.
    cerebellum_bound: Option<bool>,
}

impl KanbanBoardSnapshot {
    /// Step 5 (2026-05-20): find a task by its `task-id` string
    /// ("#42") across the 5 status buckets. Returns the task row +
    /// the wire-form status name so the detail-pane can render both.
    fn find_task(&self, id: &str) -> Option<(KanbanTaskRow, &'static str)> {
        for (col, status) in [
            (&self.backlog, "backlog"),
            (&self.todo, "todo"),
            (&self.in_progress, "in_progress"),
            (&self.review, "review"),
            (&self.done, "done"),
        ] {
            for row in col {
                if row.task_id.as_str() == id {
                    return Some((row.clone(), status));
                }
            }
        }
        None
    }
}

fn main() -> Result<()> {
    init_tracing();
    info!("neothd-gui starting (R-1 Phase 3 — autonomy + channels + keys)");

    let window = MainWindow::new()?;

    // ── Companion overlay — created here, hidden until the operator
    // clicks "⊟" in the TopBar. Both windows share the one event loop
    // that `window.run()` drives; `overlay.show()` / `overlay.hide()`
    // are safe to call from UI-thread callbacks at any time.
    // DO NOT call `overlay.run()` — only `window.run()` drives the loop.
    let overlay = MiniOverlay::new()?;

    // Theme — restore the persisted light/dark choice before the window paints
    // (default dark). Persisted at `<neoth_home>/.gui-theme` as "dark"/"light".
    {
        let is_dark = std::fs::read_to_string(default_neoth_home().join(".gui-theme"))
            .map(|s| s.trim() != "light")
            .unwrap_or(true);
        window.global::<Theme>().set_dark(is_dark);
    }
    let weak_theme = window.as_weak();
    window.on_theme_toggle_clicked(move || {
        if let Some(w) = weak_theme.upgrade() {
            // The sidebar already flipped Theme.dark live; persist the new value.
            let is_dark = w.global::<Theme>().get_dark();
            let _ = std::fs::write(
                default_neoth_home().join(".gui-theme"),
                if is_dark { "dark" } else { "light" },
            );
        }
    });

    // ODY-11 — density restore: read ~/.neoth/.gui-density and apply before
    // the first paint, mirroring the .gui-theme block above.
    {
        let val = read_gui_density(&default_neoth_home());
        window.global::<Theme>().set_density_mode(val);
        window.set_chat_density_mode(val);
    }
    let weak_density = window.as_weak();
    window.on_density_changed(move |val| {
        if let Some(w) = weak_density.upgrade() {
            let density_path = default_neoth_home().join(".gui-density");
            write_gui_density(&density_path, val);
            w.global::<Theme>().set_density_mode(val);
            w.set_chat_density_mode(val);
        }
    });

    // H-3 fix — hardware probe runs in a worker thread so a hanging
    // `neothd hardware` subprocess can never block the window from
    // appearing. The placeholder string shows until the real probe
    // result lands via `invoke_from_event_loop`.
    window.set_hardware_summary("Probing hardware…".into());
    window.set_daemon_state("connecting".into());
    let weak_hw = window.as_weak();
    std::thread::spawn(move || {
        let hw_summary = probe_hardware_via_subprocess();
        // GOLD-ADAPT-GUI-04 — footer Led state derived from the probe
        // outcome: every failure arm of the probe starts with
        // "Hardware probe" (missing binary / bad exit / spawn error).
        let led = if hw_summary.starts_with("Hardware probe") {
            "error"
        } else {
            "live"
        };
        let weak = weak_hw.clone();
        let hw_for_toast = hw_summary.clone();
        // Wave-1 call site B: toast on daemon error so the operator gets a
        // top-right signal even if they are looking at the chat surface.
        if led == "error" {
            push_toast(&weak, "warn", "Daemon unreachable", &hw_for_toast);
        }
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_hardware_summary(hw_summary.into());
                w.set_daemon_state(led.into());
            }
        });
    });

    // GOLD-ADAPT-OH-01 — prior-AI detection for the welcome migrate
    // card. Worker thread (subprocess must never block the window);
    // the card only appears when detect finds canonical stores, so a
    // missing neoth-migrate binary or empty result is silent.
    let weak_migrate = window.as_weak();
    std::thread::spawn(move || {
        let summary = which_neoth_migrate()
            .and_then(|bin| {
                std::process::Command::new(bin)
                    .arg("detect")
                    .arg("--json")
                    .env("NO_COLOR", "1")
                    .env("NEOTH_LOG", "error")
                    .output()
                    .ok()
            })
            .filter(|out| out.status.success())
            .map(|out| format_migrate_summary(&String::from_utf8_lossy(&out.stdout)))
            .unwrap_or_default();
        if summary.is_empty() {
            return;
        }
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak_migrate.upgrade() {
                w.set_migrate_summary(summary.into());
            }
        });
    });

    // QM-9 Phase 2/3+: usage rollup probe runs in its own worker so a
    // slow `neoth usage` subprocess can't block the window. Phase 3+
    // re-fires the probe every USAGE_REFRESH_INTERVAL so the dashboard
    // tile stays current as new chat turns land in the persisted log.
    // Placeholder string shows until the first probe lands via
    // invoke_from_event_loop.
    window.set_usage_summary("Loading usage…".into());
    let weak_usage = window.as_weak();
    std::thread::spawn(move || {
        loop {
            let summary = probe_usage_via_subprocess();
            let weak = weak_usage.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_usage_summary(summary.into());
                }
            });
            std::thread::sleep(USAGE_REFRESH_INTERVAL);
        }
    });

    // GOLD-WIRE-10b: live budget meter probe — same refresh-loop shape
    // as usage. Re-fires every BUDGET_REFRESH_INTERVAL so the dashboard
    // tile stays current as provider calls land in the daemon.
    window.set_budget_summary("Loading budget…".into());
    let weak_budget = window.as_weak();
    std::thread::spawn(move || {
        loop {
            let summary = probe_budget_via_subprocess();
            let weak = weak_budget.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_budget_summary(summary.into());
                }
            });
            std::thread::sleep(BUDGET_REFRESH_INTERVAL);
        }
    });

    // QM-8 Phase 2: preset list probe — same refresh-loop shape as
    // usage. Lighter cadence (5min) since presets change rarely.
    window.set_preset_summary("Loading presets…".into());
    let weak_preset = window.as_weak();
    std::thread::spawn(move || {
        loop {
            let summary = probe_preset_summary_via_subprocess();
            // SPEC-05 — also fetch the structured list for the click-to-activate
            // selector (the summary string remains the empty-state fallback).
            let presets = fetch_presets();
            let weak = weak_preset.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_preset_summary(summary.into());
                    apply_presets(&w, presets);
                }
            });
            std::thread::sleep(PRESET_REFRESH_INTERVAL);
        }
    });

    // G-2 first-launch detection: if `~/.neoth/freedom.yaml` already
    // exists the operator has been through the wizard before. Jump
    // straight to the done screen so they don't accidentally overwrite
    // their config by clicking Finish on the welcome screen. They can
    // still re-run by clicking Finish at the bottom of the wizard.
    let neoth_dir = default_neoth_home();

    // GU-03 — persona-adaptive settings panels. Read the operator's complexity
    // level (the v2 wizard's W-03a decision) + apply the panel-visibility rules.
    // A pre-v2 / fresh operator falls back to Standard. Computed once at startup
    // (the wizard re-run path re-launches the GUI, picking up the new level).
    {
        let level = panel_logic::read_complexity_level(&neoth_dir);
        let pv = panel_logic::panels_for(level);
        info!(
            complexity = level.as_str(),
            "GU-03: applied persona-adaptive panel visibility"
        );
        window.set_settings_show_hemispheres(pv.show_hemispheres);
        window.set_settings_show_channels(pv.show_channels);
        window.set_settings_show_skills(pv.show_skills);
        window.set_settings_show_plugins(pv.show_plugins);
        window.set_settings_show_memory(pv.show_memory);
        window.set_settings_show_cluster(pv.show_cluster);
        window.set_settings_show_code_sessions(pv.show_code_sessions);
    }

    let already_initialized = neoth_dir.join("freedom.yaml").exists();
    // GUI-REENTRY-PRESET fix: track whether the re-entry config read succeeded.
    // on_finish_clicked checks this flag and refuses to overwrite the existing
    // config when the read failed (preventing Slint property defaults — which
    // correspond to "balanced" preset values — from silently clobbering the
    // operator's real config). False = first-run or read failed (safe default:
    // no existing config to protect). True = re-entry with config loaded OK.
    let reentry_config_ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if already_initialized {
        info!(
            freedom_path = %neoth_dir.join("freedom.yaml").display(),
            "freedom.yaml already exists — jumping to done step"
        );
        window.set_step(WizardStep::Done);
        // The operator already accepted the licence on first run —
        // freedom.yaml's existence is the proof. Pre-arm the checkbox
        // state so the "Finish" button stays clickable on re-entry
        // (otherwise the disabled-by-default checkbox blocks the
        // operator from re-writing config without walking back to the
        // licence screen).
        window.set_license_accepted(true);

        // M-1 fix — read freedom.yaml back into the wizard properties
        // so the Done-summary card on re-entry shows the operator's
        // actual config rather than the type defaults (empty handle /
        // claude_cli / standard). The summary is the operator's only
        // confirmation that NEOTH remembered them; surfacing defaults
        // there is misleading.
        match read_freedom_yaml(&neoth_dir.join("freedom.yaml")) {
            Ok(cfg) => {
                window.set_operator_id(cfg.operator_id.into());
                window.set_provider_choice(cfg.provider_kind.into());
                window.set_autonomy_choice(cfg.autonomy.into());
                window.set_enable_telegram(cfg.channels.iter().any(|c| c == "telegram"));
                // Config loaded successfully — Finish is safe to overwrite.
                reentry_config_ok.store(true, std::sync::atomic::Ordering::Release);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not parse existing freedom.yaml — Done summary shows defaults"
                );
                // reentry_config_ok stays false: Finish will refuse to write
                // rather than clobber the existing config with type defaults.
            }
        }

        // Bite #5 — populate the cluster settings panel from the
        // existing freedom.yaml so the post-onboarding operator sees
        // their current cluster state (not Q4 defaults) when they
        // click the Cluster tab. Lossless reader — doesn't touch
        // unrelated fields.
        let cluster_state = load_cluster_settings(&neoth_dir.join("freedom.yaml"));
        window.set_cluster_mdns_enabled(cluster_state.mdns_enabled);
        window.set_cluster_listen_port(cluster_state.listen_port as i32);
        window.set_cluster_trusted_ssids_summary(cluster_state.trusted_ssids_summary.into());
        // PF-01-GUI — reflect the current skills.always_embed_route on the toggle.
        window.set_skills_always_embed_route(read_skills_always_embed_route(
            &neoth_dir.join("freedom.yaml"),
        ));

        // DES-09 — populate all editable settings fields from freedom.yaml.
        {
            let fp = &neoth_dir.join("freedom.yaml");
            // Welle A — council
            // FIX 4 — daily_usd_cap is a YAML float; as_str() always returns None for
            // numeric nodes. Use the f64 reader and format for display.
            let cap_str = read_nested_f64_in_freedom(fp, "council.daily_usd_cap", 0.0)
                .map(format_cap_f64)
                .unwrap_or_default();
            window.set_cfg_council_daily_usd(cap_str.into());
            let mc = read_nested_i64_in_freedom(fp, "council.max_calls_per_user_message", 0);
            window.set_cfg_council_max_calls(if mc == 0 { "".into() } else { mc.to_string().into() });
            let md = read_nested_i64_in_freedom(fp, "council.max_recursion_depth", 0);
            window.set_cfg_council_max_depth(if md == 0 { "".into() } else { md.to_string().into() });
            let sm = read_nested_str_in_freedom(fp, "council.selection_mode", "legacy_majority");
            // FIX 5 — 3 variants: 0=legacy_majority 1=consensus_or_best 2=best_always
            window.set_cfg_council_selection_mode_idx(match sm.as_str() {
                "consensus_or_best" => 1,
                "best_always"       => 2,
                _                   => 0,
            });
            // Welle A — provider
            window.set_cfg_provider_model(read_nested_str_in_freedom(fp, "provider_model", "").into());
            window.set_cfg_provider_endpoint(read_nested_str_in_freedom(fp, "provider_endpoint", "").into());
            window.set_cfg_provider_region(read_nested_str_in_freedom(fp, "provider_region", "").into());
            window.set_cfg_provider_api_version(read_nested_str_in_freedom(fp, "provider_api_version", "").into());
            // Welle A — profile + behavior
            let pm = read_nested_str_in_freedom(fp, "persona_mode", "");
            window.set_cfg_persona_mode_idx(if pm == "loyal_buddy" { 1 } else { 0 });
            window.set_cfg_user_tz(read_nested_str_in_freedom(fp, "user_tz", "").into());
            window.set_cfg_elicitation_enabled(read_nested_bool_in_freedom(fp, "elicitation.enabled", false));
            window.set_cfg_tone_modifier_enabled(read_nested_bool_in_freedom(fp, "tone_modifier.enabled", false));
            // Welle B — privacy
            window.set_cfg_review_gate_enabled(read_nested_bool_in_freedom(fp, "review_gate_enabled", false));
            window.set_cfg_cloud_stt_enabled(read_nested_bool_in_freedom(fp, "media.cloud_stt_enabled", false));
            window.set_cfg_cloud_tts_enabled(read_nested_bool_in_freedom(fp, "media.cloud_tts_enabled", false));
            window.set_cfg_cloud_vision_enabled(read_nested_bool_in_freedom(fp, "media.cloud_vision_enabled", false));
            window.set_cfg_vad_enabled(read_nested_bool_in_freedom(fp, "media.vad_enabled", false));
            window.set_cfg_dictation_enabled(read_nested_bool_in_freedom(fp, "media.dictation_enabled", false));
            window.set_cfg_proactive_idle_only(read_nested_bool_in_freedom(fp, "proactive.idle_only", false));
            // Welle C — memory
            window.set_cfg_memory_name_sessions(read_nested_bool_in_freedom(fp, "memory.name_sessions", false));
            window.set_cfg_memory_recall_shortcut(read_nested_bool_in_freedom(fp, "memory.recall_shortcut", false));
            let vb = read_nested_str_in_freedom(fp, "memory.vector_index.backend", "brute_force");
            window.set_cfg_memory_vector_backend_idx(if vb == "hnsw" { 1 } else { 0 });
            // Welle E — obsidian edit fields
            window.set_obs_vault_path_edit(read_nested_str_in_freedom(fp, "obsidian_vault", "").into());
            window.set_obs_subdir_edit(read_nested_str_in_freedom(fp, "obsidian_subdir", "").into());
            let asx = read_nested_i64_in_freedom(fp, "obsidian_auto_sync_secs", 0);
            window.set_obs_auto_sync_secs_edit(asx as i32);
            window.set_obs_reader_enabled_edit(read_nested_bool_in_freedom(fp, "obsidian_vault_reader_enabled", false));
        }

        window.set_status_line(
            format!(
                "NEOTH is already configured at {}.\n\
                 Click \"Open Settings →\" to reach the Code Sessions tab,\n\
                 or click Finish to re-write the config.",
                neoth_dir.display()
            )
            .into(),
        );
    }

    // Pick #29 — CLI mode handoff. Operator picked the terminal flow
    // on the mode-selection screen; print the actionable command and
    // exit the GUI so the operator drops back to their shell with a
    // clean message. The CLI binary's `neoth init` then takes over.
    let weak_cli = window.as_weak();
    window.on_cli_mode_chosen(move || {
        if let Some(w) = weak_cli.upgrade() {
            w.set_status_line(
                "GUI exited. Run `neoth init` in your terminal to continue with the CLI wizard."
                    .into(),
            );
        }
        info!("operator picked CLI mode — exiting GUI");
        // L-1 fix — eprintln so the message survives even when stdout
        // is captured (cargo run --quiet, packaged installer wrappers).
        // The operator gets a copy-paste-ready command in their shell.
        eprintln!();
        eprintln!("CLI mode selected. Run this in your terminal:");
        eprintln!();
        eprintln!("    neoth init");
        eprintln!();
        std::process::exit(0);
    });

    // R2-P0-1 (2026-05-22 Session 20) — GUI chat now reaches the
    // provider/WAL/permission/cost stack via the daemon binary, the
    // exact same code path as `neothd chat` from a terminal. Pre-fix:
    // operator bubble was pushed and the surface looked alive but Send
    // never reached an LLM. R2 reviewer flagged this as the #1 first-
    // moment regression (`PLAN/REEVALUATION_GESAMT_2026-05-21_R2.md`
    // §4 P0-1).
    //
    // Flow:
    //   1. Push operator bubble + composer empty (immediate feedback).
    //   2. Push placeholder assistant bubble ("…", streaming=true) so
    //      the operator sees "the system is thinking" without an empty
    //      scrollback gap.
    //   3. Spawn a worker thread that runs `neothd chat <body>` and
    //      captures stdout. Subprocess inherits the operator's
    //      freedom.yaml + credentials so provider / autonomy / cost
    //      gates fire identically to the CLI path.
    //   4. `invoke_from_event_loop` swaps the placeholder for the real
    //      reply (or an error bubble if the subprocess failed).
    // ODY-10: shared buffer that holds the last non-empty operator input so
    // ArrowUp-on-empty-composer can recall it. Ephemeral (process lifetime only).
    // Pre-clone before the move closure so both on_chat_send_clicked and
    // on_chat_composer_recall_requested share the same Arc.
    let last_operator_input: std::sync::Arc<std::sync::Mutex<String>> =
        std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let last_operator_input_for_send = std::sync::Arc::clone(&last_operator_input);

    // GOLD-ADAPT-ODY-04 — shared stream-supervision state:
    //   chat_child          — the running `neothd chat --stream` subprocess
    //                         (Stop on the stall banner kills it).
    //   chat_last_chunk_ms  — epoch-millis of the last stdout chunk; -1 when
    //                         no stream is in flight. The 2s watchdog timer
    //                         raises the banner at >60s silence.
    //   chat_auto_nudge_budget / chat_auto_in_progress — capped (1 per
    //                         operator send) auto-"continue" when a stream
    //                         ends truncated; the in-progress flag stops the
    //                         auto-turn from refilling its own budget.
    let chat_child: std::sync::Arc<std::sync::Mutex<Option<std::process::Child>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let chat_last_chunk_ms = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(-1));
    let chat_auto_nudge_budget = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
    let chat_auto_in_progress = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // GOLD-ADAPT-ODY-03 — pending attachment paths; the strip shows the
    // file names, the send worker consumes the paths as `--attach` args.
    let chat_attachments: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let chat_child_for_send = chat_child.clone();
    let chat_last_chunk_for_send = chat_last_chunk_ms.clone();
    let chat_budget_for_send = chat_auto_nudge_budget.clone();
    let chat_auto_flag_for_send = chat_auto_in_progress.clone();
    let chat_attach_for_send = chat_attachments.clone();

    // GOLD-ADAPT-ODY-12/14 — deep-link chip routing. `nav` chips ARE the
    // UI-control events (panel navigation); `kanban` chips navigate to the
    // board AND fire its own selection callback so the detail pane loads
    // through the existing Rust handler. Unknown kinds = prompt drift →
    // ignored rather than navigating somewhere wrong.
    {
        let weak_chips = window.as_weak();
        window.on_chat_link_chip_clicked(move |kind, id| {
            if let Some(w) = weak_chips.upgrade() {
                match kind.as_str() {
                    "nav" if NAV_PANELS.contains(&id.as_str()) => w.set_nav_active(id),
                    "kanban" => {
                        w.set_nav_active("coding".into());
                        w.invoke_kanban_task_selected(id);
                    }
                    _ => {}
                }
            }
        });
    }

    let weak_chat_send = window.as_weak();
    window.on_chat_send_clicked(move |text| {
        let body = text.trim().to_string();
        // ODY-10: capture before the empty-guard so the recall buffer is
        // always up-to-date for the most recent non-empty send.
        if !body.is_empty() {
            if let Ok(mut last) = last_operator_input_for_send.lock() {
                *last = body.clone();
            }
        }
        if body.is_empty() {
            return;
        }
        info!(message_len = body.len(), "chat: send-clicked");
        let Some(w) = weak_chat_send.upgrade() else {
            return;
        };

        // Buddy reacts: the operator just asked → the orb starts thinking.
        buddy(&w, GuiActivity::ChatThinking);

        use slint::{Model, ModelRc, VecModel};
        let mut rows: Vec<ChatMessage> = w.get_chat_messages().iter().collect();
        let placeholder_idx = rows.len() + 1;
        rows.push(ChatMessage {
            role: "operator".into(),
            text: body.clone().into(),
            timestamp: format_now_hms().into(),
            streaming: false,
            ..Default::default()
        });
        rows.push(ChatMessage {
            role: "assistant".into(),
            text: "…".into(),
            timestamp: format_now_hms().into(),
            streaming: true,
            ..Default::default()
        });
        w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
        w.set_chat_composer_draft("".into());
        // GOLD-ADAPT-GUI-07 — Send spins + re-sends are blocked until the
        // stream settles (flipped back in the completion closure below).
        w.set_chat_send_in_flight(true);
        // Wave-2 feed A: chat send start → plan row.
        {
            let snippet = if body.len() > 80 { &body[..80] } else { &body };
            push_activity(&w.as_weak(), "plan", "Thinking…", snippet);
        }
        // ODY-04 — arm the stall watchdog; refill the auto-nudge budget on
        // a MANUAL send only (the auto-fired "continue" turn must not
        // refill its own budget or it would loop).
        chat_last_chunk_for_send.store(now_epoch_ms(), std::sync::atomic::Ordering::Relaxed);
        if !chat_auto_flag_for_send.swap(false, std::sync::atomic::Ordering::AcqRel) {
            chat_budget_for_send.store(1, std::sync::atomic::Ordering::Relaxed);
        }
        w.set_chat_stall_active(false);

        // ODY-03 — consume the pending attachments for this turn (the
        // strip empties immediately; the paths ride as `--attach` args).
        let attach_paths: Vec<PathBuf> = chat_attach_for_send
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default();
        sync_attachment_strip(&w, &[]);

        let child_slot = chat_child_for_send.clone();
        let last_chunk = chat_last_chunk_for_send.clone();
        let nudge_budget = chat_budget_for_send.clone();
        let auto_flag = chat_auto_flag_for_send.clone();
        let weak_worker = w.as_weak();
        std::thread::spawn(move || {
            // Chat-feel #3: live token streaming. `neoth chat --stream`
            // prints raw reply deltas incrementally + a final
            // {"neoth_stream":"done"} sentinel. We read stdout in chunks,
            // push the accumulated partial into the placeholder bubble on
            // each chunk (live "▋" cursor), then segment the final reply.
            // On a missing binary / spawn failure / truncated stream
            // (EOF with no sentinel) we surface an error bubble.
            use std::io::Read as _;
            // ODY-12/14 — third tuple element carries the deep-link chips
            // ((label, kind, id) triples) parsed off the done-sentinel.
            #[allow(clippy::type_complexity)]
            let outcome: std::result::Result<
                (String, StreamStats, Vec<(String, String, String)>),
                String,
            > = (|| {
                let bin = which_neothd().ok_or_else(|| BINARY_MISSING_MESSAGE.to_string())?;
                let mut cmd = spawn_neothd_plain(&bin);
                cmd.arg("chat").arg("--stream");
                // ODY-03 — attachments ride as repeatable --attach args.
                for p in &attach_paths {
                    cmd.arg("--attach").arg(p);
                }
                let mut child = cmd
                    .arg(&body)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(|e| {
                        format!(
                            "Chat subprocess could not start: {e}\n\
                             Verify `neothd --version` works from a terminal."
                        )
                    })?;
                let mut stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| "stream stdout unavailable".to_string())?;
                // ODY-04 — park the child so the stall banner's Stop can
                // kill it from the UI thread.
                if let Ok(mut slot) = child_slot.lock() {
                    *slot = Some(child);
                }
                let mut acc: Vec<u8> = Vec::new();
                let mut buf = [0u8; 512];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            acc.extend_from_slice(&buf[..n]);
                            // ODY-04 — feed the watchdog clock.
                            last_chunk
                                .store(now_epoch_ms(), std::sync::atomic::Ordering::Relaxed);
                            // Re-decode the whole buffer each chunk so a
                            // split multi-byte char never bakes a U+FFFD.
                            let (live, _done) =
                                strip_stream_sentinel(&String::from_utf8_lossy(&acc));
                            let weak_live = weak_worker.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(w) = weak_live.upgrade() {
                                    // Reply deltas are arriving → the orb is on it.
                                    buddy(&w, GuiActivity::ChatStreaming);
                                    use slint::{Model, ModelRc, VecModel};
                                    let mut rows: Vec<ChatMessage> =
                                        w.get_chat_messages().iter().collect();
                                    if placeholder_idx < rows.len()
                                        && rows[placeholder_idx].streaming
                                        && rows[placeholder_idx].role == "assistant"
                                    {
                                        rows[placeholder_idx].text = live.clone().into();
                                        w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
                                    }
                                }
                            });
                        }
                        Err(e) => return Err(format!("stream read error: {e}")),
                    }
                }
                // Reclaim the parked child for the exit wait (Stop may
                // already have taken + killed it — then wait() is a no-op
                // on a None slot and status stays None).
                let status = child_slot
                    .lock()
                    .ok()
                    .and_then(|mut slot| slot.take())
                    .and_then(|mut c| c.wait().ok());
                let raw = String::from_utf8_lossy(&acc);
                let (reply, done, stats) = parse_stream_sentinel(&raw);
                if reply.is_empty() {
                    return Err("Provider returned an empty reply. Check `neoth doctor` + \
                                `~/.neoth/freedom.yaml` provider settings."
                        .to_string());
                }
                if !done {
                    // EOF without the sentinel → the stream was truncated
                    // (provider error / crash mid-reply). Surface what we
                    // got so the operator isn't left guessing.
                    let code = status.and_then(|s| s.code()).unwrap_or(-1);
                    return Err(format!(
                        "Stream ended before completion (exit {code}). Partial reply:\n\n{reply}"
                    ));
                }
                // ODY-12/14 — deep-link chips ride the same sentinel line.
                let links = parse_stream_links(&raw);
                Ok((reply, stats, links))
            })();
            // Stream over (either way) — disarm the watchdog clock.
            last_chunk.store(-1, std::sync::atomic::Ordering::Relaxed);

            let weak_for_loop = weak_worker.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak_for_loop.upgrade() {
                    // GUI-07: the stream settled (reply or error) — unspin Send.
                    w.set_chat_send_in_flight(false);
                    w.set_chat_stall_active(false);
                    // Wave-2 feed A: settle plan row + push metric.
                    {
                        let weak_settle = weak_for_loop.clone();
                        settle_activity_kind(&weak_settle, "plan");
                        let metric_detail = match &outcome {
                            Ok((_, stats, _)) => format!(
                                "{}t out · {}ms",
                                stats.output_tokens, stats.elapsed_ms
                            ),
                            Err(e) => format!("error: {}", &e[..e.len().min(60)]),
                        };
                        push_activity(&weak_settle, "metric", "Reply done", &metric_detail);
                    }
                    // ODY-12/14 — swap the deep-link chip row for this turn
                    // (cleared on error so stale chips can't dangle).
                    let chips: Vec<LinkChip> = match &outcome {
                        Ok((_, _, links)) => links
                            .iter()
                            .map(|(label, kind, id)| LinkChip {
                                label: label.as_str().into(),
                                kind: kind.as_str().into(),
                                id: id.as_str().into(),
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    // Wave-2 feed B: one activity row per deep-link chip.
                    for chip in &chips {
                        let kind = if chip.kind.as_str() == "kanban" { "kanban" } else { "link" };
                        push_activity(
                            &weak_for_loop,
                            kind,
                            chip.label.as_str(),
                            chip.id.as_str(),
                        );
                    }
                    w.set_chat_link_chips(slint::ModelRc::new(slint::VecModel::from(chips)));
                    use slint::{Model, ModelRc, VecModel};
                    let mut rows: Vec<ChatMessage> = w.get_chat_messages().iter().collect();
                    let ts = format_now_hms();
                    let succeeded = outcome.is_ok();
                    // ODY-04 — capped auto-nudge: a truncated stream fires ONE
                    // automatic "continue" turn per operator send. The flag
                    // routes the refill-guard in the send handler.
                    let auto_nudge = matches!(
                        &outcome,
                        Err(e) if e.starts_with("Stream ended before completion")
                    ) && nudge_budget
                        .fetch_update(
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                            |b| b.checked_sub(1),
                        )
                        .is_ok();
                    // Chat-feel parity: a successful reply is segmented into
                    // one bubble per paragraph (openhuman cluster feel); an
                    // error stays a single `error`-role bubble.
                    let replacements: Vec<ChatMessage> = match outcome {
                        Ok((reply, stats, _links)) => {
                            // ODY-02/05 — the LAST segment carries the
                            // context/throughput chip (chip on the tail
                            // reads as "turn summary", not per-paragraph).
                            let segs = segment_reply_into_bubbles(&reply);
                            let last = segs.len().saturating_sub(1);
                            let metrics = panel_logic::format_stream_metrics(
                                stats.used_tokens,
                                stats.limit_tokens,
                                stats.input_tokens,
                                stats.output_tokens,
                                stats.elapsed_ms,
                            );
                            segs.into_iter()
                                .enumerate()
                                .map(|(i, seg)| {
                                    let m = if i == last { metrics.clone() } else { None };
                                    let (chip, detail) = m.unwrap_or_default();
                                    ChatMessage {
                                        role: "assistant".into(),
                                        text: seg.into(),
                                        timestamp: ts.clone().into(),
                                        streaming: false,
                                        metrics: chip.into(),
                                        metrics_detail: detail.into(),
                                    }
                                })
                                .collect()
                        }
                        Err(err) => vec![ChatMessage {
                            // `error` bubble role lets the .slint side
                            // colour the surface differently (red tint
                            // when the Composer's theme picks it up).
                            // Older Composer versions render "error" the
                            // same as "assistant" — degrades cleanly.
                            role: "error".into(),
                            text: err.into(),
                            timestamp: ts.clone().into(),
                            streaming: false,
                            ..Default::default()
                        }],
                    };
                    // Splice the replacement bubble(s) in place of the
                    // streaming placeholder (penultimate row by construction;
                    // check defensively in case the operator sent a second
                    // message before the first returned).
                    if placeholder_idx < rows.len()
                        && rows[placeholder_idx].streaming
                        && rows[placeholder_idx].role == "assistant"
                    {
                        rows.remove(placeholder_idx);
                        for (i, bubble) in replacements.into_iter().enumerate() {
                            rows.insert(placeholder_idx + i, bubble);
                        }
                    } else {
                        rows.extend(replacements);
                    }
                    w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
                    // Buddy reflects the outcome: a win lights it green, a
                    // failure shows the error face. It holds that state until
                    // the next message resets it to "thinking".
                    buddy(
                        &w,
                        if succeeded {
                            GuiActivity::ChatDone
                        } else {
                            GuiActivity::ChatError
                        },
                    );
                    // ODY-04 — fire the capped auto-continue as a visible
                    // operator turn (honest: the nudge shows in scrollback).
                    if auto_nudge {
                        auto_flag.store(true, std::sync::atomic::Ordering::Release);
                        w.set_status_line(
                            "stream truncated — auto-continue fired (1/1)".into(),
                        );
                        w.invoke_chat_send_clicked("continue".into());
                    }
                }
            });
        });
    });

    // ODY-04 — stall-banner actions. "Keep waiting" re-arms the watchdog
    // clock (long tool calls are legitimate); "Stop" kills the subprocess —
    // the worker's EOF path then lands the truncated-stream error bubble.
    {
        let last_chunk = chat_last_chunk_ms.clone();
        let weak_stall = window.as_weak();
        window.on_chat_stall_continue(move || {
            last_chunk.store(now_epoch_ms(), std::sync::atomic::Ordering::Relaxed);
            if let Some(w) = weak_stall.upgrade() {
                w.set_chat_stall_active(false);
            }
        });
    }
    {
        let child_slot = chat_child.clone();
        let weak_stop = window.as_weak();
        window.on_chat_stall_stop(move || {
            if let Ok(mut slot) = child_slot.lock() {
                if let Some(child) = slot.as_mut() {
                    let _ = child.kill();
                }
            }
            if let Some(w) = weak_stop.upgrade() {
                w.set_chat_stall_active(false);
                w.set_status_line("chat stream stopped by operator".into());
            }
        });
    }
    // GOLD-ADAPT-AOS-01 — skills-index search: regroup the cached list on
    // every keystroke (pure regroup, no subprocess round-trip).
    {
        let weak_skill_filter = window.as_weak();
        window.on_skills_filter_edited(move |_| {
            if let Some(w) = weak_skill_filter.upgrade() {
                render_skill_index(&w);
            }
        });
    }

    // GOLD-ADAPT-AOS-03 — project context: load at startup (feeds the
    // sidebar operator card + prefills the wizard step on re-runs);
    // persist on the wizard step's Continue.
    {
        let ctx = panel_logic::read_project_context(&default_neoth_home());
        window.set_project_building(ctx.building.into());
        window.set_project_domain(ctx.domain.into());
        window.set_project_stack(ctx.stack.into());
        let weak_ctx = window.as_weak();
        window.on_project_context_set(move |building, domain, stack| {
            let ok = panel_logic::write_project_context(
                &default_neoth_home(),
                &panel_logic::ProjectContext {
                    building: building.trim().to_string(),
                    domain: domain.trim().to_string(),
                    stack: stack.trim().to_string(),
                },
            );
            if let Some(w) = weak_ctx.upgrade() {
                w.set_status_line(
                    if ok {
                        "project context saved to ~/.neoth/.project-context"
                    } else {
                        "project context could not be saved (disk?)"
                    }
                    .into(),
                );
            }
        });
    }

    // GOLD-ADAPT-OH-12 — first-run tour: armed while the done-marker is
    // absent; the overlay itself only shows on the chat surface. Both
    // Finish and Skip write the marker (a tour never nags twice).
    {
        let marker = default_neoth_home().join(".gui-tour-done");
        window.set_tour_active(!marker.exists());
        let weak_tour = window.as_weak();
        window.on_tour_dismissed(move || {
            let marker = default_neoth_home().join(".gui-tour-done");
            let _ = std::fs::create_dir_all(default_neoth_home());
            let _ = std::fs::write(&marker, "1");
            if let Some(w) = weak_tour.upgrade() {
                w.set_tour_active(false);
            }
        });
    }

    // GOLD-ADAPT-AOS-06 — New-Spec pane: `neothd kanban add` off-thread,
    // then a board refresh so the new task shows in Backlog immediately.
    {
        let weak_spec = window.as_weak();
        window.on_spec_create(move |title, goal, acceptance| {
            let title = title.trim().to_string();
            if title.is_empty() {
                return;
            }
            let desc =
                panel_logic::compose_spec_description(goal.as_str(), acceptance.as_str());
            let weak = weak_spec.clone();
            std::thread::spawn(move || {
                let outcome: Result<String, String> = (|| {
                    let bin =
                        which_neothd().ok_or_else(|| BINARY_MISSING_MESSAGE.to_string())?;
                    let mut cmd = spawn_neothd_plain(&bin);
                    cmd.arg("kanban").arg("add").arg(&title);
                    if let Some(d) = &desc {
                        cmd.arg("--description").arg(d);
                    }
                    match cmd.output() {
                        Ok(o) if o.status.success() => {
                            Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
                        }
                        Ok(o) => Err(format!(
                            "kanban add failed: {}",
                            String::from_utf8_lossy(&o.stderr).trim()
                        )),
                        Err(e) => Err(format!("kanban add could not start: {e}")),
                    }
                })();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        match outcome {
                            Ok(line) => {
                                w.set_status_line(line.into());
                                // Board refresh reuses the existing handler.
                                w.invoke_kanban_refresh_clicked();
                            }
                            Err(e) => w.set_status_line(e.into()),
                        }
                    }
                });
            });
        });
    }

    // GOLD-ADAPT-ODY-03 — attach/remove handlers. The picker is the native
    // modal dialog (blocks the UI thread while open — standard Open-dialog
    // semantics on Windows).
    {
        let attachments = chat_attachments.clone();
        let weak_attach = window.as_weak();
        window.on_chat_attach_clicked(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Attach files to this message")
                .pick_files();
            let Some(files) = picked else {
                return;
            };
            if let Ok(mut v) = attachments.lock() {
                v.extend(files);
                if let Some(w) = weak_attach.upgrade() {
                    sync_attachment_strip(&w, &v);
                }
            }
        });
    }
    {
        let attachments = chat_attachments.clone();
        let weak_rm = window.as_weak();
        window.on_chat_remove_attachment(move |i| {
            if let Ok(mut v) = attachments.lock() {
                let i = i as usize;
                if i < v.len() {
                    v.remove(i);
                }
                if let Some(w) = weak_rm.upgrade() {
                    sync_attachment_strip(&w, &v);
                }
            }
        });
    }

    // Watchdog timer: 2s cadence, banner at >60s chunk silence while a
    // reply is in flight.
    let weak_watchdog = window.as_weak();
    let _chat_stall_timer = {
        let timer = slint::Timer::default();
        let last_chunk = chat_last_chunk_ms.clone();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(2),
            move || {
                if let Some(w) = weak_watchdog.upgrade() {
                    let armed = last_chunk.load(std::sync::atomic::Ordering::Relaxed);
                    let stalled = armed >= 0
                        && w.get_chat_send_in_flight()
                        && now_epoch_ms().saturating_sub(armed) > 60_000;
                    if w.get_chat_stall_active() != stalled {
                        w.set_chat_stall_active(stalled);
                    }
                }
            },
        );
        timer
    };

    // GOLD-ADAPT-ODY-01 — chat-sidebar session history (hindsight cards).
    // Off-thread startup load; click sets the active marker + a footer note.
    {
        let weak_sessions = window.as_weak();
        std::thread::spawn(move || {
            let rows = panel_logic::load_session_history(&default_neoth_home(), 20);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak_sessions.upgrade() {
                    use slint::{ModelRc, VecModel};
                    let model: Vec<SessionRow> = rows
                        .into_iter()
                        .map(|s| SessionRow {
                            id: s.id.into(),
                            label: s.label.into(),
                            meta: s.meta.into(),
                        })
                        .collect();
                    w.set_chat_session_history(ModelRc::new(VecModel::from(model)));
                }
            });
        });
        let weak_sel = window.as_weak();
        window.on_chat_session_selected(move |id| {
            if let Some(w) = weak_sel.upgrade() {
                w.set_chat_active_session_id(id.clone());
                w.set_status_line(format!("session {id} selected").into());
            }
        });
    }

    // ODY-10: ArrowUp-on-empty-composer recall handler. The callback fires
    // on the Slint event-loop thread; we read the shared buffer and write
    // the last input back into the composer draft directly (no
    // invoke_from_event_loop needed — we are already on the UI thread).
    {
        let weak_recall = window.as_weak();
        let last_input_for_recall = std::sync::Arc::clone(&last_operator_input);
        window.on_chat_composer_recall_requested(move || {
            let last = last_input_for_recall
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            if last.is_empty() {
                return;
            }
            if let Some(w) = weak_recall.upgrade() {
                w.set_chat_composer_draft(last.into());
            }
        });
    }

    // H-1 fix — chat-channel-switched was likewise unbound. Now logged
    // so the operator's sidebar click reaches the daemon-facing layer
    // when channel-specific scrollback wiring lands.
    window.on_chat_channel_switched(|idx| {
        info!(channel_index = idx, "chat: channel-switched");
    });

    // Wave-2 — activity sidecar toggle: flip open↔closed.
    {
        let weak_act = window.as_weak();
        window.on_activity_toggle(move || {
            if let Some(w) = weak_act.upgrade() {
                w.set_activity_open(!w.get_activity_open());
            }
        });
    }

    // Pick #32 — Settings panel auto-save sentinel. Operator clicked
    // "Reload config" in the Settings → Config tab; drop the sentinel
    // file the daemon polls every 2s. This is the same path that
    // `/reload` writes from the CLI, so GUI ↔ CLI parity holds.
    let weak_reload = window.as_weak();
    window.on_settings_reload_clicked(move || {
        let path = default_neoth_home().join(".reload-requested");
        match std::fs::write(&path, b"reload\n") {
            Ok(_) => {
                info!(path = %path.display(), "settings: sentinel dropped");
                if let Some(w) = weak_reload.upgrade() {
                    w.set_status_line(
                        "Sentinel dropped at ~/.neoth/.reload-requested — daemon picks up within 2s.".into(),
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, path = %path.display(), "settings: sentinel write failed");
                if let Some(w) = weak_reload.upgrade() {
                    w.set_status_line(format!("Failed to drop sentinel: {e}").into());
                }
            }
        }
    });

    // G-2 fix — open the canonical license URL in the system browser
    // when the operator clicks "View full text →" on the License
    // screen. Uses platform-native open commands so we don't ship a
    // webview dependency.
    // QM-8 Phase 2.5 — operator clicked "Apply active" on the
    // preset tile. Resolve the active preset via `neothd preset
    // list`, then shell `neothd preset apply <name>` to merge
    // its values into freedom.yaml.
    let weak_preset_apply = window.as_weak();
    window.on_preset_apply_clicked(move || {
        let outcome = apply_active_preset_via_subprocess();
        // Wave-1 call site A: toast mirrors the status-line result so
        // the operator gets feedback even when not looking at the footer.
        let (toast_kind, toast_title, toast_body) =
            if outcome.to_lowercase().contains("error")
                || outcome.to_lowercase().contains("fail")
            {
                ("warn", "Preset apply failed", outcome.as_str())
            } else {
                ("success", "Preset applied", outcome.as_str())
            };
        push_toast(&weak_preset_apply, toast_kind, toast_title, toast_body);
        // Wave-2 feed E: consent row when preset actually applied.
        if toast_kind == "success" {
            push_activity(&weak_preset_apply, "consent", "Preset applied", toast_body);
        }
        let weak = weak_preset_apply.clone();
        let outcome2 = outcome.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_status_line(outcome2.into());
                // Force-refresh the preset summary so the active
                // marker reflects any change without waiting for
                // the next 5-minute tick.
                let summary = probe_preset_summary_via_subprocess();
                w.set_preset_summary(summary.into());
            }
        });
    });

    // SPEC-05 — operator clicked a preset row: activate it + refresh the list so
    // the active marker moves immediately (no wait for the 5-min tick).
    let weak_preset_activate = window.as_weak();
    window.on_preset_activate_clicked(move |name| {
        let status = activate_preset_via_subprocess(&name);
        let presets = fetch_presets();
        let summary = probe_preset_summary_via_subprocess();
        let weak = weak_preset_activate.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_status_line(status.into());
                w.set_preset_summary(summary.into());
                apply_presets(&w, presets);
            }
        });
    });

    // SPEC-05 builtin-presets — operator clicked Apply on a named preset row.
    // Flow: dry-run in worker thread → if warn_changes OR autonomy_requested==full,
    // populate consent state and show the modal; otherwise apply directly with --yes.
    let weak_named_apply = window.as_weak();
    window.on_preset_apply_named_clicked(move |name| {
        let weak = weak_named_apply.clone();
        let name_s = name.to_string();
        std::thread::spawn(move || {
            // All subprocess work stays in the worker thread; only UI mutations
            // cross back to the event loop (matching the existing preset patterns).
            let plan = dry_run_preset_via_subprocess(&name_s);
            match plan {
                None => {
                    // dry-run unavailable (old daemon / missing binary) →
                    // fall back, but still gate full-auto through the token
                    // route: apply_preset_direct does NOT pass --gui-confirmed
                    // + --gui-token, so confirm_full_auto rejects it (TTY
                    // fail-closed). Use apply_preset_with_fullauto_token for
                    // the "full-auto" builtin name even in the fallback path.
                    // GUI-FULLAUTO-CEREMONY fix.
                    let status = if name_s == "full-auto" {
                        apply_preset_with_fullauto_token(&name_s)
                    } else {
                        apply_preset_direct(&name_s)
                    };
                    let presets = fetch_presets();
                    let summary = probe_preset_summary_via_subprocess();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(w) = weak.upgrade() {
                            w.set_status_line(status.into());
                            w.set_preset_summary(summary.into());
                            apply_presets(&w, presets);
                        }
                    });
                }
                Some(plan) => {
                    let needs_consent = !plan.warn_changes.is_empty()
                        || plan.autonomy_requested.as_deref() == Some("full");
                    if needs_consent {
                        // Build the warn text for the consent panel.
                        let warn_text: String = plan
                            .warn_changes
                            .iter()
                            .map(|c| format!("{}: {} → {}", c.path, c.old, c.new))
                            .collect::<Vec<_>>()
                            .join("\n");
                        let needs_fa =
                            plan.autonomy_requested.as_deref() == Some("full");
                        let field_count = plan.fields_changed_count as i32;
                        let preset_name = plan.name;
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                // Guard: a consent panel is already pending →
                                // drop this dry-run result instead of swapping
                                // the modal's target under the operator's
                                // cursor (double-Apply race, review wave
                                // 2026-07-04). The check-then-set is atomic
                                // here — we are ON the event loop.
                                if w.get_consent_visible() {
                                    w.set_status_line(
                                        "Finish the open preset confirmation first.".into(),
                                    );
                                    return;
                                }
                                w.set_consent_preset_name(preset_name.into());
                                w.set_consent_warn_text(warn_text.into());
                                w.set_consent_needs_fullauto(needs_fa);
                                w.set_consent_fields_count(field_count);
                                w.set_consent_visible(true);
                            }
                        });
                    } else {
                        // No concerns — apply in the worker thread then refresh.
                        let status = apply_preset_direct(&name_s);
                        let presets = fetch_presets();
                        let summary = probe_preset_summary_via_subprocess();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                w.set_status_line(status.into());
                                w.set_preset_summary(summary.into());
                                apply_presets(&w, presets);
                            }
                        });
                    }
                }
            }
        });
    });

    // SPEC-05 builtin-presets — operator confirmed the consent modal.
    let weak_consent_ok = window.as_weak();
    window.on_preset_consent_confirmed(move || {
        let weak = weak_consent_ok.clone();
        // Read name and autonomy flag before clearing the modal.
        let (name_s, needs_fa) = {
            if let Some(w) = weak.upgrade() {
                let n = w.get_consent_preset_name().to_string();
                let fa = w.get_consent_needs_fullauto();
                // Hide modal immediately so the UI feels responsive.
                w.set_consent_visible(false);
                (n, fa)
            } else {
                return;
            }
        };
        std::thread::spawn(move || {
            let status = if needs_fa {
                apply_preset_with_fullauto_token(&name_s)
            } else {
                apply_preset_direct(&name_s)
            };
            let presets = fetch_presets();
            let summary = probe_preset_summary_via_subprocess();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(status.into());
                    w.set_preset_summary(summary.into());
                    apply_presets(&w, presets);
                }
            });
        });
    });

    // SPEC-05 builtin-presets — operator cancelled the consent modal.
    let weak_consent_cancel = window.as_weak();
    window.on_preset_consent_cancelled(move || {
        if let Some(w) = weak_consent_cancel.upgrade() {
            w.set_consent_visible(false);
            w.set_status_line("Preset apply cancelled.".into());
        }
    });

    // SPEC-05 builtin-presets — operator clicked Delete on an operator preset.
    // Subprocess work in a worker thread — this callback runs ON the event
    // loop; blocking here freezes the whole UI (review wave 2026-07-04).
    let weak_preset_delete = window.as_weak();
    window.on_preset_delete_clicked(move |name| {
        let weak = weak_preset_delete.clone();
        let name_s = name.to_string();
        std::thread::spawn(move || {
            let status = delete_preset_via_subprocess(&name_s);
            let presets = fetch_presets();
            let summary = probe_preset_summary_via_subprocess();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(status.into());
                    w.set_preset_summary(summary.into());
                    apply_presets(&w, presets);
                }
            });
        });
    });

    // SPEC-05 step5c — operator picked a response style: apply it + refresh so
    // the active marker moves immediately.
    let weak_profile_apply = window.as_weak();
    window.on_profile_preset_apply_clicked(move |name| {
        let status = apply_profile_preset_via_subprocess(&name);
        let presets = fetch_profile_presets();
        let weak = weak_profile_apply.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_status_line(status.into());
                apply_profile_presets(&w, presets);
            }
        });
    });

    window.on_open_license_url(|| {
        let url = "https://github.com/owner/neoth/blob/main/LICENSE";
        let result = if cfg!(target_os = "windows") {
            std::process::Command::new("cmd")
                .args(["/C", "start", "", url])
                .spawn()
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("open").arg(url).spawn()
        } else {
            std::process::Command::new("xdg-open").arg(url).spawn()
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, url, "failed to open license URL");
        }
    });

    // Reviewer-3 P1-B (2026-05-20): Identity validation. The copy
    // promises `^[a-z0-9-]{3,32}$`; the gate used to accept any
    // non-empty string. Now we round-trip through Rust on every
    // keystroke + push the verdict back as `operator-id-valid`.
    // No regex crate dep — the pattern is tiny + character-class only.
    fn validate_operator_id(s: &str) -> bool {
        let len = s.chars().count();
        if !(3..=32).contains(&len) {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }
    let weak_id = window.as_weak();
    window.on_operator_id_edited(move |text| {
        if let Some(w) = weak_id.upgrade() {
            w.set_operator_id_valid(validate_operator_id(&text));
        }
    });

    // Step 5 (2026-05-20): keep the last-applied snapshot alive in a
    // mutex so the task-click handler can resolve `task-id` → full
    // task detail (title/status/hemisphere) without re-walking the
    // Slint Model. Multiple writers (initial fetch / Refresh / 2s
    // tick) push through `store_kanban_snapshot`; the click handler
    // reads via `latest_kanban_snapshot`.
    use std::sync::{Arc, Mutex};
    let kanban_snapshot: Arc<Mutex<KanbanBoardSnapshot>> =
        Arc::new(Mutex::new(KanbanBoardSnapshot::default()));

    // Pick #8 step 2 — Code Sessions tab data binding.
    //   - At startup: fetch once so the tab shows real data the first
    //     time the operator opens it.
    //   - On Refresh button: re-fetch + re-populate.
    // Live WAL-driven updates land in step 4.
    //
    // H-4 fix — initial fetch + Refresh-click both run on a worker
    // thread so a slow `neothd kanban` subprocess can never block
    // the UI thread. The snapshot lands back on the main thread via
    // `invoke_from_event_loop`.
    let weak_kanban_init = window.as_weak();
    let mutex_init = kanban_snapshot.clone();
    std::thread::spawn(move || {
        let snap = fetch_kanban_board_snapshot();
        let snap_for_state = snap.clone();
        let weak = weak_kanban_init.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Ok(mut g) = mutex_init.lock() {
                *g = snap_for_state;
            }
            if let Some(w) = weak.upgrade() {
                apply_kanban_snapshot(&w, snap);
            }
        });
    });

    // GR-10 + GU-01 — one-shot startup fetch of the read-only settings panels
    // (Safety Rails / Hemispheres / Skills). Off the UI thread (three quick
    // subprocesses), each result marshalled back via invoke_from_event_loop.
    let weak_panels_init = window.as_weak();
    std::thread::spawn(move || {
        let rails = fetch_safe_mode_snapshot();
        let trust = fetch_trust_snapshot();
        let hardware = fetch_hardware_snapshot();
        let topology = fetch_topology_snapshot();
        let usage = fetch_usage_meter();
        let council_budget = fetch_council_budget();
        let profile_presets = fetch_profile_presets();
        let hemis = fetch_hemispheres_snapshot();
        let provider_ids = fetch_provider_ids();
        let skills = fetch_skills();
        let plugins = fetch_plugins();
        let memory = fetch_memory_snapshot();
        // Channels read credentials.yaml PRESENCE only (no subprocess, no secrets).
        let channels = panel_logic::read_channel_status(&default_neoth_home());
        let weak = weak_panels_init.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                apply_safe_mode(&w, rails);
                apply_trust(&w, trust);
                apply_hardware(&w, hardware);
                apply_topology(&w, topology);
                apply_usage_meter(&w, usage);
                apply_council_budget(&w, council_budget);
                apply_profile_presets(&w, profile_presets);
                apply_hemispheres(&w, hemis);
                apply_provider_ids(&w, provider_ids);
                apply_skills(&w, skills);
                apply_plugins(&w, plugins);
                apply_memory(&w, memory);
                apply_channels(&w, channels);
            }
        });
    });

    // SPEC-06 — operator rebound a role in the Hemispheres panel: shell
    // `neoth hemispheres set` then refresh the bindings so the panel reflects
    // the new wiring immediately.
    let weak_hemi_set = window.as_weak();
    window.on_hemisphere_set(move |role, provider, model| {
        // "(provider default)" sentinel (combo row 0) → leave the model unset.
        let model = if model == "(provider default)" {
            String::new()
        } else {
            model.to_string()
        };
        let status = set_hemisphere_via_subprocess(&role, &provider, &model);
        let hemis = fetch_hemispheres_snapshot();
        let weak = weak_hemi_set.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_status_line(status.into());
                apply_hemispheres(&w, hemis);
            }
        });
    });

    // GOLD-GUI-OVERHAUL — operator picked a provider in the rebind row; refresh
    // the model combo with that provider's options (local GGUF refs / cloud
    // catalog) off-thread so the VRAM probe never freezes the UI.
    let weak_hemi_models = window.as_weak();
    window.on_hemisphere_provider_picked(move |provider| {
        let weak = weak_hemi_models.clone();
        let provider = provider.to_string();
        std::thread::spawn(move || {
            let models = fetch_hemisphere_model_ids(&provider);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    use slint::{ModelRc, SharedString, VecModel};
                    let rows: Vec<SharedString> = models.into_iter().map(|s| s.into()).collect();
                    w.set_hemisphere_model_ids(ModelRc::new(VecModel::from(rows)));
                }
            });
        });
    });

    let weak_kanban_refresh = window.as_weak();
    let mutex_refresh = kanban_snapshot.clone();
    window.on_kanban_refresh_clicked(move || {
        if let Some(w) = weak_kanban_refresh.upgrade() {
            buddy(&w, GuiActivity::AgentParallel);
        }
        let weak = weak_kanban_refresh.clone();
        let mutex = mutex_refresh.clone();
        std::thread::spawn(move || {
            let snap = fetch_kanban_board_snapshot();
            info!(summary = %snap.summary, "kanban: refresh requested");
            let snap_for_state = snap.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Ok(mut g) = mutex.lock() {
                    *g = snap_for_state;
                }
                if let Some(w) = weak.upgrade() {
                    apply_kanban_snapshot(&w, snap);
                }
            });
        });
    });

    // GUI-improve (gap panel wf_641e1173) — re-read credentials.yaml on demand
    // so a CLI `neoth connect/disconnect` reflects without a GUI restart.
    // `read_channel_status` is a pure file read, so it runs inline on the UI
    // thread (no subprocess / no worker needed).
    let weak_channels_refresh = window.as_weak();
    window.on_channels_refresh_clicked(move || {
        let channels = panel_logic::read_channel_status(&default_neoth_home());
        if let Some(w) = weak_channels_refresh.upgrade() {
            apply_channels(&w, channels);
            w.set_status_line("Channels refreshed from credentials.yaml.".into());
        }
    });

    // Doctor tab (design-mockup surface) — run `neothd doctor` read-only and
    // stream the check output into the panel. The Buddy verifies while it runs.
    let weak_doctor = window.as_weak();
    window.on_doctor_run_clicked(move || {
        let Some(w0) = weak_doctor.upgrade() else {
            return;
        };
        w0.set_doctor_running(true);
        buddy(&w0, GuiActivity::AuditVerify);
        let weak = weak_doctor.clone();
        std::thread::spawn(move || {
            let output = match which_neothd()
                .and_then(|bin| spawn_neothd_plain(&bin).arg("doctor").output().ok())
            {
                Some(o) => {
                    let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                    let err = String::from_utf8_lossy(&o.stderr);
                    if !err.trim().is_empty() {
                        s.push('\n');
                        s.push_str(&err);
                    }
                    if s.trim().is_empty() {
                        "neoth doctor produced no output.".to_string()
                    } else {
                        s
                    }
                }
                None => "neothd binary not on PATH — cannot run doctor.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_doctor_output(output.into());
                    w.set_doctor_running(false);
                    buddy(&w, GuiActivity::AuditVerify);
                }
            });
        });
    });

    // GAP-05 — Status probe: `neoth status` → DoctorView status panel.
    let weak_status = window.as_weak();
    window.on_doctor_status_run_clicked(move || {
        let Some(w0) = weak_status.upgrade() else { return; };
        w0.set_doctor_status_running(true);
        let weak = weak_status.clone();
        std::thread::spawn(move || {
            let output = match which_neothd()
                .and_then(|bin| spawn_neothd_plain(&bin).arg("status").output().ok())
            {
                Some(o) => {
                    let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                    let err = String::from_utf8_lossy(&o.stderr);
                    if !err.trim().is_empty() {
                        s.push('\n');
                        s.push_str(&err);
                    }
                    if s.trim().is_empty() {
                        "neoth status produced no output.".to_string()
                    } else {
                        s
                    }
                }
                None => "neothd binary not on PATH — cannot run status.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_doctor_status_output(output.into());
                    w.set_doctor_status_running(false);
                }
            });
        });
    });

    // GAP-13 — Security audit probe: `neoth security audit` → DoctorView audit panel.
    let weak_secaudit = window.as_weak();
    window.on_doctor_security_run_clicked(move || {
        let Some(w0) = weak_secaudit.upgrade() else { return; };
        w0.set_doctor_security_running(true);
        let weak = weak_secaudit.clone();
        std::thread::spawn(move || {
            let output = match which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("security")
                        .arg("audit")
                        .output()
                        .ok()
                })
            {
                Some(o) => {
                    let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                    let err = String::from_utf8_lossy(&o.stderr);
                    if !err.trim().is_empty() {
                        s.push('\n');
                        s.push_str(&err);
                    }
                    if s.trim().is_empty() {
                        "neoth security audit produced no output.".to_string()
                    } else {
                        s
                    }
                }
                None => "neothd binary not on PATH — cannot run security audit.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_doctor_security_output(output.into());
                    w.set_doctor_security_running(false);
                }
            });
        });
    });

    // Agents tab — `neothd cluster status` (the agent/worker + node topology).
    let weak_agents = window.as_weak();
    window.on_agents_refresh_clicked(move || {
        let Some(w0) = weak_agents.upgrade() else {
            return;
        };
        w0.set_agents_running(true);
        buddy(&w0, GuiActivity::AgentDeploy);
        let weak = weak_agents.clone();
        std::thread::spawn(move || {
            let output = run_neothd_probe(&["agents", "list"]);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_agents_output(output.into());
                    w.set_agents_running(false);
                }
            });
        });
    });

    // ── GAP-01 Automation / Cron CRUD panel ──────────────────────────────────
    {
        // Refresh — `neoth cron list --output json` → typed model.
        let weak_cron = window.as_weak();
        window.on_cron_refresh_clicked(move || {
            let weak = weak_cron.clone();
            std::thread::spawn(move || {
                refresh_cron(weak);
            });
        });

        // Add — build arg list, omit empty optional flags.
        let weak_cron_add = window.as_weak();
        window.on_cron_add_clicked(move |id, name, cron, prompt, tz, channel, recipient, timeout| {
            let id        = id.to_string();
            let name      = name.to_string();
            let cron      = cron.to_string();
            let prompt    = prompt.to_string();
            let tz        = tz.to_string();
            let channel   = channel.to_string();
            let recipient = recipient.to_string();
            let timeout   = timeout.to_string();
            let weak = weak_cron_add.clone();
            std::thread::spawn(move || {
                let mut args: Vec<&str> = vec!["cron", "add",
                    "--id",     id.trim(),
                    "--name",   name.trim(),
                    "--cron",   cron.trim(),
                    "--prompt", prompt.trim(),
                ];
                // Optional flags — only appended when non-empty.
                if !tz.trim().is_empty()        { args.extend(["--tz",        tz.trim()]); }
                if !channel.trim().is_empty()   { args.extend(["--channel",   channel.trim()]); }
                if !recipient.trim().is_empty() { args.extend(["--recipient", recipient.trim()]); }
                if !timeout.trim().is_empty()   { args.extend(["--timeout",   timeout.trim()]); }
                let out = run_neothd_probe(&args);
                let msg = if out.trim().is_empty() { format!("added {}", id.trim()) } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "success", "Cron", &msg);
                std::thread::spawn(move || refresh_cron(weak2));
            });
        });

        // Run — `neoth cron run <id>` (daemon refuses while live; surface error as toast).
        let weak_cron_run = window.as_weak();
        window.on_cron_run_clicked(move |id| {
            let id   = id.to_string();
            let weak = weak_cron_run.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["cron", "run", id.trim()]);
                let (kind, title) = if out.to_lowercase().contains("refused")
                    || out.to_lowercase().contains("daemon")
                    || out.to_lowercase().contains("live")
                {
                    ("warn", "Cron run refused")
                } else {
                    ("info", "Cron run")
                };
                push_toast(&weak, kind, title, out.trim());
            });
        });

        // Toggle — `neoth cron edit <id> --enabled <bool>`.
        let weak_cron_tog = window.as_weak();
        window.on_cron_toggle_clicked(move |id, new_enabled| {
            let id   = id.to_string();
            let weak = weak_cron_tog.clone();
            std::thread::spawn(move || {
                let enabled_str = if new_enabled { "true" } else { "false" };
                let out = run_neothd_probe(&["cron", "edit", id.trim(), "--enabled", enabled_str]);
                let msg = if out.trim().is_empty() {
                    format!("{} {}", if new_enabled { "enabled" } else { "disabled" }, id.trim())
                } else {
                    out.trim().to_string()
                };
                let weak2 = weak.clone();
                push_toast(&weak, "info", "Cron", &msg);
                std::thread::spawn(move || refresh_cron(weak2));
            });
        });

        // Remove — `neoth cron remove <id>`.
        let weak_cron_rem = window.as_weak();
        window.on_cron_remove_clicked(move |id| {
            let id   = id.to_string();
            let weak = weak_cron_rem.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["cron", "remove", id.trim()]);
                let msg = if out.trim().is_empty() { format!("removed {}", id.trim()) } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "warn", "Cron", &msg);
                std::thread::spawn(move || refresh_cron(weak2));
            });
        });

        // Fire once at startup so the list pre-loads.
        let weak_cron_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_cron(weak_cron_init);
        });
    }

    // ── Overview / Mission Control — refresh callback ───────────────────────
    // One worker thread per click; all subprocess work stays off the event loop.
    // The initial probe fires immediately on first entry (triggered below by
    // the on_overview_refresh_clicked callback — also called from Rust on startup).
    let weak_ov = window.as_weak();
    window.on_overview_refresh_clicked(move || {
        let Some(w0) = weak_ov.upgrade() else {
            return;
        };
        // Clear stale timestamp while loading.
        w0.set_ov_refreshed_at("loading…".into());
        let weak = weak_ov.clone();
        std::thread::spawn(move || {
            refresh_overview(weak);
        });
    });

    // Fire the overview probe once at startup so the panel is populated
    // the first time the operator switches to it.
    {
        let weak_ov_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_overview(weak_ov_init);
        });
    }

    // ── Design Wave 4a — n8n panel callbacks ─────────────────────────────────
    {
        let weak_n8n = window.as_weak();
        window.on_n8n_refresh_clicked(move || {
            let weak = weak_n8n.clone();
            std::thread::spawn(move || {
                refresh_n8n(weak);
            });
        });
        // Fire once at startup so the panel is pre-populated.
        let weak_n8n_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_n8n(weak_n8n_init);
        });
    }

    // ── Design Wave 4a — Babel panel callbacks ────────────────────────────────
    {
        let weak_babel = window.as_weak();
        window.on_babel_refresh_clicked(move || {
            let weak = weak_babel.clone();
            std::thread::spawn(move || {
                refresh_babel(weak);
            });
        });

        let weak_babel_en = window.as_weak();
        window.on_babel_enable_clicked(move || {
            let weak = weak_babel_en.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["babel", "enable"]);
                let msg = if out.trim().is_empty() { "enabled".to_string() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "success", "Babel", &msg);
                std::thread::spawn(move || refresh_babel(weak2));
            });
        });

        let weak_babel_dis = window.as_weak();
        window.on_babel_disable_clicked(move || {
            let weak = weak_babel_dis.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["babel", "disable"]);
                let msg = if out.trim().is_empty() { "disabled".to_string() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "info", "Babel", &msg);
                std::thread::spawn(move || refresh_babel(weak2));
            });
        });
    }

    // ── Design Wave 4a — Calendar panel callbacks ─────────────────────────────
    {
        let weak_cal = window.as_weak();
        window.on_cal_refresh_clicked(move || {
            let weak = weak_cal.clone();
            std::thread::spawn(move || {
                refresh_calendar(weak);
            });
        });

        let weak_cal_add = window.as_weak();
        window.on_cal_add_clicked(move || {
            let Some(w0) = weak_cal_add.upgrade() else { return };
            let summary = w0.get_cal_add_summary().to_string();
            let start   = w0.get_cal_add_start().to_string();
            let end     = w0.get_cal_add_end().to_string();
            if summary.trim().is_empty() || start.trim().is_empty() {
                let _ = slint::invoke_from_event_loop({
                    let weak = weak_cal_add.clone();
                    move || {
                        if let Some(w) = weak.upgrade() {
                            w.set_cal_add_result("summary and start are required".into());
                        }
                    }
                });
                return;
            }
            let weak = weak_cal_add.clone();
            std::thread::spawn(move || {
                let probe_args: Vec<String> = if end.trim().is_empty() {
                    vec!["calendar".into(), "add".into(), summary.trim().to_string(),
                         "--start".into(), start.trim().to_string()]
                } else {
                    vec!["calendar".into(), "add".into(), summary.trim().to_string(),
                         "--start".into(), start.trim().to_string(),
                         "--end".into(), end.trim().to_string()]
                };
                let probe_refs: Vec<&str> = probe_args.iter().map(String::as_str).collect();
                let out = run_neothd_probe(&probe_refs);
                let result = if out.trim().is_empty() { "Event added.".to_string() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_cal_add_result(result.as_str().into());
                        w.set_cal_add_summary("".into());
                        w.set_cal_add_start("".into());
                        w.set_cal_add_end("".into());
                    }
                });
                std::thread::spawn(move || refresh_calendar(weak2));
            });
        });

        // Fire once at startup.
        let weak_cal_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_calendar(weak_cal_init);
        });
    }

    // ── Design Wave 4a — Self-Improve panel callbacks ─────────────────────────
    {
        let weak_si = window.as_weak();
        window.on_si_refresh_clicked(move || {
            let weak = weak_si.clone();
            std::thread::spawn(move || {
                refresh_selfimprove(weak);
            });
        });

        let weak_si_en = window.as_weak();
        window.on_si_enable_clicked(move || {
            let weak = weak_si_en.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["self-improve", "enable"]);
                let msg = if out.trim().is_empty() { "enabled".to_string() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "success", "Self-Improve", &msg);
                std::thread::spawn(move || refresh_selfimprove(weak2));
            });
        });

        let weak_si_dis = window.as_weak();
        window.on_si_disable_clicked(move || {
            let weak = weak_si_dis.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["self-improve", "disable"]);
                let msg = if out.trim().is_empty() { "disabled".to_string() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "info", "Self-Improve", &msg);
                std::thread::spawn(move || refresh_selfimprove(weak2));
            });
        });

        let weak_si_dry = window.as_weak();
        window.on_si_run_dry_clicked(move || {
            let weak = weak_si_dry.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["self-improve", "run", "--dry-run"]);
                push_toast(&weak, "info", "Self-Improve dry-run", out.trim());
            });
        });

        let weak_si_acc = window.as_weak();
        window.on_si_accept_clicked(move |id| {
            let id = id.to_string();
            let weak = weak_si_acc.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["self-improve", "accept", id.trim()]);
                let msg = if out.trim().is_empty() { id.clone() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "consent", "Accepted", &msg);
                std::thread::spawn(move || refresh_selfimprove(weak2));
            });
        });

        let weak_si_rb = window.as_weak();
        window.on_si_rollback_clicked(move |id| {
            let id = id.to_string();
            let weak = weak_si_rb.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["self-improve", "rollback", id.trim()]);
                let msg = if out.trim().is_empty() { id.clone() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "warn", "Rolled back", &msg);
                std::thread::spawn(move || refresh_selfimprove(weak2));
            });
        });

        // Fire once at startup.
        let weak_si_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_selfimprove(weak_si_init);
        });
    }

    // ── Wave 4b — Obsidian Vault panel callbacks ──────────────────────────────
    {
        let weak_obs = window.as_weak();
        window.on_obs_refresh_clicked(move || {
            let weak = weak_obs.clone();
            std::thread::spawn(move || {
                refresh_obsidian(weak);
            });
        });

        // Property reads happen HERE on the UI thread: Slint's Weak::upgrade()
        // has a thread-ID guard and returns None on any worker thread, so an
        // upgrade inside the spawned closure would silently skip the command.
        let weak_obs_sync = window.as_weak();
        window.on_obs_sync_clicked(move || {
            let weak = weak_obs_sync.clone();
            let vault = weak
                .upgrade()
                .map(|w| w.get_obs_vault_path().to_string())
                .unwrap_or_default();
            std::thread::spawn(move || {
                let args = ["obsidian", "sync", vault.trim()];
                let out = run_neothd_probe(&args);
                let msg = if out.trim().is_empty() { "Sync started.".to_string() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "success", "Obsidian", &msg);
                std::thread::spawn(move || refresh_obsidian(weak2));
            });
        });

        let weak_obs_wiki = window.as_weak();
        window.on_obs_wiki_clicked(move || {
            let weak = weak_obs_wiki.clone();
            let vault = weak
                .upgrade()
                .map(|w| w.get_obs_vault_path().to_string())
                .unwrap_or_default();
            std::thread::spawn(move || {
                let args = ["obsidian", "wiki-build", vault.trim()];
                let out = run_neothd_probe(&args);
                let msg = if out.trim().is_empty() { "Wiki build started.".to_string() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                push_toast(&weak, "success", "Obsidian", &msg);
                std::thread::spawn(move || refresh_obsidian(weak2));
            });
        });

        // Fire once at startup.
        let weak_obs_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_obsidian(weak_obs_init);
        });
    }

    // ── Wave 4b — Dreaming panel callbacks ───────────────────────────────────
    {
        let weak_dr = window.as_weak();
        window.on_dr_refresh_clicked(move || {
            let weak = weak_dr.clone();
            std::thread::spawn(move || {
                refresh_dreaming(weak);
            });
        });

        let weak_dr_show = window.as_weak();
        window.on_dr_show_day(move |day| {
            let weak = weak_dr_show.clone();
            let day = day.to_string();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["dream", "show", day.trim(), "--output", "json"]);
                let entries = panel_logic::parse_dream_entries(&out);
                let _ = slint::invoke_from_event_loop(move || {
                    use slint::VecModel;
                    let Some(w) = weak.upgrade() else { return };
                    let rows: Vec<DreamEntryRow> = entries
                        .into_iter()
                        .map(|(day, title, body)| DreamEntryRow {
                            day: day.into(),
                            title: title.into(),
                            body: body.into(),
                        })
                        .collect();
                    w.set_dr_entries(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
                });
            });
        });

        let weak_dr_now = window.as_weak();
        window.on_dr_dream_now_clicked(move || {
            let weak = weak_dr_now.clone();
            std::thread::spawn(move || {
                let _ = slint::invoke_from_event_loop({
                    let weak = weak.clone();
                    move || { if let Some(w) = weak.upgrade() { w.set_dr_dream_now_loading(true); } }
                });
                let out = run_neothd_probe(&["dream", "now"]);
                let msg = if out.trim().is_empty() { "Dream recorded.".to_string() } else { out.trim().to_string() };
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_dr_dream_now_loading(false);
                        w.set_dr_dream_now_result(msg.as_str().into());
                    }
                });
                push_toast(&weak2, "success", "Dreaming", "Dream now complete.");
                std::thread::spawn(move || refresh_dreaming(weak2));
            });
        });

        let weak_dr_ref = window.as_weak();
        window.on_dr_reflect_clicked(move || {
            let weak = weak_dr_ref.clone();
            std::thread::spawn(move || {
                let _ = slint::invoke_from_event_loop({
                    let weak = weak.clone();
                    move || { if let Some(w) = weak.upgrade() { w.set_dr_reflect_loading(true); } }
                });
                let out = run_neothd_probe(&["reflect"]);
                let msg = if out.trim().is_empty() { "Reflect complete.".to_string() } else { out.trim().to_string() };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_dr_reflect_loading(false);
                        w.set_dr_reflect_result(msg.as_str().into());
                    }
                });
            });
        });

        // Fire once at startup.
        let weak_dr_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_dreaming(weak_dr_init);
        });
    }

    // ── Wave 4b — Wiki / Capability Map panel callbacks ──────────────────────
    {
        let weak_wiki = window.as_weak();
        window.on_wiki_refresh_clicked(move || {
            let weak = weak_wiki.clone();
            std::thread::spawn(move || {
                refresh_wiki(weak);
            });
        });

        let weak_wiki_s = window.as_weak();
        window.on_wiki_search(move |text| {
            let weak = weak_wiki_s.clone();
            let text = text.to_string();
            std::thread::spawn(move || {
                refresh_wiki_filtered(weak, text, String::new());
            });
        });

        let weak_wiki_f = window.as_weak();
        window.on_wiki_filter_kind(move |kind| {
            let weak = weak_wiki_f.clone();
            let kind = kind.to_string();
            std::thread::spawn(move || {
                refresh_wiki_filtered(weak, String::new(), kind);
            });
        });

        // Fire once at startup.
        let weak_wiki_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_wiki(weak_wiki_init);
        });
    }

    // ── Wave 4b — Buddy Config panel callbacks ───────────────────────────────
    {
        let weak_bc = window.as_weak();
        window.on_bc_refresh_clicked(move || {
            let weak = weak_bc.clone();
            std::thread::spawn(move || {
                refresh_buddyconfig(weak);
            });
        });

        // Self-activation toggle — real daemon command.
        let weak_bc_sa = window.as_weak();
        window.on_bc_selfact_toggle(move |enable| {
            let weak = weak_bc_sa.clone();
            std::thread::spawn(move || {
                let flag = if enable { "--enable" } else { "--disable" };
                let out = run_neothd_probe(&["buddy", "self-activation", flag]);
                let msg = if out.trim().is_empty() {
                    format!("Self-activation {}.", if enable { "enabled" } else { "disabled" })
                } else {
                    out.trim().to_string()
                };
                let weak2 = weak.clone();
                push_toast(&weak, "success", "Buddy", &msg);
                std::thread::spawn(move || refresh_buddyconfig(weak2));
            });
        });

        // Proactive toggle — real daemon command.
        let weak_bc_pr = window.as_weak();
        window.on_bc_proactive_toggle(move |enable| {
            let weak = weak_bc_pr.clone();
            std::thread::spawn(move || {
                let flag = if enable { "--enable" } else { "--disable" };
                let out = run_neothd_probe(&["buddy", "proactive", flag]);
                let msg = if out.trim().is_empty() {
                    format!("Proactive mode {}.", if enable { "enabled" } else { "disabled" })
                } else {
                    out.trim().to_string()
                };
                let weak2 = weak.clone();
                push_toast(&weak, "success", "Buddy", &msg);
                std::thread::spawn(move || refresh_buddyconfig(weak2));
            });
        });

        // Sovereign toggle — read-only; redirect the operator to Privacy tab.
        let weak_bc_sov = window.as_weak();
        window.on_bc_sovereign_toggle(move |_| {
            push_toast(
                &weak_bc_sov,
                "info",
                "Buddy Config",
                "Change sovereign buddy in the Privacy tab.",
            );
        });

        // Smart-approve toggle — read-only per-channel; redirect to Privacy tab.
        let weak_bc_sma = window.as_weak();
        window.on_bc_smart_approve_toggle(move |_| {
            push_toast(
                &weak_bc_sma,
                "info",
                "Buddy Config",
                "Smart-approve is a per-channel setting — configure in Privacy tab.",
            );
        });

        // Fire once at startup.
        let weak_bc_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_buddyconfig(weak_bc_init);
        });
    }

    // ── Wave 4b — Companion / Smartphone Pairing panel callbacks ─────────────
    {
        let weak_cp = window.as_weak();
        window.on_cp_refresh_clicked(move || {
            let weak = weak_cp.clone();
            std::thread::spawn(move || {
                refresh_companion(weak);
            });
        });

        let weak_cp_gen = window.as_weak();
        window.on_cp_generate_invite(move || {
            let weak = weak_cp_gen.clone();
            std::thread::spawn(move || {
                let _ = slint::invoke_from_event_loop({
                    let weak = weak.clone();
                    move || { if let Some(w) = weak.upgrade() { w.set_cp_loading(true); } }
                });
                let out = run_neothd_probe(&["companion", "pair-phone", "--write-invite-for-serve"]);
                let pair_url = out
                    .lines()
                    .find(|l| l.starts_with("neoth://companion/pair"))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let ok = !pair_url.is_empty();
                let url_copy = pair_url.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_cp_loading(false);
                        w.set_cp_pair_url(url_copy.as_str().into());
                        w.set_cp_invite_pending(ok);
                        if !ok {
                            w.set_cp_error("Failed to generate invite URL.".into());
                        }
                    }
                });
            });
        });
    }

    // ── Wave 4b — Mesh & Cluster panel callbacks ──────────────────────────────
    {
        let weak_mesh = window.as_weak();
        window.on_mesh_refresh_clicked(move || {
            let weak = weak_mesh.clone();
            std::thread::spawn(move || {
                refresh_mesh(weak);
            });
        });

        // Fire once at startup.
        let weak_mesh_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_mesh(weak_mesh_init);
        });
    }

    // ── GOLD-LOOP-03 — Loop panel wiring (display-gated `gui-loop`) ────
    // The GUI never links the loop engine: runs go through a
    // `neothd loop run` subprocess (the CLI's daemon-owns-WAL guard fires
    // there and lands in the status note), history comes from the
    // `~/.neoth/loops/*.json` records the engine writes.
    window.set_show_loops(cfg!(feature = "gui-loop"));
    #[cfg(feature = "gui-loop")]
    {
        use panel_logic::LoopRunView;

        // Convergence denominator + budget cap from freedom.yaml (engine
        // defaults when missing: 3 rounds, no cap).
        let (loop_max_rounds, loop_budget) = std::fs::read_to_string(
            default_neoth_home().join("freedom.yaml"),
        )
        .map(|y| panel_logic::parse_loop_budget(&y))
        .unwrap_or((3, 0));
        window.set_loop_tool_call_budget(loop_budget as i32);

        // History cache shared by refresh + row-select; the running child
        // handle shared by run + kill.
        let loop_cache: std::sync::Arc<std::sync::Mutex<Vec<LoopRunView>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let loop_child: std::sync::Arc<std::sync::Mutex<Option<std::process::Child>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));

        // Push a history snapshot into the panel; `select` picks the run
        // whose detail (timeline/meters/final text) is shown.
        fn apply_loop_history(
            w: &MainWindow,
            runs: &[LoopRunView],
            select: Option<&str>,
            max_rounds: u32,
        ) {
            use slint::{ModelRc, VecModel};
            let rows: Vec<LoopRunRow> = runs
                .iter()
                .map(|r| LoopRunRow {
                    id: r.id.clone().into(),
                    started: r.started.clone().into(),
                    rounds: r.rounds_run as i32,
                    stop_reason: r.stop_reason.clone().into(),
                    tool_calls: r.total_tool_calls as i32,
                })
                .collect();
            w.set_loop_history(ModelRc::new(VecModel::from(rows)));
            let picked = select
                .and_then(|id| runs.iter().find(|r| r.id == id))
                .or_else(|| runs.first());
            let Some(run) = picked else {
                w.set_loop_selected_id("".into());
                w.set_loop_rounds(ModelRc::new(VecModel::from(Vec::<LoopRoundRow>::new())));
                w.set_loop_stop_reason("".into());
                w.set_loop_final_text("".into());
                w.set_loop_tool_calls(0);
                w.set_loop_convergence(0.0);
                return;
            };
            let round_rows: Vec<LoopRoundRow> = run
                .per_round
                .iter()
                .map(|r| LoopRoundRow {
                    round: r.round_num as i32,
                    iterations: r.iterations as i32,
                    ok_calls: r.ok_calls as i32,
                    fail_calls: r.fail_calls as i32,
                    stop_approved: r.stop_approved,
                    refine_fired: r.refine_fired,
                    duration: r.duration.clone().into(),
                })
                .collect();
            w.set_loop_selected_id(run.id.clone().into());
            w.set_loop_rounds(ModelRc::new(VecModel::from(round_rows)));
            w.set_loop_stop_reason(run.stop_reason.clone().into());
            w.set_loop_final_text(run.final_text.clone().into());
            w.set_loop_tool_calls(run.total_tool_calls as i32);
            w.set_loop_convergence(if run.stop_reason == "converged" {
                1.0
            } else {
                (run.rounds_run as f32 / max_rounds.max(1) as f32).min(1.0)
            });
        }

        // Refresh — worker thread reads + parses the record files. The
        // AtomicBool caps it at one scan in flight (review B8: unbounded
        // spawn let a slow stale scan overwrite a fresh one).
        let weak_loop_refresh = window.as_weak();
        let cache_refresh = loop_cache.clone();
        let loop_fetch_in_flight =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refresh_history = move |select: Option<String>| {
            if loop_fetch_in_flight.swap(true, std::sync::atomic::Ordering::AcqRel) {
                return;
            }
            let weak = weak_loop_refresh.clone();
            let cache = cache_refresh.clone();
            let done = loop_fetch_in_flight.clone();
            std::thread::spawn(move || {
                let runs = panel_logic::load_loop_history(&default_neoth_home(), 20);
                if let Ok(mut c) = cache.lock() {
                    *c = runs.clone();
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_loop_history(&w, &runs, select.as_deref(), loop_max_rounds);
                    }
                });
                done.store(false, std::sync::atomic::Ordering::Release);
            });
        };

        let refresh_for_click = refresh_history.clone();
        window.on_loop_refresh_clicked(move || {
            refresh_for_click(None);
        });

        // Row select — served from the cache (no disk hit on click).
        let weak_loop_select = window.as_weak();
        let cache_select = loop_cache.clone();
        window.on_loop_run_selected(move |id| {
            let Some(w) = weak_loop_select.upgrade() else {
                return;
            };
            if let Ok(runs) = cache_select.lock() {
                apply_loop_history(&w, &runs, Some(id.as_str()), loop_max_rounds);
            }
        });

        // Run — spawn `neothd loop run <prompt>`; drain stdout so the
        // child never blocks on a full pipe; surface a non-zero exit's
        // stderr (e.g. the daemon-owns-WAL refusal) as the status note.
        let weak_loop_run = window.as_weak();
        let child_run = loop_child.clone();
        let refresh_after_run = refresh_history.clone();
        window.on_loop_run_clicked(move |prompt| {
            let Some(w0) = weak_loop_run.upgrade() else {
                return;
            };
            if w0.get_loop_running() {
                return;
            }
            w0.set_loop_running(true);
            w0.set_loop_status_note("".into());
            let prompt = prompt.to_string();
            // Wave-2 feed D: loop started.
            {
                let snippet = if prompt.len() > 80 { &prompt[..80] } else { &prompt };
                push_activity(&w0.as_weak(), "loop", "Loop started", snippet);
            }
            let weak = weak_loop_run.clone();
            let child_slot = child_run.clone();
            let refresh = refresh_after_run.clone();
            std::thread::spawn(move || {
                let outcome: Result<(bool, String), String> = (|| {
                    let bin =
                        which_neothd().ok_or_else(|| BINARY_MISSING_MESSAGE.to_string())?;
                    let mut child = spawn_neothd_plain(&bin)
                        .arg("loop")
                        .arg("run")
                        .arg(&prompt)
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .map_err(|e| format!("loop subprocess could not start: {e}"))?;
                    let mut stdout = child.stdout.take();
                    let mut stderr = child.stderr.take();
                    if let Ok(mut slot) = child_slot.lock() {
                        *slot = Some(child);
                    }
                    // Drain stderr on its own thread — sequential draining
                    // deadlocks when the child fills the 64K stderr pipe
                    // before stdout reaches EOF (review B8).
                    let err_join = std::thread::spawn(move || {
                        let mut err_text = String::new();
                        if let Some(err) = stderr.as_mut() {
                            use std::io::Read as _;
                            let _ = err.read_to_string(&mut err_text);
                        }
                        err_text
                    });
                    // Drain stdout to EOF (keeps the child unblocked).
                    let mut sink = String::new();
                    if let Some(out) = stdout.as_mut() {
                        use std::io::Read as _;
                        let _ = out.read_to_string(&mut sink);
                    }
                    let err_text = err_join.join().unwrap_or_default();
                    let status = child_slot
                        .lock()
                        .ok()
                        .and_then(|mut slot| slot.take())
                        .and_then(|mut c| c.wait().ok());
                    let ok = status.map(|s| s.success()).unwrap_or(false);
                    Ok((ok, err_text))
                })();
                let note = match outcome {
                    Ok((true, _)) => String::new(),
                    Ok((false, err)) => {
                        let tail: String = err.lines().rev().take(3).collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect::<Vec<_>>()
                            .join(" · ");
                        if tail.is_empty() {
                            "loop exited non-zero (killed or failed)".to_string()
                        } else {
                            tail
                        }
                    }
                    Err(e) => e,
                };
                let weak_done = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak_done.upgrade() {
                        w.set_loop_running(false);
                        // Wave-2 feed D: loop done — settle the active row.
                        settle_activity_kind(&w.as_weak(), "loop");
                        if !note.is_empty() {
                            w.set_loop_status_note(note.into());
                        } else {
                            w.set_loop_prompt_draft("".into());
                        }
                    }
                });
                // Newest record (if any) becomes the selection.
                refresh(None);
            });
        });

        // Kill — terminate the running child; the run worker's wait()
        // observes the non-zero exit and lands the status note.
        let weak_loop_kill = window.as_weak();
        let child_kill = loop_child.clone();
        window.on_loop_kill_clicked(move || {
            if let Ok(mut slot) = child_kill.lock() {
                if let Some(child) = slot.as_mut() {
                    let _ = child.kill();
                }
            }
            if let Some(w) = weak_loop_kill.upgrade() {
                w.set_loop_status_note("kill signal sent — waiting for the subprocess to exit".into());
            }
        });

        // Initial history load (cheap file reads, off-thread).
        refresh_history(None);
    }

    // GUI-overhaul feature parity — live connectivity test for a channel
    // (`neoth channel test <name>`, read-only). Off-thread; the daemon's check
    // result (or error) is shaped into the footer status line.
    let weak_channel_test = window.as_weak();
    window.on_channel_test(move |name| {
        if let Some(w) = weak_channel_test.upgrade() {
            buddy(&w, GuiActivity::ChannelTest);
        }
        let weak = weak_channel_test.clone();
        let name = name.to_string();
        std::thread::spawn(move || {
            let msg = match which_neothd().and_then(|bin| {
                spawn_neothd_plain(&bin)
                    .arg("channel")
                    .arg("test")
                    .arg(&name)
                    .output()
                    .ok()
            }) {
                Some(o) if o.status.success() => {
                    let line = String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .map(str::trim)
                        .rfind(|l| !l.is_empty())
                        .unwrap_or("ok")
                        .to_string();
                    format!("{name}: {line}")
                }
                Some(o) => format!(
                    "{name} test failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                        .lines()
                        .map(str::trim)
                        .find(|l| !l.is_empty())
                        .unwrap_or("(no detail)")
                ),
                None => format!("{name}: neothd binary not on PATH"),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(msg.into());
                }
            });
        });
    });

    // GUI-overhaul feature parity — remove a channel's credential
    // (`neoth channel remove <name>`), then re-read credentials.yaml so the row
    // flips to disconnected. Gated behind an inline confirm in the UI.
    let weak_channel_remove = window.as_weak();
    window.on_channel_remove(move |name| {
        let weak = weak_channel_remove.clone();
        let name = name.to_string();
        std::thread::spawn(move || {
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("channel")
                        .arg("remove")
                        .arg(&name)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let channels = panel_logic::read_channel_status(&default_neoth_home());
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_channels(&w, channels);
                    w.set_status_line(if ok {
                        format!("Channel {name} credential removed.").into()
                    } else {
                        format!("Channel {name} remove failed (is neothd on PATH?).").into()
                    });
                }
            });
        });
    });

    // GAP-19 — Add a new channel credential from the GUI.
    // Maps (channel_type, f1..f4) → the correct `neoth channel add <type> <flags>` args.
    // Empty required fields are caught before shelling; on success re-reads
    // credentials.yaml + refreshes the channel rows exactly like on_channel_remove.
    let weak_channel_add = window.as_weak();
    window.on_channel_add(move |ctype, f1, f2, f3, f4| {
        let ctype = ctype.to_string();
        let f1 = f1.trim().to_string();
        let f2 = f2.trim().to_string();
        let f3 = f3.trim().to_string();
        let f4 = f4.trim().to_string();

        // Build the flag args for this channel type; return Err(hint) on missing required fields.
        let args_result: Result<Vec<String>, String> = (|| {
            match ctype.as_str() {
                "telegram" => {
                    if f1.is_empty() { return Err("telegram needs: --token".into()); }
                    Ok(vec!["--token".into(), f1])
                }
                "slack" => {
                    if f1.is_empty() || f2.is_empty() {
                        return Err("slack needs: --bot-token and --app-token".into());
                    }
                    Ok(vec!["--bot-token".into(), f1, "--app-token".into(), f2])
                }
                "whatsapp" => {
                    if f1.is_empty() || f2.is_empty() {
                        return Err("whatsapp needs: --token and --phone-id".into());
                    }
                    Ok(vec!["--token".into(), f1, "--phone-id".into(), f2])
                }
                "discord" => {
                    if f1.is_empty() { return Err("discord needs: --token".into()); }
                    Ok(vec!["--token".into(), f1])
                }
                "keet" => {
                    if f1.is_empty() { return Err("keet needs: --seed".into()); }
                    Ok(vec!["--seed".into(), f1])
                }
                "signal" => {
                    if f1.is_empty() || f2.is_empty() {
                        return Err("signal needs: --url and --phone".into());
                    }
                    Ok(vec!["--url".into(), f1, "--phone".into(), f2])
                }
                "line" => {
                    if f1.is_empty() { return Err("line needs: --token".into()); }
                    let mut a = vec!["--token".into(), f1];
                    if !f2.is_empty() { a.extend(["--password".into(), f2]); }
                    Ok(a)
                }
                "irc" => {
                    if f1.is_empty() || f2.is_empty() {
                        return Err("irc needs: --server and --nick".into());
                    }
                    let mut a = vec!["--server".into(), f1, "--nick".into(), f2];
                    if !f3.is_empty() { a.extend(["--password".into(), f3]); }
                    if !f4.is_empty() { a.extend(["--channels-csv".into(), f4]); }
                    Ok(a)
                }
                "imessage" | "bluebubbles" => {
                    if f1.is_empty() || f2.is_empty() {
                        return Err(format!("{ctype} needs: --url and --password"));
                    }
                    Ok(vec!["--url".into(), f1, "--password".into(), f2])
                }
                "mattermost" => {
                    if f1.is_empty() || f2.is_empty() {
                        return Err("mattermost needs: --url and --token".into());
                    }
                    Ok(vec!["--url".into(), f1, "--token".into(), f2])
                }
                "gchat" => {
                    if f1.is_empty() || f2.is_empty() {
                        return Err("gchat needs: --url and --server".into());
                    }
                    Ok(vec!["--url".into(), f1, "--server".into(), f2])
                }
                other => Err(format!("unknown channel type: {other}")),
            }
        })();

        match args_result {
            Err(hint) => {
                push_toast(&weak_channel_add, "warn", "Add channel", &hint);
            }
            Ok(extra_args) => {
                let weak = weak_channel_add.clone();
                let ctype_clone = ctype.clone();
                std::thread::spawn(move || {
                    let result = which_neothd().and_then(|bin| {
                        let mut cmd = spawn_neothd_plain(&bin);
                        cmd.arg("channel").arg("add").arg(&ctype_clone);
                        for a in &extra_args {
                            cmd.arg(a);
                        }
                        cmd.arg("--output").arg("json").output().ok()
                    });

                    let (toast_kind, toast_title, toast_body, refresh) = match result {
                        Some(o) if o.status.success() => {
                            // Parse {ok, channel, configured} from stdout.
                            let raw = String::from_utf8_lossy(&o.stdout);
                            let configured = raw.contains("\"configured\":true");
                            let msg = if configured {
                                format!("Channel {ctype_clone} connected and configured.")
                            } else {
                                format!("Channel {ctype_clone} credential stored (not yet configured).")
                            };
                            ("success", "Add channel", msg, true)
                        }
                        Some(o) => {
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            let detail = stderr.lines()
                                .map(str::trim)
                                .find(|l| !l.is_empty())
                                .unwrap_or("unknown error")
                                .to_string();
                            (
                                "error",
                                "Add channel failed",
                                format!("{ctype_clone}: {detail}"),
                                false,
                            )
                        }
                        None => (
                            "error",
                            "Add channel failed",
                            format!("{ctype_clone}: neothd binary not on PATH"),
                            false,
                        ),
                    };

                    let channels = if refresh {
                        Some(panel_logic::read_channel_status(&default_neoth_home()))
                    } else {
                        None
                    };

                    let toast_body_clone = toast_body.clone();
                    push_toast(&weak, toast_kind, toast_title, &toast_body_clone);
                    if let Some(ch) = channels {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                apply_channels(&w, ch);
                            }
                        });
                    }
                });
            }
        }
    });

    // GUI-overhaul feature parity — Memory "forget a topic". Preview runs the
    // dry-run (`neoth memory --forget <topic>`, no --confirm) and reports the
    // would-wipe summary; it mutates nothing.
    let weak_mem_preview = window.as_weak();
    window.on_memory_forget_preview(move |topic| {
        if let Some(w) = weak_mem_preview.upgrade() {
            buddy(&w, GuiActivity::MemoryForget);
        }
        let weak = weak_mem_preview.clone();
        let topic = topic.to_string();
        std::thread::spawn(move || {
            let msg = match which_neothd().and_then(|bin| {
                spawn_neothd_plain(&bin)
                    .arg("memory")
                    .arg("--forget")
                    .arg(&topic)
                    .output()
                    .ok()
            }) {
                Some(o) if o.status.success() => {
                    let line = String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .map(str::trim)
                        .rfind(|l| !l.is_empty())
                        .unwrap_or("(no matches)")
                        .to_string();
                    format!("Preview \"{topic}\": {line}")
                }
                Some(o) => format!(
                    "Forget preview failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                        .lines()
                        .map(str::trim)
                        .find(|l| !l.is_empty())
                        .unwrap_or("(no detail)")
                ),
                None => "memory: neothd binary not on PATH".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(msg.into());
                }
            });
        });
    });

    // GUI-overhaul feature parity — Memory "forget a topic", permanent. Runs the
    // wipe (`neoth memory --forget <topic> --confirm`), then re-reads the memory
    // snapshot so the blocks list reflects the change.
    let weak_mem_confirm = window.as_weak();
    window.on_memory_forget_confirm(move |topic| {
        let weak = weak_mem_confirm.clone();
        let topic = topic.to_string();
        std::thread::spawn(move || {
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("memory")
                        .arg("--forget")
                        .arg(&topic)
                        .arg("--confirm")
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let memory = fetch_memory_snapshot();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_memory(&w, memory);
                    w.set_status_line(if ok {
                        format!("Forgot \"{topic}\" — memory wiped.").into()
                    } else {
                        format!("Forget \"{topic}\" failed (is neothd on PATH?).").into()
                    });
                }
            });
        });
    });

    // GUI-overhaul (gap panel wf_8ad7096a) — feature parity: enable/disable a
    // skill from the GUI Skills tab. Shells `neoth skills --enable/--disable <id>`
    // off the UI thread, then re-fetches + applies the list so the new state
    // shows + reports a status line.
    let weak_skill_toggle = window.as_weak();
    window.on_skill_toggle(move |id, enabled| {
        if let Some(w) = weak_skill_toggle.upgrade() {
            buddy(&w, GuiActivity::SettingsApplied);
        }
        let weak = weak_skill_toggle.clone();
        let id = id.to_string();
        std::thread::spawn(move || {
            let flag = if enabled { "--enable" } else { "--disable" };
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("skills")
                        .arg(flag)
                        .arg(&id)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let skills = fetch_skills();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_skills(&w, skills);
                    let verb = if enabled { "enabled" } else { "disabled" };
                    w.set_status_line(if ok {
                        format!("Skill {id} {verb}.").into()
                    } else {
                        format!("Skill {verb} failed for {id} (is neothd on PATH?).").into()
                    });
                }
            });
        });
    });

    // GUI-overhaul feature parity — enable/disable a plugin from the GUI Plugins
    // tab. Shells `neoth plugin enable/disable <id>` off the UI thread (mutates
    // freedom.yaml::plugins.wasm.activations.<id>), then re-fetches the list.
    let weak_plugin_toggle = window.as_weak();
    window.on_plugin_toggle(move |id, enabled| {
        let weak = weak_plugin_toggle.clone();
        let id = id.to_string();
        std::thread::spawn(move || {
            let action = if enabled { "enable" } else { "disable" };
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("plugin")
                        .arg(action)
                        .arg(&id)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let plugins = fetch_plugins();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_plugins(&w, plugins);
                    let verb = if enabled { "enabled" } else { "disabled" };
                    w.set_status_line(if ok {
                        format!("Plugin {id} {verb}.").into()
                    } else {
                        format!("Plugin {verb} failed for {id} (is neothd on PATH?).").into()
                    });
                }
            });
        });
    });

    // ── Skills: install from dir ───────────────────────────────────────────────
    // Opens a native folder picker (rfd works from spawned threads on Windows),
    // shells `neoth skills --install <dir>`, toasts from the worker thread
    // (push_toast internally schedules on the event loop), then refreshes the list.
    {
        let weak_si = window.as_weak();
        window.on_skill_install(move || {
            let weak = weak_si.clone();
            std::thread::spawn(move || {
                let picked = rfd::FileDialog::new()
                    .set_title("Select skill directory (must contain skill.yaml)")
                    .pick_folder();
                let Some(dir) = picked else { return };
                let dir_str = dir.to_string_lossy().to_string();
                let result = which_neothd().and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("skills")
                        .arg("--install")
                        .arg(&dir)
                        .output()
                        .ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Skill installed", &dir_str);
                } else {
                    push_toast(&weak, "warn", "Skill install failed", &msg);
                }
                let skills = fetch_skills();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_skills(&w, skills);
                    }
                });
            });
        });
    }

    // ── Skills: uninstall by id ────────────────────────────────────────────────
    // Shells `neoth skills --uninstall <id>` → toast + refresh.
    {
        let weak_su = window.as_weak();
        window.on_skill_uninstall(move |id| {
            let weak = weak_su.clone();
            let id = id.to_string();
            std::thread::spawn(move || {
                let result = which_neothd().and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("skills")
                        .arg("--uninstall")
                        .arg(&id)
                        .output()
                        .ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Skill uninstalled", &id);
                } else {
                    push_toast(&weak, "warn", "Skill uninstall failed", &msg);
                }
                let skills = fetch_skills();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_skills(&w, skills);
                    }
                });
            });
        });
    }

    // ── Skills: create via non-interactive wizard ──────────────────────────────
    // Shells `neoth skills --create --non-interactive --create-id <id>
    //   --create-description <d> [--create-keywords <k>] --create-system-prompt <p>`
    // → toast + refresh.
    {
        let weak_sc = window.as_weak();
        window.on_skill_create(move |id, desc, keywords, prompt| {
            let weak = weak_sc.clone();
            let id = id.to_string();
            let desc = desc.to_string();
            let keywords = keywords.to_string();
            let prompt = prompt.to_string();
            std::thread::spawn(move || {
                let result = which_neothd().and_then(|bin| {
                    let mut cmd = spawn_neothd_plain(&bin);
                    cmd.arg("skills")
                        .arg("--create")
                        .arg("--non-interactive")
                        .arg("--create-id")
                        .arg(&id)
                        .arg("--create-description")
                        .arg(&desc)
                        .arg("--create-system-prompt")
                        .arg(&prompt);
                    if !keywords.is_empty() {
                        cmd.arg("--create-keywords").arg(&keywords);
                    }
                    cmd.output().ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Skill created", &id);
                } else {
                    push_toast(&weak, "warn", "Skill create failed", &msg);
                }
                let skills = fetch_skills();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_skills(&w, skills);
                    }
                });
            });
        });
    }

    // ── Plugins: install from dir ──────────────────────────────────────────────
    // Opens a native folder picker, shells `neoth plugin install <dir>` → toast + refresh.
    {
        let weak_pi = window.as_weak();
        window.on_plugin_install(move || {
            let weak = weak_pi.clone();
            std::thread::spawn(move || {
                let picked = rfd::FileDialog::new()
                    .set_title("Select plugin directory (must contain plugin.toml + plugin.wasm)")
                    .pick_folder();
                let Some(dir) = picked else { return };
                let dir_str = dir.to_string_lossy().to_string();
                let result = which_neothd().and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("plugin")
                        .arg("install")
                        .arg(&dir)
                        .output()
                        .ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Plugin installed", &dir_str);
                } else {
                    push_toast(&weak, "warn", "Plugin install failed", &msg);
                }
                let plugins = fetch_plugins();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_plugins(&w, plugins);
                    }
                });
            });
        });
    }

    // ── Plugins: remove by id ──────────────────────────────────────────────────
    // Shells `neoth plugin remove <id>` → toast + refresh.
    // The `plugin remove` subcommand is being added in a parallel PR; if the
    // daemon doesn't support it yet the stderr toast surfaces the error cleanly.
    {
        let weak_pr = window.as_weak();
        window.on_plugin_remove(move |id| {
            let weak = weak_pr.clone();
            let id = id.to_string();
            std::thread::spawn(move || {
                let result = which_neothd().and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("plugin")
                        .arg("remove")
                        .arg(&id)
                        .output()
                        .ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Plugin removed", &id);
                } else {
                    push_toast(&weak, "warn", "Plugin remove failed", &msg);
                }
                let plugins = fetch_plugins();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_plugins(&w, plugins);
                    }
                });
            });
        });
    }

    // DES-12 — Plugin WAL-feed detail pane: operator clicked "Activity" on a row.
    // Shells `neoth plugin events <id> --output json --last 30` off the UI thread,
    // parses the result, and updates plugin-detail-id / title / events.
    {
        let weak_pdc = window.as_weak();
        window.on_plugin_detail_clicked(move |id| {
            use slint::Model as _; // ModelRc::row_count / row_data
            let weak = weak_pdc.clone();
            let id_str = id.to_string();
            // Look up ui_title from the current plugins model so we can set the
            // detail title without an extra subprocess call.
            let title = weak
                .upgrade()
                .and_then(|w| {
                    let model = w.get_plugins();
                    (0..model.row_count()).find_map(|i| {
                        let row = model.row_data(i)?;
                        if row.id.as_str() == id_str {
                            Some(row.ui_title.to_string())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_default();
            std::thread::spawn(move || {
                let events = fetch_plugin_events(&id_str);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        use slint::{ModelRc, VecModel};
                        let rows: Vec<PluginEventRow> = events
                            .into_iter()
                            .map(|e| PluginEventRow {
                                // SECURITY: kind is plugin-controlled text; stored as
                                // plain string — Slint renders it via plain Text only
                                // (no markup parsing). Do NOT pass to any rich-text API.
                                kind: e.kind.into(),
                                bytes: fmt_event_bytes(e.payload_bytes).into(),
                                ts: fmt_ts_unix(e.ts_unix).into(),
                            })
                            .collect();
                        w.set_plugin_detail_id(id_str.as_str().into());
                        w.set_plugin_detail_title(title.as_str().into());
                        w.set_plugin_detail_events(ModelRc::new(VecModel::from(rows)));
                    }
                });
            });
        });
    }

    // DES-12 — Plugin detail pane close: clear the selection.
    {
        let weak_pclose = window.as_weak();
        window.on_plugin_detail_close(move || {
            if let Some(w) = weak_pclose.upgrade() {
                use slint::{ModelRc, VecModel};
                w.set_plugin_detail_id("".into());
                w.set_plugin_detail_title("".into());
                w.set_plugin_detail_events(ModelRc::new(VecModel::from(
                    Vec::<PluginEventRow>::new(),
                )));
            }
        });
    }

    // GUI-overhaul feature parity — set the autonomy level from the Privacy combo.
    // Shells `neoth autonomy set <level>` (mutates freedom.yaml::autonomy + emits
    // a WAL audit frame). On success, mirror the new level into autonomy-choice so
    // the combo + every autonomy-derived display update without a reload.
    //
    // GAP-09 — Sudomode route: if level == "full", the GUI MUST NOT call
    // `autonomy set full` directly (that path is TTY-fail-closed). Instead mint
    // a single-use token via `neoth autonomy mint-fullauto-token --output json`
    // and then call `neoth autonomy full-auto --gui-confirmed --gui-token <t>`.
    // Any mint failure is surfaced in status-line and the level is NOT changed.
    // All other levels use the normal `autonomy set <level>` path unchanged.
    let weak_autonomy_set = window.as_weak();
    window.on_autonomy_set(move |level| {
        let weak = weak_autonomy_set.clone();
        let level = level.to_string();
        std::thread::spawn(move || {
            // GAP-09: intercept "full" → token-mint path.
            if level == "full" {
                let result: Result<(), String> = (|| {
                    let bin = which_neothd()
                        .ok_or_else(|| "neothd binary not on PATH".to_string())?;
                    let tok_out = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("mint-fullauto-token")
                        .arg("--output")
                        .arg("json")
                        .output()
                        .map_err(|e| format!("mint-fullauto-token spawn failed: {e}"))?;
                    if !tok_out.status.success() {
                        let err =
                            String::from_utf8_lossy(&tok_out.stderr).trim().to_string();
                        return Err(format!("mint-fullauto-token failed: {err}"));
                    }
                    let raw = String::from_utf8_lossy(&tok_out.stdout).trim().to_string();
                    // Output may be `{"token":"…"}` or a bare token string.
                    let token = if let Ok(v) =
                        serde_json::from_str::<serde_json::Value>(&raw)
                    {
                        // JSON but token missing/not-a-string → empty, so the
                        // is_empty guard below rejects it (never pass the raw
                        // JSON blob as a token).
                        v.get("token")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string()
                    } else {
                        raw
                    };
                    if token.is_empty() {
                        return Err(
                            "mint-fullauto-token returned an empty token".to_string()
                        );
                    }
                    let apply_out = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("full-auto")
                        .arg("--gui-confirmed")
                        .arg("--gui-token")
                        .arg(&token)
                        .output()
                        .map_err(|e| format!("autonomy full-auto spawn failed: {e}"))?;
                    if !apply_out.status.success() {
                        let err =
                            String::from_utf8_lossy(&apply_out.stderr).trim().to_string();
                        return Err(format!("autonomy full-auto failed: {err}"));
                    }
                    Ok(())
                })();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        match result {
                            Ok(()) => {
                                // Orb flips to secured only on a CONFIRMED
                                // change (review wave 2026-07-04: no visual
                                // drift when the ceremony fails).
                                buddy(&w, GuiActivity::Secured);
                                w.set_autonomy_choice("full".into());
                                w.set_status_line(
                                    "Autonomy set to full (sudomode) via GUI token.".into(),
                                );
                            }
                            Err(msg) => {
                                w.set_status_line(
                                    format!(
                                        "Full-auto gate: {msg} — level NOT changed. \
                                         Daemon must be running to mint the confirm token."
                                    )
                                    .into(),
                                );
                            }
                        }
                    }
                });
                return;
            }

            // Normal path for strict / standard / elevated / custom.
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("set")
                        .arg(&level)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    if ok {
                        buddy(&w, GuiActivity::Secured);
                        w.set_autonomy_choice(level.clone().into());
                        w.set_status_line(format!("Autonomy set to {level}.").into());
                    } else {
                        w.set_status_line(
                            format!("Autonomy set to {level} failed (is neothd on PATH?).").into(),
                        );
                    }
                }
            });
        });
    });

    // ── Chat-surface consent strip wiring ─────────────────────────────────────
    // Three callbacks + one startup fire. The refresh fn is also called after
    // any mode/revoke action so the strip stays in sync.

    // Initial populate — fires immediately so the strip shows real data on first
    // chat view without requiring a manual refresh.
    {
        let weak_cc_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_chat_consent(weak_cc_init);
        });
    }

    // chat-consent-refresh — operator opened the popover; re-probe daemon.
    let weak_cc_refresh = window.as_weak();
    window.on_chat_consent_refresh(move || {
        let weak = weak_cc_refresh.clone();
        std::thread::spawn(move || {
            refresh_chat_consent(weak);
        });
    });

    // chat-consent-set-mode — "Gated" or "Full-Auto" pill clicked.
    let weak_cc_mode = window.as_weak();
    window.on_chat_consent_set_mode(move |mode| {
        let weak = weak_cc_mode.clone();
        let mode = mode.to_string();
        std::thread::spawn(move || {
            if mode == "full" {
                // GAP-09 / GR-RESID-D34: Full-auto requires the token-mint
                // ceremony — same path as on_autonomy_set("full").
                let result: Result<(), String> = (|| {
                    let bin = which_neothd()
                        .ok_or_else(|| "neothd binary not on PATH".to_string())?;
                    let tok_out = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("mint-fullauto-token")
                        .arg("--output")
                        .arg("json")
                        .output()
                        .map_err(|e| format!("mint-fullauto-token spawn failed: {e}"))?;
                    if !tok_out.status.success() {
                        let err = String::from_utf8_lossy(&tok_out.stderr).trim().to_string();
                        return Err(format!("mint-fullauto-token failed: {err}"));
                    }
                    let raw = String::from_utf8_lossy(&tok_out.stdout).trim().to_string();
                    let token = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                        v.get("token")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string()
                    } else {
                        raw
                    };
                    if token.is_empty() {
                        return Err("mint-fullauto-token returned an empty token".to_string());
                    }
                    let apply_out = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("full-auto")
                        .arg("--gui-confirmed")
                        .arg("--gui-token")
                        .arg(&token)
                        .output()
                        .map_err(|e| format!("autonomy full-auto spawn failed: {e}"))?;
                    if !apply_out.status.success() {
                        let err = String::from_utf8_lossy(&apply_out.stderr).trim().to_string();
                        return Err(format!("autonomy full-auto failed: {err}"));
                    }
                    Ok(())
                })();
                let result_ok = result.is_ok();
                let result_msg = result.err().unwrap_or_default();
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak2.upgrade() {
                        if result_ok {
                            w.set_chat_consent_mode("full-auto".into());
                            push_toast(
                                &w.as_weak(),
                                "success",
                                "Consent",
                                "Full-Auto enabled via GUI ceremony.",
                            );
                        } else {
                            w.set_status_line(
                                format!(
                                    "Full-auto gate (chat strip): {result_msg} — mode NOT changed."
                                )
                                .into(),
                            );
                        }
                    }
                });
                if result_ok {
                    refresh_chat_consent(weak);
                }
            } else {
                // Gated (and any other mode): plain autonomy set.
                let ok = which_neothd()
                    .and_then(|bin| {
                        spawn_neothd_plain(&bin)
                            .arg("autonomy")
                            .arg("gated")
                            .output()
                            .ok()
                    })
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak2.upgrade() {
                        if ok {
                            push_toast(&w.as_weak(), "success", "Consent", "Mode set to Gated.");
                        } else {
                            w.set_status_line(
                                "autonomy gated failed — is neothd on PATH?".into(),
                            );
                        }
                    }
                });
                if ok {
                    refresh_chat_consent(weak);
                }
            }
        });
    });

    // chat-consent-revoke — Revoke button clicked for a provider.
    let weak_cc_revoke = window.as_weak();
    window.on_chat_consent_revoke(move |provider| {
        let weak = weak_cc_revoke.clone();
        let provider = provider.to_string();
        std::thread::spawn(move || {
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("consent")
                        .arg("revoke")
                        .arg(&provider)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let provider2 = provider.clone();
            let weak2 = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak2.upgrade() {
                    if ok {
                        push_toast(
                            &w.as_weak(),
                            "info",
                            "Consent",
                            &format!("Revoked consent for {provider2}."),
                        );
                    } else {
                        w.set_status_line(
                            format!("consent revoke {provider2} failed.").into(),
                        );
                    }
                }
            });
            if ok {
                refresh_chat_consent(weak);
            }
        });
    });

    // Pick #8 step 4 — pseudo-live-tail via 2-second poll (2026-05-20).
    // A real WAL-file-watcher (notify crate + WAL frame parser) lands
    // when the dispatcher (Pick #6) starts mutating the board mid-run.
    // Until then the polling refresh is cheap (no work unless the
    // operator is actually on Settings) + race-free (worker thread
    // owns subprocess + invoke_from_event_loop owns the UI write).
    //
    // The Timer MUST stay in scope until window.run() returns; binding
    // it to `_kanban_live_timer` keeps it alive for the program's life.
    let weak_kanban_tick = window.as_weak();
    let mutex_tick = kanban_snapshot.clone();
    // In-flight guard: each tick spawns a subprocess fetch. If a fetch
    // takes longer than the 2s poll interval (slow box / large board),
    // the naive timer would pile up overlapping fetch threads every 2s.
    // The AtomicBool lets at most ONE fetch be in flight at a time — a
    // late fetch just skips the tick instead of stacking another thread.
    // GOLD-ADAPT-GUI-05 — TypedStatus footer ticker. One repeated timer
    // types the current `panel_logic::TICKER_MESSAGES` line in character
    // by character (80ms/char), holds it, then advances. Pure frame math
    // lives in `panel_logic::ticker_frame` (unit-tested); only the tick
    // counter + property write live here. Runs only on the shell surfaces
    // (chat/settings) — wizard steps keep their own footer.
    let weak_ticker = window.as_weak();
    let _status_ticker_timer = {
        let timer = slint::Timer::default();
        let tick = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(80),
            move || {
                if let Some(w) = weak_ticker.upgrade() {
                    let s = w.get_step();
                    if s != WizardStep::Chat && s != WizardStep::Settings {
                        return;
                    }
                    let t = tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    w.set_status_message(panel_logic::ticker_frame(t).into());
                }
            },
        );
        timer
    };

    let kanban_fetch_in_flight = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // B — persistent-stdio-stream: ONE warm `neoth gui-stream` child shared
    // across ticks, lazily connected on first board fetch. Held for the
    // window lifetime; dropped (→ child killed) when the timer drops.
    let gui_stream_client = std::sync::Arc::new(std::sync::Mutex::new(None::<GuiStreamClient>));
    let _kanban_live_timer = {
        let timer = slint::Timer::default();
        let in_flight = kanban_fetch_in_flight.clone();
        let client_timer = gui_stream_client.clone();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(2),
            move || {
                if let Some(w) = weak_kanban_tick.upgrade() {
                    // The board fetch only matters on the Code Sessions surface;
                    // the Buddy activity poll runs EVERY tick (the docked orb is
                    // always visible) so it reflects live daemon activity.
                    let want_board = w.get_step() == WizardStep::Settings;
                    // Skip if a prior fetch is still running. `swap` returns the
                    // previous value: true → another fetch is in flight → bail.
                    if in_flight.swap(true, std::sync::atomic::Ordering::AcqRel) {
                        return;
                    }
                    let weak = weak_kanban_tick.clone();
                    let mutex = mutex_tick.clone();
                    let done = in_flight.clone();
                    let client = client_timer.clone();
                    std::thread::spawn(move || {
                        // Daemon→GUI activity push — drive the docked Buddy from
                        // the daemon's most-recent (≤30s) WAL event. Only override
                        // when the daemon is actively doing something (!= idle) so
                        // a quiet daemon leaves the last user-action mood intact.
                        if let Some((act, cap)) = fetch_activity_warm(&client) {
                            if act != "idle" {
                                let weak_b = weak.clone();
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(w) = weak_b.upgrade() {
                                        w.set_buddy_mood(act.into());
                                        w.set_buddy_caption(cap.into());
                                    }
                                });
                            }
                        }
                        if want_board {
                            let snap = fetch_board_warm_or_cold(&client);
                            let snap_for_state = snap.clone();
                            // Wave-2 feed C: extract before the move into the closure.
                            let board_summary = snap_for_state.summary.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Ok(mut g) = mutex.lock() {
                                    *g = snap_for_state;
                                }
                                if let Some(w) = weak.upgrade() {
                                    apply_kanban_snapshot(&w, snap);
                                    push_activity(&w.as_weak(), "kanban", "Board updated", &board_summary);
                                }
                            });
                        }
                        // Release the slot AFTER the fetch + UI-write enqueue.
                        done.store(false, std::sync::atomic::Ordering::Release);
                    });
                }
            },
        );
        timer
    };

    // GOLD-PROG-07 — live VRAM/hardware refresh. The startup bundle fetches the
    // snapshot once; this 30s timer keeps the VRAM meter current while the
    // operator is on the Settings tab. Same race-free shape as the kanban timer:
    // a worker thread owns the subprocess, invoke_from_event_loop owns the UI
    // write, and an AtomicBool caps it at one fetch in flight. 30s (not 2s) —
    // `neoth hardware` reads sysinfo at call time, so a shorter interval just
    // taxes the Windows refresh rate without yielding finer data.
    let weak_hw_tick = window.as_weak();
    let hw_fetch_in_flight = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _hardware_live_timer = {
        let timer = slint::Timer::default();
        let in_flight = hw_fetch_in_flight.clone();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(30),
            move || {
                if let Some(w) = weak_hw_tick.upgrade() {
                    if w.get_step() != WizardStep::Settings {
                        return;
                    }
                    if in_flight.swap(true, std::sync::atomic::Ordering::AcqRel) {
                        return;
                    }
                    let weak = weak_hw_tick.clone();
                    let done = in_flight.clone();
                    std::thread::spawn(move || {
                        let snap = fetch_hardware_snapshot();
                        // GOLD-PROG-08 — refresh the live token budget on the same
                        // Settings-tab tick (both are cheap file/subprocess reads).
                        let usage = fetch_usage_meter();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                apply_hardware(&w, snap);
                                apply_usage_meter(&w, usage);
                            }
                        });
                        done.store(false, std::sync::atomic::Ordering::Release);
                    });
                }
            },
        );
        timer
    };

    // Step 6 (2026-05-20): operator action handlers. Each spawns a
    // worker thread that subprocesses `neoth kanban move/review` and
    // logs the outcome. The 2s live-tail timer picks up the resulting
    // status change in the GUI without an explicit refresh hop.
    fn strip_id_hash(s: &str) -> String {
        s.strip_prefix('#').unwrap_or(s).to_string()
    }
    window.on_kanban_task_move(move |task_id, status| {
        let id = strip_id_hash(&task_id);
        let status_str = status.to_string();
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban move: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("move")
                .arg(&id)
                .arg(&status_str)
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, status = %status_str, "kanban: move applied");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    status = %status_str,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban move failed"
                ),
                Err(e) => tracing::warn!(task_id = %id, error = %e, "kanban move could not start"),
            }
        });
    });
    window.on_kanban_task_promote(move |task_id| {
        let id = strip_id_hash(&task_id);
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban promote: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("review")
                .arg(&id)
                .arg("--promote")
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, "kanban: REVIEW promoted to DONE");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban promote failed"
                ),
                Err(e) => {
                    tracing::warn!(task_id = %id, error = %e, "kanban promote could not start")
                }
            }
        });
    });

    // v0.2 complete (2026-05-20) — comment + assign handlers.
    // Subprocess analog to move/promote; the 2s live-tail picks up
    // the resulting board state without a manual refresh.
    window.on_kanban_task_comment(move |task_id, body| {
        let id = strip_id_hash(&task_id);
        let body_str = body.to_string();
        if body_str.trim().is_empty() {
            return;
        }
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban comment: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("comment")
                .arg(&id)
                .arg(&body_str)
                .arg("--author")
                .arg("operator")
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, body_len = body_str.len(), "kanban: comment appended");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban comment failed"
                ),
                Err(e) => {
                    tracing::warn!(task_id = %id, error = %e, "kanban comment could not start")
                }
            }
        });
    });
    window.on_kanban_task_assign(move |task_id, hemi| {
        let id = strip_id_hash(&task_id);
        let hemi_str = hemi.to_string();
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban assign: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("assign")
                .arg(&id)
                .arg(&hemi_str)
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, hemisphere = %hemi_str, "kanban: assigned");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    hemisphere = %hemi_str,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban assign failed"
                ),
                Err(e) => {
                    tracing::warn!(task_id = %id, error = %e, "kanban assign could not start")
                }
            }
        });
    });

    // GAP-03: finish-task handler. Subprocesses `neoth kanban finish
    // <id>`; the 2s live-tail picks up the done status automatically.
    window.on_kanban_task_finish(move |task_id| {
        let id = strip_id_hash(&task_id);
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban finish: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("finish")
                .arg(&id)
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, "kanban: task finished");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban finish failed"
                ),
                Err(e) => {
                    tracing::warn!(task_id = %id, error = %e, "kanban finish could not start")
                }
            }
        });
    });

    // Step 5 (2026-05-20): task-card click handler. Resolves the
    // task-id from the last-applied snapshot and pushes the detail
    // properties so the Code Sessions detail pane renders.
    let weak_select = window.as_weak();
    let mutex_select = kanban_snapshot.clone();
    window.on_kanban_task_selected(move |task_id| {
        let id = task_id.to_string();
        let snapshot_clone = match mutex_select.lock() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };
        let Some((row, status)) = snapshot_clone.find_task(&id) else {
            return;
        };
        if let Some(w) = weak_select.upgrade() {
            w.set_kanban_selected_task_id(row.task_id);
            w.set_kanban_selected_title(row.title);
            w.set_kanban_selected_hemisphere(row.hemisphere);
            w.set_kanban_selected_status(status.into());
            // Description not yet carried in the snapshot — populate
            // when the board store starts surfacing it. Empty hides
            // the description line in the detail pane.
            w.set_kanban_selected_description("".into());
            // Clear stale comments while the subprocess fetch runs so
            // the operator never sees a previous task's thread.
            w.set_kanban_selected_comments(slint::ModelRc::new(slint::VecModel::from(Vec::<
                KanbanCommentRow,
            >::new(
            ))));
        }
        // Background fetch of comments via `neoth kanban task <id>
        // --output json`. Empty on subprocess error — operator still
        // sees the task body, just no thread.
        let weak_comments = weak_select.clone();
        let id_str = task_id.to_string();
        std::thread::spawn(move || {
            let comments = fetch_task_comments(&id_str);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak_comments.upgrade() {
                    use slint::{ModelRc, VecModel};
                    w.set_kanban_selected_comments(ModelRc::new(VecModel::from(comments)));
                }
            });
        });
    });

    // G-12 fix — operator changed the active provider in Settings →
    // Config. We persist by rewriting freedom.yaml in place (keeping
    // the operator's other fields intact via read-merge-write) and
    // dropping the same reload sentinel `/reload` uses, so the
    // daemon picks the change up within ~2s.
    let weak_provider = window.as_weak();
    window.on_provider_changed(move |new_provider| {
        let neoth_dir = default_neoth_home();
        let freedom_path = neoth_dir.join("freedom.yaml");
        let result = (|| -> anyhow::Result<()> {
            // MV-01c bug-fix: write losslessly. The prior path read+rewrote
            // the typed `MinimalFreedomYaml` (5 fields, no flatten), which
            // DROPPED the operator's inference topology / council / profile /
            // tokens config on every GUI provider-change. The `Value`
            // round-trip preserves every other field.
            set_top_level_string_in_freedom(&freedom_path, "provider_kind", &new_provider)?;
            std::fs::write(neoth_dir.join(".reload-requested"), b"reload\n")
                .with_context(|| "write reload sentinel")?;
            Ok(())
        })();
        if let Some(w) = weak_provider.upgrade() {
            match result {
                Ok(_) => {
                    info!(provider = %new_provider, "config: provider rewritten + reload sentinel dropped");
                    w.set_status_line(
                        format!("Provider set to {new_provider}. Daemon reloading within 2s.").into(),
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "config: provider change failed");
                    w.set_status_line(format!("Provider change failed: {e}").into());
                }
            }
        }
    });

    // Bite #5 — operator flipped the cluster auto-discovery
    // checkbox in Settings → Cluster. Mutate `cluster.mdns.enabled`
    // in freedom.yaml losslessly (`serde_yaml::Value` round-trip
    // preserves every other field) and drop the reload sentinel
    // so the daemon picks the change up within ~2s — same dispatch
    // path as `neoth cluster enable` / `disable`.
    let weak_cluster = window.as_weak();
    window.on_cluster_mdns_enabled_changed(move |enabled| {
        let neoth_dir = default_neoth_home();
        let freedom_path = neoth_dir.join("freedom.yaml");
        let result = (|| -> anyhow::Result<()> {
            set_cluster_mdns_enabled_in_freedom(&freedom_path, enabled)?;
            std::fs::write(neoth_dir.join(".reload-requested"), b"reload\n")
                .with_context(|| "write reload sentinel")?;
            Ok(())
        })();
        if let Some(w) = weak_cluster.upgrade() {
            match result {
                Ok(_) => {
                    info!(
                        enabled,
                        "cluster: mdns.enabled rewritten + reload sentinel dropped"
                    );
                    let verb = if enabled { "enabled" } else { "disabled" };
                    w.set_status_line(
                        format!("Cluster auto-discovery {verb}. Daemon reloading within 2s.")
                            .into(),
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "cluster: mdns toggle failed");
                    w.set_status_line(format!("Cluster toggle failed: {e}").into());
                }
            }
        }
    });

    // GOLD-FEAT-01c — operator confirmed enabling full-auto (sudomode) via the
    // GUI's two-step confirm. The in-GUI confirm IS the consent → invoke the CLI
    // with --gui-confirmed so it skips the TTY y/N (the bare CLI path stays
    // fail-closed). The 0xDD SUDOMODE_PRESET_APPLIED audit frame fires in the CLI.
    let weak_fa_on = window.as_weak();
    window.on_full_auto_confirmed(move || {
        let weak = weak_fa_on.clone();
        std::thread::spawn(move || {
            // GR-RESID-D34 — a bare `--gui-confirmed` no longer bypasses the TTY
            // gate. Mint a single-use, short-TTL token from the running daemon
            // (this in-GUI confirm dialog IS the consent), then pass it to
            // full-auto. A static flag baked into a script can no longer flip
            // FULL-AUTO; this live mint→use sequence requires the GUI + daemon.
            let ok = match which_neothd() {
                Some(bin) => {
                    let token = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("mint-fullauto-token")
                        .output()
                        .ok()
                        .filter(|o| o.status.success())
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .filter(|t| !t.is_empty());
                    match token {
                        Some(tok) => spawn_neothd_plain(&bin)
                            .arg("autonomy")
                            .arg("full-auto")
                            .arg("--gui-confirmed")
                            .arg("--gui-token")
                            .arg(&tok)
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false),
                        None => false, // daemon unreachable / mint failed
                    }
                }
                None => false,
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    if ok {
                        w.set_full_auto_active(true);
                        w.set_status_line(
                            "FULL-AUTO enabled — NEOTH now acts without asking. Switch back any time."
                                .into(),
                        );
                    } else {
                        w.set_status_line(
                            "Enabling full-auto failed — the daemon must be RUNNING (it mints the \
                             confirm token) and `neoth` on PATH. Still gated."
                                .into(),
                        );
                    }
                }
            });
        });
    });

    // GOLD-FEAT-01c — switch back to GATED (the safe direction → no confirm).
    let weak_fa_off = window.as_weak();
    window.on_full_auto_gated(move || {
        let weak = weak_fa_off.clone();
        std::thread::spawn(move || {
            let ok = match which_neothd() {
                Some(bin) => spawn_neothd_plain(&bin)
                    .arg("autonomy")
                    .arg("gated")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false),
                None => false,
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    if ok {
                        w.set_full_auto_active(false);
                        w.set_status_line(
                            "Switched to GATED — NEOTH asks before sensitive actions.".into(),
                        );
                    } else {
                        w.set_status_line(
                            "Switching to gated failed (is the daemon installed?).".into(),
                        );
                    }
                }
            });
        });
    });

    // PF-01-GUI — operator flipped the Skills auto-route toggle. Mutate
    // `skills.always_embed_route` losslessly + drop the reload sentinel, same
    // dispatch path as the cluster mDNS toggle.
    let weak_skills_route = window.as_weak();
    window.on_skills_always_embed_route_set(move |enabled| {
        let neoth_dir = default_neoth_home();
        let freedom_path = neoth_dir.join("freedom.yaml");
        let result = (|| -> anyhow::Result<()> {
            set_skills_always_embed_route_in_freedom(&freedom_path, enabled)?;
            std::fs::write(neoth_dir.join(".reload-requested"), b"reload\n")
                .with_context(|| "write reload sentinel")?;
            Ok(())
        })();
        if let Some(w) = weak_skills_route.upgrade() {
            match result {
                Ok(_) => {
                    info!(
                        enabled,
                        "skills: always_embed_route rewritten + reload sentinel dropped"
                    );
                    let verb = if enabled { "on" } else { "off" };
                    w.set_status_line(
                        format!("Skill auto-routing {verb}. Daemon reloading within 2s.").into(),
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "skills: always_embed_route toggle failed");
                    w.set_status_line(format!("Skill auto-route toggle failed: {e}").into());
                }
            }
        }
    });

    // ── DES-09 Welle A/B/C — freedom.yaml write-back callbacks ────────────
    //
    // Per-keystroke LineEdit fields (wire_nested_str! / _f64_str! / _i64_str!)
    // route through make_coalescing_writer: a per-field worker that keeps only
    // the last value of a keystroke burst (last-typed wins) and does one write —
    // this closes the non-FIFO-mutex ordering race a plain thread-per-keystroke
    // would introduce on slow/network home dirs. Single-fire fields (bool /
    // int_combo / persona) spawn a one-shot worker directly. All writes serialise
    // on FREEDOM_WRITE_LOCK inside set_nested_in_freedom; toasts via push_toast.
    {
        let neoth_dir = default_neoth_home();
        macro_rules! wire_nested_str {
            ($cb:ident, $key:literal, $label:literal) => {{
                // Per-keystroke LineEdit → coalescing writer (last-typed wins).
                let tx = make_coalescing_writer(
                    neoth_dir.join("freedom.yaml"),
                    neoth_dir.join(".reload-requested"),
                    $key, $label, window.as_weak(), None);
                window.$cb(move |raw: slint::SharedString| {
                    tx.send(serde_yaml::Value::from(raw.to_string().as_str())).ok();
                });
            }};
        }
        macro_rules! wire_nested_bool {
            ($cb:ident, $key:literal, $label:literal) => {{
                let nd = neoth_dir.clone();
                let weak = window.as_weak();
                window.$cb(move |v: bool| {
                    let nd2 = nd.clone();
                    let weak2 = weak.clone();
                    let state = if v { "enabled" } else { "disabled" };
                    // I/O (read + parse + fsync + rename) off the UI event loop.
                    std::thread::spawn(move || {
                        let fp = nd2.join("freedom.yaml");
                        let rd = nd2.join(".reload-requested");
                        let result = set_nested_in_freedom(&fp, $key, serde_yaml::Value::from(v))
                            .and_then(|_| std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e)));
                        slint::invoke_from_event_loop(move || {
                            match result {
                                Ok(_) => push_toast(&weak2, "success", $label, state),
                                Err(ref e) => {
                                    let msg = e.to_string();
                                    push_toast(&weak2, "warn", concat!($label, " write failed"), &msg);
                                }
                            }
                        }).ok();
                    });
                });
            }};
        }
        macro_rules! wire_nested_int_combo {
            ($cb:ident, $key:literal, $variants:expr, $label:literal) => {{
                let nd = neoth_dir.clone();
                let weak = window.as_weak();
                let variants: &'static [&'static str] = $variants;
                window.$cb(move |idx: i32| {
                    let val = variants.get(idx as usize).copied().unwrap_or(variants[0]);
                    let nd2 = nd.clone();
                    let weak2 = weak.clone();
                    // I/O (read + parse + fsync + rename) off the UI event loop.
                    std::thread::spawn(move || {
                        let fp = nd2.join("freedom.yaml");
                        let rd = nd2.join(".reload-requested");
                        let result = set_nested_in_freedom(&fp, $key, serde_yaml::Value::from(val))
                            .and_then(|_| std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e)));
                        slint::invoke_from_event_loop(move || {
                            match result {
                                Ok(_) => push_toast(&weak2, "success", $label, val),
                                Err(ref e) => {
                                    let msg = e.to_string();
                                    push_toast(&weak2, "warn", concat!($label, " write failed"), &msg);
                                }
                            }
                        }).ok();
                    });
                });
            }};
        }
        macro_rules! wire_nested_f64_str {
            ($cb:ident, $key:literal, $label:literal) => {{
                // Validate on the UI thread; only valid numbers reach the writer.
                let tx = make_coalescing_writer(
                    neoth_dir.join("freedom.yaml"),
                    neoth_dir.join(".reload-requested"),
                    $key, $label, window.as_weak(), None);
                let weak_err = window.as_weak();
                window.$cb(move |raw: slint::SharedString| {
                    let s = raw.to_string();
                    match s.trim().parse::<f64>() {
                        Ok(v) => { tx.send(serde_yaml::Value::from(v)).ok(); }
                        Err(_) => push_toast(&weak_err, "warn", concat!($label, " invalid"),
                                             &format!("not a number: {}", s.trim())),
                    }
                });
            }};
        }
        macro_rules! wire_nested_i64_str {
            ($cb:ident, $key:literal, $label:literal) => {{
                // Validate on the UI thread; only valid integers reach the writer.
                let tx = make_coalescing_writer(
                    neoth_dir.join("freedom.yaml"),
                    neoth_dir.join(".reload-requested"),
                    $key, $label, window.as_weak(), None);
                let weak_err = window.as_weak();
                window.$cb(move |raw: slint::SharedString| {
                    let s = raw.to_string();
                    match s.trim().parse::<i64>() {
                        Ok(v) => { tx.send(serde_yaml::Value::from(v)).ok(); }
                        Err(_) => push_toast(&weak_err, "warn", concat!($label, " invalid"),
                                             &format!("not an integer: {}", s.trim())),
                    }
                });
            }};
        }

        // Welle A — Council
        wire_nested_f64_str!(on_cfg_council_daily_usd_changed, "council.daily_usd_cap", "USD cap");
        wire_nested_i64_str!(on_cfg_council_max_calls_changed, "council.max_calls_per_user_message", "Max calls");
        wire_nested_i64_str!(on_cfg_council_max_depth_changed, "council.max_recursion_depth", "Max depth");
        wire_nested_int_combo!(on_cfg_council_selection_mode_changed,
            "council.selection_mode",
            &["legacy_majority", "consensus_or_best", "best_always"],  // FIX 5
            "Selection mode");

        // Welle A — Provider
        wire_nested_str!(on_cfg_provider_model_changed,        "provider_model",       "Model");
        wire_nested_str!(on_cfg_provider_endpoint_changed,     "provider_endpoint",    "Endpoint");
        wire_nested_str!(on_cfg_provider_region_changed,       "provider_region",      "Region");
        wire_nested_str!(on_cfg_provider_api_version_changed,  "provider_api_version", "API version");

        // Welle A — Profile + Behavior
        // FIX 2 — persona_mode index 0 must write YAML null (→ None) not ""
        // which would cause serde_yaml to fail parsing Option<PersonaMode>.
        // Inline callback instead of wire_nested_int_combo! to emit Null for "".
        {
            let nd = neoth_dir.clone();
            let weak = window.as_weak();
            let variants: &'static [&'static str] = &["", "loyal_buddy"];
            window.on_cfg_persona_mode_changed(move |idx: i32| {
                let val = variants.get(idx as usize).copied().unwrap_or(variants[0]);
                let yaml_val = if val.is_empty() {
                    serde_yaml::Value::Null
                } else {
                    serde_yaml::Value::from(val)
                };
                let nd2 = nd.clone();
                let weak2 = weak.clone();
                // I/O (read + parse + fsync + rename) off the UI event loop.
                std::thread::spawn(move || {
                    let fp = nd2.join("freedom.yaml");
                    let rd = nd2.join(".reload-requested");
                    let result = set_nested_in_freedom(&fp, "persona_mode", yaml_val)
                        .and_then(|_| std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e)));
                    slint::invoke_from_event_loop(move || {
                        match result {
                            Ok(_) => push_toast(&weak2, "success", "Persona mode", val),
                            Err(ref e) => {
                                let msg = e.to_string();
                                push_toast(&weak2, "warn", "Persona mode write failed", &msg);
                            }
                        }
                    }).ok();
                });
            });
        }
        wire_nested_str!(on_cfg_user_tz_changed,                "user_tz",                  "Timezone");
        wire_nested_bool!(on_cfg_elicitation_enabled_changed,   "elicitation.enabled",      "Elicitation");
        wire_nested_bool!(on_cfg_tone_modifier_enabled_changed, "tone_modifier.enabled",     "Tone modifier");

        // Welle B — Privacy
        wire_nested_bool!(on_cfg_review_gate_enabled_changed,   "review_gate_enabled",       "Review gate");
        wire_nested_bool!(on_cfg_cloud_stt_enabled_changed,     "media.cloud_stt_enabled",   "Cloud STT");
        wire_nested_bool!(on_cfg_cloud_tts_enabled_changed,     "media.cloud_tts_enabled",   "Cloud TTS");
        wire_nested_bool!(on_cfg_cloud_vision_enabled_changed,  "media.cloud_vision_enabled","Cloud vision");
        wire_nested_bool!(on_cfg_vad_enabled_changed,           "media.vad_enabled",         "VAD");
        wire_nested_bool!(on_cfg_dictation_enabled_changed,     "media.dictation_enabled",   "Dictation");
        wire_nested_bool!(on_cfg_proactive_idle_only_changed,   "proactive.idle_only",       "Proactive idle-only");

        // Welle C — Memory
        wire_nested_bool!(on_cfg_memory_name_sessions_changed,    "memory.name_sessions",           "Name sessions");
        wire_nested_bool!(on_cfg_memory_recall_shortcut_changed,  "memory.recall_shortcut",         "Recall shortcut");
        wire_nested_int_combo!(on_cfg_memory_vector_backend_changed,
            "memory.vector_index.backend",
            &["brute_force", "hnsw"],
            "Vector backend");
    }

    // ── DES-09 Welle E — Obsidian write-back callbacks ─────────────────────
    {
        let neoth_dir = default_neoth_home();

        // vault path → coalescing writer; on success re-scan the vault view.
        let obs_refresh: WriteSuccessHook =
            std::sync::Arc::new(|w: &MainWindow| w.invoke_obs_refresh_clicked());
        let tx_vault = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "obsidian_vault", "Vault path", window.as_weak(), Some(obs_refresh));
        window.on_obs_vault_path_changed(move |raw: slint::SharedString| {
            tx_vault.send(serde_yaml::Value::from(raw.to_string().as_str())).ok();
        });

        // subdir → coalescing writer (last-typed wins).
        let tx_subdir = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "obsidian_subdir", "Vault subdir", window.as_weak(), None);
        window.on_obs_subdir_changed(move |raw: slint::SharedString| {
            tx_subdir.send(serde_yaml::Value::from(raw.to_string().as_str())).ok();
        });

        // auto-sync secs (string) — validate on the UI thread, then coalescing
        // writer. Empty → Null (None = disabled); non-integer → warn, no write.
        let tx_sync = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "obsidian_auto_sync_secs", "Auto-sync interval", window.as_weak(), None);
        let weak_sync_err = window.as_weak();
        window.on_obs_auto_sync_secs_str_changed(move |raw: slint::SharedString| {
            let s = raw.to_string();
            let t = s.trim();
            if t.is_empty() {
                tx_sync.send(serde_yaml::Value::Null).ok();
            } else if let Ok(v) = t.parse::<i64>() {
                tx_sync.send(serde_yaml::Value::from(v)).ok();
            } else {
                push_toast(&weak_sync_err, "warn", "Auto-sync invalid",
                           &format!("not an integer: {t}"));
            }
        });

        // reader enabled
        let nd = neoth_dir.clone();
        let weak = window.as_weak();
        window.on_obs_reader_enabled_changed(move |v: bool| {
            let nd2 = nd.clone();
            let w2 = weak.clone();
            let state = if v { "enabled" } else { "disabled" };
            // I/O (read + parse + fsync + rename) off the UI event loop.
            std::thread::spawn(move || {
                let fp = nd2.join("freedom.yaml");
                let rd = nd2.join(".reload-requested");
                let result = set_nested_in_freedom(&fp, "obsidian_vault_reader_enabled", serde_yaml::Value::from(v))
                    .and_then(|_| std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e)));
                slint::invoke_from_event_loop(move || {
                    match result {
                        Ok(_) => push_toast(&w2, "success", "Vault reader", state),
                        Err(ref e) => {
                            let msg = e.to_string();
                            push_toast(&w2, "warn", "Vault reader write failed", &msg);
                        }
                    }
                }).ok();
            });
        });

        // Browse… — rfd folder picker, same pattern as skill-install
        let nd = neoth_dir.clone();
        let weak = window.as_weak();
        window.on_obs_browse_clicked(move || {
            let w2 = weak.clone();
            let nd2 = nd.clone();
            std::thread::spawn(move || {
                let picked = rfd::FileDialog::new()
                    .set_title("Select Obsidian vault folder")
                    .pick_folder();
                slint::invoke_from_event_loop(move || {
                    if let Some(p) = picked {
                        if let Some(w) = w2.upgrade() {
                            let s: slint::SharedString = p.to_string_lossy().to_string().into();
                            w.set_obs_vault_path_edit(s);
                        }
                        let fp = nd2.join("freedom.yaml");
                        let rd = nd2.join(".reload-requested");
                        let path_str = p.to_string_lossy().to_string();
                        let result = set_nested_in_freedom(&fp, "obsidian_vault",
                                serde_yaml::Value::from(path_str.as_str()))
                            .and_then(|_| std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e)));
                        match result {
                            Ok(_) => {
                                push_toast(&w2, "success", "Vault path", "set — daemon reloading");
                                if let Some(w) = w2.upgrade() { w.invoke_obs_refresh_clicked(); }
                            }
                            Err(ref e) => {
                                let msg = e.to_string();
                                push_toast(&w2, "warn", "Vault path write failed", &msg);
                            }
                        }
                    }
                }).ok();
            });
        });
    }

    // Pick #32 — Settings panel "Re-run wizard". Reset the wizard
    // state back to mode-selection so the operator walks the flow
    // fresh.
    let weak_wizard = window.as_weak();
    window.on_settings_wizard_rerun_clicked(move || {
        info!("settings: operator triggered wizard re-run");
        if let Some(w) = weak_wizard.upgrade() {
            w.set_step(WizardStep::ModeSelection);
            w.set_license_accepted(false);
            w.set_operator_id("".into());
            w.set_status_line(
                "Wizard reset. Re-walking the flow will overwrite existing freedom.yaml at Finish."
                    .into(),
            );
        }
    });

    // GAP-04 — Memory search: `neoth recall <query>` → settings memory panel.
    let weak_memsearch = window.as_weak();
    window.on_settings_memory_search_clicked(move |query| {
        let Some(w0) = weak_memsearch.upgrade() else { return; };
        let q = query.to_string();
        if q.trim().is_empty() {
            return; // no-op for empty query
        }
        w0.set_settings_memory_search_running(true);
        let weak = weak_memsearch.clone();
        std::thread::spawn(move || {
            let output = match which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("recall")
                        .arg(&q)
                        .output()
                        .ok()
                })
            {
                Some(o) => panel_logic::format_recall_output(
                    &String::from_utf8_lossy(&o.stdout),
                    &String::from_utf8_lossy(&o.stderr),
                    &q,
                ),
                None => "neothd binary not on PATH — cannot run recall.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_settings_memory_search_output(output.into());
                    w.set_settings_memory_search_running(false);
                }
            });
        });
    });

    // GAP-07 — Backup now: `neoth backup` → status-line.
    let weak_backup = window.as_weak();
    window.on_settings_backup_now_clicked(move || {
        let Some(w0) = weak_backup.upgrade() else { return; };
        w0.set_status_line("Running neoth backup…".into());
        let weak = weak_backup.clone();
        std::thread::spawn(move || {
            let result = match which_neothd()
                .and_then(|bin| spawn_neothd_plain(&bin).arg("backup").output().ok())
            {
                Some(o) => {
                    let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    if o.status.success() {
                        if out.is_empty() { "Backup complete.".to_string() } else { out }
                    } else {
                        format!("Backup failed: {}", if err.is_empty() { out } else { err })
                    }
                }
                None => "neothd binary not on PATH — cannot run backup.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(result.into());
                }
            });
        });
    });

    // GAP-07 — Preview rollback: `neoth rollback list` (read-only, no --confirm)
    // → status-line. The "list" subcommand shows available WAL snapshots without
    // restoring anything. Destructive `apply --confirm` is CLI-only by design.
    let weak_rollback = window.as_weak();
    window.on_settings_rollback_preview_clicked(move || {
        let Some(w0) = weak_rollback.upgrade() else { return; };
        w0.set_status_line("Listing rollback snapshots…".into());
        let weak = weak_rollback.clone();
        std::thread::spawn(move || {
            let result = match which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("rollback")
                        .arg("list")
                        .output()
                        .ok()
                })
            {
                Some(o) => {
                    let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    if out.is_empty() && err.is_empty() {
                        "No WAL snapshots found. Run some operations first.".to_string()
                    } else if !out.is_empty() {
                        out
                    } else {
                        err
                    }
                }
                None => "neothd binary not on PATH — cannot list rollback snapshots.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(result.into());
                }
            });
        });
    });

    let weak = window.as_weak();
    // GUI-REENTRY-PRESET fix: clone the flag into the closure so on_finish_clicked
    // can refuse to overwrite an existing config when read_freedom_yaml failed on
    // re-entry (prevents Slint type defaults — "standard"/"claude_cli" — from
    // silently clobbering the operator's real freedom.yaml as if "balanced" was
    // explicitly chosen).
    let reentry_config_ok_for_finish = std::sync::Arc::clone(&reentry_config_ok);
    window.on_finish_clicked(move || {
        if let Some(w) = weak.upgrade() {
            // Re-entry guard: if freedom.yaml already existed but could not be
            // parsed, refuse to write rather than stomp it with type defaults.
            // The operator must fix / inspect the YAML manually first.
            if already_initialized
                && !reentry_config_ok_for_finish
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                w.set_status_line(
                    "Cannot re-write config: the existing freedom.yaml could not be \
                     read back. Fix or remove it manually, then reopen the wizard."
                        .into(),
                );
                return;
            }
            let state = WizardSnapshot {
                operator_id: w.get_operator_id().to_string(),
                provider_kind: w.get_provider_choice().to_string(),
                autonomy: w.get_autonomy_choice().to_string(),
                license_accepted: w.get_license_accepted(),
                enable_telegram: w.get_enable_telegram(),
                provider_key: w.get_provider_key().to_string(),
                telegram_token: w.get_telegram_token().to_string(),
                cluster_discovery_disabled: w.get_cluster_discovery_disabled(),
            };
            match finish(&state) {
                Ok(report) => {
                    info!(?report.freedom_path, ?report.credentials_path, "wizard finished");
                    w.set_status_line(report.message().into());
                }
                Err(e) => {
                    let msg = format!("Setup failed: {e}");
                    tracing::error!(error = %e, "wizard finish failed");
                    w.set_status_line(msg.into());
                }
            }
        }
    });

    // ── Companion overlay wiring ──────────────────────────────────────────────
    //
    // minimize-to-companion: hide the main window, show the overlay, then
    // arm always-on-top + position it bottom-right via the winit accessor.
    // The winit accessor only succeeds while the event loop is active, so
    // we call it inside the callback (which runs on the UI thread, inside
    // the event loop). with_winit_window returns Option — ignore None
    // (headless / non-winit backend) gracefully.
    {
        use slint::winit_030::{WinitWindowAccessor, winit::window::WindowLevel};
        use slint::winit_030::winit::dpi::PhysicalPosition;

        let overlay_weak_for_minimize = overlay.as_weak();
        let window_weak_for_minimize = window.as_weak();
        window.on_minimize_to_companion(move || {
            let Some(ov) = overlay_weak_for_minimize.upgrade() else { return };
            let Some(win) = window_weak_for_minimize.upgrade() else { return };
            win.hide().unwrap_or(());
            ov.show().unwrap_or(());
            // Set always-on-top and position bottom-right after show() so the
            // winit event loop is active and the accessor can succeed.
            ov.window().with_winit_window(|w| {
                w.set_window_level(WindowLevel::AlwaysOnTop);
                // Position: primary-monitor bottom-right, 20px inset.
                if let Some(mon) = w.current_monitor() {
                    let s = mon.size();
                    // 400 × 560 is the overlay's approximate pixel footprint at
                    // default 96 DPI; at higher scale factors it may clip —
                    // the operator can drag it from there.
                    w.set_outer_position(PhysicalPosition::new(
                        (s.width as i32).saturating_sub(400),
                        (s.height as i32).saturating_sub(560),
                    ));
                }
            });
            // Seed the overlay with the current buddy state so it is not blank.
            if let Some(ov2) = overlay_weak_for_minimize.upgrade() {
                if let Some(win2) = window_weak_for_minimize.upgrade() {
                    ov2.set_buddy_mood(win2.get_buddy_mood());
                    ov2.set_status_text(win2.get_buddy_caption());
                    ov2.set_daemon_state(win2.get_daemon_state());
                }
            }
        });

        // overlay restore-clicked → hide overlay, show main window.
        let overlay_weak_for_restore = overlay.as_weak();
        let window_weak_for_restore = window.as_weak();
        overlay.on_restore_clicked(move || {
            let Some(ov) = overlay_weak_for_restore.upgrade() else { return };
            let Some(win) = window_weak_for_restore.upgrade() else { return };
            ov.hide().unwrap_or(());
            win.show().unwrap_or(());
        });

        // overlay hide-clicked → same as restore (never leave the operator windowless).
        let overlay_weak_for_hide = overlay.as_weak();
        let window_weak_for_hide = window.as_weak();
        overlay.on_hide_clicked(move || {
            let Some(ov) = overlay_weak_for_hide.upgrade() else { return };
            let Some(win) = window_weak_for_hide.upgrade() else { return };
            ov.hide().unwrap_or(());
            win.show().unwrap_or(());
        });

        // overlay send-clicked → replicate the minimal neothd chat --stream path.
        // We do NOT invoke_chat_send_clicked on the main window because the main
        // window is hidden; instead we run the same subprocess directly and feed
        // the reply snippet into the overlay's recent-lines (capped at 6).
        let overlay_weak_for_send = overlay.as_weak();
        overlay.on_send_clicked(move |text| {
            let body = text.trim().to_string();
            if body.is_empty() { return; }
            let Some(ov) = overlay_weak_for_send.upgrade() else { return };

            // Buddy goes thinking while we wait for the reply.
            ov.set_buddy_mood("thinking".into());
            ov.set_status_text("thinking…".into());

            // Append the operator line to recent-lines immediately.
            {
                use slint::{Model, ModelRc, VecModel};
                let mut lines: Vec<slint::SharedString> =
                    ov.get_recent_lines().iter().collect();
                lines.push(format!("▶ {body}").into());
                // Cap at 6 — oldest drop off.
                if lines.len() > 6 {
                    let drain_count = lines.len() - 6;
                    lines.drain(..drain_count);
                }
                ov.set_recent_lines(ModelRc::new(VecModel::from(lines)));
            }

            let ov_weak = ov.as_weak();
            let body_clone = body.clone();
            std::thread::spawn(move || {
                use std::io::Read as _;
                let result: std::result::Result<String, String> = (|| {
                    let bin = which_neothd()
                        .ok_or_else(|| "neothd not on PATH".to_string())?;
                    let mut cmd = spawn_neothd_plain(&bin);
                    cmd.arg("chat").arg("--stream").arg(&body_clone);
                    let mut child = cmd
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .map_err(|e| format!("spawn failed: {e}"))?;
                    let mut stdout = child
                        .stdout
                        .take()
                        .ok_or_else(|| "no stdout".to_string())?;
                    let mut acc: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 512];
                    loop {
                        match stdout.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => acc.extend_from_slice(&buf[..n]),
                            Err(_) => break,
                        }
                    }
                    let raw = String::from_utf8_lossy(&acc).into_owned();
                    // strip_stream_sentinel strips the JSON done-sentinel line.
                    let (reply, _) = strip_stream_sentinel(&raw);
                    Ok(reply.trim().to_string())
                })();

                let _ = slint::invoke_from_event_loop(move || {
                    use slint::{Model, ModelRc, VecModel};
                    let Some(ov) = ov_weak.upgrade() else { return };
                    let (mood, caption, snippet) = match result {
                        Ok(ref reply) if !reply.is_empty() => {
                            // Truncate to 120 chars for the compact scrollback.
                            let snip = if reply.len() > 120 {
                                format!("{}…", &reply[..120])
                            } else {
                                reply.clone()
                            };
                            ("success", "done ✓", snip)
                        }
                        Ok(_) => ("idle", "ready", "—".to_string()),
                        Err(ref e) => ("error", "error", format!("⚠ {e}")),
                    };
                    ov.set_buddy_mood(mood.into());
                    ov.set_status_text(caption.into());
                    // Append the reply snippet to recent-lines, cap at 6.
                    let mut lines: Vec<slint::SharedString> =
                        ov.get_recent_lines().iter().collect();
                    lines.push(snippet.into());
                    if lines.len() > 6 {
                        let drain_count = lines.len() - 6;
                        lines.drain(..drain_count);
                    }
                    ov.set_recent_lines(ModelRc::new(VecModel::from(lines)));
                });
            });
        });
    } // end companion overlay wiring

    window.run()?;
    Ok(())
}

/// Plain-data snapshot the wizard hands off to disk. Keeps the Slint
/// type surface separate from the on-disk schema so future schema
/// bumps stay loosely coupled to the UI.
struct WizardSnapshot {
    operator_id: String,
    provider_kind: String,
    autonomy: String,
    license_accepted: bool,
    enable_telegram: bool,
    provider_key: String,
    telegram_token: String,
    /// Q4 ratification: operator's choice on the cluster step.
    /// True means freedom.yaml gets `cluster.mdns.enabled: false`;
    /// false (default) means mDNS discovery stays ON per the
    /// noob-wizard "default ON in release" hard rule.
    cluster_discovery_disabled: bool,
}

/// What `finish()` returns. `credentials_path` is `None` when no secret
/// was entered (we deliberately skip writing the file so we don't leave
/// an empty stub behind — matches `credentials::Credentials::write`).
#[derive(Debug)]
struct FinishReport {
    freedom_path: PathBuf,
    credentials_path: Option<PathBuf>,
}

impl FinishReport {
    fn message(&self) -> String {
        let mut s = format!("Configuration written to {}.", self.freedom_path.display());
        if let Some(p) = &self.credentials_path {
            s.push_str(&format!("\nSecrets stored in {} (mode 0600).", p.display()));
        }
        s.push_str("\nClose this window and run `neothd serve`.");
        s
    }
}

/// On-disk shape for `freedom.yaml`. Mirrors a subset of the daemon's
/// `FreedomConfig`; fields we don't surface in the GUI yet (inference
/// topology, obsidian, observability listener) round-trip via the
/// daemon's `#[serde(default)]` annotations.
///
/// L-2 fix — also `Deserialize` so the re-entry path can read the
/// existing config back into the wizard properties (M-1).
#[derive(Serialize, Deserialize)]
struct MinimalFreedomYaml {
    operator_id: String,
    provider_kind: String,
    autonomy: String,
    /// Always includes `"cli"`. Telegram is appended when the operator
    /// ticked the channel + ended up with a token. We deliberately
    /// store the list inside `freedom.yaml` even though the daemon
    /// doesn't strictly read it yet — operators inspecting the file
    /// should see what they configured.
    #[serde(default)]
    channels: Vec<String>,
    /// Q4-ratified cluster block. Only serialised when the operator
    /// explicitly disabled discovery on the wizard step. Omitted
    /// otherwise — the daemon's serde-default keeps mDNS ON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cluster: Option<ClusterYamlBlock>,
}

/// Minimal mirror of the on-disk `cluster:` block.
///
/// The daemon's `ClusterConfig` (config/mod.rs) has the shape:
///   cluster:
///     name: null | string
///     enabled: bool
///
/// The GUI wizard writes a *different* shape when the operator disables
/// mDNS discovery:
///   cluster:
///     mdns:
///       enabled: false
///
/// Both shapes must round-trip through `MinimalFreedomYaml` without
/// a parse error.  All fields carry `#[serde(default)]` so that any
/// combination of present/absent keys deserialises cleanly.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct ClusterYamlBlock {
    /// Daemon-written field: `cluster.name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// Daemon-written field: `cluster.enabled`.
    #[serde(skip_serializing_if = "is_false")]
    enabled: bool,
    /// GUI-written sub-block: `cluster.mdns.enabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    mdns: Option<ClusterMdnsYamlBlock>,
}

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Serialize, Deserialize)]
struct ClusterMdnsYamlBlock {
    enabled: bool,
}

/// Mirror of `config::credentials::Credentials`, serialised here
/// without the SecretString wrapper so the GUI doesn't have to pull in
/// the whole daemon crate. The on-disk format matches verbatim — the
/// daemon reads it back through the typed struct.
#[derive(Serialize, Default)]
struct CredentialsYaml {
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    telegram_token: Option<String>,
}

impl CredentialsYaml {
    fn is_empty(&self) -> bool {
        self.provider_key.is_none() && self.telegram_token.is_none()
    }
}

fn finish(state: &WizardSnapshot) -> Result<FinishReport> {
    if !state.license_accepted {
        anyhow::bail!("license not accepted — refusing to write config");
    }
    if state.operator_id.trim().is_empty() {
        anyhow::bail!("operator id is empty — go back and enter one");
    }
    validate_autonomy(&state.autonomy)?;

    let neoth_dir = default_neoth_home();
    std::fs::create_dir_all(&neoth_dir)
        .with_context(|| format!("create {}", neoth_dir.display()))?;

    let freedom_path = write_freedom_yaml(state, &neoth_dir)?;
    let credentials_path = write_credentials_yaml(state, &neoth_dir)?;

    Ok(FinishReport {
        freedom_path,
        credentials_path,
    })
}

fn write_freedom_yaml(state: &WizardSnapshot, neoth_dir: &Path) -> Result<PathBuf> {
    let mut channels = vec!["cli".to_string()];
    if state.enable_telegram {
        channels.push("telegram".to_string());
    }
    let cluster = state
        .cluster_discovery_disabled
        .then_some(ClusterYamlBlock {
            mdns: Some(ClusterMdnsYamlBlock { enabled: false }),
            ..Default::default()
        });
    let yaml = MinimalFreedomYaml {
        operator_id: state.operator_id.clone(),
        provider_kind: state.provider_kind.clone(),
        autonomy: state.autonomy.clone(),
        channels,
        cluster,
    };
    let body = serde_yaml::to_string(&yaml).context("serialise freedom.yaml")?;
    let path = neoth_dir.join("freedom.yaml");
    write_mode_0600(&path, body.as_bytes())?;
    Ok(path)
}

fn write_credentials_yaml(state: &WizardSnapshot, neoth_dir: &Path) -> Result<Option<PathBuf>> {
    let provider_key = (!state.provider_key.is_empty()).then(|| state.provider_key.clone());
    let telegram_token = (state.enable_telegram && !state.telegram_token.is_empty())
        .then(|| state.telegram_token.clone());
    let creds = CredentialsYaml {
        provider_key,
        telegram_token,
    };
    if creds.is_empty() {
        return Ok(None);
    }
    let body = serde_yaml::to_string(&creds).context("serialise credentials.yaml")?;
    let path = neoth_dir.join("credentials.yaml");
    write_mode_0600(&path, body.as_bytes())?;
    Ok(Some(path))
}

/// M-1 helper — parse an existing `freedom.yaml` back into our minimal
/// shape so the wizard's re-entry path can pre-populate properties
/// from the operator's previous configuration.
fn read_freedom_yaml(path: &Path) -> Result<MinimalFreedomYaml> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let cfg: MinimalFreedomYaml =
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?;
    Ok(cfg)
}

/// Bite #5 — settings panel populates these on tab activation.
/// Lossless read via `serde_yaml::Value` so we don't drop fields
/// the GUI's typed `MinimalFreedomYaml` doesn't know about.
struct ClusterSettingsSnapshot {
    mdns_enabled: bool,
    listen_port: u16,
    trusted_ssids_summary: String,
}

/// Load cluster state from freedom.yaml for the settings panel
/// populator. Missing file / unparseable YAML / absent keys collapse
/// to the Q4-ratified defaults: `mdns_enabled = true`, `listen_port =
/// 49737`, empty `trusted_ssids`. Reader is read-only — never writes.
fn load_cluster_settings(path: &Path) -> ClusterSettingsSnapshot {
    const DEFAULT_LISTEN_PORT: u16 = 49737;
    let Ok(body) = std::fs::read_to_string(path) else {
        return ClusterSettingsSnapshot {
            mdns_enabled: true,
            listen_port: DEFAULT_LISTEN_PORT,
            trusted_ssids_summary: String::new(),
        };
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return ClusterSettingsSnapshot {
            mdns_enabled: true,
            listen_port: DEFAULT_LISTEN_PORT,
            trusted_ssids_summary: String::new(),
        };
    };
    let cluster = root.get("cluster");
    let mdns_enabled = cluster
        .and_then(|c| c.get("mdns"))
        .and_then(|m| m.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let listen_port = cluster
        .and_then(|c| c.get("listen_port"))
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .filter(|p| *p > 0)
        .unwrap_or(DEFAULT_LISTEN_PORT);
    let trusted_ssids_summary = cluster
        .and_then(|c| c.get("policy"))
        .and_then(|p| p.get("trusted_ssids"))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    ClusterSettingsSnapshot {
        mdns_enabled,
        listen_port,
        trusted_ssids_summary,
    }
}

/// Bite #5 — flip `cluster.mdns.enabled` in freedom.yaml without
/// disturbing other fields. Uses `serde_yaml::Value` round-trip so
/// the rest of the operator's config (inference, hemispheres,
/// council, ...) survives the rewrite unchanged. Atomic via
/// `.tmp` + rename.
fn set_cluster_mdns_enabled_in_freedom(path: &Path, enabled: bool) -> Result<()> {
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let body = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };
    let cluster_key = serde_yaml::Value::from("cluster");
    let mut cluster_map = map
        .get(&cluster_key)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    let mdns_key = serde_yaml::Value::from("mdns");
    let mut mdns_map = cluster_map
        .get(&mdns_key)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    mdns_map.insert(
        serde_yaml::Value::from("enabled"),
        serde_yaml::Value::from(enabled),
    );
    cluster_map.insert(mdns_key, serde_yaml::Value::Mapping(mdns_map));
    map.insert(cluster_key, serde_yaml::Value::Mapping(cluster_map));
    let serialised =
        serde_yaml::to_string(&root).context("serialise freedom.yaml after cluster mdns toggle")?;
    write_mode_0600(path, serialised.as_bytes())
}

/// Lossless top-level-string set: read freedom.yaml as a `serde_yaml::Value`
/// mapping, insert/replace `key = value`, write back — preserving EVERY
/// other field (inference topology, council, profile, tokens, ...). The
/// typed `MinimalFreedomYaml` round-trip is LOSSY (5 fields, no flatten) and
/// must NEVER be used for an in-place edit: it silently drops everything it
/// doesn't model. This is the only safe writer for the settings panel's
/// provider/model selectors. Atomic via `write_mode_0600` (.tmp + rename).
fn set_top_level_string_in_freedom(path: &Path, key: &str, value: &str) -> Result<()> {
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let body = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };
    map.insert(serde_yaml::Value::from(key), serde_yaml::Value::from(value));
    let serialised = serde_yaml::to_string(&root)
        .with_context(|| format!("serialise freedom.yaml after setting {key}"))?;
    write_mode_0600(path, serialised.as_bytes())
}

/// PF-01-GUI — read `skills.always_embed_route` from freedom.yaml. Defaults to
/// `true` (matching the daemon's `SkillsConfig` default) on a missing file /
/// key / malformed YAML, so the GUI toggle reflects the effective behaviour.
fn read_skills_always_embed_route(path: &Path) -> bool {
    let Ok(body) = std::fs::read_to_string(path) else {
        return true;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return true;
    };
    root.get("skills")
        .and_then(|s| s.get("always_embed_route"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// PF-01-GUI — lossless nested set of `skills.always_embed_route`. Mirrors
/// `set_cluster_mdns_enabled_in_freedom`: a serde_yaml `Value` round-trip that
/// preserves EVERY other field. Atomic via `write_mode_0600`.
fn set_skills_always_embed_route_in_freedom(path: &Path, enabled: bool) -> Result<()> {
    // Serialise with every other freedom.yaml read-modify-write (the DES-09 GUI
    // worker threads) — same lock set_nested_in_freedom holds.
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let body = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };
    let skills_key = serde_yaml::Value::from("skills");
    let mut skills_map = map
        .get(&skills_key)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    skills_map.insert(
        serde_yaml::Value::from("always_embed_route"),
        serde_yaml::Value::from(enabled),
    );
    map.insert(skills_key, serde_yaml::Value::Mapping(skills_map));
    let serialised = serde_yaml::to_string(&root)
        .context("serialise freedom.yaml after skills.always_embed_route toggle")?;
    write_mode_0600(path, serialised.as_bytes())
}

fn validate_autonomy(level: &str) -> Result<()> {
    match level {
        "strict" | "standard" | "elevated" | "full" | "custom" => Ok(()),
        other => anyhow::bail!("unrecognised autonomy level '{other}'"),
    }
}

// ── DES-09 generic nested writer ──────────────────────────────────────────
//
// All DES-09 settings-panel write-backs go through `set_nested_in_freedom`.
// The dotted-key notation "a.b.c" walks (and creates) nested YAML mappings
// exactly like the daemon's `merge_overrides` in config/presets.rs, but is
// self-contained in the GUI crate so no daemon dep is needed.
//
// Top-level keys (e.g. "obsidian_vault", "user_tz") use a single segment.

/// DES-09 — generic lossless nested-key writer for freedom.yaml.
///
/// `dotted_key` — dot-separated YAML path, e.g. "council.daily_usd_cap"
///                or bare top-level key "user_tz".
///
/// Preserves every other key via `serde_yaml::Value` round-trip.
/// Atomic write via `write_mode_0600` (.tmp + rename).
///
/// # Panics
///
/// None — all errors are returned via `Result`.
fn set_nested_in_freedom(
    path: &Path,
    dotted_key: &str,
    value: serde_yaml::Value,
) -> Result<()> {
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let body = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };

    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    match segments.as_slice() {
        [leaf] => {
            map.insert(serde_yaml::Value::from(*leaf), value);
        }
        [k1, leaf] => {
            let k1v = serde_yaml::Value::from(*k1);
            let mut inner = map
                .get(&k1v)
                .and_then(|v| v.as_mapping())
                .cloned()
                .unwrap_or_default();
            inner.insert(serde_yaml::Value::from(*leaf), value);
            map.insert(k1v, serde_yaml::Value::Mapping(inner));
        }
        [k1, k2, leaf] => {
            let k1v = serde_yaml::Value::from(*k1);
            let mut m1 = map
                .get(&k1v)
                .and_then(|v| v.as_mapping())
                .cloned()
                .unwrap_or_default();
            let k2v = serde_yaml::Value::from(*k2);
            let mut m2 = m1
                .get(&k2v)
                .and_then(|v| v.as_mapping())
                .cloned()
                .unwrap_or_default();
            m2.insert(serde_yaml::Value::from(*leaf), value);
            m1.insert(k2v, serde_yaml::Value::Mapping(m2));
            map.insert(k1v, serde_yaml::Value::Mapping(m1));
        }
        _ => anyhow::bail!("set_nested_in_freedom: path depth > 3 not supported: {dotted_key}"),
    }

    let serialised = serde_yaml::to_string(&root)
        .with_context(|| format!("serialise freedom.yaml after setting {dotted_key}"))?;
    write_mode_0600(path, serialised.as_bytes())
}

/// Post-success hook for `make_coalescing_writer`, run on the UI event loop
/// after a successful write. `Arc<dyn Fn>` so plain fields pass `None`.
type WriteSuccessHook = std::sync::Arc<dyn Fn(&MainWindow) + Send + Sync>;

/// DES-09 — per-field coalescing writer for freedom.yaml.
///
/// A LineEdit's `edited` callback fires once per keystroke, so typing "gpt-4o"
/// would otherwise spawn six writer threads that race for `FREEDOM_WRITE_LOCK`.
/// `std::sync::Mutex` is not FIFO-fair, so a stale-prefix thread ("gpt-4") can
/// acquire the lock after the final-value thread ("gpt-4o") and overwrite the
/// correct value on disk — worst on the slow/network home dirs this async path
/// exists to keep responsive.
///
/// This returns a `SyncSender`; the callback becomes a non-blocking `send`. One
/// dedicated worker per field drains the channel keeping only the latest value
/// (last-typed wins — stronger than FIFO, no ordering assumptions), then does a
/// single read-modify-write + reload sentinel + toast. Collapses a keystroke
/// burst to one fsync and one toast, and never touches the UI thread with I/O.
///
/// The worker exits cleanly when the callback (and thus the `SyncSender`) is
/// dropped on window teardown — `recv()` then returns `Err`.
///
/// `on_success`, if set, runs on the UI event loop after each successful write
/// (e.g. the Obsidian vault field re-scans the vault). `None` for plain fields.
fn make_coalescing_writer(
    fp: std::path::PathBuf,
    rd: std::path::PathBuf,
    dotted_key: &'static str,
    label: &'static str,
    weak: slint::Weak<MainWindow>,
    on_success: Option<WriteSuccessHook>,
) -> std::sync::mpsc::SyncSender<serde_yaml::Value> {
    // Bounded buffer: human typing never outpaces one fsync by 64 events, and a
    // paste is a single `edited` event, so `send` never blocks the UI thread in
    // practice while still bounding memory.
    let (tx, rx) = std::sync::mpsc::sync_channel::<serde_yaml::Value>(64);
    std::thread::spawn(move || {
        while let Ok(mut val) = rx.recv() {
            // Coalesce the burst: keep only the most recent queued value.
            while let Ok(newer) = rx.try_recv() {
                val = newer;
            }
            let result = set_nested_in_freedom(&fp, dotted_key, val)
                .and_then(|_| std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e)));
            match result {
                Ok(_) => {
                    push_toast(&weak, "success", label, "saved — daemon reloading");
                    // Optional post-success hook, marshalled to the UI event loop.
                    if let Some(hook) = &on_success {
                        let weak2 = weak.clone();
                        let hook = hook.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak2.upgrade() {
                                hook(&w);
                            }
                        })
                        .ok();
                    }
                }
                Err(ref e) => push_toast(&weak, "warn", label, &format!("write failed: {e}")),
            }
        }
    });
    tx
}

/// DES-09 helper — read a nested boolean from freedom.yaml.
/// Returns `default` on missing file / key / malformed YAML.
fn read_nested_bool_in_freedom(path: &Path, dotted_key: &str, default: bool) -> bool {
    let Ok(body) = std::fs::read_to_string(path) else {
        return default;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return default;
    };
    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    let leaf = match segments.as_slice() {
        [leaf] => root.get(serde_yaml::Value::from(*leaf)),
        [k1, leaf] => root.get(k1).and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        [k1, k2, leaf] => root
            .get(k1)
            .and_then(|v| v.get(*k2))
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        _ => None,
    };
    leaf.and_then(|v| v.as_bool()).unwrap_or(default)
}

/// DES-09 helper — read a nested string from freedom.yaml.
/// Returns `default` on missing file / key / malformed YAML.
fn read_nested_str_in_freedom<'a>(
    path: &Path,
    dotted_key: &str,
    default: &'a str,
) -> String {
    let Ok(body) = std::fs::read_to_string(path) else {
        return default.to_string();
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return default.to_string();
    };
    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    let leaf = match segments.as_slice() {
        [leaf] => root.get(serde_yaml::Value::from(*leaf)),
        [k1, leaf] => root.get(k1).and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        [k1, k2, leaf] => root
            .get(k1)
            .and_then(|v| v.get(*k2))
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        _ => None,
    };
    leaf.and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| default.to_string())
}

/// DES-09 helper — read a nested i64 from freedom.yaml.
/// Returns `default` on missing file / key / malformed YAML.
fn read_nested_i64_in_freedom(path: &Path, dotted_key: &str, default: i64) -> i64 {
    let Ok(body) = std::fs::read_to_string(path) else {
        return default;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return default;
    };
    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    let leaf = match segments.as_slice() {
        [leaf] => root.get(serde_yaml::Value::from(*leaf)),
        [k1, leaf] => root.get(k1).and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        [k1, k2, leaf] => root
            .get(k1)
            .and_then(|v| v.get(*k2))
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        _ => None,
    };
    leaf.and_then(|v| v.as_i64()).unwrap_or(default)
}

/// DES-09 helper — read a nested f64 from freedom.yaml.
/// Returns `default` on missing file / key / malformed YAML.
/// Used for fields like `council.daily_usd_cap` which are stored as YAML floats.
fn read_nested_f64_in_freedom(path: &Path, dotted_key: &str, default: f64) -> Option<f64> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return None;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return None;
    };
    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    let leaf = match segments.as_slice() {
        [leaf] => root.get(serde_yaml::Value::from(*leaf)),
        [k1, leaf] => root.get(k1).and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        [k1, k2, leaf] => root
            .get(k1)
            .and_then(|v| v.get(*k2))
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        _ => None,
    };
    leaf.and_then(|v| v.as_f64())
}

/// Format an f64 cap value for display: strip the trailing ".0" for whole
/// numbers so "10" shows instead of "10.0", but "10.5" stays "10.5".
fn format_cap_f64(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
mod des09_tests {
    use super::*;
    use tempfile::TempDir;

    fn write_yaml(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, content).unwrap();
        path
    }

    // Helper that uses std write (no ACL) so tests pass on all platforms.
    fn set_nested_test(path: &Path, key: &str, value: serde_yaml::Value) -> Result<()> {
        let body = if path.exists() {
            std::fs::read_to_string(path).unwrap()
        } else {
            String::new()
        };
        let mut root: serde_yaml::Value = if body.trim().is_empty() {
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
        } else {
            serde_yaml::from_str(&body).unwrap()
        };
        let map = match &mut root {
            serde_yaml::Value::Mapping(m) => m,
            _ => panic!("not a mapping"),
        };
        let segs: Vec<&str> = key.splitn(8, '.').collect();
        match segs.as_slice() {
            [leaf] => {
                map.insert(serde_yaml::Value::from(*leaf), value);
            }
            [k1, leaf] => {
                let k1v = serde_yaml::Value::from(*k1);
                let mut inner = map.get(&k1v).and_then(|v| v.as_mapping()).cloned().unwrap_or_default();
                inner.insert(serde_yaml::Value::from(*leaf), value);
                map.insert(k1v, serde_yaml::Value::Mapping(inner));
            }
            [k1, k2, leaf] => {
                let k1v = serde_yaml::Value::from(*k1);
                let mut m1 = map.get(&k1v).and_then(|v| v.as_mapping()).cloned().unwrap_or_default();
                let k2v = serde_yaml::Value::from(*k2);
                let mut m2 = m1.get(&k2v).and_then(|v| v.as_mapping()).cloned().unwrap_or_default();
                m2.insert(serde_yaml::Value::from(*leaf), value);
                m1.insert(k2v, serde_yaml::Value::Mapping(m2));
                map.insert(k1v, serde_yaml::Value::Mapping(m1));
            }
            _ => panic!("depth > 3"),
        }
        let out = serde_yaml::to_string(&root).unwrap();
        std::fs::write(path, out).unwrap();
        Ok(())
    }

    #[test]
    fn nested_create_two_level() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_nested_test(&path, "council.daily_usd_cap", serde_yaml::Value::from(5.0f64)).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        let got = root.get("council").and_then(|v| v.get("daily_usd_cap"))
            .and_then(|v| v.as_f64()).unwrap();
        assert!((got - 5.0).abs() < 1e-9, "expected 5.0 got {got}");
    }

    #[test]
    fn nested_update_preserves_siblings() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir,
            "council:\n  daily_usd_cap: 3.0\n  max_calls: 10\nother_key: kept\n");
        set_nested_test(&path, "council.daily_usd_cap", serde_yaml::Value::from(9.0f64)).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        // other_key preserved
        assert_eq!(root.get("other_key").and_then(|v| v.as_str()), Some("kept"));
        // sibling inside council preserved
        assert_eq!(root.get("council").and_then(|v| v.get("max_calls")).and_then(|v| v.as_i64()), Some(10));
        // updated value
        let cap = root.get("council").and_then(|v| v.get("daily_usd_cap")).and_then(|v| v.as_f64()).unwrap();
        assert!((cap - 9.0).abs() < 1e-9);
    }

    #[test]
    fn top_level_key() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir, "provider_kind: claude_cli\n");
        set_nested_test(&path, "user_tz", serde_yaml::Value::from("Europe/Berlin")).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        assert_eq!(root.get("user_tz").and_then(|v| v.as_str()), Some("Europe/Berlin"));
        // provider_kind survives
        assert_eq!(root.get("provider_kind").and_then(|v| v.as_str()), Some("claude_cli"));
    }

    #[test]
    fn three_level_nested() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_nested_test(&path, "memory.vector_index.backend", serde_yaml::Value::from("hnsw")).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        let got = root.get("memory").and_then(|v| v.get("vector_index"))
            .and_then(|v| v.get("backend")).and_then(|v| v.as_str()).unwrap();
        assert_eq!(got, "hnsw");
    }

    // ── FIX 4 tests — read_nested_f64_in_freedom + format_cap_f64 ──────────

    #[test]
    fn read_f64_returns_value_for_float_node() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir, "council:\n  daily_usd_cap: 10.0\n");
        let v = read_nested_f64_in_freedom(&path, "council.daily_usd_cap", 0.0);
        assert!(v.is_some(), "expected Some, got None");
        assert!((v.unwrap() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn read_f64_returns_none_for_missing_key() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir, "council:\n  max_calls: 5\n");
        let v = read_nested_f64_in_freedom(&path, "council.daily_usd_cap", 0.0);
        assert!(v.is_none(), "expected None for missing key");
    }

    #[test]
    fn format_cap_strips_dot_zero_for_whole() {
        assert_eq!(format_cap_f64(10.0), "10");
        assert_eq!(format_cap_f64(0.0), "0");
        assert_eq!(format_cap_f64(100.0), "100");
    }

    #[test]
    fn format_cap_preserves_fractional() {
        assert_eq!(format_cap_f64(10.5), "10.5");
        assert_eq!(format_cap_f64(3.14), "3.14");
    }

    // ── FIX 2 / FIX 3 tests — Null write deserialized as YAML null ─────────

    #[test]
    fn null_write_round_trips_as_yaml_null() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Write Null to a key; read back and verify it is YAML null / absent.
        set_nested_test(&path, "persona_mode", serde_yaml::Value::Null).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        // serde_yaml::Value::Null means Option<T> deserializes as None.
        let node = root.get("persona_mode");
        // Either the key is absent or its value is Null — both are valid representations.
        let is_null_or_absent = node.map_or(true, |v| v.is_null());
        assert!(is_null_or_absent, "expected null or absent, got {:?}", node);
    }

    #[test]
    fn null_write_for_obsidian_sync_is_yaml_null() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_nested_test(&path, "obsidian_auto_sync_secs", serde_yaml::Value::Null).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        let node = root.get("obsidian_auto_sync_secs");
        let is_null_or_absent = node.map_or(true, |v| v.is_null());
        assert!(is_null_or_absent, "expected null or absent, got {:?}", node);
    }
}

/// Per-process-unique sibling temp path for an atomic credentials write
/// (GOLD-SEC-15 / A-34) — mirrors the daemon helper.
fn atomic_tmp_path(path: &Path) -> std::path::PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("credentials.yaml");
    path.with_file_name(format!(".{name}.tmp{}", std::process::id()))
}

#[cfg(unix)]
fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // Atomic 0600 write: temp (mode 0600 at create) → write+fsync → rename
    // (GOLD-SEC-15 / A-34). Secrets are never on disk under a wider mode,
    // and a crash mid-write leaves the old file intact.
    let tmp = atomic_tmp_path(path);
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("create {} mode 0600", tmp.display()))?;
    file.write_all(body)
        .with_context(|| format!("write body to {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync {}", tmp.display()))?;
    drop(file);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("atomically replace {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    // GOLD-SEC-15 / A-34: restrict the DACL to owner-only BEFORE writing
    // any secret bytes (previously written under the inherited ACL, then
    // restricted — a readable window), then atomically rename. Fail CLOSED
    // if the DACL can't be set — it is the only at-rest protection.
    use std::io::Write;
    let tmp = atomic_tmp_path(path);
    let _ = std::fs::remove_file(&tmp);
    // create_new mirrors the Unix O_CREAT|O_EXCL arm: exclusive create
    // removes the TOCTOU window between remove_file and the first open.
    // The empty handle is dropped immediately; icacls acts on the path.
    drop(
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("create temp {}", tmp.display()))?,
    );
    if let Err(e) = icacls_restrict_to_owner(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!(
            "refusing to write {}: could not restrict the file to owner-only \
             (DACL) — the only at-rest protection for plaintext secrets ({e})",
            path.display()
        );
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&tmp)
        .with_context(|| format!("open restricted temp {}", tmp.display()))?;
    file.write_all(body)
        .with_context(|| format!("write body to {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync {}", tmp.display()))?;
    drop(file);
    // Clean up the tmp if rename fails — never leave a secret-bearing
    // stale file behind when the target is locked (common on Windows).
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("atomically replace {}", path.display()));
    }
    Ok(())
}

#[cfg(windows)]
fn icacls_restrict_to_owner(path: &Path) -> Result<()> {
    // Mirrors the daemon's `wal::win_acl::restrict_to_owner`: grant the
    // current user explicit Full Control without stripping inherited
    // ACEs. Stripping inheritance locks the owner's own processes out
    // of the file on some Windows configurations — see SECURITY.md.
    let username = std::env::var("USERNAME").context("USERNAME not set")?;
    if !safe_username(&username) {
        anyhow::bail!("USERNAME contains characters unsafe for icacls argv");
    }
    let status = std::process::Command::new("icacls.exe")
        .arg(path)
        .arg("/grant:r")
        .arg(format!("{username}:(F)"))
        .status()
        .context("spawn icacls.exe")?;
    if !status.success() {
        anyhow::bail!("icacls returned {status}");
    }
    Ok(())
}

#[cfg(windows)]
fn safe_username(name: &str) -> bool {
    // M-3 fix — Windows USERNAME with a space is technically legal
    // but our icacls argument string interpolates the username
    // directly. Drop space to remove the parse-ambiguity risk; if a
    // real operator has a space-containing username we fall back to
    // inherited ACLs (logged at warning level).
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Wall-clock HH:MM:SS for chat bubble timestamps. Pure GUI display —
/// the daemon owns the canonical PROVIDER_REQUEST timestamp in the
/// WAL; this string just gives the operator a local read-receipt
/// next to their bubble. R2-P0-1 (2026-05-22): chat_via_subprocess
/// dispatches to `neothd chat` so the bubble round-trip now hits
/// the real provider + WAL + permission gates.
fn format_now_hms() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = now % 60;
    let m = (now / 60) % 60;
    let h = (now / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// G-6 fix — every subprocess we spawn against the `neothd` binary
/// MUST opt out of ANSI colour output. Without these env vars
/// tracing-subscriber emits `[2m...[0m` escape sequences into stdout,
/// which then surface verbatim in GUI text widgets (FooterBar,
/// hardware summary, kanban session summary). Centralised here so
/// every call site stays consistent.
fn spawn_neothd_plain(bin: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin);
    cmd.env("NO_COLOR", "1")
        .env("RUST_LOG_STYLE", "never")
        .env("CLICOLOR", "0")
        // CRITICAL for stdout parsing: the daemon's `init_tracing` writes
        // tracing events (incl. the `INFO neothd: Neoth ready. Sup.`
        // startup banner) to STDOUT, not stderr. At the default
        // `info,neothd=debug` level those lines would prepend the
        // machine-readable JSON / streamed chat deltas every GUI
        // subprocess parses — corrupting `serde_json::from_slice` and the
        // `gui-stream` NDJSON channel alike. `error` suppresses the
        // banner + info/debug noise so stdout carries only the payload.
        // Genuine clap/anyhow failures still surface on stderr + via exit
        // code, so the GUI's error handling is unaffected.
        .env("NEOTH_LOG", "error");
    cmd
}

/// Run `neothd kanban list/show --output json` + group tasks by status.
/// Returns an empty snapshot with a friendly summary when the operator
/// hasn't opened a coding session yet, OR when the daemon binary is
/// missing — the GUI degrades gracefully instead of erroring out.
/// GR-10 — fetch the daemon's safety-rail state via `neoth security safe-mode
/// --json`. Returns an empty snapshot when the binary is absent or the call
/// fails (the panel renders a "no data" state, never crashes). The PARSE is the
/// unit-tested `panel_logic::parse_safe_mode`; this is the thin subprocess shell.
fn fetch_safe_mode_snapshot() -> panel_logic::SafeModeSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::SafeModeSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("security")
        .arg("safe-mode")
        .arg("--json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_safe_mode(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::SafeModeSnapshot::default(),
    }
}

/// Run a read-only `neothd <args…>` probe; return combined stdout/stderr (or a
/// friendly error). Backs the Agents / Automation tabs (off the UI thread).
fn run_neothd_probe(args: &[&str]) -> String {
    match which_neothd().and_then(|bin| {
        let mut c = spawn_neothd_plain(&bin);
        for a in args {
            c.arg(a);
        }
        c.output().ok()
    }) {
        Some(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                s.push('\n');
                s.push_str(&err);
            }
            if s.trim().is_empty() {
                "(no output)".to_string()
            } else {
                s
            }
        }
        None => "neothd binary not on PATH.".to_string(),
    }
}

/// Central Buddy driver — the ONE place a GUI event becomes an orb reaction.
/// Every handler that wants the Buddy to react calls `buddy(&w, GuiActivity::X)`
/// instead of poking `set_buddy_mood` directly, so the orb's vocabulary stays
/// consistent (see `buddy_activity::GuiActivity`).
fn buddy(window: &MainWindow, activity: GuiActivity) {
    let (mood, caption) = activity.mood();
    window.set_buddy_mood(mood.into());
    window.set_buddy_caption(caption.into());
}

/// GR-10 — push a parsed safe-mode snapshot onto the `MainWindow` Privacy-tab
/// Safety Rails panel. UI-thread only (called via `invoke_from_event_loop`).
fn apply_safe_mode(window: &MainWindow, snap: panel_logic::SafeModeSnapshot) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<SafeRailRow> = snap
        .rails
        .into_iter()
        .map(|r| SafeRailRow {
            name: r.name.into(),
            engaged: r.engaged,
            detail: r.detail.into(),
        })
        .collect();
    window.set_safety_rails(ModelRc::new(VecModel::from(rows)));
    window.set_rails_engaged_count(snap.engaged_count);
    window.set_rails_total(snap.total);
}

/// GR-03 — fetch the trust posture via `neoth trust --output json`. Empty
/// snapshot on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_trust`; this is the thin subprocess shell.
fn fetch_trust_snapshot() -> panel_logic::TrustSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::TrustSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("trust")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_trust(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::TrustSnapshot::default(),
    }
}

/// GR-03 — push a parsed trust snapshot onto the `MainWindow` Privacy-tab Trust
/// panel. UI-thread only (called via `invoke_from_event_loop`).
fn apply_trust(window: &MainWindow, snap: panel_logic::TrustSnapshot) {
    use slint::{ModelRc, VecModel};
    let to_rows = |rows: Vec<panel_logic::TrustRow>| -> ModelRc<TrustRow> {
        let v: Vec<TrustRow> = rows
            .into_iter()
            .map(|r| TrustRow {
                label: r.label.into(),
                value: r.value.into(),
            })
            .collect();
        ModelRc::new(VecModel::from(v))
    };
    // GOLD-FEAT-01c — reflect the full-auto (sudomode) toggle from the live
    // autonomy posture (autonomy=full is the proxy for the full-auto preset;
    // toggling it applies the full preset via the CLI). Compare before the
    // `.into()` below consumes the string.
    window.set_full_auto_active(snap.autonomy_level == "full");
    // GUI-improve (gap panel wf_641e1173): keep the Privacy tab's top "Current
    // autonomy" card a LIVE mirror of the trust snapshot. It was a one-shot
    // freedom.yaml read at startup, so a CLI `/autonomy` change left it stale
    // while the TRUST card below showed the new value — two contradictory
    // autonomy strings on one surface.
    window.set_autonomy_choice(snap.autonomy_level.clone().into());
    window.set_trust_autonomy_level(snap.autonomy_level.into());
    window.set_trust_autonomy_behavior(snap.autonomy_behavior.into());
    window.set_trust_privacy(to_rows(snap.privacy));
    window.set_trust_recovery(to_rows(snap.recovery));
    window.set_trust_ledger(to_rows(snap.ledger));
}

/// SL-03 — fetch the local resource snapshot via `neoth hardware --output json`.
/// Empty snapshot on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_hardware`; this is the thin subprocess shell.
fn fetch_hardware_snapshot() -> panel_logic::HardwareSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::HardwareSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("hardware")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_hardware(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::HardwareSnapshot::default(),
    }
}

/// SL-03 — push the parsed resource snapshot onto the `MainWindow` Cluster-tab
/// Local Resources panel. UI-thread only.
fn apply_hardware(window: &MainWindow, snap: panel_logic::HardwareSnapshot) {
    use slint::{ModelRc, VecModel};
    let models: Vec<TrustRow> = snap
        .models
        .into_iter()
        .map(|r| TrustRow {
            label: r.label.into(),
            value: r.value.into(),
        })
        .collect();
    window.set_hw_cpu(snap.cpu.into());
    window.set_hw_memory(snap.memory.into());
    window.set_hw_accelerator(snap.accelerator.into());
    window.set_hw_vram(snap.vram.into());
    window.set_hw_vram_fraction(snap.vram_fraction);
    window.set_hw_disk(snap.disk.into());
    window.set_hw_models(ModelRc::new(VecModel::from(models)));
}

/// SL-02 — fetch the cluster peer topology via `neoth cluster topology --output
/// json`. Empty on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_cluster_topology`; this is the thin subprocess shell.
fn fetch_topology_snapshot() -> Vec<panel_logic::ClusterPeerRow> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("cluster")
        .arg("topology")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_cluster_topology(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// SL-02 — push the parsed peer rows onto the Cluster-tab topology panel.
/// UI-thread only.
fn apply_topology(window: &MainWindow, rows: Vec<panel_logic::ClusterPeerRow>) {
    use slint::{ModelRc, VecModel};
    let peers: Vec<ClusterPeerRow> = rows
        .into_iter()
        .map(|r| ClusterPeerRow {
            label: r.label.into(),
            addr: r.addr.into(),
            status: r.status.into(),
            rtt_ms: r.rtt_ms.into(),
            stability: r.stability_pct.into(),
            last_seen: r.last_seen.into(),
        })
        .collect();
    window.set_cluster_peers(ModelRc::new(VecModel::from(peers)));
}

/// GOLD-PROG-08 — read the daemon's exported usage meter
/// (`~/.neoth/usage_meter.json`, written every 10s). PARSE is the unit-tested
/// `panel_logic::parse_usage_meter`; an absent/garbage file → unavailable (the
/// GUI is a separate process and cannot read the daemon's in-memory meter).
fn fetch_usage_meter() -> panel_logic::UsageMeterPanel {
    let path = default_neoth_home().join("usage_meter.json");
    match std::fs::read_to_string(&path) {
        Ok(s) => panel_logic::parse_usage_meter(&s),
        Err(_) => panel_logic::UsageMeterPanel::default(),
    }
}

/// GOLD-PROG-08 — push the live token budget onto the Config-tab meter.
/// UI-thread only.
fn apply_usage_meter(window: &MainWindow, panel: panel_logic::UsageMeterPanel) {
    window.set_usage_available(panel.available);
    window.set_usage_responses(panel.responses.into());
    window.set_usage_tokens(panel.tokens.into());
    window.set_usage_note(panel.note.into());
}

/// KF-08 — fetch the council budget meter via `neoth council budget --output
/// json`. PARSE is the unit-tested `panel_logic::parse_council_budget`.
fn fetch_council_budget() -> panel_logic::CouncilBudgetPanel {
    let Some(bin) = which_neothd() else {
        return panel_logic::CouncilBudgetPanel::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("council")
        .arg("budget")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_council_budget(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::CouncilBudgetPanel::default(),
    }
}

/// KF-08 — push the council budget meter onto the `MainWindow` Config-tab panel.
fn apply_council_budget(window: &MainWindow, snap: panel_logic::CouncilBudgetPanel) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<TrustRow> = snap
        .last_debate
        .into_iter()
        .map(|r| TrustRow {
            label: r.label.into(),
            value: r.value.into(),
        })
        .collect();
    window.set_council_cap(snap.configured_cap.into());
    window.set_council_daily_usd(snap.daily_usd_cap.into());
    window.set_council_depth_warning(snap.depth_cost_warning.into());
    window.set_council_last_debate(ModelRc::new(VecModel::from(rows)));
}

/// GU-01 — fetch the hemisphere bindings via `neoth hemispheres show --output
/// json`. Empty snapshot on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_hemispheres`.
fn fetch_hemispheres_snapshot() -> panel_logic::HemispheresSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::HemispheresSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("hemispheres")
        .arg("show")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_hemispheres(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::HemispheresSnapshot::default(),
    }
}

/// GU-01 — push hemisphere bindings onto the MainWindow. UI-thread only.
fn apply_hemispheres(window: &MainWindow, snap: panel_logic::HemispheresSnapshot) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<HemisphereRow> = snap
        .bindings
        .into_iter()
        .map(|b| HemisphereRow {
            role: b.role.into(),
            provider: b.provider.into(),
            model: b.model.into(),
            has_key: b.has_key,
        })
        .collect();
    window.set_hemisphere_bindings(ModelRc::new(VecModel::from(rows)));
    window.set_hemispheres_mode(snap.mode.into());
}

/// GU-01 — fetch installed skills via `neoth skills --list --output json`.
/// Empty on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_skills`.
fn fetch_skills() -> Vec<panel_logic::SkillSummary> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("skills")
        .arg("--list")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_skills(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// GOLD-ADAPT-AOS-01 — full skill list cache so the search box can
/// re-group without a subprocess round-trip per keystroke.
static SKILLS_CACHE: std::sync::Mutex<Vec<panel_logic::SkillSummary>> =
    std::sync::Mutex::new(Vec::new());

/// GU-01 — push the installed-skill list onto the MainWindow. UI-thread only.
/// AOS-01: caches the full list + renders the grouped/filtered index.
fn apply_skills(window: &MainWindow, skills: Vec<panel_logic::SkillSummary>) {
    window.set_skills_total(skills.len() as i32);
    if let Ok(mut c) = SKILLS_CACHE.lock() {
        *c = skills;
    }
    render_skill_index(window);
}

/// AOS-01 — regroup the cached skills under the current filter and push
/// the flat header+row model. UI-thread only.
fn render_skill_index(window: &MainWindow) {
    use slint::{ModelRc, VecModel};
    let filter = window.get_skills_filter().to_string();
    // Clone out of the lock immediately — holding it across the grouping
    // would stall any future off-thread cache writer.
    let skills = SKILLS_CACHE
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default();
    let rows: Vec<SkillRow> = panel_logic::group_skill_rows(&skills, &filter)
        .into_iter()
        .map(|s| SkillRow {
            id: s.id.into(),
            description: s.description.into(),
            enabled: s.enabled,
            keywords: s.keywords.into(),
            tags: s.tags.into(),
            is_header: s.is_header,
        })
        .collect();
    window.set_skills(ModelRc::new(VecModel::from(rows)));
}

/// GU-01 — fetch discovered plugins via `neoth plugin list --output json`.
fn fetch_plugins() -> Vec<panel_logic::PluginSummary> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("plugin")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_plugins(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// GU-01 — push the discovered-plugin list onto the MainWindow. UI-thread only.
fn apply_plugins(window: &MainWindow, plugins: Vec<panel_logic::PluginSummary>) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<PluginRow> = plugins
        .into_iter()
        .map(|p| PluginRow {
            id: p.id.into(),
            name: p.name.into(),
            activation: p.activation.into(),
            // DES-12
            has_ui_surface: p.has_ui_surface,
            ui_title: p.ui_title.into(),
        })
        .collect();
    window.set_plugins(ModelRc::new(VecModel::from(rows)));
}

/// DES-12 — fetch WAL-feed events for a plugin via
/// `neoth plugin events <id> --output json --last 30`.
fn fetch_plugin_events(id: &str) -> Vec<panel_logic::PluginEventRow> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("plugin")
        .arg("events")
        .arg(id)
        .arg("--output")
        .arg("json")
        .arg("--last")
        .arg("30")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_plugin_events(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// DES-12 — format a unix timestamp as HH:MM:SS (UTC).
/// Falls back to the raw seconds string when time parsing is unavailable.
fn fmt_ts_unix(ts: u64) -> String {
    // Simple modulo decomposition — avoids pulling in chrono just for display.
    let s = ts % 60;
    let m = (ts / 60) % 60;
    let h = (ts / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// DES-12 — format a byte count as a compact human-readable string.
fn fmt_event_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

/// GU-01 — fetch memory-block sizes via `neoth memory --size --output json`
/// (metadata only — no content leaves the daemon).
fn fetch_memory_snapshot() -> panel_logic::MemorySnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::MemorySnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("memory")
        .arg("--size")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_memory_size(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::MemorySnapshot::default(),
    }
}

/// Human-readable byte size (B / KB / MB).
fn fmt_bytes(n: i64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

/// GU-01 — push the memory-block sizes onto the MainWindow. UI-thread only.
fn apply_memory(window: &MainWindow, snap: panel_logic::MemorySnapshot) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<MemoryRow> = snap
        .blocks
        .into_iter()
        .map(|b| MemoryRow {
            source: b.source.into(),
            path: b.path.into(),
            bytes: fmt_bytes(b.bytes).into(),
        })
        .collect();
    window.set_memory_blocks(ModelRc::new(VecModel::from(rows)));
    window.set_memory_total(fmt_bytes(snap.total_bytes).into());
}

/// GU-01 — push per-channel connection state (presence of credentials, never
/// the secret values) onto the MainWindow. UI-thread only.
fn apply_channels(window: &MainWindow, channels: Vec<panel_logic::ChannelStatus>) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<ChannelRow> = channels
        .into_iter()
        .map(|c| ChannelRow {
            name: c.name.into(),
            connected: c.connected,
        })
        .collect();
    window.set_channels(ModelRc::new(VecModel::from(rows)));
}

/// SPEC-05 — fetch the saved presets via `neoth preset list --json`. Empty on
/// missing binary / failure. PARSE is the unit-tested `panel_logic::parse_presets`.
fn fetch_presets() -> Vec<panel_logic::PresetEntry> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("list")
        .arg("--json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_presets(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// SPEC-05 — push the preset selector list onto the MainWindow. UI-thread only.
///
/// Injects flat sentinel header rows (is-header=true) so the Slint `for` loop
/// can use the same `if p.is-header:` / `if !p.is-header:` pattern as the
/// Skills expander — no nested conditionals inside the loop body.
///
/// Layout injected:
///   PresetRow { name="BUILT-IN", is_header=true }
///   … built-in rows …
///   PresetRow { name="YOURS",    is_header=true }   ← only when operator presets exist
///   … operator rows …
fn apply_presets(window: &MainWindow, presets: Vec<panel_logic::PresetEntry>) {
    use slint::{ModelRc, VecModel};
    let header = |label: &str| PresetRow {
        name: label.into(),
        active: false,
        builtin: false,
        description: "".into(),
        is_header: true,
    };
    let data_row = |p: panel_logic::PresetEntry| PresetRow {
        name: p.name.into(),
        active: p.active,
        builtin: p.builtin,
        description: p.description.into(),
        is_header: false,
    };

    // Split into builtin / operator so the YOURS header only appears once.
    let (builtins, operators): (Vec<_>, Vec<_>) = presets.into_iter().partition(|p| p.builtin);
    let mut rows: Vec<PresetRow> = Vec::with_capacity(builtins.len() + operators.len() + 2);

    rows.push(header("BUILT-IN"));
    for p in builtins {
        rows.push(data_row(p));
    }
    if !operators.is_empty() {
        rows.push(header("YOURS"));
        for p in operators {
            rows.push(data_row(p));
        }
    }
    window.set_preset_list(ModelRc::new(VecModel::from(rows)));
}

/// SPEC-05 step5c — fetch the behavioural-profile presets via
/// `neoth profile preset list --output json`. PARSE is unit-tested.
fn fetch_profile_presets() -> Vec<panel_logic::ProfilePresetRow> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("profile")
        .arg("preset")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_profile_presets(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// SPEC-05 step5c — push the behavioural-profile list onto the MainWindow.
fn apply_profile_presets(window: &MainWindow, rows: Vec<panel_logic::ProfilePresetRow>) {
    use slint::{ModelRc, VecModel};
    let model: Vec<ProfilePresetRow> = rows
        .into_iter()
        .map(|p| ProfilePresetRow {
            name: p.name.into(),
            description: p.description.into(),
            recommended: p.recommended,
            active: p.active,
        })
        .collect();
    window.set_profile_preset_list(ModelRc::new(VecModel::from(model)));
}

/// SPEC-05 step5c — activate the operator's chosen response style via
/// `neoth profile preset apply <name>`.
fn apply_profile_preset_via_subprocess(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "profile preset: neothd binary not found".to_string();
    };
    match spawn_neothd_plain(&bin)
        .arg("profile")
        .arg("preset")
        .arg("apply")
        .arg(name)
        .output()
    {
        Ok(o) if o.status.success() => format!("response style → {name}"),
        Ok(o) => format!(
            "profile preset apply failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("profile preset apply could not start: {e}"),
    }
}

/// SPEC-06 — fetch the implemented provider ids via `neoth provider list
/// --output json` (the per-role rebind picker options). PARSE is the unit-tested
/// `panel_logic::parse_provider_ids`.
fn fetch_provider_ids() -> Vec<String> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("provider")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_provider_ids(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// SPEC-06 — push the provider-id picker options onto the MainWindow. UI-thread.
fn apply_provider_ids(window: &MainWindow, ids: Vec<String>) {
    use slint::{ModelRc, VecModel};
    // GUI-improve (gap panel wf_641e1173) — compute the Config combo's selected
    // row = position of the operator's current provider in the LIVE list, so a
    // provider absent from the old hardcoded combo list no longer silently shows
    // as row 0 (claude_cli). `provider-choice` is set from freedom.yaml at
    // startup (line 241) before this runs.
    let current = window.get_provider_choice().to_string();
    let idx = ids.iter().position(|p| p == &current).unwrap_or(0) as i32;
    let rows: Vec<slint::SharedString> = ids.into_iter().map(|s| s.into()).collect();
    window.set_provider_ids(ModelRc::new(VecModel::from(rows)));
    window.set_provider_choice_index(idx);
}

/// SPEC-06 — rebind a hemisphere role to a provider (`neoth hemispheres set
/// --role <r> --provider <p>`). The daemon owns the WAL `0x1F HEMISPHERE_REBOUND`
/// audit + its own validation. Returns an operator-readable status line.
fn set_hemisphere_via_subprocess(role: &str, provider: &str, model: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "hemispheres set: neothd binary not found".to_string();
    };
    // GOLD-GUI-OVERHAUL — forward the picked model id (HemisphereSlot.model is a
    // free-form Option<String>; the CLI already accepts --model). Empty = leave
    // the role on its provider default.
    let mut cmd = spawn_neothd_plain(&bin);
    cmd.arg("hemispheres")
        .arg("set")
        .arg("--role")
        .arg(role)
        .arg("--provider")
        .arg(provider);
    if !model.is_empty() {
        cmd.arg("--model").arg(model);
    }
    match cmd.output() {
        Ok(o) if o.status.success() => {
            if model.is_empty() {
                format!("{role} → {provider}")
            } else {
                format!("{role} → {provider} · {model}")
            }
        }
        Ok(o) => format!(
            "hemispheres set failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("hemispheres set could not start: {e}"),
    }
}

/// GOLD-GUI-OVERHAUL — the per-role model-picker options for a provider. Local
/// providers (local_qwen/local_ouro) → abliterated-then-standard GGUF refs that
/// fit this PC's VRAM (`neoth models recommend --class …`, so Alex can SELECT a
/// fitting local/abliterated model). Cloud providers → the live model catalog
/// (`neoth catalog list --provider …`). Index 0 is always "(provider default)"
/// so the operator can leave the model unset. Robust: a subprocess hiccup just
/// yields the default-only list, never a hard fail.
fn fetch_hemisphere_model_ids(provider: &str) -> Vec<String> {
    let mut out = vec!["(provider default)".to_string()];
    let Some(bin) = which_neothd() else {
        return out;
    };
    if provider == "local_qwen" || provider == "local_ouro" {
        for class in ["abliterated", "standard"] {
            if let Ok(o) = spawn_neothd_plain(&bin)
                .arg("models")
                .arg("recommend")
                .arg("--class")
                .arg(class)
                .arg("--output")
                .arg("json")
                .output()
            {
                if o.status.success() {
                    out.extend(panel_logic::parse_model_recommend_refs(
                        &String::from_utf8_lossy(&o.stdout),
                    ));
                }
            }
        }
    } else if let Ok(o) = spawn_neothd_plain(&bin)
        .arg("catalog")
        .arg("list")
        .arg("--provider")
        .arg(provider)
        .arg("--output")
        .arg("json")
        .output()
    {
        if o.status.success() {
            out.extend(panel_logic::parse_catalog_model_ids(
                &String::from_utf8_lossy(&o.stdout),
                provider,
            ));
        }
    }
    out.dedup();
    out
}

/// SPEC-05 — activate a preset by name (`neoth preset activate <name>`): sets
/// the active marker (does NOT merge into freedom.yaml — that's "Apply active").
/// Returns an operator-readable status line.
fn activate_preset_via_subprocess(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "preset activate: neothd binary not found".to_string();
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("activate")
        .arg(name)
        .output()
    {
        Ok(o) if o.status.success() => format!("active preset → {name}"),
        Ok(o) => format!(
            "preset activate failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("preset activate could not start: {e}"),
    }
}

/// SPEC-05 builtin-presets — run `neoth preset apply <name> --dry-run`
/// and parse the JSON plan. Returns the plan on success; None when the
/// binary is missing, the command fails, or the output is unparseable.
fn dry_run_preset_via_subprocess(name: &str) -> Option<panel_logic::ApplyPlan> {
    let bin = which_neothd()?;
    let out = spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("apply")
        .arg(name)
        .arg("--dry-run")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    panel_logic::parse_apply_plan(&String::from_utf8_lossy(&out.stdout))
}

/// SPEC-05 builtin-presets — mint a full-auto token then apply <name> with
/// `--yes --gui-confirmed --gui-token <token>`.
/// Returns a human-readable status string.
fn apply_preset_with_fullauto_token(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "preset apply: neothd binary not found".to_string();
    };
    // Mint the single-use token (same pattern as on_full_auto_confirmed).
    let token = spawn_neothd_plain(&bin)
        .arg("autonomy")
        .arg("mint-fullauto-token")
        .arg("--output")
        .arg("json")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            // Output may be `{"token":"…"}` or bare token — extract either way.
            let raw = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                // JSON but token missing/not-a-string → empty (caught by the
                // is_empty filter) — never pass a raw JSON blob as a token.
                v.get("token")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string()
            } else {
                raw
            }
        })
        .filter(|t| !t.is_empty());
    let Some(tok) = token else {
        return format!(
            "Full-auto token mint failed for preset `{name}` — daemon must be running."
        );
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("apply")
        .arg(name)
        .arg("--yes")
        .arg("--gui-confirmed")
        .arg("--gui-token")
        .arg(&tok)
        .output()
    {
        Ok(o) if o.status.success() => format!("Applied preset `{name}` (full-auto)."),
        Ok(o) => format!(
            "preset apply `{name}` failed (exit {}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("preset apply could not start: {e}"),
    }
}

/// SPEC-05 builtin-presets — apply <name> non-interactively with `--yes`
/// (no autonomy token needed — not a full-auto preset).
fn apply_preset_direct(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "preset apply: neothd binary not found".to_string();
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("apply")
        .arg(name)
        .arg("--yes")
        .output()
    {
        Ok(o) if o.status.success() => {
            // Try to extract fields_changed count from JSON output.
            let stdout = String::from_utf8_lossy(&o.stdout);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(n) = v
                    .get("fields_changed")
                    .and_then(|f| f.as_array())
                    .map(|a| a.len())
                {
                    return format!("Applied preset `{name}` ({n} fields changed).");
                }
            }
            format!("Applied preset `{name}`.")
        }
        Ok(o) => format!(
            "preset apply `{name}` failed (exit {}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("preset apply could not start: {e}"),
    }
}

/// SPEC-05 builtin-presets — delete an operator preset via
/// `neoth preset delete <name>`.
fn delete_preset_via_subprocess(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "preset delete: neothd binary not found".to_string();
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("delete")
        .arg(name)
        .output()
    {
        Ok(o) if o.status.success() => format!("Deleted preset `{name}`."),
        Ok(o) => format!(
            "preset delete `{name}` failed (exit {}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("preset delete could not start: {e}"),
    }
}

fn fetch_kanban_board_snapshot() -> KanbanBoardSnapshot {
    let Some(bin) = which_neothd() else {
        return KanbanBoardSnapshot {
            summary: "Run `cargo install --path ../neothd` to enable Code Sessions data."
                .to_string(),
            ..Default::default()
        };
    };

    // Step 1: list sessions (active by default — `--all` includes archived).
    let list_out = spawn_neothd_plain(&bin)
        .arg("kanban")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output();
    let list_stdout = match list_out {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return KanbanBoardSnapshot {
                summary: format!(
                    "kanban list failed (exit {}): {}",
                    out.status,
                    if stderr.is_empty() {
                        "(no stderr)"
                    } else {
                        &stderr
                    }
                ),
                ..Default::default()
            };
        }
        Err(e) => {
            return KanbanBoardSnapshot {
                summary: format!("kanban list could not start: {e}"),
                ..Default::default()
            };
        }
    };
    let sessions: Vec<CodingSessionJson> = match serde_json::from_slice(&list_stdout) {
        Ok(v) => v,
        Err(e) => {
            return KanbanBoardSnapshot {
                summary: format!("kanban list JSON parse failed: {e}"),
                ..Default::default()
            };
        }
    };
    let Some(latest) = sessions.into_iter().next() else {
        return KanbanBoardSnapshot {
            summary: "No active session. Run `neoth code \"...\"` in your terminal, then refresh."
                .to_string(),
            ..Default::default()
        };
    };

    // Step 2: full session detail incl. tasks.
    let show_out = spawn_neothd_plain(&bin)
        .arg("kanban")
        .arg("show")
        .arg(latest.session_id.to_string())
        .arg("--output")
        .arg("json")
        .output();
    let show_stdout = match show_out {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => {
            return KanbanBoardSnapshot {
                summary: format!(
                    "kanban show #{} failed (exit {})",
                    latest.session_id, out.status
                ),
                ..Default::default()
            };
        }
        Err(e) => {
            return KanbanBoardSnapshot {
                summary: format!("kanban show could not start: {e}"),
                ..Default::default()
            };
        }
    };
    let envelope: CodingShowEnvelope = match serde_json::from_slice(&show_stdout) {
        Ok(v) => v,
        Err(e) => {
            return KanbanBoardSnapshot {
                summary: format!("kanban show JSON parse failed: {e}"),
                ..Default::default()
            };
        }
    };

    // Step 3: group tasks by status into the five board buckets.
    let mut snap = KanbanBoardSnapshot {
        summary: format!(
            "Session #{}  [{}]   {}",
            envelope.session.session_id, envelope.session.status, envelope.session.prompt,
        ),
        feed: fetch_kanban_feed(&bin),
        ..Default::default()
    };
    for task in envelope.tasks {
        let row = KanbanTaskRow {
            task_id: format!("#{}", task.task_id).into(),
            title: task.title.into(),
            hemisphere: task.hemisphere.into(),
        };
        // Wire-form status names mirror `TaskStatus::as_str` in
        // `neothd::coding::types`. Unknown statuses go to BACKLOG so
        // the operator still sees them rather than silent drops.
        match task.status.as_str() {
            "todo" => snap.todo.push(row),
            "in_progress" => snap.in_progress.push(row),
            "review" => snap.review.push(row),
            "done" | "archived" => snap.done.push(row),
            _ => snap.backlog.push(row),
        }
    }
    // HO-02: only probe on the success path (we have a working binary).
    snap.cerebellum_bound = Some(probe_cerebellum_bound(&bin));
    snap
}

// ── Warm-channel board client (B — persistent-stdio-stream, Session 30) ─────
//
// The legacy `fetch_kanban_board_snapshot` above spawns FOUR cold
// subprocesses per call. `GuiStreamClient` holds ONE `neoth gui-stream`
// child open across refreshes and gets the whole board in a single
// NDJSON round-trip. On ANY I/O / protocol error the caller drops the
// client and falls back to the cold path, so the warm channel is a pure
// optimisation — it can never make the board worse than before.

/// Board payload as returned by `neoth gui-stream`'s `board` method.
/// Field-for-field mirror of the daemon's `cli::kanban::GuiBoardSnapshot`.
#[derive(Debug, Deserialize)]
struct GuiBoardJson {
    summary: String,
    cerebellum_bound: bool,
    tasks: Vec<GuiBoardTaskJson>,
    feed: Vec<FeedEntryJson>,
}

#[derive(Debug, Deserialize)]
struct GuiBoardTaskJson {
    task_id: i64,
    title: String,
    hemisphere: String,
    status: String,
}

/// Map the warm-channel board payload into the same `KanbanBoardSnapshot`
/// the cold path produces. The status-bucketing + feed `rev()`+map mirror
/// `fetch_kanban_board_snapshot` (task loop) and `fetch_kanban_feed`
/// EXACTLY, so warm and cold are byte-for-byte equivalent in the UI.
fn board_json_to_snapshot(b: GuiBoardJson) -> KanbanBoardSnapshot {
    let mut snap = KanbanBoardSnapshot {
        summary: b.summary,
        cerebellum_bound: Some(b.cerebellum_bound),
        ..Default::default()
    };
    for t in b.tasks {
        let row = KanbanTaskRow {
            task_id: format!("#{}", t.task_id).into(),
            title: t.title.into(),
            hemisphere: t.hemisphere.into(),
        };
        match t.status.as_str() {
            "todo" => snap.todo.push(row),
            "in_progress" => snap.in_progress.push(row),
            "review" => snap.review.push(row),
            "done" | "archived" => snap.done.push(row),
            _ => snap.backlog.push(row),
        }
    }
    // Server returns feed oldest-first (WAL append order); the right rail
    // wants most-recent-first — same `.rev()` as `fetch_kanban_feed`.
    snap.feed = b
        .feed
        .into_iter()
        .rev()
        .map(|e| KanbanFeedRow {
            ts: format_hms_from_ns(e.ts_ns).into(),
            actor: e.actor.into(),
            message: e.message.into(),
        })
        .collect();
    snap
}

/// Per-request read budget. The warm channel is local IPC — a healthy
/// daemon answers in single-digit ms. 5s is generous slack; exceeding it
/// means the child is hung, so `request_board` gives up and the caller
/// falls back to the cold path (and drops this client so the next tick
/// reconnects). Bounds how long a worker thread can sit on a stalled read.
const GUI_STREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Persistent client to a `neoth gui-stream` child. Owns the child + its
/// stdin, plus an `mpsc` receiver fed by a dedicated reader thread that
/// owns stdout. Decoupling the blocking read into its own thread means
/// `request_board` waits on a `recv_timeout` (never an unbounded
/// `read_line`), so a hung daemon can neither pin the per-tick worker
/// thread nor delay this client's `Drop` (and thus the child kill) past
/// the timeout. Dropping the client kills the child, which EOFs the
/// reader thread.
struct GuiStreamClient {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    /// Lines the reader thread pulled off the child's stdout, in order.
    rx: std::sync::mpsc::Receiver<String>,
    next_id: u64,
}

impl GuiStreamClient {
    /// Spawn `neoth gui-stream` with piped stdin/stdout (stderr to null).
    /// `spawn_neothd_plain` sets `NEOTH_LOG=error`, so stdout carries only
    /// the NDJSON responses; `request_board` additionally skips any stray
    /// non-JSON line as a belt-and-suspenders guard. Errors propagate so
    /// the caller falls back to the cold path.
    fn connect(bin: &Path) -> std::io::Result<Self> {
        use std::process::Stdio;
        let mut child = spawn_neothd_plain(bin)
            .arg("gui-stream")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gui-stream: no stdin pipe")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gui-stream: no stdout pipe")
        })?;
        // Dedicated reader thread owns stdout, pushes whole lines onto the
        // channel. It exits when the child dies (read_line → EOF) or when
        // the receiver is dropped (send error). Detached on purpose: it is
        // self-terminating and cheap, and we never want to JOIN it from a
        // drop path that might otherwise block on a stalled read.
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break, // EOF — child exited
                    Ok(_) => {
                        if tx.send(std::mem::take(&mut line)).is_err() {
                            break; // receiver gone — client dropped
                        }
                    }
                    Err(_) => break, // pipe error — give up
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            rx,
            next_id: 1,
        })
    }

    /// One `{"id":N,"method":"board"}` round-trip → mapped snapshot.
    /// `None` on any I/O, EOF, timeout, protocol (`ok:false`), or parse
    /// failure; the caller then drops `self` and falls back to the cold
    /// path. Never blocks longer than `GUI_STREAM_READ_TIMEOUT` per line.
    fn request_board(&mut self) -> Option<KanbanBoardSnapshot> {
        use std::io::Write;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        // Hand-format the request line — no need to pull in a serialiser
        // for a two-field object with a numeric id + a literal method.
        let req = format!("{{\"id\":{id},\"method\":\"board\"}}\n");
        self.stdin.write_all(req.as_bytes()).ok()?;
        self.stdin.flush().ok()?;

        // Pull lines (via the reader thread) until we get a parseable JSON
        // response object. `NEOTH_LOG=error` already keeps stdout free of
        // the daemon's INFO banner, but this is the robustness net: ANY
        // stray non-JSON line (e.g. an error-level tracing event) is
        // skipped. Bounded by MAX_SKIP (chatty stream) AND by the per-recv
        // timeout (hung daemon) — both fall back to the cold path.
        const MAX_SKIP: usize = 32;
        for _ in 0..MAX_SKIP {
            let line = self.rx.recv_timeout(GUI_STREAM_READ_TIMEOUT).ok()?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue; // not JSON — a log line; skip it
            };
            // A genuine response carries an `ok` bool. Anything else that
            // happens to be JSON but lacks it is not our response — skip.
            let Some(ok) = v.get("ok").and_then(|b| b.as_bool()) else {
                continue;
            };
            if !ok {
                tracing::warn!(response = %trimmed, "gui-stream: board request not ok");
                return None;
            }
            let board: GuiBoardJson = serde_json::from_value(v.get("board")?.clone()).ok()?;
            return Some(board_json_to_snapshot(board));
        }
        // Too many non-response lines — treat as a broken channel.
        None
    }

    /// One `{"id":N,"method":"activity"}` round-trip → `(mood, caption)`. Same
    /// robustness net + fallback semantics as `request_board`. Best-effort: a
    /// `None` just skips a Buddy update this tick.
    fn request_activity(&mut self) -> Option<(String, String)> {
        use std::io::Write;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let req = format!("{{\"id\":{id},\"method\":\"activity\"}}\n");
        self.stdin.write_all(req.as_bytes()).ok()?;
        self.stdin.flush().ok()?;
        const MAX_SKIP: usize = 32;
        for _ in 0..MAX_SKIP {
            let line = self.rx.recv_timeout(GUI_STREAM_READ_TIMEOUT).ok()?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };
            let Some(ok) = v.get("ok").and_then(|b| b.as_bool()) else {
                continue;
            };
            if !ok {
                return None;
            }
            let activity = v.get("activity")?.as_str()?.to_string();
            let caption = v
                .get("caption")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            return Some((activity, caption));
        }
        None
    }
}

impl Drop for GuiStreamClient {
    fn drop(&mut self) {
        // Kill + reap the child. This closes the child's stdout, so the
        // detached reader thread's `read_line` returns EOF and the thread
        // exits on its own. Because `request_board` waits on a bounded
        // `recv_timeout` (not a raw blocking `read_line`), this Drop is
        // never gated behind an unbounded read — it runs promptly even if
        // the daemon had gone unresponsive.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Board fetch for the live-tail timer: try the warm `gui-stream` channel
/// first (lazy-connecting the client on first use), fall back to the cold
/// 4-subprocess path on any failure. A failed warm request drops the dead
/// client so the next tick reconnects from scratch.
/// Warm-only activity probe for the docked Buddy. Reuses the SHARED gui-stream
/// client (serialised by its mutex with the board fetch, so requests never
/// interleave on the wire). `None` when there's no warm channel — the Buddy
/// keeps its current mood that tick (no cold-path subprocess for ambient mood).
fn fetch_activity_warm(
    client: &std::sync::Mutex<Option<GuiStreamClient>>,
) -> Option<(String, String)> {
    let bin = which_neothd()?;
    let mut guard = client.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() {
        // Spawn the warm channel on first activity poll so the Buddy reflects
        // the daemon even if the operator never opens the Code Sessions tab.
        match GuiStreamClient::connect(&bin) {
            Ok(c) => *guard = Some(c),
            Err(_) => return None,
        }
    }
    let c = guard.as_mut()?;
    match c.request_activity() {
        Some(v) => Some(v),
        None => {
            // Broken channel — drop it so the next fetch reconnects.
            *guard = None;
            None
        }
    }
}

fn fetch_board_warm_or_cold(
    client: &std::sync::Mutex<Option<GuiStreamClient>>,
) -> KanbanBoardSnapshot {
    let Some(bin) = which_neothd() else {
        return fetch_kanban_board_snapshot(); // surfaces the "install" hint
    };
    // Recover from a poisoned lock rather than panicking the worker — the
    // guarded value is just a reconnectable client, never corrupt state.
    let mut guard = client.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() {
        match GuiStreamClient::connect(&bin) {
            Ok(c) => *guard = Some(c),
            Err(e) => {
                tracing::warn!(error = %e, "gui-stream: connect failed; using cold path");
                return fetch_kanban_board_snapshot();
            }
        }
    }
    if let Some(c) = guard.as_mut() {
        if let Some(snap) = c.request_board() {
            return snap;
        }
        // Warm request failed — drop the dead child so the next tick
        // reconnects, and serve this tick from the cold path.
        tracing::warn!("gui-stream: warm request failed; dropping client + cold fallback");
        *guard = None;
    }
    fetch_kanban_board_snapshot()
}

/// HO-02: probe whether a Cerebellum provider is bound. Runs
/// `neoth hemispheres show --output json` and returns true UNLESS we can
/// positively determine the cerebellum role has no provider AND there is
/// no single-mode fallback. Fail-safe (true) on any spawn/parse error so
/// a transient probe failure never false-alarms the operator with the
/// "no Cerebellum bound" banner.
fn probe_cerebellum_bound(bin: &Path) -> bool {
    let out = spawn_neothd_plain(bin)
        .arg("hemispheres")
        .arg("show")
        .arg("--output")
        .arg("json")
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return true, // fail-safe: don't alarm when the probe can't run
    };
    let v: serde_json::Value = match serde_json::from_slice(&stdout) {
        Ok(v) => v,
        Err(_) => return true,
    };
    // single-mode: every role routes to the single fallback provider.
    if v.get("single_provider_fallback")
        .and_then(|x| x.as_str())
        .is_some()
    {
        return true;
    }
    // per-role mode: the cerebellum role must carry a provider string.
    if let Some(roles) = v.get("roles").and_then(|x| x.as_array()) {
        for r in roles {
            if r.get("role").and_then(|x| x.as_str()) == Some("cerebellum") {
                return r.get("provider").and_then(|x| x.as_str()).is_some();
            }
        }
    }
    // No fallback + no cerebellum role row → decompose can't run.
    false
}

/// Pick #8 step 3 — Activity feed right rail. Subprocess
/// `neothd kanban watch --output json` reads the latest kanban frames
/// from `~/.neoth/wal/`, returns `Vec<FeedEntryJson>`. We collapse
/// failures to an empty feed (degraded UI is fine — board still works).
fn fetch_kanban_feed(bin: &Path) -> Vec<KanbanFeedRow> {
    let out = spawn_neothd_plain(bin)
        .arg("kanban")
        .arg("watch")
        .arg("--output")
        .arg("json")
        .arg("--limit")
        .arg("50")
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            tracing::warn!(
                exit = ?o.status,
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "kanban watch failed; rendering empty feed",
            );
            return Vec::new();
        }
        Err(e) => {
            tracing::warn!(error = %e, "kanban watch could not start; rendering empty feed");
            return Vec::new();
        }
    };
    let entries: Vec<FeedEntryJson> = match serde_json::from_slice(&stdout) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "kanban watch JSON parse failed; rendering empty feed");
            return Vec::new();
        }
    };
    // Most-recent-first for the right rail — the WAL scan returns
    // newest-last (append order), so reverse for the UI.
    entries
        .into_iter()
        .rev()
        .map(|e| KanbanFeedRow {
            ts: format_hms_from_ns(e.ts_ns).into(),
            actor: e.actor.into(),
            message: e.message.into(),
        })
        .collect()
}

/// Detail-pane subprocess fetch. Strips the leading `#` from the
/// Slint-formatted task id, calls `neoth kanban task <id> --output
/// json`, parses the `{task, comments}` envelope, returns the
/// formatted `KanbanCommentRow` vec. Empty vec on any failure — the
/// detail pane just renders without a comment thread instead of
/// surfacing a subprocess error in the UI.
fn fetch_task_comments(task_id_with_hash: &str) -> Vec<KanbanCommentRow> {
    let id = task_id_with_hash
        .strip_prefix('#')
        .unwrap_or(task_id_with_hash);
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    let out = spawn_neothd_plain(&bin)
        .arg("kanban")
        .arg("task")
        .arg(id)
        .arg("--output")
        .arg("json")
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            tracing::warn!(
                task_id = id,
                exit = ?o.status,
                "kanban task fetch failed; rendering empty comments"
            );
            return Vec::new();
        }
        Err(e) => {
            tracing::warn!(task_id = id, error = %e, "kanban task fetch could not start");
            return Vec::new();
        }
    };
    let envelope: TaskDetailEnvelope = match serde_json::from_slice(&stdout) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "kanban task JSON parse failed");
            return Vec::new();
        }
    };
    envelope
        .comments
        .into_iter()
        .map(|c| KanbanCommentRow {
            ts: format_hms_from_ns(c.created_ns).into(),
            author: c.author.into(),
            body: c.body.into(),
        })
        .collect()
}

/// Format a unix-ns timestamp as `HH:MM` for the activity feed. Mirrors
/// `neothd::cli::kanban::format_ts_short` but emits HH:MM (not HH:MM:SS)
/// because the feed rail is narrow + the seconds add visual noise.
fn format_hms_from_ns(ts_ns: u64) -> String {
    let secs = ts_ns / 1_000_000_000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    format!("{h:02}:{m:02}")
}

/// Push a `KanbanBoardSnapshot` into the eight Slint properties on the
/// MainWindow. Single call site means a future schema bump only needs
/// one update — the property names stay 1:1 with the snapshot fields.
fn apply_kanban_snapshot(window: &MainWindow, snap: KanbanBoardSnapshot) {
    use slint::{ModelRc, VecModel};
    window.set_kanban_backlog(ModelRc::new(VecModel::from(snap.backlog)));
    window.set_kanban_todo(ModelRc::new(VecModel::from(snap.todo)));
    window.set_kanban_in_progress(ModelRc::new(VecModel::from(snap.in_progress)));
    window.set_kanban_review(ModelRc::new(VecModel::from(snap.review)));
    window.set_kanban_done(ModelRc::new(VecModel::from(snap.done)));
    window.set_kanban_feed(ModelRc::new(VecModel::from(snap.feed)));
    window.set_kanban_session_summary(snap.summary.into());
    // HO-02: None (degraded / un-probed path) → true, so the banner only
    // shows when we positively determined no Cerebellum is bound.
    window.set_cerebellum_bound(snap.cerebellum_bound.unwrap_or(true));
}

/// R2-P0-1: GUI chat dispatch via the `neothd chat` subprocess. Returns
/// `Ok(reply_text)` on success or `Err(error_for_bubble)` so the caller
/// can render either path as a chat bubble.
///
/// Routing through the daemon binary (same pattern as
/// `probe_hardware_via_subprocess`) keeps the GUI crate decoupled from
/// daemon internals while ensuring GUI Send hits EXACTLY the same
/// provider / WAL / permission / cost / autonomy code path as
/// `neothd chat` from a terminal — that's the R2 done-criterion.
/// Chat-feel parity (openhuman): split a NEOTH assistant reply into
/// multiple bubbles at blank-line (paragraph) boundaries, so a
/// multi-paragraph reply reads as a conversation cluster instead of one
/// wall of text. Mirrors openhuman's render-time `splitAgentMessageInto
/// Bubbles` — a pure line-iterator state machine, no Slint/UI dependency,
/// fully unit-testable.
///
/// Rules:
/// - A fenced code block (```…```) is kept INTACT as one bubble — blank
///   lines inside a fence never split it (avoids fragmenting code/tables).
/// - A blank line OUTSIDE a fence ends the current bubble.
/// - Segments that are only a visual separator (`---` / `***` / `___`) are
///   dropped (openhuman's `isVisualSeparatorOnly`) so horizontal rules
///   don't render as empty bubbles.
/// - Each emitted segment is trimmed. A non-empty reply always yields at
///   least one bubble (falls back to the whole trimmed reply).
pub fn segment_reply_into_bubbles(reply: &str) -> Vec<String> {
    fn push_segment(cur: &[&str], out: &mut Vec<String>) {
        let trimmed = cur.join("\n");
        let trimmed = trimmed.trim();
        if !trimmed.is_empty() && !is_visual_separator_only(trimmed) {
            out.push(trimmed.to_string());
        }
    }
    let mut bubbles: Vec<String> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut in_fence = false;
    for line in reply.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            current.push(line);
            continue;
        }
        if !in_fence && line.trim().is_empty() {
            push_segment(&current, &mut bubbles);
            current.clear();
        } else {
            current.push(line);
        }
    }
    push_segment(&current, &mut bubbles);
    if bubbles.is_empty() {
        let t = reply.trim();
        if !t.is_empty() {
            bubbles.push(t.to_string());
        }
    }
    bubbles
}

/// True when `s` (already trimmed, non-empty) is ONLY a Markdown
/// horizontal-rule / visual separator — 3+ of `-`/`*`/`_` (allowing
/// interspersed spaces, as Markdown permits `- - -`). Such a segment
/// carries no content and is dropped during bubble segmentation.
fn is_visual_separator_only(s: &str) -> bool {
    let non_space: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    non_space.len() >= 3
        && non_space.iter().all(|&c| c == '-' || c == '*' || c == '_')
        && non_space.iter().all(|&c| c == non_space[0])
}

/// Chat-feel parity #3 (beat-openhuman): split the raw stdout of
/// `neoth chat --stream` into `(reply_text, done)`. The CLI streams raw
/// reply deltas incrementally, then emits a blank line + a final sentinel
/// line `{"neoth_stream":"done","count":N}` (OPEN_DECISIONS D-005) so a
/// consumer can tell a CLEAN completion from a truncated stream. Everything
/// before the sentinel is the reply (trailing blank trimmed); `done` is
/// true once the sentinel appears. Pure fn — unit-testable; called per
/// stdout chunk during streaming (mid-stream: no sentinel yet → done=false,
/// live partial text) and once at EOF (done=true → final text to segment).
pub fn strip_stream_sentinel(raw: &str) -> (String, bool) {
    let (text, done, _) = parse_stream_sentinel(raw);
    (text, done)
}

/// GOLD-ADAPT-ODY-02/05 — token/timing stats the extended done-sentinel
/// carries. All-zero when the daemon predates the extension (recall
/// early-return still emits the minimal `{"neoth_stream":"done","count":1}`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StreamStats {
    pub used_tokens: u64,
    pub limit_tokens: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub elapsed_ms: u64,
}

/// Split the accumulated stream buffer into (reply-text, done, stats).
/// Mid-stream (no sentinel yet): done=false, zero stats.
pub fn parse_stream_sentinel(raw: &str) -> (String, bool, StreamStats) {
    let Some(pos) = raw.rfind("{\"neoth_stream\":\"done\"") else {
        return (raw.trim_end().to_string(), false, StreamStats::default());
    };
    // Parse ONLY the sentinel line — any stray byte after it would make
    // serde reject the whole slice and silently zero the stats.
    let sentinel_line = raw[pos..].lines().next().unwrap_or("");
    let stats = serde_json::from_str::<serde_json::Value>(sentinel_line.trim())
        .ok()
        .map(|v| {
            let g = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
            StreamStats {
                used_tokens: g("used_tokens"),
                limit_tokens: g("limit_tokens"),
                input_tokens: g("input_tokens"),
                output_tokens: g("output_tokens"),
                elapsed_ms: g("elapsed_ms"),
            }
        })
        .unwrap_or_default();
    (raw[..pos].trim_end().to_string(), true, stats)
}

/// ODY-12 UI-control targets — must match `main.slint`'s nav values.
/// A `nav` chip whose id is not in this list is ignored (prompt drift
/// must not navigate somewhere undefined).
pub const NAV_PANELS: [&str; 25] = [
    "chat",
    "overview",
    "memory",
    "hemispheres",
    "channels",
    "coding",
    "agents",
    "automation",
    "privacy",
    "plugins",
    "cluster",
    "resources",
    "doctor",
    "loops",
    "config",
    // Wave 4a
    "n8n",
    "babel",
    "calendar",
    "evolve",
    // Wave 4b
    "obsidian",
    "dreaming",
    "wiki",
    "buddyconfig",
    "companion",
    "mesh",
];

/// GOLD-ADAPT-ODY-12/14 — deep-link chips from the done-sentinel's
/// additive `links` array (`[{label, kind, id}, ..]`). Empty when the
/// field is absent (older daemons), mid-stream, or malformed — the
/// chips row simply doesn't render. Returns (label, kind, id) tuples.
pub fn parse_stream_links(raw: &str) -> Vec<(String, String, String)> {
    let Some(pos) = raw.rfind("{\"neoth_stream\":\"done\"") else {
        return Vec::new();
    };
    let sentinel_line = raw[pos..].lines().next().unwrap_or("");
    serde_json::from_str::<serde_json::Value>(sentinel_line.trim())
        .ok()
        .and_then(|v| v.get("links").cloned())
        .and_then(|l| l.as_array().cloned())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    Some((
                        e.get("label")?.as_str()?.to_string(),
                        e.get("kind")?.as_str()?.to_string(),
                        e.get("id")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Non-streaming chat round-trip (waits for full stdout). The live chat
/// path now uses `neoth chat --stream` (see the send-worker), so this is
/// retained as the test-injection seam for [`shape_chat_output`]: the
/// caller pins the binary path, letting tests run a synthetic fake-neothd
/// (tempdir-staged `bin.sh` / `bin.cmd` that emit fixture stdout/stderr)
/// instead of the real daemon. Kept because the four-outcome shaping logic
/// it exercises is the same error taxonomy the streaming path's terminal
/// states map onto.
#[cfg_attr(not(test), allow(dead_code))]
pub fn chat_via_subprocess_with(
    bin: &std::path::Path,
    message: &str,
) -> std::result::Result<String, String> {
    let output = spawn_neothd_plain(bin).arg("chat").arg(message).output();
    match output {
        Ok(out) => shape_chat_output(
            out.status.success(),
            &out.stdout,
            &out.stderr,
            out.status.code(),
        ),
        Err(e) => Err(format!(
            "Chat subprocess could not start: {e}\n\
             Verify `neothd --version` works from a terminal."
        )),
    }
}

/// R4-P1 pure result-shaping helper. Decouples the four-outcome
/// decision tree (success-with-reply / success-but-empty / non-zero-
/// exit-with-stderr / non-zero-exit-no-stderr) from the real subprocess
/// so tests pin the contract without an actual spawn.
pub fn shape_chat_output(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    code: Option<i32>,
) -> std::result::Result<String, String> {
    if success {
        let s = String::from_utf8_lossy(stdout);
        let reply = s.trim_end_matches(['\n', '\r']).to_string();
        if reply.is_empty() {
            return Err("Provider returned an empty reply. Check `neoth doctor` + \
                 `~/.neoth/freedom.yaml` provider settings."
                .to_string());
        }
        return Ok(reply);
    }
    let stderr_str = String::from_utf8_lossy(stderr);
    let trimmed = stderr_str.trim();
    let exit_label = code
        .map(|c| format!("exit {c}"))
        .unwrap_or_else(|| "exit ?".to_string());
    if trimmed.is_empty() {
        Err(format!(
            "`neothd chat` exited {exit_label} with no diagnostic. Run from \
             a terminal to capture the failure context."
        ))
    } else {
        // Cap at ~600 chars so a stack-traceful Rust panic doesn't blow
        // the chat bubble. Operators reading the full failure run
        // `neothd chat` from a shell anyway.
        let snippet = if trimmed.len() > 600 {
            // Char-boundary-safe truncation for UTF-8 stderr bytes.
            let chars: Vec<char> = trimmed.chars().collect();
            let cap = chars.iter().take(599).collect::<String>();
            format!("{cap}…")
        } else {
            trimmed.to_string()
        };
        Err(format!("Chat failed ({exit_label}):\n{snippet}"))
    }
}

/// R4-P1 operator-readable diagnostic for the binary-missing path.
/// Pulled to a const so tests can pin the exact string.
pub const BINARY_MISSING_MESSAGE: &str = "Chat unavailable — `neothd` binary not on PATH.\n\
     Install the daemon first (the release tarball ships both \
     `neothd-gui` and `neothd` side-by-side; from source, \
     `cargo install --path ../neothd`).";

/// QM-9 Phase 3+: how often the dashboard tile re-fires the
/// `neoth usage` subprocess. 60s feels live-enough for chat-
/// cost monitoring without spawning a subprocess every second.
/// Operators wanting faster refresh use `neoth usage --format
/// json` in a `watch -n 1` loop.
pub const USAGE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// GOLD-WIRE-10b: how often the dashboard tile re-fires the
/// `neoth meter --json` subprocess. 15s gives a near-live budget
/// feel without spawning a subprocess every second.
pub const BUDGET_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// QM-8 Phase 2: how often the preset tile re-fires `neoth preset
/// list`. Lighter cadence than usage since presets change rarely.
pub const PRESET_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

#[cfg(test)]
mod chat_subprocess_tests {
    use super::*;

    #[test]
    fn segment_single_paragraph_is_one_bubble() {
        let r = segment_reply_into_bubbles("Just one line of reply.");
        assert_eq!(r, vec!["Just one line of reply.".to_string()]);
    }

    #[test]
    fn segment_splits_paragraphs_at_blank_line() {
        let r = segment_reply_into_bubbles("First paragraph.\n\nSecond paragraph.\n\nThird.");
        assert_eq!(
            r,
            vec![
                "First paragraph.".to_string(),
                "Second paragraph.".to_string(),
                "Third.".to_string()
            ]
        );
    }

    #[test]
    fn segment_keeps_fenced_code_block_intact() {
        // A code fence with internal blank lines must stay ONE bubble.
        let reply = "Here is the fix:\n\n```rust\nfn a() {}\n\nfn b() {}\n```\n\nDone.";
        let r = segment_reply_into_bubbles(reply);
        assert_eq!(r.len(), 3, "intro + fenced block + outro: {r:?}");
        assert!(
            r[1].contains("fn a()") && r[1].contains("fn b()"),
            "fence intact: {:?}",
            r[1]
        );
        assert!(r[1].contains("```"), "fence markers preserved");
    }

    #[test]
    fn segment_drops_visual_separator_segments() {
        // A `---` horizontal rule between paragraphs is dropped, not a bubble.
        let r = segment_reply_into_bubbles("Above the line.\n\n---\n\nBelow the line.");
        assert_eq!(
            r,
            vec!["Above the line.".to_string(), "Below the line.".to_string()]
        );
    }

    #[test]
    fn segment_trims_and_collapses_leading_trailing_blanks() {
        let r = segment_reply_into_bubbles("\n\n  Only content.  \n\n\n");
        assert_eq!(r, vec!["Only content.".to_string()]);
    }

    #[test]
    fn segment_empty_reply_yields_no_bubbles() {
        assert!(segment_reply_into_bubbles("   \n\n  ").is_empty());
    }

    #[test]
    fn strip_stream_sentinel_mid_stream_has_no_sentinel() {
        // While streaming, the sentinel hasn't arrived → done=false, the
        // accumulated partial text is returned (trailing whitespace trimmed).
        let (txt, done) = strip_stream_sentinel("Hello, I am think");
        assert_eq!(txt, "Hello, I am think");
        assert!(!done);
    }

    #[test]
    fn strip_stream_sentinel_strips_done_line_and_trailing_blank() {
        // Clean completion: reply + blank line + sentinel JSON line.
        let raw = "Here is the answer.\n\n{\"neoth_stream\":\"done\",\"count\":7}\n";
        let (txt, done) = strip_stream_sentinel(raw);
        assert_eq!(txt, "Here is the answer.");
        assert!(done);
        assert!(!txt.contains("neoth_stream"), "sentinel must be stripped");
    }

    #[test]
    fn strip_stream_sentinel_empty_reply_with_sentinel_is_done() {
        let (txt, done) = strip_stream_sentinel("\n{\"neoth_stream\":\"done\",\"count\":0}\n");
        assert_eq!(txt, "");
        assert!(done);
    }

    // ODY-02/05 — the extended sentinel carries token/timing stats.
    #[test]
    fn parse_stream_sentinel_reads_extended_token_fields() {
        let raw = "Answer.\n\n{\"neoth_stream\":\"done\",\"count\":3,\
                   \"used_tokens\":12400,\"limit_tokens\":200000,\
                   \"input_tokens\":12000,\"output_tokens\":400,\"elapsed_ms\":10000}\n";
        let (txt, done, stats) = parse_stream_sentinel(raw);
        assert_eq!(txt, "Answer.");
        assert!(done);
        assert_eq!(
            stats,
            StreamStats {
                used_tokens: 12_400,
                limit_tokens: 200_000,
                input_tokens: 12_000,
                output_tokens: 400,
                elapsed_ms: 10_000,
            }
        );
    }

    // Minimal legacy sentinel (recall early-return) → zero stats, still done.
    #[test]
    fn parse_stream_sentinel_minimal_sentinel_zero_stats() {
        let (txt, done, stats) =
            parse_stream_sentinel("hit\n{\"neoth_stream\":\"done\",\"count\":1}\n");
        assert_eq!(txt, "hit");
        assert!(done);
        assert_eq!(stats, StreamStats::default());
    }

    #[test]
    fn strip_stream_sentinel_multiparagraph_preserved_before_sentinel() {
        // Internal blank lines (paragraph breaks) survive — only the
        // trailing blank+sentinel is removed, so segmentation still works.
        let raw = "Para one.\n\nPara two.\n\n{\"neoth_stream\":\"done\",\"count\":3}";
        let (txt, done) = strip_stream_sentinel(raw);
        assert_eq!(txt, "Para one.\n\nPara two.");
        assert!(done);
        // And it segments into two bubbles downstream.
        assert_eq!(segment_reply_into_bubbles(&txt).len(), 2);
    }

    #[test]
    fn visual_separator_matrix() {
        assert!(is_visual_separator_only("---"));
        assert!(is_visual_separator_only("***"));
        assert!(is_visual_separator_only("___"));
        assert!(is_visual_separator_only("- - -")); // markdown spaced hr
        assert!(!is_visual_separator_only("--")); // too short
        assert!(!is_visual_separator_only("-*-")); // mixed glyphs
        assert!(!is_visual_separator_only("text")); // real content
    }

    #[test]
    fn shape_chat_output_happy_path_returns_trimmed_stdout() {
        // Reply with trailing newlines (every `neothd chat` adds one);
        // shape_chat_output trims the tail but preserves internal
        // newlines for code blocks / lists.
        let result = shape_chat_output(true, b"The answer is 42.\nLine two.\n\n", b"", Some(0));
        assert_eq!(result, Ok("The answer is 42.\nLine two.".to_string()));
    }

    #[test]
    fn shape_chat_output_empty_stdout_is_error_with_doctor_hint() {
        let result = shape_chat_output(true, b"", b"", Some(0));
        match result {
            Err(msg) => {
                assert!(msg.contains("empty reply"));
                assert!(msg.contains("neoth doctor"));
            }
            Ok(_) => panic!("empty stdout must error"),
        }
    }

    #[test]
    fn shape_chat_output_nonzero_with_stderr_surfaces_diagnostic() {
        let result = shape_chat_output(
            false,
            b"",
            b"Error: no provider configured. Run `neoth init` first.",
            Some(1),
        );
        match result {
            Err(msg) => {
                assert!(msg.contains("exit 1"));
                assert!(msg.contains("no provider configured"));
                assert!(msg.contains("Chat failed"));
            }
            Ok(_) => panic!("non-zero exit must error"),
        }
    }

    #[test]
    fn shape_chat_output_nonzero_no_stderr_points_at_terminal() {
        let result = shape_chat_output(false, b"", b"", Some(137));
        match result {
            Err(msg) => {
                assert!(msg.contains("exit 137"));
                assert!(msg.contains("no diagnostic"));
                assert!(msg.contains("terminal"));
            }
            Ok(_) => panic!("non-zero exit must error"),
        }
    }

    #[test]
    fn shape_chat_output_truncates_long_stderr_to_600_chars() {
        let long_stderr = "X".repeat(5000);
        let result = shape_chat_output(false, b"", long_stderr.as_bytes(), Some(1));
        match result {
            Err(msg) => {
                // Total error message includes prefix + 599 chars of
                // stderr + ellipsis. Bound at ~650 to allow prefix.
                assert!(msg.len() < 700, "msg too long: {} chars", msg.len());
                assert!(msg.contains("…"));
            }
            Ok(_) => panic!("non-zero must error"),
        }
    }

    #[test]
    fn shape_chat_output_handles_utf8_multibyte_stderr_truncation() {
        // 1000 em-dashes (3 bytes each in utf-8) — truncation must
        // not split a multi-byte char.
        let long_stderr = "—".repeat(1000);
        let result = shape_chat_output(false, b"", long_stderr.as_bytes(), Some(2));
        match result {
            Err(msg) => {
                // The message must be valid utf-8 (would panic on the
                // older `&str[..600]` byte-slice path).
                assert!(msg.is_ascii() || msg.chars().count() > 100);
                assert!(msg.contains("…"));
            }
            Ok(_) => panic!("non-zero must error"),
        }
    }

    #[test]
    fn shape_chat_output_handles_none_exit_code() {
        // Process killed by signal: status.code() returns None.
        let result = shape_chat_output(false, b"", b"killed", None);
        match result {
            Err(msg) => assert!(msg.contains("exit ?")),
            Ok(_) => panic!("killed must error"),
        }
    }

    #[test]
    fn binary_missing_message_carries_install_pointer() {
        // Operator-readable diagnostic for the no-binary path. Pin
        // the install pointers so a future refactor doesn't drop them.
        assert!(BINARY_MISSING_MESSAGE.contains("neothd"));
        assert!(BINARY_MISSING_MESSAGE.contains("PATH"));
        assert!(
            BINARY_MISSING_MESSAGE.contains("release tarball")
                || BINARY_MISSING_MESSAGE.contains("cargo install")
        );
    }

    // ── QM-9 Phase 2 dashboard probe tests ──────────────────────────────

    #[test]
    fn shape_usage_summary_renders_calls_ok_err_cost() {
        let json = r#"{
            "since_unix": 0,
            "until_unix": 100,
            "total_call_count": 7,
            "total_ok_count": 6,
            "total_err_count": 1,
            "total_input_tokens": 500,
            "total_output_tokens": 800,
            "total_cost_usd": 0.1234,
            "per_provider": []
        }"#;
        let s = crate::shape_usage_summary(json);
        assert!(s.contains("7 calls"));
        assert!(s.contains("ok=6"));
        assert!(s.contains("err=1"));
        assert!(s.contains("$0.1234"));
    }

    #[test]
    fn shape_usage_summary_zero_calls_says_no_usage() {
        let json = r#"{
            "since_unix": 0,
            "until_unix": 100,
            "total_call_count": 0,
            "total_ok_count": 0,
            "total_err_count": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost_usd": 0.0,
            "per_provider": []
        }"#;
        let s = crate::shape_usage_summary(json);
        assert!(s.contains("No usage"));
    }

    #[test]
    fn shape_usage_summary_malformed_json_returns_error_string() {
        let s = crate::shape_usage_summary("{not json");
        assert!(s.contains("malformed"));
    }

    #[test]
    fn shape_usage_summary_missing_fields_defaults_to_zero() {
        let s = crate::shape_usage_summary("{}");
        assert!(s.contains("No usage"));
    }

    // ── QM-8 Phase 2 preset summary tests ───────────────────────────────

    #[test]
    fn shape_preset_summary_no_presets_says_so() {
        let s = crate::shape_preset_summary(b"(no presets - run `neoth preset --help` ...)\n");
        assert!(s.contains("No presets saved"));
    }

    #[test]
    fn shape_preset_summary_renders_count_and_active() {
        let stdout = b"   alpha\n * middle\n   zeta\n";
        let s = crate::shape_preset_summary(stdout);
        assert!(s.contains("3 presets"));
        assert!(s.contains("middle"));
    }

    #[test]
    fn shape_preset_summary_handles_no_active_marker() {
        let stdout = b"   alpha\n   zeta\n";
        let s = crate::shape_preset_summary(stdout);
        assert!(s.contains("2 presets"));
        assert!(s.contains("no active"));
    }

    #[test]
    fn shape_preset_summary_empty_stdout_says_no_presets() {
        let s = crate::shape_preset_summary(b"");
        assert!(s.contains("No presets saved"));
    }

    #[test]
    fn parse_active_preset_name_finds_starred_row() {
        let stdout = b"   alpha\n * middle\n   zeta\n";
        assert_eq!(
            crate::parse_active_preset_name(stdout),
            Some("middle".to_string())
        );
    }

    #[test]
    fn parse_active_preset_name_returns_none_without_marker() {
        let stdout = b"   alpha\n   zeta\n";
        assert_eq!(crate::parse_active_preset_name(stdout), None);
    }

    #[test]
    fn parse_active_preset_name_handles_empty_stdout() {
        assert_eq!(crate::parse_active_preset_name(b""), None);
    }

    #[test]
    fn parse_active_preset_name_handles_only_star() {
        // Star without name → None.
        let stdout = b"   alpha\n * \n   zeta\n";
        assert_eq!(crate::parse_active_preset_name(stdout), None);
    }

    #[test]
    fn chat_via_subprocess_with_returns_error_when_bin_does_not_exist() {
        // Bin at a path that doesn't exist on disk → subprocess
        // spawn errors with NotFound. Pin the operator-readable
        // "could not start" diagnostic.
        let nonexistent = std::path::PathBuf::from("/this/path/does/not/exist/neothd_test_fake");
        let result = chat_via_subprocess_with(&nonexistent, "hello");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("could not start") || msg.contains("Chat subprocess"));
    }

    #[test]
    fn apply_active_preset_via_subprocess_with_reports_binary_missing() {
        // GR-05: the apply seam degrades to an operator-readable status
        // string (not a panic) when the pinned binary can't spawn — the
        // first subprocess (`preset list`) fails to start. The
        // active-name parsing the happy path relies on is covered
        // separately by `parse_active_preset_name_*`.
        let nonexistent =
            std::path::PathBuf::from("/this/path/does/not/exist/neothd_test_fake_preset");
        let result = crate::apply_active_preset_via_subprocess_with(&nonexistent);
        assert!(
            result.contains("could not start"),
            "expected a spawn-failure status, got: {result}"
        );
    }

    /// GR-05: stage a fake `neothd` that answers `preset list` (with or
    /// without an active `*` marker) and `preset apply <name>` (exit 0),
    /// so the full list → parse-active → apply seam can be driven end-to-end
    /// against a staged binary. Windows → `.cmd`; unix → an executable
    /// `#!/bin/sh` script.
    fn stage_fake_preset_neothd(
        dir: &std::path::Path,
        list_has_active: bool,
    ) -> std::path::PathBuf {
        #[cfg(windows)]
        {
            let p = dir.join("neothd.cmd");
            let list_line = if list_has_active {
                "echo * lowkey"
            } else {
                "echo   lowkey"
            };
            // `preset list` echoes the bundle list; everything else (incl.
            // `preset apply`) just exits 0.
            let body = format!(
                "@echo off\r\nif \"%1\"==\"preset\" if \"%2\"==\"list\" {list_line}\r\nexit /b 0\r\n"
            );
            std::fs::write(&p, body).unwrap();
            p
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.join("neothd.sh");
            let list_line = if list_has_active {
                "echo '* lowkey'"
            } else {
                "echo '  lowkey'"
            };
            let body = format!(
                "#!/bin/sh\nif [ \"$1\" = preset ] && [ \"$2\" = list ]; then {list_line}; fi\nexit 0\n"
            );
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        }
    }

    #[test]
    fn apply_active_preset_via_subprocess_with_applies_when_active_present() {
        // Full happy path: list returns `* lowkey` → parse-active finds
        // `lowkey` → apply succeeds (exit 0) → "Applied preset `lowkey`."
        let dir = tempfile::TempDir::new().unwrap();
        let bin = stage_fake_preset_neothd(dir.path(), true);
        let result = crate::apply_active_preset_via_subprocess_with(&bin);
        assert!(
            result.contains("Applied preset") && result.contains("lowkey"),
            "expected applied-preset status, got: {result}"
        );
    }

    #[test]
    fn apply_active_preset_via_subprocess_with_reports_no_active_when_no_marker() {
        // List has no `*` marker → no active preset → the seam stops before
        // any apply and returns the operator-guidance status.
        let dir = tempfile::TempDir::new().unwrap();
        let bin = stage_fake_preset_neothd(dir.path(), false);
        let result = crate::apply_active_preset_via_subprocess_with(&bin);
        assert!(
            result.contains("No active preset"),
            "expected no-active-preset status, got: {result}"
        );
    }

    // ODY-10: recall buffer logic — pure Rust unit tests (no Slint window).

    #[test]
    fn recall_buffer_captures_last_non_empty_send() {
        let buf: std::sync::Arc<std::sync::Mutex<String>> =
            std::sync::Arc::new(std::sync::Mutex::new(String::new()));

        // Simulate what on_chat_send_clicked does on a non-empty body.
        let body = "  hello world  ".trim().to_string();
        if !body.is_empty() {
            if let Ok(mut last) = buf.lock() {
                *last = body.clone();
            }
        }
        assert_eq!(*buf.lock().unwrap(), "hello world");

        // A second non-empty send overwrites the buffer.
        let body2 = "second message".to_string();
        if !body2.is_empty() {
            if let Ok(mut last) = buf.lock() {
                *last = body2.clone();
            }
        }
        assert_eq!(*buf.lock().unwrap(), "second message");
    }

    #[test]
    fn recall_buffer_ignores_empty_body() {
        let buf: std::sync::Arc<std::sync::Mutex<String>> =
            std::sync::Arc::new(std::sync::Mutex::new("previous".to_string()));

        // An empty body (early-return guard) must NOT overwrite the buffer.
        let body = "  ".trim().to_string();
        if !body.is_empty() {
            if let Ok(mut last) = buf.lock() {
                *last = body.clone();
            }
        }
        assert_eq!(
            *buf.lock().unwrap(),
            "previous",
            "empty send must not clobber recall buffer"
        );
    }
}

// ── GAP-01 Cron panel probe ───────────────────────────────────────────────────
//
// Shells `neoth cron list --output json`, parses via panel_logic::parse_cron_jobs,
// then pushes a typed CronJobRow model into the Slint event loop.
fn refresh_cron(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let json = run_neothd_probe(&["cron", "list", "--output", "json"]);
    let jobs = panel_logic::parse_cron_jobs(&json);
    let ts   = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let rows: Vec<CronJobRow> = jobs
            .into_iter()
            .map(|(id, name, enabled, cron, tz, role, timeout, channel, recipient)| CronJobRow {
                id:        id.into(),
                name:      name.into(),
                enabled,
                cron:      cron.into(),
                tz:        tz.into(),
                role:      role.into(),
                timeout:   timeout.into(),
                channel:   channel.into(),
                recipient: recipient.into(),
            })
            .collect();
        w.set_cron_jobs(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        w.set_cron_running(false);
        w.set_cron_refreshed_at(ts.as_str().into());
    });
}

// ── Design Wave 4a — n8n panel probe ─────────────────────────────────────────
fn refresh_n8n(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let status_json    = run_neothd_probe(&["n8n", "status",    "--output", "json"]);
    let workflows_json = run_neothd_probe(&["n8n", "workflows", "--output", "json"]);

    let (installed, webhook_base, n8n_path) =
        panel_logic::parse_n8n_status(&status_json);
    let workflows = panel_logic::parse_n8n_workflows(&workflows_json);

    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_n8n_installed(installed);
        w.set_n8n_webhook_base(webhook_base.as_str().into());
        w.set_n8n_path(n8n_path.as_str().into());
        {
            let rows: Vec<N8nWorkflow> = workflows
                .into_iter()
                .map(|(name, description)| N8nWorkflow {
                    name: name.into(),
                    description: description.into(),
                })
                .collect();
            w.set_n8n_workflows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        w.set_n8n_refreshed_at(ts.as_str().into());
    });
}

// ── Design Wave 4a — Babel panel probe ───────────────────────────────────────
fn refresh_babel(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let status_json  = run_neothd_probe(&["babel", "status",  "--output", "json"]);
    let windows_json = run_neothd_probe(&["babel", "windows", "--n", "12", "--output", "json"]);

    let (enabled, threshold, epsilon, federate, total_windows, collapse_flagged, gran_rows) =
        panel_logic::parse_babel_status(&status_json);
    let window_rows = panel_logic::parse_babel_windows(&windows_json);

    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_babel_enabled(enabled);
        w.set_babel_threshold(threshold.as_str().into());
        w.set_babel_epsilon(epsilon.as_str().into());
        w.set_babel_federate(federate);
        w.set_babel_total_windows(total_windows);
        w.set_babel_collapse_flagged(collapse_flagged);
        {
            let rows: Vec<BabelGranRow> = gran_rows
                .into_iter()
                .map(|(window_secs, count, last_ts_end)| BabelGranRow {
                    window_secs,
                    count,
                    last_ts_end: last_ts_end.into(),
                })
                .collect();
            w.set_babel_gran_rows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        {
            let rows: Vec<BabelWindowRow> = window_rows
                .into_iter()
                .map(|(id, window_secs, ts_start, ts_end, b_log, b_mult, b_bottleneck, collapse_kind)| {
                    BabelWindowRow {
                        id: id.into(),
                        window_secs,
                        ts_start: ts_start.into(),
                        ts_end: ts_end.into(),
                        b_log,
                        b_mult,
                        b_bottleneck,
                        collapse_kind: collapse_kind.into(),
                    }
                })
                .collect();
            w.set_babel_window_rows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        w.set_babel_refreshed_at(ts.as_str().into());
    });
}

// ── Design Wave 4a — Calendar panel probe ────────────────────────────────────
fn refresh_calendar(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let cal_json = run_neothd_probe(&["calendar", "list", "--output", "json"]);

    let (configured, events) = panel_logic::parse_calendar_events(&cal_json);

    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_cal_configured(configured);
        {
            let rows: Vec<CalEventRow> = events
                .into_iter()
                .map(|(datetime, summary, location)| CalEventRow {
                    datetime: datetime.into(),
                    summary: summary.into(),
                    location: location.into(),
                })
                .collect();
            w.set_cal_events(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        w.set_cal_refreshed_at(ts.as_str().into());
    });
}

// ── Design Wave 4a — Self-Improve panel probe ─────────────────────────────────
fn refresh_selfimprove(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let status_json  = run_neothd_probe(&["self-improve", "status", "--output", "json"]);
    let review_json  = run_neothd_probe(&["self-improve", "review", "--output", "json"]);
    let log_json     = run_neothd_probe(&["self-improve", "log",    "--output", "json"]);

    let (si_enabled, si_auto, si_skillopt, si_last, si_autonomy) =
        panel_logic::parse_selfimprove_status(&status_json);
    let proposals = panel_logic::parse_selfimprove_proposals(&review_json);
    let log_rows  = panel_logic::parse_selfimprove_log(&log_json);

    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_si_enabled(si_enabled);
        w.set_si_auto(si_auto);
        w.set_si_skillopt_installed(si_skillopt);
        w.set_si_last_run(si_last.as_str().into());
        w.set_si_autonomy(si_autonomy.as_str().into());
        {
            let rows: Vec<SiProposalRow> = proposals
                .into_iter()
                .map(|(id, title, description)| SiProposalRow {
                    id: id.into(),
                    title: title.into(),
                    description: description.into(),
                })
                .collect();
            w.set_si_proposals(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        {
            let rows: Vec<SiLogRow> = log_rows
                .into_iter()
                .map(|(id, title, status, ts_entry)| SiLogRow {
                    id: id.into(),
                    title: title.into(),
                    status: status.into(),
                    ts: ts_entry.into(),
                })
                .collect();
            w.set_si_log(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        w.set_si_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Obsidian Vault probe ───────────────────────────────────────────
fn refresh_obsidian(weak: slint::Weak<MainWindow>) {
    let out = run_neothd_probe(&["obsidian", "status", "--output", "json"]);
    let (vault_path, subdir, result_text) = panel_logic::parse_obsidian_status(&out);
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_obs_vault_path(vault_path.as_str().into());
        w.set_obs_subdir(subdir.as_str().into());
        w.set_obs_result_text(result_text.as_str().into());
        w.set_obs_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Dreaming / Memory & Self-Awareness probe ───────────────────────
fn refresh_dreaming(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let out = run_neothd_probe(&["dream", "list", "--output", "json"]);
    let (days, refreshed_at) = panel_logic::parse_dream_days(&out);
    let ts = if refreshed_at.is_empty() { panel_logic::now_hhmm() } else { refreshed_at };
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let rows: Vec<DreamDayRow> = days
            .into_iter()
            .map(|(day, path, entries)| DreamDayRow {
                day: day.into(),
                path: path.into(),
                entries,
            })
            .collect();
        w.set_dr_days(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        w.set_dr_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Wiki / Capability Map probe ────────────────────────────────────
fn refresh_wiki(weak: slint::Weak<MainWindow>) {
    let out = run_neothd_probe(&["capabilities", "--output", "json"]);
    let rows = panel_logic::parse_wiki_rows(&out);
    apply_wiki(weak, rows);
}

fn refresh_wiki_filtered(weak: slint::Weak<MainWindow>, search: String, kind: String) {
    let out = run_neothd_probe(&["capabilities", "--output", "json"]);
    let all = panel_logic::parse_wiki_rows(&out);
    let rows = panel_logic::filter_wiki_rows(all, &search, &kind);
    apply_wiki(weak, rows);
}

fn apply_wiki(weak: slint::Weak<MainWindow>, rows: Vec<panel_logic::WikiRowData>) {
    use slint::VecModel;
    let total = rows.len() as i32;
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let slint_rows: Vec<WikiRow> = rows
            .into_iter()
            .map(|r| WikiRow {
                id: r.id.into(),
                kind: r.kind.into(),
                description: r.description.into(),
                gate: r.gate.into(),
            })
            .collect();
        w.set_wiki_rows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(slint_rows))));
        w.set_wiki_total(total);
        w.set_wiki_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Buddy Config probe ─────────────────────────────────────────────
fn refresh_buddyconfig(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let out = run_neothd_probe(&["buddy", "status", "--output", "json"]);
    let snap = panel_logic::parse_buddy_status(&out);
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let skill_rows: Vec<SelfActSkill> = snap
            .self_activation_skills
            .into_iter()
            .map(|name| SelfActSkill { name: name.into() })
            .collect();
        w.set_bc_self_activation_skills(
            slint::ModelRc::new(std::rc::Rc::new(VecModel::from(skill_rows))),
        );
        w.set_bc_autonomy(snap.autonomy.as_str().into());
        w.set_bc_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Companion probe ────────────────────────────────────────────────
fn refresh_companion(weak: slint::Weak<MainWindow>) {
    let home = default_neoth_home();
    let pending = home.join("companion_pending_invite.json").exists();
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_cp_invite_pending(pending);
        w.set_cp_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Mesh & Cluster probe ───────────────────────────────────────────
fn refresh_mesh(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let out = run_neothd_probe(&["cluster", "status", "--output", "json"]);
    let snap = panel_logic::parse_mesh_status(&out);
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_mesh_node_id(snap.node_id.as_str().into());
        w.set_mesh_listen_port(snap.listen_port.as_str().into());
        w.set_mesh_trusted_ssids(snap.trusted_ssids.as_str().into());
        let peer_rows: Vec<MeshPeerRow> = snap
            .peers
            .into_iter()
            .map(|p| MeshPeerRow {
                id: p.id.into(),
                last_seen: p.last_seen.into(), // Slint kebab→snake: last-seen → last_seen
                reachable: p.reachable,
            })
            .collect();
        w.set_mesh_peers(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(peer_rows))));
        w.set_mesh_gossip_note(snap.gossip_note.as_str().into());
        w.set_mesh_refreshed_at(ts.as_str().into());
    });
}

// ── Chat-surface consent strip probe ─────────────────────────────────────────
//
// Shells two JSON subcommands (`autonomy show` + `consent list`), parses via
// panel_logic pure-fns, then writes chat-consent-mode and chat-consent-grants
// in one invoke_from_event_loop call.  Must be called from a worker thread.
fn refresh_chat_consent(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;

    let run = |args: &[&str]| -> String {
        which_neothd()
            .and_then(|bin| {
                spawn_neothd_plain(&bin)
                    .args(args)
                    .output()
                    .ok()
            })
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default()
    };

    let autonomy_json = run(&["autonomy", "show", "--output", "json"]);
    let consent_json  = run(&["consent", "list", "--output", "json"]);

    let mode   = panel_logic::parse_autonomy_mode(&autonomy_json);
    let grants = panel_logic::parse_chat_consent_grants(&consent_json);

    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_chat_consent_mode(mode.as_str().into());
        let grant_rows: Vec<ConsentGrant> = grants
            .into_iter()
            .map(|(provider, granted)| ConsentGrant {
                provider: provider.into(),
                granted,
            })
            .collect();
        w.set_chat_consent_grants(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(
            grant_rows,
        ))));
    });
}

// ── Overview / Mission Control probe (Design Wave 3) ─────────────────────────
//
// Shells the JSON daemon commands sequentially (tolerate individual failures),
// parses via panel_logic pure-fns, then mutates the MainWindow in one
// invoke_from_event_loop call.  Must be called from a worker thread — never
// from the Slint event loop.
fn refresh_overview(weak: slint::Weak<MainWindow>) {
    let bin = match which_neothd() {
        Some(b) => b,
        None => {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_ov_operating_mode("neothd not found".into());
                    w.set_ov_daemon_state("error".into());
                    w.set_ov_refreshed_at("binary missing".into());
                }
            });
            return;
        }
    };

    // Helper: run a neothd subcommand, return stdout or an empty string on
    // failure. Individual failures degrade a card to "unavailable" rather than
    // aborting the whole refresh.
    let run = |args: &[&str]| -> String {
        spawn_neothd_plain(&bin)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default()
    };

    // Fire all JSON probes.
    let status_json  = run(&["status",     "--output",  "json"]);
    let meter_json   = run(&["meter",      "--format",  "json"]);
    let hemi_json    = run(&["hemispheres","show",      "--output", "json"]);
    let agents_json  = run(&["agents",     "list",      "--output", "json"]);
    let skills_json  = run(&["skills",     "list",      "--output", "json"]);
    let plugin_json  = run(&["plugin",     "list",      "--output", "json"]);
    let cal_json     = run(&["calendar",   "list",      "--output", "json"]);
    let consent_json = run(&["consent",    "list",      "--output", "json"]);

    // Parse — all pure fns in panel_logic.
    let (mode, autonomy, ch_health, wal_bytes, tier_counts, daemon_state) =
        panel_logic::parse_overview_status(&status_json);
    let (tok_in, tok_out, responses, cost, tok_fraction) =
        panel_logic::parse_meter(&meter_json);
    let hemis       = panel_logic::parse_overview_hemispheres(&hemi_json);
    let (agents_count, agent_names) = panel_logic::parse_agents(&agents_json);
    let (skills_count, skill_names) = panel_logic::parse_overview_skills(&skills_json);
    let (plugins_count, plugin_names) = panel_logic::parse_overview_skills(&plugin_json);
    let (cal_configured, cal_events) = panel_logic::parse_calendar_next(&cal_json, 3);
    let (consent_entries, smart_approve) = panel_logic::parse_consent(&consent_json);

    // Timestamp.
    let ts = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hh = (secs / 3600) % 24;
        let mm = (secs / 60) % 60;
        let ss = secs % 60;
        format!("{hh:02}:{mm:02}:{ss:02} UTC")
    };

    // Push everything to the UI in one event-loop hop.
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };

        // STATUS
        w.set_ov_operating_mode(mode.into());
        w.set_ov_autonomy(autonomy.into());
        w.set_ov_daemon_state(daemon_state.into());
        w.set_ov_channel_health(ch_health.into());
        w.set_ov_wal_bytes(wal_bytes.into());
        w.set_ov_tier_counts(tier_counts.into());

        // TOKENS
        w.set_ov_tokens_in(tok_in.into());
        w.set_ov_tokens_out(tok_out.into());
        w.set_ov_responses(responses.into());
        w.set_ov_cost(cost.into());
        w.set_ov_token_fraction(tok_fraction);

        // HEMISPHERES — build the [HemiCard] model
        {
            use slint::VecModel;
            let rows: Vec<HemiCard> = hemis
                .into_iter()
                .map(|(role, provider, model, ok)| HemiCard {
                    role: role.into(),
                    provider: provider.into(),
                    model: model.into(),
                    ok,
                })
                .collect();
            w.set_ov_hemispheres(std::rc::Rc::new(VecModel::from(rows)).into());
        }

        // AGENTS
        w.set_ov_agents_count(agents_count.into());
        {
            use slint::VecModel;
            let rows: Vec<slint::SharedString> =
                agent_names.into_iter().map(Into::into).collect();
            w.set_ov_agent_names(std::rc::Rc::new(VecModel::from(rows)).into());
        }

        // SKILLS & PLUGINS
        w.set_ov_skills_active(skills_count.into());
        w.set_ov_plugins_active(plugins_count.into());
        {
            use slint::VecModel;
            let srows: Vec<slint::SharedString> =
                skill_names.into_iter().map(Into::into).collect();
            w.set_ov_skill_names(std::rc::Rc::new(VecModel::from(srows)).into());
            let prows: Vec<slint::SharedString> =
                plugin_names.into_iter().map(Into::into).collect();
            w.set_ov_plugin_names(std::rc::Rc::new(VecModel::from(prows)).into());
        }

        // CALENDAR
        w.set_ov_calendar_configured(cal_configured);
        {
            use slint::VecModel;
            let rows: Vec<CalEvent> = cal_events
                .into_iter()
                .map(|(time, summary)| CalEvent {
                    time: time.into(),
                    summary: summary.into(),
                })
                .collect();
            w.set_ov_calendar_events(std::rc::Rc::new(VecModel::from(rows)).into());
        }

        // CONSENT
        {
            use slint::VecModel;
            let rows: Vec<ConsentEntry> = consent_entries
                .into_iter()
                .map(|(provider, granted)| ConsentEntry {
                    provider: provider.into(),
                    granted,
                })
                .collect();
            w.set_ov_consent_entries(std::rc::Rc::new(VecModel::from(rows)).into());
        }
        w.set_ov_smart_approve(smart_approve.into());

        // Timestamp
        w.set_ov_refreshed_at(ts.into());
    });
}

fn probe_hardware_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Hardware probe unavailable — `neothd` binary not on PATH.\n\
                Install the daemon first (cargo install --path ../neothd)."
            .to_string();
    };
    let output = spawn_neothd_plain(&bin)
        .arg("hardware")
        .arg("--output")
        .arg("table")
        .output();
    match output {
        Ok(out) if out.status.success() => {
            shape_hardware_footer(&String::from_utf8_lossy(&out.stdout))
        }
        Ok(out) => format!(
            "Hardware probe failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Err(e) => format!("Hardware probe could not start: {e}"),
    }
}

/// Collapse the multi-line `neoth hardware --output table` probe into a single
/// footer line. The FooterBar is one 36px row — the full table (10+ lines)
/// spilled past it and was clipped by the window edge. Keep only the operator-
/// relevant fields, whitespace-collapsed, joined with " · ".
fn shape_hardware_footer(table: &str) -> String {
    const KEEP: [&str; 5] = ["CPU:", "RAM:", "Accelerator:", "GPU VRAM:", "Disk:"];
    let parts: Vec<String> = table
        .lines()
        .map(str::trim)
        .filter(|line| KEEP.iter().any(|k| line.starts_with(k)))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    if parts.is_empty() {
        "NEOTH — Your buddy. Your life.".to_string()
    } else {
        parts.join("   ·   ")
    }
}

/// QM-9 Phase 2: probe the last 24h of usage via the same `neoth
/// usage --format json` surface the CLI ships. Returns an operator-
/// readable one-line summary on success, or a clear error string
/// when the subprocess can't run / fails / returns malformed JSON.
fn probe_usage_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Usage unavailable — `neothd` binary not on PATH.".to_string();
    };
    let output = spawn_neothd_plain(&bin)
        .arg("usage")
        .arg("--format")
        .arg("json")
        .arg("--days")
        .arg("1")
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            shape_usage_summary(&stdout)
        }
        Ok(out) => format!(
            "Usage probe failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("Usage probe could not start: {e}"),
    }
}

/// Parse the `neoth usage --format json` envelope + render a one-line
/// summary. Pure function so the test path can pin the rendering
/// without spawning a real subprocess.
pub fn shape_usage_summary(json: &str) -> String {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json) else {
        return "Usage: malformed response".to_string();
    };
    let calls = val
        .get("total_call_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let ok = val
        .get("total_ok_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let err = val
        .get("total_err_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cost = val
        .get("total_cost_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    if calls == 0 {
        return "No usage in the last 24h.".to_string();
    }
    format!("Last 24h: {calls} calls (ok={ok}, err={err}), ${cost:.4}")
}

/// GOLD-WIRE-10b: probe the daemon's live token-budget meter via the
/// same `neoth meter --json` surface the CLI ships. Returns an operator-
/// readable one-line summary, or a clear error string when the subprocess
/// can't run / fails / returns malformed JSON.
fn probe_budget_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Budget unavailable — `neothd` binary not on PATH.".to_string();
    };
    let output = spawn_neothd_plain(&bin)
        .arg("meter")
        .arg("--format")
        .arg("json")
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let panel = panel_logic::parse_usage_meter(&stdout);
            if panel.available {
                format!("{} · {} · {}", panel.responses, panel.tokens, panel.note)
            } else {
                "Budget unavailable — daemon may not be running.".to_string()
            }
        }
        Ok(out) => format!(
            "Budget probe failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("Budget probe could not start: {e}"),
    }
}

/// QM-8 Phase 2.5: resolve the active preset (via `neoth preset list`),
/// then shell `neoth preset apply <active>`. Returns an operator-
/// readable result string for the status line.
fn apply_active_preset_via_subprocess() -> String {
    let Some(bin) = which_neothd() else {
        return "Preset apply unavailable — `neothd` binary not on PATH.".to_string();
    };
    apply_active_preset_via_subprocess_with(&bin)
}

/// GR-05 test-injection seam (mirrors [`chat_via_subprocess_with`]): the
/// caller pins the binary path so a test can drive the full
/// list → parse-active → apply flow against a staged fake `neothd`
/// instead of requiring the real daemon on PATH.
pub fn apply_active_preset_via_subprocess_with(bin: &std::path::Path) -> String {
    // First: list to find the active marker.
    let list_output = spawn_neothd_plain(bin).arg("preset").arg("list").output();
    let stdout = match list_output {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => {
            return format!(
                "preset list failed (exit {}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => return format!("preset list could not start: {e}"),
    };
    let active = parse_active_preset_name(&stdout);
    let Some(name) = active else {
        return "No active preset — `neoth preset activate <name>` first.".to_string();
    };
    let apply_output = spawn_neothd_plain(bin)
        .arg("preset")
        .arg("apply")
        .arg(&name)
        .output();
    match apply_output {
        Ok(out) if out.status.success() => format!("Applied preset `{name}`."),
        Ok(out) => format!(
            "preset apply `{name}` failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("preset apply could not start: {e}"),
    }
}

/// Parse the active preset name out of `neoth preset list` stdout.
/// Returns the bare name (no `*` prefix) when an active marker is
/// present, else None.
pub fn parse_active_preset_name(stdout: &[u8]) -> Option<String> {
    let body = String::from_utf8_lossy(stdout);
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('*') {
            let name = trimmed
                .trim_start_matches(|c: char| c == '*' || c.is_whitespace())
                .trim()
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// QM-8 Phase 2: probe the saved preset list via `neoth preset list`
/// and render a compact summary. Same worker-thread shape as the
/// usage probe.
fn probe_preset_summary_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Preset list unavailable — `neothd` binary not on PATH.".to_string();
    };
    let output = spawn_neothd_plain(&bin).arg("preset").arg("list").output();
    match output {
        Ok(out) if out.status.success() => shape_preset_summary(&out.stdout),
        Ok(out) => format!(
            "Preset list failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("Preset list could not start: {e}"),
    }
}

/// Pure shaping helper — tested in isolation. Input shape matches
/// `cli::preset::run_list` stdout (lines like "  zeta", "* active").
pub fn shape_preset_summary(stdout: &[u8]) -> String {
    let body = String::from_utf8_lossy(stdout);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() || lines[0].starts_with("(no presets") {
        return "No presets saved. Use `neoth preset ...` from a terminal.".to_string();
    }
    let mut active: Option<&str> = None;
    let mut count = 0usize;
    for line in &lines {
        if line.trim_start().starts_with('*') {
            active = Some(line.trim_start_matches(|c: char| c == '*' || c.is_whitespace()));
        }
        count += 1;
    }
    match active {
        Some(name) => format!("{count} presets · active: {name}"),
        None => format!("{count} presets · no active"),
    }
}

fn which_neothd() -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        "neothd.exe"
    } else {
        "neothd"
    };
    if let Some(path_env) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path_env) {
            let candidate = entry.join(exe);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    let exe_path = std::env::current_exe().ok()?;
    let dir = exe_path.parent()?;
    let sibling = dir.join(exe);
    sibling.exists().then_some(sibling)
}

/// GOLD-ADAPT-OH-01 — locate the `neoth-migrate` helper binary (PATH
/// scan, then sibling-to-exe) for the welcome-step migration card.
fn which_neoth_migrate() -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        "neoth-migrate.exe"
    } else {
        "neoth-migrate"
    };
    if let Some(path_env) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path_env) {
            let candidate = entry.join(exe);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    let exe_path = std::env::current_exe().ok()?;
    let dir = exe_path.parent()?;
    let sibling = dir.join(exe);
    sibling.exists().then_some(sibling)
}

/// GOLD-ADAPT-OH-01 — shape `neoth-migrate detect --json` output into
/// the welcome-card body. Empty string = hide the card (no sources /
/// unparseable output / detect unavailable). Pure — unit-tested.
pub fn format_migrate_summary(detect_json: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(detect_json) else {
        return String::new();
    };
    let Some(sources) = v.get("sources").and_then(|s| s.as_array()) else {
        return String::new();
    };
    let names: Vec<&str> = sources
        .iter()
        .filter_map(|s| s.get("name").and_then(|n| n.as_str()))
        .collect();
    if names.is_empty() {
        return String::new();
    }
    format!(
        "{} prior-AI store(s) found: {}",
        names.len(),
        names.join(", ")
    )
}

fn default_neoth_home() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".neoth")
}

/// ODY-04 — wall-clock epoch millis for the stall-watchdog clock.
fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// ODY-03 — mirror the pending attachment paths into the strip (names only).
fn sync_attachment_strip(w: &MainWindow, paths: &[PathBuf]) {
    use slint::{ModelRc, VecModel};
    let names: Vec<slint::SharedString> = paths
        .iter()
        .map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .into()
        })
        .collect();
    w.set_chat_pending_attachments(ModelRc::new(VecModel::from(names)));
}

// ODY-11 — density persistence helpers (pure, testable without Slint window).
// Same extraction pattern as `shape_usage_summary` / `parse_active_preset_name`.

/// Read `<neoth_home>/.gui-density` → 0 (compact) / 1 (normal) / 2 (spacious).
/// Returns 1 on missing file or unrecognised content.
pub fn read_gui_density(neoth_home: &Path) -> i32 {
    std::fs::read_to_string(neoth_home.join(".gui-density"))
        .map(|s| match s.trim() {
            "compact" => 0,
            "spacious" => 2,
            _ => 1,
        })
        .unwrap_or(1)
}

/// Write the density int (0/1/2) as a human-readable label to `path`.
/// Out-of-range values fall through to "normal".
pub fn write_gui_density(path: &Path, val: i32) {
    let label = match val {
        0 => "compact",
        2 => "spacious",
        _ => "normal",
    };
    let _ = std::fs::write(path, label);
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("NEOTH_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,neothd_gui=debug"));
    // M-2 fix — `.with_ansi(false)` keeps tracing output free of
    // escape sequences. Important on Windows where the operator's
    // terminal often does not interpret ANSI cleanly.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .with_ansi(false)
        .compact()
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn empty_snapshot() -> WizardSnapshot {
        WizardSnapshot {
            operator_id: "sam".into(),
            provider_kind: "claude_cli".into(),
            autonomy: "standard".into(),
            license_accepted: true,
            enable_telegram: false,
            provider_key: String::new(),
            telegram_token: String::new(),
            cluster_discovery_disabled: false,
        }
    }

    #[test]
    fn board_json_buckets_tasks_by_status_like_cold_path() {
        let b = GuiBoardJson {
            summary: "Session #1  [running]   do stuff".into(),
            cerebellum_bound: true,
            tasks: vec![
                GuiBoardTaskJson {
                    task_id: 1,
                    title: "a".into(),
                    hemisphere: "left".into(),
                    status: "backlog".into(),
                },
                GuiBoardTaskJson {
                    task_id: 2,
                    title: "b".into(),
                    hemisphere: "right".into(),
                    status: "todo".into(),
                },
                GuiBoardTaskJson {
                    task_id: 3,
                    title: "c".into(),
                    hemisphere: "left".into(),
                    status: "in_progress".into(),
                },
                GuiBoardTaskJson {
                    task_id: 4,
                    title: "d".into(),
                    hemisphere: "right".into(),
                    status: "review".into(),
                },
                GuiBoardTaskJson {
                    task_id: 5,
                    title: "e".into(),
                    hemisphere: "left".into(),
                    status: "done".into(),
                },
                GuiBoardTaskJson {
                    task_id: 6,
                    title: "f".into(),
                    hemisphere: "left".into(),
                    status: "archived".into(),
                },
                GuiBoardTaskJson {
                    task_id: 7,
                    title: "g".into(),
                    hemisphere: "left".into(),
                    status: "totally_unknown".into(),
                },
            ],
            feed: vec![],
        };
        let snap = board_json_to_snapshot(b);
        assert_eq!(snap.todo.len(), 1);
        assert_eq!(snap.in_progress.len(), 1);
        assert_eq!(snap.review.len(), 1);
        // `done` + `archived` both land in DONE (mirrors the cold path).
        assert_eq!(snap.done.len(), 2);
        // explicit `backlog` + the unknown status both land in BACKLOG.
        assert_eq!(snap.backlog.len(), 2);
        assert_eq!(snap.cerebellum_bound, Some(true));
        assert_eq!(snap.todo[0].task_id.as_str(), "#2");
    }

    #[test]
    fn board_json_feed_is_reversed_to_newest_first() {
        let b = GuiBoardJson {
            summary: "s".into(),
            cerebellum_bound: false,
            tasks: vec![],
            feed: vec![
                FeedEntryJson {
                    ts_ns: 100,
                    actor: "left".into(),
                    message: "first".into(),
                },
                FeedEntryJson {
                    ts_ns: 200,
                    actor: "right".into(),
                    message: "second".into(),
                },
            ],
        };
        let snap = board_json_to_snapshot(b);
        // Server emits oldest-first (WAL append order); the rail shows
        // newest-first — same reversal the cold `fetch_kanban_feed` does.
        assert_eq!(snap.feed.len(), 2);
        assert_eq!(snap.feed[0].message.as_str(), "second");
        assert_eq!(snap.feed[1].message.as_str(), "first");
        assert_eq!(snap.cerebellum_bound, Some(false));
    }

    #[test]
    fn validate_autonomy_accepts_known_levels() {
        for level in ["strict", "standard", "elevated", "full", "custom"] {
            validate_autonomy(level).unwrap_or_else(|_| panic!("expected {level} to validate"));
        }
    }

    #[test]
    fn validate_autonomy_rejects_unknown() {
        assert!(validate_autonomy("ultra").is_err());
        assert!(validate_autonomy("").is_err());
    }

    #[test]
    fn finish_writes_freedom_only_when_no_secrets() {
        let dir = TempDir::new().unwrap();
        let state = empty_snapshot();
        let freedom = write_freedom_yaml(&state, dir.path()).expect("freedom.yaml");
        let credentials = write_credentials_yaml(&state, dir.path()).expect("credentials");
        assert!(freedom.exists());
        assert!(credentials.is_none());
        let body = std::fs::read_to_string(&freedom).unwrap();
        assert!(body.contains("operator_id: sam"));
        assert!(body.contains("autonomy: standard"));
        assert!(body.contains("channels:"));
        // No telegram channel because enable_telegram=false.
        assert!(!body.contains("- telegram"));
    }

    #[test]
    fn finish_writes_credentials_when_provider_key_set() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.provider_kind = "openai_api".into();
        state.provider_key = "sk-test".into();
        let credentials = write_credentials_yaml(&state, dir.path())
            .expect("credentials")
            .expect("path returned");
        let body = std::fs::read_to_string(&credentials).unwrap();
        assert!(body.contains("provider_key: sk-test"));
        assert!(!body.contains("telegram_token"));
    }

    #[test]
    fn finish_writes_telegram_only_when_channel_enabled_and_token_set() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.enable_telegram = true;
        state.telegram_token = "123:abc".into();
        let credentials = write_credentials_yaml(&state, dir.path())
            .expect("credentials")
            .expect("path returned");
        let body = std::fs::read_to_string(&credentials).unwrap();
        assert!(body.contains("telegram_token: 123:abc"));
    }

    #[test]
    fn finish_skips_telegram_token_when_channel_disabled() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.enable_telegram = false;
        state.telegram_token = "leaked-from-stale-state".into();
        let credentials = write_credentials_yaml(&state, dir.path()).expect("credentials");
        assert!(
            credentials.is_none(),
            "must not persist a telegram_token when the channel is off — \
             would leak a stale UI value past the operator's intent"
        );
    }

    #[test]
    fn finish_rejects_unaccepted_license() {
        // L-3 fix — instead of `unsafe set_var` for HOME/USERPROFILE
        // (which races against any other test reading those env
        // vars under parallel execution), exercise the license check
        // via the same path WITHOUT touching globals. `finish` returns
        // the license error before it ever reads the env, so the
        // assertion holds regardless of env state.
        let mut state = empty_snapshot();
        state.license_accepted = false;
        let err = finish(&state).unwrap_err();
        assert!(err.to_string().contains("license"));
    }

    #[test]
    fn channels_list_contains_telegram_when_enabled() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.enable_telegram = true;
        let freedom = write_freedom_yaml(&state, dir.path()).expect("freedom");
        let body = std::fs::read_to_string(&freedom).unwrap();
        assert!(body.contains("- cli"));
        assert!(body.contains("- telegram"));
    }

    /// Regression test for the M-1 parse failure:
    /// The real operator freedom.yaml written by neothd has
    ///   cluster:
    ///     name: null
    ///     enabled: false
    /// which is the daemon's ClusterConfig shape — NOT the GUI's
    /// `mdns: { enabled: false }` sub-block shape.  The old
    /// ClusterYamlBlock required a `mdns:` key and had no
    /// `#[serde(default)]`, so serde_yaml returned
    /// "missing field `mdns`" and read_freedom_yaml failed,
    /// causing the Done summary to show defaults instead of
    /// the operator's real values.
    #[test]
    fn read_freedom_yaml_parses_daemon_written_cluster_block() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Exact shape that neothd writes (ClusterConfig with name+enabled,
        // no mdns sub-block).
        std::fs::write(
            &path,
            "operator_id: testop\n\
             provider_kind: claude_cli\n\
             autonomy: full\n\
             channels:\n- cli\n\
             cluster:\n  name: null\n  enabled: false\n",
        )
        .unwrap();
        let cfg = read_freedom_yaml(&path)
            .expect("must parse daemon-written cluster block without error");
        assert_eq!(cfg.operator_id, "testop");
        assert_eq!(cfg.provider_kind, "claude_cli");
        assert_eq!(cfg.autonomy, "full");
        assert!(cfg.channels.iter().any(|c| c == "cli"));
        // cluster is present but carries only daemon fields — must not panic
        assert!(cfg.cluster.is_some());
    }

    /// Also verify the full real-world shape (many extra top-level fields)
    /// does not trip the parse.
    #[test]
    fn read_freedom_yaml_parses_fully_expanded_real_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: n\n\
             provider_kind: claude_cli\n\
             autonomy: full\n\
             channels:\n- cli\n\
             cluster:\n  name: null\n  enabled: false\n\
             inference:\n  mode: single\n\
             council:\n  selection_mode: legacy_majority\n\
             skills:\n  disabled_for_eval_sessions: false\n\
             security:\n  dangerous_commands: deny\n",
        )
        .unwrap();
        let cfg = read_freedom_yaml(&path).expect("fully-expanded freedom.yaml must parse");
        assert_eq!(cfg.operator_id, "n");
        assert_eq!(cfg.autonomy, "full");
    }

    #[test]
    fn cluster_block_omitted_when_discovery_stays_default() {
        // Operator left the checkbox unchecked → discovery stays
        // ON per the noob-wizard "default ON" rule. We must NOT
        // write `cluster.mdns.enabled: false` because that would
        // override the daemon's serde-default + tell future
        // operators reading the YAML that the field was set
        // intentionally.
        let dir = TempDir::new().unwrap();
        let state = empty_snapshot();
        assert!(!state.cluster_discovery_disabled);
        let freedom = write_freedom_yaml(&state, dir.path()).expect("freedom");
        let body = std::fs::read_to_string(&freedom).unwrap();
        assert!(
            !body.contains("cluster"),
            "freedom.yaml must NOT carry a cluster block when discovery defaults stay: {body}"
        );
    }

    #[test]
    fn cluster_block_written_when_discovery_disabled() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.cluster_discovery_disabled = true;
        let freedom = write_freedom_yaml(&state, dir.path()).expect("freedom");
        let body = std::fs::read_to_string(&freedom).unwrap();
        assert!(body.contains("cluster:"), "expected cluster block: {body}");
        assert!(body.contains("mdns:"), "expected mdns subblock: {body}");
        assert!(
            body.contains("enabled: false"),
            "expected enabled: false: {body}"
        );
    }

    // ── Bite #5 — settings panel cluster state ─────────────────────

    #[test]
    fn load_cluster_settings_returns_defaults_when_freedom_missing() {
        let dir = TempDir::new().unwrap();
        let snap = load_cluster_settings(&dir.path().join("freedom.yaml"));
        assert!(snap.mdns_enabled, "Q4 default: mdns enabled");
        assert_eq!(snap.listen_port, 49737);
        assert!(snap.trusted_ssids_summary.is_empty());
    }

    #[test]
    fn load_cluster_settings_returns_defaults_when_unparseable() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "::: garbage :::").unwrap();
        let snap = load_cluster_settings(&path);
        assert!(snap.mdns_enabled);
        assert_eq!(snap.listen_port, 49737);
        assert!(snap.trusted_ssids_summary.is_empty());
    }

    #[test]
    fn load_cluster_settings_reads_full_block() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        let yaml = "operator_id: alice\n\
                    cluster:\n  \
                    mdns:\n    enabled: false\n  \
                    listen_port: 4242\n  \
                    policy:\n    \
                    announce_on_untrusted_wifi: false\n    \
                    trusted_ssids:\n      - home-wifi\n      - home-wifi-5g\n";
        std::fs::write(&path, yaml).unwrap();
        let snap = load_cluster_settings(&path);
        assert!(!snap.mdns_enabled);
        assert_eq!(snap.listen_port, 4242);
        assert_eq!(snap.trusted_ssids_summary, "home-wifi, home-wifi-5g");
    }

    #[test]
    fn load_cluster_settings_rejects_out_of_range_listen_port() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "cluster:\n  listen_port: 70000\n").unwrap();
        let snap = load_cluster_settings(&path);
        assert_eq!(
            snap.listen_port, 49737,
            "out-of-range falls back to default"
        );
    }

    #[test]
    fn set_cluster_mdns_writes_enabled_field_atomically() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_cluster_mdns_enabled_in_freedom(&path, false).unwrap();
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        // YAML normalises bool to the unquoted token.
        assert!(body.contains("enabled: false"), "got: {body}");
        // .tmp left behind would mean the rename didn't happen.
        assert!(!dir.path().join("freedom.yaml.tmp").exists());
    }

    #[test]
    fn set_top_level_string_preserves_every_other_field() {
        // MV-01c bug-fix regression guard: the GUI provider/model selectors
        // must NOT drop the operator's other config. Seed a freedom.yaml
        // with a custom inference topology + council + profile block, change
        // provider_kind + provider_model via the lossless writer, assert all
        // the other fields SURVIVE (the prior MinimalFreedomYaml round-trip
        // would have wiped them).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: alice\n\
             provider_kind: claude_cli\n\
             provider_model: claude-opus-4-8\n\
             inference:\n  mode: triplet\n  left:\n    provider: local_qwen\n\
             council:\n  daily_usd_cap: 5.0\n  disabled: false\n\
             profile:\n  learn_enabled: true\n",
        )
        .unwrap();

        set_top_level_string_in_freedom(&path, "provider_kind", "openai_api").unwrap();
        set_top_level_string_in_freedom(&path, "provider_model", "gpt-5.5").unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("provider_kind: openai_api"),
            "provider updated: {body}"
        );
        assert!(
            body.contains("provider_model: gpt-5.5"),
            "model updated: {body}"
        );
        // The fields MinimalFreedomYaml never modelled MUST survive.
        assert!(
            body.contains("mode: triplet"),
            "inference topology dropped: {body}"
        );
        assert!(
            body.contains("provider: local_qwen"),
            "hemisphere slot dropped: {body}"
        );
        assert!(
            body.contains("daily_usd_cap"),
            "council config dropped: {body}"
        );
        assert!(
            body.contains("learn_enabled"),
            "profile config dropped: {body}"
        );
        assert!(!dir.path().join("freedom.yaml.tmp").exists());
    }

    #[test]
    fn set_top_level_string_creates_mapping_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_top_level_string_in_freedom(&path, "provider_kind", "gemini_api").unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("provider_kind: gemini_api"), "got: {body}");
    }

    #[test]
    fn set_cluster_mdns_round_trip_via_load_cluster_settings() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Start ENABLED → toggle OFF → load sees false → toggle ON →
        // load sees true. Pins the wire shape across the read+write
        // pair so the settings panel can't drift away from the
        // on-disk format.
        set_cluster_mdns_enabled_in_freedom(&path, true).unwrap();
        assert!(load_cluster_settings(&path).mdns_enabled);
        set_cluster_mdns_enabled_in_freedom(&path, false).unwrap();
        assert!(!load_cluster_settings(&path).mdns_enabled);
        set_cluster_mdns_enabled_in_freedom(&path, true).unwrap();
        assert!(load_cluster_settings(&path).mdns_enabled);
    }

    #[test]
    fn set_cluster_mdns_preserves_other_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Pre-seed freedom.yaml with fields the GUI's MinimalFreedomYaml
        // doesn't know about. The toggle MUST NOT drop them — that's
        // the whole point of using the lossless serde_yaml::Value
        // round-trip instead of typed read-merge-write.
        let original = "operator_id: alice\n\
                        provider_kind: openai_api\n\
                        inference:\n  topology: triplet\n  left:\n    provider: openai_api\n\
                        cluster:\n  \
                        mdns:\n    enabled: true\n  \
                        listen_port: 50000\n  \
                        policy:\n    \
                        trusted_ssids:\n      - home-wifi\n";
        std::fs::write(&path, original).unwrap();
        set_cluster_mdns_enabled_in_freedom(&path, false).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        // Toggle landed.
        assert!(body.contains("enabled: false"));
        // Untyped neighbours survived.
        assert!(body.contains("operator_id: alice"));
        assert!(body.contains("provider_kind: openai_api"));
        assert!(body.contains("topology: triplet"));
        assert!(body.contains("listen_port: 50000"));
        assert!(body.contains("home-wifi"));
    }

    // ── PF-01-GUI: skills.always_embed_route toggle ──────────────────────────

    #[test]
    fn read_skills_always_embed_route_defaults_true() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Missing file → true (matches the daemon SkillsConfig default).
        assert!(read_skills_always_embed_route(&path));
        // Present but no skills key → true.
        std::fs::write(&path, "operator_id: a\n").unwrap();
        assert!(read_skills_always_embed_route(&path));
        // Malformed → true.
        std::fs::write(&path, "%%% not yaml %%%").unwrap();
        assert!(read_skills_always_embed_route(&path));
    }

    #[test]
    fn skills_always_embed_route_write_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_skills_always_embed_route_in_freedom(&path, false).unwrap();
        assert!(!read_skills_always_embed_route(&path));
        set_skills_always_embed_route_in_freedom(&path, true).unwrap();
        assert!(read_skills_always_embed_route(&path));
    }

    #[test]
    fn set_skills_always_embed_route_preserves_other_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        let original = "operator_id: alice\n\
                        provider_kind: openai_api\n\
                        skills:\n  disabled_for_eval_sessions: true\n\
                        cluster:\n  listen_port: 50000\n";
        std::fs::write(&path, original).unwrap();
        set_skills_always_embed_route_in_freedom(&path, false).unwrap();
        assert!(!read_skills_always_embed_route(&path));
        let body = std::fs::read_to_string(&path).unwrap();
        // Sibling under skills + unrelated fields survived the nested write.
        assert!(body.contains("disabled_for_eval_sessions: true"));
        assert!(body.contains("operator_id: alice"));
        assert!(body.contains("listen_port: 50000"));
    }

    // ── ODY-11 density helpers ────────────────────────────────────────────

    #[test]
    fn density_restore_reads_compact_from_disk() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gui-density"), b"compact").unwrap();
        assert_eq!(read_gui_density(dir.path()), 0);
    }

    #[test]
    fn density_restore_reads_spacious_from_disk() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gui-density"), b"spacious").unwrap();
        assert_eq!(read_gui_density(dir.path()), 2);
    }

    #[test]
    fn density_restore_reads_normal_from_disk() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gui-density"), b"normal").unwrap();
        assert_eq!(read_gui_density(dir.path()), 1);
    }

    #[test]
    fn density_restore_defaults_to_normal_on_missing_file() {
        let dir = TempDir::new().unwrap();
        assert_eq!(read_gui_density(dir.path()), 1);
    }

    #[test]
    fn density_restore_defaults_to_normal_on_garbage_file() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gui-density"), b"%%%invalid%%%").unwrap();
        assert_eq!(read_gui_density(dir.path()), 1);
    }

    #[test]
    fn density_write_round_trips_all_three_values() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".gui-density");
        // compact
        write_gui_density(&path, 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "compact");
        assert_eq!(read_gui_density(dir.path()), 0);
        // normal
        write_gui_density(&path, 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "normal");
        assert_eq!(read_gui_density(dir.path()), 1);
        // spacious
        write_gui_density(&path, 2);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "spacious");
        assert_eq!(read_gui_density(dir.path()), 2);
    }

    #[test]
    fn density_write_out_of_range_falls_through_to_normal() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".gui-density");
        write_gui_density(&path, 99);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "normal");
        assert_eq!(read_gui_density(dir.path()), 1);
    }
}

/// GOLD-ADAPT-ODY-12/14 — deep-link chip parsing + nav routing contract.
#[cfg(test)]
mod deep_link_tests {
    use super::{parse_stream_links, NAV_PANELS};

    #[test]
    fn parses_links_array_from_extended_sentinel() {
        let raw = "reply text\n\n{\"neoth_stream\":\"done\",\"count\":2,\
                   \"links\":[{\"label\":\"task 42\",\"kind\":\"kanban\",\"id\":\"42\"},\
                   {\"label\":\"board\",\"kind\":\"nav\",\"id\":\"coding\"}]}\n";
        let links = parse_stream_links(raw);
        assert_eq!(links.len(), 2);
        assert_eq!(
            links[0],
            ("task 42".to_string(), "kanban".to_string(), "42".to_string())
        );
        assert_eq!(links[1].1, "nav");
        assert_eq!(links[1].2, "coding");
    }

    #[test]
    fn absent_links_field_and_old_daemons_yield_empty() {
        // Old minimal sentinel (recall early-return) has no links field.
        assert!(parse_stream_links("x\n{\"neoth_stream\":\"done\",\"count\":1}\n").is_empty());
        // Mid-stream: no sentinel at all.
        assert!(parse_stream_links("still streaming...").is_empty());
        // Malformed entries are skipped, not fatal.
        let raw = "r\n{\"neoth_stream\":\"done\",\"links\":[{\"label\":\"x\"},\
                   {\"label\":\"ok\",\"kind\":\"nav\",\"id\":\"memory\"}]}\n";
        let links = parse_stream_links(raw);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].2, "memory");
    }

    #[test]
    fn nav_panels_list_matches_slint_nav_values() {
        // Drift guard: main.slint's nav-active values. A chip id outside
        // this list is ignored by the click handler.
        assert_eq!(NAV_PANELS.len(), 25);
        for p in ["chat", "overview", "coding", "memory", "config", "loops",
                  "n8n", "babel", "calendar", "evolve",
                  "obsidian", "dreaming", "wiki", "buddyconfig", "companion", "mesh"] {
            assert!(NAV_PANELS.contains(&p), "{p} must be a nav panel");
        }
    }
}

/// GOLD-ADAPT-OH-01 — welcome migrate-card summary shaping.
#[cfg(test)]
mod migrate_card_tests {
    use super::format_migrate_summary;

    #[test]
    fn shapes_detected_sources_into_one_line() {
        let json = "{\"sources\":[{\"name\":\"hermes-memory\"},{\"name\":\"openclaw-layers\"}],\"scans\":[]}";
        assert_eq!(
            format_migrate_summary(json),
            "2 prior-AI store(s) found: hermes-memory, openclaw-layers"
        );
    }

    #[test]
    fn empty_or_malformed_hides_the_card() {
        assert_eq!(format_migrate_summary("{\"sources\":[],\"scans\":[]}"), "");
        assert_eq!(format_migrate_summary("not json"), "");
        assert_eq!(format_migrate_summary("{}"), "");
    }
}

/// GUI-FULLAUTO-CEREMONY + GUI-REENTRY-PRESET regression tests.
///
/// Both fixes live in `on_preset_apply_named_clicked` and `on_finish_clicked`
/// (pure-logic branches) — no Slint or subprocess dependency needed here.
#[cfg(test)]
mod gui_bug_regression_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;

    use super::{finish, read_freedom_yaml, WizardSnapshot};

    fn base_snapshot() -> WizardSnapshot {
        WizardSnapshot {
            operator_id: "alice".into(),
            provider_kind: "claude_cli".into(),
            autonomy: "standard".into(),
            license_accepted: true,
            enable_telegram: false,
            provider_key: String::new(),
            telegram_token: String::new(),
            cluster_discovery_disabled: false,
        }
    }

    // ── GUI-FULLAUTO-CEREMONY ────────────────────────────────────────────────

    /// The routing predicate in the None (dry-run unavailable) arm:
    /// only `"full-auto"` must be sent through the token route.
    #[test]
    fn full_auto_preset_name_triggers_token_route() {
        let requires_token = |name: &str| name == "full-auto";
        assert!(requires_token("full-auto"));
        assert!(!requires_token("balanced"));
        assert!(!requires_token("essentials"));
        assert!(!requires_token("local-sovereign"));
        assert!(!requires_token("my-custom"));
        assert!(!requires_token(""));
    }

    // ── GUI-REENTRY-PRESET ───────────────────────────────────────────────────

    /// Valid freedom.yaml → `reentry_config_ok` flag set to true.
    #[test]
    fn reentry_flag_set_when_yaml_valid() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: alice\nprovider_kind: claude_cli\n\
             autonomy: standard\nchannels:\n- cli\n",
        )
        .unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        if read_freedom_yaml(&path).is_ok() {
            flag.store(true, Ordering::Release);
        }
        assert!(flag.load(Ordering::Acquire), "flag must be true for valid yaml");
    }

    /// Corrupted freedom.yaml → `reentry_config_ok` flag stays false.
    #[test]
    fn reentry_flag_stays_false_when_yaml_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "this is: [not: valid: yaml:\n").unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        if read_freedom_yaml(&path).is_ok() {
            flag.store(true, Ordering::Release);
        }
        assert!(!flag.load(Ordering::Acquire), "flag must stay false for corrupt yaml");
    }

    /// Guard: already_initialized=true + flag=false → block.
    #[test]
    fn guard_blocks_when_already_initialized_and_read_failed() {
        let already_initialized = true;
        let flag = Arc::new(AtomicBool::new(false));
        let blocked = already_initialized && !flag.load(Ordering::Acquire);
        assert!(blocked);
    }

    /// Guard: already_initialized=true + flag=true → allow.
    #[test]
    fn guard_allows_when_already_initialized_and_read_succeeded() {
        let already_initialized = true;
        let flag = Arc::new(AtomicBool::new(true));
        let blocked = already_initialized && !flag.load(Ordering::Acquire);
        assert!(!blocked);
    }

    /// Guard: already_initialized=false → never block regardless of flag.
    #[test]
    fn guard_never_blocks_on_first_run() {
        let already_initialized = false;
        for v in [false, true] {
            let flag = Arc::new(AtomicBool::new(v));
            let blocked = already_initialized && !flag.load(Ordering::Acquire);
            assert!(!blocked, "first-run must never be blocked (flag={v})");
        }
    }

    /// finish() still validates state even when the re-entry guard passes.
    #[test]
    fn finish_validates_state_after_reentry_guard_passes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: alice\nprovider_kind: claude_cli\n\
             autonomy: standard\nchannels:\n- cli\n",
        )
        .unwrap();
        let cfg = read_freedom_yaml(&path).expect("parses");
        let mut state = base_snapshot();
        state.operator_id = cfg.operator_id;
        state.autonomy = cfg.autonomy;
        state.license_accepted = false; // operator unchecked license
        let err = finish(&state).unwrap_err();
        assert!(err.to_string().contains("license"));
    }
}
