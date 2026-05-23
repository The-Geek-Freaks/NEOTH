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

slint::include_modules!();

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

    // H-3 fix — hardware probe runs in a worker thread so a hanging
    // `neothd hardware` subprocess can never block the window from
    // appearing. The placeholder string shows until the real probe
    // result lands via `invoke_from_event_loop`.
    window.set_hardware_summary("Probing hardware…".into());
    let weak_hw = window.as_weak();
    std::thread::spawn(move || {
        let hw_summary = probe_hardware_via_subprocess();
        let weak = weak_hw.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_hardware_summary(hw_summary.into());
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

    // QM-8 Phase 2: preset list probe — same refresh-loop shape as
    // usage. Lighter cadence (5min) since presets change rarely.
    window.set_preset_summary("Loading presets…".into());
    let weak_preset = window.as_weak();
    std::thread::spawn(move || {
        loop {
            let summary = probe_preset_summary_via_subprocess();
            let weak = weak_preset.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_preset_summary(summary.into());
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
    let already_initialized = neoth_dir.join("freedom.yaml").exists();
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
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not parse existing freedom.yaml — Done summary shows defaults"
                );
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
    let weak_chat_send = window.as_weak();
    window.on_chat_send_clicked(move |text| {
        let body = text.trim().to_string();
        if body.is_empty() {
            return;
        }
        info!(message_len = body.len(), "chat: send-clicked");
        let Some(w) = weak_chat_send.upgrade() else {
            return;
        };

        use slint::{Model, ModelRc, VecModel};
        let mut rows: Vec<ChatMessage> = w.get_chat_messages().iter().collect();
        let placeholder_idx = rows.len() + 1;
        rows.push(ChatMessage {
            role: "operator".into(),
            text: body.clone().into(),
            timestamp: format_now_hms().into(),
            streaming: false,
        });
        rows.push(ChatMessage {
            role: "assistant".into(),
            text: "…".into(),
            timestamp: format_now_hms().into(),
            streaming: true,
        });
        w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
        w.set_chat_composer_draft("".into());

        let weak_worker = w.as_weak();
        std::thread::spawn(move || {
            let outcome = chat_via_subprocess(&body);
            let weak_for_loop = weak_worker.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak_for_loop.upgrade() {
                    use slint::{Model, ModelRc, VecModel};
                    let mut rows: Vec<ChatMessage> = w.get_chat_messages().iter().collect();
                    let target = match outcome {
                        Ok(reply) => ChatMessage {
                            role: "assistant".into(),
                            text: reply.into(),
                            timestamp: format_now_hms().into(),
                            streaming: false,
                        },
                        Err(err) => ChatMessage {
                            // `error` bubble role lets the .slint side
                            // colour the surface differently (red tint
                            // when the Composer's theme picks it up).
                            // Older Composer versions render "error" the
                            // same as "assistant" — degrades cleanly.
                            role: "error".into(),
                            text: err.into(),
                            timestamp: format_now_hms().into(),
                            streaming: false,
                        },
                    };
                    // Replace the streaming placeholder (penultimate row
                    // by construction; check defensively in case the
                    // operator sent a second message before the first
                    // returned).
                    if placeholder_idx < rows.len()
                        && rows[placeholder_idx].streaming
                        && rows[placeholder_idx].role == "assistant"
                    {
                        rows[placeholder_idx] = target;
                    } else {
                        rows.push(target);
                    }
                    w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
                }
            });
        });
    });

    // H-1 fix — chat-channel-switched was likewise unbound. Now logged
    // so the operator's sidebar click reaches the daemon-facing layer
    // when channel-specific scrollback wiring lands.
    window.on_chat_channel_switched(|idx| {
        info!(channel_index = idx, "chat: channel-switched");
    });

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
        let weak = weak_preset_apply.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_status_line(outcome.into());
                // Force-refresh the preset summary so the active
                // marker reflects any change without waiting for
                // the next 5-minute tick.
                let summary = probe_preset_summary_via_subprocess();
                w.set_preset_summary(summary.into());
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

    let weak_kanban_refresh = window.as_weak();
    let mutex_refresh = kanban_snapshot.clone();
    window.on_kanban_refresh_clicked(move || {
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
    let _kanban_live_timer = {
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(2),
            move || {
                if let Some(w) = weak_kanban_tick.upgrade() {
                    // Skip the subprocess churn when the operator
                    // isn't looking at the Code Sessions surface.
                    if w.get_step() != WizardStep::Settings {
                        return;
                    }
                    let weak = weak_kanban_tick.clone();
                    let mutex = mutex_tick.clone();
                    std::thread::spawn(move || {
                        let snap = fetch_kanban_board_snapshot();
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
            let mut cfg = read_freedom_yaml(&freedom_path)?;
            cfg.provider_kind = new_provider.to_string();
            let body = serde_yaml::to_string(&cfg)
                .context("serialise freedom.yaml")?;
            write_mode_0600(&freedom_path, body.as_bytes())?;
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

    let weak = window.as_weak();
    window.on_finish_clicked(move || {
        if let Some(w) = weak.upgrade() {
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

#[derive(Serialize, Deserialize)]
struct ClusterYamlBlock {
    mdns: ClusterMdnsYamlBlock,
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
            mdns: ClusterMdnsYamlBlock { enabled: false },
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

fn validate_autonomy(level: &str) -> Result<()> {
    match level {
        "strict" | "standard" | "elevated" | "full" | "custom" => Ok(()),
        other => anyhow::bail!("unrecognised autonomy level '{other}'"),
    }
}

#[cfg(unix)]
fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {} mode 0600", path.display()))?;
    file.write_all(body)
        .with_context(|| format!("write body to {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    // Windows DACL restriction lives in the daemon's `wal::win_acl`
    // module; pulling it in from the GUI crate would force a hard
    // dependency on the whole daemon. Instead we ship the same icacls
    // subprocess inline — the call surface is tiny and the GUI runs in
    // the operator's session so it has the right privilege.
    std::fs::write(path, body).with_context(|| format!("write {}", path.display()))?;
    if let Err(e) = icacls_restrict_to_owner(path) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "DACL restriction failed; file inherits parent ACL",
        );
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
        .env("CLICOLOR", "0");
    cmd
}

/// Run `neothd kanban list/show --output json` + group tasks by status.
/// Returns an empty snapshot with a friendly summary when the operator
/// hasn't opened a coding session yet, OR when the daemon binary is
/// missing — the GUI degrades gracefully instead of erroring out.
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
    snap
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
fn chat_via_subprocess(message: &str) -> std::result::Result<String, String> {
    let Some(bin) = which_neothd() else {
        return Err(BINARY_MISSING_MESSAGE.to_string());
    };
    chat_via_subprocess_with(&bin, message)
}

/// R4-P1 test-injection entry point. Same logic as
/// [`chat_via_subprocess`] but the caller pins the binary path —
/// lets tests run with a synthetic fake-neothd binary on disk
/// instead of relying on the real daemon being installed. The
/// production path forwards from `chat_via_subprocess` after
/// `which_neothd` resolves; tests pass tempdir-staged `bin.sh` /
/// `bin.cmd` scripts that emit fixture stdout/stderr.
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

/// QM-8 Phase 2: how often the preset tile re-fires `neoth preset
/// list`. Lighter cadence than usage since presets change rarely.
pub const PRESET_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

#[cfg(test)]
mod chat_subprocess_tests {
    use super::*;

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
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        Ok(out) => format!(
            "Hardware probe failed (exit {}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("Hardware probe could not start: {e}"),
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

/// QM-8 Phase 2.5: resolve the active preset (via `neoth preset list`),
/// then shell `neoth preset apply <active>`. Returns an operator-
/// readable result string for the status line.
fn apply_active_preset_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Preset apply unavailable — `neothd` binary not on PATH.".to_string();
    };
    // First: list to find the active marker.
    let list_output = spawn_neothd_plain(&bin).arg("preset").arg("list").output();
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
    let apply_output = spawn_neothd_plain(&bin)
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

fn default_neoth_home() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".neoth")
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
            operator_id: "alex".into(),
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
        assert!(body.contains("operator_id: alex"));
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
}
