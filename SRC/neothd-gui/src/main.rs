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

/// GU-03 — persona-adaptive settings-panel visibility rule engine (pure Rust,
/// unit-tested without Slint). The `.slint` binds its `show_*` properties to
/// [`panel_logic::PanelVisibility`], populated on startup from the operator's
/// complexity level.
mod buddy_activity;
mod panel_logic;

use buddy_activity::GuiActivity;

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
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_hardware_summary(hw_summary.into());
                w.set_daemon_state(led.into());
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
        // PF-01-GUI — reflect the current skills.always_embed_route on the toggle.
        window.set_skills_always_embed_route(read_skills_always_embed_route(
            &neoth_dir.join("freedom.yaml"),
        ));

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
            let outcome: std::result::Result<(String, StreamStats), String> = (|| {
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
                let (reply, done, stats) =
                    parse_stream_sentinel(&String::from_utf8_lossy(&acc));
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
                Ok((reply, stats))
            })();
            // Stream over (either way) — disarm the watchdog clock.
            last_chunk.store(-1, std::sync::atomic::Ordering::Relaxed);

            let weak_for_loop = weak_worker.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak_for_loop.upgrade() {
                    // GUI-07: the stream settled (reply or error) — unspin Send.
                    w.set_chat_send_in_flight(false);
                    w.set_chat_stall_active(false);
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
                        Ok((reply, stats)) => {
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
            let output = run_neothd_probe(&["cluster", "status"]);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_agents_output(output.into());
                    w.set_agents_running(false);
                }
            });
        });
    });

    // Automation tab — scheduled crons + the n8n bridge.
    let weak_auto = window.as_weak();
    window.on_automation_refresh_clicked(move || {
        let Some(w0) = weak_auto.upgrade() else {
            return;
        };
        w0.set_automation_running(true);
        buddy(&w0, GuiActivity::AgentParallel);
        let weak = weak_auto.clone();
        std::thread::spawn(move || {
            let cron = run_neothd_probe(&["cron", "list"]);
            let n8n = run_neothd_probe(&["n8n", "status"]);
            let output = format!("── CRON ──\n{cron}\n\n── N8N ──\n{n8n}");
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_automation_output(output.into());
                    w.set_automation_running(false);
                }
            });
        });
    });

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

        // Refresh — worker thread reads + parses the record files.
        let weak_loop_refresh = window.as_weak();
        let cache_refresh = loop_cache.clone();
        let refresh_history = move |select: Option<String>| {
            let weak = weak_loop_refresh.clone();
            let cache = cache_refresh.clone();
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
                    // Drain stdout to EOF (keeps the child unblocked).
                    let mut sink = String::new();
                    if let Some(out) = stdout.as_mut() {
                        use std::io::Read as _;
                        let _ = out.read_to_string(&mut sink);
                    }
                    // ponytail: stderr read after stdout EOF — loop stderr is
                    // short (refusal/one error line); switch to a reader
                    // thread if it ever exceeds the 64K pipe buffer.
                    let mut err_text = String::new();
                    if let Some(err) = stderr.as_mut() {
                        use std::io::Read as _;
                        let _ = err.read_to_string(&mut err_text);
                    }
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

    // GUI-overhaul feature parity — set the autonomy level from the Privacy combo.
    // Shells `neoth autonomy set <level>` (mutates freedom.yaml::autonomy + emits
    // a WAL audit frame). On success, mirror the new level into autonomy-choice so
    // the combo + every autonomy-derived display update without a reload.
    let weak_autonomy_set = window.as_weak();
    window.on_autonomy_set(move |level| {
        if let Some(w) = weak_autonomy_set.upgrade() {
            // Autonomy is a trust decision → the orb shows the secured state.
            buddy(&w, GuiActivity::Secured);
        }
        let weak = weak_autonomy_set.clone();
        let level = level.to_string();
        std::thread::spawn(move || {
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
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Ok(mut g) = mutex.lock() {
                                    *g = snap_for_state;
                                }
                                if let Some(w) = weak.upgrade() {
                                    apply_kanban_snapshot(&w, snap);
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
    let rows: Vec<SkillRow> = SKILLS_CACHE
        .lock()
        .map(|c| panel_logic::group_skill_rows(&c, &filter))
        .unwrap_or_default()
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
        })
        .collect();
    window.set_plugins(ModelRc::new(VecModel::from(rows)));
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
fn apply_presets(window: &MainWindow, presets: Vec<panel_logic::PresetEntry>) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<PresetRow> = presets
        .into_iter()
        .map(|p| PresetRow {
            name: p.name.into(),
            active: p.active,
        })
        .collect();
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
    let stats = serde_json::from_str::<serde_json::Value>(raw[pos..].trim())
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
