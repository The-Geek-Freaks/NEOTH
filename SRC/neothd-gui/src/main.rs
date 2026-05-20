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

/// Plain snapshot the Rust side hands to Slint. Owning-Vecs keep the
/// Slint Model construction simple — we build `ModelRc<VecModel<…>>`
/// from each Vec at the property-set site.
#[derive(Default)]
struct KanbanBoardSnapshot {
    backlog: Vec<KanbanTaskRow>,
    todo: Vec<KanbanTaskRow>,
    in_progress: Vec<KanbanTaskRow>,
    review: Vec<KanbanTaskRow>,
    done: Vec<KanbanTaskRow>,
    feed: Vec<KanbanFeedRow>,
    summary: String,
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
                window.set_enable_telegram(
                    cfg.channels.iter().any(|c| c == "telegram"),
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not parse existing freedom.yaml — Done summary shows defaults"
                );
            }
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

    // C-1 fix — chat-send-clicked was declared in main.slint:162 and
    // wired through ChatView → Composer but the Rust side had no
    // closure registered. Every Send click + Enter hit fired into a
    // void. We now log the message + clear the composer + push a stub
    // operator bubble into scrollback so the GUI proves it received
    // the keystroke. The full provider dispatch lands in the next
    // Chat-wiring pick; for now the operator sees their own message
    // bubble appear and knows the surface is alive.
    let weak_chat_send = window.as_weak();
    window.on_chat_send_clicked(move |text| {
        let body = text.trim().to_string();
        if body.is_empty() {
            return;
        }
        info!(message_len = body.len(), "chat: send-clicked");
        if let Some(w) = weak_chat_send.upgrade() {
            use slint::{Model, ModelRc, VecModel};
            let mut rows: Vec<ChatMessage> = w
                .get_chat_messages()
                .iter()
                .collect();
            rows.push(ChatMessage {
                role: "operator".into(),
                text: body.into(),
                timestamp: format_now_hms().into(),
                streaming: false,
            });
            w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
            w.set_chat_composer_draft("".into());
        }
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
    std::thread::spawn(move || {
        let snap = fetch_kanban_board_snapshot();
        let weak = weak_kanban_init.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                apply_kanban_snapshot(&w, snap);
            }
        });
    });

    let weak_kanban_refresh = window.as_weak();
    window.on_kanban_refresh_clicked(move || {
        let weak = weak_kanban_refresh.clone();
        std::thread::spawn(move || {
            let snap = fetch_kanban_board_snapshot();
            info!(summary = %snap.summary, "kanban: refresh requested");
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_kanban_snapshot(&w, snap);
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
    let yaml = MinimalFreedomYaml {
        operator_id: state.operator_id.clone(),
        provider_kind: state.provider_kind.clone(),
        autonomy: state.autonomy.clone(),
        channels,
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
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let cfg: MinimalFreedomYaml = serde_yaml::from_str(&body)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(cfg)
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
/// the daemon will eventually own the canonical timestamp when the
/// provider dispatch wiring lands; this string is just so the
/// operator sees something next to their bubble during the in-process
/// stub-send.
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
                    if stderr.is_empty() { "(no stderr)" } else { &stderr }
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
            envelope.session.session_id,
            envelope.session.status,
            envelope.session.prompt,
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
}
