//! Explicit packaged GUI acceptance probe for P2-26b.
//!
//! This is intentionally an executable-only seam.  It starts a sibling daemon
//! against a fresh temporary `NEOTH_HOME`, drives the normal Slint callbacks,
//! and leaves a content-free receipt for the package workflow.

use std::{
    cell::RefCell,
    ffi::OsString,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    rc::Rc,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use slint::{ComponentHandle, Model as _};

use crate::{
    MainWindow, MiniOverlay,
    gui_chat_bridge_controller::{self, InstalledGuiChat, PackagedChatProbeSnapshot},
};

/// Kept separate from the ordinary runtime probe: this mode owns a real
/// daemon/provider pair and must always leave a machine-readable receipt.
const FLAG: &str = "--packaged-chat-acceptance";
const TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_KEY: &str = "packaged-probe-only-key";
const SUCCESS_BODY: &str = "packaged-chat-probe-success";

pub(crate) fn prepare(args: &[OsString]) -> Result<Option<PackagedChatAcceptance>> {
    let Some(receipt) = parse_receipt(args)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        !receipt.exists(),
        "{FLAG} refuses an existing receipt path to prevent stale acceptance evidence"
    );
    let home = isolated_home()?;
    anyhow::ensure!(
        !receipt.starts_with(&home),
        "{FLAG} receipt path must be outside the owned temporary home"
    );
    // This must precede all config and daemon discovery in the ordinary GUI
    // startup path.  Both GUI and core resolve the same NEOTH_HOME.
    unsafe { std::env::set_var("NEOTH_HOME", &home) };

    let provider = LoopbackProvider::spawn()?;
    seed_home(&home, &provider.endpoint)?;
    let mut daemon = spawn_daemon(&home)?;
    if let Err(error) = wait_for_attested_bridge(&home, &daemon) {
        let daemon_pid = daemon.id();
        let _ = daemon.kill();
        let exit = daemon.wait().ok().and_then(|status| status.code());
        provider.control.release_all();
        let _ = write_startup_failure_receipt(&receipt, daemon_pid, exit, &error.to_string());
        let _ = fs::remove_dir_all(&home);
        return Err(error);
    }

    Ok(Some(PackagedChatAcceptance {
        receipt,
        home,
        provider,
        daemon: Some(daemon),
        timer: None,
    }))
}

pub(crate) fn remove_flag(arguments: &mut Vec<OsString>) {
    if arguments.first().is_some_and(|argument| argument == FLAG) {
        arguments.drain(..2);
    }
}

fn parse_receipt(args: &[OsString]) -> Result<Option<PathBuf>> {
    match args {
        [] => Ok(None),
        [flag, receipt] if flag == FLAG => {
            let receipt = PathBuf::from(receipt);
            anyhow::ensure!(
                receipt.is_absolute(),
                "{FLAG} requires an absolute receipt path"
            );
            Ok(Some(receipt))
        }
        [flag] if flag == FLAG => anyhow::bail!("{FLAG} requires a receipt path"),
        _ if args.first().is_some_and(|argument| argument == FLAG) => {
            anyhow::bail!("{FLAG} accepts exactly one receipt path")
        }
        _ => Ok(None),
    }
}

pub(crate) struct PackagedChatAcceptance {
    receipt: PathBuf,
    home: PathBuf,
    provider: LoopbackProvider,
    daemon: Option<Child>,
    timer: Option<slint::Timer>,
}

impl PackagedChatAcceptance {
    pub(crate) fn receipt_path(&self) -> PathBuf {
        self.receipt.clone()
    }
    pub(crate) fn fail_controller_install(&self) {
        let daemon_pid = self.daemon.as_ref().map(Child::id).unwrap_or_default();
        let value = serde_json::json!({
            "schema":"neoth-packaged-chat-probe/v1",
            "result":"failed",
            "failure":"attested-daemon-chat-controller-unavailable",
            "gui_pid":std::process::id(),
            "daemon_pid":daemon_pid,
            "daemon_exit_success":serde_json::Value::Null,
            "home_removed":false,
            "provider_requests":self.provider.control.requests(),
            "checks":{"controller_installed":false}
        });
        if let Some(parent) = self.receipt.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(
            &self.receipt,
            serde_json::to_vec_pretty(&value).unwrap_or_default(),
        );
    }
    pub(crate) fn schedule(
        &mut self,
        window: &MainWindow,
        overlay: &MiniOverlay,
        installed: Arc<Mutex<InstalledGuiChat>>,
    ) {
        let state = Rc::new(RefCell::new(ProbeState::new(installed)));
        let weak_window = window.as_weak();
        let weak_overlay = overlay.as_weak();
        let provider = self.provider.control.clone();
        let receipt = self.receipt.clone();
        let daemon_pid = self.daemon.as_ref().map(Child::id).unwrap_or_default();
        let timer = slint::Timer::default();
        let observed_state = Rc::clone(&state);
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(20),
            move || {
                let Some(window) = weak_window.upgrade() else {
                    let _ = slint::quit_event_loop();
                    return;
                };
                let Some(overlay) = weak_overlay.upgrade() else {
                    fail(&observed_state, "overlay disappeared");
                    let _ = slint::quit_event_loop();
                    return;
                };
                let outcome = step(&window, &overlay, &provider, &observed_state);
                if let Some(result) = outcome {
                    let state = observed_state.borrow();
                    let receipt_result = write_receipt(
                        &receipt,
                        &state,
                        provider.requests(),
                        daemon_pid,
                        result.as_deref(),
                    );
                    if receipt_result.is_err() {
                        eprintln!("packaged chat probe receipt write failed");
                    }
                    let _ = window.hide();
                    let _ = slint::quit_event_loop();
                }
            },
        );
        self.timer = Some(timer);
    }
}

/// Called after the owner has dropped the probe and therefore reaped the
/// daemon/removed the temporary home. A failed receipt is a process failure,
/// never a successful GUI exit with a warning hidden in a JSON file.
pub(crate) fn verify_finished_receipt(path: &Path) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).context("read packaged chat receipt")?)
            .context("parse packaged chat receipt")?;
    anyhow::ensure!(
        value.get("result").and_then(serde_json::Value::as_str) == Some("passed"),
        "packaged chat acceptance receipt is not passed"
    );
    anyhow::ensure!(
        value
            .get("daemon_exit_success")
            .and_then(serde_json::Value::as_bool)
            == Some(true),
        "packaged daemon did not exit cleanly"
    );
    anyhow::ensure!(
        value
            .get("home_removed")
            .and_then(serde_json::Value::as_bool)
            == Some(true),
        "packaged temporary home was not removed"
    );
    Ok(())
}

impl Drop for PackagedChatAcceptance {
    fn drop(&mut self) {
        self.timer.take();
        self.provider.control.release_all();
        let mut daemon_exit = "not-started".to_owned();
        let mut daemon_exit_success = false;
        let mut daemon_pid = 0_u32;
        if let Some(mut daemon) = self.daemon.take() {
            daemon_pid = daemon.id();
            let (status, forced) = stop_owned_daemon(&mut daemon);
            // `serve` owns SIGTERM draining and promises exit 0. A signal,
            // crash, or nonzero exit is evidence of failed cleanup even if
            // the child was reaped within the grace window.
            daemon_exit_success = !forced
                && status
                    .as_ref()
                    .is_some_and(std::process::ExitStatus::success);
            daemon_exit = status
                .and_then(|status| status.code().map(|code| code.to_string()))
                .unwrap_or_else(|| "forced-or-wait-error".to_owned());
        }
        // The event-loop callback writes the content-free receipt before it
        // asks Slint to quit.  Update only the direct child fact after its
        // bounded shutdown; no provider/request body is ever retained here.
        if let Ok(raw) = fs::read(&self.receipt)
            && let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&raw)
        {
            value["daemon_pid"] = serde_json::json!(daemon_pid);
            value["daemon_exit_success"] = serde_json::json!(daemon_exit_success);
            value["daemon_exit"] = serde_json::json!(daemon_exit);
            if !daemon_exit_success {
                value["result"] = serde_json::json!("failed");
                value["failure"] = serde_json::json!("daemon-clean-shutdown-failed");
            }
            let _ = fs::write(
                &self.receipt,
                serde_json::to_vec_pretty(&value).unwrap_or_default(),
            );
        }
        let home_removed = fs::remove_dir_all(&self.home).is_ok() && !self.home.exists();
        if let Ok(raw) = fs::read(&self.receipt)
            && let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&raw)
        {
            value["home_removed"] = serde_json::json!(home_removed);
            if !home_removed {
                value["result"] = serde_json::json!("failed");
                value["failure"] = serde_json::json!("temporary-home-cleanup-failed");
            }
            let _ = fs::write(
                &self.receipt,
                serde_json::to_vec_pretty(&value).unwrap_or_default(),
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    StartBuddy,
    WaitBuddy,
    Restore,
    WaitReattach,
    WaitSuccess,
    StartError,
    WaitError,
    StartCancel,
    WaitCancel,
    Done,
}

struct ProbeState {
    installed: Arc<Mutex<InstalledGuiChat>>,
    phase: Phase,
    started: Instant,
    success_turn: Option<String>,
    error_turn: Option<String>,
    cancel_turn: Option<String>,
    success_operation_before: Option<u64>,
    success_operation_after: Option<u64>,
    reattach_phase: Option<String>,
    success_cursor_before: Option<u64>,
    success_cursor_after: Option<u64>,
    completed_before_cancel: usize,
    buddy_partial_visible: bool,
    success_visible_exact: bool,
    error_terminal: bool,
    cancel_terminal: bool,
    failure: Option<String>,
}
impl ProbeState {
    fn new(installed: Arc<Mutex<InstalledGuiChat>>) -> Self {
        Self {
            installed,
            phase: Phase::StartBuddy,
            started: Instant::now(),
            success_turn: None,
            error_turn: None,
            cancel_turn: None,
            success_operation_before: None,
            success_operation_after: None,
            reattach_phase: None,
            success_cursor_before: None,
            success_cursor_after: None,
            completed_before_cancel: 0,
            buddy_partial_visible: false,
            success_visible_exact: false,
            error_terminal: false,
            cancel_terminal: false,
            failure: None,
        }
    }
}

fn step(
    window: &MainWindow,
    overlay: &MiniOverlay,
    provider: &ProviderControl,
    state: &Rc<RefCell<ProbeState>>,
) -> Option<Option<String>> {
    if state.borrow().started.elapsed() > TIMEOUT {
        fail(state, "timed out");
        return Some(state.borrow().failure.clone());
    }
    let phase = state.borrow().phase;
    match phase {
        Phase::StartBuddy => {
            overlay.invoke_send_clicked("probe-buddy-reattach".into(), false);
            state.borrow_mut().phase = Phase::WaitBuddy;
        }
        Phase::WaitBuddy => {
            if provider.requests() >= 1 {
                let installed = Arc::clone(&state.borrow().installed);
                match snapshot(&installed) {
                    // The first SSE delta was flushed before this observation.
                    // Require a nonzero authoritative cursor before handoff so
                    // this cannot pass by attaching only after terminal output.
                    Ok(Some(snapshot))
                        if snapshot.surface
                            == neothd::daemon::gui_chat_bridge::GuiChatSurface::Buddy
                            && snapshot.latest_sequence > 0 =>
                    {
                        let buddy_partial = overlay
                            .get_recent_lines()
                            .iter()
                            .any(|line| line.contains("packaged-chat-"));
                        if !buddy_partial {
                            return None;
                        }
                        let mut locked = state.borrow_mut();
                        locked.buddy_partial_visible = true;
                        locked.success_turn = Some(snapshot.turn_id.clone());
                        locked.success_operation_before = Some(snapshot.operation_id);
                        locked.success_cursor_before = Some(snapshot.latest_sequence);
                        locked.phase = Phase::Restore;
                    }
                    Ok(_) => {}
                    Err(_) => fail(state, "could not observe active Buddy turn"),
                }
            }
        }
        Phase::Restore => {
            overlay.invoke_restore_clicked();
            state.borrow_mut().phase = Phase::WaitReattach;
        }
        Phase::WaitReattach => {
            let installed = Arc::clone(&state.borrow().installed);
            match snapshot(&installed) {
                Ok(Some(snapshot))
                    if snapshot.surface
                        == neothd::daemon::gui_chat_bridge::GuiChatSurface::Main =>
                {
                    let valid = {
                        let prior = state.borrow();
                        prior.success_turn.as_deref() == Some(snapshot.turn_id.as_str())
                            && Some(snapshot.operation_id) > prior.success_operation_before
                            && snapshot.latest_sequence
                                >= prior.success_cursor_before.unwrap_or_default()
                    };
                    if !valid {
                        fail(
                            state,
                            "turn identity, operation, or cursor changed during Buddy handoff",
                        );
                    } else {
                        let mut locked = state.borrow_mut();
                        locked.success_operation_after = Some(snapshot.operation_id);
                        locked.reattach_phase = Some(snapshot.phase);
                        locked.success_cursor_after = Some(snapshot.latest_sequence);
                        locked.phase = Phase::WaitSuccess;
                        provider.release(0);
                    }
                }
                Ok(_) => {}
                Err(_) => fail(state, "could not observe Main reattach"),
            }
        }
        Phase::WaitSuccess => {
            if !window.get_chat_send_in_flight() {
                let rows = window.get_chat_live_messages();
                let success_turn = state.borrow().success_turn.clone();
                let matches = rows
                    .iter()
                    .filter(|row| {
                        row.request_id.as_str() == success_turn.as_deref().unwrap_or("")
                            && row.role.as_str() == "assistant"
                            && row.stream_phase.as_str() == "complete"
                            && row.text.as_str() == SUCCESS_BODY
                    })
                    .count();
                if matches != 1 || provider.requests() != 1 || !state.borrow().buddy_partial_visible
                {
                    fail(
                        state,
                        "reattached turn did not preserve Buddy partial and settle Main exactly once",
                    );
                } else {
                    let mut locked = state.borrow_mut();
                    locked.success_visible_exact = true;
                    locked.phase = Phase::StartError;
                }
            }
        }
        Phase::StartError => {
            window.invoke_chat_send_clicked("probe-provider-failure".into(), false);
            state.borrow_mut().phase = Phase::WaitError;
        }
        Phase::WaitError => {
            if provider.requests() >= 2 {
                let installed = Arc::clone(&state.borrow().installed);
                if state.borrow().error_turn.is_none() {
                    if let Ok(Some(snapshot)) = snapshot(&installed) {
                        state.borrow_mut().error_turn = Some(snapshot.turn_id);
                        provider.release(1);
                    }
                    return None;
                }
                if window.get_chat_send_in_flight() {
                    return None;
                }
                let error_turn = state.borrow().error_turn.clone();
                let failed = window.get_chat_live_messages().iter().any(|row| {
                    row.request_id.as_str() == error_turn.as_deref().unwrap_or("")
                        && row.role.as_str() == "error"
                        && row.stream_phase.as_str() == "failed"
                });
                if !failed {
                    fail(state, "provider failure had no failed terminal");
                } else {
                    state.borrow_mut().error_terminal = true;
                    state.borrow_mut().phase = Phase::StartCancel;
                }
            }
        }
        Phase::StartCancel => {
            let rows = window.get_chat_live_messages();
            let mut locked = state.borrow_mut();
            locked.completed_before_cancel = rows
                .iter()
                .filter(|row| {
                    row.role.as_str() == "assistant" && row.stream_phase.as_str() == "complete"
                })
                .count();
            drop(locked);
            overlay.invoke_send_clicked("probe-cancellation".into(), false);
            state.borrow_mut().phase = Phase::WaitCancel;
        }
        Phase::WaitCancel => {
            if provider.requests() >= 3 {
                let installed = Arc::clone(&state.borrow().installed);
                if let Ok(Some(snapshot)) = snapshot(&installed) {
                    state.borrow_mut().cancel_turn = Some(snapshot.turn_id);
                }
                window.invoke_chat_stop_stream();
                state.borrow_mut().phase = Phase::Done;
            }
        }
        Phase::Done => {
            if !window.get_chat_send_in_flight() {
                let rows = window.get_chat_live_messages();
                let cancel_turn = state.borrow().cancel_turn.clone();
                let cancelled = rows.iter().any(|row| {
                    row.request_id.as_str() == cancel_turn.as_deref().unwrap_or("")
                        && row.stream_phase.as_str() == "cancelled"
                });
                let completed_after_cancel = rows
                    .iter()
                    .filter(|row| {
                        row.role.as_str() == "assistant" && row.stream_phase.as_str() == "complete"
                    })
                    .count();
                if !cancelled || completed_after_cancel != state.borrow().completed_before_cancel {
                    fail(state, "cancellation terminal or repaint check failed");
                } else {
                    state.borrow_mut().cancel_terminal = true;
                    return Some(None);
                }
            }
        }
    }
    state
        .borrow()
        .failure
        .as_ref()
        .map(|_| Some("failed".to_owned()))
}

fn fail(state: &Rc<RefCell<ProbeState>>, reason: &str) {
    state.borrow_mut().failure = Some(reason.to_owned());
}
fn stop_owned_daemon(daemon: &mut Child) -> (Option<std::process::ExitStatus>, bool) {
    #[cfg(unix)]
    unsafe {
        libc::kill(daemon.id() as i32, libc::SIGTERM);
    }
    #[cfg(not(unix))]
    {
        let _ = daemon.kill();
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match daemon.try_wait() {
            Ok(Some(status)) => return (Some(status), false),
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return (None, true),
        }
    }
    let _ = daemon.kill();
    (daemon.wait().ok(), true)
}
fn snapshot(installed: &Arc<Mutex<InstalledGuiChat>>) -> Result<Option<PackagedChatProbeSnapshot>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(gui_chat_bridge_controller::packaged_probe_snapshot(
            installed,
        ))
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

struct ProviderControl {
    requests: AtomicUsize,
    releases: Mutex<[bool; 3]>,
    released: Condvar,
}
impl ProviderControl {
    fn requests(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }
    fn release(&self, index: usize) {
        let mut releases = self.releases.lock().unwrap_or_else(|p| p.into_inner());
        releases[index] = true;
        self.released.notify_all();
    }
    fn release_all(&self) {
        let mut releases = self.releases.lock().unwrap_or_else(|p| p.into_inner());
        *releases = [true; 3];
        self.released.notify_all();
    }
    fn wait(&self, index: usize) {
        let mut releases = self.releases.lock().unwrap_or_else(|p| p.into_inner());
        while !releases[index] {
            releases = self
                .released
                .wait(releases)
                .unwrap_or_else(|p| p.into_inner());
        }
    }
}
struct LoopbackProvider {
    endpoint: String,
    control: Arc<ProviderControl>,
}
impl LoopbackProvider {
    fn spawn() -> Result<Self> {
        let listener =
            TcpListener::bind("127.0.0.1:0").context("bind packaged probe loopback provider")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let control = Arc::new(ProviderControl {
            requests: AtomicUsize::new(0),
            releases: Mutex::new([false; 3]),
            released: Condvar::new(),
        });
        let worker = Arc::clone(&control);
        let _ = std::thread::spawn(move || {
            for index in 0..3 {
                let Ok((mut socket, _)) = listener.accept() else {
                    return;
                };
                if read_request(&mut socket).is_err() {
                    return;
                }
                worker.requests.fetch_add(1, Ordering::AcqRel);
                if index == 1 {
                    worker.wait(index);
                    let _ = write_response(&mut socket, 400, "provider failed");
                    continue;
                }
                if index == 0 {
                    let _ = write_stream_prefix(&mut socket);
                }
                worker.wait(index);
                if index == 0 {
                    let _ = write_stream_finish(&mut socket);
                }
            }
        });
        Ok(Self { endpoint, control })
    }
}
fn read_request(socket: &mut TcpStream) -> Result<()> {
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    let head = loop {
        let count = socket.read(&mut buf)?;
        anyhow::ensure!(count > 0, "loopback request ended before headers");
        received.extend_from_slice(&buf[..count]);
        if let Some(position) = received.windows(4).position(|part| part == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&received[..head])?;
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .context("missing content length")?;
    while received.len() < head + length {
        let count = socket.read(&mut buf)?;
        anyhow::ensure!(count > 0, "loopback request ended before body");
        received.extend_from_slice(&buf[..count]);
    }
    let _: serde_json::Value = serde_json::from_slice(&received[head..head + length])?;
    Ok(())
}
fn write_response(socket: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let payload = if status == 200 {
        serde_json::json!({"id":"packaged-probe","object":"chat.completion","created":0,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":body},"finish_reason":"stop"}]}).to_string()
    } else {
        serde_json::json!({"error":{"message":body}}).to_string()
    };
    let reason = if status == 200 {
        "OK"
    } else {
        "Internal Server Error"
    };
    write!(
        socket,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    )?;
    Ok(())
}
fn write_stream_prefix(socket: &mut TcpStream) -> Result<()> {
    write!(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\ndata: {{\"id\":\"packaged-probe\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"packaged-chat-\"}},\"finish_reason\":null}}]}}\n\n"
    )?;
    socket.flush()?;
    Ok(())
}
fn write_stream_finish(socket: &mut TcpStream) -> Result<()> {
    write!(
        socket,
        "data: {{\"id\":\"packaged-probe\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"probe-success\"}},\"finish_reason\":\"stop\"}}]}}\n\ndata: [DONE]\n\n"
    )?;
    socket.flush()?;
    Ok(())
}

fn isolated_home() -> Result<PathBuf> {
    let mut entropy = [0u8; 16];
    getrandom::getrandom(&mut entropy)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let home = std::env::temp_dir().join(format!(
        "neoth-packaged-chat-{:x}-{}",
        stamp,
        hex::encode(entropy)
    ));
    fs::create_dir_all(&home)?;
    Ok(home)
}
fn seed_home(home: &Path, endpoint: &str) -> Result<()> {
    let config = neothd::config::FreedomConfig {
        autonomy: neothd::permissions::AutonomyLevel::Full,
        provider_kind: Some(neothd::cli::init::ProviderKind::OpenaiCompat),
        provider_endpoint: Some(endpoint.to_owned()),
        provider_model: Some("gpt-4o".to_owned()),
        onboarding_complete: true,
        ..Default::default()
    };
    fs::write(home.join("freedom.yaml"), serde_yaml::to_string(&config)?)?;
    fs::write(
        home.join("credentials.yaml"),
        format!("provider_key: {PROBE_KEY}\n"),
    )?;
    let marker = neothd::consent::marker_path(home, neothd::cli::init::ProviderKind::OpenaiCompat);
    let mut endpoints = std::collections::BTreeMap::new();
    endpoints.insert(endpoint.to_owned(), "1");
    fs::write(
        marker,
        serde_json::to_vec(&serde_json::json!({"version":1,"endpoints":endpoints}))?,
    )?;
    Ok(())
}
fn spawn_daemon(home: &Path) -> Result<Child> {
    // A packaged acceptance is meaningful only when it uses the exact daemon
    // bundled beside this GUI (on macOS: Contents/MacOS). PATH and a checkout
    // fallback would turn this into a developer-machine probe.
    let gui =
        std::fs::canonicalize(std::env::current_exe().context("resolve packaged GUI executable")?)?;
    let directory = gui
        .parent()
        .context("packaged GUI has no executable directory")?;
    let binary = if cfg!(windows) {
        ["neothd.exe", "neoth.exe"]
    } else {
        ["neothd", "neoth"]
    }
    .into_iter()
    .map(|name| directory.join(name))
    .find(|candidate| candidate.is_file())
    .context("bundled neothd sibling missing beside packaged GUI")?;
    Command::new(binary)
        .arg("serve")
        .arg("--config")
        .arg(home.join("freedom.yaml"))
        .env("NEOTH_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start packaged sibling daemon")
}
fn wait_for_attested_bridge(home: &Path, daemon: &Child) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if neothd::daemon::gui_chat_bridge::bridge_for_attested_current_instance().is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "packaged daemon did not attest GUI chat at {} (pid {})",
                home.display(),
                daemon.id()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn write_startup_failure_receipt(
    path: &Path,
    daemon_pid: u32,
    exit: Option<i32>,
    reason: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let value = serde_json::json!({"schema":"neoth-packaged-chat-probe/v1","result":"failed","failure":"source-ready-failed","reason":reason,"gui_pid":std::process::id(),"daemon_pid":daemon_pid,"daemon_exit_success":exit == Some(0),"home_removed":true,"provider_requests":0,"checks":{"source_ready":false}});
    fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}
fn write_receipt(
    path: &Path,
    state: &ProbeState,
    requests: usize,
    daemon_pid: u32,
    result: Option<&str>,
) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(state.success_turn.as_deref().unwrap_or(""));
    let nonce_hash = hex::encode(hasher.finalize());
    let passed = result.is_none();
    let value = serde_json::json!({"schema":"neoth-packaged-chat-probe/v1","result":if passed {"passed"} else {"failed"},"failure":result,"gui_pid":std::process::id(),"daemon_pid":daemon_pid,"daemon_exit_success":serde_json::Value::Null,"home_removed":false,"nonce_hash":nonce_hash,"turn_ids":{"reattached":state.success_turn,"provider_failure":state.error_turn,"cancelled":state.cancel_turn},"operations":{"before_handoff":state.success_operation_before,"after_handoff":state.success_operation_after},"cursors":{"before_handoff":state.success_cursor_before,"after_handoff":state.success_cursor_after},"phases":{"reattach":state.reattach_phase,"provider_failure_terminal":state.error_terminal,"cancellation_terminal":state.cancel_terminal},"provider_requests":requests,"deadline_ms":TIMEOUT.as_millis(),"checks":{"same_turn_reopen":state.success_turn.is_some(),"fresh_main_operation":state.success_operation_after > state.success_operation_before,"cursor_monotonic":state.success_cursor_after >= state.success_cursor_before,"provider_failure_terminal":state.error_terminal,"cancellation_terminal":state.cancel_terminal,"buddy_partial_visible":state.buddy_partial_visible,"main_buddy_parity":state.buddy_partial_visible && state.success_visible_exact,"deduplicated_visible_completion":state.success_visible_exact && requests == 3}});
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}
