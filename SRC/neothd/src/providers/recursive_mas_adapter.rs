//! GOLD-ADAPT-RMAS-03 — RecursiveMAS Python sidecar adapter.
//!
//! ⚠ EXPERIMENTAL, `recursive-mas` Cargo feature only. Spawns the
//! OPERATOR-INSTALLED RecursiveMAS checkout (`inference_mas.py`) as a
//! long-lived child process and talks JSON-over-stdio:
//!
//! ```text
//! → {"prompt": "...", "system": "...", "style": "...", "rounds": N}\n
//! ← {"response": "..."}\n            (or {"error": "..."})
//! ```
//!
//! Lifecycle mirrors `transport::hysteria::HysteriaSupervisor`: the child
//! is killed + reaped on Drop (poison-recovering lock). No watchdog — a
//! dead sidecar surfaces as a completion error and the council falls
//! back to the standard hemispheres (fail-open at the call site).
//!
//! ## Sovereignty / license
//!
//! Upstream RecursiveMAS has no resolved license → NEOTH never vendors,
//! downloads, or updates it. `spawn` additionally requires a one-time
//! operator acknowledgement marker in the exact active NEOTH instance home,
//! so enabling the flag or acknowledging a different instance cannot silently
//! execute third-party code.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::config::RecursiveMasConfig;
use crate::providers::{
    ChatTurnEffectKind, Completion, EffectOwnerCancellation, EffectOwnerRegistration, Provider,
    ProviderDispatchPermit, ProviderRequestControls, Request, TurnEffectOwner,
};

/// Local ML inference is slow — generous per-completion ceiling.
const SIDECAR_TIMEOUT: Duration = Duration::from_secs(120);
/// Byte ceiling for one sidecar response line. The timeout cannot interrupt a
/// blocking read, so the read itself has to stop.
const MAX_SIDECAR_LINE_BYTES: usize = 1024 * 1024;

/// Consent marker file name under `~/.neoth/`. Re-exported from the
/// always-compiled `recursive_mas` gate module so the CLI write path and this
/// spawn-time check use one shared constant.
pub use super::recursive_mas::CONSENT_MARKER;

pub struct RecursiveMasAdapter {
    child: Arc<Mutex<std::process::Child>>,
    containment: Arc<Mutex<SidecarContainment>>,
    // ONE mutex over the whole request→response turn: with separate
    // stdin/stdout locks, concurrent complete() calls could interleave
    // (A writes, B writes, B reads A's reply). The stdio protocol has no
    // request IDs, so the turn itself must be the critical section.
    io: Arc<Mutex<SidecarIo>>,
    style: String,
    rounds: u8,
}

enum SidecarContainment {
    #[cfg(windows)]
    Windows(crate::updater::process_containment::WindowsProcessJob),
    #[cfg(unix)]
    Unix(crate::updater::process_containment::UnixProcessGroup),
}

/// Owns a just-spawned suspended Windows sidecar until all setup steps have
/// succeeded. `std::process::Child` does not reap on Drop; without this guard,
/// assignment, resume, or pipe-acquisition failure can strand a suspended
/// process outside the Job Object.
#[cfg(windows)]
struct PendingWindowsSidecar {
    child: Option<std::process::Child>,
    job: Option<crate::updater::process_containment::WindowsProcessJob>,
}

#[cfg(windows)]
impl PendingWindowsSidecar {
    fn new(
        child: std::process::Child,
        job: crate::updater::process_containment::WindowsProcessJob,
    ) -> Self {
        Self {
            child: Some(child),
            job: Some(job),
        }
    }

    fn assign_and_resume(&self) -> Result<()> {
        let child = self
            .child
            .as_ref()
            .expect("pending Windows sidecar child missing");
        let job = self
            .job
            .as_ref()
            .expect("pending Windows sidecar Job Object missing");
        job.assign_std_child(child)?;
        job.resume_std_child(child)
    }

    fn child_mut(&mut self) -> &mut std::process::Child {
        self.child
            .as_mut()
            .expect("pending Windows sidecar child missing")
    }

    fn into_parts(
        mut self,
    ) -> (
        std::process::Child,
        crate::updater::process_containment::WindowsProcessJob,
    ) {
        (
            self.child
                .take()
                .expect("pending Windows sidecar child missing"),
            self.job
                .take()
                .expect("pending Windows sidecar Job Object missing"),
        )
    }
}

#[cfg(windows)]
impl Drop for PendingWindowsSidecar {
    fn drop(&mut self) {
        // The Job may still be empty if assignment failed, so always finish
        // with the direct leader kill/wait as well. `TerminateProcess` kills a
        // suspended child, and a successful assignment makes the first call
        // terminate all descendants before the leader is reaped.
        if let Some(job) = self.job.as_ref() {
            let _ = job.terminate();
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct SidecarIo {
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl RecursiveMasAdapter {
    /// Gate + consent-check + spawn. Errors are operator-actionable.
    pub fn spawn(cfg: &RecursiveMasConfig, home: &std::path::Path) -> Result<Self> {
        if !cfg.enabled {
            anyhow::bail!(
                "recursive_mas unavailable: {}",
                crate::providers::recursive_mas::RmasUnavailableReason::Disabled
            );
        }
        // Consent BEFORE the hardware probe (error-hunt wave s4): the
        // probe shells out to nvidia-smi/rocm-smi — no subprocess work
        // until the operator has acknowledged running third-party code.
        if !crate::providers::recursive_mas::code_acknowledgement_present(home)? {
            anyhow::bail!(
                "RecursiveMAS code acknowledgement is missing. This runs OPERATOR-INSTALLED \
                 third-party code with an unresolved upstream license — review the \
                 upstream repository yourself, then run \
                 `neoth rmas consent --acknowledge --home {:?}` for this exact instance. \
                 NEOTH never downloads or updates the sidecar.",
                home
            );
        }
        let vram = crate::daemon::hardware::probe(home)?.vram;
        crate::providers::recursive_mas::recursive_mas_available(cfg, vram.as_ref())
            .map_err(|reason| anyhow::anyhow!("recursive_mas unavailable: {reason}"))?;

        // The RMAS-02 gate guarantees sidecar_repo is Some + marker file present.
        let repo = cfg
            .sidecar_repo
            .as_ref()
            .context("recursive_mas.sidecar_repo unset (gate should have refused)")?;
        let python = cfg
            .sidecar_python
            .clone()
            .unwrap_or_else(|| "python".into());

        let mut command = std::process::Command::new(&python);
        command
            .arg(repo.join("inference_mas.py"))
            .arg("--style")
            .arg(&cfg.style)
            .arg("--rounds")
            .arg(cfg.num_recursive_rounds.to_string())
            .current_dir(repo)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            // stderr inherits the daemon's stderr: a crashing sidecar
            // (import error, CUDA OOM) must leave a visible trace —
            // Stdio::null() made respawn-after-crash undiagnosable.
            .stderr(std::process::Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            command.creation_flags(0x0000_0004 | 0x0800_0000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        #[cfg(windows)]
        let job = crate::updater::process_containment::WindowsProcessJob::create()?;
        let child = command.spawn().with_context(|| {
            format!(
                "spawn RecursiveMAS sidecar: {} {}",
                python.display(),
                repo.join("inference_mas.py").display()
            )
        })?;
        #[cfg(windows)]
        let mut pending_windows_sidecar = PendingWindowsSidecar::new(child, job);
        #[cfg(windows)]
        pending_windows_sidecar.assign_and_resume()?;
        #[cfg(unix)]
        let mut child = child;
        #[cfg(unix)]
        let containment = SidecarContainment::Unix(
            crate::updater::process_containment::UnixProcessGroup::from_spawned_pid(child.id())?,
        );

        #[cfg(windows)]
        let stdin = pending_windows_sidecar
            .child_mut()
            .stdin
            .take()
            .context("sidecar stdin unavailable")?;
        #[cfg(unix)]
        let stdin = child.stdin.take().context("sidecar stdin unavailable")?;
        #[cfg(windows)]
        let stdout = pending_windows_sidecar
            .child_mut()
            .stdout
            .take()
            .context("sidecar stdout unavailable")?;
        #[cfg(unix)]
        let stdout = child.stdout.take().context("sidecar stdout unavailable")?;
        #[cfg(windows)]
        let (child, containment) = pending_windows_sidecar.into_parts();
        #[cfg(windows)]
        let containment = SidecarContainment::Windows(containment);
        tracing::info!(
            repo = %repo.display(),
            style = %cfg.style,
            rounds = cfg.num_recursive_rounds,
            "RecursiveMAS sidecar spawned (EXPERIMENTAL)"
        );
        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            containment: Arc::new(Mutex::new(containment)),
            io: Arc::new(Mutex::new(SidecarIo {
                stdin,
                stdout: BufReader::new(stdout),
            })),
            style: cfg.style.clone(),
            rounds: cfg.num_recursive_rounds,
        })
    }
}

impl RecursiveMasAdapter {
    /// Terminate and reap the sidecar after a protocol failure.
    ///
    /// The adapter is dead afterwards; the council falls back to the standard
    /// hemispheres. That is strictly better than answering request N+1 with
    /// leftover bytes from request N.
    fn kill_sidecar(&self) {
        kill_sidecar_child(&self.child, &self.containment);
    }
}

fn kill_sidecar_child(
    child: &Arc<Mutex<std::process::Child>>,
    containment: &Arc<Mutex<SidecarContainment>>,
) {
    let mut containment = containment.lock().unwrap_or_else(PoisonError::into_inner);
    match &mut *containment {
        #[cfg(windows)]
        SidecarContainment::Windows(job) => {
            let _ = job.terminate();
        }
        #[cfg(unix)]
        SidecarContainment::Unix(group) => {
            let _ = group.terminate();
        }
    }
    let mut child = child.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = child.kill();
    let _ = child.wait();
}

/// Owns one blocking request worker. The caller awaits this handle directly;
/// any early exit kills the sidecar and hands the join to the turn owner.
struct SidecarRequestOwner {
    completion: tokio::sync::oneshot::Receiver<Result<String>>,
    local_drain: Option<TurnEffectOwner>,
    cancellation: EffectOwnerCancellation,
    start_permit: Option<std::sync::mpsc::Sender<()>>,
    resume_after_started: Option<std::sync::mpsc::Sender<()>>,
    armed: bool,
}

impl SidecarRequestOwner {
    async fn abort_and_join(&mut self) {
        self.cancellation.cancel();
        self.start_permit.take();
        self.resume_after_started.take();
        if let Some(owner) = self.local_drain.take() {
            owner.drain().await;
        }
        let _ = (&mut self.completion).await;
    }

    fn resume_body_read(&mut self) -> Result<()> {
        self.resume_after_started
            .take()
            .context("sidecar worker resume channel missing")?
            .send(())
            .map_err(|_| anyhow::anyhow!("sidecar worker exited before response-body permission"))
    }

    async fn join_after_resume(&mut self) -> Result<String> {
        if let Some(owner) = self.local_drain.take() {
            owner.drain().await;
        }
        let result = (&mut self.completion)
            .await
            .map_err(|_| anyhow::anyhow!("turn-owned sidecar worker drain dropped"))?;
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Drop for SidecarRequestOwner {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.cancellation.cancel();
        let Some(owner) = self.local_drain.take() else {
            return;
        };
        // Direct/None callers have no daemon JoinSet. The native thread is
        // deliberately joined here, so future cancellation cannot return
        // while a local sidecar worker still owns pipe I/O.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            std::thread::scope(|scope| {
                let drain = scope.spawn(move || runtime.block_on(owner.drain()));
                let _ = drain.join();
            });
        }
    }
}

fn spawn_sidecar_request_worker(
    io_arc: Arc<Mutex<SidecarIo>>,
    line: String,
    committed: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
    start_permit: std::sync::mpsc::Receiver<()>,
    resume_after_started: std::sync::mpsc::Receiver<()>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<Result<String>> {
    tokio::task::spawn_blocking(move || -> Result<String> {
        loop {
            match start_permit.recv_timeout(Duration::from_millis(50)) {
                Ok(()) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    if !cancelled.load(std::sync::atomic::Ordering::Acquire) =>
                {
                    continue;
                }
                Err(_) => {
                    anyhow::bail!("sidecar request cancelled before owned start registration")
                }
            }
        }
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            anyhow::bail!("sidecar request cancelled before owned start registration");
        }
        let mut io = io_arc.lock().unwrap_or_else(PoisonError::into_inner);
        // This write plus flush is the sidecar request commit. No response
        // byte is read until the async owner durably records Started.
        if let Err(error) = io
            .stdin
            .write_all(line.as_bytes())
            .and_then(|_| io.stdin.flush())
        {
            let _ = committed.send(Err(error.to_string()));
            return Err(error).context("commit request to sidecar stdin");
        }
        let _ = committed.send(Ok(()));
        loop {
            match resume_after_started.recv_timeout(Duration::from_millis(50)) {
                Ok(()) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    if !cancelled.load(std::sync::atomic::Ordering::Acquire) =>
                {
                    continue;
                }
                Err(_) => anyhow::bail!("sidecar response read cancelled before Started ACK"),
            }
        }
        let mut buf = Vec::new();
        let n = (&mut io.stdout)
            .take(MAX_SIDECAR_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)
            .context("read sidecar stdout")?;
        if n == 0 {
            anyhow::bail!("sidecar closed stdout (process died?)");
        }
        if n > MAX_SIDECAR_LINE_BYTES {
            anyhow::bail!("sidecar response line exceeded {MAX_SIDECAR_LINE_BYTES} bytes");
        }
        String::from_utf8(buf).context("sidecar stdout line is not valid UTF-8")
    })
}

/// Build the one-line JSON request the sidecar consumes.
fn encode_request(req: &Request, style: &str, rounds: u8) -> String {
    let mut line = serde_json::json!({
        "prompt": req.prompt,
        "style": style,
        "rounds": rounds,
    });
    if let Some(sys) = &req.system {
        line["system"] = serde_json::Value::String(sys.clone());
    }
    format!("{line}\n")
}

/// Parse the sidecar's one-line JSON reply. Public-in-module so the
/// protocol is unit-testable without a live python.
fn parse_response_line(line: &str) -> Result<String> {
    let v: serde_json::Value =
        serde_json::from_str(line.trim()).context("sidecar reply is not JSON")?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        anyhow::bail!("sidecar error: {err}");
    }
    v.get("response")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .context("sidecar reply missing `response` field")
}

#[async_trait]
impl Provider for RecursiveMasAdapter {
    fn name(&self) -> &'static str {
        "recursive_mas"
    }

    #[expect(
        private_interfaces,
        reason = "the private W41 probe seals this hook to reviewed in-crate adapters"
    )]
    fn w41_effect_start_adapter(&self, _: super::W41EffectStartProbe) -> bool {
        true
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::NONE
    }

    fn default_model(&self) -> Option<&str> {
        Some("recursive_mas")
    }

    fn consent_route(&self) -> Option<crate::consent::ConsentRoute> {
        Some(crate::consent::ConsentRoute::new(
            crate::cli::init::ProviderKind::RecursiveMas,
            None,
        ))
    }

    async fn complete_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        let started = Instant::now();
        let line = encode_request(&req, &self.style, self.rounds);

        let io_arc = Arc::clone(&self.io);
        let effect = permit
            .prepare_effect(ChatTurnEffectKind::Provider {
                call_scope: "recursive_mas.sidecar_request",
                streaming: false,
            })
            .await?;
        let lease = match effect {
            Some(effect) => Some(effect.begin_start().await?),
            None => None,
        };
        let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation_child = Arc::clone(&self.child);
        let cancellation_containment = Arc::clone(&self.containment);
        let cancellation_flag = Arc::clone(&cancelled);
        let cancellation = EffectOwnerCancellation::new(move || {
            cancellation_flag.store(true, std::sync::atomic::Ordering::Release);
            kill_sidecar_child(&cancellation_child, &cancellation_containment);
        });
        let join =
            spawn_sidecar_request_worker(io_arc, line, commit_tx, start_rx, resume_rx, cancelled);
        let (completion_tx, completion) = tokio::sync::oneshot::channel();
        let drain = Box::pin(async move {
            let result = join
                .await
                .context("sidecar I/O task panicked")
                .and_then(|result| result);
            let _ = completion_tx.send(result);
        });
        // This synchronous call transfers the GUI owner into the daemon
        // JoinSet before it returns. An error has already been cancelled and
        // drained by that gate; `Some` is the direct/None local owner.
        let local_drain =
            match permit.register_effect_owner(TurnEffectOwner::new(drain, cancellation.clone())) {
                EffectOwnerRegistration::Local(owner) => Some(owner),
                EffectOwnerRegistration::Registered => None,
                EffectOwnerRegistration::Transferred { error } => {
                    return Err(error).context("transfer RecursiveMAS worker owner");
                }
                EffectOwnerRegistration::Untransferred { error, owner } => {
                    // The worker has not received its start permit. Retain the
                    // returned local owner before the cancellation/join await.
                    let mut rejected = SidecarRequestOwner {
                        completion,
                        local_drain: Some(owner),
                        cancellation: cancellation.clone(),
                        start_permit: Some(start_tx),
                        resume_after_started: Some(resume_tx),
                        armed: true,
                    };
                    rejected.abort_and_join().await;
                    return Err(error).context("register RecursiveMAS worker owner");
                }
            };
        let mut owner = SidecarRequestOwner {
            completion,
            local_drain,
            cancellation,
            start_permit: Some(start_tx),
            resume_after_started: Some(resume_tx),
            armed: true,
        };
        owner
            .start_permit
            .take()
            .context("sidecar worker start permit missing")?
            .send(())
            .map_err(|_| anyhow::anyhow!("sidecar worker exited before registered start"))?;
        // Wait for the actual sidecar request commit, then ACK Started before
        // granting the worker permission to consume the response body.
        if let Some(lease) = lease {
            let committed = match tokio::time::timeout_at(lease.deadline(), commit_rx).await {
                Ok(Ok(Ok(()))) => {
                    if let Err(error) = lease.started().await {
                        owner.abort_and_join().await;
                        return Err(error).context("ack RecursiveMAS request start");
                    }
                    true
                }
                Ok(Ok(Err(error))) => {
                    lease.indeterminate().await?;
                    owner.abort_and_join().await;
                    return Err(anyhow::anyhow!(
                        "RecursiveMAS request write outcome is unknown: {error}"
                    ));
                }
                Ok(Err(_)) | Err(_) => {
                    lease.indeterminate().await?;
                    owner.abort_and_join().await;
                    return Err(anyhow::anyhow!(
                        "RecursiveMAS request-start handshake did not confirm a committed write"
                    ));
                }
            };
            debug_assert!(committed);
        }
        if let Err(error) = owner.resume_body_read() {
            owner.abort_and_join().await;
            return Err(error);
        }
        let reply = match tokio::time::timeout(SIDECAR_TIMEOUT, owner.join_after_resume()).await {
            Ok(joined) => match joined {
                Ok(reply) => reply,
                Err(framing) => {
                    // The stream is a single long-lived pipe with no request
                    // ids. After an oversize or invalid line, the unread
                    // remainder of THIS response is still queued, and the next
                    // request would read that suffix as its own answer. Kill
                    // the child so the desynchronised stream cannot be reused.
                    self.kill_sidecar();
                    return Err(framing.context(
                        "sidecar framing failure — child killed to prevent a                          desynchronised stream serving the next request",
                    ));
                }
            },
            Err(_elapsed) => {
                // Error-hunt wave s4: the blocking thread is still stuck
                // in read_line HOLDING the io lock — spawn_blocking
                // threads can't be aborted. Kill the child so read_line
                // unblocks (EOF) and the lock frees; otherwise every
                // later complete() queues on the lock forever and the
                // blocking pool fills with stuck threads.
                owner.abort_and_join().await;
                anyhow::bail!(
                    "sidecar timed out after {SIDECAR_TIMEOUT:?} — child killed \
                     (adapter is dead; council falls back to standard hemispheres)"
                );
            }
        };

        // A reply that does not parse leaves the protocol in the same doubt as
        // an oversize one: reset rather than guess.
        let text = match parse_response_line(&reply) {
            Ok(text) => text,
            Err(malformed) => {
                self.kill_sidecar();
                return Err(malformed.context("sidecar reply unparseable — child killed"));
            }
        };
        Ok(Completion {
            termination: Default::default(),
            text,
            identity: Default::default(),
            model: "recursive-mas".to_string(),
            latency: started.elapsed(),
            ..Default::default()
        })
    }
}

impl Drop for RecursiveMasAdapter {
    fn drop(&mut self) {
        let mut child = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_refuses_when_disabled() {
        let cfg = RecursiveMasConfig::default();
        let home = tempfile::tempdir().unwrap();
        let err = RecursiveMasAdapter::spawn(&cfg, home.path())
            .err()
            .expect("default config must refuse")
            .to_string();
        assert!(err.contains("disabled"), "got: {err}");
    }

    #[test]
    fn spawn_does_not_inherit_acknowledgement_from_another_instance() {
        let acknowledged_home = tempfile::tempdir().unwrap();
        let selected_home = tempfile::tempdir().unwrap();
        crate::cli::rmas::write_rmas_consent_marker(acknowledged_home.path()).unwrap();
        let cfg = RecursiveMasConfig {
            enabled: true,
            ..RecursiveMasConfig::default()
        };

        let error = RecursiveMasAdapter::spawn(&cfg, selected_home.path())
            .err()
            .expect("the selected instance has no code acknowledgement");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("code acknowledgement is missing"));
        assert!(rendered.contains(&format!("{:?}", selected_home.path())));
        assert!(!rendered.contains(&format!("{:?}", acknowledged_home.path())));
    }

    #[test]
    fn encode_request_includes_prompt_style_rounds_and_optional_system() {
        let req = Request {
            prompt: "Q".into(),
            system: Some("S".into()),
            ..Default::default()
        };
        let line = encode_request(&req, "sequential_light", 3);
        assert!(line.ends_with('\n'));
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["prompt"], "Q");
        assert_eq!(v["system"], "S");
        assert_eq!(v["style"], "sequential_light");
        assert_eq!(v["rounds"], 3);
    }

    #[test]
    fn explicit_output_cap_is_rejected_for_unbounded_sidecar_invocations() {
        let request = Request {
            max_output_tokens: Some(512),
            ..Request::default()
        };
        let error = ProviderRequestControls::NONE
            .validate("recursive_mas", &request)
            .expect_err("the sidecar protocol has no verified output-cap wire field");
        assert!(error.to_string().contains("max_output_tokens"));
    }

    #[test]
    fn parse_response_happy_error_and_malformed() {
        assert_eq!(
            parse_response_line("{\"response\":\"ok\"}\n").unwrap(),
            "ok"
        );
        let e = parse_response_line("{\"error\":\"boom\"}").unwrap_err();
        assert!(e.to_string().contains("boom"));
        assert!(parse_response_line("not json").is_err());
        assert!(parse_response_line("{}").is_err());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn w41_committed_sidecar_write_waits_for_started_ack_before_body_read() {
        use std::os::windows::process::CommandExt as _;

        use crate::providers::ChatTurnEffectGate;
        use crate::providers::effect_test_support::{RecordedPhase, RecordingEffectGate};

        // `set /p` blocks until the worker writes one line, then emits a
        // deterministic sidecar response. The worker must remain unfinished
        // after commit until this test durably acknowledges Started.
        let mut child = std::process::Command::new("cmd")
            // `cmd /c` does not use CRT argument parsing. The whole fixed
            // fixture tail is raw so the outer quotes and caret-quoted JSON
            // keys survive into `echo`; no test input is interpolated here.
            .args(["/D", "/S", "/C"])
            .raw_arg(r#""set /p request=& echo {^"response^":^"fixture^"}""#)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn controlled sidecar fixture");
        let stdin = child.stdin.take().expect("fixture stdin");
        let stdout = child.stdout.take().expect("fixture stdout");
        let io = Arc::new(Mutex::new(SidecarIo {
            stdin,
            stdout: BufReader::new(stdout),
        }));
        let gate = RecordingEffectGate::new(Duration::from_secs(2));
        let pending = gate
            .intent(
                ChatTurnEffectKind::Provider {
                    call_scope: "recursive_mas.sidecar_request",
                    streaming: false,
                },
                "fixture-binding",
            )
            .await
            .expect("reserve request effect");
        let lease = pending
            .begin_start()
            .await
            .expect("enter request handshake");
        let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut join = spawn_sidecar_request_worker(
            io,
            "fixture request\n".into(),
            committed_tx,
            start_rx,
            resume_rx,
            Arc::clone(&cancelled),
        );
        start_tx.send(()).expect("release registered test worker");

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), committed_rx)
                .await
                .expect("commit deadline")
                .expect("commit signal"),
            Ok(())
        );
        assert_eq!(gate.phase(), RecordedPhase::Handshaking);
        assert!(!join.is_finished(), "body read must wait for Started ACK");
        lease
            .started()
            .await
            .expect("durably acknowledge write commit");
        assert_eq!(gate.phase(), RecordedPhase::Started);
        resume_tx.send(()).expect("release response read after ACK");
        let reply = (&mut join)
            .await
            .expect("join controlled worker")
            .expect("read after ACK");
        assert_eq!(
            parse_response_line(&reply).expect("fixture JSON"),
            "fixture"
        );
        child.wait().expect("reap controlled sidecar fixture");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn w41_failed_start_ack_kills_and_joins_committed_sidecar_worker() {
        use std::os::windows::process::CommandExt as _;

        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let mut command = std::process::Command::new("cmd");
        command
            // Parent accepts the request, launches a descendant which keeps
            // inherited stdout open, then exits. `start /b` makes this a
            // real detached descendant: after the parent is reaped, EOF can
            // only arrive if the Job Object ends the remaining process tree.
            // Keep the complete trusted tail raw: `cmd /c` needs its outer
            // quote pair, while the inner caret quotes retain the `start`
            // title and the descendant's redirection for the nested cmd.
            .args(["/D", "/S", "/C"])
            .raw_arg(r#""set /p request=& start ^"fixture descendant^" /b cmd /d /s /c ^"ping -n 30 127.0.0.1 ^>nul^" & exit 0""#)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);

        // Exercise the exact production create → assign-suspended-child →
        // resume path. Assignment precedes any sidecar execution, so the
        // `start /b` grandchild is born inside the kill-on-close Job Object.
        let job = crate::updater::process_containment::WindowsProcessJob::create()
            .expect("create fixture Job Object");
        let mut child = command
            .spawn()
            .expect("spawn delayed controlled sidecar fixture");
        job.assign_std_child(&child)
            .expect("assign suspended fixture sidecar to Job Object");
        job.resume_std_child(&child)
            .expect("resume contained fixture sidecar");
        let stdin = child.stdin.take().expect("fixture stdin");
        let stdout = child.stdout.take().expect("fixture stdout");
        let child = Arc::new(Mutex::new(child));
        let containment = Arc::new(Mutex::new(SidecarContainment::Windows(job)));
        let io = Arc::new(Mutex::new(SidecarIo {
            stdin,
            stdout: BufReader::new(stdout),
        }));
        let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut join = spawn_sidecar_request_worker(
            io,
            "fixture request\n".into(),
            committed_tx,
            start_rx,
            resume_rx,
            Arc::clone(&cancelled),
        );
        start_tx.send(()).expect("release registered test worker");

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), committed_rx)
                .await
                .expect("commit deadline")
                .expect("commit signal"),
            Ok(())
        );
        resume_tx.send(()).expect("release blocked response read");

        // The direct parent is gone while its `start /b` descendant still
        // owns stdout. A clean EOF before cancellation would mean the fixture
        // stopped modeling the pipe-retention failure.
        let mut parent_reaped = false;
        for _ in 0..100 {
            if child
                .lock()
                .expect("fixture child lock")
                .try_wait()
                .expect("fixture parent status")
                .is_some()
            {
                parent_reaped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            parent_reaped,
            "fixture parent must exit after starting its descendant"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut join)
                .await
                .is_err(),
            "grandchild must retain stdout and keep the response read blocked"
        );

        // Model an ACK/deadline failure after the write commit and body-read
        // release. The same containment-aware cancellation as production
        // terminates the Job before the local owner drains its worker.
        let cancellation_child = Arc::clone(&child);
        let cancellation_containment = Arc::clone(&containment);
        let cancellation_flag = Arc::clone(&cancelled);
        let cancellation_completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation_completed_for_callback = Arc::clone(&cancellation_completed);
        let cancellation = EffectOwnerCancellation::new(move || {
            cancellation_flag.store(true, std::sync::atomic::Ordering::Release);
            kill_sidecar_child(&cancellation_child, &cancellation_containment);
            cancellation_completed_for_callback.store(true, std::sync::atomic::Ordering::Release);
        });
        let (completion_tx, completion) = tokio::sync::oneshot::channel();
        let worker_reaped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_reaped_for_drain = Arc::clone(&worker_reaped);
        let drain = Box::pin(async move {
            let result = join
                .await
                .context("fixture worker join")
                .and_then(|result| result);
            worker_reaped_for_drain.store(true, std::sync::atomic::Ordering::Release);
            let _ = completion_tx.send(result);
        });
        let owner = SidecarRequestOwner {
            completion,
            local_drain: Some(TurnEffectOwner::new(drain, cancellation.clone())),
            cancellation,
            start_permit: None,
            resume_after_started: None,
            armed: true,
        };
        // This is the None-path future-drop regression: Drop must not return
        // until the Job closes the grandchild's inherited stdout, cancellation
        // reaps the child, and the local drain joins the blocked worker.
        drop(owner);
        assert!(
            cancellation_completed.load(std::sync::atomic::Ordering::Acquire),
            "None-path drop must complete containment cancellation before returning"
        );
        assert!(
            worker_reaped.load(std::sync::atomic::Ordering::Acquire),
            "None-path drop must wait for the formerly blocked worker to join"
        );
        assert!(
            child
                .lock()
                .expect("fixture child lock")
                .try_wait()
                .expect("fixture child status")
                .is_some(),
            "containment cancellation must leave the parent reaped"
        );
    }
}
