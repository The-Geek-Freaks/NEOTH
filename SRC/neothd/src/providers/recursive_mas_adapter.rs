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
//! operator acknowledgement marker (`~/.neoth/rmas_consent_acknowledged`)
//! so enabling the flag alone can't silently execute third-party code.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::config::RecursiveMasConfig;
use crate::providers::{Completion, Provider, Request};

/// Local ML inference is slow — generous per-completion ceiling.
const SIDECAR_TIMEOUT: Duration = Duration::from_secs(120);

/// Consent marker file name under `~/.neoth/`.
pub const CONSENT_MARKER: &str = "rmas_consent_acknowledged";

pub struct RecursiveMasAdapter {
    child: Arc<Mutex<std::process::Child>>,
    stdin: Arc<Mutex<std::process::ChildStdin>>,
    stdout: Arc<Mutex<BufReader<std::process::ChildStdout>>>,
    style: String,
    rounds: u8,
}

impl RecursiveMasAdapter {
    /// Gate + consent-check + spawn. Errors are operator-actionable.
    pub fn spawn(cfg: &RecursiveMasConfig) -> Result<Self> {
        let home = crate::config::FreedomConfig::default_neoth_home();
        // Probe VRAM only when the master switch is on (probe shells out
        // to nvidia-smi/rocm-smi — pointless for the disabled early-exit).
        let vram = if cfg.enabled {
            crate::daemon::hardware::probe(&home).vram
        } else {
            None
        };
        crate::providers::recursive_mas::recursive_mas_available(cfg, vram.as_ref())
            .map_err(|reason| anyhow::anyhow!("recursive_mas unavailable: {reason}"))?;

        let marker = home.join(CONSENT_MARKER);
        if !marker.exists() {
            anyhow::bail!(
                "RecursiveMAS consent marker missing. This runs OPERATOR-INSTALLED \
                 third-party code with an unresolved upstream license — review the \
                 upstream repository yourself, then create the empty file {} to \
                 acknowledge. NEOTH never downloads or updates the sidecar.",
                marker.display()
            );
        }

        // The RMAS-02 gate guarantees sidecar_repo is Some + marker file present.
        let repo = cfg
            .sidecar_repo
            .as_ref()
            .context("recursive_mas.sidecar_repo unset (gate should have refused)")?;
        let python = cfg
            .sidecar_python
            .clone()
            .unwrap_or_else(|| "python".into());

        let mut child = std::process::Command::new(&python)
            .arg(repo.join("inference_mas.py"))
            .arg("--style")
            .arg(&cfg.style)
            .arg("--rounds")
            .arg(cfg.num_recursive_rounds.to_string())
            .current_dir(repo)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| {
                format!(
                    "spawn RecursiveMAS sidecar: {} {}",
                    python.display(),
                    repo.join("inference_mas.py").display()
                )
            })?;

        let stdin = child.stdin.take().context("sidecar stdin unavailable")?;
        let stdout = child.stdout.take().context("sidecar stdout unavailable")?;
        tracing::info!(
            repo = %repo.display(),
            style = %cfg.style,
            rounds = cfg.num_recursive_rounds,
            "RecursiveMAS sidecar spawned (EXPERIMENTAL)"
        );
        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            stdin: Arc::new(Mutex::new(stdin)),
            stdout: Arc::new(Mutex::new(BufReader::new(stdout))),
            style: cfg.style.clone(),
            rounds: cfg.num_recursive_rounds,
        })
    }
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

    async fn complete(&self, req: Request) -> Result<Completion> {
        let started = Instant::now();
        let line = encode_request(&req, &self.style, self.rounds);

        let stdin = Arc::clone(&self.stdin);
        let stdout = Arc::clone(&self.stdout);
        // Blocking pipe I/O off the reactor; locks live entirely inside
        // the blocking closure (never across an .await).
        let io = tokio::task::spawn_blocking(move || -> Result<String> {
            {
                let mut w = stdin.lock().unwrap_or_else(PoisonError::into_inner);
                w.write_all(line.as_bytes()).context("write to sidecar stdin")?;
                w.flush().context("flush sidecar stdin")?;
            }
            let mut buf = String::new();
            let mut r = stdout.lock().unwrap_or_else(PoisonError::into_inner);
            let n = r.read_line(&mut buf).context("read sidecar stdout")?;
            if n == 0 {
                anyhow::bail!("sidecar closed stdout (process died?)");
            }
            Ok(buf)
        });
        let reply = tokio::time::timeout(SIDECAR_TIMEOUT, io)
            .await
            .map_err(|_| anyhow::anyhow!("sidecar timed out after {SIDECAR_TIMEOUT:?}"))?
            .context("sidecar I/O task panicked")??;

        let text = parse_response_line(&reply)?;
        Ok(Completion {
            text,
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

/// True when the marker exists — shared helper for call sites that want
/// to pre-check without constructing the adapter.
pub fn consent_acknowledged(home: &Path) -> bool {
    home.join(CONSENT_MARKER).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_refuses_when_disabled() {
        let cfg = RecursiveMasConfig::default();
        let err = RecursiveMasAdapter::spawn(&cfg)
            .err()
            .expect("default config must refuse")
            .to_string();
        assert!(err.contains("disabled"), "got: {err}");
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

    #[test]
    fn consent_helper_reflects_marker_presence() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!consent_acknowledged(dir.path()));
        std::fs::write(dir.path().join(CONSENT_MARKER), "").unwrap();
        assert!(consent_acknowledged(dir.path()));
    }
}
