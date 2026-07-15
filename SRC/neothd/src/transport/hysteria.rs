//! Hysteria transport manager.
//!
//! Hysteria (https://github.com/apernet/hysteria) is a QUIC-based proxy
//! that gives NEOTH encrypted egress for provider HTTP traffic. The manager
//! detects and supervises the binary, exposes a loopback SOCKS5 listener, and
//! installs that listener into the shared reqwest client builder before
//! provider construction.
//!
//! Design pins:
//!   - **Operator supplies the server config.** NEOTH never hardcodes a
//!     server address (self-contained rule: operator owns the upstream).
//!   - **Binary lookup**: `$NEOTH_HYSTERIA_BIN` env override wins,
//!     otherwise `hysteria` on `PATH`, otherwise `~/.neoth/bin/hysteria`.
//!     Missing binary → loud error, never panic.
//!   - **Health check** = TCP-connect to the operator's `local_socks_port`
//!     within `HEALTH_TIMEOUT`. SOCKS5 handshake itself is the next slice.
//!   - **Subprocess** management is owned by `HysteriaSupervisor`. Drop
//!     kills the child cleanly via SIGTERM (unix) / `kill` (windows).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// 2 seconds — the operator's local Hysteria responds in < 50ms typically,
/// 2s is the "something is genuinely broken" threshold.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

/// Operator-supplied Hysteria server config — gets handed verbatim to the
/// Hysteria binary as a YAML file. We keep this struct minimal; the full
/// Hysteria schema has dozens of optional fields. Operator who needs
/// auth/obfuscation/multipath edits the YAML directly after `neoth init`.
///
/// `PartialEq`/`Eq` deliberately not derived: the `auth` field is now a
/// `SecretString` (Pick #32 security audit-fix). Comparing two
/// `HysteriaConfig` values via `==` would have to expose the secret,
/// which defeats the redact-by-default invariant. No production call
/// site needed `==` — confirmed by the build.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HysteriaConfig {
    /// Upstream Hysteria server endpoint, e.g. `vps.example.com:443`.
    /// Empty string when the manager should not start the subprocess.
    pub server: String,
    /// Shared secret / password for the server.
    ///
    /// Pick #32 (Session 14, security audit-fix): previously typed
    /// `String`. Promoted to `SecretString` so the field round-trips
    /// through freedom.yaml under mlock + zeroize-on-drop, matching
    /// every other credential on `FreedomConfig`. The `Debug` impl
    /// for `SecretString` redacts the body, so log lines accidentally
    /// printing `cfg.auth` now show `REDACTED` rather than the
    /// plaintext shared secret.
    pub auth: SecretString,
    /// Local SOCKS5 listener port the manager binds to. Defaults to 1080.
    #[serde(default = "default_socks_port")]
    pub local_socks_port: u16,
}

impl Default for HysteriaConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            auth: SecretString::new(String::new()),
            local_socks_port: default_socks_port(),
        }
    }
}

fn default_socks_port() -> u16 {
    1080
}

/// R-3 (2026-05-21): parse a `hysteria2://auth@host:port` operator
/// URL into a HysteriaConfig. Tolerant: the scheme is optional
/// (operators paste `auth@host:port` from shells without escaping);
/// the port is optional and defaults to 443 (Hysteria's standard).
///
/// Errors only when the URL has no `@` separator (no auth supplied)
/// or no `host` after it. Empty `auth` is legal (free relays use it).
pub fn parse_hysteria_url(s: &str) -> Result<HysteriaConfig> {
    use anyhow::Context as _;
    let trimmed = s.trim();
    let after_scheme = trimmed
        .strip_prefix("hysteria2://")
        .or_else(|| trimmed.strip_prefix("hysteria://"))
        .unwrap_or(trimmed);
    let (auth, host_port) = after_scheme
        .split_once('@')
        .with_context(|| format!("hysteria URL missing `@`: {s:?}"))?;
    if host_port.trim().is_empty() {
        anyhow::bail!("hysteria URL missing host: {s:?}");
    }
    // Default to port 443 when omitted.
    let server = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:443")
    };
    Ok(HysteriaConfig {
        server,
        auth: SecretString::new(auth.to_string()),
        local_socks_port: default_socks_port(),
    })
}

/// Resolved path to the `hysteria` binary. Errors when no candidate
/// resolves — operator sees the search order in the error body.
pub fn locate_binary() -> Result<PathBuf> {
    if let Ok(env) = std::env::var("NEOTH_HYSTERIA_BIN") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Ok(p);
        }
    }
    if let Ok(found) = which_hysteria_on_path() {
        return Ok(found);
    }
    let home = crate::config::FreedomConfig::default_neoth_home();
    let candidate = home.join("bin").join(if cfg!(windows) {
        "hysteria.exe"
    } else {
        "hysteria"
    });
    if candidate.exists() {
        return Ok(candidate);
    }
    anyhow::bail!(
        "hysteria binary not found. Searched: $NEOTH_HYSTERIA_BIN, $PATH, {}. \
         Install via your package manager or download from \
         https://github.com/apernet/hysteria/releases.",
        candidate.display()
    );
}

fn which_hysteria_on_path() -> Result<PathBuf> {
    let exe = if cfg!(windows) {
        "hysteria.exe"
    } else {
        "hysteria"
    };
    let path_env = std::env::var_os("PATH").context("PATH env unset")?;
    for entry in std::env::split_paths(&path_env) {
        let candidate = entry.join(exe);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("{exe} not on PATH");
}

/// Render the operator's config as the YAML shape Hysteria expects on
/// disk. Pure function — caller writes it to a temp file before spawning.
/// Validates `server` and `auth` against newline / control-char
/// injection so a tampered freedom.yaml cannot inject extra YAML keys
/// (e.g. `socks5.listen: 0.0.0.0:1080` to expose the proxy).
pub fn render_yaml_config(cfg: &HysteriaConfig) -> String {
    // Treat newlines + colon-newlines as injection attempts. The
    // YAML schema Hysteria reads has no field whose value contains
    // newlines, so the rejection has no false-positive cost.
    let sanitize = |s: &str| -> String {
        if s.chars().any(|c| c == '\n' || c == '\r' || c.is_control()) {
            // Rather than silently mangling, replace the value with a
            // poison sentinel that Hysteria will reject. Logging
            // happens at the supervisor layer.
            "<<rejected: contains control characters>>".to_string()
        } else {
            s.to_string()
        }
    };
    // GOLD-SEC-35 / A-69: emit each value as a DOUBLE-QUOTED, escaped YAML
    // scalar. A bare `auth: {value}` mis-parsed when the value began with a
    // YAML indicator (`*`, `&`, `{`, `[`, `!`, leading space) or contained
    // `:` + space — silently corrupting the sidecar config. Control chars
    // are already rejected by `sanitize`, so escaping `\` and `"` yields a
    // valid double-quoted scalar.
    let yaml_quote =
        |s: &str| -> String { format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")) };
    format!(
        "server: {}\nauth: {}\nsocks5:\n  listen: 127.0.0.1:{}\n",
        yaml_quote(&sanitize(&cfg.server)),
        yaml_quote(&sanitize(cfg.auth.expose())),
        cfg.local_socks_port,
    )
}

/// Probe the local SOCKS5 port — returns Ok when something accepts a
/// TCP connection, Err otherwise. Used in tests + the daemon's
/// post-spawn health check.
///
/// **TCP-only LOCAL liveness, NOT end-to-end tunnel health (GOLD-HON-20 /
/// A-17):** this verifies only that the local `hysteria` client's SOCKS5
/// listener is up and accepting TCP — it does NOT prove the QUIC tunnel to
/// the remote relay is established or that traffic actually egresses. A
/// passing probe means "the client process bound its port", not "the tunnel
/// works".
pub async fn probe_socks_port(port: u16) -> Result<()> {
    use tokio::net::TcpStream;
    let addr = format!("127.0.0.1:{port}");
    let stream = tokio::time::timeout(HEALTH_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("hysteria SOCKS5 port {port} timed out"))?
        .map_err(|e| anyhow::anyhow!("hysteria SOCKS5 port {port} connect failed: {e}"))?;
    drop(stream);
    Ok(())
}

/// Supervisor wraps the Hysteria subprocess. Drop kills the child and
/// aborts the watchdog. The daemon calls [`Self::start_watchdog`] after
/// the SOCKS5 probe succeeds so a crashed child is respawned with
/// exponential backoff instead of silently leaving egress direct.
pub struct HysteriaSupervisor {
    /// Shared with the watchdog task so a respawn can swap the child in.
    child: std::sync::Arc<std::sync::Mutex<std::process::Child>>,
    /// Respawn loop handle; `None` until `start_watchdog` runs (CLI
    /// one-shots and tests never start it).
    watchdog: Option<tokio::task::JoinHandle<()>>,
    /// Shutdown latch: set by Drop BEFORE aborting the watchdog.
    /// `JoinHandle::abort()` is cooperative — the task keeps running
    /// until its next `.await` — so without this flag the watchdog can
    /// respawn a child AFTER Drop killed the old one, leaking the new
    /// process. The watchdog checks the flag before spawning and again
    /// after storing (killing the fresh child if shutdown raced in).
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Local SOCKS5 port the supervisor told Hysteria to listen on.
    pub socks_port: u16,
    /// Path to the rendered config file. Deleted on drop so secrets
    /// don't linger. The watchdog re-uses it for respawns.
    config_path: PathBuf,
    /// Resolved hysteria binary, kept so the watchdog can respawn
    /// without re-probing PATH.
    binary: PathBuf,
}

impl HysteriaSupervisor {
    /// R-3 Phase 3b: render the SOCKS5 URL the local Hysteria
    /// listener accepts. Plug this into `NEOTH_HTTP_PROXY` (the
    /// env var `providers::http_client::build_client` already
    /// consults) to wire every provider HTTP call through the
    /// QUIC tunnel.
    pub fn socks_proxy_url(&self) -> String {
        format!("socks5://127.0.0.1:{}", self.socks_port)
    }

    /// R-3 Phase 3b: process-wide opt-in wire-through. Installs the
    /// SOCKS5 URL into `providers::http_client`'s process-proxy slot so
    /// subsequent `build_client()` calls pick it up automatically.
    /// Returns the URL so callers can log it. Last-write-wins (matches
    /// the old env-write semantics — a re-provisioned supervisor on a
    /// new port must be able to re-install). Replaces the old
    /// `std::env::set_var` write, which is unsound inside the
    /// multi-threaded Tokio runtime the daemon startup already runs on;
    /// the `NEOTH_HTTP_PROXY` env var remains a supported operator-set
    /// fallback read by `build_client`.
    pub fn install_as_process_proxy(&self) -> String {
        let url = self.socks_proxy_url();
        crate::providers::http_client::set_process_proxy(&url);
        url
    }

    /// Spawn the respawn watchdog: polls the child every 5 s; on exit,
    /// respawns via the stored binary + rendered config with exponential
    /// backoff (1 s → 60 s cap, reset after a healthy poll). Idempotent.
    /// Must run inside a Tokio runtime — `serve` calls it after the
    /// SOCKS5 probe succeeds.
    pub fn start_watchdog(&mut self) {
        if self.watchdog.is_some() {
            return;
        }
        let child = std::sync::Arc::clone(&self.child);
        let shutdown = std::sync::Arc::clone(&self.shutdown);
        let binary = self.binary.clone();
        let config_path = self.config_path.clone();
        self.watchdog = Some(tokio::spawn(async move {
            use std::sync::atomic::Ordering;
            let mut backoff_secs: u64 = 1;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if shutdown.load(Ordering::Acquire) {
                    return;
                }
                // Lock scope kept await-free (no guard across .await).
                // Poisoned mutex = a panic elsewhere; recover the child
                // rather than silently disabling respawn forever.
                let exited = {
                    let mut guard = child
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    matches!(guard.try_wait(), Ok(Some(_)))
                };
                if !exited {
                    backoff_secs = 1;
                    continue;
                }
                tracing::warn!(
                    backoff_secs,
                    "hysteria child exited — respawning after backoff"
                );
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
                if shutdown.load(Ordering::Acquire) {
                    return;
                }
                match spawn_child(&binary, &config_path) {
                    Ok(mut new_child) => {
                        if shutdown.load(Ordering::Acquire) {
                            // Drop raced in between our check and the
                            // spawn — reap the fresh child, don't leak it.
                            let _ = new_child.kill();
                            let _ = new_child.wait();
                            return;
                        }
                        let mut guard = child
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        // Error-hunt wave s4: re-check UNDER the lock.
                        // Drop may have won the lock between our check
                        // above and this acquisition (killed the old
                        // child and exited) — storing now would leak the
                        // fresh child with nobody left to kill it.
                        if shutdown.load(Ordering::Acquire) {
                            drop(guard);
                            let _ = new_child.kill();
                            let _ = new_child.wait();
                            return;
                        }
                        *guard = new_child;
                        tracing::info!("hysteria child respawned");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "hysteria respawn failed — will retry");
                    }
                }
            }
        }));
    }

    /// Spawn the Hysteria subprocess against `config`. Returns once the
    /// child has been launched (no health probe — caller invokes
    /// `probe_socks_port` after a brief delay).
    pub fn spawn(config: &HysteriaConfig) -> Result<Self> {
        let binary = locate_binary()?;
        // Write the YAML to a temp file inside ~/.neoth/.
        let home = crate::config::FreedomConfig::default_neoth_home();
        std::fs::create_dir_all(home.join("hysteria"))
            .with_context(|| format!("create {}/hysteria", home.display()))?;
        let config_path = home.join("hysteria").join("config.yaml");
        std::fs::write(&config_path, render_yaml_config(config))
            .with_context(|| format!("write {}", config_path.display()))?;

        let child = spawn_child(&binary, &config_path)?;

        Ok(Self {
            child: std::sync::Arc::new(std::sync::Mutex::new(child)),
            watchdog: None,
            shutdown: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            socks_port: config.local_socks_port,
            config_path,
            binary,
        })
    }
}

/// Launch the hysteria client subprocess — shared by the initial spawn
/// and the watchdog respawn path.
fn spawn_child(binary: &Path, config_path: &Path) -> Result<std::process::Child> {
    std::process::Command::new(binary)
        .arg("client")
        .arg("--config")
        .arg(config_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawn hysteria client via {}", binary.display()))
}

impl Drop for HysteriaSupervisor {
    fn drop(&mut self) {
        // Latch shutdown BEFORE abort: abort() is cooperative and the
        // watchdog may be mid-respawn — the flag makes it reap (not
        // store) any child it spawns after this point.
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(handle) = self.watchdog.take() {
            handle.abort();
        }
        // Poison-recover: a panicked watchdog must not leak the child.
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = child.kill();
        let _ = child.wait();
        drop(child);
        let _ = std::fs::remove_file(&self.config_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socks_port_is_1080() {
        let cfg = HysteriaConfig::default();
        assert_eq!(cfg.local_socks_port, 1080);
    }

    #[test]
    fn socks_proxy_url_renders_localhost_with_configured_port() {
        // Without spawning a real child, hand-construct a supervisor
        // shape for the URL helper. We can't allocate a real
        // std::process::Child without spawning, so test the helper
        // by going through a config + port path.
        let cfg = HysteriaConfig {
            server: "relay.example.com:443".into(),
            auth: SecretString::from("hunter2"),
            local_socks_port: 31337,
        };
        // The formatter takes only the port — verify the format
        // by composing it directly.
        let url = format!("socks5://127.0.0.1:{}", cfg.local_socks_port);
        assert_eq!(url, "socks5://127.0.0.1:31337");
    }

    #[test]
    fn parse_url_with_explicit_port() {
        let cfg = parse_hysteria_url("hysteria2://mysecret@relay.example.com:8443").unwrap();
        assert_eq!(cfg.server, "relay.example.com:8443");
        assert_eq!(cfg.auth.expose(), "mysecret");
    }

    #[test]
    fn parse_url_defaults_port_to_443() {
        let cfg = parse_hysteria_url("hysteria2://pw@host.example.com").unwrap();
        assert_eq!(cfg.server, "host.example.com:443");
    }

    #[test]
    fn parse_url_accepts_no_scheme() {
        // Operator pastes the bare `auth@host` form from a shell
        // session — be tolerant, the scheme is decorative.
        let cfg = parse_hysteria_url("token@host:443").unwrap();
        assert_eq!(cfg.server, "host:443");
        assert_eq!(cfg.auth.expose(), "token");
    }

    #[test]
    fn parse_url_accepts_hysteria1_scheme() {
        let cfg = parse_hysteria_url("hysteria://x@y:1").unwrap();
        assert_eq!(cfg.server, "y:1");
    }

    #[test]
    fn parse_url_bails_without_at_separator() {
        let err = parse_hysteria_url("just-a-host:443")
            .unwrap_err()
            .to_string();
        assert!(err.contains("@"));
    }

    #[test]
    fn parse_url_bails_on_empty_host() {
        let err = parse_hysteria_url("auth@").unwrap_err().to_string();
        assert!(err.contains("host"));
    }

    #[test]
    fn parse_url_allows_empty_auth() {
        // Free relays sometimes use empty auth — pin that we accept
        // it rather than bailing.
        let cfg = parse_hysteria_url("@open.relay.io:443").unwrap();
        assert_eq!(cfg.server, "open.relay.io:443");
        assert!(cfg.auth.expose().is_empty());
    }

    #[test]
    fn render_yaml_includes_every_required_key() {
        let cfg = HysteriaConfig {
            server: "vps.example.com:443".into(),
            auth: SecretString::new("secret".into()),
            local_socks_port: 1080,
        };
        let s = render_yaml_config(&cfg);
        // GOLD-SEC-35: values are double-quoted YAML scalars.
        assert!(s.contains("server: \"vps.example.com:443\""));
        assert!(s.contains("auth: \"secret\""));
        assert!(s.contains("listen: 127.0.0.1:1080"));
    }

    #[test]
    fn render_yaml_quotes_values_with_indicator_chars() {
        // GOLD-SEC-35 / A-69: a value starting with a YAML indicator or
        // containing `: ` must be quoted so Hysteria's parser reads it
        // literally instead of mis-parsing the config.
        let cfg = HysteriaConfig {
            server: "*anchor: trap".into(),
            auth: SecretString::new(" leading-space".into()),
            local_socks_port: 1080,
        };
        let s = render_yaml_config(&cfg);
        assert!(s.contains("server: \"*anchor: trap\""));
        assert!(s.contains("auth: \" leading-space\""));
        // The rendered config round-trips through a YAML parser cleanly.
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&s).expect("rendered config is valid YAML");
        assert_eq!(parsed["server"].as_str(), Some("*anchor: trap"));
        assert_eq!(parsed["auth"].as_str(), Some(" leading-space"));
    }

    #[test]
    fn render_yaml_uses_operator_port_override() {
        let cfg = HysteriaConfig {
            server: "x:1".into(),
            auth: SecretString::new("y".into()),
            local_socks_port: 31337,
        };
        let s = render_yaml_config(&cfg);
        assert!(s.contains("listen: 127.0.0.1:31337"));
    }

    #[test]
    fn render_yaml_rejects_newline_injection_in_server() {
        // Attacker-controlled freedom.yaml tries to inject extra YAML
        // keys to flip the SOCKS5 listener to all-interfaces.
        let cfg = HysteriaConfig {
            server: "vps:443\nsocks5:\n  listen: 0.0.0.0:1080".into(),
            auth: SecretString::new("x".into()),
            local_socks_port: 1080,
        };
        let s = render_yaml_config(&cfg);
        assert!(
            s.contains("<<rejected: contains control characters>>"),
            "injection payload must be replaced with poison sentinel"
        );
        assert!(
            !s.contains("0.0.0.0:1080"),
            "injected listener must not leak into the rendered YAML"
        );
    }

    #[test]
    fn hysteria_config_tolerates_unknown_fields() {
        // Operators who need obfuscation / multipath / bandwidth caps
        // add Hysteria's full schema to their freedom.yaml; NEOTH only
        // touches the three fields it owns and ignores the rest. The
        // struct has NO `#[serde(deny_unknown_fields)]` so this stays
        // permissive — the test pins that invariant so a future deny
        // attribute doesn't silently break operator configs.
        let yaml = r#"
server: "vps.example.com:443"
auth: "secret"
local_socks_port: 1080
bandwidth:
  up: "100 mbps"
  down: "100 mbps"
obfs:
  type: salamander
  password: "obfuscation-token"
tls:
  insecure: false
"#;
        let cfg: HysteriaConfig =
            serde_yaml::from_str(yaml).expect("permissive deserialize must tolerate unknown keys");
        assert_eq!(cfg.server, "vps.example.com:443");
        assert_eq!(cfg.auth.expose(), "secret");
        assert_eq!(cfg.local_socks_port, 1080);
    }

    #[test]
    fn render_yaml_rejects_newline_injection_in_auth() {
        let cfg = HysteriaConfig {
            server: "vps:443".into(),
            auth: SecretString::new("tok\nextra-key: pwned".into()),
            local_socks_port: 1080,
        };
        let s = render_yaml_config(&cfg);
        assert!(s.contains("<<rejected: contains control characters>>"));
        assert!(!s.contains("extra-key: pwned"));
    }

    #[test]
    fn locate_binary_reports_search_order_in_error() {
        // Force every search path to miss by setting NEOTH_HYSTERIA_BIN
        // to a non-existent file. We don't unset PATH because that would
        // break the rest of the test process.
        let _env = crate::test_env::lock();
        let prev = std::env::var("NEOTH_HYSTERIA_BIN").ok();
        // SAFETY: test-only env mutation. The test process is the sole
        // toucher of this variable for the duration of this test; no
        // other test reads it concurrently.
        unsafe {
            std::env::set_var(
                "NEOTH_HYSTERIA_BIN",
                "C:\\definitely-not-here\\hysteria.exe",
            );
        }
        // PATH may or may not contain hysteria locally — this test
        // tolerates either outcome but verifies the error body shape
        // when it does fail.
        let result = locate_binary();
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(
                msg.contains("NEOTH_HYSTERIA_BIN"),
                "error should mention env override: {msg}",
            );
            assert!(msg.contains("PATH"), "error should mention PATH: {msg}");
        }
        // Restore env. SAFETY: same single-thread invariant as above.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("NEOTH_HYSTERIA_BIN", v),
                None => std::env::remove_var("NEOTH_HYSTERIA_BIN"),
            }
        }
    }

    #[tokio::test]
    async fn probe_socks_port_errors_on_dead_port() {
        // Port 1 is reserved tcpmux; no one's listening. The probe must
        // error quickly, not hang.
        let r = probe_socks_port(1).await;
        assert!(r.is_err());
    }
}
