//! Claude CLI subprocess adapter — built-in bridge for `claude` CLI.
//!
//! Owns the full local-bridge logic so NEOTH does not depend on the
//! operator's external `claude_openai_bridge.py`. Any operator who installs NEOTH +
//! claude-cli via the wizard gets working `neoth chat` without a separate
//! service. See `memory/neoth-bridge-builtin.md`.
//!
//! **What this adapter does (V1, this iteration):**
//!   - Spawns `claude --print --output-format json --model <M>` per request.
//!   - Scrubs harness env vars (`NEOTH_*` except `NEOTH_LOG`, plus any
//!     operator-declared prefixes) before exec so they do not contaminate
//!     Claude's view.
//!   - Parses the JSON envelope, extracts `result` plus token usage.
//!   - Raises a clean error when `result` is empty (signals operator's
//!     Memory/tool-stack swallowed the response — pointer to bare-mode docs).
//!   - On Windows: spawns through `cmd /C` so npm shell-shims (`claude.cmd`)
//!     resolve correctly (per `memory/neoth-windows-build.md`).
//!
//! **Deferred (V2 — port from the operator's `bridge/claude_openai_bridge.py`):**
//!   - tmux backend for persistent warm DM sessions.
//!
//! **B-7 system-prompt sanitizer** (Phase 33c hardening): the operator's
//! NEOTH.md / skill prompts / channel context are concatenated into the
//! system block by `cli/chat.rs`. Any of those upstream sources could
//! accidentally embed a Claude Code control marker (`#` Memory, `/cmd`
//! slash, `@file` attachment) that the CLI would interpret as a
//! conversation command rather than text. `strip_memory_triggers`
//! defangs each before the wrap so the system block is text-only.

use std::process::Stdio;
use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::stream::StreamExt;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Bridge.py-derived signal: when this string lands in a Claude
/// response, Claude has just rewritten its context window to save
/// tokens. The conversation is the same logically, but the warm
/// session has lost prior memory — running too many compactions in
/// a single session drifts personality + degrades coherence. After
/// [`TmuxSlot::compaction_rotate_after`] occurrences we rotate to a
/// fresh session. Default cap matches bridge.py (10).
const COMPACTION_MARKER: &str = "Memory was condensed";

use super::{ChunkStream, Completion, CompletionChunk, Provider, Request};

/// Subset of `claude --output-format json` envelope NEOTH cares about.
/// Real schema is huge; ignore unknown fields with `#[serde(default)]`.
#[derive(Debug, Deserialize)]
struct ClaudeJsonEnvelope {
    #[serde(default)]
    result: String,
    #[serde(default)]
    is_error: bool,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    api_error_status: Option<String>,
    #[serde(default)]
    usage: Option<ClaudeUsage>,
}

#[derive(Debug, Deserialize)]
struct ClaudeUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

/// Backend mode for the Claude CLI provider. `Auto` (default) picks
/// tmux when available + falls back to subprocess; `Tmux` forces the
/// warm-session path (errors at startup if tmux is missing); `Subprocess`
/// forces the cold-start `claude --print` path (broken on some operator
/// setups per `[[neoth-claude-cli-tmux-mandatory]]`, kept for environments
/// where tmux isn't an option — Windows without WSL).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ClaudeBackend {
    #[default]
    Auto,
    Tmux,
    Subprocess,
}

impl ClaudeBackend {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "tmux" => Some(Self::Tmux),
            "subprocess" => Some(Self::Subprocess),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Tmux => "tmux",
            Self::Subprocess => "subprocess",
        }
    }
}

/// Singleton tmux session per adapter — the v0.1 scope of B-6 Item 1.
/// Future iterations can expand this into a conversation-keyed
/// `HashMap<ConversationId, PoolEntry>` (Agent 4 architecture) once
/// the chat dispatch threads a conversation_id through Request.
pub struct TmuxSlot {
    inner: tokio::sync::Mutex<Option<super::tmux_session::TmuxSession>>,
    /// Compaction counter — rotated to a fresh session after N
    /// "Memory was condensed" markers in responses. Default 10
    /// matches bridge.py.
    compaction_count: std::sync::atomic::AtomicU32,
    /// Maximum compactions before forced rotation.
    compaction_rotate_after: u32,
    /// Tmux session name pattern (with placeholder for the rotation
    /// counter so old + new sessions don't collide during handoff).
    session_name_root: String,
    /// Counter that bumps on every rotation so session names stay
    /// unique across the adapter's lifetime.
    rotation_seq: std::sync::atomic::AtomicU32,
}

impl TmuxSlot {
    fn new(session_name_root: String, compaction_rotate_after: u32) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(None),
            compaction_count: std::sync::atomic::AtomicU32::new(0),
            compaction_rotate_after,
            session_name_root,
            rotation_seq: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

/// Claude CLI provider with optional tmux warm-session backend.
///
/// `binary` is typically `"claude"` (PATH-resolved) but operators on Windows
/// may need the full `C:\Users\<u>\AppData\Roaming\npm\claude` path. The
/// wizard auto-detects via `which_binary("claude")` and writes the resolved
/// path into `freedom.yaml`.
pub struct ClaudeCliAdapter {
    binary: String,
    model: String,
    backend: ClaudeBackend,
    tmux_slot: std::sync::Arc<TmuxSlot>,
    /// B-9: concurrent-request dedup. Two `complete` calls with the
    /// same `(prompt, system, model)` tuple in flight at the same time
    /// share one upstream spawn. Stream path is not deduped — chunk
    /// timing differs per subscriber and the protocol cost is amortised
    /// over the stream.
    dedup: std::sync::Arc<super::singleflight::Singleflight<Completion>>,
    /// Pick #35 (Session 14, B-6 design-audit gap-fix): operator-tunable
    /// idle + hard timeouts for the tmux warm-session path. Previously
    /// declared in `ClaudeCliTmuxConfig` but the adapter still read
    /// module-level constants — so the operator could edit
    /// `freedom.yaml::claude_cli.tmux.idle_timeout_secs: 240` and see
    /// no effect. Now wired through.
    idle_timeout_secs: u64,
    hard_timeout_secs: u64,
    /// Audit 2026-05-19 (Session 15 Pick #3): per-adapter once-flag for
    /// the "auto → subprocess" fallback diagnostic. Memory hard rule
    /// `neoth_claude_cli_tmux_mandatory.md` says the subprocess path is
    /// broken on some setups; operators silently falling into it (most
    /// often Windows where tmux is not on PATH) saw empty-result errors
    /// with no actionable hint. Fires once per adapter instance — second
    /// + Nth `complete` calls stay quiet.
    auto_fallback_warned: std::sync::atomic::AtomicBool,
    /// Optional claude-cli session UUID to resume. Passed through
    /// `strip_dead_resume_args` before any spawn so a stale/deleted
    /// JSONL never kills the session start.
    resume_session_id: Option<String>,
}

impl ClaudeCliAdapter {
    /// Legacy constructor — defaults to `Auto` backend + the
    /// module-level constants from `claude_tmux`. New callers should
    /// use [`new_with_backend_and_timeouts`] to be explicit.
    pub fn new(binary: String, model: String) -> Self {
        Self::new_with_backend_and_timeouts(
            binary,
            model,
            ClaudeBackend::Auto,
            10,
            super::claude_tmux::IDLE_TIMEOUT_SECS,
            super::claude_tmux::HARD_TIMEOUT_SECS,
        )
    }

    /// Backwards-compat shim — preserves the prior arity for any
    /// caller that hasn't been updated to pass timeouts.
    pub fn new_with_backend(
        binary: String,
        model: String,
        backend: ClaudeBackend,
        compaction_rotate_after: u32,
    ) -> Self {
        Self::new_with_backend_and_timeouts(
            binary,
            model,
            backend,
            compaction_rotate_after,
            super::claude_tmux::IDLE_TIMEOUT_SECS,
            super::claude_tmux::HARD_TIMEOUT_SECS,
        )
    }

    /// Full constructor — every knob the operator can tune via
    /// `freedom.yaml::claude_cli.*`. The provider factory at
    /// `providers/mod.rs::from_config` calls this with the resolved
    /// `ClaudeCliConfig`.
    pub fn new_with_backend_and_timeouts(
        binary: String,
        model: String,
        backend: ClaudeBackend,
        compaction_rotate_after: u32,
        idle_timeout_secs: u64,
        hard_timeout_secs: u64,
    ) -> Self {
        let session_name_root = format!("neoth-cc-{}", std::process::id());
        // Normalise legacy model aliases (opusplan → opus-4-7[1m]) at
        // construction so every downstream code path sees the canonical
        // name. Bridge.py does the same translation.
        let model = normalise_model(&model);
        Self {
            binary,
            model,
            backend,
            tmux_slot: std::sync::Arc::new(TmuxSlot::new(
                session_name_root,
                compaction_rotate_after,
            )),
            dedup: std::sync::Arc::new(super::singleflight::Singleflight::new()),
            idle_timeout_secs,
            hard_timeout_secs,
            auto_fallback_warned: std::sync::atomic::AtomicBool::new(false),
            resume_session_id: None,
        }
    }

    /// Set the optional claude-cli session UUID to resume. Builder-style
    /// so existing call sites keep compiling without a signature churn.
    pub fn with_resume_session_id(mut self, id: Option<String>) -> Self {
        self.resume_session_id = id;
        self
    }

    pub fn backend(&self) -> ClaudeBackend {
        self.backend
    }

    /// Resolve the effective backend at call time. `Auto` consults
    /// `TmuxSession::is_available()` (cached at first call); `Tmux` /
    /// `Subprocess` return verbatim. Used by `complete` to branch.
    ///
    /// When `Auto` resolves to `Subprocess` (tmux not on PATH or not
    /// runnable), fire a one-shot WARN with platform-specific install
    /// hints — the memory hard rule says the subprocess path is broken
    /// on some reference setups, so the operator needs to see the
    /// install path before the first empty-result error lands.
    async fn effective_backend(&self) -> ClaudeBackend {
        match self.backend {
            ClaudeBackend::Auto => {
                if super::tmux_session::TmuxSession::is_available().await {
                    ClaudeBackend::Tmux
                } else {
                    self.warn_auto_subprocess_fallback_once();
                    ClaudeBackend::Subprocess
                }
            }
            other => other,
        }
    }

    /// Fire once per adapter instance. Subsequent calls compare-and-swap
    /// to a no-op so a Telegram bot looping 100 messages doesn't spam
    /// the operator's journal.
    fn warn_auto_subprocess_fallback_once(&self) {
        use std::sync::atomic::Ordering;
        if self
            .auto_fallback_warned
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let install_hint = if cfg!(target_os = "windows") {
                "Windows: `scoop install tmux` OR `choco install tmux` OR run NEOTH under WSL."
            } else if cfg!(target_os = "macos") {
                "macOS: `brew install tmux`."
            } else {
                "Linux: `apt install tmux` / `pacman -S tmux` / `dnf install tmux`."
            };
            warn!(
                target: "claude_cli",
                "claude_cli backend=auto: tmux is not available; falling back to subprocess. \
                 The subprocess path returns empty results on some claude-cli versions \
                 (see memory rule `claude-cli requires tmux`). Install tmux for the stable \
                 warm-session backend — {install_hint} \
                 To silence this warning, set `claude_cli.backend: subprocess` in freedom.yaml \
                 (acknowledges the risk)."
            );
        }
    }

    /// Test-only accessor used by the once-warning regression test.
    /// `pub(crate)` so it stays inside the daemon crate.
    #[cfg(test)]
    pub(crate) fn auto_fallback_warned_for_test(&self) -> bool {
        self.auto_fallback_warned
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Hash the request shape that defines "identical call" for dedup.
    /// Prompt + system + effective model — sampling parameters are
    /// excluded so two callers asking the same question with different
    /// temperatures still share the cache (cheap operator-side win).
    fn dedup_key(&self, req: &Request) -> u64 {
        use xxhash_rust::xxh3::Xxh3;
        let mut h = Xxh3::new();
        h.update(req.prompt.as_bytes());
        h.update(b"\x00");
        if let Some(s) = &req.system {
            h.update(s.as_bytes());
        }
        h.update(b"\x00");
        let model = req.model.as_deref().unwrap_or(&self.model);
        h.update(model.as_bytes());
        h.digest()
    }
}

/// Build the final argv for a `claude` spawn, injecting `--resume <uuid>`
/// when the adapter is configured to resume a session and stripping the
/// resume pair if the underlying JSONL no longer exists. This is the single
/// call site that wires `claude_session::strip_dead_resume_args` into the
/// live spawn paths (subprocess + tmux session start).
fn build_claude_spawn_args(base: &[&str], resume_session_id: &Option<String>) -> Vec<String> {
    let mut args: Vec<String> = base.iter().map(|s| s.to_string()).collect();
    if let Some(uuid) = resume_session_id {
        args.push(super::claude_session::RESUME_FLAG_LONG.to_string());
        args.push(uuid.clone());
    }
    if let Some(dir) = super::claude_session::claude_sessions_dir() {
        super::claude_session::strip_dead_resume_args(&args, &dir)
    } else {
        // No home dir resolvable — liveness can't be checked, but the
        // operator-controlled resume id must still pass a UUID-format gate
        // before reaching the spawn (F71: the field contract promises a
        // strip pass before ANY spawn; the prior verbatim return skipped it).
        super::claude_session::strip_format_invalid_resume_args(&args)
    }
}

/// Quote argv tokens for a shell command string. Only wraps tokens that
/// contain whitespace or quotes; model names and UUIDs pass through clean.
fn join_args_for_shell(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.chars()
                .any(|c| c.is_whitespace() || c == '"' || c == '\'')
            {
                let escaped = a.replace('"', "\\\"");
                format!("\"{escaped}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Spawn `claude` with stdout/stdin piped. On Windows, npm installs the CLI
/// as a shell script (`claude`) plus `claude.cmd` — CreateProcessW cannot
/// execute the bare shell script directly (it returns OS error 193,
/// "%1 ist keine zulässige Win32-Anwendung"). Bouncing through cmd.exe
/// resolves the extension automatically.
///
/// Env scrubbing: harness identifier vars (`NEOTH_*` except `NEOTH_LOG`,
/// plus any operator-declared `claude_cli.scrub_env_prefixes`) are dropped
/// before exec so they do not contaminate Claude's view. Ported from the
/// `_sanitize_outbound_env` bridge pattern.
///
/// B-6 / Agent 5 perf wedge 2026-05-16: the scrub result is cached
/// behind a `OnceLock` so each subprocess spawn reuses the same env
/// vector instead of re-iterating `std::env::vars()` (50-150 entries
/// per scan on Windows, ~80µs of allocator pressure per call). On a
/// council debate firing three hemispheres in parallel, this drops
/// 3× repeated env scans to a single cold-start scan. The process
/// env is treated as immutable post-startup — operators who flip
/// HTTP_PROXY mid-daemon need to restart; the explicit "scan once"
/// contract is documented at `cached_scrubbed_env()`.
fn spawn_claude(binary: &str, args: &[String]) -> std::io::Result<tokio::process::Child> {
    let scrubbed = cached_scrubbed_env();
    #[cfg(windows)]
    {
        // cmd /C "<binary>" arg1 arg2 ... — quotes around the binary path so
        // spaces in `C:\Program Files\...` survive cmd's word-splitting.
        let mut cmd = Command::new("cmd");
        cmd.arg("/C").arg(binary);
        for a in args {
            cmd.arg(a);
        }
        cmd.env_clear();
        for (k, v) in scrubbed.iter() {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }
    #[cfg(not(windows))]
    {
        let mut cmd = Command::new(binary);
        for a in args {
            cmd.arg(a);
        }
        cmd.env_clear();
        for (k, v) in scrubbed.iter() {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }
}

/// B-6 / Agent 5 perf wedge: return a reference to the
/// scrub-once-cache-forever env vector. First call seeds it via
/// `scrub_outbound_env`; every subsequent call hits the lock-free
/// `OnceLock::get` fast path. The contract: NEOTH treats its own
/// process env as immutable for the daemon's lifetime — operators
/// who change HTTP_PROXY / NEOTH_LOG / etc. mid-run need to restart
/// to pick up the new value. This is consistent with the rest of
/// the daemon (config is loaded once at startup, hooks reload via
/// SIGHUP, but env vars stay frozen).
fn cached_scrubbed_env() -> &'static [(String, String)] {
    static CACHE: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();
    CACHE.get_or_init(scrub_outbound_env).as_slice()
}

/// GOLD-CCPARITY-EFFORT-03 — spawn `claude` with a per-call env override on
/// top of the cached scrubbed env. This is the correct injection point for
/// `MAX_THINKING_TOKENS`: `cached_scrubbed_env()` is a `OnceLock` and cannot
/// be mutated per-call, so we clone it into a fresh vec and apply the override
/// before spawning. Cost: one `Vec::clone` (~80-150 small `(String,String)` pairs)
/// per call that carries an effort override — negligible vs the LLM round-trip.
///
/// `extra_overrides` is a slice of `(key, value)` pairs applied via
/// `inject_or_override` AFTER the cached scrub, so they always win over the
/// scrubbed defaults (the same order `scrub_outbound_env` uses for its own
/// mandatory injections).
fn spawn_claude_with_extra_env(
    binary: &str,
    args: &[String],
    extra_overrides: &[(&str, String)],
) -> std::io::Result<tokio::process::Child> {
    let mut env: Vec<(String, String)> = cached_scrubbed_env().to_vec();
    for (key, value) in extra_overrides {
        inject_or_override(&mut env, key, value);
    }
    #[cfg(windows)]
    {
        let mut cmd = tokio::process::Command::new("cmd");
        cmd.arg("/C").arg(binary);
        for a in args {
            cmd.arg(a);
        }
        cmd.env_clear();
        for (k, v) in &env {
            cmd.env(k, v);
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
    }
    #[cfg(not(windows))]
    {
        let mut cmd = tokio::process::Command::new(binary);
        for a in args {
            cmd.arg(a);
        }
        cmd.env_clear();
        for (k, v) in &env {
            cmd.env(k, v);
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
    }
}

/// Return the current process env with NEOTH + operator-declared harness
/// vars stripped + mandatory bridge.py-derived env knobs injected. Whitelist-style
/// for clarity: keep PATH, HOME, USERPROFILE, APPDATA, anything Claude
/// legitimately needs to find its OAuth token, `NEOTH_LOG` so subprocesses
/// inherit tracing config, and the standard terminal vars. Drops:
///   - Operator-declared harness prefixes
///     (`freedom.yaml::claude_cli.scrub_env_prefixes`, default empty) so
///     the model can't see another agent stack the operator runs.
///   - NEOTH_* except NEOTH_LOG (same reason).
///   - CI markers (CI/GITHUB_ACTIONS/GITLAB_CI/CIRCLECI/TRAVIS) so claude
///     doesn't enable CI-mode formatting (would leak hidden text in the
///     pane scrape).
///   - CLAUDECODE markers (CLAUDECODE/CLAUDE_CODE_*) so when NEOTH runs
///     under claude-code itself the child claude doesn't think it's
///     re-entering its parent session.
///   - TMUX env vars when on the subprocess path so the child claude
///     doesn't believe it's in a tmux pane when in fact it's a bare pipe
///     (would render box-drawing chrome that breaks `claude --print` JSON
///     output).
///
/// Bridge.py-derived injected env vars (set after scrub so they always
/// win over inherited values):
///   - `DISABLE_AUTOUPDATER=1` — block claude-cli mid-session auto-update
///     (would 30-second freeze the pane during a chat).
///   - `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` — defence-in-depth signal to
///     the CLI to also scrub its own subprocess env (it does this anyway
///     in recent versions, but explicit beats implicit).
///   - `BASH_DEFAULT_TIMEOUT_MS=120000` — bash-tool timeout cap.
///     Operators routinely run `pytest` / `npm test` that take >2 min
///     locally; we cap at 2 min so a single stuck command doesn't pin
///     the warm session.
///   - `MAX_THINKING_TOKENS=10000` — bound extended-thinking budget so a
///     pathological prompt doesn't burn 31k thinking tokens before
///     emitting any visible output.
fn scrub_outbound_env() -> Vec<(String, String)> {
    // Operator-declared harness prefixes to strip
    // (`freedom.yaml::claude_cli.scrub_env_prefixes`); default empty.
    // Loaded once — this fn is cached behind `cached_scrubbed_env()`.
    let harness_prefixes = crate::config::FreedomConfig::load_from_default_path()
        .map(|c| c.claude_cli.scrub_env_prefixes)
        .unwrap_or_default();
    scrub_outbound_env_with(&harness_prefixes)
}

/// Core scrub (testable). `harness_prefixes` are the operator-declared
/// env-var prefixes to strip so the operator's OTHER agent-stack secrets
/// never reach the model — empty by default; nothing operator-specific
/// is hardcoded here. The generic scrubs below (`NEOTH_*` except
/// `NEOTH_LOG`, CI markers, `CLAUDECODE_*`, TMUX) run for every operator
/// regardless of the prefix list.
fn scrub_outbound_env_with(harness_prefixes: &[String]) -> Vec<(String, String)> {
    const CI_MARKERS: &[&str] = &[
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "CIRCLECI",
        "TRAVIS",
        "JENKINS_URL",
        "BUILDKITE",
    ];
    const CLAUDECODE_PREFIXES: &[&str] = &["CLAUDECODE", "CLAUDE_CODE_"];
    const TMUX_VARS: &[&str] = &["TMUX", "TMUX_PANE"];

    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            if harness_prefixes.iter().any(|p| k.starts_with(p.as_str())) {
                return false;
            }
            if k.starts_with("NEOTH_") && k != "NEOTH_LOG" {
                return false;
            }
            if CI_MARKERS.iter().any(|m| k == m) {
                return false;
            }
            if CLAUDECODE_PREFIXES.iter().any(|p| k.starts_with(p)) {
                return false;
            }
            if TMUX_VARS.iter().any(|m| k == m) {
                return false;
            }
            true
        })
        .collect();

    // Inject bridge.py-derived mandatory knobs AFTER scrub so they
    // always reach claude even if the operator had them set to a
    // different value upstream.
    inject_or_override(&mut env, "DISABLE_AUTOUPDATER", "1");
    inject_or_override(&mut env, "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB", "1");
    inject_or_override(&mut env, "BASH_DEFAULT_TIMEOUT_MS", "120000");
    inject_or_override(&mut env, "MAX_THINKING_TOKENS", "10000");

    env
}

/// Replace `key` if already present, append otherwise. Pure helper —
/// keeps `scrub_outbound_env` legible and the inject behaviour
/// idempotent across repeat calls (only matters in tests that mutate
/// the global env; production env-scrub is cached).
fn inject_or_override(env: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value.to_string();
    } else {
        env.push((key.to_string(), value.to_string()));
    }
}

/// Normalise legacy model aliases to their canonical names. `opusplan`
/// is the pre-rebrand alias for the 1M-context Opus variant; bridge.py
/// translates it because some operator configs still reference the
/// alias + claude-cli rejects unknown model names. Pure mapping —
/// unknown inputs pass through unchanged.
pub(super) fn normalise_model(model: &str) -> String {
    match model {
        "opusplan" | "opus-plan" => "claude-opus-4-7[1m]".to_string(),
        other => other.to_string(),
    }
}

#[async_trait]
impl Provider for ClaudeCliAdapter {
    fn name(&self) -> &'static str {
        "claude_cli"
    }

    async fn complete(&self, req: Request) -> Result<Completion> {
        // GR-04: circuit breaker — same pattern as openai_api. Note
        // the dedup `Singleflight` already collapses concurrent
        // duplicates; the breaker counts each Singleflight outcome
        // once (which is the right denominator for failure-rate).
        crate::providers::circuit_breaker::run_with_breaker("claude_cli", async {
            // B-9: dedup by (prompt, system, model). Concurrent identical
            // requests share one upstream spawn for both backends.
            let backend = self.effective_backend().await;
            let key = self.dedup_key(&req);
            let binary = self.binary.clone();
            let model_default = self.model.clone();
            let tmux_slot = self.tmux_slot.clone();
            let idle_timeout_secs = self.idle_timeout_secs;
            let hard_timeout_secs = self.hard_timeout_secs;
            let resume_session_id = self.resume_session_id.clone();
            let result = self
                .dedup
                .do_call(key, move || async move {
                    match backend {
                        ClaudeBackend::Tmux => {
                            complete_tmux_uncached(
                                &tmux_slot,
                                &binary,
                                &model_default,
                                req,
                                idle_timeout_secs,
                                hard_timeout_secs,
                                resume_session_id.clone(),
                            )
                            .await
                        }
                        ClaudeBackend::Subprocess | ClaudeBackend::Auto => {
                            // Auto cannot reach here in practice (resolved
                            // above) but the exhaustive match keeps future
                            // variants explicit.
                            complete_uncached(
                                &binary,
                                &model_default,
                                req,
                                resume_session_id.clone(),
                            )
                            .await
                        }
                    }
                })
                .await?;
            // `Singleflight` returns `Arc<Completion>`; clone the inner
            // value so the caller owns it. Completion is small (string +
            // counters), so the clone cost is negligible compared to the
            // dedup win on a concurrent identical request.
            Ok((*result).clone())
        })
        .await
    }

    /// Streaming: read claude stdout line-by-line and emit each line as a
    /// chunk. Uses `--output-format stream-json` (B-8): claude-cli emits
    /// one Anthropic SSE event per stdout line, NDJSON-style. We parse
    /// each line, extract text deltas from `content_block_delta` events,
    /// and capture final token usage from `message_delta`. Unrecognised
    /// event types are skipped — Anthropic adds new types occasionally
    /// (e.g. tool-use blocks) and we do not want to fail the stream when
    /// the CLI version is ahead of NEOTH's parser.
    async fn stream(&self, req: Request) -> Result<ChunkStream> {
        // GR-04 stream-wrap: same circuit-breaker semantics as
        // `complete` (fast-fail on Open, record success on final
        // done-chunk, record failure on error / premature drop).
        crate::providers::circuit_breaker_stream::run_stream_with_breaker("claude_cli", async {
            let model = req.model.clone().unwrap_or_else(|| self.model.clone());
            let prompt = build_prompt_payload(&req);

            let args = build_claude_spawn_args(
                &[
                    "--print",
                    "--model",
                    &model,
                    "--output-format",
                    "stream-json",
                    "--verbose",
                ],
                &self.resume_session_id,
            );
            // GOLD-CCPARITY-EFFORT-03: same per-call MAX_THINKING_TOKENS override
            // as complete_uncached — use spawn_claude_with_extra_env when the
            // request carries a thinking_budget, plain spawn_claude otherwise.
            let mut child = if let Some(budget) = req.thinking_budget {
                spawn_claude_with_extra_env(
                    &self.binary,
                    &args,
                    &[("MAX_THINKING_TOKENS", budget.to_string())],
                )
            } else {
                spawn_claude(&self.binary, &args)
            }
            .with_context(|| {
                format!(
                    "spawn `{} --print --model {}` for streaming",
                    self.binary, model
                )
            })?;

            // Write prompt to stdin, close so the CLI sees EOF and starts generating.
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(prompt.as_bytes())
                    .await
                    .context("write prompt to claude stdin (stream)")?;
                stdin
                    .shutdown()
                    .await
                    .context("close claude stdin (stream)")?;
            }

            let stdout = child
                .stdout
                .take()
                .context("claude CLI stdout pipe missing for stream")?;
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            // Build the stream as an async-iter over NDJSON events. Each line
            // is one Anthropic SSE event reformatted as JSON. We extract
            // text deltas + final usage; non-text events are ignored.
            let s = async_stream::try_stream! {
                let mut input_tokens: Option<u32> = None;
                let mut output_tokens: Option<u32> = None;

                while let Some(line) = lines.next_line().await.transpose() {
                    let line = line.context("read claude stdout line")?;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match parse_stream_event(trimmed) {
                        StreamEvent::TextDelta(text) => {
                            yield CompletionChunk {
                                delta: text,
                                done: false,
                                input_tokens: None,
                                output_tokens: None,
                                cache_creation_tokens: None,
                                cache_read_tokens: None,
                            };
                        }
                        StreamEvent::Usage { input, output } => {
                            if let Some(v) = input { input_tokens = Some(v); }
                            if let Some(v) = output { output_tokens = Some(v); }
                        }
                        StreamEvent::Ignore => {}
                        StreamEvent::ParseError(err) => {
                            // A malformed line is loud — better to surface
                            // than silently drop, since stream-json is the
                            // contract between NEOTH and claude-cli.
                            Err(anyhow::anyhow!(
                                "claude stream-json parse error on `{}`: {err}",
                                trimmed.chars().take(120).collect::<String>(),
                            ))?;
                        }
                    }
                }

                // Drain remaining stderr + check exit status.
                let output = child
                    .wait_with_output()
                    .await
                    .context("await claude CLI after stream")?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(anyhow::anyhow!(
                        "claude CLI exited with {:?} during stream: {}",
                        output.status.code(),
                        stderr.trim()
                    ))?;
                }
                // Final done-chunk with usage populated from the message_delta /
                // result events we saw mid-stream. Empty delta — the visible
                // text was already emitted as content_block_delta chunks.
                yield CompletionChunk {
                    delta: String::new(),
                    done: true,
                    input_tokens,
                    output_tokens,
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                };
            };

            // The try_stream macro yields `Result<CompletionChunk, anyhow::Error>`
            // already; wrap into the trait's ChunkStream type.
            Ok(Box::pin(s) as ChunkStream)
        })
        .await
    }
}

/// Adapter-free completion: spawn + parse + return. Extracted so the
/// singleflight wrapper in [`ClaudeCliAdapter::complete`] can call it as
/// a `FnOnce()` closure without dragging `&self` through the lifetime.
async fn complete_uncached(
    binary: &str,
    model_default: &str,
    req: Request,
    resume_session_id: Option<String>,
) -> Result<Completion> {
    let started = Instant::now();
    let model = req
        .model
        .clone()
        .map(|m| normalise_model(&m))
        .unwrap_or_else(|| model_default.to_string());

    // `claude --print --output-format json` runs non-interactively and
    // emits a JSON envelope on stdout. We parse it to get the real
    // result + usage. Without JSON we cannot distinguish "claude returned
    // empty text" from "claude tool-called and never produced text" —
    // both look identical in text mode (zero bytes on stdout).
    let args = build_claude_spawn_args(
        &["--print", "--model", &model, "--output-format", "json"],
        &resume_session_id,
    );
    // GOLD-CCPARITY-EFFORT-03: when the request carries a per-skill thinking
    // budget, override MAX_THINKING_TOKENS before spawning so this specific
    // call uses the skill-declared token count instead of the cached default
    // (10 000). We use `spawn_claude_with_extra_env` rather than mutating the
    // `OnceLock`-cached env (which is immutable post-startup by contract).
    let mut child = if let Some(budget) = req.thinking_budget {
        spawn_claude_with_extra_env(
            binary,
            &args,
            &[("MAX_THINKING_TOKENS", budget.to_string())],
        )
    } else {
        spawn_claude(binary, &args)
    }
    .with_context(|| {
        format!(
            "spawn `{binary} --print --model {model}`. Is the claude CLI installed and on PATH?"
        )
    })?;

    let payload = build_prompt_payload(&req);

    {
        let mut stdin = child
            .stdin
            .take()
            .context("claude CLI stdin pipe missing")?;
        stdin
            .write_all(payload.as_bytes())
            .await
            .context("write prompt to claude stdin")?;
        stdin
            .shutdown()
            .await
            .context("close claude stdin to signal EOF")?;
    }

    let output = child
        .wait_with_output()
        .await
        .context("await claude CLI completion")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "claude CLI exited with {:?}: {}",
            output.status.code(),
            stderr.trim()
        );
    }

    let stdout =
        String::from_utf8(output.stdout).context("claude CLI stdout was not valid UTF-8")?;
    let envelope: ClaudeJsonEnvelope = serde_json::from_str(stdout.trim()).with_context(|| {
        format!(
            "parse claude --output-format json. Raw stdout (first 400 chars): {}",
            stdout.chars().take(400).collect::<String>()
        )
    })?;

    if envelope.is_error {
        anyhow::bail!(
            "claude CLI reported is_error=true: stop_reason={:?}, api_error_status={:?}",
            envelope.stop_reason,
            envelope.api_error_status
        );
    }

    let text = envelope.result.clone();
    if text.is_empty() {
        // This happens when the operator's claude-code setup runs the
        // model in a tool-calling loop (Memory injection, agents, hooks)
        // and `stop_reason: end_turn` fires before any text is produced.
        // Surface a clear actionable error instead of an empty success.
        //
        // Pick #35 (Session 14, B-6 design-audit gap-fix): added the
        // tmux warm-session path as a THIRD fix. On OAuth setups
        // the subprocess `--print` path is the documented-broken case;
        // installing tmux + setting `claude_cli.backend: tmux` (or
        // leaving `auto` to auto-detect) routes around it entirely
        // via the warm-session bridge port.
        anyhow::bail!(
            "claude CLI returned empty `result` (stop_reason={:?}). \
             Your claude-code setup likely loaded a tool/agent stack — \
             NEOTH expects bare model output. Three fixes: \
             (1) run `neoth chat` with `claude --bare` mode (pending V2), \
             (2) point provider_kind at `openai_compat` against an external bridge, \
             (3) install tmux + set `claude_cli.backend: tmux` (or leave `auto` — \
             NEOTH will auto-detect tmux and use the warm-session path that avoids \
             this issue entirely on OAuth setups).",
            envelope.stop_reason
        );
    }

    let latency = started.elapsed();
    debug!(
        model = %model,
        response_bytes = text.len(),
        latency_ms = latency.as_millis(),
        input_tokens = envelope.usage.as_ref().map(|u| u.input_tokens),
        output_tokens = envelope.usage.as_ref().map(|u| u.output_tokens),
        "claude_cli completion"
    );

    Ok(Completion {
        text,
        model,
        latency,
        input_tokens: envelope.usage.as_ref().map(|u| u.input_tokens),
        output_tokens: envelope.usage.as_ref().map(|u| u.output_tokens),
        cache_creation_tokens: None,
        cache_read_tokens: None,
    })
}

/// Drive a completion through the warm tmux session. Locks the
/// singleton session for the entire request — the tmux pane is a
/// single-conversation resource and concurrent sends would interleave.
/// Identical concurrent prompts are already collapsed by the upstream
/// singleflight; non-identical concurrent calls serialise here.
///
/// Failure modes:
///   - **Pane disappeared mid-conversation** → clear the slot + bail
///     with a clear pointer (`neoth doctor`). The next call will spawn
///     a fresh session. v0.1 deliberately does NOT auto-retry: Item 3
///     of B-6 (the 4-class retry classifier) owns the retry policy.
///   - **Idle-timer fired with empty response** → bail; the operator's
///     session was likely stuck in tool-call mode.
///   - **Compaction marker observed** → bump counter; rotate to a
///     fresh session when the cap is hit.
/// GOLD-WIRE-06 — one concrete step the warm-tmux retry loop should take
/// (the [`TmuxRetryPlan::Retry`] payload).
#[derive(Clone, Copy, Debug)]
struct TmuxRetryStep {
    class: super::claude_retry::RetryClass,
    sleep: std::time::Duration,
    /// Drop + respawn the warm session before the next attempt (only
    /// `SessionCollision` sets this).
    reset_session: bool,
    hint: &'static str,
}

/// GOLD-WIRE-06 — the retry policy's verdict for one attempt. Carries the
/// classified `class` (+ its operator `hint`) in BOTH arms so the loop never
/// has to re-run `classify_failure` (which allocates) to format the final
/// surfaced error.
#[derive(Clone, Copy, Debug)]
enum TmuxRetryPlan {
    /// Sleep, optionally reset the session, then retry.
    Retry(TmuxRetryStep),
    /// Attempts exhausted (or an `Auth` failure) — surface the error now.
    Surface {
        class: super::claude_retry::RetryClass,
        hint: &'static str,
    },
}

/// GOLD-WIRE-06 — pure retry policy for the warm-tmux send path. Classifies
/// the observed failure via [`super::claude_retry::classify_failure`] (Auth /
/// SessionCollision / EmptyStdout / Transient) and, for the 0-indexed
/// `attempt`, returns the concrete step — or [`TmuxRetryPlan::Surface`] when
/// that class's `max_attempts` is exhausted (Auth's `max_attempts` is 0, so it
/// always surfaces: immediate, never retried). Kept pure so the loop's
/// decision logic is unit-testable without spawning a tmux session.
fn plan_tmux_retry(signal: &super::claude_retry::FailureSignal<'_>, attempt: u32) -> TmuxRetryPlan {
    let class = super::claude_retry::classify_failure(signal);
    let decision = super::claude_retry::retry_decision(class);
    if attempt >= decision.max_attempts {
        return TmuxRetryPlan::Surface {
            class,
            hint: decision.hint,
        };
    }
    TmuxRetryPlan::Retry(TmuxRetryStep {
        class,
        sleep: super::claude_retry::backoff_for_attempt(&decision, attempt),
        reset_session: decision.reset_session,
        hint: decision.hint,
    })
}

async fn complete_tmux_uncached(
    tmux_slot: &TmuxSlot,
    binary: &str,
    model_default: &str,
    req: Request,
    idle_timeout_secs: u64,
    hard_timeout_secs: u64,
    resume_session_id: Option<String>,
) -> Result<Completion> {
    let started = Instant::now();

    // The tmux session is pinned to the daemon's default model — the
    // interactive `claude` CLI doesn't expose a runtime model switch
    // that survives across prompts. A per-call `req.model` override
    // would either need a fresh session per request (defeating the
    // warm-session purpose) or risk silently sending to the wrong
    // model. v0.1: log + use the session model. Operators who need
    // per-call switching stay on `backend: subprocess`.
    if let Some(req_model) = req.model.as_ref() {
        if req_model != model_default {
            warn!(
                requested = %req_model,
                session = %model_default,
                "claude tmux: per-call model override ignored — session pinned to default. \
                 Use `backend: subprocess` in freedom.yaml for per-call model switching."
            );
        }
    }
    let model = model_default.to_string();
    let payload = build_prompt_payload(&req);

    let mut guard = tmux_slot.inner.lock().await;

    // GOLD-WIRE-06: the send is wrapped in a classify-driven retry loop
    // (`claude_retry`). Each iteration (re)ensures the warm session, sends,
    // and on failure routes the signal through `plan_tmux_retry`: an Auth
    // failure surfaces immediately, an empty pane / vanished pane retries
    // once (the latter respawning the session), transient upstream errors
    // retry with exponential backoff — every class bounded by its
    // `max_attempts`. The slot lock is intentionally held across the retries:
    // the warm pane is a single serial conversation, so concurrent callers
    // already queue on this lock regardless of retry.
    let mut attempt: u32 = 0;
    let response = loop {
        // Repair stale slot: tmux may have lost the session (operator
        // killed it, OS OOM, server restart). Detect + clear so the
        // session-start branch below spawns a fresh one.
        if let Some(s) = guard.as_ref() {
            if !s.exists().await {
                warn!(name = s.name(), "claude tmux session vanished — recreating");
                *guard = None;
            }
        }
        // Session-start branch: spawn a fresh warm session when none is held
        // (first attempt, a vanished pane, or a retry that reset the session).
        if guard.is_none() {
            let rot = tmux_slot
                .rotation_seq
                .load(std::sync::atomic::Ordering::Relaxed);
            let name = format!("{}-{}", tmux_slot.session_name_root, rot);
            // Interactive claude shares the `--model` flag with `--print`
            // mode. Tmux runs the command through the system shell. Wire
            // the optional resume session id through the same strip-dead
            // guard as the subprocess path.
            let resume_args = build_claude_spawn_args(&["--model", &model], &resume_session_id);
            let cmd = format!("{binary} {}", join_args_for_shell(&resume_args));
            let session = super::tmux_session::TmuxSession::new(&name, &cmd)
                .await
                .with_context(|| {
                    format!(
                        "spawn warm `claude` tmux session `{name}`. \
                         Is tmux installed and is `{binary}` on PATH?"
                    )
                })?;
            // B-6 Item 4: apply bridge.py-derived per-session tmux
            // options. Best-effort: failures log at WARN and the rest
            // still apply; quality-of-life only, not correctness.
            super::claude_tmux::configure_session_for_claude(&session).await;
            // Initial settle — interactive claude takes ~1s to render
            // its splash + show the input prompt. Skipping this races
            // the first send against the splash redraw.
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            *guard = Some(session);
        }

        let send_result = {
            let session = guard.as_ref().expect("session populated above");
            // Pick #35 (Session 14, B-6 gap-fix): use the operator-tunable
            // timeouts threaded through from freedom.yaml::claude_cli.tmux,
            // not the module-level constants. `send_and_wait` is now a
            // legacy entry kept only for tests + callers that haven't
            // adopted the timeout knobs.
            super::claude_tmux::send_and_wait_with_timeouts(
                session,
                &payload,
                std::time::Duration::from_secs(idle_timeout_secs),
                std::time::Duration::from_secs(hard_timeout_secs),
            )
            .await
        };

        // Success: a non-empty pane reply ends the loop.
        if let Ok(r) = &send_result {
            if !r.trim().is_empty() {
                break r.clone();
            }
        }

        // Failure path: model the outcome as a `claude_retry::FailureSignal`.
        // `exit_code == Some(0)` + empty stdout is the EmptyStdout signature
        // (empty pane reply / hard timeout with no output); a vanished pane
        // carries the SessionCollision needle in its message; any other tmux
        // error is classified from its text (Auth keywords vs transient).
        // `exit_code == Some(0)` is the EmptyStdout signature (empty pane
        // reply / hard timeout — pane mid tool-call); a vanished pane carries
        // the SessionCollision needle in its Display; any other tmux error is
        // classified from its text (Auth keywords vs transient). Error arms
        // reuse the variant's own Display so operator + classifier see the
        // same string.
        let (exit_code, err_msg): (Option<i32>, String) = match &send_result {
            Ok(_) => (Some(0), "claude pane returned empty output".to_string()),
            Err(e @ super::claude_tmux::ClaudeTmuxError::PaneDisappeared { .. }) => {
                (None, e.to_string())
            }
            Err(e @ super::claude_tmux::ClaudeTmuxError::HardTimeoutNoOutput) => {
                (Some(0), e.to_string())
            }
            Err(e @ super::claude_tmux::ClaudeTmuxError::Tmux(_)) => (None, e.to_string()),
        };
        let signal = super::claude_retry::FailureSignal {
            exit_code,
            stdout: "",
            stderr: "",
            error_message: &err_msg,
        };

        match plan_tmux_retry(&signal, attempt) {
            TmuxRetryPlan::Surface { class, hint } => {
                // Surface. If the pane is dead (SessionCollision), drop +
                // rotate so the next call respawns cleanly — preserves the
                // prior PaneDisappeared contract.
                if class == super::claude_retry::RetryClass::SessionCollision {
                    if let Some(mut old) = guard.take() {
                        let _ = old.kill().await;
                    }
                    // Bump the name suffix (mirrors the compaction-rotation
                    // path below): tmux keeps a killed session's window
                    // registered under `remain-on-exit`, so reusing the same
                    // name would race a duplicate-session spawn failure.
                    tmux_slot
                        .rotation_seq
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                return Err(anyhow::anyhow!(
                    "claude tmux send failed after {} attempt(s) [{}]: {} — {}. \
                     If this recurs, run `neoth doctor`.",
                    attempt + 1,
                    class.as_str(),
                    err_msg,
                    hint
                ));
            }
            TmuxRetryPlan::Retry(step) => {
                warn!(
                    class = step.class.as_str(),
                    attempt = attempt + 1,
                    backoff_ms = step.sleep.as_millis() as u64,
                    hint = step.hint,
                    "claude tmux send failed — retrying"
                );
                if step.reset_session {
                    if let Some(mut old) = guard.take() {
                        let _ = old.kill().await;
                    }
                    // Fresh name on respawn — see the rotation note above.
                    tmux_slot
                        .rotation_seq
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                tokio::time::sleep(step.sleep).await;
                attempt += 1;
                continue;
            }
        }
    };

    if response.contains(COMPACTION_MARKER) {
        let count = tmux_slot
            .compaction_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        debug!(
            count,
            cap = tmux_slot.compaction_rotate_after,
            "claude tmux compaction observed"
        );
        if count >= tmux_slot.compaction_rotate_after {
            if let Some(mut old) = guard.take() {
                let _ = old.kill().await;
                info!(
                    cap = tmux_slot.compaction_rotate_after,
                    "claude tmux rotated after compaction cap reached"
                );
            }
            tmux_slot
                .compaction_count
                .store(0, std::sync::atomic::Ordering::Relaxed);
            tmux_slot
                .rotation_seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    let latency = started.elapsed();
    debug!(
        model = %model,
        response_bytes = response.len(),
        latency_ms = latency.as_millis(),
        "claude_cli tmux completion"
    );

    // No empty-response guard here: the GOLD-WIRE-06 retry loop only breaks on
    // a non-empty reply (an empty pane reply is the EmptyStdout class, retried
    // then surfaced as a classified error inside the loop), so `response` is
    // guaranteed non-empty at this point.

    Ok(Completion {
        text: response,
        model,
        latency,
        // Interactive CLI doesn't surface token usage in the pane.
        // Token counting via `/cost` scrape is a follow-up.
        input_tokens: None,
        output_tokens: None,
        cache_creation_tokens: None,
        cache_read_tokens: None,
    })
}

/// Classified outcome of parsing one NDJSON line from
/// `claude --output-format stream-json`. `Ignore` covers the events we
/// recognise but do not act on (start/stop markers, system metadata,
/// tool-use blocks — claude-cli adds variants over time and ignoring is
/// forward-compatible). `ParseError` carries the serde error message so
/// the caller can surface a precise diagnostic.
#[derive(Debug, PartialEq)]
enum StreamEvent {
    TextDelta(String),
    Usage {
        input: Option<u32>,
        output: Option<u32>,
    },
    Ignore,
    ParseError(String),
}

/// Parse one NDJSON line from claude-cli's stream-json output.
///
/// Anthropic's streaming event shape (subset we care about):
///   - `content_block_delta.delta.text` → incremental text chunk
///   - `message_delta.usage.{input_tokens, output_tokens}` → token totals
///   - `result.usage.{...}` → claude-cli's own summary at stream end
///
/// Everything else (`message_start`, `content_block_start/stop`,
/// `message_stop`, `system`, `assistant` wrapper, unknown tool events)
/// is classified `Ignore`. A line that fails JSON parse altogether is
/// `ParseError` — surfaces as an error chunk in the stream because the
/// CLI contract is violated.
fn parse_stream_event(line: &str) -> StreamEvent {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return StreamEvent::ParseError(e.to_string()),
    };
    let event_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match event_type {
        "content_block_delta" => {
            // Standard shape: { "type":"content_block_delta",
            //                   "delta":{"type":"text_delta","text":"..."}}
            // Tool-use deltas (`input_json_delta`) are intentionally
            // dropped — operator-facing streaming should only carry the
            // human-readable text content.
            let delta = value.get("delta");
            let delta_type = delta
                .and_then(|d| d.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if delta_type == "text_delta" {
                let text = delta
                    .and_then(|d| d.get("text"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if text.is_empty() {
                    StreamEvent::Ignore
                } else {
                    StreamEvent::TextDelta(text.to_string())
                }
            } else {
                StreamEvent::Ignore
            }
        }
        "message_delta" | "result" => {
            // Both shapes carry the same usage block: { usage:
            // {input_tokens:N, output_tokens:N} }. `result` is the
            // claude-cli-specific terminator; `message_delta` is the
            // upstream Anthropic event. Either suffices.
            let usage = value.get("usage");
            let input = usage
                .and_then(|u| u.get("input_tokens"))
                .and_then(|v| v.as_u64())
                .map(|n| n as u32);
            let output = usage
                .and_then(|u| u.get("output_tokens"))
                .and_then(|v| v.as_u64())
                .map(|n| n as u32);
            if input.is_none() && output.is_none() {
                StreamEvent::Ignore
            } else {
                StreamEvent::Usage { input, output }
            }
        }
        _ => StreamEvent::Ignore,
    }
}

fn build_prompt_payload(req: &Request) -> String {
    if let Some(sys) = &req.system {
        let scrubbed = strip_memory_triggers(sys);
        format!("[system]\n{scrubbed}\n\n[user]\n{}", req.prompt)
    } else {
        req.prompt.clone()
    }
}

/// B-7 (Phase 11a continuation): strip Claude Code Memory + slash + file
/// trigger strings from a system-prompt block before passing it to
/// `claude --print`. The operator's `NEOTH.md` / skill prompts / channel
/// context get concatenated into the system block; if any of those
/// upstream sources accidentally include a Claude Code control marker
/// the CLI would interpret it as an in-conversation command rather than
/// plain text.
///
/// Sanitised patterns (line-anchored, leading-whitespace tolerant):
///   - `# ...`       → Memory directive (would be appended to CLAUDE.md)
///   - `/cmd ...`    → slash command (would dispatch to Claude Code's tools)
///   - `@path/file`  → file-reference hint (would attempt to attach)
///
/// Each matched leading character is rewritten to a visually equivalent
/// non-ASCII codepoint so the CLI tokenizer no longer parses it as a
/// control marker, while the rendered output stays readable:
///   - `#` → `＃` (U+FF03 fullwidth number sign)
///   - `/` → `⁄` (U+2044 fraction slash)
///   - `@` → `＠` (U+FF20 fullwidth at-sign)
fn strip_memory_triggers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let trimmed = line.trim_start();
        let leading = &line[..line.len() - trimmed.len()];
        out.push_str(leading);
        if let Some(rest) = trimmed.strip_prefix("# ") {
            // Memory directive — rewrite leading `#` to fullwidth so the
            // CLI tokenizer no longer sees the `# ` prefix while the
            // rendered output stays readable.
            out.push('\u{ff03}');
            out.push(' ');
            out.push_str(rest);
        } else if trimmed.starts_with('/')
            && trimmed
                .chars()
                .nth(1)
                .is_some_and(|c| c.is_ascii_alphabetic())
        {
            // Slash command — neutralise the leading slash with U+2044.
            out.push('\u{2044}');
            out.push_str(&trimmed[1..]);
        } else if trimmed.starts_with('@')
            && trimmed
                .chars()
                .nth(1)
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '/' || c == '.')
        {
            // File-attachment hint — replace `@` with fullwidth.
            out.push('\u{ff20}');
            out.push_str(&trimmed[1..]);
        } else {
            out.push_str(trimmed);
        }
    }
    out
}

// Keep StreamExt in scope for `.next()` on the returned stream in tests.
#[allow(unused_imports)]
use StreamExt as _;

#[cfg(test)]
mod tests {
    use super::*;

    // ── GOLD-WIRE-06: claude_retry-driven tmux retry policy ───────────────

    /// Test helper: the `TmuxRetryStep` if the plan says retry, else None.
    fn retry_step(plan: TmuxRetryPlan) -> Option<TmuxRetryStep> {
        match plan {
            TmuxRetryPlan::Retry(s) => Some(s),
            TmuxRetryPlan::Surface { .. } => None,
        }
    }

    #[test]
    fn plan_tmux_retry_auth_surfaces_immediately() {
        // Acceptance: an auth failure NEVER retries — `plan_tmux_retry`
        // surfaces on the very first attempt, carrying the Auth class.
        use crate::providers::claude_retry::RetryClass;
        let sig = crate::providers::claude_retry::FailureSignal {
            exit_code: None,
            stdout: "",
            stderr: "",
            error_message: "OAuth token expired — please run `claude /login`",
        };
        assert!(
            matches!(
                plan_tmux_retry(&sig, 0),
                TmuxRetryPlan::Surface {
                    class: RetryClass::Auth,
                    ..
                }
            ),
            "auth failure must surface immediately as Auth, never retry"
        );
    }

    #[test]
    fn plan_tmux_retry_empty_stdout_retries_once_with_backoff() {
        // Acceptance: an empty pane reply (exit 0 + blank stdout) retries
        // once with the 2s idle-wait backoff, then is exhausted.
        use crate::providers::claude_retry::{FailureSignal, RetryClass};
        let sig = FailureSignal {
            exit_code: Some(0),
            stdout: "   ",
            stderr: "",
            error_message: "claude pane returned empty output",
        };
        let step = retry_step(plan_tmux_retry(&sig, 0)).expect("empty stdout retries once");
        assert_eq!(step.class, RetryClass::EmptyStdout);
        assert!(
            step.sleep >= std::time::Duration::from_millis(2_000),
            "empty-stdout backoff is the longer idle wait, got {:?}",
            step.sleep
        );
        assert!(
            !step.reset_session,
            "empty stdout does not reset the session"
        );
        assert!(
            retry_step(plan_tmux_retry(&sig, 1)).is_none(),
            "empty stdout is max_attempts=1 — attempt 1 is exhausted"
        );
    }

    #[test]
    fn plan_tmux_retry_pane_disappeared_resets_and_retries_once() {
        use crate::providers::claude_retry::{FailureSignal, RetryClass};
        // The real `ClaudeTmuxError::PaneDisappeared` Display, which the loop
        // feeds into the signal — must classify as SessionCollision.
        let sig = FailureSignal {
            exit_code: None,
            stdout: "",
            stderr: "",
            error_message: "claude pane disappeared mid-conversation (session=neoth-cc-1-0) — restart needed",
        };
        let step = retry_step(plan_tmux_retry(&sig, 0)).expect("session collision retries once");
        assert_eq!(step.class, RetryClass::SessionCollision);
        assert!(
            step.reset_session,
            "a vanished pane must reset the warm session before the retry"
        );
        assert!(
            retry_step(plan_tmux_retry(&sig, 1)).is_none(),
            "session collision is max_attempts=1"
        );
    }

    #[test]
    fn plan_tmux_retry_transient_uses_growing_backoff_to_three() {
        use crate::providers::claude_retry::{FailureSignal, RetryClass};
        let sig = FailureSignal {
            exit_code: None,
            stdout: "",
            stderr: "",
            error_message: "connection refused",
        };
        let s0 = retry_step(plan_tmux_retry(&sig, 0)).expect("attempt 0 retries");
        let s1 = retry_step(plan_tmux_retry(&sig, 1)).expect("attempt 1 retries");
        assert_eq!(s0.class, RetryClass::Transient);
        assert!(s1.sleep > s0.sleep, "transient backoff grows per attempt");
        assert!(
            retry_step(plan_tmux_retry(&sig, 3)).is_none(),
            "transient exhausts at max_attempts=3"
        );
    }

    #[test]
    fn scrub_drops_operator_declared_prefixes_and_neoth_vars() {
        // Serialize against other env-mutating tests — the scrub reads the
        // WHOLE process env, so a concurrent set_var elsewhere would race.
        // See crate::test_env.
        let _env = crate::test_env::lock();
        // A generic, operator-declared harness prefix (no personal names) +
        // NEOTH control vars. Only the declared prefix + NEOTH_* (except
        // NEOTH_LOG) should disappear.
        unsafe {
            std::env::set_var("MYGW_TEST_KEY", "leak");
            std::env::set_var("NEOTH_TEST_KEY", "leak3");
            std::env::set_var("NEOTH_LOG", "info"); // must SURVIVE scrubbing
            std::env::set_var("NEOTH_KEEPME_NOT", "leak4"); // dropped
        }
        let scrubbed = scrub_outbound_env_with(&["MYGW_".to_string()]);
        let keys: Vec<&str> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();

        assert!(
            !keys.contains(&"MYGW_TEST_KEY"),
            "operator-declared prefix must be dropped"
        );
        assert!(!keys.contains(&"NEOTH_TEST_KEY"));
        assert!(!keys.contains(&"NEOTH_KEEPME_NOT"));
        assert!(keys.contains(&"NEOTH_LOG"), "NEOTH_LOG must survive");

        unsafe {
            std::env::remove_var("MYGW_TEST_KEY");
            std::env::remove_var("NEOTH_TEST_KEY");
            std::env::remove_var("NEOTH_LOG");
            std::env::remove_var("NEOTH_KEEPME_NOT");
        }
    }

    #[test]
    fn scrub_with_no_declared_prefixes_keeps_arbitrary_vars() {
        // Public-default posture: with NO operator-declared prefixes, the
        // scrub must NOT drop arbitrary third-party vars — only the generic
        // NEOTH_*/CI/CLAUDECODE/TMUX scrubs apply. Nothing operator-specific
        // is hardcoded.
        let _env = crate::test_env::lock();
        unsafe {
            std::env::set_var("SOMEGATEWAY_KEY", "keep");
        }
        let scrubbed = scrub_outbound_env_with(&[]);
        let keys: Vec<&str> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            keys.contains(&"SOMEGATEWAY_KEY"),
            "no declared prefixes => arbitrary var must survive"
        );
        unsafe {
            std::env::remove_var("SOMEGATEWAY_KEY");
        }
    }

    /// B-6 / Agent 5 wedge: `cached_scrubbed_env()` must return the
    /// exact same slice address on repeat calls (`OnceLock` fast
    /// path), so spawn-per-call doesn't re-iterate the OS env.
    #[test]
    fn cached_scrubbed_env_returns_same_slice_on_repeated_calls() {
        let first = cached_scrubbed_env();
        let second = cached_scrubbed_env();
        // Pointer identity proves the cache hit — OnceLock returns
        // a reference into the same heap-stored Vec on every call.
        assert!(
            std::ptr::eq(first.as_ptr(), second.as_ptr()),
            "cached_scrubbed_env must return the same backing storage on repeat calls"
        );
        // Content sanity check — non-empty + contains nothing with
        // a harness prefix (drift guard against future scrub
        // misconfigurations).
        assert!(!first.is_empty(), "scrubbed env must include base vars");
        for (k, _) in first.iter() {
            // NEOTH's own vars are always scrubbed (except NEOTH_LOG),
            // independent of operator-declared prefixes.
            assert!(
                !(k.starts_with("NEOTH_") && k != "NEOTH_LOG"),
                "cached env leaked NEOTH_* key (only NEOTH_LOG should survive): {k}"
            );
        }
    }

    #[test]
    fn strip_memory_triggers_defangs_memory_line() {
        // `# foo` on its own line would be a Memory append. Strip the
        // trigger but preserve the visible payload.
        let input = "# remember the operator prefers blunt replies";
        let out = strip_memory_triggers(input);
        assert!(
            !out.starts_with("# "),
            "leading `# ` must not survive: {out:?}"
        );
        assert!(out.contains("remember the operator prefers blunt replies"));
    }

    #[test]
    fn strip_memory_triggers_defangs_slash_command() {
        let input = "/compact some hint";
        let out = strip_memory_triggers(input);
        assert!(
            !out.starts_with('/'),
            "leading `/` must be neutralised: {out:?}"
        );
        assert!(out.starts_with('\u{2044}'));
        assert!(out.contains("compact some hint"));
    }

    #[test]
    fn strip_memory_triggers_defangs_file_attachment_hint() {
        let input = "@src/main.rs check this";
        let out = strip_memory_triggers(input);
        assert!(!out.starts_with('@'));
        assert!(out.starts_with('\u{ff20}'));
        assert!(out.contains("src/main.rs"));
    }

    #[test]
    fn strip_memory_triggers_preserves_clean_lines() {
        let input = "You are an analytic assistant.\nFollow PEP-8 conventions.";
        let out = strip_memory_triggers(input);
        assert_eq!(out, input);
    }

    #[test]
    fn strip_memory_triggers_handles_leading_whitespace_before_trigger() {
        // The trim ignores indentation but the indent is preserved in
        // the output so visual layout survives.
        let input = "    # operator note";
        let out = strip_memory_triggers(input);
        assert!(out.starts_with("    "), "indent preserved: {out:?}");
        assert!(!out.contains("    # "));
        assert!(out.contains("operator note"));
    }

    #[test]
    fn strip_memory_triggers_keeps_inline_hash_intact() {
        // `foo # bar` (hash mid-line) is not a Memory directive — the
        // sanitizer should not touch it.
        let input = "use the # sentinel value";
        let out = strip_memory_triggers(input);
        assert_eq!(out, input);
    }

    #[test]
    fn strip_memory_triggers_keeps_slash_url_paths_alone() {
        // `/path` that starts with a non-letter (like `//comment` or
        // `/123`) is not a slash command — we only neutralise when the
        // second char is alphabetic.
        let input = "//two-slash comment";
        let out = strip_memory_triggers(input);
        assert_eq!(out, input, "comment-style // must survive untouched");
    }

    #[test]
    fn strip_memory_triggers_multi_line_mixed_payload() {
        let input = "intro\n# memory hijack\n/compact also bad\nnormal line";
        let out = strip_memory_triggers(input);
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some("intro"));
        let memory_line = lines.next().unwrap();
        assert!(
            memory_line.starts_with('\u{ff03}'),
            "leading fullwidth hash: {memory_line:?}"
        );
        assert!(!memory_line.starts_with("# "));
        assert!(memory_line.contains("memory hijack"));
        let slash_line = lines.next().unwrap();
        assert!(slash_line.starts_with('\u{2044}'));
        assert!(slash_line.contains("compact"));
        assert_eq!(lines.next(), Some("normal line"));
    }

    #[test]
    fn parse_stream_event_extracts_text_delta() {
        let line = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello "}}"#;
        assert_eq!(
            parse_stream_event(line),
            StreamEvent::TextDelta("Hello ".to_string())
        );
    }

    #[test]
    fn parse_stream_event_ignores_empty_text_delta() {
        // A `text_delta` event with empty text contributes nothing — drop
        // it before the chunk reaches the operator. Anthropic emits
        // these occasionally between content blocks.
        let line =
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":""}}"#;
        assert_eq!(parse_stream_event(line), StreamEvent::Ignore);
    }

    #[test]
    fn parse_stream_event_extracts_usage_from_message_delta() {
        let line = r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":42,"output_tokens":17}}"#;
        assert_eq!(
            parse_stream_event(line),
            StreamEvent::Usage {
                input: Some(42),
                output: Some(17),
            }
        );
    }

    #[test]
    fn parse_stream_event_extracts_usage_from_result_event() {
        // claude-cli's terminator event also carries usage in the same
        // shape — accept it so token counts survive the stream when
        // upstream Anthropic format drops `message_delta`.
        let line = r#"{"type":"result","result":"final text","usage":{"input_tokens":10,"output_tokens":3}}"#;
        assert_eq!(
            parse_stream_event(line),
            StreamEvent::Usage {
                input: Some(10),
                output: Some(3),
            }
        );
    }

    #[test]
    fn parse_stream_event_ignores_input_json_delta() {
        // Tool-use deltas (input_json_delta) are not operator-visible
        // text and would corrupt the streamed response if emitted.
        let line = r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\""}}"#;
        assert_eq!(parse_stream_event(line), StreamEvent::Ignore);
    }

    #[test]
    fn parse_stream_event_ignores_unknown_event_types() {
        // Forward-compat: claude-cli adds variants over time. Ignoring
        // unknowns keeps the stream alive across CLI upgrades.
        let line = r#"{"type":"some_future_event","payload":"whatever"}"#;
        assert_eq!(parse_stream_event(line), StreamEvent::Ignore);
    }

    #[test]
    fn parse_stream_event_ignores_message_start_and_stop() {
        assert_eq!(
            parse_stream_event(r#"{"type":"message_start","message":{"id":"x"}}"#),
            StreamEvent::Ignore,
        );
        assert_eq!(
            parse_stream_event(r#"{"type":"message_stop"}"#),
            StreamEvent::Ignore,
        );
        assert_eq!(
            parse_stream_event(r#"{"type":"content_block_start","index":0}"#),
            StreamEvent::Ignore,
        );
        assert_eq!(
            parse_stream_event(r#"{"type":"content_block_stop","index":0}"#),
            StreamEvent::Ignore,
        );
    }

    #[test]
    fn parse_stream_event_surfaces_malformed_json_as_parse_error() {
        // The CLI contract says every line is JSON — anything else is a
        // protocol violation we want to surface, not silently drop.
        match parse_stream_event("not actually json {") {
            StreamEvent::ParseError(_) => {}
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn parse_stream_event_message_delta_without_usage_ignored() {
        // Some message_delta events carry only the stop_reason; no usage.
        // Should not falsely surface a Usage{None,None} chunk.
        let line = r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#;
        assert_eq!(parse_stream_event(line), StreamEvent::Ignore);
    }

    // ── B-6 Item 3: env scrub + model normalisation ──────────────────────

    #[test]
    fn scrub_drops_ci_markers() {
        // CI markers must not survive — bridge.py drops them so claude
        // doesn't enable CI-mode formatting that breaks pane scrape.
        unsafe {
            std::env::set_var("CI", "true");
            std::env::set_var("GITHUB_ACTIONS", "true");
            std::env::set_var("JENKINS_URL", "http://ci.local");
        }
        let scrubbed = scrub_outbound_env();
        let keys: Vec<&str> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"CI"));
        assert!(!keys.contains(&"GITHUB_ACTIONS"));
        assert!(!keys.contains(&"JENKINS_URL"));
        unsafe {
            std::env::remove_var("CI");
            std::env::remove_var("GITHUB_ACTIONS");
            std::env::remove_var("JENKINS_URL");
        }
    }

    #[test]
    fn scrub_drops_claudecode_prefixes() {
        // When NEOTH runs as a subprocess of claude-code itself, those
        // markers must not pass to the child claude — would confuse the
        // CLI into thinking it's re-entering its parent session.
        let _env = crate::test_env::lock();
        unsafe {
            std::env::set_var("CLAUDECODE", "1");
            std::env::set_var("CLAUDE_CODE_SESSION_ID", "abc-123");
        }
        let scrubbed = scrub_outbound_env();
        let keys: Vec<&str> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"CLAUDECODE"));
        assert!(!keys.contains(&"CLAUDE_CODE_SESSION_ID"));
        unsafe {
            std::env::remove_var("CLAUDECODE");
            std::env::remove_var("CLAUDE_CODE_SESSION_ID");
        }
    }

    #[test]
    fn scrub_drops_tmux_vars_for_subprocess_path() {
        // Subprocess claude must not see TMUX env or it renders
        // box-drawing chrome that corrupts --print JSON output.
        let _env = crate::test_env::lock();
        unsafe {
            std::env::set_var("TMUX", "/tmp/tmux-1000/default,1234,0");
            std::env::set_var("TMUX_PANE", "%1");
        }
        let scrubbed = scrub_outbound_env();
        let keys: Vec<&str> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"TMUX"));
        assert!(!keys.contains(&"TMUX_PANE"));
        unsafe {
            std::env::remove_var("TMUX");
            std::env::remove_var("TMUX_PANE");
        }
    }

    #[test]
    fn scrub_injects_mandatory_bridge_py_vars() {
        // Bridge.py-derived knobs that MUST survive into the child
        // claude regardless of operator env. Drift-guarded so a future
        // refactor that drops one fails loudly.
        let scrubbed = scrub_outbound_env();
        let map: std::collections::HashMap<&str, &str> = scrubbed
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(map.get("DISABLE_AUTOUPDATER"), Some(&"1"));
        assert_eq!(map.get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"), Some(&"1"));
        assert_eq!(map.get("BASH_DEFAULT_TIMEOUT_MS"), Some(&"120000"));
        assert_eq!(map.get("MAX_THINKING_TOKENS"), Some(&"10000"));
    }

    #[test]
    fn scrub_inject_overrides_existing_operator_value() {
        // If the operator pinned DISABLE_AUTOUPDATER=0 (wanting
        // auto-update inside claude), we still force 1 — auto-update
        // mid-warm-session would freeze the pane for 30s + break
        // running prompts. Operator concerns are real but tractable
        // out-of-band (separate `npm i -g @anthropic-ai/claude-code`).
        let _env = crate::test_env::lock();
        unsafe {
            std::env::set_var("DISABLE_AUTOUPDATER", "0");
        }
        // Bypass the OnceLock by calling the inner function directly.
        let scrubbed = scrub_outbound_env();
        let value = scrubbed
            .iter()
            .find(|(k, _)| k == "DISABLE_AUTOUPDATER")
            .map(|(_, v)| v.as_str());
        assert_eq!(value, Some("1"), "injection must override operator value");
        unsafe {
            std::env::remove_var("DISABLE_AUTOUPDATER");
        }
    }

    #[test]
    fn normalise_model_maps_opusplan_to_canonical_one_million_context() {
        assert_eq!(normalise_model("opusplan"), "claude-opus-4-7[1m]");
        assert_eq!(normalise_model("opus-plan"), "claude-opus-4-7[1m]");
    }

    #[test]
    fn normalise_model_passes_through_unknown_values_verbatim() {
        // Drift guard: we never silently rewrite unknown model names
        // (would mask typos as "model not found" surfacing late).
        assert_eq!(normalise_model("claude-opus-4-7"), "claude-opus-4-7");
        assert_eq!(normalise_model("sonnet-4-6"), "sonnet-4-6");
        assert_eq!(normalise_model(""), "");
        // MV-01d non-regression: current + future Opus/Sonnet codenames
        // pass through verbatim with NO hand-patching — the
        // model-version-agnostic hard rule. New models work the day they
        // ship via claude-cli, no NEOTH release needed.
        assert_eq!(normalise_model("claude-opus-4-8"), "claude-opus-4-8");
        assert_eq!(normalise_model("claude-opus-4-9"), "claude-opus-4-9");
        assert_eq!(normalise_model("claude-sonnet-4-8"), "claude-sonnet-4-8");
    }

    #[test]
    fn new_with_backend_normalises_legacy_model_alias() {
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "opusplan".into(),
            ClaudeBackend::Auto,
            10,
        );
        assert_eq!(adapter.model, "claude-opus-4-7[1m]");
    }

    // ── Backend selection + TmuxSlot wiring ──────────────────────────────

    #[test]
    fn claude_backend_parse_accepts_canonical_lowercase_strings() {
        assert_eq!(ClaudeBackend::parse("auto"), Some(ClaudeBackend::Auto));
        assert_eq!(ClaudeBackend::parse("tmux"), Some(ClaudeBackend::Tmux));
        assert_eq!(
            ClaudeBackend::parse("subprocess"),
            Some(ClaudeBackend::Subprocess)
        );
    }

    #[test]
    fn claude_backend_parse_is_case_insensitive() {
        assert_eq!(ClaudeBackend::parse("TMUX"), Some(ClaudeBackend::Tmux));
        assert_eq!(
            ClaudeBackend::parse("Subprocess"),
            Some(ClaudeBackend::Subprocess)
        );
    }

    #[test]
    fn claude_backend_parse_rejects_unknown_values() {
        assert_eq!(ClaudeBackend::parse(""), None);
        assert_eq!(ClaudeBackend::parse("invalid"), None);
        assert_eq!(ClaudeBackend::parse("tmuxx"), None);
    }

    #[test]
    fn claude_backend_default_is_auto() {
        assert_eq!(ClaudeBackend::default(), ClaudeBackend::Auto);
    }

    #[test]
    fn legacy_new_constructor_picks_auto_backend() {
        let adapter = ClaudeCliAdapter::new("claude".into(), "sonnet-4-6".into());
        assert_eq!(adapter.backend(), ClaudeBackend::Auto);
    }

    #[test]
    fn new_with_backend_pins_backend_and_compaction_cap() {
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "opus-4-7".into(),
            ClaudeBackend::Tmux,
            5,
        );
        assert_eq!(adapter.backend(), ClaudeBackend::Tmux);
        assert_eq!(adapter.tmux_slot.compaction_rotate_after, 5);
    }

    /// Pin the bridge.py-derived marker. Bridge.py uses
    /// `"Memory was condensed"` to detect compactions in operator
    /// pipelines; drifting from that exact substring would silently
    /// disable rotation + leak personality drift across long sessions.
    #[test]
    fn compaction_marker_matches_bridge_py() {
        assert_eq!(COMPACTION_MARKER, "Memory was condensed");
    }

    #[tokio::test]
    async fn effective_backend_returns_explicit_tmux_unchanged() {
        // Tmux/Subprocess are passed verbatim — no environment probe.
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "sonnet".into(),
            ClaudeBackend::Tmux,
            10,
        );
        assert_eq!(adapter.effective_backend().await, ClaudeBackend::Tmux);
    }

    #[tokio::test]
    async fn effective_backend_returns_explicit_subprocess_unchanged() {
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "sonnet".into(),
            ClaudeBackend::Subprocess,
            10,
        );
        assert_eq!(adapter.effective_backend().await, ClaudeBackend::Subprocess);
    }

    // ── Audit 2026-05-19 (Pick #3) — Auto→Subprocess fallback warn ────

    #[tokio::test]
    async fn explicit_subprocess_does_not_set_auto_fallback_flag() {
        // Operator picked Subprocess on purpose — they don't need
        // the install-tmux nag.
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "sonnet".into(),
            ClaudeBackend::Subprocess,
            10,
        );
        let _ = adapter.effective_backend().await;
        assert!(!adapter.auto_fallback_warned_for_test());
    }

    #[tokio::test]
    async fn explicit_tmux_does_not_set_auto_fallback_flag() {
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "sonnet".into(),
            ClaudeBackend::Tmux,
            10,
        );
        let _ = adapter.effective_backend().await;
        assert!(!adapter.auto_fallback_warned_for_test());
    }

    #[tokio::test]
    async fn auto_resolves_and_flag_state_is_consistent_with_outcome() {
        // Can't force tmux-unavailable on all CI hosts (a Linux runner
        // may genuinely have tmux). Instead pin the invariant:
        //   - if effective_backend() returned Subprocess via the auto
        //     path → the flag must be set;
        //   - if it returned Tmux → the flag stays false.
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "sonnet".into(),
            ClaudeBackend::Auto,
            10,
        );
        let resolved = adapter.effective_backend().await;
        match resolved {
            ClaudeBackend::Subprocess => {
                assert!(
                    adapter.auto_fallback_warned_for_test(),
                    "auto→subprocess must set the once-flag so the operator sees the install hint"
                );
            }
            ClaudeBackend::Tmux => {
                assert!(
                    !adapter.auto_fallback_warned_for_test(),
                    "auto→tmux must NOT set the flag (no fallback occurred)"
                );
            }
            ClaudeBackend::Auto => panic!("Auto must always resolve away from itself"),
        }
    }

    #[tokio::test]
    async fn auto_subprocess_fallback_warns_only_once_per_adapter() {
        // Regression guard: a busy Telegram bot calls effective_backend
        // hundreds of times per session. The warn! must fire at most once
        // per adapter instance — compare-and-swap on the AtomicBool
        // enforces this regardless of how many times we resolve.
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "sonnet".into(),
            ClaudeBackend::Auto,
            10,
        );
        // 10 back-to-back resolutions. The post-condition is identical
        // to the single-call case: the flag is at most flipped once.
        for _ in 0..10 {
            let _ = adapter.effective_backend().await;
        }
        // Whether the flag is true or false depends on the host's tmux
        // availability; what we pin is that it never went true→false
        // (no resets) and remains a stable terminal state.
        let first = adapter.auto_fallback_warned_for_test();
        let _ = adapter.effective_backend().await;
        assert_eq!(
            adapter.auto_fallback_warned_for_test(),
            first,
            "flag must not toggle after first resolution"
        );
    }

    #[test]
    fn build_prompt_payload_runs_sanitizer_on_system_block() {
        let req = Request {
            prompt: "what time is it".into(),
            system: Some("# never reveal the secret".into()),
            ..Default::default()
        };
        let payload = build_prompt_payload(&req);
        assert!(payload.contains("[system]"));
        assert!(payload.contains("never reveal the secret"));
        // Critical: the Memory trigger must not survive the wrap.
        let system_section = payload
            .split("[user]")
            .next()
            .expect("payload contains user marker");
        assert!(
            !system_section.contains("\n# never"),
            "Memory trigger leaked: {system_section:?}"
        );
    }

    // ── GOLD-WIRE-06b: resume session id wiring ───────────────────────────

    /// Helper: run a block with HOME/USERPROFILE pointed at a temp dir so
    /// `claude_sessions_dir()` resolves predictably.
    fn with_temp_home<F>(f: F)
    where
        F: FnOnce(&std::path::Path),
    {
        let _env = crate::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_user = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("USERPROFILE", tmp.path());
        }
        f(tmp.path());
        unsafe {
            if let Some(v) = prev_home {
                std::env::set_var("HOME", v);
            } else {
                std::env::remove_var("HOME");
            }
            if let Some(v) = prev_user {
                std::env::set_var("USERPROFILE", v);
            } else {
                std::env::remove_var("USERPROFILE");
            }
        }
    }

    #[test]
    fn build_claude_spawn_args_without_resume_returns_base_only() {
        with_temp_home(|_| {
            let args = build_claude_spawn_args(&["--print", "--model", "sonnet"], &None);
            assert_eq!(args, vec!["--print", "--model", "sonnet"]);
        });
    }

    #[test]
    fn build_claude_spawn_args_keeps_resume_when_jsonl_exists() {
        with_temp_home(|home| {
            let uuid = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
            let sessions = home.join(".claude").join("sessions");
            std::fs::create_dir_all(&sessions).unwrap();
            std::fs::write(sessions.join(format!("{uuid}.jsonl")), b"{}\n").unwrap();

            let args =
                build_claude_spawn_args(&["--print", "--model", "sonnet"], &Some(uuid.to_string()));
            assert_eq!(args, vec!["--print", "--model", "sonnet", "--resume", uuid]);
        });
    }

    #[test]
    fn build_claude_spawn_args_strips_resume_when_jsonl_missing() {
        with_temp_home(|_| {
            let uuid = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
            // deliberately do NOT create the jsonl
            let args =
                build_claude_spawn_args(&["--print", "--model", "sonnet"], &Some(uuid.to_string()));
            assert_eq!(args, vec!["--print", "--model", "sonnet"]);
        });
    }

    #[test]
    fn build_claude_spawn_args_strips_resume_for_bad_uuid() {
        with_temp_home(|_| {
            let args = build_claude_spawn_args(
                &["--print", "--model", "sonnet"],
                &Some("not-a-uuid".to_string()),
            );
            assert_eq!(args, vec!["--print", "--model", "sonnet"]);
        });
    }

    #[test]
    fn join_args_for_shell_quotes_tokens_with_whitespace() {
        let args = vec![
            "--model".to_string(),
            "claude opus".to_string(),
            "--resume".to_string(),
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427".to_string(),
        ];
        let joined = join_args_for_shell(&args);
        assert_eq!(
            joined,
            "--model \"claude opus\" --resume 1b4e28ba-2fa1-11d2-883f-0016d3cca427"
        );
    }

    #[test]
    fn with_resume_session_id_round_trips() {
        let adapter = ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "sonnet".into(),
            ClaudeBackend::Auto,
            10,
        )
        .with_resume_session_id(Some("deadbeef-dead-beef-dead-beefdeadbeef".to_string()));
        assert_eq!(
            adapter.resume_session_id,
            Some("deadbeef-dead-beef-dead-beefdeadbeef".to_string())
        );
    }
}
