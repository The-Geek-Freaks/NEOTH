//! Claude CLI tmux backend (B-6 full warm-session port).
//!
//! Ports the protocol from Alex's `claude_openai_bridge.py` v6.2 — the
//! only path that reliably produces output for the operator's stack
//! (per `memory/neoth-claude-cli-tmux-mandatory.md`). `claude --print`
//! subprocess mode is documented broken in the operator's environment;
//! this module is the mandatory replacement, not an optimisation.
//!
//! Protocol pieces ported from bridge.py:
//!   - **Idle detection** (`is_pane_idle`): the interactive `claude`
//!     CLI shows a `❯` prompt marker + a `─` border in the last few
//!     pane lines once it stops generating. Absence of working
//!     indicators alone isn't enough — the prompt must be visible.
//!   - **Working detection** (`is_pane_working`): `ctrl+c to interrupt`
//!     / `esc to interrupt` text + Unicode markers (`✽ ✻ ✶ ·` with
//!     `…`) + `Running…` indicator are the signals that the model is
//!     still emitting tokens. Idle-timer must NOT fire while working.
//!   - **Dual-timer wait** (`send_and_wait`): IDLE_TIMEOUT (no-change
//!     window — default 120s) tracks output-stability; HARD_TIMEOUT
//!     (absolute cap — default 300s) bounds total wait. Working
//!     status resets the idle timer.
//!   - **Stable confirm**: after detecting idle, poll once more after
//!     [`STABLE_CONFIRM_DELAY`] to confirm no late tokens arrive.
//!
//! Deferred from bridge.py (port surface stays minimal):
//!   - pipe-pane byte-offset tracking — bridge.py uses `pipe-pane` to
//!     write the pane stream to a file + reads only new bytes per
//!     response. NEOTH v0.1 uses `capture-pane` snapshots; the
//!     pipe-pane optimisation is a follow-up once we ship a working
//!     baseline.
//!   - load-buffer + paste-buffer prompt injection — bridge.py uses
//!     this for prompts >2KB to avoid tmux's send-keys arg limits.
//!     NEOTH v0.1 ships with `send_text` + `send_enter` from
//!     `TmuxSession`; large prompts that hit the arg limit will need
//!     the buffer path added.
//!   - wa-send.js detection — Alex's stack uses a side-channel for
//!     WhatsApp delivery. Not relevant to NEOTH's pipeline.
//!
//! ## Failure mode
//!
//! When the pane disappears mid-conversation (claude crash, OOM,
//! operator killed the session manually), this module returns
//! [`ClaudeTmuxError::PaneDisappeared`]. Callers (the adapter) should
//! NOT silently fall back to `claude --print` subprocess mode — that
//! path is documented broken in the operator's environment. Instead
//! surface the error to the operator with a clear "restart tmux
//! session" pointer.

use std::process::Stdio;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::process::Command;
use tracing::{debug, info, warn};

use super::tmux_session::TmuxSession;

/// B-6 Item 4: per-session tmux options NEOTH applies after creating a
/// warm `claude` session. Bridge.py applies these via `~/.tmux.conf`
/// on its dedicated `-L neoth` server; NEOTH v0.1 shares the
/// operator's default tmux server and so applies the subset that is
/// safely session-scoped or window-scoped (server-scoped options that
/// would mutate operator's other tmux sessions are documented in
/// [`SERVER_LEVEL_NOTE`] for the operator's ~/.tmux.conf).
///
/// Applied per session (safe under shared server):
///   - `status off` (session-level) — hide status bar so capture-pane
///     sees one more line of response content per snapshot.
///   - `monitor-activity off` (window-level) — silence activity bell
///     so operator's other tmux clients don't see NEOTH's chatter.
///   - `monitor-bell off` (window-level) — same for bell signals.
///   - `remain-on-exit on` (window-level) — keep the pane visible
///     after claude exits so the operator can read the death reason
///     in `tmux attach -t neoth-cc-*` instead of finding an empty
///     window. Critical for diagnosing PaneDisappeared errors.
///
/// Operator-applied via ~/.tmux.conf (server-scoped — NEOTH does
/// NOT touch these; would corrupt operator's other tmux sessions):
///   - `set -s escape-time 0` (zero ESC-key detection delay)
///   - `set -s assume-paste-time 0` (no paste auto-detection)
///   - `set -gs terminal-overrides "*:smcup@:rmcup@"` (no alt-screen)
///   - `set -g history-limit 10000` (raise scrollback)
///   - `set -g allow-passthrough on` (OSC-52 clipboard)
const SERVER_LEVEL_NOTE: &str = concat!(
    "For best `neoth chat` performance via tmux, add to ~/.tmux.conf:\n",
    "  set -s escape-time 0\n",
    "  set -s assume-paste-time 0\n",
    "  set -gs terminal-overrides '*:smcup@:rmcup@'\n",
    "  set -g history-limit 10000\n",
    "  set -g allow-passthrough on"
);

/// Apply NEOTH's per-session tmux options to the warm `claude`
/// session. Best-effort: any single failure logs at WARN and the
/// rest still apply — bridge.py-derived options are operator quality
/// improvements, not load-bearing for correctness.
pub async fn configure_session_for_claude(session: &TmuxSession) {
    let name = session.name();
    // status (session-scoped)
    let _ = run_tmux_set(&["set-option", "-t", name, "status", "off"]).await;
    // window-scoped trio
    let _ = run_tmux_set(&["set-window-option", "-t", name, "monitor-activity", "off"]).await;
    let _ = run_tmux_set(&["set-window-option", "-t", name, "monitor-bell", "off"]).await;
    let _ = run_tmux_set(&["set-window-option", "-t", name, "remain-on-exit", "on"]).await;
    debug!(session = name, "claude tmux per-session options applied");
    info!("{SERVER_LEVEL_NOTE}");
}

/// Run `tmux <args>` for a set-option invocation, logging failures at
/// WARN. Caller can ignore the Result — failures are quality-of-life
/// degradations, not correctness violations.
async fn run_tmux_set(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("tmux")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await;
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => {
            warn!(args = ?args, code = s.code(), "tmux set-option failed (non-fatal)");
            anyhow::bail!("tmux {:?} exited with {:?}", args, s.code());
        }
        Err(e) => {
            warn!(args = ?args, error = %e, "tmux set-option spawn failed (non-fatal)");
            Err(anyhow::Error::new(e))
        }
    }
}

/// Idle-timer window — no pane-content change for this long counts as
/// "Claude finished emitting tokens". Ported from bridge.py
/// `IDLE_TIMEOUT = 120` (raised from 90 to survive SOUL.md reads —
/// Claude can spend ~90s scanning operator memory before answering).
pub const IDLE_TIMEOUT_SECS: u64 = 120;

/// Absolute upper bound. After this, give up + return whatever response
/// was captured. Ported from bridge.py `HARD_TIMEOUT = 300`.
pub const HARD_TIMEOUT_SECS: u64 = 300;

/// After detecting idle, wait this long + check once more to confirm
/// no late tokens arrive. Ported from bridge.py `TMUX_STABLE_CONFIRM`.
pub const STABLE_CONFIRM_DELAY_MS: u64 = 2000;

/// Polling cadence inside the wait loop. Ported from bridge.py
/// `TMUX_POLL_INTERVAL`.
pub const POLL_INTERVAL_MS: u64 = 500;

/// Initial grace period after sending — gives Claude a moment to
/// start rendering before the idle/working checks fire. Ported from
/// bridge.py `TMUX_INITIAL_GRACE`.
pub const INITIAL_GRACE_MS: u64 = 800;

/// Pane history depth for the per-loop idle/working check. Tail-only
/// inspection so the check stays cheap even when the session has
/// scrolled hundreds of lines.
pub const CHECK_HISTORY_LINES: i32 = 15;

/// Pane history depth for the final response extraction. Long enough
/// to catch a several-paragraph reply without scrolling back so far
/// that prior turns leak into the parse.
pub const EXTRACT_HISTORY_LINES: i32 = 500;

#[derive(Debug, Error)]
pub enum ClaudeTmuxError {
    #[error("claude pane disappeared mid-conversation (session={session}) — restart needed")]
    PaneDisappeared { session: String },
    #[error(
        "claude tmux wait hit the hard timeout ({HARD_TIMEOUT_SECS}s) without producing output"
    )]
    HardTimeoutNoOutput,
    #[error("tmux operation failed: {0}")]
    Tmux(#[from] anyhow::Error),
}

/// Detect whether the interactive `claude` CLI is actively working.
/// Pure-function — takes the captured pane content + returns the
/// classification. Tests pin every branch.
///
/// The order of checks matters: ALWAYS check idle-prompt presence
/// first. If `❯` + `─` are visible in the tail, Claude is DONE
/// regardless of upstream working markers that may still be in the
/// scrollback (a completed Bash tool call leaves `● Bash` /  `⎿`
/// markers behind that look working-shaped without actually being).
pub fn is_pane_working(content: &str) -> bool {
    if content.is_empty() {
        return false;
    }
    let lines: Vec<&str> = content.lines().collect();
    // Idle prompt + border in last 6 lines → DONE, not working.
    let tail = if lines.len() > 6 {
        &lines[lines.len() - 6..]
    } else {
        &lines[..]
    };
    let (has_prompt, has_border) = scan_idle_markers(tail);
    if has_prompt && has_border {
        return false;
    }
    // Active working text markers.
    let lower = content.to_ascii_lowercase();
    if lower.contains("ctrl+c to interrupt") || lower.contains("esc to interrupt") {
        return true;
    }
    // Thinking-animation Unicode markers in the last 8 lines.
    let working_tail = if lines.len() > 8 {
        &lines[lines.len() - 8..]
    } else {
        &lines[..]
    };
    for line in working_tail {
        let stripped = line.trim_start();
        for marker in ['✽', '✻', '✶', '·'] {
            if stripped.starts_with(marker) && stripped.contains('…') {
                return true;
            }
        }
    }
    // Active tool streaming.
    let running_tail = if lines.len() > 5 {
        &lines[lines.len() - 5..]
    } else {
        &lines[..]
    };
    for line in running_tail {
        if line.trim().contains("Running…") {
            return true;
        }
    }
    false
}

/// Detect whether the pane is showing the idle Claude prompt
/// (`❯` + `─` border) and is NOT working.
pub fn is_pane_idle(content: &str) -> bool {
    if content.is_empty() {
        return false;
    }
    if is_pane_working(content) {
        return false;
    }
    let lines: Vec<&str> = content.lines().collect();
    let tail = if lines.len() > 6 {
        &lines[lines.len() - 6..]
    } else {
        &lines[..]
    };
    let (has_prompt, has_border) = scan_idle_markers(tail);
    has_prompt && has_border
}

fn scan_idle_markers(lines: &[&str]) -> (bool, bool) {
    let mut has_prompt = false;
    let mut has_border = false;
    for line in lines {
        let stripped = line.trim();
        // `❯` alone (or with a single space) marks the prompt position.
        if stripped.contains('❯') && stripped.chars().count() <= 3 {
            has_prompt = true;
        }
        // The pane footer is a long box-drawing rule (────────).
        if stripped.contains('─') && stripped.chars().count() > 20 {
            has_border = true;
        }
    }
    (has_prompt, has_border)
}

/// Send `prompt` into the warm `claude` session + wait for the
/// response. Implements the dual-timer + stable-confirm protocol
/// ported from bridge.py.
///
/// Returns the extracted response text. Empty string means Claude
/// produced no output within the timer window (operator should retry
/// or restart the session).
pub async fn send_and_wait(
    session: &TmuxSession,
    prompt: &str,
) -> std::result::Result<String, ClaudeTmuxError> {
    send_and_wait_with_timeouts(
        session,
        prompt,
        Duration::from_secs(IDLE_TIMEOUT_SECS),
        Duration::from_secs(HARD_TIMEOUT_SECS),
    )
    .await
}

/// Test-injectable variant — production calls use [`send_and_wait`]
/// with the defaults; tests pass shorter timeouts to keep CI fast.
pub async fn send_and_wait_with_timeouts(
    session: &TmuxSession,
    prompt: &str,
    idle_timeout: Duration,
    hard_timeout: Duration,
) -> std::result::Result<String, ClaudeTmuxError> {
    // Send the prompt. v0.1 uses TmuxSession's send_text + send_enter
    // (literal-mode send-keys). load-buffer/paste-buffer is the
    // bridge.py path for >2KB prompts; deferred (see module doc).
    session.send_text(prompt).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    session.send_enter().await?;

    tokio::time::sleep(Duration::from_millis(INITIAL_GRACE_MS)).await;

    let start = Instant::now();
    let mut last_snapshot = String::new();
    let mut last_change = Instant::now();

    loop {
        let elapsed = start.elapsed();
        if elapsed > hard_timeout {
            warn!(
                session = session.name(),
                hard_secs = hard_timeout.as_secs(),
                "claude tmux hard timeout — extracting whatever's there"
            );
            let final_snap = session.capture_pane(EXTRACT_HISTORY_LINES).await?;
            let response = extract_response(&final_snap, prompt);
            if response.is_empty() {
                return Err(ClaudeTmuxError::HardTimeoutNoOutput);
            }
            return Ok(response);
        }

        // Pane death = unrecoverable; surface immediately so caller
        // doesn't silently retry against a dead session.
        if !session.exists().await {
            return Err(ClaudeTmuxError::PaneDisappeared {
                session: session.name().to_string(),
            });
        }

        let snap = session.capture_pane(CHECK_HISTORY_LINES).await?;
        if snap != last_snapshot {
            last_snapshot = snap.clone();
            last_change = Instant::now();
        }

        if is_pane_idle(&snap) {
            tokio::time::sleep(Duration::from_millis(STABLE_CONFIRM_DELAY_MS)).await;
            let confirm = session.capture_pane(CHECK_HISTORY_LINES).await?;
            if confirm == snap && is_pane_idle(&confirm) {
                let full = session.capture_pane(EXTRACT_HISTORY_LINES).await?;
                let response = extract_response(&full, prompt);
                info!(
                    session = session.name(),
                    elapsed_secs = elapsed.as_secs(),
                    response_chars = response.chars().count(),
                    "claude tmux response captured"
                );
                return Ok(response);
            }
        }

        // Idle-timer: no pane-change for `idle_timeout`. Reset the
        // timer when Claude is still working — long tool calls don't
        // emit new pane content per second but ARE producing output
        // that we should wait for.
        let idle_elapsed = last_change.elapsed();
        if idle_elapsed > idle_timeout && elapsed.as_secs() > 15 {
            if is_pane_working(&snap) {
                last_change = Instant::now();
                debug!(
                    session = session.name(),
                    elapsed_secs = elapsed.as_secs(),
                    "idle timer reset: claude still working"
                );
            } else {
                warn!(
                    session = session.name(),
                    elapsed_secs = elapsed.as_secs(),
                    idle_secs = idle_elapsed.as_secs(),
                    "claude tmux idle timeout — no output for {} seconds",
                    idle_elapsed.as_secs()
                );
                let full = session.capture_pane(EXTRACT_HISTORY_LINES).await?;
                return Ok(extract_response(&full, prompt));
            }
        }

        tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

/// Extract the actual response text from the captured pane content.
///
/// Ported from bridge.py v6.3.2 "hardened extractor" (live in
/// v6.4.3-jarvis-live). Strategy:
///   1. Walk pane backwards finding the LAST `●` bullet line that
///      is NOT a tool-output bullet (skip "Searched", "Read",
///      "Edited", "Wrote", "Ran", etc.).
///   2. If no conversational bullet found, fall back to the LAST
///      tool bullet (operator still wants SOME signal).
///   3. Take that bullet's content + walk forward picking up
///      continuation lines until next bullet / border / prompt.
///   4. Skip TUI artefacts (single glyphs, fragmenty redraw debris,
///      spinner verb suffixes).
///   5. Strip `⎿` continuation prefix on follow-up lines.
///   6. Strip leading tool-output prefix lines + trailing partial-
///      redraw junk + final noise pass.
///
/// Supersedes the earlier prompt-prefix-fallback approach (still in
/// git for the next sprint as the v6.0-style port). The bullet-line
/// strategy handles prompt-wrap correctly without needing to find
/// the prompt in the pane at all — Claude's response always lands
/// on a fresh `●` bullet.
pub fn extract_response(pane: &str, prompt: &str) -> String {
    let lines: Vec<&str> = pane.lines().collect();

    let (last_bullet_idx, used_tool_fallback) = match find_last_response_bullet(&lines) {
        Some((i, is_tool)) => (i, is_tool),
        None => return String::new(),
    };

    let mut response_parts: Vec<String> = Vec::new();
    if let Some(first) = extract_bullet_content(lines[last_bullet_idx]) {
        let stripped_first = strip_spinner_suffix(&first);
        if !stripped_first.is_empty() {
            response_parts.push(stripped_first);
        }
    }

    // Walk forward picking up continuation lines.
    for line in lines.iter().skip(last_bullet_idx + 1) {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }
        // Stop on border / prompt / next bullet.
        if (stripped.contains('─') && stripped.chars().count() > 20)
            || (stripped.contains('❯') && stripped.chars().count() <= 3)
            || stripped.starts_with('●')
        {
            break;
        }
        // Skip TUI artefacts: single glyphs + short fragments + spinner tokens.
        if stripped.chars().count() <= 3 && !stripped.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // Strip ⎿ continuation marker.
        let cleaned = if let Some(rest) = stripped.strip_prefix('⎿') {
            rest.trim()
        } else {
            stripped
        };
        if cleaned.is_empty() {
            continue;
        }
        response_parts.push(cleaned.to_string());
    }

    let raw = response_parts.join("\n").trim().to_string();
    if raw.is_empty() {
        return String::new();
    }

    // Strip leading tool-output prefix lines (v6.4.0 cleanup). Skip
    // when we deliberately fell back to a tool bullet because no
    // conversational bullet existed — in that case the tool prefix
    // IS the response.
    let mut out_lines: Vec<&str> = raw.lines().collect();
    if !used_tool_fallback {
        while let Some(first) = out_lines.first() {
            let s = first.trim();
            if s.is_empty() {
                out_lines.remove(0);
                continue;
            }
            if TOOL_OUTPUT_PREFIXES.iter().any(|p| s.starts_with(p)) {
                out_lines.remove(0);
                continue;
            }
            break;
        }
    }

    // Strip trailing partial-redraw junk (short last lines that are
    // mostly whitespace).
    while out_lines.len() > 1 {
        let last = out_lines.last().unwrap().trim();
        let spaces = last.chars().filter(|c| c.is_whitespace()).count();
        if last.chars().count() < 4 || spaces > last.chars().count() / 2 {
            out_lines.pop();
        } else {
            break;
        }
    }

    let result = out_lines.join("\n").trim().to_string();
    // Final noise filter (existing line-classifier pass).
    let final_lines: Vec<&str> = result.lines().filter(|l| !is_noise_line(l)).collect();
    // Drop the echoed prompt if it survived.
    let trimmed_prompt = prompt.trim();
    let final_lines: Vec<&str> = final_lines
        .into_iter()
        .filter(|l| l.trim() != trimmed_prompt)
        .collect();
    final_lines.join("\n").trim().to_string()
}

/// Tool-output bullet prefixes — these `●` lines are tool results,
/// NOT conversation. The extractor skips them when looking for the
/// "last response bullet" + drops them if they survive to the
/// post-processing pass.
const TOOL_OUTPUT_PREFIXES: &[&str] = &[
    "Searched for",
    "Read ",
    "Edited ",
    "Created ",
    "Wrote ",
    "Ran ",
    "Listed ",
    "Deleted ",
    "Moved ",
    "Copied ",
    "Updated ",
    "Glob found",
    "Found ",
    "No matches",
];

/// Returns `(line_index, used_tool_fallback)`. `used_tool_fallback`
/// is true when no conversational bullet existed + we anchored on a
/// tool-output bullet — the caller must skip the leading-tool-prefix
/// strip in that case so the tool result survives as the response.
fn find_last_response_bullet(lines: &[&str]) -> Option<(usize, bool)> {
    let mut tool_bullet_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().rev() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('●') {
            continue;
        }
        let content = trimmed.trim_start_matches('●').trim();
        let is_tool = TOOL_OUTPUT_PREFIXES.iter().any(|p| content.starts_with(p));
        if is_tool {
            if tool_bullet_idx.is_none() {
                tool_bullet_idx = Some(i);
            }
            continue;
        }
        return Some((i, false));
    }
    tool_bullet_idx.map(|i| (i, true))
}

fn extract_bullet_content(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('●') {
        return None;
    }
    Some(trimmed.trim_start_matches('●').trim().to_string())
}

/// Strip trailing spinner-verb suffixes like "  · Enchanting…" that
/// the TUI sometimes leaves on the bullet line when capture races
/// the redraw.
fn strip_spinner_suffix(s: &str) -> String {
    // Find the first occurrence of a lowercase-letter sequence ending
    // in "ing" followed by "…" or "..."; everything from that point
    // is spinner debris. Pure-string scan (no regex dep needed).
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_uppercase() {
            // Scan a word like "Enchanting".
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_lowercase() {
                j += 1;
            }
            // Did the word end in "ing"?
            if j > i + 3 && &bytes[j - 3..j] == b"ing" {
                // Check whether spinner-completion follows.
                let after = &s[j..];
                let after_trimmed = after.trim_start();
                if after_trimmed.starts_with('…') || after_trimmed.starts_with("...") {
                    return s[..i].trim_end().to_string();
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    s.to_string()
}

fn truncate_at_idle_prompt(text: &str) -> &str {
    // The interactive `claude` CLI ends every response with a fresh
    // `❯` prompt + `─` border. We cut at the first border we hit
    // AFTER the response started.
    let mut last_safe_end = text.len();
    for (i, line) in text.lines().enumerate() {
        if line.trim().chars().count() > 20 && line.trim().contains('─') {
            // Found a border — truncate at its start.
            let prefix_lines: Vec<&str> = text.lines().take(i).collect();
            let prefix_len = prefix_lines.join("\n").len();
            last_safe_end = prefix_len;
            break;
        }
    }
    &text[..last_safe_end]
}

/// B-6 Item 3i — strip ANSI escape sequences in-place (CSI + OSC +
/// the bare ESC byte). `tmux capture-pane` without `-e` already
/// drops most ANSI, but operator setups using `-e` for colour-aware
/// capture or non-tmux interactive captures need this. Pure-string,
/// no regex dep; handles:
///   - CSI: `ESC [ params final` (params: `0-?`, final: `@-~`)
///   - OSC: `ESC ] params BEL` or `ESC ] params ESC \\` (string term)
///   - Bare ESC characters that snuck in alone (drop them).
/// Reference: ECMA-48 §5.4 + xterm Control Sequences.
pub fn strip_ansi_sequences(input: &str) -> String {
    const ESC: char = '\u{1b}';
    const BEL: char = '\u{07}';
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != ESC {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some(&'[') => {
                chars.next();
                while let Some(&p) = chars.peek() {
                    if ('\u{40}'..='\u{7e}').contains(&p) {
                        chars.next();
                        break;
                    }
                    chars.next();
                }
            }
            Some(&']') => {
                chars.next();
                while let Some(&p) = chars.peek() {
                    if p == BEL {
                        chars.next();
                        break;
                    }
                    if p == ESC {
                        chars.next();
                        if let Some(&q) = chars.peek() {
                            if q == '\\' {
                                chars.next();
                                break;
                            }
                        }
                        break;
                    }
                    chars.next();
                }
            }
            _ => {
                // Bare ESC or unknown introducer — drop ESC, leave
                // the next char in place.
            }
        }
    }
    out
}

/// B-6 Item 3j — merge a base `system` block with an additional
/// `--append-system-prompt` payload. The two strings come from
/// distinct sources (operator's `freedom.yaml::providers.system_prompt`
/// vs a per-call `Request::system_addendum`) and must compose without
/// either overwriting the other.
///
/// Contract:
///   - Either side empty/whitespace-only → return the other verbatim.
///   - Both present → join with a single blank line (Markdown-friendly
///     paragraph break) so a downstream renderer keeps both blocks
///     visually distinct.
///   - Order is preserved: base block comes first; the append block
///     is appended below. Tested + drift-guarded so a future swap
///     doesn't silently change operator behaviour.
pub fn merge_system_prompts(base: &str, append: &str) -> String {
    let base_trim = base.trim();
    let append_trim = append.trim();
    match (base_trim.is_empty(), append_trim.is_empty()) {
        (true, true) => String::new(),
        (true, false) => append_trim.to_string(),
        (false, true) => base_trim.to_string(),
        (false, false) => format!("{base_trim}\n\n{append_trim}"),
    }
}

fn is_noise_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }
    // ANSI escape leftovers we don't want in the operator-visible reply.
    if trimmed.starts_with("\u{1b}[") {
        return true;
    }
    // Claude Code rendering scaffolding — UI chrome, not reply content.
    let noise_prefixes = [
        "● ", "⎿ ", "↳ ", "│ ", "╭", "╰", "╮", "╯",
        // Memory-feedback hint lines the CLI prints after every reply.
        "> ",
    ];
    for pfx in noise_prefixes {
        if trimmed.starts_with(pfx) {
            return true;
        }
    }
    // Working indicators that may end up captured if we read too early.
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("ctrl+c to interrupt") || lower.contains("esc to interrupt") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Idle / working detection ──────────────────────────────────────────

    #[test]
    fn idle_pane_with_prompt_and_border_is_idle() {
        let pane = "previous response text\nsome lines\n\n\
                    ──────────────────────────────────────\n\
                    ❯\n\
                    ──────────────────────────────────────\n";
        assert!(is_pane_idle(pane));
        assert!(!is_pane_working(pane));
    }

    #[test]
    fn working_pane_with_esc_to_interrupt_is_working() {
        let pane = "\n\nThinking…\n· Working on it…\n  esc to interrupt\n";
        assert!(is_pane_working(pane));
        assert!(!is_pane_idle(pane));
    }

    #[test]
    fn working_pane_with_unicode_marker_in_tail() {
        let pane = "header\n\n✽ Thinking…\n";
        assert!(is_pane_working(pane));
    }

    #[test]
    fn idle_takes_precedence_over_working_markers_in_scrollback() {
        // Completed bash tool leaves `● Bash` + `⎿ Error` in the
        // history. With a fresh idle prompt below them, the pane is
        // idle.
        let pane = "● Bash\n⎿ Error: exited 1\n\n\
                    ──────────────────────────────────────\n\
                    ❯\n\
                    ──────────────────────────────────────\n";
        assert!(is_pane_idle(pane));
        assert!(!is_pane_working(pane));
    }

    #[test]
    fn empty_pane_is_neither_idle_nor_working() {
        assert!(!is_pane_idle(""));
        assert!(!is_pane_working(""));
    }

    #[test]
    fn pane_without_border_is_not_idle() {
        // Prompt visible but no border — incomplete prompt frame.
        let pane = "previous reply ended\n❯\n";
        assert!(!is_pane_idle(pane));
    }

    #[test]
    fn pane_without_prompt_is_not_idle() {
        // Border visible but no prompt marker.
        let pane = "previous reply\n\
                    ──────────────────────────────────────\n";
        assert!(!is_pane_idle(pane));
    }

    // ── Response extraction ──────────────────────────────────────────────

    #[test]
    fn extract_response_takes_last_conversational_bullet() {
        let pane = "(scrollback)\n\
                    > what is 2 + 2?\n\
                    \n\
                    ● The answer is 4.\n\
                    \n\
                    ──────────────────────────────────────\n\
                    ❯\n";
        let r = extract_response(pane, "what is 2 + 2?");
        assert_eq!(r, "The answer is 4.");
    }

    #[test]
    fn extract_response_skips_tool_bullets_finds_conversational() {
        let pane = "> read this file\n\
                    \n\
                    ● Read file.rs\n\
                    ⎿ 100 lines\n\
                    \n\
                    ● Here's a summary of file.rs.\n\
                    The main function spawns three workers.\n\
                    \n\
                    ──────────────────────────────────────\n\
                    ❯\n";
        let r = extract_response(pane, "read this file");
        assert!(
            r.contains("Here's a summary"),
            "must pick the conversational bullet, got: {r:?}"
        );
        assert!(
            r.contains("three workers"),
            "continuation line must survive, got: {r:?}"
        );
        assert!(!r.contains("Read file.rs"));
    }

    #[test]
    fn extract_response_falls_back_to_tool_bullet_when_no_conversational() {
        // No conversational bullet — operator still wants SOME signal.
        let pane = "> ran a tool\n\
                    \n\
                    ● Read file.rs\n\
                    \n\
                    ──────────────────────────────────────\n\
                    ❯\n";
        let r = extract_response(pane, "ran a tool");
        assert!(r.contains("Read file.rs"));
    }

    #[test]
    fn extract_response_strips_spinner_suffix_from_bullet() {
        let pane = "● Done Enchanting…\n\
                    \n\
                    ──────────────────────────────────────\n\
                    ❯\n";
        let r = extract_response(pane, "");
        assert_eq!(r, "Done");
    }

    #[test]
    fn extract_response_picks_up_lambda_continuation_lines() {
        let pane = "● Step 1\n\
                    ⎿ continuation detail\n\
                    ⎿ more detail\n\
                    \n\
                    ──────────────────────────────────────\n\
                    ❯\n";
        let r = extract_response(pane, "");
        assert!(r.contains("Step 1"));
        assert!(r.contains("continuation detail"));
        assert!(r.contains("more detail"));
        assert!(!r.contains('⎿'));
    }

    #[test]
    fn extract_response_handles_wrapped_prompt() {
        // v6.3.2 bullet-line strategy doesn't depend on finding the
        // prompt in the pane — prompt-wrap is a non-issue.
        let prompt = "fetch and summarise https://example.com/very/long/path/that/wraps";
        let pane = "> fetch and summarise https://example.com/very/long/p\n\
                    ath/that/wraps\n\
                    \n\
                    ● The page describes the project structure.\n\
                    \n\
                    ──────────────────────────────────────\n\
                    ❯\n";
        let r = extract_response(pane, prompt);
        assert!(r.contains("project structure"));
    }

    #[test]
    fn extract_response_no_bullet_yields_empty_string() {
        // Bullet-line strategy: no `●` means no extractable response.
        let pane = "(scrollback)\n\
                    > ask\n\
                    Plain response text without a bullet.\n\
                    \n\
                    ──────────────────────────────────────\n\
                    ❯\n";
        let r = extract_response(pane, "ask");
        assert_eq!(r, "");
    }

    #[test]
    fn extract_response_empty_pane_yields_empty_string() {
        let r = extract_response("", "anything");
        assert_eq!(r, "");
    }

    #[test]
    fn noise_line_classifier_pins_known_chrome() {
        assert!(is_noise_line(""));
        assert!(is_noise_line("● Bash"));
        assert!(is_noise_line("⎿ ran"));
        assert!(is_noise_line("│ inner"));
        assert!(is_noise_line("╭ border-corner"));
        assert!(is_noise_line("> prompt-echo"));
        assert!(!is_noise_line("This is real reply content."));
        assert!(!is_noise_line("Code: let x = 1;"));
    }

    // ── Wait loop (tmux-gated) ────────────────────────────────────────────
    //
    // The full `send_and_wait` loop requires a live tmux session +
    // an interactive `claude` CLI to be useful. We can't replicate
    // either in CI. The pure-function detection logic above covers
    // every branch the loop hits per iteration; the loop itself is
    // straight tokio-sleep + state-machine glue. Operator-side
    // verification happens via:
    //   neoth chat "hello" with freedom.yaml::claude_cli.tmux_backend=true
    // once the wiring lands in ClaudeCliAdapter.

    #[test]
    fn server_level_note_lists_the_five_operator_settings() {
        // Drift guard: bridge.py pins these 5 server-scoped tmux
        // settings as best-practice for warm claude sessions. NEOTH
        // doesn't apply them itself (would corrupt shared tmux
        // servers) but MUST surface them to operators.
        assert!(SERVER_LEVEL_NOTE.contains("escape-time 0"));
        assert!(SERVER_LEVEL_NOTE.contains("assume-paste-time 0"));
        assert!(SERVER_LEVEL_NOTE.contains("terminal-overrides"));
        assert!(SERVER_LEVEL_NOTE.contains("history-limit 10000"));
        assert!(SERVER_LEVEL_NOTE.contains("allow-passthrough on"));
    }

    /// Live tmux integration — only runs when tmux is on PATH.
    /// Spawns a `sleep 60` session, applies NEOTH's options, then
    /// reads back the values via `tmux show-options` to confirm
    /// they landed.
    #[tokio::test]
    async fn live_configure_session_applies_per_session_options() {
        if !TmuxSession::is_available().await {
            eprintln!("tmux not available, skipping live integration test");
            return;
        }
        let name = format!("neoth-cfg-{}", std::process::id());
        let mut session = match TmuxSession::new(&name, "cat").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tmux new-session failed: {e}");
                return;
            }
        };
        configure_session_for_claude(&session).await;
        // Read back status — must be "off".
        let output = tokio::process::Command::new("tmux")
            .arg("show-options")
            .arg("-t")
            .arg(&name)
            .arg("status")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .expect("show-options");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("status off"),
            "expected `status off` per-session, got: {stdout}"
        );
        let _ = session.kill().await;
    }

    #[test]
    fn timeout_constants_match_bridge_py_defaults() {
        // Drift guard — bridge.py operator-tested these. Don't lower
        // them without re-validating against Alex's SOUL.md workload.
        assert_eq!(IDLE_TIMEOUT_SECS, 120);
        assert_eq!(HARD_TIMEOUT_SECS, 300);
        assert_eq!(STABLE_CONFIRM_DELAY_MS, 2000);
        assert_eq!(POLL_INTERVAL_MS, 500);
    }

    // ── B-6 Item 3i — ANSI strip tests ───────────────────────────

    #[test]
    fn b6_3i_strips_csi_color_sequence() {
        // SGR colour reset: ESC [ 0 m → drops entirely.
        let input = "\u{1b}[31mred text\u{1b}[0m normal";
        assert_eq!(strip_ansi_sequences(input), "red text normal");
    }

    #[test]
    fn b6_3i_strips_csi_cursor_move() {
        // Cursor positioning: ESC [ 12 ; 5 H → drops.
        let input = "before\u{1b}[12;5Hafter";
        assert_eq!(strip_ansi_sequences(input), "beforeafter");
    }

    #[test]
    fn b6_3i_strips_osc_with_bel_terminator() {
        // Set window title: ESC ] 0 ; title BEL → drops entirely.
        let input = "x\u{1b}]0;my title\u{07}y";
        assert_eq!(strip_ansi_sequences(input), "xy");
    }

    #[test]
    fn b6_3i_strips_osc_with_st_terminator() {
        // OSC with ST terminator: ESC ] params ESC \\
        let input = "a\u{1b}]52;c;XYZ\u{1b}\\b";
        assert_eq!(strip_ansi_sequences(input), "ab");
    }

    #[test]
    fn b6_3i_drops_bare_esc() {
        // Bare ESC byte (no introducer): drop the ESC, keep what
        // follows untouched.
        let input = "x\u{1b}y";
        assert_eq!(strip_ansi_sequences(input), "xy");
    }

    #[test]
    fn b6_3i_preserves_non_ansi_content() {
        let input = "plain text\nwith newlines\tand tabs";
        assert_eq!(strip_ansi_sequences(input), input);
    }

    #[test]
    fn b6_3i_strips_multiple_sequences_in_one_string() {
        let input = "\u{1b}[1mbold\u{1b}[0m \u{1b}[32mgreen\u{1b}[0m end";
        assert_eq!(strip_ansi_sequences(input), "bold green end");
    }

    // ── B-6 Item 3j — system-prompt conflict merge tests ─────────

    #[test]
    fn b6_3j_merge_returns_base_when_append_empty() {
        let merged = merge_system_prompts("You are NEOTH.", "");
        assert_eq!(merged, "You are NEOTH.");
    }

    #[test]
    fn b6_3j_merge_returns_append_when_base_empty() {
        let merged = merge_system_prompts("", "Be concise.");
        assert_eq!(merged, "Be concise.");
    }

    #[test]
    fn b6_3j_merge_joins_with_paragraph_break() {
        let merged = merge_system_prompts("You are NEOTH.", "Be concise.");
        assert_eq!(merged, "You are NEOTH.\n\nBe concise.");
    }

    #[test]
    fn b6_3j_merge_handles_both_empty() {
        assert_eq!(merge_system_prompts("", ""), "");
        assert_eq!(merge_system_prompts("   ", "\n\n"), "");
    }

    #[test]
    fn b6_3j_merge_trims_surrounding_whitespace_per_side() {
        // Either side may arrive with trailing newlines (operator
        // wrote heredoc) or leading spaces — normalize before join.
        let merged = merge_system_prompts("  base  \n", "\n\nappend\n");
        assert_eq!(merged, "base\n\nappend");
    }

    #[test]
    fn b6_3j_merge_preserves_order_base_before_append() {
        // Drift guard — flipping the order changes operator semantics
        // (a permission rule in base could be overridden by append).
        let merged = merge_system_prompts("BASE_RULE", "APPEND_RULE");
        let base_idx = merged.find("BASE_RULE").unwrap();
        let append_idx = merged.find("APPEND_RULE").unwrap();
        assert!(base_idx < append_idx);
    }
}
