//! Tool/binary availability doctor checks (GOLD-ARCH-06): node/npm
//! toolchain, tmux for claude_cli, stuck claude processes, model caches,
//! hysteria config, wasm plugins.

use std::path::{Path, PathBuf};

use super::super::{CheckOutcome, CheckStatus};

/// Probe a binary's `--version`. Returns `Some(stdout)` on success,
/// `None` when the binary is missing or returns non-zero. Pure
/// sync — doctor checks all run synchronously.
pub(crate) fn probe_version_sync(binary: &str) -> Option<String> {
    let output = match std::process::Command::new(binary).arg("--version").output() {
        Ok(o) => o,
        Err(_) => return None,
    };
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// NOOB-UX-6: probe node + npm on PATH. Warn only when the operator
/// picked a Node-backed CLI provider (claude-cli / codex) at the
/// wizard — LocalQwen / API-only / antigravity (shell-script) /
/// gemini_api (REST) operators don't need npm and shouldn't see
/// yellow. Antigravity CLI was migrated off npm by Google on
/// 2026-05-19 so the legacy `gemini_cli` provider_kind no longer
/// implies npm dependency either.
pub(crate) fn check_node_toolchain(home: &Path) -> CheckOutcome {
    let needs_npm = freedom_uses_node_cli_provider(home);
    let node_version = probe_version_sync("node");
    let npm_version = probe_version_sync("npm");
    match (node_version, npm_version, needs_npm) {
        (Some(node), Some(npm), _) => CheckOutcome {
            name: "node toolchain",
            status: CheckStatus::Pass,
            detail: format!("node {node}, npm {npm}"),
        },
        (None, None, false) => CheckOutcome {
            name: "node toolchain",
            status: CheckStatus::Pass,
            detail: "node + npm not on PATH; not needed for your provider".to_string(),
        },
        (node, npm, true) => CheckOutcome {
            name: "node toolchain",
            status: CheckStatus::Warn,
            detail: format!(
                "node={} npm={}; required by your provider_kind for CLI auto-install. \
                 Install Node 20 LTS from nodejs.org / brew / your distro.",
                node.as_deref().unwrap_or("MISSING"),
                npm.as_deref().unwrap_or("MISSING"),
            ),
        },
        (node, npm, false) => CheckOutcome {
            name: "node toolchain",
            status: CheckStatus::Warn,
            detail: format!(
                "partial: node={} npm={}; your provider doesn't need npm but a half-\
                 install often signals a broken PATH.",
                node.as_deref().unwrap_or("MISSING"),
                npm.as_deref().unwrap_or("MISSING"),
            ),
        },
    }
}

/// NOOB-UX-6: probe tmux on PATH. Warn only when provider_kind ==
/// ClaudeCli, since claude-cli's only working backend on some setups
/// is the tmux warm-session path.
pub(crate) fn check_tmux_for_claude_cli(home: &Path) -> CheckOutcome {
    let needs_tmux = freedom_uses_claude_cli(home);
    match (probe_version_sync("tmux"), needs_tmux) {
        (Some(v), _) => CheckOutcome {
            name: "tmux for claude-cli",
            status: CheckStatus::Pass,
            detail: v,
        },
        (None, false) => CheckOutcome {
            name: "tmux for claude-cli",
            status: CheckStatus::Pass,
            detail: "tmux not on PATH; not needed for your provider".to_string(),
        },
        (None, true) => CheckOutcome {
            name: "tmux for claude-cli",
            status: CheckStatus::Warn,
            detail: "tmux MISSING; claude-cli falls back to the broken --print path. \
                     Install via scoop/choco/brew/apt and restart NEOTH."
                .to_string(),
        },
    }
}

/// GOLD-WIRE-05 — pure render: map the PID hunter's stuck-process list to a
/// doctor `CheckOutcome`. Empty → PASS; any stuck process → WARN (never
/// FAIL — a hung process is a recoverable runtime condition, not a broken
/// install). Kept pure + separate from the scan so the WARN/PASS mapping is
/// unit-testable without spawning processes. Deliberately does NOT echo
/// `claude_pid_hunter::stuck_hint()`, whose copy points at the not-yet-built
/// `neoth doctor stuck-clean` / `neoth chat reset` commands — operator
/// guidance here references only real, available recovery actions.
pub(crate) fn stuck_processes_outcome(
    stuck: &[crate::providers::claude_pid_hunter::StuckProcess],
) -> CheckOutcome {
    const NAME: &str = "stuck claude processes";
    if stuck.is_empty() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "no stuck claude processes".to_string(),
        };
    }
    let listed: Vec<String> = stuck
        .iter()
        .map(|s| {
            format!(
                "pid {} ({}, {}m idle)",
                s.meta.pid,
                s.meta.name,
                s.meta.runtime.as_secs() / 60
            )
        })
        .collect();
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: format!(
            "{} stuck claude process(es): {} — each past the runtime floor at idle CPU \
             (likely hung mid tool-call or on a closed OAuth browser). Confirm it is \
             not your active session, then kill the PID (Unix: `kill <pid>`; Windows: \
             `taskkill /PID <pid>`).",
            stuck.len(),
            listed.join(", ")
        ),
    }
}

/// GOLD-WIRE-05 — flag `claude` processes the PID hunter classifies as
/// stuck (past the runtime floor at idle CPU). Gated on claude_cli being the
/// configured provider so operators on local_qwen / cloud APIs don't pay for
/// a process-table scan that can never find a relevant process. PASS when
/// claude_cli isn't configured or no stuck process is found; WARN listing
/// the offending PIDs otherwise.
pub(crate) fn check_stuck_claude_processes(home: &Path) -> CheckOutcome {
    if !freedom_uses_claude_cli(home) {
        return CheckOutcome {
            name: "stuck claude processes",
            status: CheckStatus::Pass,
            detail: "claude_cli not your provider — process scan skipped".to_string(),
        };
    }
    let stuck = crate::providers::claude_pid_hunter::scan_stuck_processes_blocking(
        crate::providers::claude_pid_hunter::StuckThresholds::default(),
    );
    stuck_processes_outcome(&stuck)
}

/// True when `freedom.yaml::provider_kind` is one of the Node-backed
/// CLIs (claude_cli / codex). Best-effort: a missing or unparseable
/// freedom.yaml returns false so the doctor stays quiet. Antigravity
/// CLI ships via vendor shell-script (not npm), so neither
/// `antigravity_cli` nor the legacy `gemini_cli` alias counts here —
/// listing them would emit a false-positive npm-missing warning to
/// operators who picked the new Google CLI.
pub(crate) fn freedom_uses_node_cli_provider(home: &Path) -> bool {
    let path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return false;
    };
    let kind = val
        .get("provider_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    matches!(kind, "claude_cli" | "codex")
}

/// True when `freedom.yaml::provider_kind == "claude_cli"`. Same
/// best-effort semantics as the node check.
pub(crate) fn freedom_uses_claude_cli(home: &Path) -> bool {
    let path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return false;
    };
    val.get("provider_kind").and_then(|v| v.as_str()) == Some("claude_cli")
}

/// CLIP + Whisper caches are optional — extractions fall back to
/// metadata-only when missing — but operators who plan to send media
/// to NEOTH want them populated. We emit a `Warn` (not `Fail`) so
/// `neoth doctor` exits clean for text-only setups while still
/// surfacing the actionable next step.
pub(crate) fn check_model_caches() -> CheckOutcome {
    use crate::providers::{clip_engine, whisper};

    let clip_dir = clip_engine::default_cache_dir(clip_engine::DEFAULT_CLIP_REPO);
    let clip_present = [
        clip_engine::CONFIG_FILE,
        clip_engine::SAFETENSORS_FILE,
        clip_engine::TOKENIZER_FILE,
    ]
    .iter()
    .all(|f| clip_dir.join(f).exists());

    let whisper_dir = whisper_doctor_cache_dir(whisper::DEFAULT_WHISPER_REPO);
    let whisper_present = [
        whisper::CONFIG_FILE,
        whisper::TOKENIZER_FILE,
        whisper::SAFETENSORS_FILE,
    ]
    .iter()
    .all(|f| whisper_dir.join(f).exists());

    let detail = match (clip_present, whisper_present) {
        (true, true) => "clip + whisper cached".to_string(),
        (true, false) => "whisper missing — run `neoth models pull whisper`".to_string(),
        (false, true) => "clip missing — run `neoth models pull clip`".to_string(),
        (false, false) => {
            "clip + whisper missing — run `neoth models pull clip whisper`".to_string()
        }
    };
    let status = if clip_present && whisper_present {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };
    CheckOutcome {
        name: "model caches",
        status,
        detail,
    }
}

/// R-3 Hysteria — when freedom.yaml has a server configured, verify
/// the binary is reachable + the rendered YAML has the fields Hysteria
/// expects. No live spawn here; that's `neoth hysteria test`'s job.
pub(crate) fn check_hysteria_config(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let Ok(cfg) = crate::config::FreedomConfig::load_from_path(&freedom_path) else {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable; check_freedom_yaml owns the diagnostic".into(),
        };
    };
    let Some(hcfg) = cfg.hysteria.as_ref() else {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "not configured (direct egress)".into(),
        };
    };
    if hcfg.server.is_empty() {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "configured but server empty (direct egress)".into(),
        };
    }
    match crate::transport::hysteria::locate_binary() {
        Ok(path) => CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: format!("binary at {}, server={}", path.display(), hcfg.server),
        },
        Err(e) => CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Warn,
            detail: format!("config set ({}) but binary missing: {e}", hcfg.server,),
        },
    }
}

/// NOOB-UX-3 doctor surface — report the effective state of the
/// WASM plugin host so an operator who expected plugins to be
/// live sees the mismatch (slim build vs. operator-disabled).
pub(crate) fn check_wasm_plugins(home: &Path) -> CheckOutcome {
    use crate::config::FreedomConfig;
    let compiled_in = cfg!(feature = "wasm-plugin-host");
    let cfg_enabled = FreedomConfig::load_from_path(&home.join("freedom.yaml"))
        .map(|c| c.plugins.wasm.enabled)
        .unwrap_or(true);
    let (status, detail) = match (compiled_in, cfg_enabled) {
        (true, true) => (
            CheckStatus::Pass,
            "compiled-in + enabled by config — operator-loadable plugins are live".to_string(),
        ),
        (true, false) => (
            CheckStatus::Warn,
            "compiled-in but DISABLED by config (freedom.yaml::plugins.wasm.enabled = false). \
             Hook actions of kind Plugin{..} will degrade to Allow. \
             Flip the config to enable, or rebuild without `--features wasm-plugin-host` if \
             intentional."
                .to_string(),
        ),
        (false, true) => (
            CheckStatus::Warn,
            "not compiled in (slim daemon build); freedom.yaml has plugins.wasm.enabled=true \
             but the cargo `wasm-plugin-host` feature is OFF. Operator expecting plugins should \
             rebuild with `--features wasm-plugin-host` or install the release tarball."
                .to_string(),
        ),
        (false, false) => (
            CheckStatus::Pass,
            "not compiled in (slim daemon) AND config disabled — coherent slim state".to_string(),
        ),
    };
    CheckOutcome {
        name: "wasm plugins",
        status,
        detail,
    }
}

/// Local copy of the whisper engine's `default_cache_dir` so the doctor
/// can run with the same path math as the engine without exposing the
/// engine's `pub` surface. Kept in sync via the
/// `whisper_cache_dir_matches_engine_default` test in
/// `cli::models::tests`.
pub(crate) fn whisper_doctor_cache_dir(repo: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    let flattened = repo.replace('/', "-");
    home.join(".neoth").join("models").join(flattened)
}
