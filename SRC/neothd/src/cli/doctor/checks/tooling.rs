//! Tool/binary availability doctor checks (GOLD-ARCH-06): node/npm
//! toolchain, tmux for claude_cli, stuck claude processes, model caches,
//! hysteria config, wasm plugins.

use std::path::{Path, PathBuf};

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus};

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
pub(crate) fn check_model_caches(_home: &Path) -> CheckOutcome {
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

/// GOLD-ADAPT-DOC-01 — advisory gate for the `ppt_master` skill.
///
/// Probes whether python-pptx is importable on the operator's host.
/// The skill ALWAYS routes and loads regardless of this result —
/// the gate is advisory (the system_prompt itself handles the absent case).
/// PASS when python-pptx is importable; WARN with install hint otherwise.
pub(crate) fn check_pptmaster_python(_home: &Path) -> CheckOutcome {
    let installed = crate::config::installer::is_pptmaster_installed();
    CheckOutcome {
        name: "ppt_master python",
        status: if installed {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if installed {
            "python-pptx importable — ppt_master skill ready (generate presentations with `pip install python-pptx` already done)".to_string()
        } else {
            format!(
                "python-pptx not found — ppt_master skill routes but generated code \
                 needs it to run; install with `{}`",
                crate::config::installer::PPTMASTER_INSTALL_CMD
            )
        },
    }
}

/// GOLD-ADAPT-GRAPH-04 — advisory gate for the `graphify` skill.
///
/// Probes whether graphifyy is importable on the operator's Python via
/// `python -m graphifyy --version` (sync). The skill ALWAYS routes and loads
/// regardless of this result — the gate is ADVISORY. When graphifyy is absent
/// the skill's system_prompt instructs the LLM to surface the install hint.
/// PASS when graphifyy is importable; WARN with install hint otherwise.
pub(crate) fn check_graphify_python(_home: &Path) -> CheckOutcome {
    let installed = crate::config::installer::is_graphify_installed();
    CheckOutcome {
        name: "graphify python",
        status: if installed {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if installed {
            "graphifyy importable — `graphify` skill and `neoth graph` CLI ready".to_string()
        } else {
            format!(
                "graphifyy not found — install with `{}`; then `neoth graph <path>` works",
                crate::config::installer::GRAPHIFY_INSTALL_CMD
            )
        },
    }
}

/// GOLD-ADAPT-DOC-04 — advisory gate for the `officecli_*` skill family (11 skills).
///
/// Probes whether the officecli binary is on PATH via `officecli --version`.
/// The skills ship `enabled: false` and are never activated by the router
/// until the operator explicitly enables them — this check is ADVISORY only.
/// PASS when the binary is present; WARN with install hint (`d.officecli.ai`) otherwise.
pub(crate) fn check_officecli_binary(_home: &Path) -> CheckOutcome {
    let installed = crate::config::installer::is_officecli_installed();
    CheckOutcome {
        name: "officecli binary",
        status: if installed {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if installed {
            "officecli on PATH — the 11 officecli_* skills are ready to enable \
             (set `freedom.yaml::skills.enabled: [officecli_docx_edit, ...]` to activate)"
                .to_string()
        } else {
            format!(
                "officecli not found — 11 officecli_* skills ship disabled until the binary \
                 is on PATH; install from {}",
                crate::config::installer::OFFICECLI_INSTALL_URL
            )
        },
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

/// Registration: this domain's diagnostics, run in order by
/// `run_all_checks`. Adding a check = add the fn + a `CheckDoc` here.
pub(crate) const CHECKS: &[CheckFn] = &[
    check_model_caches,
    check_hysteria_config,
    check_node_toolchain,
    check_tmux_for_claude_cli,
    check_stuck_claude_processes,
    check_wasm_plugins,
    // GOLD-ADAPT-DOC-01 (2026-06-23) — ppt_master Python gate.
    check_pptmaster_python,
    // GOLD-ADAPT-DOC-04 (2026-06-23) — officecli binary gate (11 skills).
    check_officecli_binary,
    // GOLD-ADAPT-GRAPH-04 (2026-06-27) — graphify Python gate (advisory).
    check_graphify_python,
];

/// Operator runbook entries for this domain (the `--explain` surface).
pub(crate) const DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "model caches",
        purpose: "HuggingFace model caches under \
                  `~/.cache/huggingface/hub/`. Doctor checks the bundled \
                  models (whisper-large-v3, clip-vit-base-patch32, \
                  Qwen2.5-3B-Instruct) are downloaded — warns when \
                  missing so operators don't first discover the \
                  network requirement mid-chat.",
        common_failures: "Fresh install with no HF cache; partial download \
                         (interrupted git-lfs).",
        fix: "Run `neoth models pull` to bulk-download. Or accept the \
              warning — models lazy-download on first use.",
    },
    CheckDoc {
        name: "hysteria",
        purpose: "Hysteria QUIC transport config at \
                  `freedom.yaml::hysteria.{server, auth, socks_port}`. \
                  Doctor verifies the binary exists (in PATH or \
                  `~/.neoth/bin/hysteria`) + the SOCKS5 port is bindable.",
        common_failures: "Operator configured server but didn't install \
                         binary; SOCKS port collision with another \
                         service.",
        fix: "Binary missing → download from \
              https://github.com/apernet/hysteria/releases or remove \
              the hysteria block. Port collision → pick a different \
              `socks_port` in freedom.yaml.",
    },
    CheckDoc {
        name: "node toolchain",
        purpose: "NOOB-UX-6 AIO-compliance probe. Detects whether Node \
                  + npm are on PATH so the wizard's auto-install path \
                  for claude-cli / codex actually works (Antigravity \
                  CLI ships via shell-script, not npm). Pass when both \
                  binaries respond to `--version`; Warn when missing \
                  AND the operator's freedom.yaml selects a Node-CLI- \
                  backed provider; silent when the operator runs \
                  LocalQwen / API-only / antigravity providers.",
        common_failures: "Fresh Windows install with no Node — wizard \
                         step 5d picks claude-cli, install_kind spawns \
                         `npm install -g …`, npm not found, operator \
                         gets a cryptic spawn error.",
        fix: "Install Node 20 LTS from nodejs.org/en/download (Windows \
              installer adds npm to PATH automatically). On macOS \
              `brew install node`. On Linux use your distro's package \
              manager (`apt install nodejs npm` on Debian/Ubuntu; \
              `dnf install nodejs` on Fedora). Restart NEOTH so the \
              new PATH takes effect.",
    },
    CheckDoc {
        name: "tmux for claude-cli",
        purpose: "NOOB-UX-6 AIO-compliance probe. claude-cli's working \
                  backend is the tmux warm-session path \
                  (subprocess --print mode is unreliable on some Anthropic \
                  OAuth/build configurations; the tmux warm-session is the \
                  supported path). Pass when `tmux -V` answers; \
                  Warn when missing AND the operator's provider_kind \
                  is ClaudeCli; silent otherwise.",
        common_failures: "Operator picks claude-cli in the wizard on a \
                         fresh Windows or macOS install with no tmux, \
                         daemon silently falls back to the broken \
                         subprocess path on chat send.",
        fix: "Install tmux via your platform's package manager. Windows: \
              `scoop install tmux` or `choco install tmux` or install \
              WSL + apt. macOS: `brew install tmux`. Linux: \
              `apt install tmux` / `pacman -S tmux` / `dnf install tmux`. \
              Restart NEOTH after install. To silence this check when \
              you intentionally accept the subprocess path, set \
              `freedom.yaml::claude_cli.backend: subprocess`.",
    },
    CheckDoc {
        name: "stuck claude processes",
        purpose: "GOLD-WIRE-05 PID-hunter probe. A `claude` / `claude-cli` \
                  process can hang mid tool-call, on a closed OAuth browser, \
                  or on a stale WebSocket — the tmux session still looks live \
                  (low idle_secs) but the pane is unresponsive, so only \
                  PID-CPU monitoring catches it. Scans the process table for \
                  processes past the runtime floor (15 min) at idle CPU \
                  (< 1%). Gated on top-level `provider_kind == claude_cli` so \
                  other providers skip the scan — a claude_cli pinned ONLY in \
                  a per-hemisphere slot is not scanned yet (same scope as the \
                  tmux check). Warn when one is found; never Fail (a hung \
                  process is recoverable, not a broken install).",
        common_failures: "claude-cli wedged after an interrupted tool-call or \
                         an OAuth login where the browser tab was closed \
                         before the callback; a build/test loop that spawned \
                         a claude child which never exited.",
        fix: "Confirm the flagged PID is NOT your active foreground claude \
              session, then kill it — Unix: `kill <pid>` (then `kill -9 <pid>` \
              if it ignores SIGTERM); Windows: `taskkill /PID <pid>` (add `/F` \
              to force). Re-run `neoth doctor` to confirm it cleared. Raise \
              the idle-CPU floor in code if a legitimate low-CPU long-runner \
              keeps tripping the check.",
    },
    CheckDoc {
        name: "wasm plugins",
        purpose: "NOOB-UX-3 effective state of the WASM plugin host. \
                  Reports one of three states: `compiled-in + enabled` \
                  (release feature on, freedom.yaml says enabled), \
                  `compiled-in but disabled by config` (operator flipped \
                  `freedom.yaml::plugins.wasm.enabled: false`), or \
                  `not compiled in` (slim daemon build without the \
                  `wasm-plugin-host` cargo feature). Surfaces the gap \
                  between build-time + runtime gates so an operator \
                  who set `enabled: true` but runs a slim build sees \
                  the mismatch immediately.",
        common_failures: "Operator expects plugins to work on a slim \
                         build (cargo feature not compiled in); \
                         operator's freedom.yaml has `enabled: false` \
                         but the wizard step7b explanation isn't fresh \
                         in memory.",
        fix: "Slim build → rebuild with `--features wasm-plugin-host` \
              or install the release tarball (cargo-dist flips the \
              feature ON). Disabled-by-config → edit \
              `~/.neoth/freedom.yaml` and flip \
              `plugins:\\n  wasm:\\n    enabled: true`, then \
              restart the daemon.",
    },
    // GOLD-ADAPT-DOC-01 (2026-06-23) — ppt_master python gate.
    CheckDoc {
        name: "ppt_master python",
        purpose: "GOLD-ADAPT-DOC-01 advisory gate for the `ppt_master` \
                  bundled skill. Probes whether python-pptx is importable \
                  on the operator's Python by running `python -c \
                  \"import pptx\"` (Windows) or `python3 -c \"import pptx\"` \
                  (Linux/macOS). PASS = python-pptx present, the skill \
                  produces runnable code immediately. WARN = python-pptx \
                  absent, the skill still routes and the LLM will surface \
                  the install hint in its reply. The gate is ADVISORY: \
                  skill routing is never suppressed.",
        common_failures: "Fresh Python install without python-pptx; \
                         operator using a virtual environment that is \
                         not active when the daemon probes; Python not \
                         on PATH at all (Windows without system Python).",
        fix: "Run `pip install python-pptx` (or `pip3 install python-pptx` \
              on Linux/macOS) in the Python environment that will run the \
              generated script. Restart `neoth doctor` to confirm. If \
              Python is not on PATH at all, install Python 3.10+ first \
              from python.org.",
    },
    // GOLD-ADAPT-GRAPH-04 (2026-06-27) — graphify python gate.
    CheckDoc {
        name: "graphify python",
        purpose: "GOLD-ADAPT-GRAPH-04 advisory gate for the `graphify` \
                  bundled skill. Probes whether graphifyy is importable \
                  on the operator's Python by running `python -m graphifyy \
                  --version` (Windows) or `python3 -m graphifyy --version` \
                  (Linux/macOS). PASS = graphifyy present, the `graphify` \
                  skill is fully operational and `neoth graph` CLI works. \
                  WARN = graphifyy absent, the skill still routes and the \
                  LLM will surface the install hint in its reply. The gate \
                  is ADVISORY: skill routing is never suppressed.",
        common_failures: "Fresh Python install without graphifyy; \
                         operator using a virtual environment that is not \
                         active when the daemon probes; Python not on PATH \
                         (Windows without system Python); graphifyy \
                         installed as `graphify` (wrong package name — \
                         the pip package is `graphifyy` with a double y).",
        fix: "Run `pip install graphifyy` (or `pip3 install graphifyy` \
              on Linux/macOS) in the Python environment the daemon uses. \
              Restart `neoth doctor` to confirm PASS. If Python is not on \
              PATH at all, install Python 3.10+ from python.org first.",
    },
    // GOLD-ADAPT-DOC-04 (2026-06-23) — officecli binary gate.
    CheckDoc {
        name: "officecli binary",
        purpose: "GOLD-ADAPT-DOC-04 advisory gate for the 11 `officecli_*` \
                  bundled skills (docx/xlsx/pptx create, edit, format, \
                  convert, pdf export, pipeline). Probes `officecli \
                  --version` on PATH. PASS = binary present, operator can \
                  enable the skill family via `freedom.yaml::skills.enabled`. \
                  WARN = binary absent, skills ship disabled and will not \
                  be activated by the router. The gate is ADVISORY: the \
                  enabled:false field is the actual router gate.",
        common_failures: "officecli not installed (most common — fresh \
                         operator install); officecli installed but not \
                         on PATH (e.g. installed to ~/bin without PATH \
                         update); version mismatch (old officecli returns \
                         non-zero on --version).",
        fix: "Download and install officecli from d.officecli.ai. Ensure \
              the binary directory is on your PATH (add it to ~/.bashrc / \
              ~/.zshrc / System env on Windows). After install, run \
              `neoth doctor` to confirm PASS. Then enable skills: add \
              `officecli_docx_edit` (and others) to \
              `freedom.yaml::skills.enabled` and restart the daemon.",
    },
];
