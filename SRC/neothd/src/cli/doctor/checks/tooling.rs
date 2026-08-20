//! Tool/binary availability doctor checks (GOLD-ARCH-06): node/npm
//! toolchain, tmux for claude_cli, stuck claude processes, model caches,
//! hysteria config, wasm plugins.

use std::path::Path;

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
pub(crate) fn check_model_caches(home: &Path) -> CheckOutcome {
    use crate::providers::clip_engine;

    let models_root = home.join("models");
    let clip_dir = clip_engine::cache_dir_at(&models_root, clip_engine::DEFAULT_CLIP_REPO);
    let clip_health = clip_engine::cache_health_at(&models_root, clip_engine::DEFAULT_CLIP_REPO);
    let clip_ready = clip_health.is_ready();
    let clip_detail = format!("{} ({clip_health})", clip_dir.display());

    let config = crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml"))
        .unwrap_or_default();
    let whisper_target = crate::media::stt_provider::resolve_local_whisper_target(
        home,
        config.media.stt.primary,
        config.media.stt.model_size,
    );
    let (whisper_present, whisper_required, whisper_detail) = match whisper_target {
        Ok(target) => {
            let health = target.cache_health();
            (
                health.is_ready(),
                true,
                format!(
                    "{} {} at {} ({health})",
                    target.backend().as_str(),
                    target.model_id(),
                    target.cache_path().display()
                ),
            )
        }
        Err(error) => (false, false, error.to_string()),
    };

    let detail = match (clip_ready, whisper_required, whisper_present) {
        (true, true, true) => format!(
            "clip cached at {} + configured whisper cached ({whisper_detail})",
            clip_dir.display()
        ),
        (true, true, false) => format!(
            "configured whisper cache not ready ({whisper_detail}) — run `neoth models pull whisper`"
        ),
        (false, true, true) => {
            format!(
                "clip cache not ready ({clip_detail}) — run `neoth models pull clip`; configured whisper cached"
            )
        }
        (false, true, false) => format!(
            "clip cache not ready ({clip_detail}) + configured whisper cache not ready ({whisper_detail}) — run `neoth models pull clip`, then `neoth models pull whisper`"
        ),
        (true, false, _) => format!(
            "clip cached; configured STT has no managed local Whisper cache ({whisper_detail})"
        ),
        (false, false, _) => format!(
            "clip cache not ready ({clip_detail}) — run `neoth models pull clip`; configured STT has no managed local Whisper cache ({whisper_detail})"
        ),
    };
    let status = if clip_ready && (!whisper_required || whisper_present) {
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

/// TTS Gold — validate the exact configured production provider without making
/// a network request or synthesising. Piper checks executable + contained model
/// assets; cloud providers check consent and their canonical credential fields.
pub(crate) fn check_tts_runtime(home: &Path) -> CheckOutcome {
    use crate::media::tts_dispatch::TtsProvider;

    let path = home.join("freedom.yaml");
    let runtime = match crate::config::load_runtime_config_pair_from_path_or_default(&path) {
        Ok(runtime) => runtime,
        Err(_) => {
            return CheckOutcome {
                name: "TTS runtime",
                status: CheckStatus::Pass,
                detail: "config/credential pair unreadable; config check owns this diagnostic"
                    .into(),
            };
        }
    };
    let config = runtime.config;
    let provider = config.media.tts.primary;
    let result = match provider {
        TtsProvider::SystemNative => {
            let binary = match crate::media::tts_provider::pick_native_binary() {
                crate::media::tts_provider::NativeBinary::MacSay => "say",
                crate::media::tts_provider::NativeBinary::LinuxEspeakNg => "espeak-ng",
                crate::media::tts_provider::NativeBinary::WindowsPowerShellSapi => "powershell",
            };
            if crate::media::tts_provider::find_on_path(binary).is_some() {
                Ok(format!("offline system-native provider ready ({binary})"))
            } else {
                Err(format!(
                    "system-native TTS executable `{binary}` is missing"
                ))
            }
        }
        TtsProvider::Piper => {
            let voice = if config.media.tts.voice.is_empty() {
                crate::media::tts_dispatch::pick_voice_for_locale(
                    &config.media.tts.locale,
                    TtsProvider::Piper,
                )
                .unwrap_or("")
                .to_string()
            } else {
                config.media.tts.voice.clone()
            };
            crate::media::tts_provider::piper_status(
                &home.join("models/piper"),
                config.media.tts.piper_model.as_deref(),
                config.media.tts.piper_config.as_deref(),
                &voice,
            )
            .map(|assets| {
                format!(
                    "Piper ready: model={} config={}",
                    assets.model.display(),
                    assets.config.display()
                )
            })
        }
        TtsProvider::EdgeTts => {
            if !config.media.cloud_tts_enabled {
                Err("edge_tts is cloud egress but media.cloud_tts_enabled is false".to_string())
            } else if crate::media::tts_provider::edge_tts_exe().is_none() {
                Err("edge-tts executable missing; install with `pip install edge-tts`".to_string())
            } else {
                Ok("edge_tts executable present + cloud consent enabled".to_string())
            }
        }
        TtsProvider::ElevenLabs | TtsProvider::AzureTts => {
            if !config.media.cloud_tts_enabled {
                Err(format!(
                    "{} selected but media.cloud_tts_enabled is false",
                    provider.as_str()
                ))
            } else {
                let credentials = &runtime.credentials;
                let present = match provider {
                    TtsProvider::ElevenLabs => credentials.elevenlabs_tts_api_key.is_some(),
                    TtsProvider::AzureTts => {
                        credentials.azure_tts_api_key.is_some()
                            && config.media.tts.azure_region.is_some()
                    }
                    _ => unreachable!(),
                };
                if present {
                    Ok(format!("{} consent + credentials ready", provider.as_str()))
                } else {
                    Err(format!(
                        "{} credential/region missing; inspect credentials.yaml and media.tts",
                        provider.as_str()
                    ))
                }
            }
        }
        TtsProvider::ViitorVoice => {
            if !config.media.cloud_tts_enabled {
                Err("viitor_voice selected but media.cloud_tts_enabled is false".to_string())
            } else if config.media.tts.viitor_endpoint.is_none() {
                Err("viitor_voice endpoint missing under media.tts.viitor_endpoint".to_string())
            } else {
                Ok("viitor_voice endpoint + cloud consent configured".to_string())
            }
        }
    };
    match result {
        Ok(detail) => CheckOutcome {
            name: "TTS runtime",
            status: CheckStatus::Pass,
            detail,
        },
        Err(detail) => CheckOutcome {
            name: "TTS runtime",
            status: CheckStatus::Warn,
            detail: format!("{detail}; run `neoth tts status` and `neoth models list`"),
        },
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

/// The complete Graphify readiness result shown by `neoth doctor`.
///
/// `Unavailable` is deliberately distinct from `NotReady`: installing a
/// Python package can repair the latter, but can never create the required
/// descendant-containment primitive on an unsupported platform.
#[derive(Debug, PartialEq, Eq)]
enum GraphifyDoctorReadiness {
    Ready,
    Unavailable(String),
    NotReady(String),
}

/// Perform the same readiness discovery as production Graphify execution.
///
/// Doctor checks use a synchronous function-pointer registry, while
/// [`crate::graphify_runner::GraphifyRuntime::discover`] is intentionally
/// async because it runs a bounded contained process. A short-lived dedicated
/// Tokio runtime bridges that shape without weakening the runtime contract or
/// running a raw ambient `python` probe. The containment prerequisite is
/// checked before creating that runtime, so unsupported platforms execute no
/// Graphify subprocess and receive the exact central reason.
fn graphify_runtime_readiness() -> GraphifyDoctorReadiness {
    if let Err(error) = crate::graphify_runner::ensure_graphify_containment_supported() {
        return GraphifyDoctorReadiness::Unavailable(format!("{error:#}"));
    }

    let worker = std::thread::Builder::new()
        .name("neoth-doctor-graphify".to_owned())
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("create Graphify readiness runtime: {error}"))?;
            runtime
                .block_on(crate::graphify_runner::GraphifyRuntime::discover("python"))
                .map(|_| ())
                .map_err(|error| format!("{error:#}"))
        });

    match worker {
        Ok(worker) => match worker.join() {
            Ok(Ok(())) => GraphifyDoctorReadiness::Ready,
            Ok(Err(error)) => GraphifyDoctorReadiness::NotReady(error),
            Err(_) => GraphifyDoctorReadiness::NotReady(
                "Graphify readiness worker panicked before runtime verification".to_owned(),
            ),
        },
        Err(error) => {
            GraphifyDoctorReadiness::NotReady(format!("start Graphify readiness worker: {error}"))
        }
    }
}

fn graphify_readiness_outcome(readiness: GraphifyDoctorReadiness) -> CheckOutcome {
    let (status, detail) = match readiness {
        GraphifyDoctorReadiness::Ready => (
            CheckStatus::Pass,
            "Graphify runtime verified through NEOTH containment, canonical interpreter, and isolated module contract — `graphify` skill and `neoth graph` CLI ready".to_owned(),
        ),
        GraphifyDoctorReadiness::Unavailable(reason) => (
            CheckStatus::Warn,
            format!(
                "Graphify runtime unavailable: {reason}. Package installation is not a fix on this platform."
            ),
        ),
        GraphifyDoctorReadiness::NotReady(reason) => (
            CheckStatus::Warn,
            format!(
                "Graphify runtime not ready: {reason}. On a supported platform, install with `{}` then rerun `neoth doctor`.",
                crate::config::installer::GRAPHIFY_INSTALL_CMD
            ),
        ),
    };
    CheckOutcome {
        name: "graphify python",
        status,
        detail,
    }
}

/// GOLD-ADAPT-GRAPH-04 — advisory runtime gate for the `graphify` skill.
///
/// This verifies NEOTH-executable Graphify readiness, not merely whether the
/// `graphifyy` distribution can be imported. The skill continues to route
/// when unavailable, but Doctor never reports a command as ready unless the
/// same containment, interpreter identity, isolated environment, deadline,
/// output bounds, and module probe used by production have succeeded.
pub(crate) fn check_graphify_python(_home: &Path) -> CheckOutcome {
    graphify_readiness_outcome(graphify_runtime_readiness())
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

/// Registration: this domain's diagnostics, run in order by
/// `run_all_checks`. Adding a check = add the fn + a `CheckDoc` here.
pub(crate) const CHECKS: &[CheckFn] = &[
    check_model_caches,
    check_tts_runtime,
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
        purpose: "Doctor checks CLIP plus the exact local Whisper backend/model \
                  selected by `media.stt`. Candle uses `<NEOTH_HOME>/models`; \
                  faster-whisper follows the effective Hugging Face cache root. \
                  Cloud configurations are not misreported as missing local models.",
        common_failures: "Fresh install, a policy-blocked or interrupted model \
                         download, or a model-size/backend change whose exact \
                         cache has not been populated yet.",
        fix: "Run `neoth models pull clip`. For a configured local STT backend, \
              also run `neoth models pull whisper`.",
    },
    CheckDoc {
        name: "TTS runtime",
        purpose: "Validates the exact `media.tts.primary` production path. Piper requires the native executable plus an operator-provided ONNX/config pair contained under `~/.neoth/models/piper`; Edge and REST providers require explicit cloud consent; credential values are never printed.",
        common_failures: "Piper executable or voice files missing, model path escaping the Piper root, Edge selected without cloud consent, or a cloud provider selected without its dedicated credential/region.",
        fix: "Run `neoth tts status` and `neoth models list`. For Piper, install the `piper` executable and place the ONNX plus matching `.onnx.json` beneath `~/.neoth/models/piper`; NEOTH intentionally does not download an unpinned voice.",
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
        purpose: "GOLD-ADAPT-GRAPH-04 advisory runtime gate for the `graphify` \
                  bundled skill. It first verifies the same descendant- \
                  containment prerequisite as real Graphify execution, then \
                  discovers NEOTH's canonical Python executable and runs the \
                  bounded isolated `-I -m graphify --version` verification. \
                  PASS means the `graphify` skill and `neoth graph` command \
                  are executable through NEOTH's runtime contract. WARN means \
                  either the containment platform is unavailable or the \
                  supported runtime/module verification failed. The gate is \
                  ADVISORY: skill routing is never suppressed.",
        common_failures: "An unsupported platform where NEOTH deliberately \
                         fails closed rather than allowing descendants to \
                         escape containment; fresh supported-platform Python \
                         without graphifyy; Python missing from PATH; or the \
                         `graphify` module not exposed under isolated `-I` \
                         execution. An installed graphifyy package alone is \
                         not proof that NEOTH can run Graphify.",
        fix: "If the detail says containment is unavailable, use a platform \
              with a supported NEOTH Graphify runtime; installing Python or \
              graphifyy cannot repair that condition. Otherwise, on the \
              supported platform run `pip install graphifyy` in the Python \
              environment NEOTH resolves and rerun `neoth doctor`. If Python \
              is absent from PATH, install Python 3.10+ first.",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphify_unavailable_containment_never_suggests_package_install() {
        let outcome = graphify_readiness_outcome(GraphifyDoctorReadiness::Unavailable(
            "required containment unavailable".to_owned(),
        ));

        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("runtime unavailable"));
        assert!(outcome.detail.contains("Package installation is not a fix"));
        assert!(!outcome.detail.contains("pip install"));
    }

    #[test]
    fn graphify_supported_runtime_contract_reports_pass_only_after_verification() {
        let outcome = graphify_readiness_outcome(GraphifyDoctorReadiness::Ready);

        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("containment"));
        assert!(outcome.detail.contains("canonical interpreter"));
        assert!(outcome.detail.contains("isolated module contract"));
    }

    #[test]
    fn graphify_supported_runtime_failure_has_a_bounded_repair_hint() {
        let outcome = graphify_readiness_outcome(GraphifyDoctorReadiness::NotReady(
            "isolated module verification failed".to_owned(),
        ));

        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(
            outcome
                .detail
                .contains(crate::config::installer::GRAPHIFY_INSTALL_CMD)
        );
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn graphify_check_is_unavailable_on_non_linux_unix_before_any_python_probe() {
        let home = tempfile::tempdir().unwrap();
        let outcome = check_graphify_python(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(
            outcome
                .detail
                .contains("Graphify runner is unavailable on this Unix platform")
        );
        assert!(outcome.detail.contains("Package installation is not a fix"));
        assert!(!outcome.detail.contains("pip install"));
    }

    fn materialize_clip_cache(home: &Path) -> std::path::PathBuf {
        crate::providers::clip_engine::materialize_structural_test_cache(&home.join("models"))
            .unwrap()
    }

    #[test]
    fn model_cache_check_uses_exact_home_and_configured_whisper_size() {
        let home = tempfile::tempdir().unwrap();
        materialize_clip_cache(home.path());
        crate::providers::whisper::materialize_structural_test_cache(
            &home.path().join("models"),
            "openai/whisper-base",
        )
        .unwrap();

        let outcome = check_model_caches(home.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("openai/whisper-base"));
        assert!(outcome.detail.contains(&home.path().display().to_string()));
    }

    #[test]
    fn cloud_stt_does_not_report_a_missing_local_whisper_model() {
        let home = tempfile::tempdir().unwrap();
        materialize_clip_cache(home.path());
        let mut config = crate::config::FreedomConfig::default();
        config.media.stt.primary = crate::media::stt_dispatch::SttProvider::OpenAiWhisperApi;
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();

        let outcome = check_model_caches(home.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no managed local Whisper cache"));
        assert!(outcome.detail.contains("openai_whisper_api"));
    }

    #[test]
    fn model_cache_check_surfaces_structurally_corrupt_whisper_cache() {
        let home = tempfile::tempdir().unwrap();
        materialize_clip_cache(home.path());
        let whisper = crate::providers::whisper::materialize_structural_test_cache(
            &home.path().join("models"),
            "openai/whisper-base",
        )
        .unwrap();
        std::fs::write(whisper.join(crate::providers::whisper::CONFIG_FILE), b"bad").unwrap();

        let outcome = check_model_caches(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("corrupt"));
        assert!(outcome.detail.contains("config.json"));
    }

    #[test]
    fn model_cache_check_surfaces_structurally_corrupt_clip_cache() {
        let home = tempfile::tempdir().unwrap();
        let clip = materialize_clip_cache(home.path());
        crate::providers::whisper::materialize_structural_test_cache(
            &home.path().join("models"),
            "openai/whisper-base",
        )
        .unwrap();
        std::fs::write(
            clip.join(crate::providers::clip_engine::CONFIG_FILE),
            b"bad",
        )
        .unwrap();

        let outcome = check_model_caches(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("clip cache not ready"));
        assert!(outcome.detail.contains("corrupt"));
        assert!(outcome.detail.contains("config.json"));
    }
}
