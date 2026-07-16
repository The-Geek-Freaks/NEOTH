//! Operator-integration doctor checks (GOLD-ARCH-06): hooks dir, agents
//! dir, MCP servers, channels wiring, cloud archive dest, vector index
//! snapshot.

use std::path::Path;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus};

/// True ⇔ `freedom.yaml::memory.vector_index.backend == "hnsw"`. Best-effort
/// `serde_yaml::Value` walk so a partial/unparseable config (or a missing
/// `memory` block) reads as "brute_force" rather than tripping the check.
pub(crate) fn freedom_vector_backend_is_hnsw(home: &Path) -> bool {
    let freedom_path = home.join("freedom.yaml");
    let Ok(snapshot) = crate::config::snapshot_raw_config_pair(&freedom_path) else {
        return false;
    };
    let Some(body) = snapshot.freedom.as_deref() else {
        return false;
    };
    let Ok(val) = serde_yaml::from_slice::<serde_yaml::Value>(body) else {
        return false;
    };
    val.get("memory")
        .and_then(|m| m.get("vector_index"))
        .and_then(|vi| vi.get("backend"))
        .and_then(|b| b.as_str())
        == Some("hnsw")
}

/// GOLD-WIRE-07 advisory: when the operator selected `memory.vector_index.
/// backend: hnsw`, surface a missing OR stale `embeddings.hnsw` snapshot —
/// the two cases where HNSW recall silently falls back to brute-force and
/// silently MISSES embeddings upserted since the last rebuild. PASS for the
/// brute-force default (nothing to check) and for a present + fresh snapshot;
/// WARN (never FAIL — recall still works via fallback) otherwise. Read-only.
pub(crate) fn check_vector_index_snapshot(home: &Path) -> CheckOutcome {
    const NAME: &str = "vector index snapshot";
    if !freedom_vector_backend_is_hnsw(home) {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "backend=brute_force — no HNSW snapshot needed".to_string(),
        };
    }
    let snap = crate::memory::embeddings::hnsw_snapshot_path(home);
    if !snap.exists() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: format!(
                "backend=hnsw but no snapshot at {} — run `neoth memory --rebuild-index` \
                 (recall falls back to brute-force until then)",
                snap.display()
            ),
        };
    }
    // Freshness: snapshot mtime vs the newest idx_embedding.created_at. A
    // best-effort read — if either side is unavailable we report present-OK
    // rather than crying wolf.
    let snap_mtime = std::fs::metadata(&snap)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    // store::open would CREATE the DB + apply schema on a missing file —
    // a doctor check must stay read-only. Open the existing file with
    // SQLITE_OPEN_READ_ONLY (same pattern as the credentials readers) and
    // treat any failure as "unavailable" → present-OK path.
    let db_path = home.join("views.db");
    let newest_embedding = if db_path.exists() {
        use rusqlite::OpenFlags;
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        rusqlite::Connection::open_with_flags(&db_path, flags)
            .ok()
            .and_then(|c| {
                c.query_row("SELECT MAX(created_at) FROM idx_embedding", [], |r| {
                    r.get::<_, Option<i64>>(0)
                })
                .ok()
                .flatten()
            })
    } else {
        None
    };
    match (snap_mtime, newest_embedding) {
        (Some(mtime), Some(latest)) if latest > mtime => CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: format!(
                "HNSW snapshot is STALE — the newest embedding (created_at {latest}) is newer \
                 than the snapshot ({mtime}); HNSW recall is silently missing recent vectors. \
                 Run `neoth memory --rebuild-index`."
            ),
        },
        _ => CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "HNSW snapshot present and fresh".to_string(),
        },
    }
}

/// OMI-MULTIMODAL-01 — verify the full cross-file credential/config contract
/// plus the durable ledger/halt posture without creating or mutating the DB.
pub(crate) fn check_omi_runtime(home: &Path) -> CheckOutcome {
    const NAME: &str = "OMI runtime";
    let config_path = home.join("freedom.yaml");
    let Ok(runtime) = crate::config::load_runtime_config_pair_from_path(&config_path) else {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "config/credential pair unreadable; config check owns the diagnostic".into(),
        };
    };
    let config = runtime.config;
    if !config.omi.enabled {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "disabled (opt-in)".into(),
        };
    }
    if let Err(error) = config.omi.validate_with_credentials(&runtime.credentials) {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail: format!("invalid configuration/credential contract: {error}"),
        };
    }

    let db_path = home.join("views.db");
    if !db_path.exists() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: "configured correctly; views.db not initialized yet (start neoth serve)".into(),
        };
    }
    let connection = match rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => connection,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: format!("cannot open OMI ledger read-only: {error}"),
            };
        }
    };
    let status = match crate::memory::omi::status(&connection) {
        Ok(status) => status,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: format!(
                    "OMI schema/state unavailable: {error:#}; run `neoth migrate` or start the daemon"
                ),
            };
        }
    };
    if status.sanitizer_halted {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail: "SC-18 sanitizer halted ingestion; review and run `neoth omi resume --review-note ...`"
                .into(),
        };
    }
    if let Some(error) = status.last_retention_error.as_deref() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail: format!("retention failed: {error}"),
        };
    }
    let live_daemon_pid = match crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid")) {
        Ok(pid) => pid,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: format!("cannot verify daemon PID state: {error:#}"),
            };
        }
    };
    let runtime_state =
        crate::cli::omi::effective_omi_runtime_state(true, &status, live_daemon_pid);
    if let Some((check_status, detail)) = omi_runtime_diagnostic(&status, &runtime_state) {
        return CheckOutcome {
            name: NAME,
            status: check_status,
            detail,
        };
    }
    if let Some(error) = status.last_error.as_deref() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: format!("last runtime error: {error}"),
        };
    }
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Pass,
        detail: format!(
            "runtime=healthy; mode={:?}; conversations={}; media={}; tombstones={}; pending_audits=0",
            config.omi.mode, status.conversations, status.media, status.tombstones
        ),
    }
}

fn omi_runtime_diagnostic(
    status: &crate::memory::omi::OmiStatus,
    runtime_state: &str,
) -> Option<(CheckStatus, String)> {
    match runtime_state {
        "failed" | "degraded" => Some((
            CheckStatus::Fail,
            format!(
                "runtime={runtime_state}: {}",
                status
                    .runtime_detail
                    .as_deref()
                    .unwrap_or("no detail recorded")
            ),
        )),
        "healthy" if status.pending_audits > 0 => Some((
            CheckStatus::Warn,
            format!(
                "runtime=healthy but {} projection audit intent(s) await crash reconciliation",
                status.pending_audits
            ),
        )),
        "healthy" => None,
        _ => Some((
            CheckStatus::Warn,
            format!(
                "runtime={runtime_state}; start/reload `neoth serve` and verify `neoth omi status`{}",
                status
                    .runtime_detail
                    .as_deref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default()
            ),
        )),
    }
}

pub(crate) fn check_hooks_dir(home: &Path) -> CheckOutcome {
    let dir = home.join("hooks");
    if !dir.is_dir() {
        return CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Pass,
            detail: "absent (no operator-defined hooks loaded)".into(),
        };
    }
    // Walk *.toml files. Parse each individually; one malformed file
    // shouldn't fail the whole check — surface a count of bad rows.
    let mut total = 0usize;
    let mut bad = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            total += 1;
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    if let Err(e) = toml::from_str::<crate::hooks::schema::HookDef>(&body) {
                        bad.push(format!(
                            "{}: {e}",
                            path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                        ));
                    }
                }
                Err(e) => bad.push(format!(
                    "{}: {e}",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                )),
            }
        }
    }
    if bad.is_empty() {
        CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Pass,
            detail: format!("{total} hook file(s) parse cleanly"),
        }
    } else {
        CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Fail,
            detail: format!(
                "{} of {total} hook file(s) fail to parse: {}",
                bad.len(),
                bad.join("; ")
            ),
        }
    }
}

pub(crate) fn check_agents_dir(home: &Path) -> CheckOutcome {
    let dir = home.join("agents");
    if !dir.is_dir() {
        return CheckOutcome {
            name: "agents/",
            status: CheckStatus::Pass,
            detail: "absent (built-in sub-agents only)".into(),
        };
    }
    let mut total = 0usize;
    let mut bad = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            total += 1;
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    if let Err(e) = toml::from_str::<crate::sub_agents::schema::SubAgent>(&body) {
                        bad.push(format!(
                            "{}: {e}",
                            path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                        ));
                    }
                }
                Err(e) => bad.push(format!(
                    "{}: {e}",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                )),
            }
        }
    }
    if bad.is_empty() {
        CheckOutcome {
            name: "agents/",
            status: CheckStatus::Pass,
            detail: format!("{total} sub-agent file(s) parse cleanly"),
        }
    } else {
        CheckOutcome {
            name: "agents/",
            status: CheckStatus::Fail,
            detail: format!(
                "{} of {total} sub-agent file(s) fail to parse: {}",
                bad.len(),
                bad.join("; ")
            ),
        }
    }
}

/// R-8 Cloud archive — when freedom.yaml has a destination, verify the
/// folder actually exists. Most common operator error is a typo'd
/// path, or the cloud client wasn't installed.
pub(crate) fn check_cloud_archive_dest(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let Ok(cfg) = crate::config::FreedomConfig::load_from_path(&freedom_path) else {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable; check_freedom_yaml owns the diagnostic".into(),
        };
    };
    let Some(dest_str) = cfg.cloud_archive_dest.as_deref() else {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Pass,
            detail: "not configured".into(),
        };
    };
    let dest = std::path::Path::new(dest_str);
    if !dest.exists() {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Warn,
            detail: format!(
                "configured dest {dest_str} does not exist (is the cloud client running?)",
            ),
        };
    }
    if !dest.is_dir() {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Fail,
            detail: format!("configured dest {dest_str} is a file, not a directory"),
        };
    }
    CheckOutcome {
        name: "cloud archive",
        status: CheckStatus::Pass,
        detail: format!("destination {dest_str} present"),
    }
}

/// CDX-05 follow-up: surface the MCP servers config + flag stale
/// entries. Pure config-read — no process spawn (would slow down
/// `neoth doctor` from <1s to >5s). Operators run `neoth mcp tools
/// <id>` for a live handshake test.
///
/// Three outcomes:
///   - File missing → Pass with "(not configured)" since MCP is
///     optional. NEOTH still runs.
///   - File present, zero servers → Warn (file exists but nothing to
///     do — operator probably half-configured something).
///   - File present, N enabled → Pass listing ids + whether each pins
///     `allow_tools` (CDX-03 hardening posture).
pub(crate) fn check_mcp_servers(home: &Path) -> CheckOutcome {
    let path = home.join("mcp_servers.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Pass,
            detail: "(not configured — create ~/.neoth/mcp_servers.yaml to enable MCP)".into(),
        };
    }
    let servers = match crate::mcp::McpServers::load_from(&path) {
        Ok(s) => s,
        Err(e) => {
            return CheckOutcome {
                name: "mcp servers",
                status: CheckStatus::Fail,
                detail: format!("{} unreadable: {e}", path.display()),
            };
        }
    };
    let enabled = servers.enabled();
    if enabled.is_empty() {
        let invalid_disabled: Vec<String> = servers
            .servers
            .iter()
            .filter_map(|server| {
                server
                    .validate_launcher()
                    .err()
                    .map(|error| format!("{}: {error}", server.id))
            })
            .collect();
        return CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Warn,
            detail: if invalid_disabled.is_empty() {
                format!(
                    "{} present but zero enabled servers (operator half-configured?)",
                    path.display(),
                )
            } else {
                format!(
                    "{} present but zero enabled servers; invalid disabled launcher(s): {}",
                    path.display(),
                    invalid_disabled.join("; ")
                )
            },
        };
    }
    let invalid_enabled: Vec<String> = enabled
        .iter()
        .filter_map(|server| {
            server
                .validate_launcher()
                .err()
                .map(|error| format!("{}: {error}", server.id))
        })
        .collect();
    if !invalid_enabled.is_empty() {
        return CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Fail,
            detail: format!(
                "enabled MCP launcher(s) fail the supply-chain contract and cannot spawn: {}",
                invalid_enabled.join("; ")
            ),
        };
    }
    // Reviewer-1 P1-A doctor warning (2026-05-20): three buckets now.
    //   `hardened`   — allow_tools pinned (recommended)
    //   `trust_all`  — operator explicitly opted into the legacy
    //                  catalogue-trust path via `trust_all_tools: true`
    //   `broken`     — allow_tools=None AND trust_all_tools=false →
    //                  the gate will DENY every call (secure-default)
    let hardened: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_some())
        .map(|s| s.id.as_str())
        .collect();
    let trust_all: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_none() && s.trust_all_tools)
        .map(|s| s.id.as_str())
        .collect();
    let broken: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_none() && !s.trust_all_tools)
        .map(|s| s.id.as_str())
        .collect();
    // GOLD-ADAPT-SNYK-03 supply-chain surface: npx-launched MCP servers fetch
    // their package at runtime (e.g. the hex-* servers). Flag any whose package
    // name looks like a typosquat of a popular npm package so the operator
    // verifies the source before trusting it.
    let typosquats: Vec<String> = enabled
        .iter()
        .filter_map(|s| {
            let pkg = s.pinned_npx_package()?;
            crate::security::dep_health::typosquat_risk(pkg, "npm").map(|h| h.describe())
        })
        .collect();
    let detail = if !broken.is_empty() {
        format!(
            "{} enabled — hardened: [{}]; trust_all_tools: [{}]; \
             BROKEN (no allow_tools + trust_all_tools=false → all calls denied): [{}]. \
             Pin allow_tools or set trust_all_tools: true on each broken server.",
            enabled.len(),
            hardened.join(", "),
            trust_all.join(", "),
            broken.join(", "),
        )
    } else {
        format!(
            "{} enabled — hardened (allow_tools pinned): [{}]; legacy (trust_all_tools=true): [{}]",
            enabled.len(),
            hardened.join(", "),
            trust_all.join(", "),
        )
    };
    // Posture: Pass when every enabled server is either hardened or
    // explicit-trust. Warn when any server is in the broken state
    // (operator's gate denies every call until they opt-in or pin).
    let detail = if typosquats.is_empty() {
        detail
    } else {
        format!(
            "{detail} ⚠ possible typosquat npx package(s): {}",
            typosquats.join("; "),
        )
    };
    let status = if broken.is_empty() && typosquats.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };
    CheckOutcome {
        name: "mcp servers",
        status,
        detail,
    }
}

/// R2-P0-2 doctor surface — honest per-channel wiring status.
///
/// Closes the "Channels on deck" honesty gap flagged by the R2
/// reviewer (`PLAN/REEVALUATION_GESAMT_2026-05-21_R2.md` §4 P0-2).
/// Pre-fix: README/Status claimed channels were live when
/// `cli::serve` only spawned Telegram. Operators configured Slack /
/// WhatsApp tokens, saw "ok" in their setup, and never realised
/// inbound was deferred.
///
/// Post-fix: each channel gets one of four classifications:
///
/// - **LIVE**: tokens configured + adapter has live inbound + serve
///   spawns it. Telegram today.
/// - **OUTBOUND-ONLY**: tokens configured + adapter can send_text but
///   the inbound receive loop is deferred.
/// - **CONFIGURED-NOT-STARTED**: tokens configured + adapter has full
///   inbound code BUT serve does not bootstrap it. Discord (gateway
///   loop ships) is the current example.
/// - **NOT-CONFIGURED**: no credentials present. Silent.
pub(crate) fn check_channels_wiring(home: &Path) -> CheckOutcome {
    let creds = match crate::config::credentials::Credentials::load_or_default(
        &home.join("credentials.yaml"),
    ) {
        Ok(c) => c,
        Err(_) => {
            return CheckOutcome {
                name: "channels wiring",
                status: CheckStatus::Warn,
                detail: "credentials.yaml unreadable; per-channel status unavailable".to_string(),
            };
        }
    };

    // Tuple shape: (channel name, classification, note). Only configured
    // channels show up — silent on NOT-CONFIGURED to keep doctor output
    // focused on what the operator actually set up.
    let mut rows: Vec<(&'static str, &'static str, &'static str)> = Vec::new();

    if creds.telegram_token.is_some() {
        rows.push((
            "telegram",
            "LIVE",
            "polling loop spawned by serve; send + receive both real",
        ));
    }
    match (
        creds.slack_bot_token.is_some(),
        creds.slack_app_token.is_some(),
    ) {
        (true, true) => rows.push((
            "slack",
            "LIVE",
            "socket-mode WS loop spawned by serve; send + receive both real",
        )),
        (true, false) | (false, true) => rows.push((
            "slack",
            "CONFIGURED-NOT-STARTED",
            "socket mode needs BOTH bot_token (xoxb-) and app_token (xapp-); \
             only one supplied — send_text still works",
        )),
        (false, false) => {}
    }
    if creds.whatsapp_token.is_some() || creds.whatsapp_phone_id.is_some() {
        let inbound_ready = creds.whatsapp_verify_token.is_some()
            && creds.whatsapp_app_secret.is_some()
            && creds.whatsapp_phone_id.is_some();
        if inbound_ready {
            rows.push((
                "whatsapp",
                "LIVE",
                "Meta webhook listener spawned by serve; send + receive both real",
            ));
        } else {
            rows.push((
                "whatsapp",
                "OUTBOUND-ONLY",
                "send_text via Graph API works; inbound needs whatsapp_verify_token + \
                 whatsapp_app_secret + whatsapp_phone_id in credentials.yaml",
            ));
        }
    }
    let keet = crate::channels::probe::ChannelCredsView::from_config(None, &creds);
    let keet_any = keet.keet_bridge_url
        || keet.keet_topic
        || keet.keet_allowed_senders
        || keet.keet_bearer
        || keet.keet_seed;
    if keet.keet_bridge_url && keet.keet_topic && keet.keet_allowed_senders && keet.keet_bearer {
        rows.push((
            "keet",
            "CONFIGURED-NEEDS-LIVE-PROBE",
            "run `neoth channel test keet`; only authenticated full-duplex companion v1 is accepted",
        ));
    } else if keet_any {
        rows.push((
            "keet",
            "CONFIGURED-NOT-STARTED",
            "needs keet_bridge_url + keet_bridge_bearer_token + keet_topic + keet_allowed_senders; legacy seed is ignored",
        ));
    }

    if rows.is_empty() {
        return CheckOutcome {
            name: "channels wiring",
            status: CheckStatus::Pass,
            detail: "no channel credentials configured — daemon runs in CLI-only mode".to_string(),
        };
    }

    // Aggregate status: LIVE counts as Pass; anything less downgrades
    // the whole check to Warn so operators who configured Slack/
    // WhatsApp expecting live inbound see a yellow flag.
    let any_partial = rows.iter().any(|(_, cls, _)| *cls != "LIVE");
    let status = if any_partial {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };

    let detail = rows
        .iter()
        .map(|(ch, cls, note)| format!("{ch}: {cls} — {note}"))
        .collect::<Vec<_>>()
        .join("; ");

    CheckOutcome {
        name: "channels wiring",
        status,
        detail,
    }
}

/// Registration: this domain's diagnostics, run in order by
/// `run_all_checks`. Adding a check = add the fn + a `CheckDoc` here.
pub(crate) const CHECKS: &[CheckFn] = &[
    check_hooks_dir,
    check_agents_dir,
    check_cloud_archive_dest,
    check_mcp_servers,
    check_channels_wiring,
    check_vector_index_snapshot,
    check_omi_runtime,
];

/// Operator runbook entries for this domain (the `--explain` surface).
pub(crate) const DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "hooks/",
        purpose: "Operator hooks at `~/.neoth/hooks/*.toml`. Each file \
                  defines an event stage + a command. Doctor loads every \
                  file via `hooks::load_all` so YAML/TOML syntax errors + \
                  unknown stages surface BEFORE the daemon hits the event.",
        common_failures: "Typo in stage name (unknown HookStage); shell \
                         command not in PATH; regex syntax error in the \
                         matcher field.",
        fix: "Run `neoth hooks list` for parse errors. `neoth hooks \
              validate` runs the schema + regex check standalone. Fix \
              the file or remove it.",
    },
    CheckDoc {
        name: "OMI runtime",
        purpose: "Validates the enabled OMI mode, its dedicated credentials, bounded endpoint/listener policy, and the durable conversation/retention state.",
        common_failures: "Missing omi_dev_* key or native bearer token; unsafe endpoint/bind; inactive/degraded supervisor; pending crash-reconciliation intents; SC-18 halt; retention error; database not migrated.",
        fix: "Run `neoth omi status` for exact persisted and effective runtime state. Correct freedom.yaml/credentials.yaml, start or reload `neoth serve`, or review a sanitizer halt and use `neoth omi resume --review-note ...`.",
    },
    CheckDoc {
        name: "agents/",
        purpose: "Sub-agents at `~/.neoth/agents/*.md`. Each markdown file \
                  defines an operator-callable agent's system prompt + \
                  trigger keywords. Doctor loads every agent via \
                  `sub_agents::load_all`.",
        common_failures: "Empty system prompt; malformed YAML frontmatter; \
                         unknown tool_allowlist entries.",
        fix: "Edit the offending .md to fix the frontmatter. `neoth agents \
              list` shows parse errors with line numbers.",
    },
    CheckDoc {
        name: "cloud archive",
        purpose: "Cloud archive mirror target at \
                  `freedom.yaml::cloud_archive_dest` (typically a folder \
                  the operator's Dropbox / GDrive / OneDrive desktop \
                  client syncs upstream). Doctor checks the path exists + \
                  is writeable + is a directory (not a file).",
        common_failures: "Path is a file (operator typo); doesn't exist; \
                         not writeable.",
        fix: "Edit `freedom.yaml::cloud_archive_dest` to a real existing \
              directory. Remove the field to disable cloud archive \
              entirely.",
    },
    CheckDoc {
        name: "mcp servers",
        purpose: "Model Context Protocol server registry at \
                  `~/.neoth/mcp_servers.yaml`. Doctor loads via \
                  `McpServers::load`, flags parse errors, warns when \
                  enabled servers reference a command that's not in PATH.",
        common_failures: "Missing file (fine — MCP autoroute defaults off); \
                         malformed YAML; binary not installed.",
        fix: "Missing → no action. Parse error → diff against \
              `mcp_servers.yaml.example`. Binary missing → install the \
              server (e.g. `npm i -g @modelcontextprotocol/server-filesystem`).",
    },
    CheckDoc {
        name: "channels wiring",
        purpose: "R2-P0-2 honesty surface. Loads `credentials.yaml` + \
                  classifies every configured channel as one of: LIVE \
                  (send + receive both real), OUTBOUND-ONLY (send works, \
                  inbound receive loop not yet wired), CONFIGURED-NOT-\
                  STARTED (full inbound code ships but serve does not \
                  bootstrap it), or absent (silent). Closes the \
                  documented gap where README/Status claimed channels \
                  were live while `cli::serve` only spawned Telegram.",
        common_failures: "Operator configures Slack/WhatsApp credentials \
                         + expects bidirectional chat. Aggregate Warn \
                         when any partial (OUTBOUND-ONLY / CONFIGURED-NOT-\
                         STARTED) channel is in the set so the gap \
                         surfaces during install verification.",
        fix: "Telegram inbound + outbound: live today. Slack inbound: \
              live when BOTH bot_token + app_token configured (socket \
              mode auto-spawns). WhatsApp inbound: live when full Meta \
              secret set (token + phone_id + verify_token + app_secret) \
              configured (webhook listener auto-spawns on 127.0.0.1). \
              Partial configs surface as CONFIGURED-NOT-STARTED with a \
              precise per-missing-field hint.",
    },
    CheckDoc {
        name: "vector index snapshot",
        purpose: "GOLD-WIRE-07 advisory. When `memory.vector_index.backend: \
                  hnsw` is set, `neoth recall --similar-to*` cold-loads the \
                  `<neoth_home>/embeddings.hnsw` snapshot. This check flags the \
                  two states where HNSW recall silently degrades: the snapshot \
                  is ABSENT (recall falls back to brute-force entirely) or STALE \
                  (the newest `idx_embedding.created_at` is newer than the \
                  snapshot's mtime, so HNSW recall silently misses every vector \
                  upserted since the last rebuild). Read-only. Pass for the \
                  brute-force default + for a present, fresh snapshot; Warn \
                  otherwise; never Fail (recall always works via fallback).",
        common_failures: "Operator set `backend: hnsw` but never ran \
                         `neoth memory --rebuild-index` (absent snapshot); or \
                         built it once, then ingested more images so the \
                         snapshot lags the DB (stale).",
        fix: "Run `neoth memory --rebuild-index` to (re)build the snapshot \
              from `idx_embedding`. Re-run after any large ingest. Or set \
              `memory.vector_index.backend: brute_force` to stay on the \
              always-fresh O(N) scan. (Automatic snapshot freshness via a \
              daemon warm index is GOLD-WIRE-07b.)",
    },
];

#[cfg(test)]
mod omi_tests {
    use super::*;

    #[test]
    fn pending_audits_warn_even_when_runtime_is_healthy() {
        let status = crate::memory::omi::OmiStatus {
            pending_audits: 2,
            ..Default::default()
        };
        let (check, detail) = omi_runtime_diagnostic(&status, "healthy").unwrap();
        assert_eq!(check, CheckStatus::Warn);
        assert!(detail.contains("2 projection audit intent"));
    }

    #[test]
    fn inactive_or_stale_runtime_warns_and_failed_runtime_fails() {
        let status = crate::memory::omi::OmiStatus::default();
        assert_eq!(
            omi_runtime_diagnostic(&status, "inactive").unwrap().0,
            CheckStatus::Warn
        );
        assert_eq!(
            omi_runtime_diagnostic(&status, "unknown").unwrap().0,
            CheckStatus::Warn
        );
        assert_eq!(
            omi_runtime_diagnostic(&status, "failed").unwrap().0,
            CheckStatus::Fail
        );
        assert!(omi_runtime_diagnostic(&status, "healthy").is_none());
    }
}
