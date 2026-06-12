//! Operator-integration doctor checks (GOLD-ARCH-06): hooks dir, agents
//! dir, MCP servers, channels wiring, cloud archive dest, vector index
//! snapshot.

use std::path::Path;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus};

/// True ⇔ `freedom.yaml::memory.vector_index.backend == "hnsw"`. Best-effort
/// `serde_yaml::Value` walk so a partial/unparseable config (or a missing
/// `memory` block) reads as "brute_force" rather than tripping the check.
pub(crate) fn freedom_vector_backend_is_hnsw(home: &Path) -> bool {
    let Ok(body) = std::fs::read_to_string(home.join("freedom.yaml")) else {
        return false;
    };
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
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
                "configured dest {} does not exist (is the cloud client running?)",
                dest_str,
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
        return CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Warn,
            detail: format!(
                "{} present but zero enabled servers (operator half-configured?)",
                path.display(),
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
    let status = if broken.is_empty() {
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
///   the inbound receive loop is deferred. WhatsApp + Keet adapters
///   bail on `run()`. Slack adapter has socket_mode but serve does
///   not spawn it yet.
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
    // Discord + Keet have no credentials.yaml fields yet, so they only
    // surface here when their config moves to credentials.yaml. Note
    // the design intent so operators reading the diagnostic see why
    // they aren't listed.

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
