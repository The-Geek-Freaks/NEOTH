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

/// CRG-01 lifecycle diagnostic. This deliberately reads `freedom.yaml` and an
/// existing code-map store without using a config migration or `persist::open`:
/// Doctor must describe a missing or corrupt store, never create or repair it.
pub(crate) fn check_code_map_lifecycle(home: &Path) -> CheckOutcome {
    const NAME: &str = "code-map lifecycle";
    let config_path = home.join("freedom.yaml");
    let config = match std::fs::read(&config_path) {
        Ok(bytes) => match serde_yaml::from_slice::<crate::config::FreedomConfig>(&bytes) {
            Ok(config) if config.code_map.validate().is_ok() => config,
            _ => {
                return CheckOutcome {
                    name: NAME,
                    status: CheckStatus::Pass,
                    detail: "freedom.yaml is unavailable or invalid; the config check owns that diagnostic".into(),
                };
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::config::FreedomConfig::default()
        }
        Err(_) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Pass,
                detail:
                    "freedom.yaml is unavailable or invalid; the config check owns that diagnostic"
                        .into(),
            };
        }
    };
    let lifecycle = &config.code_map.lifecycle;
    if !lifecycle.enabled {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "disabled by freedom.yaml — no managed repository watchers are expected".into(),
        };
    }
    if lifecycle.managed_roots.is_empty() {
        // Accepted configuration forbids this, but retain a precise defensive
        // result for programmatic or future configuration construction.
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail: "enabled with no managed roots — set code_map.lifecycle.managed_roots before starting neoth serve".into(),
        };
    }

    let database_path = home.join("code_map.db");
    let mut aggregate = CheckStatus::Pass;
    let mut details = Vec::with_capacity(lifecycle.managed_roots.len());
    for root in &lifecycle.managed_roots {
        let status = crate::code_map::lifecycle::inspect(&database_path, root);
        // Prefer the lifecycle service's canonical physical display when it
        // could establish one. An unmapped/nonexistent configured path falls
        // back to the exact configured string so its repair instruction still
        // tells the operator what needs correction.
        let inspected_root = status.root.as_deref().map(Path::new).unwrap_or(root);
        let (severity, mut detail) = code_map_lifecycle_detail(inspected_root, &status.state);
        let automatic =
            crate::code_map::inspect_automatic_context_readiness(&config, &database_path, root);
        let automatic_detail = if matches!(
            &automatic,
            crate::code_map::AutomaticContextReadiness::Disabled
        ) {
            "automatic Chat/Channel context disabled".to_owned()
        } else if let crate::code_map::AutomaticContextReadiness::Eligible { max_files, .. } =
            &automatic
        {
            format!("automatic Chat/Channel context eligible (max_files={max_files})")
        } else if let crate::code_map::AutomaticContextReadiness::Unavailable { reason } =
            &automatic
        {
            format!(
                "automatic Chat/Channel context unavailable ({})",
                reason.code()
            )
        } else {
            unreachable!("automatic context readiness has three states")
        };
        detail.push_str("; ");
        detail.push_str(&automatic_detail);
        aggregate = more_severe(aggregate, severity);
        details.push(detail);
    }
    CheckOutcome {
        name: NAME,
        status: aggregate,
        detail: details.join("; "),
    }
}

/// CRG-03/04 evidence diagnostic. This is intentionally separate from the
/// lifecycle check: lifecycle owns store existence, physical-root identity,
/// freshness, and repair advice; this check only describes bounded persisted
/// `TestedBy` graph evidence once that lifecycle state is already fresh.
pub(crate) fn check_code_map_analysis_readiness(home: &Path) -> CheckOutcome {
    const NAME: &str = "code-map analysis readiness";
    let config_path = home.join("freedom.yaml");
    let config = match std::fs::read(&config_path) {
        Ok(bytes) => match serde_yaml::from_slice::<crate::config::FreedomConfig>(&bytes) {
            Ok(config) if config.code_map.validate().is_ok() => config,
            _ => {
                return CheckOutcome {
                    name: NAME,
                    status: CheckStatus::Pass,
                    detail: "freedom.yaml is unavailable or invalid; the config check owns that diagnostic".into(),
                };
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::config::FreedomConfig::default()
        }
        Err(_) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Pass,
                detail:
                    "freedom.yaml is unavailable or invalid; the config check owns that diagnostic"
                        .into(),
            };
        }
    };
    let lifecycle = &config.code_map.lifecycle;
    if !lifecycle.enabled {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "disabled by freedom.yaml — no managed analysis snapshot is expected".into(),
        };
    }
    if lifecycle.managed_roots.is_empty() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Fail,
            detail: "enabled with no managed roots — the code-map lifecycle check owns this configuration state".into(),
        };
    }

    let database_path = home.join("code_map.db");
    let mut aggregate = CheckStatus::Pass;
    let mut details = Vec::with_capacity(lifecycle.managed_roots.len());
    for configured_root in &lifecycle.managed_roots {
        let lifecycle_status = crate::code_map::lifecycle::inspect(&database_path, configured_root);
        let Some(physical_root) = lifecycle_status.root.as_deref() else {
            details.push(format!(
                "{}: analysis evidence not assessed; code-map lifecycle owns {} state",
                configured_root.display(),
                code_map_lifecycle_state_label(&lifecycle_status.state),
            ));
            continue;
        };
        let crate::code_map::lifecycle::CodeMapLifecycleState::Fresh { snapshot } =
            &lifecycle_status.state
        else {
            details.push(format!(
                "{}: analysis evidence not assessed; code-map lifecycle owns {} state",
                physical_root,
                code_map_lifecycle_state_label(&lifecycle_status.state),
            ));
            continue;
        };
        let detail = match crate::code_map::persist::open_read_only(&database_path).and_then(
            |connection| {
                crate::code_map::persist::root_test_evidence_summary(&connection, physical_root)
            },
        ) {
            Ok(summary) => code_map_analysis_detail(physical_root, snapshot, &summary),
            Err(error) => (
                CheckStatus::Warn,
                format!(
                    "{physical_root}: read-only test-evidence query was not assessed ({error:#}); no database migration, refresh, or repair was attempted"
                ),
            ),
        };
        aggregate = more_severe(aggregate, detail.0);
        details.push(detail.1);
    }
    CheckOutcome {
        name: NAME,
        status: aggregate,
        detail: details.join("; "),
    }
}

/// CRG-05 operator diagnostic for the opt-in W53 sidecar. This deliberately
/// shares only the exact generated descriptor classification with the producer:
/// Doctor never prepares a sidecar, starts a child, or treats readiness as a
/// request that was enriched.
pub(crate) fn check_codegraph_outline_enrichment(home: &Path) -> CheckOutcome {
    const NAME: &str = "codegraph outline enrichment";
    let config_path = home.join("freedom.yaml");
    let config = match std::fs::read(&config_path) {
        Ok(bytes) => match serde_yaml::from_slice::<crate::config::FreedomConfig>(&bytes) {
            Ok(config) if config.code_map.validate().is_ok() => config,
            _ => return CheckOutcome {
                name: NAME,
                status: CheckStatus::Warn,
                detail: "outline enrichment configuration is unavailable or invalid; Doctor did not inspect MCP registration or SQLite".into(),
            },
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => crate::config::FreedomConfig::default(),
        Err(_) => return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: "outline enrichment configuration is unavailable or invalid; Doctor did not inspect MCP registration or SQLite".into(),
        },
    };
    if !config.code_map.outline_enrichment {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "disabled by freedom.yaml — no outline enrichment readiness is expected and no SQLite database was opened".into(),
        };
    }
    let registry_path = home.join("mcp_servers.yaml");
    let servers = match crate::mcp::McpServers::load_from(&registry_path) {
        Ok(servers) => servers,
        Err(_) => return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: "enabled, but mcp_servers.yaml is unavailable or invalid; no child, provider, or SQLite inspection was attempted".into(),
        },
    };
    let database_path = match crate::mcp::codegraph_server::inspect_builtin_outline_registration(
        servers.get_enabled("neoth-codegraph"),
    ) {
        crate::mcp::codegraph_server::BuiltinOutlineRegistrationReadiness::Exact { database_path } => database_path,
        crate::mcp::codegraph_server::BuiltinOutlineRegistrationReadiness::DatabaseUnavailable => return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: "enabled, but the exact generated codegraph registration names an absent or inaccessible database; Doctor did not create, migrate, or repair it".into(),
        },
        crate::mcp::codegraph_server::BuiltinOutlineRegistrationReadiness::NotExactGenerated => return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: "enabled, but no exact generated neoth-codegraph registration is eligible; custom or lookalike registrations are not used for outline enrichment".into(),
        },
    };
    let lifecycle = &config.code_map.lifecycle;
    if !lifecycle.enabled || lifecycle.managed_roots.is_empty() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: "enabled with no managed code-map roots; Doctor cannot establish a fresh complete outline snapshot".into(),
        };
    }

    let mut ready = Vec::new();
    let mut unavailable = Vec::new();
    // `CodeMapLifecycleConfig` validates this operator-controlled list to at
    // most eight roots. `inspect` is read-only and preserves its normal
    // physical-root identity, completeness, freshness, and corruption rules.
    for root in &lifecycle.managed_roots {
        let observed = crate::code_map::lifecycle::inspect(&database_path, root);
        match (&observed.root, &observed.state) {
            (
                Some(physical_root),
                crate::code_map::lifecycle::CodeMapLifecycleState::Fresh { snapshot },
            ) if snapshot.index_generation > 0
                && snapshot.index_generation == snapshot.graph_generation =>
            {
                ready.push(format!(
                    "{} (index_generation={}, graph_generation={})",
                    physical_root, snapshot.index_generation, snapshot.graph_generation
                ));
            }
            (Some(physical_root), state) => unavailable.push(format!(
                "{}: {}",
                physical_root,
                code_map_lifecycle_state_label(state)
            )),
            (None, state) => unavailable.push(format!(
                "{}: {}",
                root.display(),
                code_map_lifecycle_state_label(state)
            )),
        }
    }
    if ready.is_empty() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: format!(
                "enabled exact generated registration found, but no fresh complete managed map is ready ({}) ; Doctor did not rebuild, refresh, or enrich a request",
                unavailable.join(", ")
            ),
        };
    }
    let suffix = if !unavailable.is_empty() {
        format!(
            "; other managed roots unavailable: {}",
            unavailable.join(", ")
        )
    } else {
        String::new()
    };
    let selection = if config.code_map.enrichment_selectors.is_empty() {
        "the existing built-in neoth-codegraph/codegraph_outline route".to_owned()
    } else {
        format!(
            "the built-in route and {} exact configured ReadPath selector(s)",
            config.code_map.enrichment_selectors.len(),
        )
    };
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Pass,
        detail: format!(
            "ready for a next eligible attempt through {} across {} fresh complete managed root(s): {}{}; Doctor did not enrich a request",
            selection,
            ready.len(),
            ready.join(", "),
            suffix
        ),
    }
}

fn code_map_analysis_detail(
    root: &str,
    lifecycle: &crate::code_map::lifecycle::LifecycleGeneration,
    summary: &crate::code_map::persist::RootTestEvidenceSummary,
) -> (CheckStatus, String) {
    if summary.schema_version != crate::code_map::persist::CODE_MAP_SCHEMA_VERSION {
        return (
            CheckStatus::Warn,
            format!(
                "{root}: schema version {} is not current {}; exact test evidence was not assessed",
                summary.schema_version,
                crate::code_map::persist::CODE_MAP_SCHEMA_VERSION,
            ),
        );
    }
    if !summary.snapshot_complete
        || summary.index_generation != lifecycle.index_generation
        || summary.graph_generation != lifecycle.graph_generation
        || summary.index_generation != summary.graph_generation
    {
        return (
            CheckStatus::Warn,
            format!(
                "{root}: persisted analysis generations changed or are incomplete after lifecycle inspection; exact test evidence was not assessed"
            ),
        );
    }
    if summary.capped {
        return (
            CheckStatus::Warn,
            format!(
                "{root}: bounded read observed the first {} persisted `tested_by` rows and hit its cap; exact test evidence was not assessed as a total",
                summary.observed_tested_by_edges,
            ),
        );
    }
    if summary.observed_exact_tested_by_edges == 0 {
        return (
            CheckStatus::Warn,
            format!(
                "{root}: no observed exact `TestedBy` evidence in {} persisted `tested_by` rows; this does not prove the repository has no tests or coverage",
                summary.observed_tested_by_edges,
            ),
        );
    }
    (
        CheckStatus::Pass,
        format!(
            "{root}: observed {} exact `TestedBy` edges among {} persisted `tested_by` rows (structural graph evidence only; not executed test coverage)",
            summary.observed_exact_tested_by_edges, summary.observed_tested_by_edges,
        ),
    )
}

fn code_map_lifecycle_state_label(
    state: &crate::code_map::lifecycle::CodeMapLifecycleState,
) -> &'static str {
    match state {
        crate::code_map::lifecycle::CodeMapLifecycleState::Disabled => "disabled",
        crate::code_map::lifecycle::CodeMapLifecycleState::Absent => "absent",
        crate::code_map::lifecycle::CodeMapLifecycleState::Unmapped => "unmapped",
        crate::code_map::lifecycle::CodeMapLifecycleState::Incomplete { .. } => "incomplete",
        crate::code_map::lifecycle::CodeMapLifecycleState::Fresh { .. } => "fresh",
        crate::code_map::lifecycle::CodeMapLifecycleState::Stale { .. } => "stale",
        crate::code_map::lifecycle::CodeMapLifecycleState::Refreshing { .. } => "refreshing",
        crate::code_map::lifecycle::CodeMapLifecycleState::Recovering { .. } => "recovering",
        crate::code_map::lifecycle::CodeMapLifecycleState::Corrupt { .. } => "corrupt",
    }
}

fn more_severe(current: CheckStatus, candidate: CheckStatus) -> CheckStatus {
    match (current, candidate) {
        (CheckStatus::Fail, _) | (_, CheckStatus::Fail) => CheckStatus::Fail,
        (CheckStatus::Warn, _) | (_, CheckStatus::Warn) => CheckStatus::Warn,
        _ => CheckStatus::Pass,
    }
}

fn code_map_lifecycle_detail(
    root: &Path,
    state: &crate::code_map::lifecycle::CodeMapLifecycleState,
) -> (CheckStatus, String) {
    let command_root = quote_code_map_command_path(root);
    let refresh = format!("neoth code-map refresh {command_root}");
    match state {
        crate::code_map::lifecycle::CodeMapLifecycleState::Disabled => {
            (CheckStatus::Pass, format!("{}: disabled", root.display()))
        }
        crate::code_map::lifecycle::CodeMapLifecycleState::Fresh { snapshot } => (
            CheckStatus::Pass,
            format!(
                "{}: fresh (index={} graph={})",
                root.display(),
                snapshot.index_generation,
                snapshot.graph_generation
            ),
        ),
        crate::code_map::lifecycle::CodeMapLifecycleState::Absent => (
            CheckStatus::Warn,
            format!("{}: no index exists — run `{refresh}`", root.display()),
        ),
        crate::code_map::lifecycle::CodeMapLifecycleState::Unmapped => (
            CheckStatus::Warn,
            format!(
                "{}: root is not mapped to a verified snapshot — run `{refresh}`",
                root.display()
            ),
        ),
        crate::code_map::lifecycle::CodeMapLifecycleState::Incomplete { snapshot } => (
            CheckStatus::Warn,
            format!(
                "{}: incomplete index={} graph={} — run `{refresh}`",
                root.display(),
                snapshot.index_generation,
                snapshot.graph_generation
            ),
        ),
        crate::code_map::lifecycle::CodeMapLifecycleState::Stale { snapshot } => (
            CheckStatus::Warn,
            format!(
                "{}: stale index={} graph={} — run `{refresh}`",
                root.display(),
                snapshot.index_generation,
                snapshot.graph_generation
            ),
        ),
        crate::code_map::lifecycle::CodeMapLifecycleState::Refreshing { attempt_id, .. } => (
            CheckStatus::Warn,
            format!(
                "{}: refresh attempt {attempt_id} is active — re-run `neoth code-map status {}` after it completes",
                root.display(),
                command_root
            ),
        ),
        crate::code_map::lifecycle::CodeMapLifecycleState::Recovering { attempt_id, .. } => (
            CheckStatus::Warn,
            format!(
                "{}: interrupted refresh attempt {attempt_id} needs recovery — run `{refresh}`",
                root.display()
            ),
        ),
        crate::code_map::lifecycle::CodeMapLifecycleState::Corrupt { diagnostic } => (
            CheckStatus::Fail,
            format!(
                "{}: code-map database is corrupt ({diagnostic}) — preserve and rebuild with `neoth code-map refresh {} --repair-corrupt`",
                root.display(),
                command_root
            ),
        ),
    }
}

/// Render an operator-selected filesystem path as one PowerShell-safe command
/// argument. Bare paths remain readable; whitespace and shell-significant
/// characters use a single-quoted literal, with embedded apostrophes doubled.
fn quote_code_map_command_path(path: &Path) -> String {
    let raw = path.display().to_string();
    if !raw.is_empty()
        && raw.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '_' | '-' | '/' | '\\' | ':')
        })
    {
        raw
    } else {
        format!("'{}'", raw.replace('\'', "''"))
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
    check_code_map_lifecycle,
    check_code_map_analysis_readiness,
    check_codegraph_outline_enrichment,
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
    CheckDoc {
        name: "code-map lifecycle",
        purpose: "Read-only status for every explicitly managed repository in \
                  `freedom.yaml::code_map.lifecycle.managed_roots`. Doctor \
                  verifies the selected physical root against the existing \
                  `code_map.db` and reports absent, unmapped, incomplete, stale, \
                  recovering, and corrupt snapshots without creating, migrating, \
                  refreshing, or repairing that database.",
        common_failures: "The lifecycle is enabled before a first index exists; \
                  repository files changed since the published generation; a root \
                  was replaced or no longer resolves to its persisted physical \
                  identity; an earlier refresh was interrupted; or SQLite cannot \
                  read the database.",
        fix: "First index or stale/incomplete root: run `neoth code-map refresh \
                  <absolute-root>`. Inspect any root without mutation using \
                  `neoth code-map status <absolute-root>`. A corrupt database is \
                  never replaced automatically: run `neoth code-map refresh \
                  <absolute-root> --repair-corrupt` to preserve its forensic copy \
                  and create a replacement. Ensure lifecycle roots are explicit, \
                  absolute, non-overlapping paths in freedom.yaml.",
    },
    CheckDoc {
        name: "code-map analysis readiness",
        purpose: "Read-only companion to `code-map lifecycle`. After lifecycle \
                  establishes a fresh complete physical-root snapshot, Doctor \
                  observes a bounded prefix of persisted `tested_by` graph rows \
                  and reports exact resolved-target evidence. It never calculates \
                  a diff impact, test gap, coverage percentage, or executed-test \
                  result; an empty observation is explicitly not proof of no tests.",
        common_failures: "Lifecycle is absent/stale/incomplete/recovering/corrupt \
                  (that diagnostic remains owned by `code-map lifecycle`); an \
                  older/unreadable schema cannot expose exact target identity; or \
                  the bounded evidence query reaches its row or SQLite work cap.",
        fix: "Resolve the lifecycle diagnostic first and then refresh the \
                  repository through the normal `neoth code-map refresh \
                  <absolute-root>` path. Doctor does not migrate, refresh, \
                  rebuild, repair, or infer test absence. If a large store reaches \
                  the read-only cap, use a scoped CRG consumer rather than \
                  treating this health summary as a repository-wide census.",
    },
    CheckDoc {
        name: "codegraph outline enrichment",
        purpose: "Read-only readiness for the opt-in local `ReadPath` \
                  sidecar. With only the master switch, Doctor assesses the existing built-in route; no selector is \
                  required. Exact selectors add configured-provider routes. Doctor accepts only the exact generated \
                  `neoth-codegraph` registration, then inspects at most the eight \
                  configured managed roots using the existing lifecycle rules. A pass \
                  means a future eligible call can attempt enrichment; it \
                  does not claim any request was enriched.",
        common_failures: "The feature is disabled by default; freedom.yaml or \
                  mcp_servers.yaml is malformed; a custom/lookalike registration \
                  replaced the generated descriptor; the selected database is absent \
                  or corrupt; or every managed root is absent, incomplete, stale, or \
                  otherwise not fresh.",
        fix: "Enable `code_map.outline_enrichment` and keep the generated registration intact for the built-in route. \
              Add an exact `ReadPath` selector only when a configured provider should receive a sidecar, then use the normal \
              `neoth code-map refresh <absolute-root>` lifecycle path until at least \
              one managed physical root is fresh and complete. Doctor never starts \
              codegraph-serve, calls tools/list, migrates, rebuilds, repairs, or \
              changes configuration.",
    },
];

#[cfg(test)]
mod omi_tests {
    use super::*;

    fn write_enabled_code_map_lifecycle(home: &Path, root: &Path) {
        let mut config = crate::config::FreedomConfig::default();
        config.code_map.lifecycle.enabled = true;
        config.code_map.lifecycle.managed_roots = vec![root.to_path_buf()];
        std::fs::write(
            home.join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize lifecycle fixture config"),
        )
        .expect("write lifecycle fixture config");
    }

    fn persist_fresh_analysis_fixture(
        home: &Path,
        repository: &Path,
        edges: &[crate::code_map::graph::CodeEdge],
    ) {
        write_enabled_code_map_lifecycle(home, repository);
        let root = crate::code_map::CanonicalRepoRoot::discover(repository)
            .expect("canonical fixture repository");
        let map = crate::code_map::RepoMap {
            root: root.display().to_owned(),
            files: Vec::new(),
            report: crate::code_map::ScanReport {
                total_files: 0,
                total_bytes: 0,
                total_loc: 0,
                by_language: Vec::new(),
                oversize_skipped: 0,
                truncated_at: None,
            },
        };
        let mut store = crate::code_map::persist::open(&home.join("code_map.db"))
            .expect("create fixture store outside Doctor");
        crate::code_map::persist::persist_map_and_edges(&mut store, &map, edges)
            .expect("publish fixture map and graph");
    }

    fn write_enabled_outline_enrichment(home: &Path, root: &Path) {
        let mut config = crate::config::FreedomConfig::default();
        config.code_map.outline_enrichment = true;
        config.code_map.lifecycle.enabled = true;
        config.code_map.lifecycle.managed_roots = vec![root.to_path_buf()];
        std::fs::write(
            home.join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize outline fixture config"),
        )
        .expect("write outline fixture config");
    }

    fn write_enabled_configured_read_path_selector(home: &Path, root: &Path) {
        write_enabled_outline_enrichment(home, root);
        let config_path = home.join("freedom.yaml");
        let mut config = serde_yaml::from_slice::<crate::config::FreedomConfig>(
            &std::fs::read(&config_path).expect("read outline fixture config"),
        )
        .expect("deserialize outline fixture config");
        config.code_map.enrichment_selectors = vec![crate::config::ConfiguredMcpPathRead {
            server_id: "w95-doctor-configured-read".into(),
            tool: "read_path".into(),
            kind: crate::config::ConfiguredMcpPathReadKind::ReadPath,
            path_field: "path".into(),
        }];
        std::fs::write(
            config_path,
            serde_yaml::to_string(&config).expect("serialize configured selector fixture config"),
        )
        .expect("write configured selector fixture config");
    }

    fn write_generated_outline_registration(home: &Path, database: &Path) {
        let server = crate::mcp::McpServerConfig {
            id: "neoth-codegraph".into(),
            description: None,
            command: std::env::current_exe()
                .expect("fixture executable")
                .canonicalize()
                .expect("canonical fixture executable")
                .display()
                .to_string(),
            args: vec![
                "mcp".into(),
                "codegraph-serve".into(),
                "--db".into(),
                database.display().to_string(),
            ],
            env: std::collections::HashMap::new(),
            enabled: true,
            allow_tools: Some(
                crate::mcp::codegraph_server::TOOL_NAMES
                    .iter()
                    .map(|tool| (*tool).to_owned())
                    .collect(),
            ),
            trust_all_tools: false,
            smart_approve: true,
            autonomy_gate: None,
        };
        let servers = crate::mcp::McpServers {
            servers: vec![server],
            smart_loading: true,
        };
        std::fs::write(
            home.join("mcp_servers.yaml"),
            serde_yaml::to_string(&servers).expect("serialize generated outline registration"),
        )
        .expect("write generated outline registration");
    }

    fn code_map_store_artifacts(home: &Path) -> Vec<(std::ffi::OsString, Vec<u8>)> {
        let mut artifacts = std::fs::read_dir(home)
            .expect("read fixture home")
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name();
                name.to_str()
                    .is_some_and(|name| name.starts_with("code_map.db"))
                    .then(|| {
                        (
                            name,
                            std::fs::read(entry.path()).expect("read code-map artifact"),
                        )
                    })
            })
            .collect::<Vec<_>>();
        artifacts.sort_by(|left, right| left.0.cmp(&right.0));
        artifacts
    }

    fn assert_no_pending_fixture_wal(home: &Path) {
        assert!(
            code_map_store_artifacts(home)
                .iter()
                .all(|(name, _)| name.to_string_lossy().as_ref() != "code_map.db-wal"),
            "the fixture writer must be closed and leave no pending WAL before the Doctor baseline"
        );
    }

    fn assert_valid_read_only_wal_artifacts(home: &Path) {
        for (name, bytes) in code_map_store_artifacts(home) {
            match name.to_string_lossy().as_ref() {
                "code_map.db" | "code_map.db-shm" => {}
                "code_map.db-wal" => assert!(
                    bytes.is_empty(),
                    "a valid read-only Doctor path may coordinate through WAL but must not leave WAL frames"
                ),
                unexpected => panic!(
                    "valid read-only Doctor path created an unexpected code-map artifact {unexpected:?}"
                ),
            }
        }
    }

    /// A valid SQLite WAL reader may create or remove `code_map.db-shm` and an
    /// empty `code_map.db-wal` coordination sidecar. Those runtime artifacts do
    /// not constitute a code-map refresh or persisted-data mutation. The
    /// non-mutation contract for a valid store is therefore the main DB bytes,
    /// persisted snapshot data, root generations, and freshness result.
    fn code_map_read_only_observation(
        home: &Path,
        root: &str,
    ) -> (Vec<u8>, i64, i64, Vec<u8>, bool) {
        let database_path = home.join("code_map.db");
        let connection = crate::code_map::persist::open_read_only(&database_path)
            .expect("open existing fixture store read-only");
        let index_generation = crate::code_map::persist::root_index_generation(&connection, root)
            .expect("read fixture index generation")
            .expect("fixture root exists");
        let graph_generation = crate::code_map::persist::root_graph_generation(&connection, root)
            .expect("read fixture graph generation")
            .expect("fixture root graph exists");
        let map = crate::code_map::persist::load_map(&connection, root)
            .expect("load fixture map")
            .expect("fixture map exists");
        let serialized_map = serde_json::to_vec(&map).expect("serialize persisted fixture map");
        let stale = crate::code_map::persist::is_index_stale(&connection, root)
            .expect("read fixture freshness");
        drop(connection);
        (
            std::fs::read(&database_path).expect("read fixture main DB"),
            index_generation,
            graph_generation,
            serialized_map,
            stale,
        )
    }

    #[test]
    fn code_map_analysis_readiness_leaves_an_absent_store_lifecycle_owned() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        write_enabled_code_map_lifecycle(home.path(), repository.path());
        let store = home.path().join("code_map.db");

        let outcome = check_code_map_analysis_readiness(home.path());

        assert_eq!(outcome.status, CheckStatus::Pass, "{outcome:?}");
        assert!(outcome.detail.contains("analysis evidence not assessed"));
        assert!(outcome.detail.contains("lifecycle owns absent state"));
        assert!(
            !store.exists() && code_map_store_artifacts(home.path()).is_empty(),
            "analysis readiness must not create an absent SQLite store or sidecar"
        );
    }

    #[test]
    fn code_map_analysis_readiness_leaves_a_corrupt_store_lifecycle_owned() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        write_enabled_code_map_lifecycle(home.path(), repository.path());
        let store = home.path().join("code_map.db");
        std::fs::write(
            &store,
            b"not a SQLite database; preserve this forensic evidence",
        )
        .unwrap();
        let before = code_map_store_artifacts(home.path());

        let outcome = check_code_map_analysis_readiness(home.path());

        assert_eq!(outcome.status, CheckStatus::Pass, "{outcome:?}");
        assert!(outcome.detail.contains("analysis evidence not assessed"));
        assert!(outcome.detail.contains("lifecycle owns corrupt state"));
        assert_eq!(
            code_map_store_artifacts(home.path()),
            before,
            "analysis readiness must not migrate, repair, or add sidecars to corrupt evidence"
        );
    }

    #[test]
    fn code_map_analysis_readiness_leaves_a_stale_real_sqlite_store_lifecycle_owned() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        write_enabled_code_map_lifecycle(home.path(), repository.path());
        let source = repository.path().join("tracked.rs");
        std::fs::write(&source, "pub fn tracked() {}\n").unwrap();
        let map = crate::code_map::RepoMapBuilder::new(repository.path())
            .scan()
            .expect("scan fixture before persistence");
        let mut store = crate::code_map::persist::open(&home.path().join("code_map.db"))
            .expect("create real fixture store outside Doctor");
        crate::code_map::persist::persist_map_and_edges(&mut store, &map, &[])
            .expect("publish fresh fixture snapshot");
        drop(store);
        std::fs::write(&source, "pub fn tracked() { let changed = true; }\n").unwrap();
        assert_no_pending_fixture_wal(home.path());
        let before = code_map_read_only_observation(home.path(), &map.root);
        assert!(
            before.4,
            "source edit must make the fixture stale before Doctor"
        );

        let outcome = check_code_map_analysis_readiness(home.path());

        assert_eq!(outcome.status, CheckStatus::Pass, "{outcome:?}");
        assert!(outcome.detail.contains("analysis evidence not assessed"));
        assert!(outcome.detail.contains("lifecycle owns stale state"));
        let after = code_map_read_only_observation(home.path(), &map.root);
        assert_eq!(
            after.0, before.0,
            "analysis readiness must not change valid stale main DB bytes"
        );
        assert_eq!(
            (after.1, after.2, after.3, after.4),
            (before.1, before.2, before.3, before.4),
            "analysis readiness must not refresh stale persisted map data, generations, or freshness"
        );
        assert_valid_read_only_wal_artifacts(home.path());
    }

    #[test]
    fn code_map_analysis_readiness_preserves_fresh_main_db_data_generations_and_freshness() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let edge = crate::code_map::graph::CodeEdge::resolved_tested_by(
            "tests/work_test.rs",
            "observes_work",
            "work",
            "src/work.rs",
        );
        persist_fresh_analysis_fixture(home.path(), repository.path(), &[edge]);
        let root = crate::code_map::CanonicalRepoRoot::discover(repository.path())
            .expect("canonical fixture root");
        assert_no_pending_fixture_wal(home.path());
        let before = code_map_read_only_observation(home.path(), root.display());
        assert!(!before.4, "fresh fixture must be fresh before Doctor");

        let outcome = check_code_map_analysis_readiness(home.path());

        assert_eq!(outcome.status, CheckStatus::Pass, "{outcome:?}");
        let after = code_map_read_only_observation(home.path(), root.display());
        assert_eq!(
            after.0, before.0,
            "analysis readiness must not change valid fresh main DB bytes"
        );
        assert_eq!(
            (after.1, after.2, after.3, after.4),
            (before.1, before.2, before.3, before.4),
            "analysis readiness must not change fresh persisted map data, generations, or freshness"
        );
        assert_valid_read_only_wal_artifacts(home.path());
    }

    #[test]
    fn code_map_analysis_readiness_reports_exact_evidence_without_coverage_claim() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let edge = crate::code_map::graph::CodeEdge::resolved_tested_by(
            "tests/work_test.rs",
            "observes_work",
            "work",
            "src/work.rs",
        );
        persist_fresh_analysis_fixture(home.path(), repository.path(), &[edge]);

        let outcome = check_code_map_analysis_readiness(home.path());

        assert_eq!(outcome.name, "code-map analysis readiness");
        assert_eq!(outcome.status, CheckStatus::Pass, "{outcome:?}");
        assert!(outcome.detail.contains("observed 1 exact `TestedBy`"));
        assert!(outcome.detail.contains("not executed test coverage"));
    }

    #[test]
    fn code_map_analysis_readiness_warns_for_nonexact_evidence_without_claiming_no_tests() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let legacy = crate::code_map::graph::CodeEdge {
            from_file: "tests/work_test.rs".into(),
            from_symbol: "observes_work".into(),
            to_name: "work".into(),
            target_file: Some("src/work.rs".into()),
            kind: crate::code_map::graph::EdgeKind::TestedBy,
            confidence: crate::code_map::graph::EdgeConfidenceTier::INFERRED_CONFIDENCE,
            confidence_tier: crate::code_map::graph::EdgeConfidenceTier::Inferred,
        };
        persist_fresh_analysis_fixture(home.path(), repository.path(), &[legacy]);

        let outcome = check_code_map_analysis_readiness(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn, "{outcome:?}");
        assert!(
            outcome
                .detail
                .contains("no observed exact `TestedBy` evidence")
        );
        assert!(
            outcome
                .detail
                .contains("does not prove the repository has no tests or coverage"),
            "{outcome:?}"
        );
    }

    #[test]
    fn outline_enrichment_disabled_returns_before_database_open() {
        let home = tempfile::tempdir().unwrap();
        let store = home.path().join("code_map.db");

        let outcome = check_codegraph_outline_enrichment(home.path());

        assert_eq!(outcome.status, CheckStatus::Pass, "{outcome:?}");
        assert!(outcome.detail.contains("disabled by freedom.yaml"));
        assert!(
            !store.exists(),
            "disabled readiness must not create a database"
        );
    }

    #[test]
    fn outline_enrichment_warns_for_invalid_config_without_inspection() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("freedom.yaml"), "code_map: [not-a-map]\n").unwrap();

        let outcome = check_codegraph_outline_enrichment(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn, "{outcome:?}");
        assert!(
            outcome
                .detail
                .contains("configuration is unavailable or invalid")
        );
        assert!(code_map_store_artifacts(home.path()).is_empty());
    }

    #[test]
    fn outline_enrichment_rejects_custom_lookalike_registration_without_child_work() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        write_enabled_outline_enrichment(home.path(), repository.path());
        let mut server = crate::mcp::McpServerConfig {
            id: "neoth-codegraph".into(),
            description: None,
            command: std::env::current_exe()
                .unwrap()
                .canonicalize()
                .unwrap()
                .display()
                .to_string(),
            args: vec![
                "mcp".into(),
                "codegraph-serve".into(),
                "--db".into(),
                home.path().join("missing.db").display().to_string(),
                "--lookalike".into(),
            ],
            env: std::collections::HashMap::new(),
            enabled: true,
            allow_tools: Some(
                crate::mcp::codegraph_server::TOOL_NAMES
                    .iter()
                    .map(|tool| (*tool).to_owned())
                    .collect(),
            ),
            trust_all_tools: false,
            smart_approve: true,
            autonomy_gate: None,
        };
        server.description = Some("custom must not gain built-in provenance".into());
        let servers = crate::mcp::McpServers {
            servers: vec![server],
            smart_loading: true,
        };
        std::fs::write(
            home.path().join("mcp_servers.yaml"),
            serde_yaml::to_string(&servers).unwrap(),
        )
        .unwrap();

        let outcome = check_codegraph_outline_enrichment(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn, "{outcome:?}");
        assert!(outcome.detail.contains("custom or lookalike"));
        assert!(
            code_map_store_artifacts(home.path()).is_empty(),
            "registration rejection must precede SQLite work"
        );
    }

    #[test]
    fn outline_enrichment_warns_for_absent_or_corrupt_database_without_repair() {
        let absent_home = tempfile::tempdir().unwrap();
        let absent_repo = tempfile::tempdir().unwrap();
        write_enabled_outline_enrichment(absent_home.path(), absent_repo.path());
        let absent_database = absent_home.path().join("missing.db");
        write_generated_outline_registration(absent_home.path(), &absent_database);
        let absent = check_codegraph_outline_enrichment(absent_home.path());
        assert_eq!(absent.status, CheckStatus::Warn, "{absent:?}");
        assert!(absent.detail.contains("absent or inaccessible database"));
        assert!(!absent_database.exists());

        let corrupt_home = tempfile::tempdir().unwrap();
        let corrupt_repo = tempfile::tempdir().unwrap();
        write_enabled_outline_enrichment(corrupt_home.path(), corrupt_repo.path());
        let corrupt_database = corrupt_home.path().join("code_map.db");
        let bytes = b"not sqlite evidence";
        std::fs::write(&corrupt_database, bytes).unwrap();
        write_generated_outline_registration(corrupt_home.path(), &corrupt_database);
        let corrupt = check_codegraph_outline_enrichment(corrupt_home.path());
        assert_eq!(corrupt.status, CheckStatus::Warn, "{corrupt:?}");
        assert!(corrupt.detail.contains("no fresh complete managed map"));
        assert_eq!(std::fs::read(&corrupt_database).unwrap(), bytes);
    }

    #[test]
    fn outline_enrichment_warns_for_stale_map_and_reports_fresh_physical_generation() {
        let stale_home = tempfile::tempdir().unwrap();
        let stale_repository = tempfile::tempdir().unwrap();
        let source = stale_repository.path().join("tracked.rs");
        std::fs::write(&source, "pub fn tracked() {}\n").unwrap();
        write_enabled_outline_enrichment(stale_home.path(), stale_repository.path());
        let map = crate::code_map::RepoMapBuilder::new(stale_repository.path())
            .scan()
            .unwrap();
        let stale_database = stale_home.path().join("code_map.db");
        let mut store = crate::code_map::persist::open(&stale_database).unwrap();
        crate::code_map::persist::persist_map_and_edges(&mut store, &map, &[]).unwrap();
        drop(store);
        write_generated_outline_registration(stale_home.path(), &stale_database);
        std::fs::write(&source, "pub fn tracked() { let stale = true; }\n").unwrap();
        let stale = check_codegraph_outline_enrichment(stale_home.path());
        assert_eq!(stale.status, CheckStatus::Warn, "{stale:?}");
        assert!(stale.detail.contains("stale"));

        let fresh_home = tempfile::tempdir().unwrap();
        let fresh_repository = tempfile::tempdir().unwrap();
        write_enabled_outline_enrichment(fresh_home.path(), fresh_repository.path());
        let fresh_database = fresh_home.path().join("code_map.db");
        let fresh_map = crate::code_map::RepoMapBuilder::new(fresh_repository.path())
            .scan()
            .unwrap();
        let mut fresh_store = crate::code_map::persist::open(&fresh_database).unwrap();
        crate::code_map::persist::persist_map_and_edges(&mut fresh_store, &fresh_map, &[]).unwrap();
        drop(fresh_store);
        write_generated_outline_registration(fresh_home.path(), &fresh_database);
        let fresh = check_codegraph_outline_enrichment(fresh_home.path());
        assert_eq!(fresh.status, CheckStatus::Pass, "{fresh:?}");
        assert!(
            fresh
                .detail
                .contains("existing built-in neoth-codegraph/codegraph_outline route")
        );
        assert!(fresh.detail.contains("fresh complete managed root(s)"));
        assert!(fresh.detail.contains("index_generation="));
        assert!(fresh.detail.contains("Doctor did not enrich a request"));
        assert_valid_read_only_wal_artifacts(fresh_home.path());

        write_enabled_configured_read_path_selector(fresh_home.path(), fresh_repository.path());
        let selected = check_codegraph_outline_enrichment(fresh_home.path());
        assert_eq!(selected.status, CheckStatus::Pass, "{selected:?}");
        assert!(
            selected
                .detail
                .contains("1 exact configured ReadPath selector(s)")
        );
        assert!(selected.detail.contains("built-in route"));
    }

    #[test]
    fn outline_enrichment_warns_for_incomplete_generation_without_rebuild() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        write_enabled_outline_enrichment(home.path(), repository.path());
        let database = home.path().join("code_map.db");
        let map = crate::code_map::RepoMapBuilder::new(repository.path())
            .scan()
            .unwrap();
        let mut store = crate::code_map::persist::open(&database).unwrap();
        crate::code_map::persist::persist_map_and_edges(&mut store, &map, &[]).unwrap();
        store
            .execute(
                "UPDATE code_map_roots SET graph_generation = graph_generation + 1 WHERE root = ?1",
                rusqlite::params![map.root],
            )
            .unwrap();
        drop(store);
        write_generated_outline_registration(home.path(), &database);
        let before = std::fs::read(&database).unwrap();

        let outcome = check_codegraph_outline_enrichment(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn, "{outcome:?}");
        assert!(outcome.detail.contains("incomplete"));
        assert_eq!(
            std::fs::read(&database).unwrap(),
            before,
            "Doctor must not repair incomplete generations"
        );
    }

    #[test]
    fn code_map_lifecycle_absent_index_warns_without_creating_the_store() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        std::fs::write(
            repository.path().join("lib.rs"),
            "pub fn first_index() {}\n",
        )
        .unwrap();
        write_enabled_code_map_lifecycle(home.path(), repository.path());
        let store = home.path().join("code_map.db");

        let outcome = check_code_map_lifecycle(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("no index exists"), "{outcome:?}");
        assert!(
            outcome.detail.contains("neoth code-map refresh"),
            "{outcome:?}"
        );
        assert!(
            !store.exists(),
            "Doctor must not create or migrate an absent code-map store"
        );
    }

    #[test]
    fn lifecycle_doctor_reports_enabled_automatic_context_missing_store_without_mutation() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        std::fs::write(repository.path().join("lib.rs"), "pub fn fixture() {}\n").unwrap();
        let mut config = crate::config::FreedomConfig::default();
        config.code_map.lifecycle.enabled = true;
        config.code_map.lifecycle.managed_roots = vec![repository.path().to_path_buf()];
        config.code_map.auto_context_max_files = 3;
        let database = home.path().join("code_map.db");
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();

        let outcome = check_code_map_lifecycle(home.path());

        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(
            outcome
                .detail
                .contains("automatic Chat/Channel context unavailable (missing_store)"),
            "{outcome:?}"
        );
        assert!(
            !database.exists(),
            "Doctor status must not create the missing store"
        );
    }

    #[test]
    fn lifecycle_doctor_reports_automatic_context_disabled_eligible_stale_and_unmapped() {
        let disabled_home = tempfile::tempdir().unwrap();
        let disabled_repository = tempfile::tempdir().unwrap();
        std::fs::write(
            disabled_repository.path().join("lib.rs"),
            "pub fn disabled() {}\n",
        )
        .unwrap();
        write_enabled_code_map_lifecycle(disabled_home.path(), disabled_repository.path());
        let disabled = check_code_map_lifecycle(disabled_home.path());
        assert_eq!(disabled.status, CheckStatus::Warn, "{disabled:?}");
        assert!(
            disabled
                .detail
                .contains("automatic Chat/Channel context disabled"),
            "{disabled:?}"
        );
        assert!(
            !disabled_home.path().join("code_map.db").exists(),
            "Doctor must not open a disabled automatic-context store"
        );

        let eligible_home = tempfile::tempdir().unwrap();
        let eligible_repository = tempfile::tempdir().unwrap();
        std::fs::write(
            eligible_repository.path().join("lib.rs"),
            "pub fn eligible() {}\n",
        )
        .unwrap();
        let mut eligible_config = crate::config::FreedomConfig::default();
        eligible_config.code_map.lifecycle.enabled = true;
        eligible_config.code_map.lifecycle.managed_roots =
            vec![eligible_repository.path().to_path_buf()];
        eligible_config.code_map.auto_context_max_files = 3;
        std::fs::write(
            eligible_home.path().join("freedom.yaml"),
            serde_yaml::to_string(&eligible_config).unwrap(),
        )
        .unwrap();
        let eligible_database = eligible_home.path().join("code_map.db");
        let eligible_root =
            crate::code_map::CanonicalRepoRoot::discover(eligible_repository.path()).unwrap();
        crate::code_map::rebuild_snapshot(
            &eligible_root,
            &eligible_database,
            crate::code_map::RebuildOptions::default(),
        )
        .unwrap();
        let eligible_before = std::fs::read(&eligible_database).unwrap();
        let eligible = check_code_map_lifecycle(eligible_home.path());
        assert_eq!(eligible.status, CheckStatus::Pass, "{eligible:?}");
        assert!(
            eligible
                .detail
                .contains("automatic Chat/Channel context eligible (max_files=3)"),
            "{eligible:?}"
        );
        assert_eq!(
            std::fs::read(&eligible_database).unwrap(),
            eligible_before,
            "Doctor must not mutate an eligible store"
        );
        assert_valid_read_only_wal_artifacts(eligible_home.path());

        let stale_home = tempfile::tempdir().unwrap();
        let stale_repository = tempfile::tempdir().unwrap();
        let stale_source = stale_repository.path().join("lib.rs");
        std::fs::write(&stale_source, "pub fn stale() {}\n").unwrap();
        let mut stale_config = eligible_config.clone();
        stale_config.code_map.lifecycle.managed_roots = vec![stale_repository.path().to_path_buf()];
        std::fs::write(
            stale_home.path().join("freedom.yaml"),
            serde_yaml::to_string(&stale_config).unwrap(),
        )
        .unwrap();
        let stale_database = stale_home.path().join("code_map.db");
        let stale_root =
            crate::code_map::CanonicalRepoRoot::discover(stale_repository.path()).unwrap();
        crate::code_map::rebuild_snapshot(
            &stale_root,
            &stale_database,
            crate::code_map::RebuildOptions::default(),
        )
        .unwrap();
        std::fs::write(&stale_source, "pub fn stale() { changed(); }\n").unwrap();
        let stale_before = std::fs::read(&stale_database).unwrap();
        let stale = check_code_map_lifecycle(stale_home.path());
        assert_eq!(stale.status, CheckStatus::Warn, "{stale:?}");
        assert!(
            stale
                .detail
                .contains("automatic Chat/Channel context unavailable (stale_snapshot)"),
            "{stale:?}"
        );
        assert!(stale.detail.contains("neoth code-map refresh"), "{stale:?}");
        assert_eq!(
            std::fs::read(&stale_database).unwrap(),
            stale_before,
            "Doctor must not refresh a stale store"
        );
        assert_valid_read_only_wal_artifacts(stale_home.path());

        let unmapped_home = tempfile::tempdir().unwrap();
        let mapped_repository = tempfile::tempdir().unwrap();
        let unmapped_repository = tempfile::tempdir().unwrap();
        std::fs::write(
            mapped_repository.path().join("lib.rs"),
            "pub fn mapped() {}\n",
        )
        .unwrap();
        std::fs::write(
            unmapped_repository.path().join("lib.rs"),
            "pub fn unmapped() {}\n",
        )
        .unwrap();
        let mut unmapped_config = eligible_config;
        unmapped_config.code_map.lifecycle.managed_roots =
            vec![unmapped_repository.path().to_path_buf()];
        std::fs::write(
            unmapped_home.path().join("freedom.yaml"),
            serde_yaml::to_string(&unmapped_config).unwrap(),
        )
        .unwrap();
        let unmapped_database = unmapped_home.path().join("code_map.db");
        let mapped_root =
            crate::code_map::CanonicalRepoRoot::discover(mapped_repository.path()).unwrap();
        crate::code_map::rebuild_snapshot(
            &mapped_root,
            &unmapped_database,
            crate::code_map::RebuildOptions::default(),
        )
        .unwrap();
        let unmapped_before = std::fs::read(&unmapped_database).unwrap();
        let unmapped = check_code_map_lifecycle(unmapped_home.path());
        assert_eq!(unmapped.status, CheckStatus::Warn, "{unmapped:?}");
        assert!(
            unmapped
                .detail
                .contains("automatic Chat/Channel context unavailable (unmapped_root)"),
            "{unmapped:?}"
        );
        assert!(
            unmapped.detail.contains("neoth code-map refresh"),
            "{unmapped:?}"
        );
        assert_eq!(
            std::fs::read(&unmapped_database).unwrap(),
            unmapped_before,
            "Doctor must not map or refresh an unmapped root"
        );
        assert_valid_read_only_wal_artifacts(unmapped_home.path());
    }

    #[test]
    fn code_map_lifecycle_corrupt_store_fails_without_repairing_it() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        std::fs::write(
            repository.path().join("lib.rs"),
            "pub fn corrupt_fixture() {}\n",
        )
        .unwrap();
        write_enabled_code_map_lifecycle(home.path(), repository.path());
        let store = home.path().join("code_map.db");
        let original = b"this is not a sqlite database";
        std::fs::write(&store, original).unwrap();

        let outcome = check_code_map_lifecycle(home.path());

        assert_eq!(outcome.status, CheckStatus::Fail);
        assert!(outcome.detail.contains("--repair-corrupt"), "{outcome:?}");
        assert!(
            outcome
                .detail
                .contains("automatic Chat/Channel context disabled"),
            "{outcome:?}"
        );
        let config_path = home.path().join("freedom.yaml");
        let mut config = crate::config::FreedomConfig::load_from_path(&config_path).unwrap();
        config.code_map.auto_context_max_files = 3;
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let outcome = check_code_map_lifecycle(home.path());
        assert_eq!(outcome.status, CheckStatus::Fail);
        assert!(outcome.detail.contains("--repair-corrupt"), "{outcome:?}");
        assert!(
            outcome
                .detail
                .contains("automatic Chat/Channel context unavailable (unreadable_store)"),
            "{outcome:?}"
        );
        assert_eq!(
            std::fs::read(&store).unwrap(),
            original,
            "Doctor must leave corrupt forensic evidence untouched"
        );
    }

    #[test]
    fn code_map_lifecycle_quotes_canonical_root_with_whitespace_in_repair_command() {
        let home = tempfile::tempdir().unwrap();
        let repository = home.path().join("repository with spaces");
        std::fs::create_dir(&repository).unwrap();
        std::fs::write(repository.join("lib.rs"), "pub fn quoted_root() {}\n").unwrap();
        write_enabled_code_map_lifecycle(home.path(), &repository);

        let outcome = check_code_map_lifecycle(home.path());
        let canonical = std::fs::canonicalize(&repository).unwrap();
        let quoted = quote_code_map_command_path(&canonical);

        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(
            outcome
                .detail
                .contains(&format!("neoth code-map refresh {quoted}")),
            "Doctor must preserve the canonical root as one command argument: {outcome:?}"
        );
        assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
    }

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
