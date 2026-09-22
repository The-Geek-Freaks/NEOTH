//! Capability-readiness checks — the "is the whole product wired?" surface.
//!
//! One `neoth doctor` run proves each headline capability is actually plumbed:
//! computer-use (cua-driver MCP), OKF memory export, the iroh cluster transport,
//! MCP servers, and the WAL audit chain. This is the integration proof — a
//! product readout, not a feature list.

use std::path::Path;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus};

/// Computer-use (trycua cua-driver) — installed + registered as a gated MCP
/// server? Optional capability, so "off" is a clean Pass, not a failure.
pub(crate) fn check_computer_use(home: &Path) -> CheckOutcome {
    let installed = crate::computer_use::is_installed();
    // GR-fix: honour `doctor --home DIR` — load the MCP registry from the passed
    // home, not the hardcoded default (the check ignored --home before).
    let registered = crate::mcp::config::McpServers::load_from(&home.join("mcp_servers.yaml"))
        .ok()
        .map(|s| {
            s.servers
                .iter()
                .any(|x| x.id == crate::computer_use::CUA_DRIVER_SERVER_ID && x.enabled)
        })
        .unwrap_or(false);
    let (status, detail) = match (installed, registered) {
        (true, true) => (
            CheckStatus::Pass,
            "cua-driver installed + enabled (autonomy-gated + WAL-audited MCP)",
        ),
        (false, true) => (
            CheckStatus::Warn,
            "registered but cua-driver not installed — `neoth computer-use install`",
        ),
        (true, false) => (
            CheckStatus::Warn,
            "cua-driver installed but not enabled — `neoth computer-use enable`",
        ),
        (false, false) => (
            CheckStatus::Pass,
            "off (optional) — `neoth computer-use enable` to wire desktop control",
        ),
    };
    CheckOutcome {
        name: "computer-use",
        status,
        detail: detail.to_string(),
    }
}

/// OKF export — can NEOTH write a knowledge bundle? Probes the home dir.
pub(crate) fn check_okf_export(home: &Path) -> CheckOutcome {
    // GR-fix: read-only check — `neoth doctor` is documented as non-mutating, but
    // this wrote a `.okf-write-probe` file every run and left it behind if the
    // remove failed. A metadata readonly-bit check keeps the diagnostic side-effect-free.
    let writable = home.exists()
        && home
            .metadata()
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false);
    if writable {
        CheckOutcome {
            name: "okf export",
            status: CheckStatus::Pass,
            detail: "knowledge bundle dir writable — `neoth okf export` / `okf sync --vault`"
                .into(),
        }
    } else {
        CheckOutcome {
            name: "okf export",
            status: CheckStatus::Warn,
            detail: format!(
                "neoth home not writable ({}) — okf export will fail",
                home.display()
            ),
        }
    }
}

/// iroh cluster transport — compiled in (the `cluster-iroh` feature) + selected?
pub(crate) fn check_iroh_transport(_home: &Path) -> CheckOutcome {
    let feature = cfg!(feature = "cluster-iroh");
    let cluster = cfg!(feature = "cluster");
    let (status, detail) = if feature {
        (
            CheckStatus::Pass,
            "iroh transport available (cluster-iroh) — set `cluster.transport: iroh` to use it"
                .to_string(),
        )
    } else if cluster {
        (
            CheckStatus::Pass,
            "peeroxide transport (default); rebuild `--features cluster-iroh` for the iroh carrier"
                .to_string(),
        )
    } else {
        (
            CheckStatus::Pass,
            "clustering compiled out (no `cluster` feature)".to_string(),
        )
    };
    CheckOutcome {
        name: "iroh transport",
        status,
        detail,
    }
}

/// MCP servers — how many are registered + enabled (the tool surface).
pub(crate) fn check_mcp_servers(home: &Path) -> CheckOutcome {
    // GR-fix: honour `doctor --home DIR` (was ignoring it via the default-path load).
    match crate::mcp::config::McpServers::load_from(&home.join("mcp_servers.yaml")) {
        Ok(s) => {
            let enabled = s.servers.iter().filter(|x| x.enabled).count();
            let total = s.servers.len();
            CheckOutcome {
                // F12 — distinct name from integrations::check_mcp_servers (the
                // rich analysis keeps "mcp servers"); this simple count was a
                // duplicate name → double output + --explain shadowing.
                name: "mcp tool surface",
                status: CheckStatus::Pass,
                detail: format!("{enabled}/{total} MCP server(s) enabled (mcp_servers.yaml)"),
            }
        }
        Err(_) => CheckOutcome {
            name: "mcp tool surface",
            status: CheckStatus::Pass,
            detail: "no mcp_servers.yaml — no external MCP tools configured".into(),
        },
    }
}

/// WAL audit chain — the tamper-evident ledger every gated action lands in.
pub(crate) fn check_wal_audit_health(home: &Path) -> CheckOutcome {
    // GR-fix: honour `doctor --home DIR` (was using the hardcoded default WAL dir).
    let wal_dir = crate::config::FreedomConfig::default_wal_dir_at(home);
    if !wal_dir.exists() {
        return CheckOutcome {
            name: "wal audit",
            status: CheckStatus::Pass,
            detail: "WAL dir absent (daemon hasn't run yet) — created on first `neoth serve`"
                .into(),
        };
    }
    let segments = std::fs::read_dir(&wal_dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().map(|x| x == "wal").unwrap_or(false))
                .count()
        })
        .unwrap_or(0);
    if segments > 0 {
        CheckOutcome {
            name: "wal audit",
            status: CheckStatus::Pass,
            detail: format!(
                "{segments} WAL segment(s) — audit chain present (0xC0 MCP, gate frames)"
            ),
        }
    } else {
        CheckOutcome {
            name: "wal audit",
            status: CheckStatus::Warn,
            detail: "WAL dir exists but has no segments yet".into(),
        }
    }
}

/// P2-06 — observational provider/capability quality trend from a complete
/// authenticated terminal-WAL prefix. This is intentionally advisory only.
pub(crate) fn check_capability_quality(home: &Path) -> CheckOutcome {
    let now = crate::time::now_unix_i64();
    let report = match crate::daemon::capability_decay::inspect_authenticated_terminal_history(
        home, now,
    ) {
        Ok(report) => report,
        Err(error) => {
            return CheckOutcome {
                name: "capability quality",
                status: CheckStatus::Warn,
                detail: format!(
                    "unavailable: authenticated terminal history could not be read completely ({error:#}); no quality conclusion"
                ),
            };
        }
    };
    let degrading: Vec<_> = report
        .observations
        .iter()
        .filter(|row| row.trend == crate::daemon::capability_decay::CapabilityTrend::Degrading)
        .collect();
    let recovering = report
        .observations
        .iter()
        .filter(|row| row.trend == crate::daemon::capability_decay::CapabilityTrend::Recovering)
        .count();
    let comparable = report
        .observations
        .iter()
        .filter(|row| {
            row.trend != crate::daemon::capability_decay::CapabilityTrend::InsufficientSamples
        })
        .count();
    let attribution = match (
        report.unattributed_terminal_rows,
        report.legacy_terminal_rows,
    ) {
        (0, 0) => String::new(),
        (unattributed, legacy) => {
            format!("; {unattributed} unattributed and {legacy} legacy terminal row(s) excluded")
        }
    };
    if !degrading.is_empty() {
        let labels = render_degrading_labels(&degrading);
        return CheckOutcome {
            name: "capability quality",
            status: CheckStatus::Warn,
            detail: format!(
                "observed degradation for {labels}; advisory failure/latency evidence only, no routing or disable action{attribution}"
            ),
        };
    }
    if comparable == 0 {
        return CheckOutcome {
            name: "capability quality",
            status: CheckStatus::Pass,
            detail: format!(
                "inconclusive: no provider/model/workflow identity has the conservative recent+baseline sample floor{attribution}"
            ),
        };
    }
    CheckOutcome {
        name: "capability quality",
        status: CheckStatus::Pass,
        detail: format!(
            "{comparable} provider/model/workflow identity(s) have stable or recovering operational evidence ({recovering} recovering); adapter outcomes and latency do not measure reasoning quality{attribution}"
        ),
    }
}

fn render_degrading_labels(
    rows: &[&crate::daemon::capability_decay::CapabilityObservation],
) -> String {
    let shown = rows
        .iter()
        .take(crate::daemon::capability_decay::MAX_RENDERED_DEGRADATIONS)
        .map(|row| {
            format!(
                "{}/{}/{} (errors {}/{} -> {}/{}, p90 {} -> {} ms)",
                row.identity.provider,
                row.identity.model,
                row.identity.workflow.as_str(),
                row.baseline_failures,
                row.baseline_samples,
                row.recent_failures,
                row.recent_samples,
                row.baseline_p90_latency_ms,
                row.recent_p90_latency_ms,
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let omitted = rows
        .len()
        .saturating_sub(crate::daemon::capability_decay::MAX_RENDERED_DEGRADATIONS);
    if omitted == 0 {
        shown
    } else {
        format!("{shown} (+{omitted} more)")
    }
}

/// Self-improvement (SkillOpt) — switch state + engine availability + last run.
pub(crate) fn check_self_improve(home: &Path) -> CheckOutcome {
    let cfg = match crate::self_improve::SelfImproveConfig::load(home) {
        Ok(cfg) => cfg,
        Err(error) => {
            return CheckOutcome {
                name: "self-improvement",
                status: CheckStatus::Fail,
                detail: format!("self_improve.yaml is unreadable or corrupt: {error:#}"),
            };
        }
    };
    let installed = crate::self_improve::is_installed();
    let (status, detail) = if cfg.enabled && installed {
        let detail = match crate::self_improve::last_record(home) {
            Ok(Some(r)) => format!(
                "enabled; last: {} ({})",
                r.skill,
                if r.accepted { "improved" } else { "no change" }
            ),
            Ok(None) => "enabled; SkillOpt ready; no runs yet".to_string(),
            Err(error) => {
                return CheckOutcome {
                    name: "self-improvement",
                    status: CheckStatus::Fail,
                    detail: format!("self-improvement ledger is unreadable or corrupt: {error:#}"),
                };
            }
        };
        (CheckStatus::Pass, detail)
    } else if cfg.enabled && !installed {
        (
            CheckStatus::Warn,
            "enabled but SkillOpt not installed — `pip install skillopt`".to_string(),
        )
    } else {
        (
            CheckStatus::Pass,
            "off (optional) — `neoth self-improve enable` to let NEOTH evolve its skills"
                .to_string(),
        )
    };
    CheckOutcome {
        name: "self-improvement",
        status,
        detail,
    }
}

pub(crate) const CHECKS: &[CheckFn] = &[
    check_computer_use,
    check_okf_export,
    check_iroh_transport,
    check_mcp_servers,
    check_wal_audit_health,
    check_capability_quality,
    check_self_improve,
];

pub(crate) const DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "computer-use",
        purpose: "Whether trycua cua-driver is installed + registered as a gated \
                  MCP server, so the agent can drive the desktop (screenshot / \
                  click / type) with every call autonomy-gated + WAL-audited.",
        common_failures: "Driver not installed; registered but disabled; tool \
                         allowlist drift after a driver upgrade.",
        fix: "`neoth computer-use install` then `enable`; `neoth computer-use \
              doctor` to check version + advertised-vs-allowed tools.",
    },
    CheckDoc {
        name: "okf export",
        purpose: "Whether NEOTH can write an Open Knowledge Format bundle of its \
                  memory (entities + relations + facts) for Obsidian / LLM reuse.",
        common_failures: "neoth home directory missing or read-only.",
        fix: "Ensure `~/.neoth` exists + is writable; then `neoth okf export` or \
              `neoth okf sync --vault <path>`.",
    },
    CheckDoc {
        name: "iroh transport",
        purpose: "Whether the iroh QUIC cluster transport (dial-by-key, NAT- \
                  traversal, relay) is compiled in and which carrier is selected \
                  (peeroxide default vs iroh).",
        common_failures: "Built without `--features cluster-iroh`; \
                         `cluster.transport: iroh` set but feature absent.",
        fix: "Rebuild with `--features cluster-iroh`; set \
              `cluster.transport: iroh` in freedom.yaml to switch the carrier.",
    },
    CheckDoc {
        name: "mcp tool surface",
        purpose: "Count of registered + enabled MCP servers in \
                  `~/.neoth/mcp_servers.yaml` — the agent's external tool surface.",
        common_failures: "No mcp_servers.yaml; servers disabled.",
        fix: "Add servers to mcp_servers.yaml; `neoth mcp list-tools --server \
              <id>` to inspect.",
    },
    CheckDoc {
        name: "wal audit",
        purpose: "Whether the WAL audit chain exists — the tamper-evident ledger \
                  every gated action (MCP 0xC0, channel send, consent) lands in.",
        common_failures: "Daemon never run (no WAL dir); empty WAL dir.",
        fix: "Run `neoth serve` once to initialise the WAL; `neoth wal show` to \
              inspect frames.",
    },
    CheckDoc {
        name: "capability quality",
        purpose: "Read-only operational trend from a complete authenticated provider-terminal WAL prefix. It separates provider, wire model and closed workflow identity, compares a conservative 24-hour window with the preceding 7-day baseline, and reports only failure/latency evidence.",
        common_failures: "No complete authenticated WAL prefix; too few comparable terminal outcomes; missing or unknown capability attribution; elevated completed-call failures or p90 latency.",
        fix: "Inspect the named provider/model/workflow and its WAL terminal receipts. This check never routes around, disables, retries, or evaluates reasoning/factual quality.",
    },
    CheckDoc {
        name: "self-improvement",
        purpose: "Whether NEOTH's SkillOpt-based self-evolution is enabled + the \
                  engine is installed, plus the last improvement outcome. NEOTH \
                  can evolve its own skills (validation-gated, review-then-adopt).",
        common_failures: "Switch off (default — opt-in); SkillOpt not pip-installed.",
        fix: "`pip install skillopt`; `neoth self-improve enable [--auto]`; \
              `neoth self-improve run` / `log` to drive + inspect.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn degrading_observation(
        index: usize,
    ) -> crate::daemon::capability_decay::CapabilityObservation {
        crate::daemon::capability_decay::CapabilityObservation {
            identity: crate::daemon::capability_decay::CapabilityIdentity {
                provider: format!("provider-{index}"),
                model: format!("model-{index}"),
                workflow: crate::daemon::usage_log::WorkflowKey(
                    crate::daemon::usage_log::WorkflowKind::ChatTurn,
                ),
            },
            trend: crate::daemon::capability_decay::CapabilityTrend::Degrading,
            recent_samples: 8,
            baseline_samples: 12,
            recent_failures: 4,
            baseline_failures: 0,
            recent_p90_latency_ms: 900,
            baseline_p90_latency_ms: 100,
        }
    }

    #[test]
    fn every_check_has_a_doc() {
        for c in CHECKS {
            let out = c(std::path::Path::new("."));
            assert!(
                DOCS.iter().any(|d| d.name == out.name),
                "check `{}` has no DOCS entry",
                out.name
            );
        }
    }

    #[test]
    fn checks_never_panic_and_are_named() {
        for c in CHECKS {
            let out = c(std::path::Path::new("."));
            assert!(!out.name.is_empty());
            assert!(!out.detail.is_empty());
        }
    }

    #[test]
    fn capability_quality_doctor_home_is_read_only_when_history_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let before: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let outcome = check_capability_quality(dir.path());
        let after: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(matches!(
            outcome.status,
            CheckStatus::Pass | CheckStatus::Warn
        ));
        assert_eq!(
            before, after,
            "Doctor capability observation must not create or repair home state"
        );
    }

    #[test]
    fn capability_quality_limits_rendered_degradation_labels() {
        let rows = (0..6).map(degrading_observation).collect::<Vec<_>>();
        let references = rows.iter().collect::<Vec<_>>();
        let rendered = render_degrading_labels(&references);
        assert!(rendered.contains("provider-0/model-0/chat_turn"));
        assert!(rendered.contains("errors 0/12 -> 4/8, p90 100 -> 900 ms"));
        assert!(rendered.contains("provider-3/model-3/chat_turn"));
        assert!(!rendered.contains("provider-4/model-4/chat_turn"));
        assert!(rendered.ends_with("(+2 more)"));
    }
}
