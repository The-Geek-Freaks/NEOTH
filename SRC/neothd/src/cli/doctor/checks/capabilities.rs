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
pub(crate) fn check_computer_use(_home: &Path) -> CheckOutcome {
    let installed = crate::computer_use::is_installed();
    let registered = crate::mcp::config::McpServers::load()
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
    let writable = home.exists() && {
        let probe = home.join(".okf-write-probe");
        let ok = std::fs::write(&probe, b"x").is_ok();
        let _ = std::fs::remove_file(&probe);
        ok
    };
    if writable {
        CheckOutcome {
            name: "okf export",
            status: CheckStatus::Pass,
            detail: "knowledge bundle dir writable — `neoth okf export` / `okf sync --vault`".into(),
        }
    } else {
        CheckOutcome {
            name: "okf export",
            status: CheckStatus::Warn,
            detail: format!("neoth home not writable ({}) — okf export will fail", home.display()),
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
pub(crate) fn check_mcp_servers(_home: &Path) -> CheckOutcome {
    match crate::mcp::config::McpServers::load() {
        Ok(s) => {
            let enabled = s.servers.iter().filter(|x| x.enabled).count();
            let total = s.servers.len();
            CheckOutcome {
                name: "mcp servers",
                status: CheckStatus::Pass,
                detail: format!("{enabled}/{total} MCP server(s) enabled (mcp_servers.yaml)"),
            }
        }
        Err(_) => CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Pass,
            detail: "no mcp_servers.yaml — no external MCP tools configured".into(),
        },
    }
}

/// WAL audit chain — the tamper-evident ledger every gated action lands in.
pub(crate) fn check_wal_audit_health(_home: &Path) -> CheckOutcome {
    let wal_dir = crate::config::FreedomConfig::default_wal_dir();
    if !wal_dir.exists() {
        return CheckOutcome {
            name: "wal audit",
            status: CheckStatus::Pass,
            detail: "WAL dir absent (daemon hasn't run yet) — created on first `neoth serve`".into(),
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
            detail: format!("{segments} WAL segment(s) — audit chain present (0xC0 MCP, gate frames)"),
        }
    } else {
        CheckOutcome {
            name: "wal audit",
            status: CheckStatus::Warn,
            detail: "WAL dir exists but has no segments yet".into(),
        }
    }
}

/// Self-improvement (SkillOpt) — switch state + engine availability + last run.
pub(crate) fn check_self_improve(home: &Path) -> CheckOutcome {
    let cfg = crate::self_improve::SelfImproveConfig::load(home);
    let installed = crate::self_improve::is_installed();
    let (status, detail) = if cfg.enabled && installed {
        let detail = match crate::self_improve::last_record(home) {
            Some(r) => format!(
                "enabled; last: {} ({})",
                r.skill,
                if r.accepted { "improved" } else { "no change" }
            ),
            None => "enabled; SkillOpt ready; no runs yet".to_string(),
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
            "off (optional) — `neoth self-improve enable` to let NEOTH evolve its skills".to_string(),
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
        name: "mcp servers",
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
}
