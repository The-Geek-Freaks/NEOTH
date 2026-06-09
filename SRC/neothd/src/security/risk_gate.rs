//! GOLD-ADOPT-23 P0 — tool-call risk policy gate.
//!
//! Turns the [`crate::security::egress`] + [`crate::security::dangerous_command`]
//! findings (previously surfaced as a tracing warn only) into a deny / confirm /
//! allow DECISION, driven by [`crate::config::SecurityPolicy`]:
//!
//! - A **Critical** dangerous-command finding → the operator's
//!   `dangerous_commands` policy (default `Deny` — the LLM must not autonomously
//!   run a host-destroying command; `Confirm` blocks-with-ask; `Warn` doesn't
//!   block). High-severity findings never hard-block (warn only).
//! - An outbound **egress** destination not on the allowlist → the `egress.mode`
//!   policy (`Allow` = warn only, `ConfirmUnknown` = block-with-ask,
//!   `DenyUnknown` = block).
//!
//! Pure + deterministic — the dispatch loop calls it after scanning a call's
//! arguments. Deny outranks Confirm outranks Allow.

use crate::config::{DangerousPolicy, EgressMode, SecurityPolicy};
use crate::security::dangerous_command::Severity;
use crate::security::ToolCallRisk;

/// The gate's verdict for one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskGate {
    /// Run the call (findings, if any, were warn-only under the active policy).
    Allow,
    /// Block + tell the LLM the operator must confirm before this can run.
    Confirm(String),
    /// Block outright.
    Deny(String),
}

impl RiskGate {
    pub fn is_blocked(&self) -> bool {
        !matches!(self, RiskGate::Allow)
    }
    /// Severity ordering for combining two verdicts (Deny > Confirm > Allow).
    fn rank(&self) -> u8 {
        match self {
            RiskGate::Deny(_) => 2,
            RiskGate::Confirm(_) => 1,
            RiskGate::Allow => 0,
        }
    }
    /// Keep the stricter of two verdicts.
    fn max(self, other: RiskGate) -> RiskGate {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// True when `domain` is covered by the allowlist — exact match or a suffix
/// match on a dot boundary (`github.com` allows `api.github.com` but NOT
/// `evilgithub.com` or `github.com.attacker.net`).
fn domain_allowed(domain: &str, allowlist: &[String]) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    allowlist.iter().any(|a| {
        let a = a.trim().trim_end_matches('.').to_ascii_lowercase();
        !a.is_empty() && (d == a || d.ends_with(&format!(".{a}")))
    })
}

/// Evaluate a scanned [`ToolCallRisk`] against the operator's policy.
pub fn evaluate_tool_risk(risk: &ToolCallRisk, policy: &SecurityPolicy) -> RiskGate {
    let mut verdict = RiskGate::Allow;

    // ── Dangerous-command findings ────────────────────────────────────────
    let worst_critical = risk
        .dangerous
        .iter()
        .find(|f| f.severity == Severity::Critical);
    if let Some(f) = worst_critical {
        verdict = verdict.max(match policy.dangerous_commands {
            DangerousPolicy::Deny => RiskGate::Deny(format!(
                "dangerous-command policy=deny: `{}` ({}). Not executed. \
                 Operator: set security.dangerous_commands=confirm|warn to lift.",
                f.id, f.reason
            )),
            DangerousPolicy::Confirm => RiskGate::Confirm(format!(
                "dangerous-command policy=confirm: `{}` ({}) needs operator approval.",
                f.id, f.reason
            )),
            DangerousPolicy::Warn => RiskGate::Allow,
        });
    }

    // ── Egress findings ───────────────────────────────────────────────────
    if !matches!(policy.egress.mode, EgressMode::Allow) {
        let unknown: Vec<&str> = risk
            .egress
            .iter()
            .filter(|e| !e.domain.is_empty() && !domain_allowed(&e.domain, &policy.egress.allowlist))
            .map(|e| e.domain.as_str())
            .collect();
        if !unknown.is_empty() {
            let domains = {
                let mut d: Vec<&str> = unknown.clone();
                d.sort_unstable();
                d.dedup();
                d.join(", ")
            };
            verdict = verdict.max(match policy.egress.mode {
                EgressMode::DenyUnknown => RiskGate::Deny(format!(
                    "egress policy=deny_unknown: outbound to non-allowlisted {domains}. Not executed."
                )),
                EgressMode::ConfirmUnknown => RiskGate::Confirm(format!(
                    "egress policy=confirm_unknown: outbound to non-allowlisted {domains} needs operator approval."
                )),
                EgressMode::Allow => RiskGate::Allow,
            });
        }
    }

    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EgressPolicy;
    use crate::security::dangerous_command::DangerousFinding;
    use crate::security::egress::EgressDestination;

    fn dangerous(id: &'static str, sev: Severity) -> DangerousFinding {
        DangerousFinding {
            id,
            severity: sev,
            reason: "test reason",
        }
    }
    fn egress(domain: &str) -> EgressDestination {
        EgressDestination {
            kind: "url".into(),
            destination: format!("https://{domain}/x"),
            domain: domain.into(),
        }
    }
    fn risk(d: Vec<DangerousFinding>, e: Vec<EgressDestination>) -> ToolCallRisk {
        ToolCallRisk {
            dangerous: d,
            egress: e,
        }
    }

    #[test]
    fn critical_dangerous_denied_by_default() {
        let p = SecurityPolicy::default();
        assert_eq!(p.dangerous_commands, DangerousPolicy::Deny);
        let v = evaluate_tool_risk(&risk(vec![dangerous("rm_rf_root", Severity::Critical)], vec![]), &p);
        assert!(matches!(v, RiskGate::Deny(_)));
    }

    #[test]
    fn high_severity_never_hard_blocks() {
        let p = SecurityPolicy::default();
        let v = evaluate_tool_risk(&risk(vec![dangerous("git_force_push", Severity::High)], vec![]), &p);
        assert_eq!(v, RiskGate::Allow, "High findings warn-only, never gate");
    }

    #[test]
    fn dangerous_policy_confirm_and_warn() {
        let mut p = SecurityPolicy::default();
        p.dangerous_commands = DangerousPolicy::Confirm;
        assert!(matches!(
            evaluate_tool_risk(&risk(vec![dangerous("mkfs_format", Severity::Critical)], vec![]), &p),
            RiskGate::Confirm(_)
        ));
        p.dangerous_commands = DangerousPolicy::Warn;
        assert_eq!(
            evaluate_tool_risk(&risk(vec![dangerous("mkfs_format", Severity::Critical)], vec![]), &p),
            RiskGate::Allow
        );
    }

    #[test]
    fn egress_allow_mode_never_blocks() {
        let p = SecurityPolicy::default(); // egress mode = Allow
        let v = evaluate_tool_risk(&risk(vec![], vec![egress("evil.com")]), &p);
        assert_eq!(v, RiskGate::Allow);
    }

    #[test]
    fn egress_deny_unknown_blocks_non_allowlisted() {
        let p = SecurityPolicy {
            egress: EgressPolicy {
                mode: EgressMode::DenyUnknown,
                allowlist: vec!["github.com".into()],
            },
            ..Default::default()
        };
        // Allowlisted (suffix) → allowed.
        assert_eq!(
            evaluate_tool_risk(&risk(vec![], vec![egress("api.github.com")]), &p),
            RiskGate::Allow
        );
        // Non-allowlisted → denied.
        assert!(matches!(
            evaluate_tool_risk(&risk(vec![], vec![egress("evil.com")]), &p),
            RiskGate::Deny(_)
        ));
    }

    #[test]
    fn egress_confirm_unknown_asks() {
        let p = SecurityPolicy {
            egress: EgressPolicy {
                mode: EgressMode::ConfirmUnknown,
                allowlist: vec![],
            },
            ..Default::default()
        };
        assert!(matches!(
            evaluate_tool_risk(&risk(vec![], vec![egress("data-sink.io")]), &p),
            RiskGate::Confirm(_)
        ));
    }

    #[test]
    fn deny_outranks_confirm() {
        // Critical-deny dangerous + confirm-unknown egress → Deny wins.
        let p = SecurityPolicy {
            dangerous_commands: DangerousPolicy::Deny,
            egress: EgressPolicy {
                mode: EgressMode::ConfirmUnknown,
                allowlist: vec![],
            },
        };
        let v = evaluate_tool_risk(
            &risk(vec![dangerous("rm_rf_root", Severity::Critical)], vec![egress("x.com")]),
            &p,
        );
        assert!(matches!(v, RiskGate::Deny(_)));
    }

    #[test]
    fn domain_suffix_match_is_boundary_safe() {
        let allow = vec!["github.com".to_string()];
        assert!(domain_allowed("github.com", &allow));
        assert!(domain_allowed("api.github.com", &allow));
        assert!(!domain_allowed("evilgithub.com", &allow));
        assert!(!domain_allowed("github.com.attacker.net", &allow));
    }

    #[test]
    fn empty_risk_is_allow() {
        assert_eq!(
            evaluate_tool_risk(&risk(vec![], vec![]), &SecurityPolicy::default()),
            RiskGate::Allow
        );
    }
}
