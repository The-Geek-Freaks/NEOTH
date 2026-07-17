//! GOLD-ADAPT-GOOSE-02 — pluggable tool-inspection chain.
//!
//! Port of goose's `ToolInspector` trait + inspector vector
//! (`crates/goose/src/agents/tool_inspection.rs`): the pre-dispatch safety
//! checks run as an ordered chain of [`ToolInspector`]s instead of a
//! hand-wired sequence inside [`crate::mcp::dispatch_loop`]. Each inspector
//! returns a typed [`InspectorVerdict`]; the chain returns the FIRST block.
//! Unliftable guards run before the lease-liftable risk policy so an operator
//! risk lease can never bypass secret-egress or manifest-scan enforcement.
//!
//! ## Scope (deliberate, security-reviewed)
//!
//! The chain DECIDES "is this call blocked, and why" — it computes the
//! repetition verdict (GOLD-ADOPT-20), the dangerous-command/egress risk
//! verdict (GOLD-ADOPT-23), and the pre-send secret-egress verdict
//! (GOLD-ADAPT-CAF-01). It does NOT perform the NEOTH-specific
//! risk-confirm LEASE lift or the distinct WAL audit emits: those are async +
//! stateful authorization side-effects (filesystem leases, the WAL writer),
//! not a pure inspection, so they stay in the dispatch loop, driven by the
//! [`BlockKind::Risk`] payload the chain hands back. The allowlist / autonomy
//! / SmartApprove checks likewise stay in the [`crate::mcp::gate`] preflight/authorize/invoke split
//! (they need the live `McpClient`). A new PURE safety check bolts on by
//! implementing [`ToolInspector`] and pushing it into the chain.
//!
//! Package-manager command parsing and immutable install-intent binding live
//! in the sibling `package_gate` module. Its public intent types are
//! re-exported here so existing callers keep one stable inspection API.

pub use super::package_gate::{
    InstallApproval, InstallGateRequest, InstallIntent, ManifestSnapshotApproval,
    RegistryPackageRequest, UnverifiedInstallIntent,
};
#[cfg(test)]
use super::package_gate::{PackageManager, is_ambient_resolution_override, registry_request};
use super::package_gate::{ParsedInstall, parse_install, validate_approval};
use crate::config::SecurityPolicy;
use crate::mcp::repetition_guard::{GuardVerdict, ToolRepetitionGuard};
use crate::mcp::tool_call_parser::ParsedToolCall;
use crate::security::risk_gate::{RiskGate, evaluate_tool_risk};
use crate::security::secrets_scan::scan_text;
use crate::security::{ToolCallRisk, inspect_tool_args};

/// One inspector's decision for a prospective tool call.
pub enum InspectorVerdict {
    /// No objection from this inspector.
    Allow,
    /// Block the call. `inspector` names the source for logging/audit.
    Block {
        inspector: &'static str,
        kind: BlockKind,
    },
}

/// The typed payload behind a block, so the dispatch loop can act with the
/// full context the original inline code had.
pub enum BlockKind {
    /// Stuck-loop guard tripped — carries the verdict for the LLM notice.
    Repetition(GuardVerdict),
    /// Dangerous-command / egress risk gate tripped — carries the findings +
    /// the base gate so the loop can run the lease-lift + distinct WAL emit.
    Risk { risk: ToolCallRisk, gate: RiskGate },
    /// Secret / credential pattern detected in outbound tool-call arguments
    /// (GOLD-ADAPT-CAF-01). `pattern` is the regex rule name; `redacted` is
    /// the masked excerpt — safe to surface in logs and LLM error replies.
    SecretEgress {
        /// Name of the matched secret pattern (e.g. `"openai_key"`).
        pattern: &'static str,
        /// Matched value with first/last 4 chars visible, middle masked.
        redacted: String,
    },
    /// GOLD-ADAPT-SNYK-02 — package-manager calls classified by the strict
    /// parser are blocked. Only immutable, lock-backed resolution commands can
    /// earn a one-shot retry; direct fetch/mutation remains fail-closed.
    ManifestGate { request: InstallGateRequest },
}

/// A pre-dispatch safety check. `Send` so the chain can be held across the
/// dispatch loop's `.await` points.
pub trait ToolInspector: Send {
    /// Stable name for logs/audit.
    fn name(&self) -> &'static str;
    /// Judge ONE prospective call. Called exactly once per dispatch attempt
    /// (a stateful inspector, e.g. the repetition guard, records the attempt).
    fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict;
    /// Called only after every registry coordinate and manifest snapshot for
    /// one exact install intent received a conclusive policy-clean result.
    fn on_install_dependency_policy_clean(&mut self, _approval: InstallApproval) {}
    /// Revalidate and consume the one-shot permit at the final dispatch edge.
    fn consume_install_permit(&mut self, _call: &ParsedToolCall) -> Result<(), &'static str> {
        Ok(())
    }
}

/// Stuck-loop guard as an inspector (GOLD-ADOPT-20).
pub struct RepetitionInspector(pub ToolRepetitionGuard);

impl ToolInspector for RepetitionInspector {
    fn name(&self) -> &'static str {
        "repetition"
    }
    fn inspect(&mut self, call: &ParsedToolCall, _policy: &SecurityPolicy) -> InspectorVerdict {
        let v = self.0.check(call);
        if v.is_blocked() {
            InspectorVerdict::Block {
                inspector: "repetition",
                kind: BlockKind::Repetition(v),
            }
        } else {
            InspectorVerdict::Allow
        }
    }
}

/// Dangerous-command + egress risk policy as an inspector (GOLD-ADOPT-23).
/// Computes the verdict + surfaces every finding (tracing warn) exactly as the
/// pre-chain loop did; the lease-lift + WAL emits stay in the loop.
pub struct RiskPolicyInspector;

impl ToolInspector for RiskPolicyInspector {
    fn name(&self) -> &'static str {
        "risk_policy"
    }
    fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict {
        let risk = inspect_tool_args(&call.arguments);
        if risk.is_empty() {
            return InspectorVerdict::Allow;
        }
        // GOLD-ADOPT-23 P0 — ALWAYS surface dangerous + egress findings, even
        // when the policy is warn-only and the gate ends up Allow.
        for d in &risk.dangerous {
            tracing::warn!(
                server = %call.server, tool = %call.tool,
                rule = d.id, severity = d.severity.as_str(),
                "dangerous-command pattern in tool call: {}", d.reason
            );
        }
        for e in &risk.egress {
            tracing::warn!(
                server = %call.server, tool = %call.tool,
                kind = %e.kind, domain = %e.domain,
                "outbound egress destination in tool call"
            );
        }
        let gate = evaluate_tool_risk(&risk, policy);
        if gate.is_blocked() {
            InspectorVerdict::Block {
                inspector: "risk_policy",
                kind: BlockKind::Risk { risk, gate },
            }
        } else {
            InspectorVerdict::Allow
        }
    }
}

/// Pre-send credential / secret scanner (GOLD-ADAPT-CAF-01).
///
/// Serialises the full `arguments` payload to JSON text and runs
/// [`scan_text`] from [`crate::security::secrets_scan`] over it. If any
/// credential-shape regex matches, the call is blocked immediately with
/// [`BlockKind::SecretEgress`] carrying a redacted excerpt. The raw secret
/// value never appears in logs or LLM replies.
///
/// This runs BEFORE the lease-liftable risk-policy inspector. Secret
/// exfiltration is an unconditional block and must not disappear merely
/// because the same call also matches a risk rule with an operator lease.
pub struct SecretEgressInspector;

impl ToolInspector for SecretEgressInspector {
    fn name(&self) -> &'static str {
        "secret_egress"
    }

    fn inspect(&mut self, call: &ParsedToolCall, _policy: &SecurityPolicy) -> InspectorVerdict {
        // Serialise arguments to text. serde_json::to_string can only fail
        // for types with custom serialisers that return an error; Value
        // never does.
        let text = call.arguments.to_string();
        let findings = scan_text(&text);
        if let Some(f) = findings.into_iter().next() {
            tracing::warn!(
                server = %call.server,
                tool   = %call.tool,
                pattern = f.pattern,
                redacted = %f.redacted,
                "secret-egress: credential pattern in outbound tool-call arguments — call blocked"
            );
            InspectorVerdict::Block {
                inspector: "secret_egress",
                kind: BlockKind::SecretEgress {
                    pattern: f.pattern,
                    redacted: f.redacted,
                },
            }
        } else {
            InspectorVerdict::Allow
        }
    }
}

/// GOLD-ADAPT-SNYK-02 — immutable lock-backed package-manager actions are a
/// two-step operation: first attempt scans the exact transitive lock graph,
/// then one exact retry may dispatch. Direct mutation/fetch commands and
/// unresolved actions stay fail-closed. A new loop always scans again.
pub struct ManifestInstallInspector {
    approved: Option<InstallApproval>,
    ready: Option<InstallApproval>,
}

impl ManifestInstallInspector {
    pub fn new() -> Self {
        Self {
            approved: None,
            ready: None,
        }
    }
}

impl Default for ManifestInstallInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolInspector for ManifestInstallInspector {
    fn name(&self) -> &'static str {
        "manifest_install"
    }

    fn inspect(&mut self, call: &ParsedToolCall, _policy: &SecurityPolicy) -> InspectorVerdict {
        self.ready = None;
        match parse_install(call) {
            ParsedInstall::NotInstall => InspectorVerdict::Allow,
            ParsedInstall::Unverified(intent) => InspectorVerdict::Block {
                inspector: "manifest_install",
                kind: BlockKind::ManifestGate {
                    request: InstallGateRequest::Unverified(intent),
                },
            },
            ParsedInstall::Scan(intent) => {
                if let Some(approval) = self.approved.take()
                    && validate_approval(&approval, &intent).is_ok()
                {
                    self.ready = Some(approval);
                    return InspectorVerdict::Allow;
                }
                InspectorVerdict::Block {
                    inspector: "manifest_install",
                    kind: BlockKind::ManifestGate {
                        request: InstallGateRequest::Scan(Box::new(intent)),
                    },
                }
            }
        }
    }

    fn on_install_dependency_policy_clean(&mut self, approval: InstallApproval) {
        self.approved = Some(approval);
    }

    fn consume_install_permit(&mut self, call: &ParsedToolCall) -> Result<(), &'static str> {
        match parse_install(call) {
            ParsedInstall::NotInstall => Ok(()),
            ParsedInstall::Unverified(_) => Err("install_intent_became_unverified"),
            ParsedInstall::Scan(intent) => {
                let Some(approval) = self.ready.take() else {
                    return Err("install_permit_missing");
                };
                validate_approval(&approval, &intent)
            }
        }
    }
}

/// Ordered chain of inspectors. The FIRST block wins. Hard, unliftable guards
/// must precede the risk-policy inspector because the dispatch loop may lift a
/// risk block with an operator lease and then execute the call without another
/// inspection pass.
pub struct ToolInspectorChain {
    inspectors: Vec<Box<dyn ToolInspector>>,
}

impl ToolInspectorChain {
    /// The shipped chain: repetition guard + unconditional secret-egress and
    /// manifest guards + the lease-liftable risk policy last.
    pub fn with_defaults() -> Self {
        Self {
            inspectors: vec![
                Box::new(RepetitionInspector(ToolRepetitionGuard::with_defaults())),
                Box::new(SecretEgressInspector),
                Box::new(ManifestInstallInspector::new()),
                Box::new(RiskPolicyInspector),
            ],
        }
    }

    /// Build from an explicit inspector list (tests / future custom chains).
    pub fn new(inspectors: Vec<Box<dyn ToolInspector>>) -> Self {
        Self { inspectors }
    }

    /// Record one conclusive, exact-intent install approval.
    pub fn on_install_dependency_policy_clean(&mut self, approval: InstallApproval) {
        for insp in self.inspectors.iter_mut() {
            insp.on_install_dependency_policy_clean(approval.clone());
        }
    }

    /// Consume and revalidate any package-manager permit immediately before
    /// dispatch. Non-install calls are no-ops in every inspector.
    pub fn consume_install_permit(&mut self, call: &ParsedToolCall) -> Result<(), &'static str> {
        for inspector in self.inspectors.iter_mut() {
            inspector.consume_install_permit(call)?;
        }
        Ok(())
    }

    /// Run inspectors in order; return the FIRST block, else `Allow`. Every
    /// inspector up to (and including) the first blocker is run, so stateful
    /// inspectors before the blocker still record the attempt.
    pub fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict {
        for insp in self.inspectors.iter_mut() {
            match insp.inspect(call, policy) {
                InspectorVerdict::Allow => continue,
                block => return block,
            }
        }
        InspectorVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(server: &str, tool: &str, args: serde_json::Value) -> ParsedToolCall {
        ParsedToolCall {
            server: server.into(),
            tool: tool.into(),
            arguments: args,
        }
    }

    fn policy() -> SecurityPolicy {
        SecurityPolicy::default()
    }

    #[test]
    fn clean_call_passes_the_whole_chain() {
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("fs", "read", serde_json::json!({ "path": "notes.md" }));
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Allow
        ));
    }

    #[test]
    fn repetition_inspector_blocks_a_repeated_call() {
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("fs", "read", serde_json::json!({ "path": "a" }));
        // Defaults: a 4th identical call in a row blocks.
        for _ in 0..3 {
            assert!(matches!(
                chain.inspect(&c, &policy()),
                InspectorVerdict::Allow
            ));
        }
        match chain.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::Repetition(_),
            } => {
                assert_eq!(inspector, "repetition")
            }
            _ => panic!("expected a repetition block on the 4th identical call"),
        }
    }

    #[test]
    fn risk_inspector_blocks_a_dangerous_command_under_default_deny() {
        let mut chain = ToolInspectorChain::with_defaults();
        // The default dangerous-command policy is Deny.
        let c = call("sh", "exec", serde_json::json!({ "command": "rm -rf /" }));
        match chain.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::Risk { gate, .. },
            } => {
                assert_eq!(inspector, "risk_policy");
                assert!(gate.is_blocked());
            }
            _ => panic!("expected a risk block for a dangerous command"),
        }
    }

    #[test]
    fn repetition_is_checked_before_risk() {
        // A call that is BOTH repeated past the threshold AND dangerous must
        // surface as a Repetition block (repetition runs first), never Risk.
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("sh", "exec", serde_json::json!({ "command": "rm -rf /" }));
        // First three are risk-blocks (dangerous), but they also tick the
        // repetition counter; the 4th identical call trips repetition first.
        for _ in 0..3 {
            assert!(matches!(
                chain.inspect(&c, &policy()),
                InspectorVerdict::Block {
                    kind: BlockKind::Risk { .. },
                    ..
                }
            ));
        }
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Block {
                kind: BlockKind::Repetition(_),
                ..
            }
        ));
    }

    #[test]
    fn unconditional_secret_guard_precedes_lease_liftable_risk() {
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call(
            "sh",
            "exec",
            serde_json::json!({
                "command": "rm -rf /",
                "token": "sk-testFAKEkey1234567890ABCDEFGHIJ"
            }),
        );
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Block {
                inspector: "secret_egress",
                kind: BlockKind::SecretEgress { .. },
            }
        ));
    }

    #[test]
    fn manifest_guard_precedes_lease_liftable_risk() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        std::fs::write(&manifest, "{\"dependencies\":{\"serde\":\"1\"}}").unwrap();
        let manifest = manifest.to_string_lossy().into_owned();
        let mut chain = ToolInspectorChain::with_defaults();
        let edit = call(
            "fs",
            "write_file",
            serde_json::json!({ "path": &manifest, "content": "{}" }),
        );
        assert!(matches!(
            chain.inspect(&edit, &policy()),
            InspectorVerdict::Allow
        ));
        let risky_install = call(
            "sh",
            "exec",
            serde_json::json!({ "command": "npm install && rm -rf /" }),
        );
        assert!(matches!(
            chain.inspect(&risky_install, &policy()),
            InspectorVerdict::Block {
                inspector: "manifest_install",
                kind: BlockKind::ManifestGate { .. },
            }
        ));
    }

    #[test]
    fn custom_pure_inspector_bolts_on_without_a_loop_edit() {
        // Demonstrates the extensibility seam: a new inspector just implements
        // the trait + joins the chain; the dispatch loop never changes.
        struct DenyAll;
        impl ToolInspector for DenyAll {
            fn name(&self) -> &'static str {
                "deny_all"
            }
            fn inspect(&mut self, _c: &ParsedToolCall, _p: &SecurityPolicy) -> InspectorVerdict {
                InspectorVerdict::Block {
                    inspector: "deny_all",
                    kind: BlockKind::Repetition(GuardVerdict::Allow),
                }
            }
        }
        let mut chain = ToolInspectorChain::new(vec![Box::new(DenyAll)]);
        let c = call("fs", "read", serde_json::json!({}));
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Block {
                inspector: "deny_all",
                ..
            }
        ));
    }

    // ── GOLD-ADAPT-CAF-01: SecretEgressInspector ─────────────────────────────

    #[test]
    fn secret_egress_blocks_openai_key_in_payload() {
        // A fetch/http tool whose body carries a fake OpenAI key must be
        // blocked before dispatch. The key matches the `openai_key` pattern
        // (sk- prefix, ≥20 alphanum chars).
        let mut insp = SecretEgressInspector;
        let c = call(
            "http",
            "fetch",
            serde_json::json!({
                "url": "https://example.com/api",
                "headers": { "Authorization": "Bearer sk-testFAKEkey1234567890ABCDEFGHIJ" }
            }),
        );
        match insp.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::SecretEgress { pattern, redacted },
            } => {
                assert_eq!(inspector, "secret_egress");
                assert_eq!(pattern, "openai_key");
                // Redacted must not contain the full secret (first 4 + last 4
                // visible; middle masked). The full key is 30+ chars so the
                // redacted form must include the masking ellipsis.
                assert!(
                    redacted.contains('…'),
                    "expected masked redaction, got: {redacted}"
                );
            }
            _ => panic!("expected secret_egress block for payload containing an OpenAI key"),
        }
    }

    #[test]
    fn secret_egress_blocks_aws_access_key_in_payload() {
        // AWS access key IDs follow the AKIA[0-9A-Z]{16} shape.
        let mut insp = SecretEgressInspector;
        let c = call(
            "channel",
            "send",
            serde_json::json!({
                "body": "My key is AKIAIOSFODNN7EXAMPLE and I need help"
            }),
        );
        match insp.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::SecretEgress { pattern, .. },
            } => {
                assert_eq!(inspector, "secret_egress");
                assert_eq!(pattern, "aws_access_key_id");
            }
            _ => panic!("expected secret_egress block for payload containing an AWS key"),
        }
    }

    #[test]
    fn secret_egress_allows_clean_payload() {
        // A normal tool call with no credential-shaped values must pass.
        let mut insp = SecretEgressInspector;
        let c = call(
            "fs",
            "read_file",
            serde_json::json!({ "path": "/home/user/notes.md" }),
        );
        assert!(
            matches!(insp.inspect(&c, &policy()), InspectorVerdict::Allow),
            "clean payload must not be blocked by secret_egress inspector"
        );
    }

    // ── GOLD-ADAPT-SNYK-02: ManifestInstallInspector ─────────────────────────

    fn scan_intent(insp: &mut ManifestInstallInspector, install: &ParsedToolCall) -> InstallIntent {
        match insp.inspect(install, &policy()) {
            InspectorVerdict::Block {
                inspector: "manifest_install",
                kind:
                    BlockKind::ManifestGate {
                        request: InstallGateRequest::Scan(intent),
                    },
            } => *intent,
            _ => panic!("expected exact install scan request"),
        }
    }

    fn unverified_code(
        insp: &mut ManifestInstallInspector,
        install: &ParsedToolCall,
    ) -> &'static str {
        match insp.inspect(install, &policy()) {
            InspectorVerdict::Block {
                inspector: "manifest_install",
                kind:
                    BlockKind::ManifestGate {
                        request: InstallGateRequest::Unverified(intent),
                    },
            } => intent.code,
            _ => panic!("expected fail-closed package-manager request"),
        }
    }

    fn approval_for(intent: &InstallIntent) -> InstallApproval {
        InstallApproval {
            binding_sha256: intent.binding_sha256.clone(),
            manifests: intent
                .manifests
                .iter()
                .map(|path| ManifestSnapshotApproval {
                    path: path.clone(),
                    sha256: crate::security::dep_health::manifest_sha256(std::path::Path::new(
                        path,
                    ))
                    .unwrap(),
                })
                .collect(),
        }
    }

    fn write_npm_locked_project(dir: &std::path::Path) {
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"^1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
                "name":"fixture",
                "version":"1.0.0",
                "lockfileVersion":3,
                "packages":{
                    "":{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"^1.0.0"}},
                    "node_modules/left-pad":{
                        "version":"1.3.0",
                        "resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                        "integrity":"sha512-fixture"
                    }
                }
            }"#,
        )
        .unwrap();
    }

    fn write_js_locked_project(dir: &std::path::Path, manager: PackageManager) {
        if manager == PackageManager::Npm {
            write_npm_locked_project(dir);
            return;
        }
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"^1.0.0"}}"#,
        )
        .unwrap();
        let (name, body) = match manager {
            PackageManager::Yarn => (
                "yarn.lock",
                r#"left-pad@^1.0.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"
  integrity sha512-Zml4dHVyZQ==
"#,
            ),
            PackageManager::Pnpm => (
                "pnpm-lock.yaml",
                r#"lockfileVersion: '9.0'
packages:
  left-pad@1.3.0:
    resolution:
      integrity: sha512-Zml4dHVyZQ==
"#,
            ),
            PackageManager::Bun => (
                "bun.lock",
                r#"{
  "lockfileVersion": 1,
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-Zml4dHVyZQ=="],
  },
}
"#,
            ),
            _ => panic!("not a JavaScript lockfile manager"),
        };
        std::fs::write(dir.join(name), body).unwrap();
    }

    fn write_cargo_locked_project(dir: &std::path::Path) {
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n[dependencies]\nserde='1'\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("Cargo.lock"),
            r#"version = 4

[[package]]
name = "fixture"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fixture"
"#,
        )
        .unwrap();
    }

    /// Package-manager policy intentionally observes the real process
    /// environment. CI runners commonly inject registry variables (notably
    /// `NPM_CONFIG_REGISTRY` on Windows), so tests for a different rejection
    /// reason must run in an isolated home with those ambient overrides removed.
    /// The crate-wide lock keeps this process-global mutation race-free.
    struct IsolatedPackageManagerEnv {
        saved: Vec<(std::ffi::OsString, Option<std::ffi::OsString>)>,
        _home: tempfile::TempDir,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl IsolatedPackageManagerEnv {
        fn new() -> Self {
            let lock = crate::test_env::lock();
            let home = tempfile::tempdir().expect("isolated package-manager home");
            let managers = [
                PackageManager::Npm,
                PackageManager::Yarn,
                PackageManager::Pnpm,
                PackageManager::Bun,
                PackageManager::Cargo,
                PackageManager::Pip,
                PackageManager::Pipenv,
                PackageManager::Uv,
                PackageManager::Poetry,
                PackageManager::Go,
            ];
            let mut keys = std::env::vars_os()
                .filter_map(|(key, _)| {
                    let text = key.to_string_lossy();
                    managers
                        .iter()
                        .any(|manager| is_ambient_resolution_override(*manager, &text))
                        .then_some(key)
                })
                .collect::<std::collections::BTreeSet<_>>();
            keys.extend(
                [
                    "HOME",
                    "USERPROFILE",
                    "CARGO_HOME",
                    "NPM_CONFIG_REGISTRY",
                    "NPM_CONFIG_USERCONFIG",
                    "NPM_CONFIG_PREFIX",
                    "NPM_CONFIG_GLOBAL",
                    "NPM_CONFIG_WORKSPACE",
                    "NPM_CONFIG_WORKSPACES",
                    "YARN_NPM_REGISTRY_SERVER",
                    "YARN_RC_FILENAME",
                    "COREPACK_NPM_REGISTRY",
                    "CARGO_REGISTRY_DEFAULT",
                    "PIP_CONFIG_FILE",
                    "PIP_INDEX_URL",
                    "PIP_EXTRA_INDEX_URL",
                    "PIP_FIND_LINKS",
                    "PIPENV_PYPI_MIRROR",
                    "PIPENV_PIPFILE",
                    "UV_CONFIG_FILE",
                    "UV_DEFAULT_INDEX",
                    "UV_INDEX_URL",
                    "UV_EXTRA_INDEX_URL",
                    "UV_FIND_LINKS",
                    "POETRY_REPOSITORIES",
                    "GOPROXY",
                    "GONOPROXY",
                    "GOPRIVATE",
                    "GONOSUMDB",
                    "GOSUMDB",
                    "GOENV",
                    "GOWORK",
                ]
                .into_iter()
                .map(std::ffi::OsString::from),
            );

            let mut saved = Vec::with_capacity(keys.len());
            for key in keys {
                saved.push((key.clone(), std::env::var_os(&key)));
                // SAFETY: every test that reads or mutates these variables uses
                // the crate-wide test_env lock, held by this guard until Drop.
                unsafe { std::env::remove_var(&key) };
            }
            for key in ["HOME", "USERPROFILE", "CARGO_HOME"] {
                // SAFETY: serialized by the same crate-wide lock above.
                unsafe { std::env::set_var(key, home.path()) };
            }

            Self {
                saved,
                _home: home,
                _lock: lock,
            }
        }
    }

    impl Drop for IsolatedPackageManagerEnv {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..).rev() {
                // SAFETY: the crate-wide lock remains held until after this
                // Drop implementation restores the original environment.
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    #[test]
    fn exact_coordinate_parsers_are_ecosystem_specific() {
        let npm = registry_request(PackageManager::Npm, "left-pad@1.3.0").unwrap();
        assert_eq!(npm.version.as_deref(), Some("1.3.0"));
        assert!(registry_request(PackageManager::Npm, "left-pad@1.x").is_err());
        assert!(registry_request(PackageManager::Npm, "left-pad@1.latest").is_err());

        for version in ["1.0", "2024.1", "1!2.0", "2.0rc1"] {
            let request =
                registry_request(PackageManager::Pip, &format!("package=={version}")).unwrap();
            assert_eq!(request.version.as_deref(), Some(version));
        }
        assert!(registry_request(PackageManager::Pip, "package==1.*").is_err());
    }

    #[test]
    fn direct_mutations_and_fetch_runners_fail_closed_without_transitive_resolution() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        std::fs::create_dir(&app).unwrap();
        std::fs::write(app.join("package.json"), "{\"dependencies\":{}}\n").unwrap();
        std::fs::write(
            app.join("Cargo.toml"),
            "[package]\nname='x'\nversion='0.1.0'\n",
        )
        .unwrap();
        let cases = [
            ("npm --prefix app install left-pad@1.3.0", dir.path()),
            ("pnpm -C app add left-pad@1.3.0", dir.path()),
            ("cargo +nightly add serde@1.0.228", app.as_path()),
            ("python -m pip install requests==2.32.0", app.as_path()),
            ("npm exec --package runner@1.2.3 -- runner", app.as_path()),
            ("npx runner@1.2.3", app.as_path()),
            ("pnpm dlx runner@1.2.3", app.as_path()),
            ("bunx runner@1.2.3", app.as_path()),
            ("uvx runner==1.0", app.as_path()),
            ("pipx run runner==1.0", app.as_path()),
            ("pipx install runner==1.0", app.as_path()),
            ("go install example.com/runner@v1.2.3", app.as_path()),
            ("go run example.com/runner@v1.2.3", app.as_path()),
        ];
        for (command, cwd) in cases {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": cwd}),
            );
            assert_eq!(
                unverified_code(&mut insp, &install),
                "transitive_resolution_unproven",
                "{command}"
            );
        }
    }

    #[test]
    fn ranged_sources_with_exact_locks_get_one_shot_permits() {
        let _env = IsolatedPackageManagerEnv::new();
        let npm = tempfile::tempdir().unwrap();
        write_npm_locked_project(npm.path());
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci --ignore-scripts", "cwd": npm.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &npm_ci);
        assert_eq!(intent.manifests.len(), 2);
        assert_eq!(intent.resolution_locks.len(), 1);
        assert!(intent.resolution_locks[0].ends_with("package-lock.json"));
        insp.on_install_dependency_policy_clean(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&npm_ci, &policy()),
            InspectorVerdict::Allow
        ));
        assert!(insp.consume_install_permit(&npm_ci).is_ok());

        let cargo = tempfile::tempdir().unwrap();
        write_cargo_locked_project(cargo.path());
        let cargo_check = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo check --locked", "cwd": cargo.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &cargo_check);
        assert_eq!(intent.manifests.len(), 2);
        assert_eq!(intent.resolution_locks.len(), 1);
        assert!(intent.resolution_locks[0].ends_with("Cargo.lock"));
        insp.on_install_dependency_policy_clean(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&cargo_check, &policy()),
            InspectorVerdict::Allow
        ));
        assert!(insp.consume_install_permit(&cargo_check).is_ok());
    }

    #[test]
    fn javascript_lockfile_installs_with_ignore_scripts_are_scan_eligible() {
        let _env = IsolatedPackageManagerEnv::new();
        for (manager, command, expected_manager, expected_lock) in [
            (
                PackageManager::Npm,
                "npm ci --ignore-scripts",
                "npm",
                "package-lock.json",
            ),
            (
                PackageManager::Pnpm,
                "pnpm install --frozen-lockfile --ignore-scripts",
                "pnpm",
                "pnpm-lock.yaml",
            ),
            (
                PackageManager::Yarn,
                "yarn install --immutable --ignore-scripts",
                "yarn",
                "yarn.lock",
            ),
            (
                PackageManager::Bun,
                "bun install --frozen-lockfile --ignore-scripts",
                "bun",
                "bun.lock",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            write_js_locked_project(dir.path(), manager);
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            let mut inspector = ManifestInstallInspector::new();
            let intent = scan_intent(&mut inspector, &install);
            assert_eq!(intent.manager, expected_manager, "{command}");
            assert_eq!(intent.resolution_locks.len(), 1, "{command}");
            assert!(
                intent.resolution_locks[0].ends_with(expected_lock),
                "{command}"
            );
        }
    }

    #[test]
    fn javascript_lockfile_installs_without_ignore_scripts_fail_closed() {
        let _env = IsolatedPackageManagerEnv::new();
        for (manager, command) in [
            (PackageManager::Npm, "npm ci"),
            (PackageManager::Pnpm, "pnpm install --frozen-lockfile"),
            (PackageManager::Yarn, "yarn install --immutable"),
            (PackageManager::Bun, "bun install --frozen-lockfile"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            write_js_locked_project(dir.path(), manager);
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            let mut inspector = ManifestInstallInspector::new();
            assert_eq!(
                unverified_code(&mut inspector, &install),
                "lifecycle_scripts_not_disabled",
                "{command}"
            );
        }
    }

    #[test]
    fn binary_bun_lockfile_fails_closed_with_a_stable_code() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{\"dependencies\":{}}\n").unwrap();
        std::fs::write(dir.path().join("bun.lockb"), [0_u8, 0xff, 0x10]).unwrap();
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({
                "command": "bun install --frozen-lockfile --ignore-scripts",
                "cwd": dir.path()
            }),
        );
        let mut inspector = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut inspector, &install),
            "binary_bun_lockfile_unsupported"
        );
    }

    #[test]
    fn ranges_without_the_expected_lock_and_unpinned_fetchers_fail_closed() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"left-pad":"^1.0.0"}}"#,
        )
        .unwrap();
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci --ignore-scripts", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &npm_ci),
            "required_lockfile_missing"
        );

        for command in [
            "npm exec --package runner@1 -- runner",
            "npx runner@1.x",
            "pnpm dlx runner@1.latest",
            "bunx runner@1",
            "uvx runner==1.*",
            "pipx run runner",
            "pipx install runner",
            "go install example.com/runner@v1",
            "go run example.com/runner@latest",
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            let code = unverified_code(&mut insp, &install);
            if command == "uvx runner==1.*" {
                assert_eq!(code, "shell_expansion_unsupported", "{command}");
            } else {
                assert!(
                    code.contains("exact_registry_version"),
                    "{command} must fail closed"
                );
            }
        }
    }

    #[test]
    fn common_manifest_install_commands_never_bypass_the_gate() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        for command in [
            "npm i",
            "npm ci",
            "pipenv install",
            "poetry install",
            "go get",
            "go install",
            "go mod download",
        ] {
            let mut inspector = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            assert!(
                matches!(
                    inspector.inspect(&install, &policy()),
                    InspectorVerdict::Block {
                        inspector: "manifest_install",
                        kind: BlockKind::ManifestGate { .. },
                    }
                ),
                "{command} must be recognized and fail closed"
            );
        }
    }

    #[test]
    fn windows_launcher_suffixes_and_paths_never_bypass_the_gate() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        for command in [
            "npm.cmd ci",
            "NPM.EXE ci",
            r#"C:\tools\nodejs\npm.cmd ci"#,
            r#"C:\tools\nodejs\NPM.BAT ci"#,
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            let intent = scan_intent(&mut insp, &install);
            assert_eq!(intent.manager, "npm", "{command}");
            assert_eq!(intent.operation, "ci", "{command}");
        }
    }

    #[test]
    fn shell_expansions_and_global_install_contexts_fail_closed() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        for command in [
            "npm ci --flag=$EVIL",
            "npm ci --flag=%EVIL%",
            "npm ci --flag=!EVIL!",
            "npm ci ^--ignore-scripts",
            "npm ci --workspace=*",
            "npm ci --workspace=?",
            "npm ci --workspace={a,b}",
            "npm ci --workspace=[ab]",
            "npm ci --prefix ~/app",
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            assert_eq!(
                unverified_code(&mut insp, &install),
                "shell_expansion_unsupported",
                "{command}"
            );
        }

        for command in [
            "npm -g ci",
            "npm ci --global",
            "npm ci --global=true",
            "npm ci --location=global",
            "npm ci --location GLOBAL",
            "pnpm install --global-dir global --frozen-lockfile",
            "bun install -g",
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            assert_eq!(
                unverified_code(&mut insp, &install),
                "unsupported_global_install_context",
                "{command}"
            );
        }
    }

    #[test]
    fn unrecognized_command_fields_with_package_manager_text_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut insp = ManifestInstallInspector::new();
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"shell_command": "npm ci", "cwd": dir.path()}),
        );
        assert_eq!(
            unverified_code(&mut insp, &install),
            "command_field_unrecognized"
        );
    }

    #[test]
    fn ambient_configs_and_parent_workspaces_fail_closed() {
        let _env = IsolatedPackageManagerEnv::new();
        let npm_root = tempfile::tempdir().unwrap();
        let npm_child = npm_root.path().join("packages").join("child");
        std::fs::create_dir_all(&npm_child).unwrap();
        write_npm_locked_project(&npm_child);
        std::fs::write(
            npm_root.path().join("package.json"),
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": &npm_child}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &npm_ci),
            "ambient_workspace_context"
        );

        let cargo_root = tempfile::tempdir().unwrap();
        let cargo_child = cargo_root.path().join("member");
        std::fs::create_dir(&cargo_child).unwrap();
        write_cargo_locked_project(&cargo_child);
        std::fs::write(
            cargo_root.path().join("Cargo.toml"),
            "[workspace]\nmembers=['member']\n",
        )
        .unwrap();
        let cargo_check = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo check --locked", "cwd": &cargo_child}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &cargo_check),
            "ambient_workspace_context"
        );

        let config_dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(config_dir.path());
        std::fs::write(
            config_dir.path().join(".npmrc"),
            "registry=https://example.invalid/\n",
        )
        .unwrap();
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": config_dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &npm_ci),
            "ambient_package_manager_config"
        );
    }

    #[test]
    fn ambient_registry_environment_override_still_fails_closed() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        // SAFETY: IsolatedPackageManagerEnv holds the crate-wide environment
        // lock and restores the runner's original value when it is dropped.
        unsafe {
            std::env::set_var("NPM_CONFIG_REGISTRY", "https://example.invalid/");
        }
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &npm_ci),
            "ambient_registry_override"
        );
    }

    #[test]
    fn missing_cwd_combined_remote_and_non_registry_forms_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        for arguments in [
            serde_json::json!({"command": "npm install left-pad"}),
            serde_json::json!({"command": "npm install left-pad", "cwd": dir.path()}),
            serde_json::json!({"command": "npm install left-pad@latest", "cwd": dir.path()}),
            serde_json::json!({"command": "cargo add left-pad@latest", "cwd": dir.path()}),
            serde_json::json!({"command": "go get example.com/mod@latest", "cwd": dir.path()}),
            serde_json::json!({"command": "ssh host npm install left-pad", "cwd": dir.path()}),
            serde_json::json!({"command": "npm install ok && npm install evil", "cwd": dir.path()}),
            serde_json::json!({"command": "pip install git+https://example.invalid/x", "cwd": dir.path()}),
            serde_json::json!({"command": "NPM_CONFIG_REGISTRY=https://example.invalid npm install x@1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "npm --userconfig customrc install x@1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "cargo --config net.git-fetch-with-cli=true add x@1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "pip install -c constraints.txt x==1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "cargo build -p member", "cwd": dir.path()}),
            serde_json::json!({"command": "cargo check --locked", "cwd": dir.path(), "env": {"CARGO_REGISTRY_DEFAULT": "evil"}}),
            serde_json::json!({"command": "npm install x@1.0.0", "cmd": "npm install y@1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "npm install x@1.0.0", "cwd": dir.path(), "workdir": dir.path()}),
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call("shell", "exec", arguments);
            assert!(matches!(
                insp.inspect(&install, &policy()),
                InspectorVerdict::Block {
                    kind: BlockKind::ManifestGate {
                        request: InstallGateRequest::Unverified(_),
                    },
                    ..
                }
            ));
        }
    }

    #[test]
    fn approval_is_one_shot_and_bound_to_the_full_exact_intent() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        write_cargo_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo check --locked", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        insp.on_install_dependency_policy_clean(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Allow
        ));
        assert!(insp.consume_install_permit(&install).is_ok());
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Block {
                kind: BlockKind::ManifestGate { .. },
                ..
            }
        ));

        let other_dir = tempfile::tempdir().unwrap();
        write_cargo_locked_project(other_dir.path());
        let mut changed_server = install.clone();
        changed_server.server = "other-shell".into();
        let mut changed_tool = install.clone();
        changed_tool.tool = "run".into();
        let changed_command = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo build --locked", "cwd": dir.path()}),
        );
        let changed_target = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo check --locked", "cwd": other_dir.path()}),
        );
        // Same parsed command and cwd, but different MCP argument keys. This
        // proves the binding covers the complete argument object, not only the
        // parser's normalized values.
        let changed_argument_shape = call(
            "local-shell",
            "exec",
            serde_json::json!({"cmd": "cargo check --locked", "directory": dir.path()}),
        );
        for changed in [
            changed_server,
            changed_tool,
            changed_command,
            changed_target,
            changed_argument_shape,
        ] {
            let mut binding_insp = ManifestInstallInspector::new();
            let intent = scan_intent(&mut binding_insp, &install);
            binding_insp.on_install_dependency_policy_clean(approval_for(&intent));
            assert!(matches!(
                binding_insp.inspect(&changed, &policy()),
                InspectorVerdict::Block {
                    kind: BlockKind::ManifestGate {
                        request: InstallGateRequest::Scan(_),
                    },
                    ..
                }
            ));
        }
    }

    #[test]
    fn final_dispatch_rehash_rejects_post_inspection_manifest_swap() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        write_npm_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci --ignore-scripts", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        insp.on_install_dependency_policy_clean(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Allow
        ));
        std::fs::write(
            &manifest,
            r#"{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"^2.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(
            insp.consume_install_permit(&install),
            Err("manifest_changed_after_approval")
        );
    }

    #[test]
    fn newly_created_lockfile_invalidates_the_approved_manifest_set() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci --ignore-scripts", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        assert_eq!(intent.manifests.len(), 2);
        insp.on_install_dependency_policy_clean(approval_for(&intent));
        std::fs::copy(
            dir.path().join("package-lock.json"),
            dir.path().join("npm-shrinkwrap.json"),
        )
        .unwrap();
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Block {
                kind: BlockKind::ManifestGate {
                    request: InstallGateRequest::Scan(_),
                },
                ..
            }
        ));
    }

    #[test]
    fn final_dispatch_rejects_a_lockfile_created_after_inspection() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci --ignore-scripts", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        insp.on_install_dependency_policy_clean(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Allow
        ));
        std::fs::copy(
            dir.path().join("package-lock.json"),
            dir.path().join("npm-shrinkwrap.json"),
        )
        .unwrap();
        assert_eq!(
            insp.consume_install_permit(&install),
            Err("install_permit_manifest_set_mismatch")
        );
    }

    #[test]
    fn final_dispatch_rehash_rejects_post_inspection_lock_swap() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci --ignore-scripts", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        insp.on_install_dependency_policy_clean(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Allow
        ));
        let lock = dir.path().join("package-lock.json");
        let mut body = std::fs::read_to_string(&lock).unwrap();
        body.push('\n');
        std::fs::write(lock, body).unwrap();
        assert_eq!(
            insp.consume_install_permit(&install),
            Err("manifest_changed_after_approval")
        );
    }

    #[test]
    fn bare_yarn_frozen_lockfile_is_a_manifest_install() {
        let _env = IsolatedPackageManagerEnv::new();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{\"dependencies\":{}}\n").unwrap();
        std::fs::write(dir.path().join("yarn.lock"), "# empty lock\n").unwrap();
        let mut insp = ManifestInstallInspector::new();
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "yarn --frozen-lockfile --ignore-scripts", "cwd": dir.path()}),
        );
        let intent = scan_intent(&mut insp, &install);
        assert_eq!(intent.manager, "yarn");
        assert_eq!(intent.operation, "install");
        assert_eq!(intent.manifests.len(), 2);
        assert_eq!(intent.resolution_locks.len(), 1);
    }

    #[test]
    fn non_package_manager_call_still_allows() {
        let dir = tempfile::tempdir().unwrap();
        let mut insp = ManifestInstallInspector::new();
        let call = call(
            "shell",
            "exec",
            serde_json::json!({"command": "git status", "cwd": dir.path()}),
        );
        assert!(matches!(
            insp.inspect(&call, &policy()),
            InspectorVerdict::Allow
        ));
        assert!(insp.consume_install_permit(&call).is_ok());
    }
}
