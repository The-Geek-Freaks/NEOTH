//! Computer-use — NEOTH's first-class desktop-control capability.
//!
//! Backed by trycua's **cua-driver** (background computer-use over MCP/stdio on
//! macOS + Windows; Linux pre-release): agents click, type, and verify native
//! desktop apps WITHOUT stealing the cursor/focus.
//!
//! NEOTH owns it as a KNOWN MCP server. Once enabled (`neoth computer-use
//! enable`), the cua-driver tools (screenshot / click / type / …) flow through
//! NEOTH's existing MCP machinery, so every computer-use action is:
//!   - **autonomy-gated** — `permissions::evaluate(McpToolInvocation, autonomy)`
//!     (`mcp/gate.rs`) decides Allow / Confirm / Deny per call;
//!   - **WAL-audited** — a `0xC0` MCP-invocation frame per call;
//!   - **allowlisted** — secure-by-default: only the pinned computer-use verbs
//!     can fire, never the server's full catalogue.
//!
//! Self-contained per the wizard-installs rule: cua-driver is an external binary
//! NEOTH installs + drives (like claude-cli / node), not an embedded service.

use crate::mcp::config::McpServerConfig;

/// Stable id for the cua-driver MCP server in `mcp_servers.yaml`.
pub const CUA_DRIVER_SERVER_ID: &str = "cua-driver";

/// The cua-driver computer-use tool verbs, pinned as the server `allow_tools`
/// allowlist. Secure-by-default: `trust_all_tools` stays `false`, so ONLY these
/// can be invoked even if the driver advertises more. Re-pin via
/// `neoth mcp list-tools --server cua-driver` if the installed version differs.
pub const COMPUTER_USE_TOOLS: &[&str] = &[
    "screenshot",
    "click",
    "double_click",
    "right_click",
    "move",
    "drag",
    "scroll",
    "type",
    "key",
    "get_windows",
    "wait",
];

/// The canonical cua-driver MCP server config — `cua-driver mcp` over stdio,
/// secure-by-default (pinned allowlist, no blanket trust).
pub fn cua_driver_server() -> McpServerConfig {
    McpServerConfig {
        id: CUA_DRIVER_SERVER_ID.to_string(),
        description: Some(
            "trycua cua-driver — background desktop computer-use (MCP/stdio)".to_string(),
        ),
        command: "cua-driver".to_string(),
        args: vec!["mcp".to_string()],
        env: std::collections::HashMap::new(),
        enabled: true,
        allow_tools: Some(COMPUTER_USE_TOOLS.iter().map(|s| s.to_string()).collect()),
        trust_all_tools: false,
        smart_approve: false,
    }
}

/// Platform install one-liner for cua-driver (operator runs it in a shell —
/// NEOTH never auto-pipes a remote script to a shell).
pub fn install_command() -> &'static str {
    if cfg!(target_os = "windows") {
        "irm https://raw.githubusercontent.com/trycua/cua/main/libs/cua-driver/scripts/install.ps1 | iex"
    } else {
        "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/trycua/cua/main/libs/cua-driver/scripts/install.sh)\""
    }
}

/// Installed cua-driver version (first line of `cua-driver --version`), or
/// `None` if it isn't on PATH / the probe fails. Used by `computer-use doctor`
/// to detect a driver upgrade that may have changed the tool set.
pub fn cua_driver_version() -> Option<String> {
    let out = std::process::Command::new("cua-driver")
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.to_string())
}

/// Is `cua-driver` on `PATH`? Pure PATH scan — no subprocess.
pub fn is_installed() -> bool {
    let exe = if cfg!(target_os = "windows") {
        "cua-driver.exe"
    } else {
        "cua-driver"
    };
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(exe).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cua_driver_server_is_secure_by_default() {
        let s = cua_driver_server();
        assert_eq!(s.id, CUA_DRIVER_SERVER_ID);
        assert_eq!(s.command, "cua-driver");
        assert_eq!(s.args, vec!["mcp".to_string()]);
        assert!(s.enabled);
        // secure-by-default: never trust the full catalogue; pin the verbs.
        assert!(!s.trust_all_tools);
        assert!(!s.smart_approve);
        let allow = s.allow_tools.expect("allowlist pinned");
        assert!(allow.contains(&"screenshot".to_string()));
        assert!(allow.contains(&"click".to_string()));
        assert!(allow.contains(&"type".to_string()));
        assert_eq!(allow.len(), COMPUTER_USE_TOOLS.len());
    }

    #[test]
    fn install_command_is_platform_specific() {
        let c = install_command();
        assert!(c.contains("trycua/cua"));
        if cfg!(target_os = "windows") {
            assert!(c.contains("install.ps1"));
        } else {
            assert!(c.contains("install.sh"));
        }
    }
}
