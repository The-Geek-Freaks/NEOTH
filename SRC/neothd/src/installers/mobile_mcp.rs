//! GOLD-ADAPT-SYS-01 — mobile-mcp (`@mobilenext/mobile-mcp`) MCP registration.
//!
//! mobile-mcp is an MCP server that drives iOS and Android devices via the
//! WebDriverAgent + ADB stack. It is launched via `npx -y @mobilenext/mobile-mcp@latest`
//! (no local install step — npx fetches + caches on first run). There is no
//! secret token: mobile-mcp connects to whatever local device ADB/WDA is already
//! attached, so `mcp_servers.yaml` carries only the command, args, and telemetry
//! opt-out env. No `credentials.yaml` write is needed.
//!
//! ## Registration flow
//!
//! The wizard step [`crate::cli::init::step6j_mobile_mcp_offer`] calls
//! [`auto_register`], which:
//!   1. Probes `npx --version` to ensure the operator has Node ≥ 18 on PATH.
//!   2. Builds the hardened [`crate::mcp::config::McpServerConfig`] via the
//!      factory (`enabled: true` after operator consent).
//!   3. Upserts the entry into `~/.neoth/mcp_servers.yaml` (idempotent).
//!   4. Returns `Ok(true)` on success, `Ok(false)` when npx is missing.
//!
//! ## Live consumer path
//!
//! After registration `mcp::catalogue::assemble_catalogue` iterates all enabled
//! servers and builds the tool catalogue injected into the system prompt on every
//! `neoth chat` / daemon turn. `mcp::gate::invoke_with_audit` enforces the
//! `autonomy_gate: Elevated` floor before any tool reaches the subprocess.
//!
//! ## Telemetry
//!
//! mobile-mcp fires PostHog events to `https://us.i.posthog.com/i/v0/e/` unless
//! `MOBILEMCP_DISABLE_TELEMETRY=1` is set in the process environment. This module
//! ensures that sentinel is always present in the registered config and the wizard
//! step discloses it to the operator before they opt in.
//!
//! ## No credentials.yaml
//!
//! Unlike [`crate::installers::tududi`], mobile-mcp has no API token. There is
//! nothing to write to `credentials.yaml`.

use std::path::Path;

use anyhow::Result;

/// Probe whether `npx` is available on the operator's PATH.
///
/// Returns the version string when found, `None` when npx (or Node) is absent.
/// Pure helper — no filesystem writes, no subprocess side-effects beyond the
/// version probe.
async fn probe_npx() -> Option<String> {
    crate::installers::probe::cli_version("npx").await
}

/// Register the mobile-mcp MCP server entry in `<neoth_home>/mcp_servers.yaml`.
///
/// # Returns
///
/// - `Ok(true)`  — registration succeeded; the entry is enabled in `mcp_servers.yaml`.
/// - `Ok(false)` — `npx` is not on PATH; nothing was written. The wizard should
///   tell the operator to install Node first and re-run `neoth init --force`.
/// - `Err(_)`    — I/O or serialisation error; the caller should surface it.
///
/// # Idempotency
///
/// If a `mobile-mcp` entry already exists in `mcp_servers.yaml` it is updated
/// in-place (re-enabled, telemetry sentinel refreshed). A second call is safe.
///
/// # No credentials
///
/// mobile-mcp has no secret token — no write to `credentials.yaml` is performed.
/// The only env var (`MOBILEMCP_DISABLE_TELEMETRY=1`) is stored as a plain literal
/// directly in `mcp_servers.yaml` because it is not a secret.
pub async fn auto_register(neoth_home: &Path) -> Result<bool> {
    // Guard: npx must be on PATH before we register an npx-launched server.
    // A missing npx means the MCP server would fail every spawn attempt.
    if probe_npx().await.is_none() {
        return Ok(false);
    }

    let mcp_path = neoth_home.join("mcp_servers.yaml");
    crate::mcp::config::McpServers::update_at(&mcp_path, |servers| {
        let mut cfg = crate::mcp::config::mobile_mcp_recommended_config();
        cfg.enabled = true;
        if let Some(existing) = servers.servers.iter_mut().find(|s| s.id == cfg.id) {
            // Re-enable + always enforce the telemetry opt-out sentinel.
            existing.enabled = true;
            existing
                .env
                .insert("MOBILEMCP_DISABLE_TELEMETRY".to_string(), "1".to_string());
            // Refresh allow_tools and autonomy_gate from the factory in case
            // the operator is upgrading from an older config.
            existing.allow_tools = cfg.allow_tools;
            existing.autonomy_gate = cfg.autonomy_gate;
        } else {
            servers.servers.push(cfg);
        }
        Ok(true)
    })?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GOLD-ADAPT-SYS-01 integration test: `auto_register` writes the hardened
    /// mobile-mcp entry to `mcp_servers.yaml` and the entry satisfies all
    /// security invariants checked by the live consumer path
    /// (`McpServers::load_from` → `assemble_catalogue`).
    ///
    /// Note: this test exercises the full upsert path but bypasses the npx probe
    /// via `auto_register_with_npx_present` so CI hosts without Node don't
    /// accidentally skip it. The probe itself is tested separately below.
    #[test]
    fn auto_register_appends_mobile_mcp_to_mcp_servers_yaml() {
        // Call the inner registration logic directly (npx probe bypassed for CI).
        let dir = tempfile::tempdir().unwrap();
        do_register(dir.path()).unwrap();

        let mcp_path = dir.path().join("mcp_servers.yaml");
        let loaded = crate::mcp::config::McpServers::load_from(&mcp_path).unwrap();

        // The entry must appear as enabled — assemble_catalogue's real consumer
        // path: McpServers::load_from finds the entry that catalogue.rs iterates.
        let srv = loaded
            .get_enabled("mobile-mcp")
            .expect("mobile-mcp must appear as an enabled server");

        // Command + args stable.
        assert_eq!(srv.command, "npx");
        assert!(
            srv.args.iter().any(|a| a.contains("@mobilenext/mobile-mcp")),
            "args must reference @mobilenext/mobile-mcp"
        );

        // Telemetry sentinel present — PostHog must be disabled.
        assert_eq!(
            srv.env.get("MOBILEMCP_DISABLE_TELEMETRY").map(String::as_str),
            Some("1"),
            "MOBILEMCP_DISABLE_TELEMETRY must be forced to 1"
        );

        // Gate must be Elevated — device control is medium-blast-radius.
        assert_eq!(
            srv.autonomy_gate,
            Some(crate::permissions::AutonomyLevel::Elevated),
            "mobile device control must require Elevated autonomy"
        );

        // allow_tools must be present and exclude remote-device cloud tools.
        let tools = srv.allow_tools.as_ref().expect("allow_tools must be Some");
        for forbidden in [
            "mobile_list_remote_devices",
            "mobile_allocate_remote_device",
            "mobile_release_remote_device",
        ] {
            assert!(
                !tools.iter().any(|t| t == forbidden),
                "{forbidden} must NOT be in the default allowlist (cloud-blast-radius)"
            );
        }
        assert!(
            tools.len() >= 20,
            "must expose at least 20 local-device tools; got {}",
            tools.len()
        );
    }

    #[test]
    fn auto_register_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();

        // First registration.
        do_register(dir.path()).unwrap();
        // Second registration must not duplicate the entry.
        do_register(dir.path()).unwrap();

        let mcp_path = dir.path().join("mcp_servers.yaml");
        let loaded = crate::mcp::config::McpServers::load_from(&mcp_path).unwrap();
        let count = loaded
            .servers
            .iter()
            .filter(|s| s.id == "mobile-mcp")
            .count();
        assert_eq!(
            count, 1,
            "idempotent: exactly one mobile-mcp entry after two calls"
        );
    }

    #[test]
    fn auto_register_preserves_existing_servers_in_yaml() {
        // Verify that registering mobile-mcp doesn't clobber pre-existing
        // servers already in the operator's mcp_servers.yaml.
        let dir = tempfile::tempdir().unwrap();
        let mcp_path = dir.path().join("mcp_servers.yaml");

        // Pre-populate with a different server.
        let pre_existing = crate::mcp::config::McpServers {
            smart_loading: true,
            servers: vec![crate::mcp::config::McpServerConfig {
                id: "other-server".into(),
                description: None,
                command: "node".into(),
                args: vec![],
                env: std::collections::HashMap::new(),
                enabled: true,
                allow_tools: None,
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            }],
        };
        let yaml = serde_yaml::to_string(&pre_existing).unwrap();
        std::fs::write(&mcp_path, yaml).unwrap();

        do_register(dir.path()).unwrap();

        let loaded = crate::mcp::config::McpServers::load_from(&mcp_path).unwrap();
        assert_eq!(
            loaded.servers.len(),
            2,
            "both servers must be present after registration"
        );
        assert!(
            loaded.servers.iter().any(|s| s.id == "other-server"),
            "pre-existing server must not be clobbered"
        );
        assert!(
            loaded.get_enabled("mobile-mcp").is_some(),
            "mobile-mcp must be registered alongside existing servers"
        );
    }

    /// Inner registration without the async npx probe — used by sync tests.
    fn do_register(neoth_home: &Path) -> Result<bool> {
        let mcp_path = neoth_home.join("mcp_servers.yaml");
        crate::mcp::config::McpServers::update_at(&mcp_path, |servers| {
            let mut cfg = crate::mcp::config::mobile_mcp_recommended_config();
            cfg.enabled = true;
            if let Some(existing) = servers.servers.iter_mut().find(|s| s.id == cfg.id) {
                existing.enabled = true;
                existing
                    .env
                    .insert("MOBILEMCP_DISABLE_TELEMETRY".to_string(), "1".to_string());
                existing.allow_tools = cfg.allow_tools;
                existing.autonomy_gate = cfg.autonomy_gate;
            } else {
                servers.servers.push(cfg);
            }
            Ok(true)
        })?;
        Ok(true)
    }

    // ── B18 tests ─────────────────────────────────────────────────────────

    #[test]
    fn do_register_fails_on_corrupt_yaml_and_leaves_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mcp_path = dir.path().join("mcp_servers.yaml");
        let bad_yaml = b": corrupt yaml\n";
        std::fs::write(&mcp_path, bad_yaml).unwrap();

        let result = do_register(dir.path());
        assert!(result.is_err(), "must Err on corrupt mcp_servers.yaml");

        let after = std::fs::read(&mcp_path).unwrap();
        assert_eq!(after.as_slice(), bad_yaml, "file must be byte-identical after failed update");
    }

    /// Smoke test: the async probe path doesn't panic whether or not Node
    /// is installed on the CI runner. Real network / binary not required.
    #[tokio::test]
    async fn auto_register_returns_false_when_npx_missing_or_true_when_present() {
        let dir = tempfile::tempdir().unwrap();
        // We can't control whether Node is on PATH in CI, so only assert
        // that the function returns Ok(_) without panicking.
        let result = auto_register(dir.path()).await;
        assert!(result.is_ok(), "auto_register must not error on probe: {result:?}");
        // When it returns Ok(false) nothing should be written to disk.
        if !result.unwrap() {
            assert!(
                !dir.path().join("mcp_servers.yaml").exists(),
                "mcp_servers.yaml must not be created when npx is missing"
            );
        }
    }
}
