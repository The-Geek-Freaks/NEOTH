//! GOLD-ADAPT-TUDU-01 — tududi self-hosted task manager MCP registration.
//!
//! tududi is a self-hosted, open-source task manager with a Node.js MCP
//! stdio server at `backend/modules/mcp/server.js` (8 task tools). This
//! module handles:
//!
//!   1. Detecting whether the operator's `server.js` path is a real file.
//!   2. Building the hardened [`McpServerConfig`] entry (8 task tools,
//!      `TUDUDI_API_TOKEN: from_env`, `enabled: true` on registration).
//!   3. Upserting the entry into `~/.neoth/mcp_servers.yaml` (idempotent).
//!   4. Writing the API token to `credentials.yaml` so the `from_env`
//!      sentinel resolves at spawn time without exposing the token in
//!      `mcp_servers.yaml`.
//!
//! The wizard step that calls this module is [`crate::cli::init::step6i_tududi_offer`].
//! The live consumer path is `mcp::catalogue::assemble_catalogue` which loops
//! all enabled servers and injects their tools into the system prompt on every
//! `neoth chat` / daemon turn.
//!
//! ## Secret isolation
//!
//! `mcp_servers.yaml` holds only the `from_env` sentinel for
//! `TUDUDI_API_TOKEN`. The actual token lands in `credentials.yaml` under
//! `tududi_api_token`. The NEOTH daemon's credential loader populates the
//! process env at startup so `McpServerConfig::resolve_env()` finds the real
//! value at MCP subprocess spawn time. This preserves the invariant that
//! `mcp_servers.yaml` is a non-secret config file (safe to back up, export,
//! or display via `neoth mcp list`).

use std::path::Path;

use anyhow::{Context, Result};

/// Return true when `path` points to a regular file on the filesystem.
///
/// Pure predicate — no subprocess, no network. Used by [`auto_register`] to
/// guard against registering a tududi entry whose `node <path>` would fail at
/// MCP spawn time with "file not found".
pub fn is_server_file_present(path: &str) -> bool {
    Path::new(path).is_file()
}

/// Register tududi's MCP server entry in `<neoth_home>/mcp_servers.yaml` and
/// persist the API token to `<neoth_home>/credentials.yaml`.
///
/// # Returns
///
/// - `Ok(true)`  — registration succeeded; the entry is now in `mcp_servers.yaml`
///   with `enabled: true` and the token is in `credentials.yaml`.
/// - `Ok(false)` — `server_js_path` is not a regular file; nothing was written.
///   The wizard can show a hint telling the operator to check their path.
/// - `Err(_)`    — I/O or serialisation error; the caller should surface it.
///
/// # Idempotency
///
/// If a `tududi` entry already exists in `mcp_servers.yaml`, it is updated
/// in-place (re-enabled + args refreshed). If the token in `credentials.yaml`
/// already matches, the file is rewritten atomically (same value, safe
/// no-op effect).
///
/// # Security invariant
///
/// `api_token` is NEVER written into `mcp_servers.yaml`. The env map stores
/// only `"from_env"`. The token goes exclusively to `credentials.yaml`
/// under `tududi_api_token` (mode 0600 / icacls-restricted on Windows).
pub fn auto_register(server_js_path: &str, api_token: &str, neoth_home: &Path) -> Result<bool> {
    // Guard: the Node.js script must exist before we register it.
    if !is_server_file_present(server_js_path) {
        return Ok(false);
    }

    let mcp_path = neoth_home.join("mcp_servers.yaml");
    let cred_path = neoth_home.join("credentials.yaml");

    // Phase 1 — Pre-validate: both target files must load without error.
    // A corrupted file is an operator error that must surface BEFORE any
    // write — never silently replaced with a one-entry file.
    crate::mcp::config::McpServers::load_from(&mcp_path)
        .with_context(|| format!("pre-validate {}", mcp_path.display()))?;
    crate::config::credentials::Credentials::load_or_default(&cred_path)
        .with_context(|| format!("pre-validate {}", cred_path.display()))?;

    // Phase 2 — Commit the secret FIRST (B18 two-phase invariant).
    // A crash here leaves an unused token in credentials.yaml (harmless —
    // no enabled MCP server references it yet). The dangerous state to
    // avoid is the opposite: an enabled server with no token.
    crate::config::credentials::Credentials::update_at(&cred_path, |creds| {
        creds.tududi_api_token = Some(crate::secret::SecretString::new(api_token.to_string()));
        Ok(())
    })
    .context("write tududi_api_token to credentials.yaml")?;

    // Phase 3 — Activate the MCP entry SECOND (token is now durable).
    // A crash here leaves an unused token — retry is idempotent.
    let server_js_owned = server_js_path.to_string();
    crate::mcp::config::McpServers::update_at(&mcp_path, |servers| {
        let mut cfg = crate::mcp::config::tududi_recommended_config(&server_js_owned);
        cfg.enabled = true;
        if let Some(existing) = servers.servers.iter_mut().find(|s| s.id == cfg.id) {
            existing.enabled = true;
            // Refresh the server.js path in case the operator moved the file.
            existing.args = cfg.args.clone();
            // Always enforce the token sentinel (never a literal value).
            existing
                .env
                .insert("TUDUDI_API_TOKEN".to_string(), "from_env".to_string());
        } else {
            servers.servers.push(cfg);
        }
        Ok(true)
    })
    .context("update mcp_servers.yaml")?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Smoke-test the presence check independently of the filesystem state
    /// on a CI runner (which definitely has no `/nonexistent/server.js`).
    #[test]
    fn is_server_file_present_returns_false_for_nonexistent_path() {
        assert!(!is_server_file_present("/nonexistent/tududi/server.js"));
    }

    #[test]
    fn is_server_file_present_returns_true_for_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.js");
        std::fs::write(&path, b"// stub").unwrap();
        assert!(is_server_file_present(path.to_str().unwrap()));
    }

    /// GOLD-ADAPT-TUDU-01 integration test: `auto_register` writes the entry
    /// to `mcp_servers.yaml` and the token to `credentials.yaml`.
    ///
    /// This exercises the real consumer path: `McpServers::load_from` (called
    /// by `assemble_catalogue` and `run_list`) must find the registered entry
    /// after `auto_register` returns.
    #[test]
    fn auto_register_appends_tududi_to_mcp_servers_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let server_js = dir.path().join("server.js");
        std::fs::write(&server_js, b"// stub").unwrap();

        let result =
            auto_register(server_js.to_str().unwrap(), "test-token-abc", dir.path()).unwrap();
        assert!(
            result,
            "auto_register must return true when server.js exists"
        );

        // Verify mcp_servers.yaml was written with an enabled tududi entry.
        let mcp_path = dir.path().join("mcp_servers.yaml");
        let loaded = crate::mcp::config::McpServers::load_from(&mcp_path).unwrap();
        let srv = loaded
            .get_enabled("tududi")
            .expect("tududi must appear as an enabled server");
        assert_eq!(srv.command, "node");
        assert!(
            srv.args.iter().any(|a| a.contains("server.js")),
            "args must reference server.js"
        );
        assert_eq!(
            srv.env.get("TUDUDI_API_TOKEN").map(String::as_str),
            Some("from_env"),
            "env must use from_env sentinel, not the literal token"
        );

        // The literal token must NOT appear in mcp_servers.yaml.
        let raw = std::fs::read_to_string(&mcp_path).unwrap();
        assert!(
            !raw.contains("test-token-abc"),
            "API token must NOT be stored in mcp_servers.yaml (secret-in-config leak)"
        );

        // The token MUST appear in credentials.yaml.
        let cred_path = dir.path().join("credentials.yaml");
        let creds = crate::config::credentials::Credentials::load_or_default(&cred_path).unwrap();
        assert!(
            creds.tududi_api_token.is_some(),
            "tududi_api_token must be written to credentials.yaml"
        );
    }

    #[test]
    fn auto_register_returns_false_when_server_js_missing() {
        let dir = tempfile::tempdir().unwrap();
        let result = auto_register("/nonexistent/server.js", "token", dir.path()).unwrap();
        assert!(
            !result,
            "must return false when server.js is not a real file"
        );
        // Nothing should be written when the guard fires.
        assert!(
            !dir.path().join("mcp_servers.yaml").exists(),
            "mcp_servers.yaml must not be created when server.js is missing"
        );
    }

    #[test]
    fn auto_register_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let server_js = dir.path().join("server.js");
        std::fs::write(&server_js, b"// stub").unwrap();
        let path_str = server_js.to_str().unwrap();

        // First registration.
        auto_register(path_str, "tok", dir.path()).unwrap();
        // Second registration must not duplicate the entry.
        auto_register(path_str, "tok", dir.path()).unwrap();

        let mcp_path = dir.path().join("mcp_servers.yaml");
        let loaded = crate::mcp::config::McpServers::load_from(&mcp_path).unwrap();
        let count = loaded.servers.iter().filter(|s| s.id == "tududi").count();
        assert_eq!(
            count, 1,
            "idempotent: exactly one tududi entry after two calls"
        );
    }

    #[test]
    fn auto_register_refreshes_server_path_on_re_register() {
        // If the operator moves their tududi installation, re-running the
        // wizard step should update the args path in-place.
        let dir = tempfile::tempdir().unwrap();

        let old_js = dir.path().join("old_server.js");
        std::fs::write(&old_js, b"// stub").unwrap();
        auto_register(old_js.to_str().unwrap(), "tok", dir.path()).unwrap();

        let new_js = dir.path().join("new_server.js");
        std::fs::write(&new_js, b"// stub").unwrap();
        auto_register(new_js.to_str().unwrap(), "tok", dir.path()).unwrap();

        let mcp_path = dir.path().join("mcp_servers.yaml");
        let loaded = crate::mcp::config::McpServers::load_from(&mcp_path).unwrap();
        let count = loaded.servers.iter().filter(|s| s.id == "tududi").count();
        assert_eq!(count, 1, "still exactly one entry after path change");

        let srv = loaded.get_enabled("tududi").unwrap();
        assert!(
            srv.args.iter().any(|a| a.contains("new_server.js")),
            "args must reflect the updated server.js path"
        );
    }

    // ── B18 fault-injection tests ─────────────────────────────────────────

    /// Pre-validate fires before any write: corrupt mcp_servers.yaml → Err,
    /// credentials.yaml must NOT be created (no partial state).
    #[test]
    fn auto_register_prevalidate_rejects_bad_mcp_yaml_before_credential_write() {
        let dir = tempfile::tempdir().unwrap();
        let server_js = dir.path().join("server.js");
        std::fs::write(&server_js, b"// stub").unwrap();

        let mcp_path = dir.path().join("mcp_servers.yaml");
        let bad_yaml = b": invalid yaml structure\n";
        std::fs::write(&mcp_path, bad_yaml).unwrap();
        let bad_bytes = bad_yaml.to_vec();

        let result = auto_register(server_js.to_str().unwrap(), "secret-token", dir.path());
        assert!(result.is_err(), "must Err on corrupt mcp_servers.yaml");

        // mcp_servers.yaml must be byte-identical — not clobbered.
        let after_mcp = std::fs::read(&mcp_path).unwrap();
        assert_eq!(after_mcp, bad_bytes, "mcp_servers.yaml must be unchanged");

        // credentials.yaml must NOT exist: no write occurred before pre-validate error.
        assert!(
            !dir.path().join("credentials.yaml").exists(),
            "credentials.yaml must not be created when pre-validate fails"
        );
    }

    /// Corrupt credentials.yaml → Err, neither file mutated.
    #[test]
    fn auto_register_prevalidate_rejects_bad_credentials_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let server_js = dir.path().join("server.js");
        std::fs::write(&server_js, b"// stub").unwrap();

        let cred_path = dir.path().join("credentials.yaml");
        let bad_yaml = b": invalid yaml structure\n";
        std::fs::write(&cred_path, bad_yaml).unwrap();
        let bad_bytes = bad_yaml.to_vec();

        let result = auto_register(server_js.to_str().unwrap(), "secret-token", dir.path());
        assert!(result.is_err(), "must Err on corrupt credentials.yaml");

        // credentials.yaml must be byte-identical — not clobbered.
        let after_cred = std::fs::read(&cred_path).unwrap();
        assert_eq!(after_cred, bad_bytes, "credentials.yaml must be unchanged");

        // mcp_servers.yaml must NOT have been created.
        assert!(
            !dir.path().join("mcp_servers.yaml").exists(),
            "mcp_servers.yaml must not be created when pre-validate fails on credentials.yaml"
        );
    }

    /// Prove that `PathBuf` helper used internally gives a canonical abs path.
    #[test]
    fn auto_register_uses_absolute_path_in_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let server_js = dir.path().join("server.js");
        std::fs::write(&server_js, b"// stub").unwrap();
        auto_register(server_js.to_str().unwrap(), "tok", dir.path()).unwrap();

        let mcp_path = dir.path().join("mcp_servers.yaml");
        let loaded = crate::mcp::config::McpServers::load_from(&mcp_path).unwrap();
        let srv = loaded.get_enabled("tududi").unwrap();
        // The path must be absolute so `node <path>` works from any cwd.
        let arg_path = PathBuf::from(&srv.args[0]);
        assert!(
            arg_path.is_absolute(),
            "server.js arg must be an absolute path; got {:?}",
            srv.args[0]
        );
    }
}
