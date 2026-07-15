//! Release-proof MCP security matrix — asserts the security posture of EVERY
//! shipped `*_recommended_config()` + the per-server autonomy floor, as one
//! catalog that fails CI if a future config regresses to insecure-by-default.
//!
//! ## Why this exists
//! `mcp/config.rs` has per-config unit tests, but nothing asserts the
//! cross-config INVARIANT: that no recommended server NEOTH ships ever defaults
//! to enabled / trust-all / un-pinned tools, and that the high-blast-radius
//! servers (a browser driver, an SSH/remote-edit server) carry the CCS-02
//! `autonomy_gate: Elevated` floor. A new recommended config added without
//! these properties is a security regression; this matrix catches it.
//!
//! ## The matrix
//! | Invariant                                  | Applies to              |
//! |--------------------------------------------|-------------------------|
//! | enabled == false (operator opts in)        | every recommended cfg   |
//! | trust_all_tools == false (secure default)  | every recommended cfg   |
//! | allow_tools is a non-empty pin             | every recommended cfg   |
//! | smart_approve == false (no confirm-bypass) | every recommended cfg   |
//! | autonomy_gate == Some(Elevated)            | browser + ssh (hi-risk) |
//! | meets_gate enforces Strict<Standard<Elev<Full, Custom fail-closed | the floor |

use neothd::mcp::config::{
    McpServerConfig, cbm_recommended_config, chrome_devtools_recommended_config,
    hex_graph_recommended_config, hex_line_recommended_config, hex_research_recommended_config,
    hex_ssh_recommended_config, mobile_mcp_recommended_config, tududi_recommended_config,
};
use neothd::permissions::AutonomyLevel;

/// Every recommended config NEOTH ships, by id.
fn all_recommended() -> Vec<(&'static str, McpServerConfig)> {
    vec![
        ("cbm", cbm_recommended_config()),
        ("hex-graph", hex_graph_recommended_config()),
        ("hex-line", hex_line_recommended_config()),
        ("hex-research", hex_research_recommended_config()),
        ("hex-ssh", hex_ssh_recommended_config()),
        ("chrome-devtools", chrome_devtools_recommended_config()),
        ("mobile-mcp", mobile_mcp_recommended_config()),
        (
            "tududi",
            tududi_recommended_config("/tmp/tududi-mcp/server.js"),
        ),
    ]
}

#[test]
fn every_recommended_config_is_secure_by_default() {
    for (name, cfg) in all_recommended() {
        assert!(
            !cfg.enabled,
            "{name}: recommended configs MUST default enabled:false (operator opts in)"
        );
        assert!(
            !cfg.trust_all_tools,
            "{name}: trust_all_tools MUST be false (secure-by-default — no catalogue trust)"
        );
        assert!(
            !cfg.smart_approve,
            "{name}: smart_approve MUST be false (no per-server confirm-bypass by default)"
        );
        let tools = cfg
            .allow_tools
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: allow_tools MUST be a pinned list, not None"));
        assert!(
            !tools.is_empty(),
            "{name}: allow_tools MUST be non-empty (None+empty = the deny posture, not a config)"
        );
    }
}

#[test]
fn high_blast_radius_servers_carry_an_elevated_floor() {
    // A browser driver (arbitrary navigation/DOM/JS) and an SSH/remote-edit
    // server are the high-blast-radius class — CCS-02 requires they stay inert
    // below Elevated autonomy.
    let configs = all_recommended();
    for id in ["chrome-devtools", "hex-ssh"] {
        let cfg = &configs
            .iter()
            .find(|(n, _)| *n == id)
            .unwrap_or_else(|| panic!("{id} recommended config must exist"))
            .1;
        assert_eq!(
            cfg.autonomy_gate,
            Some(AutonomyLevel::Elevated),
            "{id}: high-blast-radius server MUST be autonomy_gate: Elevated (CCS-02)"
        );
    }
}

#[test]
fn autonomy_gate_floor_enforces_linear_order() {
    use AutonomyLevel::*;
    // An Elevated-gated server is invokable only at Elevated/Full.
    assert!(Elevated.meets_gate(Elevated));
    assert!(Full.meets_gate(Elevated));
    assert!(!Standard.meets_gate(Elevated));
    assert!(!Strict.meets_gate(Elevated));
    // Custom is fail-closed: it never implicitly satisfies an Elevated floor.
    assert!(!Custom.meets_gate(Elevated));
}
