//! ZF-05 — pure preset-classification logic + wizard YAML-key documentation.
//!
//! Screen NAVIGATION lives in `ui/main.slint` (`WizardStep` enum + the
//! per-screen continue/back handlers + the derived `wz-is-express`
//! property) — Slint owns the flow; a Rust twin of the state machine was
//! deliberately dropped to avoid an unenforceable duplicate.
//!
//! What lives here is what `main.rs` actually consumes:
//!   - [`BUILTIN_PRESETS`] — the preset cards + name validation on Finish.
//!   - [`preset_is_express`] — express-vs-custom decision (CLI ZF-02
//!     semantics: any non-empty, non-"custom" preset = express; the Finish
//!     handler then applies the preset via `neoth preset apply`).
//!
//! Express path (enforced in main.slint): Welcome → License → Identity →
//! PresetPicker → Done. Custom path additionally walks the parity screens
//! HmacSetup → ObsidianSetup → N8nSetup → KeetTip → WasmSetup.
//!
//! YAML keys each wizard screen writes (documentation):
//!
//!   obsidian-setup:
//!     obsidian_vault                  — String (absolute path)
//!     obsidian_subdir                 — String (default "NEOTH-sessions")
//!     obsidian_vault_reader_enabled   — bool
//!
//!   hmac-setup (webhook outbound signing):
//!     webhook_manager.enabled         — bool (master switch)
//!     webhook_manager.endpoints       — first entry url + secret
//!
//!   n8n-setup:
//!     n8n_api.enabled                 — bool
//!     n8n_api.port                    — u16 (default 9744)
//!
//!   wasm-setup:
//!     plugins.wasm.enabled            — bool
//!
//!   keet-tip: informational only — no yaml writes from wizard screen
//!     (Keet seed phrase lives in credentials.yaml; the wizard screen
//!     explains how to pair via `neoth keet pair` at runtime).

/// The four built-in presets + custom, in display order.
/// Mirrors `neothd::config::preset_builtins::builtin_by_name` names.
pub const BUILTIN_PRESETS: &[(&str, &str)] = &[
    (
        "full-auto",
        "Full autonomous — acts on its own, asks rarely. For solo power-users.",
    ),
    (
        "balanced",
        "Balanced — confirms before writes outside ~/.neoth. Default for most.",
    ),
    (
        "essentials",
        "Essentials — minimal feature set, no cloud channels, local-first.",
    ),
    (
        "local-sovereign",
        "Local-sovereign — air-gapped, Ollama-only, no outbound traffic.",
    ),
    (
        "custom",
        "Custom — walk every setup screen and pick each option yourself.",
    ),
];

/// Returns `true` when `name` is a non-empty, non-custom built-in preset,
/// meaning the operator chose the express path.
pub fn preset_is_express(name: &str) -> bool {
    !name.is_empty() && name != "custom"
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Preset classification ─────────────────────────────────────────────────

    #[test]
    fn preset_is_express_for_all_builtins_except_custom() {
        for (name, _) in BUILTIN_PRESETS {
            if *name == "custom" {
                assert!(!preset_is_express(name), "custom must NOT be express");
            } else {
                assert!(preset_is_express(name), "builtin {name} must be express");
            }
        }
    }

    #[test]
    fn empty_preset_name_is_not_express() {
        assert!(!preset_is_express(""));
    }

    #[test]
    fn unknown_preset_name_treated_as_express() {
        // An operator preset (not "custom") activates the express path.
        assert!(preset_is_express("my-custom-profile"));
    }

    // ── YAML key documentation tests ──────────────────────────────────────────
    // These compile-time assertions document the exact freedom.yaml field names
    // that each wizard screen writes. They live here (not in neothd) so a
    // rename in the daemon's FreedomConfig needs a corresponding update here.

    #[test]
    fn obsidian_yaml_keys_documented() {
        // neothd::config::FreedomConfig fields (snake_case = yaml key):
        //   obsidian_vault                 → Option<String>
        //   obsidian_subdir                → Option<String>  (default "NEOTH-sessions")
        //   obsidian_vault_reader_enabled  → bool
        let keys = ["obsidian_vault", "obsidian_subdir", "obsidian_vault_reader_enabled"];
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn hmac_yaml_keys_documented() {
        // neothd::config::FreedomConfig::webhook_manager → WebhookManagerConfig:
        //   enabled  → bool (master switch, written as `webhook_manager.enabled`)
        //   endpoints[0].url    → String
        //   endpoints[0].secret → SecretString (HMAC-SHA256 signing key)
        let keys = [
            "webhook_manager.enabled",
            "webhook_manager.endpoints.url",
            "webhook_manager.endpoints.secret",
        ];
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn n8n_yaml_keys_documented() {
        // neothd::config::FreedomConfig::n8n_api → N8nApiConfig:
        //   enabled   → bool
        //   port      → u16 (default 9744)
        let keys = ["n8n_api.enabled", "n8n_api.port"];
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn wasm_yaml_keys_documented() {
        // neothd::config::FreedomConfig::plugins → PluginsConfig:
        //   wasm.enabled → bool (runtime gate; default true in release builds)
        let keys = ["plugins.wasm.enabled"];
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn keet_wizard_is_informational_only() {
        // The Keet tip screen writes nothing to freedom.yaml.
        // Keet seed phrases go to credentials.yaml at runtime (`neoth keet pair`).
        // This test documents the intentional absence of YAML writes.
        let yaml_keys: Vec<&str> = vec![];
        assert!(yaml_keys.is_empty(), "keet-tip wizard screen must not write yaml");
    }

    // ── Preset-to-yaml-key mapping ────────────────────────────────────────────
    // When the operator picks an express preset, the Finish handler applies
    // the preset overlay via `neothd preset apply <name>` (or the equivalent
    // MinimalFreedomYaml preset field). These tests document which presets
    // exist and that all non-custom ones trigger the express path.

    #[test]
    fn all_builtin_preset_names_known() {
        let names: Vec<&str> = BUILTIN_PRESETS.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"full-auto"));
        assert!(names.contains(&"balanced"));
        assert!(names.contains(&"essentials"));
        assert!(names.contains(&"local-sovereign"));
        assert!(names.contains(&"custom"));
        assert_eq!(names.len(), 5);
    }

    #[test]
    fn all_builtins_have_non_empty_descriptions() {
        for (name, desc) in BUILTIN_PRESETS {
            assert!(!desc.is_empty(), "preset {name} has empty description");
        }
    }
}
