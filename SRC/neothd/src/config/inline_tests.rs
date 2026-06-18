//! Inline tests extracted from `config/mod.rs`.

#[cfg(test)]
mod config_defaults_tests {
    use super::super::*;

    #[test]
    fn omi_config_defaults_off_and_local() {
        // OM-01 — default OFF, local endpoint, 30s/0.75 knobs; serde round-trips.
        let d = OmiConfig::default();
        assert!(!d.enabled);
        assert_eq!(d.endpoint, crate::installers::omi::DEFAULT_OMI_ENDPOINT);
        assert_eq!(d.poll_interval_secs, 30);
        assert!((d.confidence_threshold - 0.75).abs() < 1e-6);
        let absent: FreedomConfig = serde_yaml::from_str("operator_id: a\n").expect("parse");
        assert!(!absent.omi.enabled);
        let set: FreedomConfig = serde_yaml::from_str(
            "operator_id: a\nomi:\n  enabled: true\n  endpoint: http://127.0.0.1:9999\n",
        )
        .expect("parse");
        assert!(set.omi.enabled);
        assert_eq!(set.omi.endpoint, "http://127.0.0.1:9999");
    }

    #[test]
    fn goal_config_max_turns_defaults_to_five() {
        // GM-01 — default 5 (the prior hardcoded dispatch-loop cap; no behaviour
        // change). An absent `goal:` block + a partial one both read 5.
        assert_eq!(GoalConfig::default().max_turns, 5);
        let absent: FreedomConfig = serde_yaml::from_str("operator_id: a\n").expect("parse");
        assert_eq!(absent.goal.max_turns, 5);
        let set: FreedomConfig =
            serde_yaml::from_str("operator_id: a\ngoal:\n  max_turns: 12\n").expect("parse");
        assert_eq!(set.goal.max_turns, 12);
    }

    #[test]
    fn email_config_tiebreak_serde_defaults_are_safe() {
        // PL-05b — both flags off by default (cost-safe + security-conservative).
        let d = EmailConfig::default();
        assert!(!d.llm_tiebreak);
        assert!(!d.llm_tiebreak_allow_downgrade);

        // Absent `email:` block ⇒ both false.
        let absent: FreedomConfig =
            serde_yaml::from_str("operator_id: alice\n").expect("parse minimal");
        assert!(!absent.email.llm_tiebreak);
        assert!(!absent.email.llm_tiebreak_allow_downgrade);

        // Partial block (opt into the tie-breaker, OMIT the dangerous downgrade)
        // ⇒ the downgrade must stay false (the most important regression guard).
        let partial: FreedomConfig =
            serde_yaml::from_str("operator_id: a\nemail:\n  llm_tiebreak: true\n")
                .expect("parse partial email block");
        assert!(partial.email.llm_tiebreak);
        assert!(
            !partial.email.llm_tiebreak_allow_downgrade,
            "omitted downgrade flag must default false, never silently true"
        );

        // Full explicit opt-in ⇒ both true (the opt-in path isn't suppressed).
        let full: FreedomConfig = serde_yaml::from_str(
            "operator_id: a\nemail:\n  llm_tiebreak: true\n  llm_tiebreak_allow_downgrade: true\n",
        )
        .expect("parse full email block");
        assert!(full.email.llm_tiebreak);
        assert!(full.email.llm_tiebreak_allow_downgrade);
    }
}

#[cfg(test)]
mod compression_config_tests {
    use super::super::*;

    #[test]
    fn defaults_are_disabled_and_conservative() {
        let c = CompressionConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.min_block_bytes, 2048);
        assert_eq!(c.live_zone_turns, 3);
        assert_eq!(c.reformat_target_ratio, 0.5);
        assert_eq!(c.bloat_threshold, 0.5);
        assert_eq!(c.offload_fallback_ratio, 0.85);
    }

    #[test]
    fn omitted_block_deserialises_to_disabled_default() {
        // A freedom.yaml that omits the field (or an empty block) must agree
        // with ::default() — both disabled — so loaded configs behave like
        // code-built ones.
        let from_empty: CompressionConfig =
            serde_yaml::from_str("{}").expect("empty compression block deserialises");
        assert_eq!(from_empty, CompressionConfig::default());
        assert!(!from_empty.enabled);
    }

    #[test]
    fn gate_and_thresholds_mirror_config_fields() {
        let c = CompressionConfig {
            enabled: true,
            min_block_bytes: 4096,
            live_zone_turns: 5,
            reformat_target_ratio: 0.3,
            bloat_threshold: 0.7,
            offload_fallback_ratio: 0.9,
        };
        let g = c.gate();
        assert!(g.enabled);
        assert_eq!(g.min_block_bytes, 4096);
        assert_eq!(g.live_zone_turns, 5);
        let t = c.thresholds();
        assert_eq!(t.reformat_target_ratio, 0.3);
        assert_eq!(t.bloat_threshold, 0.7);
        assert_eq!(t.offload_fallback_ratio, 0.9);
    }
}

#[cfg(test)]
mod sub_config_tests {
    use super::super::*;

    #[test]
    fn skills_config_default_eval_disabled() {
        let cfg = SkillsConfig::default();
        assert!(!cfg.disabled_for_eval_sessions);
        assert!(!cfg.eval_session_active);
        assert!(!cfg.should_suppress_for_eval());
    }

    #[test]
    fn skills_config_always_embed_route_defaults_true_consistently() {
        // PF-01: `::default()` AND a freedom.yaml that OMITS the field
        // must agree (both true) — a divergence would make code-built
        // configs route differently from loaded ones.
        assert!(SkillsConfig::default().always_embed_route);
        let from_empty: SkillsConfig =
            serde_yaml::from_str("{}").expect("empty skills block deserialises");
        assert!(
            from_empty.always_embed_route,
            "omitted always_embed_route must default true to match ::default()"
        );
        // And an explicit false round-trips.
        let off: SkillsConfig =
            serde_yaml::from_str("always_embed_route: false\n").expect("explicit false");
        assert!(!off.always_embed_route);
    }

    #[test]
    fn skills_config_suppress_requires_both_flags() {
        // Mutates the process-global NEOTH_EVAL_SESSION — take the
        // crate env lock so it can't race the sibling test below (or
        // any other env test) under the multi-threaded runner.
        let _env = crate::test_env::lock();
        let mut cfg = SkillsConfig::default();
        cfg.disabled_for_eval_sessions = true;
        // Without eval_session_active OR env → still false.
        unsafe { std::env::remove_var("NEOTH_EVAL_SESSION") };
        assert!(!cfg.should_suppress_for_eval());
        cfg.eval_session_active = true;
        assert!(cfg.should_suppress_for_eval());
    }

    #[test]
    fn skills_config_suppress_honours_env_var() {
        let _env = crate::test_env::lock();
        let mut cfg = SkillsConfig::default();
        cfg.disabled_for_eval_sessions = true;
        cfg.eval_session_active = false;
        unsafe { std::env::set_var("NEOTH_EVAL_SESSION", "1") };
        assert!(cfg.should_suppress_for_eval());
        unsafe { std::env::remove_var("NEOTH_EVAL_SESSION") };
    }

    #[test]
    fn tokens_config_default_is_100k() {
        assert_eq!(TokensConfig::default().max_per_request, 100_000);
        assert_eq!(TokensConfig::default_max_per_request(), 100_000);
    }

    #[test]
    fn tokens_config_serde_round_trip_with_default() {
        let json = r#"{}"#;
        let cfg: TokensConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.max_per_request, 100_000);
    }

    #[test]
    fn tokens_config_serde_round_trip_with_override() {
        let json = r#"{"max_per_request": 8192}"#;
        let cfg: TokensConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.max_per_request, 8192);
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_yaml(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("freedom.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn load_minimal_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nrole: developer\nprovider_kind: claude_cli\nsteps_completed: [1,2,3,4,5,6,7]\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.operator_id.as_deref(), Some("alice"));
        assert_eq!(cfg.role, Some(OperatorRole::Developer));
        assert_eq!(cfg.provider_kind, Some(ProviderKind::ClaudeCli));
    }

    #[test]
    fn load_missing_file_says_to_run_init() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.yaml");
        let err = FreedomConfig::load_from_path(&path).unwrap_err();
        assert!(err.to_string().contains("neoth init"));
    }

    #[test]
    fn load_tolerates_unknown_fields() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nfuture_field: 42\nanother_unknown: foo\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.operator_id.as_deref(), Some("alice"));
    }

    #[test]
    fn load_rejects_malformed_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: [unterminated\n");
        let err = FreedomConfig::load_from_path(&path).unwrap_err();
        assert!(err.to_string().contains("parse YAML"));
    }

    /// V02-08 acceptance: the shipped `freedom.yaml.example` must
    /// parse cleanly through `FreedomConfig::load_from_path`. Catches
    /// the failure mode where someone adds a new field to the struct
    /// + the wizard, but forgets to update the example.
    #[test]
    fn freedom_yaml_example_parses_cleanly() {
        // The example file lives at SRC/freedom.yaml.example —
        // walking up from CARGO_MANIFEST_DIR (neothd crate root).
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let example_path = manifest_dir.parent().unwrap().join("freedom.yaml.example");
        if !example_path.exists() {
            // The workspace shape may vary across local checkouts; skip
            // gracefully rather than break developer flow when the
            // example file is moved.
            eprintln!(
                "skipping: freedom.yaml.example not at {}",
                example_path.display()
            );
            return;
        }
        let cfg = FreedomConfig::load_from_path(&example_path)
            .expect("freedom.yaml.example must parse via FreedomConfig::load_from_path");
        // Spot-check the documented defaults landed.
        assert_eq!(cfg.operator_id.as_deref(), Some("demo-user"));
        assert_eq!(cfg.role, Some(OperatorRole::Developer));
        assert_eq!(cfg.provider_kind, Some(ProviderKind::ClaudeCli));
        assert!(
            cfg.rollback
                .capture_kinds
                .contains(&"config_write".to_string())
        );
        assert!(
            cfg.rollback
                .capture_kinds
                .contains(&"channel_send".to_string())
        );
        assert_eq!(cfg.rollback.max_snapshot_bytes, 65_536);
    }

    #[test]
    fn refusal_recovery_default_is_enabled_with_no_disabled_reframings() {
        // R-04 2026-05-17: default ON so refusals get auto-retried via
        // pure-function reframings. Operators who want raw refusals
        // visible (debugging / forensic) flip enabled=false. Drift
        // guard so a future refactor flipping the default fails
        // loudly rather than silently changing recovery behaviour.
        let cfg = RefusalRecoveryConfig::default();
        assert!(cfg.enabled, "default must be opt-in (auto-recovery on)");
        assert!(cfg.disabled_reframings.is_empty());
    }

    #[test]
    fn refusal_recovery_block_round_trips_through_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             refusal_recovery:\n  \
               enabled: false\n  \
               disabled_reframings:\n    \
                 - operator_authority\n    \
                 - historical_framing\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.refusal_recovery.enabled);
        assert_eq!(cfg.refusal_recovery.disabled_reframings.len(), 2);
        assert!(
            cfg.refusal_recovery
                .disabled_reframings
                .contains(&"operator_authority".to_string())
        );
    }

    #[test]
    fn refusal_recovery_block_missing_inherits_enabled_default() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.refusal_recovery.enabled);
        assert!(cfg.refusal_recovery.disabled_reframings.is_empty());
    }

    #[test]
    fn profile_config_default_is_opt_out_with_15s_timeout() {
        // 2026-05-17 Session 2: default OFF so paid-cloud operators
        // don't get a surprise 2× token bill from the post-reply
        // extract LLM call. Drift guard so a future refactor flipping
        // the default fails loudly.
        let cfg = ProfileConfig::default();
        assert!(!cfg.learn_enabled, "default must be opt-out");
        assert_eq!(cfg.timeout_secs, 15);
        // L-06 (2026-05-22): cheap-by-default learn provider so
        // turning learning ON doesn't suddenly cost cloud tokens.
        assert_eq!(cfg.learn_provider.as_deref(), Some("local_qwen"));
        // L-07: fail-closed by default. Operators explicitly opt in
        // to "spend cloud tokens when local fails".
        assert!(!cfg.allow_cloud_fallback);
    }

    #[test]
    fn l_06_l_07_profile_block_round_trips_new_fields() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               learn_enabled: true\n  \
               learn_provider: openai_api\n  \
               allow_cloud_fallback: true\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.profile.learn_enabled);
        assert_eq!(cfg.profile.learn_provider.as_deref(), Some("openai_api"));
        assert!(cfg.profile.allow_cloud_fallback);
    }

    #[test]
    fn l_06_explicit_null_learn_provider_disables_pin() {
        // Operator who wants the profile-extract to follow the main
        // provider_kind sets learn_provider: null. Verify the
        // round-trip preserves None instead of falling back to the
        // default `Some("local_qwen")`.
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               learn_provider: null\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.profile.learn_provider.is_none());
    }

    #[test]
    fn profile_block_missing_inherits_opt_out_default() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.profile.learn_enabled);
        assert_eq!(cfg.profile.timeout_secs, 15);
    }

    #[test]
    fn profile_block_round_trips_through_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               learn_enabled: true\n  \
               timeout_secs: 30\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.profile.learn_enabled);
        assert_eq!(cfg.profile.timeout_secs, 30);
    }

    #[test]
    fn profile_partial_block_fills_unspecified_fields_with_defaults() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nprofile:\n  learn_enabled: true\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.profile.learn_enabled);
        // Missing timeout_secs falls back to default.
        assert_eq!(cfg.profile.timeout_secs, 15);
    }

    #[test]
    fn claude_cli_block_round_trips_through_yaml_when_present() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             claude_cli:\n  \
               backend: tmux\n  \
               tmux:\n    \
                 session_scope: per_conversation\n    \
                 compaction_rotate_after: 5\n    \
                 idle_ttl_secs: 600\n    \
                 idle_timeout_secs: 90\n    \
                 hard_timeout_secs: 240\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.claude_cli.backend, ClaudeCliBackendCfg::Tmux);
        assert_eq!(
            cfg.claude_cli.tmux.session_scope,
            TmuxSessionScope::PerConversation
        );
        assert_eq!(cfg.claude_cli.tmux.compaction_rotate_after, 5);
        assert_eq!(cfg.claude_cli.tmux.idle_ttl_secs, 600);
        assert_eq!(cfg.claude_cli.tmux.idle_timeout_secs, 90);
        assert_eq!(cfg.claude_cli.tmux.hard_timeout_secs, 240);
    }

    #[test]
    fn claude_cli_block_missing_inherits_defaults() {
        // Backward compat: freedom.yaml files written before B-6
        // landed have no `claude_cli:` block; serde must populate
        // the defaults transparently.
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.claude_cli.backend, ClaudeCliBackendCfg::Auto);
        assert_eq!(cfg.claude_cli.tmux.compaction_rotate_after, 10);
    }

    #[test]
    fn claude_cli_partial_block_fills_unspecified_fields_with_defaults() {
        // Operator overrides one knob (compaction cap) but leaves the
        // rest implicit. Missing fields must inherit defaults rather
        // than throwing.
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             claude_cli:\n  \
               tmux:\n    \
                 compaction_rotate_after: 3\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.claude_cli.backend, ClaudeCliBackendCfg::Auto);
        assert_eq!(cfg.claude_cli.tmux.compaction_rotate_after, 3);
        // Other tmux fields still default.
        assert_eq!(cfg.claude_cli.tmux.idle_timeout_secs, 120);
        assert_eq!(cfg.claude_cli.tmux.hard_timeout_secs, 300);
    }

    // ── V03-09 Phase 2a — AutoUpdateConfig ─────────────────────────

    #[test]
    fn auto_update_config_defaults_are_check_only_disabled() {
        // Master switch is OFF; auto_apply is OFF. Stock build does
        // nothing on the update front until the operator opts in.
        let cfg = AutoUpdateConfig::default();
        assert!(!cfg.enabled, "auto-update master switch must default OFF");
        assert!(!cfg.auto_apply, "auto_apply must default OFF (check-only)");
        assert_eq!(cfg.channel, "stable");
        assert_eq!(cfg.check_interval_secs, 24 * 60 * 60);
        assert_eq!(cfg.repo, "The-Geek-Freaks/NEOTH");
        assert!(cfg.target_triple.is_none());
    }

    #[test]
    fn auto_update_config_inherits_default_when_yaml_omits_block() {
        // Backward compat with freedom.yaml written before this
        // field existed: load must succeed + populate the default.
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.auto_update, AutoUpdateConfig::default());
    }

    #[test]
    fn auto_update_config_partial_block_fills_defaults() {
        // Operator only writes `enabled: true` — channel, repo,
        // interval, etc. must inherit defaults so a future field
        // addition doesn't break existing configs.
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nauto_update:\n  enabled: true\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.auto_update.enabled);
        assert!(!cfg.auto_update.auto_apply);
        assert_eq!(cfg.auto_update.channel, "stable");
        assert_eq!(cfg.auto_update.repo, "The-Geek-Freaks/NEOTH");
    }

    #[test]
    fn auto_update_config_full_block_round_trips() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nauto_update:\n  enabled: true\n  auto_apply: true\n  channel: rc\n  check_interval_secs: 3600\n  repo: example/fork\n  target_triple: x86_64-unknown-linux-musl\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.auto_update.enabled);
        assert!(cfg.auto_update.auto_apply);
        assert_eq!(cfg.auto_update.channel, "rc");
        assert_eq!(cfg.auto_update.check_interval_secs, 3_600);
        assert_eq!(cfg.auto_update.repo, "example/fork");
        assert_eq!(
            cfg.auto_update.target_triple.as_deref(),
            Some("x86_64-unknown-linux-musl")
        );
    }

    #[test]
    fn auto_update_config_serializes_to_yaml_with_snake_case_fields() {
        // Wire form pin: operator-facing keys are snake_case so the
        // wizard + docs match.
        let cfg = FreedomConfig {
            operator_id: Some("alice".to_string()),
            auto_update: AutoUpdateConfig {
                enabled: true,
                auto_apply: true,
                channel: "stable".to_string(),
                check_interval_secs: 7_200,
                repo: "The-Geek-Freaks/NEOTH".to_string(),
                target_triple: None,
            },
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        assert!(yaml.contains("auto_update:"));
        assert!(yaml.contains("auto_apply: true"));
        assert!(yaml.contains("check_interval_secs: 7200"));
        assert!(yaml.contains("channel: stable"));
    }

    // ── NOOB-UX-3 PluginsConfig runtime gate ────────────────────────

    #[test]
    fn plugins_wasm_enabled_defaults_to_true() {
        // Honours the neoth-features-default-on hard rule —
        // operators on a shipped release expect the feature to
        // be live unless they explicitly disabled it.
        let cfg = PluginsConfig::default();
        assert!(cfg.wasm.enabled);
    }

    #[test]
    fn plugins_block_inherits_default_when_yaml_omits_it() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.plugins.wasm.enabled, "absent block → default ON");
    }

    #[test]
    fn plugins_wasm_disabled_via_yaml_round_trips() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nplugins:\n  wasm:\n    enabled: false\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.plugins.wasm.enabled, "operator override took effect");
    }

    #[test]
    fn plugins_block_serialises_with_snake_case_fields() {
        // Wire form pin — the wizard + docs use these exact keys.
        let cfg = FreedomConfig {
            operator_id: Some("alice".to_string()),
            plugins: PluginsConfig {
                wasm: WasmPluginsConfig {
                    enabled: false,
                    activations: std::collections::BTreeMap::new(),
                    pinned_hashes: std::collections::BTreeMap::new(),
                    require_all_pinned: false,
                    ..Default::default()
                },
            },
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        assert!(yaml.contains("plugins:"));
        assert!(yaml.contains("wasm:"));
        assert!(yaml.contains("enabled: false"));
    }

    #[test]
    fn rollback_round_trips_through_yaml() {
        // Backward compat: freedom.yaml without a `rollback:` block
        // inherits the default config.
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.rollback.should_capture("config_write"));
        // And with an explicit block, operator can shrink or extend.
        let path2 = write_yaml(
            dir.path(),
            "operator_id: alice\nrollback:\n  capture_kinds: [sql_mutation, file_write]\n  max_snapshot_bytes: 32768\n",
        );
        let cfg2 = FreedomConfig::load_from_path(&path2).unwrap();
        assert!(cfg2.rollback.should_capture("sql_mutation"));
        assert!(cfg2.rollback.should_capture("file_write"));
        assert!(!cfg2.rollback.should_capture("config_write"));
        assert_eq!(cfg2.rollback.max_snapshot_bytes, 32_768);
    }

    // ── R-02 Phase 4c — DreamingConfig serde wiring ──────────────────

    #[test]
    fn dreaming_config_default_is_off() {
        let cfg = DreamingConfig::default();
        assert!(!cfg.enabled, "Phase 4c task is OFF by default");
        assert!(cfg.interval_secs.is_none());
        assert!(cfg.window_secs.is_none());
        assert!(cfg.max_events.is_none());
        assert!(!cfg.summarize_themes);
        assert!(
            !cfg.merge_cross_themes,
            "SPEC-12 cross-theme merge is opt-in"
        );
    }

    #[test]
    fn dreaming_merge_cross_themes_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "dreaming:\n  merge_cross_themes: true\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.dreaming.merge_cross_themes);
    }

    #[test]
    fn dreaming_section_absent_loads_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.dreaming.enabled);
        assert!(cfg.dreaming.interval_secs.is_none());
    }

    #[test]
    fn dreaming_enabled_with_custom_interval_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\n\
                    dreaming:\n  \
                    enabled: true\n  \
                    interval_secs: 3600\n  \
                    window_secs: 86400\n  \
                    max_events: 100\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.dreaming.enabled);
        assert_eq!(cfg.dreaming.interval_secs, Some(3600));
        assert_eq!(cfg.dreaming.window_secs, Some(86_400));
        assert_eq!(cfg.dreaming.max_events, Some(100));
    }

    #[test]
    fn dreaming_partial_block_inherits_defaults() {
        let dir = tempfile::tempdir().unwrap();
        // Operator sets only `enabled: true` — rest fall through to
        // None which means downstream uses the task's DEFAULT_*.
        let yaml = "dreaming:\n  enabled: true\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.dreaming.enabled);
        assert!(cfg.dreaming.interval_secs.is_none());
        assert!(cfg.dreaming.window_secs.is_none());
        assert!(cfg.dreaming.max_events.is_none());
    }

    // ── C-16 proactive: enabled (Session 21) ────────────────────

    #[test]
    fn proactive_config_default_is_off() {
        // AGENTER hard rule drift guard — "no destructive auto-
        // action without operator GO per command". A future
        // refactor flipping the default to true would surface here.
        let cfg = ProactiveConfig::default();
        assert!(!cfg.enabled);
    }

    #[test]
    fn proactive_section_absent_loads_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.proactive.enabled);
    }

    #[test]
    fn proactive_enabled_true_round_trips_via_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\nproactive:\n  enabled: true\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.proactive.enabled);
    }

    // ── SC-10 per-model download policy ───────────────────────────────
    #[test]
    fn sc10_model_download_allowed_falls_back_to_global_flag() {
        let mut u = UpdaterConfig::default();
        assert!(u.model_download_policy.is_empty());
        // Global true (default) ⇒ any model allowed.
        assert!(u.model_download_allowed("clip", None));
        // Global false ⇒ any model blocked when no per-model entry.
        u.allow_huggingface_downloads = false;
        assert!(!u.model_download_allowed("clip", None));
    }

    #[test]
    fn sc10_per_model_entry_overrides_global_both_directions() {
        let mut u = UpdaterConfig::default();
        // Block one model on an otherwise-open install.
        u.allow_huggingface_downloads = true;
        u.model_download_policy.insert("whisper".into(), false);
        assert!(!u.model_download_allowed("whisper", None));
        assert!(u.model_download_allowed("clip", None)); // unlisted ⇒ global true
        // Permit one model on an otherwise air-gapped install.
        u.allow_huggingface_downloads = false;
        u.model_download_policy.clear();
        u.model_download_policy.insert("clip".into(), true);
        assert!(u.model_download_allowed("clip", None));
        assert!(!u.model_download_allowed("whisper", None)); // unlisted ⇒ global false
    }

    #[test]
    fn sc10_model_download_policy_round_trips_via_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\nupdater:\n  model_download_policy:\n    whisper: false\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(
            cfg.updater.model_download_policy.get("whisper"),
            Some(&false)
        );
        assert!(!cfg.updater.model_download_allowed("whisper", None));
        // The actual run_pull call site passes the FULL repo string + the
        // short name — a `whisper: false` policy entry MUST still block it
        // (the high-sev gate-bypass regression guard).
        assert!(
            !cfg.updater
                .model_download_allowed("openai/whisper-large-v3-turbo", Some("whisper"))
        );
        assert!(
            cfg.updater
                .check_model_download("openai/whisper-large-v3-turbo", Some("whisper"))
                .is_err()
        );
    }

    #[test]
    fn sc10_short_name_policy_blocks_full_repo_string() {
        // The call site passes (full_repo, Some(short_name)); the operator
        // writes the short name. Either identifier must match the policy.
        let mut u = UpdaterConfig::default();
        u.allow_huggingface_downloads = true; // global open
        u.model_download_policy.insert("whisper".into(), false);
        assert!(!u.model_download_allowed("openai/whisper-large-v3-turbo", Some("whisper")));
        // Different model, name not in policy ⇒ global true.
        assert!(u.model_download_allowed("openai/clip-vit-base-patch32", Some("clip")));
        // check_model_download surfaces the per-model error, not the global.
        let err = u
            .check_model_download("openai/whisper-large-v3-turbo", Some("whisper"))
            .unwrap_err();
        assert!(err.contains("per-model policy"), "got: {err}");
    }

    // ── AR-03 (Session 24) hook_chain per-stage policy ────────────────

    #[test]
    fn ar_03_hook_chain_section_absent_returns_lenient_default() {
        // No section in freedom.yaml → every stage is lenient
        // (fail_fast=false). Back-compat with every existing install.
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.hook_chain.is_empty());
        for stage in [
            crate::hooks::stages::HookStage::PreProviderCall,
            crate::hooks::stages::HookStage::PreChannelIngress,
            crate::hooks::stages::HookStage::PostProviderCall,
        ] {
            assert!(
                !cfg.fail_fast_for_stage(stage),
                "default for {} must be lenient",
                stage.as_str(),
            );
        }
    }

    #[test]
    fn ar_03_hook_chain_fail_fast_round_trips_via_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\n\
                    hook_chain:\n  \
                      pre_provider_call:\n    \
                        fail_fast: true\n  \
                      post_provider_call:\n    \
                        fail_fast: false\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(
            cfg.fail_fast_for_stage(crate::hooks::stages::HookStage::PreProviderCall),
            "pre_provider_call opted into fail_fast",
        );
        assert!(
            !cfg.fail_fast_for_stage(crate::hooks::stages::HookStage::PostProviderCall),
            "post_provider_call explicitly opted out",
        );
        // Stage not mentioned in yaml → default lenient.
        assert!(
            !cfg.fail_fast_for_stage(crate::hooks::stages::HookStage::PreChannelIngress),
            "absent stage → lenient default",
        );
    }
}
