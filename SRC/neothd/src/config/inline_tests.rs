//! Inline tests extracted from `config/mod.rs`.

#[cfg(test)]
mod config_defaults_tests {
    use super::super::*;

    #[test]
    fn omi_config_defaults_off_and_local() {
        // OMI-MULTIMODAL-01 — default OFF and selects the supported Developer
        // API path; every media/privacy surface has an explicit safe default.
        let d = OmiConfig::default();
        assert!(!d.enabled);
        assert_eq!(d.mode, OmiIngestMode::DeveloperApi);
        assert_eq!(d.endpoint, crate::installers::omi::DEFAULT_OMI_ENDPOINT);
        assert!(!d.allow_cloud_api);
        assert_eq!(d.poll_interval_secs, 30);
        assert!((d.confidence_threshold - 0.75).abs() < 1e-6);
        assert_eq!(d.listen_addr, "127.0.0.1:8003");
        assert_eq!(d.initial_lookback_secs, 86_400);
        assert_eq!(d.max_conversations_per_poll, 100);
        assert!(!d.retain_transcripts);
        assert!(!d.audio_enabled);
        assert!(!d.visual_enabled);
        assert!(!d.video_enabled);
        assert!(d.create_actions);
        assert!(d.seed_groundtruth);
        assert!(d.summary_enabled);
        assert!(!d.allow_cloud_summary);
        assert_eq!(d.retention_days, 30);
        assert_eq!(d.max_audio_bytes_per_stream, 64 * 1024 * 1024);
        assert_eq!(d.max_image_bytes, 16 * 1024 * 1024);
        assert_eq!(d.max_connections, 4);
        assert_eq!(d.max_active_calls, 4);
        assert_eq!(d.idle_timeout_secs, 120);
        assert!(d.allowed_uids.is_empty());
        d.validate().expect("defaults must be valid");

        let absent: FreedomConfig = serde_yaml::from_str("operator_id: a\n").expect("parse");
        assert!(!absent.omi.enabled);
        let old_yaml: FreedomConfig = serde_yaml::from_str(
            "operator_id: a\nomi:\n  enabled: true\n  endpoint: http://127.0.0.1:9999\n",
        )
        .expect("parse");
        assert!(old_yaml.omi.enabled);
        assert_eq!(old_yaml.omi.endpoint, "http://127.0.0.1:9999");
        assert_eq!(old_yaml.omi.mode, OmiIngestMode::DeveloperApi);
        assert!(!old_yaml.omi.allow_cloud_api);
        assert!(!old_yaml.omi.audio_enabled);
        assert!(old_yaml.omi.create_actions);
        assert!(old_yaml.omi.seed_groundtruth);

        let encoded = serde_yaml::to_string(&old_yaml.omi).expect("serialize OMI config");
        let decoded: OmiConfig = serde_yaml::from_str(&encoded).expect("round-trip OMI config");
        assert_eq!(decoded, old_yaml.omi);
    }

    #[test]
    fn omi_ingest_mode_helpers_and_serde_are_pinned() {
        assert!(OmiIngestMode::DeveloperApi.polls());
        assert!(!OmiIngestMode::DeveloperApi.listens());
        assert!(!OmiIngestMode::NativeIngest.polls());
        assert!(OmiIngestMode::NativeIngest.listens());
        assert!(OmiIngestMode::Both.polls());
        assert!(OmiIngestMode::Both.listens());
        assert!(OmiIngestMode::LegacyMemories.polls());
        assert!(!OmiIngestMode::LegacyMemories.listens());
        assert_eq!(
            serde_yaml::to_string(&OmiIngestMode::NativeIngest)
                .expect("serialize mode")
                .trim(),
            "native_ingest"
        );
    }

    #[test]
    fn omi_config_validation_rejects_unsafe_and_zero_bounds() {
        let mut cfg = OmiConfig::default();
        cfg.endpoint = "https://api.omi.me".to_string();
        assert!(cfg.validate().is_err(), "cloud polling endpoint must fail");

        cfg.allow_cloud_api = true;
        cfg.validate()
            .expect("explicit cloud Developer API opt-in must pass");

        cfg.mode = OmiIngestMode::LegacyMemories;
        assert!(
            cfg.validate().is_err(),
            "legacy memories must remain local even with cloud opt-in"
        );

        let mut cfg = OmiConfig::default();
        cfg.listen_addr = "0.0.0.0:8003".to_string();
        assert!(cfg.validate().is_err(), "wildcard listener must fail");

        let mut cfg = OmiConfig::default();
        cfg.listen_addr = "127.0.0.1:0".to_string();
        assert!(cfg.validate().is_err(), "zero port must fail");

        let zero_cases: &[fn(&mut OmiConfig)] = &[
            |c| c.poll_interval_secs = 0,
            |c| c.confidence_threshold = 0.0,
            |c| c.initial_lookback_secs = 0,
            |c| c.max_conversations_per_poll = 0,
            |c| c.retention_days = 0,
            |c| c.max_audio_bytes_per_stream = 0,
            |c| c.max_image_bytes = 0,
            |c| c.max_connections = 0,
            |c| c.max_active_calls = 0,
            |c| c.idle_timeout_secs = 0,
        ];
        for make_invalid in zero_cases {
            let mut cfg = OmiConfig::default();
            make_invalid(&mut cfg);
            assert!(cfg.validate().is_err(), "zero bound must fail: {cfg:?}");
        }

        let mut cfg = OmiConfig::default();
        cfg.confidence_threshold = f32::NAN;
        assert!(cfg.validate().is_err(), "NaN confidence must fail");

        let mut cfg = OmiConfig::default();
        cfg.max_active_calls = 5;
        let error = cfg.validate().expect_err("more than four calls must fail");
        assert!(
            error.contains("between 1 and 4"),
            "operator-facing hard-cap error must name the supported range: {error}"
        );

        let mut cfg = OmiConfig::default();
        cfg.allowed_uids = vec!["".to_string()];
        assert!(cfg.validate().is_err(), "blank UID must fail");

        let mut cfg = OmiConfig::default();
        cfg.allowed_uids = vec!["device-a".to_string(), "device-a".to_string()];
        assert!(cfg.validate().is_err(), "duplicate UID must fail");
    }

    #[test]
    fn omi_enabled_surfaces_require_their_dedicated_credentials() {
        use crate::config::credentials::Credentials;
        use crate::secret::SecretString;

        let mut cfg = OmiConfig {
            enabled: true,
            ..OmiConfig::default()
        };
        assert!(
            cfg.validate_with_credentials(&Credentials::default())
                .is_err()
        );

        let developer = Credentials {
            omi_developer_api_key: Some(SecretString::from("omi_dev_test")),
            ..Credentials::default()
        };
        cfg.validate_with_credentials(&developer)
            .expect("Developer API key satisfies Developer API mode");

        cfg.mode = OmiIngestMode::NativeIngest;
        assert!(cfg.validate_with_credentials(&developer).is_err());
        let native = Credentials {
            omi_ingest_token: Some(SecretString::from("local-ingest-token-at-least-32-bytes")),
            ..Credentials::default()
        };
        cfg.validate_with_credentials(&native)
            .expect("ingest token satisfies native mode");

        cfg.mode = OmiIngestMode::Both;
        let both = Credentials {
            omi_developer_api_key: Some(SecretString::from("omi_dev_test")),
            omi_ingest_token: Some(SecretString::from("local-ingest-token-at-least-32-bytes")),
            ..Credentials::default()
        };
        cfg.validate_with_credentials(&both)
            .expect("both mode requires and accepts both dedicated secrets");

        cfg.mode = OmiIngestMode::LegacyMemories;
        cfg.validate_with_credentials(&Credentials::default())
            .expect("legacy local compatibility remains credential-free");

        cfg.enabled = false;
        cfg.mode = OmiIngestMode::Both;
        cfg.validate_with_credentials(&Credentials::default())
            .expect("disabled OMI must not force unused credentials");
    }

    #[test]
    fn omi_multimodal_controls_survive_the_real_config_load_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            concat!(
                "operator_id: reload-test\n",
                "omi:\n",
                "  enabled: true\n",
                "  mode: both\n",
                "  endpoint: https://api.omi.me\n",
                "  allow_cloud_api: true\n",
                "  listen_addr: 192.168.1.40:8003\n",
                "  retain_transcripts: true\n",
                "  audio_enabled: true\n",
                "  visual_enabled: true\n",
                "  video_enabled: true\n",
                "  allow_cloud_summary: true\n",
                "  allowed_uids: [device-a, device-b]\n",
            ),
        )
        .unwrap();

        let loaded = FreedomConfig::load_from_path(&path).expect("real config load path");
        assert_eq!(loaded.omi.mode, OmiIngestMode::Both);
        assert!(loaded.omi.allow_cloud_api);
        assert_eq!(loaded.omi.listen_addr, "192.168.1.40:8003");
        assert!(loaded.omi.retain_transcripts);
        assert!(loaded.omi.audio_enabled);
        assert!(loaded.omi.visual_enabled);
        assert!(loaded.omi.video_enabled);
        assert!(loaded.omi.allow_cloud_summary);
        assert_eq!(
            loaded.omi.allowed_uids,
            vec!["device-a".to_string(), "device-b".to_string()]
        );
        loaded.omi.validate().expect("reloaded OMI config is valid");
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
    fn companion_p2p_requires_loopback_http_consumer_on_real_load_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: p2p-test\ncompanion:\n  enabled: false\n  p2p_enabled: true\n",
        )
        .unwrap();

        let error = FreedomConfig::load_from_path(&path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("companion.p2p_enabled requires companion.enabled=true"),
            "unexpected load error: {error:#}"
        );

        std::fs::write(
            &path,
            "operator_id: p2p-test\ncompanion:\n  enabled: true\n  p2p_enabled: true\n",
        )
        .unwrap();
        FreedomConfig::load_from_path(&path).expect("fully wired companion config must load");
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
mod ssh_secret_boundary_tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::super::FreedomConfig;
    use crate::secret::SecretString;
    use crate::transport::ssh_config::{SshAuth, SshEndpoint, SshTunnelConfig};

    fn secret_tunnel() -> SshTunnelConfig {
        SshTunnelConfig {
            endpoint: SshEndpoint {
                host: "bastion.example".into(),
                port: 22,
                username: "alex".into(),
                auth: SshAuth::PrivateKey {
                    path: PathBuf::from("/home/alex/.ssh/id_ed25519"),
                    passphrase: Some(SecretString::from("private-passphrase")),
                },
            },
            remote_host: "127.0.0.1".into(),
            remote_port: 5432,
            local_port: 0,
            jump_hosts: vec![SshEndpoint {
                host: "jump.example".into(),
                port: 22,
                username: "alex".into(),
                auth: SshAuth::Password(SecretString::from("jump-password")),
            }],
            max_retries: 5,
            retry_delay: Duration::from_secs(2),
        }
    }

    #[test]
    fn freedom_serialization_never_contains_ssh_authority_or_secrets() {
        let mut config = FreedomConfig::default();
        config.ssh_tunnels = vec![secret_tunnel()];

        for yaml in [
            serde_yaml::to_string(&config).expect("generic FreedomConfig serialization"),
            config
                .public_yaml()
                .expect("public FreedomConfig rendering"),
        ] {
            assert!(!yaml.contains("ssh_tunnels"));
            assert!(!yaml.contains("private-passphrase"));
            assert!(!yaml.contains("jump-password"));
            assert!(!yaml.contains("bastion.example"));
        }
    }
}

#[cfg(test)]
mod custom_autonomy_config_tests {
    use super::super::FreedomConfig;
    use crate::permissions::{ActionKind, AutonomyLevel, CustomDecision};

    #[test]
    fn missing_custom_policy_defaults_to_standard_baseline_map() {
        let cfg: FreedomConfig = serde_yaml::from_str("autonomy: custom\n").unwrap();
        assert_eq!(cfg.autonomy, AutonomyLevel::Custom);
        assert!(cfg.custom_autonomy.overrides.is_empty());
    }

    #[test]
    fn nested_custom_policy_deserializes_and_rejects_invalid_wire_values() {
        let cfg: FreedomConfig = serde_yaml::from_str(
            "autonomy: custom\ncustom_autonomy:\n  overrides:\n    external_http_request: deny\n",
        )
        .unwrap();
        assert_eq!(
            cfg.custom_autonomy
                .overrides
                .get(&ActionKind::ExternalHttpRequest),
            Some(&CustomDecision::Deny)
        );
        assert!(
            serde_yaml::from_str::<FreedomConfig>(
                "custom_autonomy:\n  overrides:\n    unknown_action: allow\n"
            )
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<FreedomConfig>(
                "custom_autonomy:\n  overrides:\n    read: maybe\n"
            )
            .is_err()
        );
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

    fn diagnostic_legacy_ssh_yaml(legacy_endpoint: &str) -> String {
        format!(
            "operator_id: alex\n\
             ssh_tunnels:\n\
             \u{20}\u{20}- endpoint:\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}host: {legacy_endpoint}\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}username: alex\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}auth:\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}password: legacy-private\n\
             \u{20}\u{20}\u{20}\u{20}remote_host: 127.0.0.1\n\
             \u{20}\u{20}\u{20}\u{20}remote_port: 5432\n"
        )
    }

    fn diagnostic_keychain_tunnel() -> crate::transport::ssh_config::SshTunnelConfig {
        crate::transport::ssh_config::SshTunnelConfig {
            endpoint: crate::transport::ssh_config::SshEndpoint {
                host: "keychain.example".into(),
                port: 22,
                username: "alex".into(),
                auth: crate::transport::ssh_config::SshAuth::Password(
                    crate::secret::SecretString::from("keychain-private"),
                ),
            },
            remote_host: "127.0.0.1".into(),
            remote_port: 5432,
            local_port: 0,
            jump_hosts: Vec::new(),
            max_retries: 5,
            retry_delay: std::time::Duration::from_secs(2),
        }
    }

    #[test]
    fn diagnostic_snapshot_previews_valid_legacy_ssh_without_mutating_files() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), &diagnostic_legacy_ssh_yaml("legacy.example"));
        let before = std::fs::read(&path).unwrap();

        let snapshot = load_runtime_config_diagnostic_snapshot(&path).unwrap();

        assert!(snapshot.config_error.is_none());
        let config = snapshot.config.expect("valid diagnostic config");
        assert_eq!(config.ssh_tunnels.len(), 1);
        assert_eq!(config.ssh_tunnels[0].endpoint.host, "legacy.example");
        assert_eq!(
            snapshot
                .credentials
                .expect("previewed credentials")
                .ssh_tunnels
                .expect("legacy SSH preview")
                .len(),
            1
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!dir.path().join("credentials.yaml").exists());
    }

    #[test]
    fn diagnostic_snapshot_classifies_effective_malformed_legacy_ssh() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alex\nssh_tunnels:\n  - endpoint: definitely-not-a-map\n",
        );
        let before = std::fs::read(&path).unwrap();

        let snapshot = load_runtime_config_diagnostic_snapshot(&path).unwrap();

        assert!(snapshot.config.is_none());
        assert!(
            snapshot
                .config_error
                .as_deref()
                .is_some_and(|error| error.contains("legacy freedom.yaml::ssh_tunnels preview"))
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!dir.path().join("credentials.yaml").exists());
    }

    #[test]
    fn diagnostic_snapshot_dedicated_file_ssh_wins_over_malformed_legacy() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alex\nssh_tunnels:\n  - endpoint: definitely-not-a-map\n",
        );
        let credentials_path = dir.path().join("credentials.yaml");
        credentials::Credentials {
            ssh_tunnels: Some(Vec::new()),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();
        let public_before = std::fs::read(&path).unwrap();
        let private_before = std::fs::read(&credentials_path).unwrap();

        let snapshot = load_runtime_config_diagnostic_snapshot(&path).unwrap();

        assert!(snapshot.config_error.is_none());
        assert!(
            snapshot
                .config
                .expect("dedicated authority keeps config valid")
                .ssh_tunnels
                .is_empty()
        );
        assert_eq!(std::fs::read(&path).unwrap(), public_before);
        assert_eq!(std::fs::read(&credentials_path).unwrap(), private_before);
    }

    #[test]
    fn diagnostic_snapshot_keychain_ssh_wins_over_legacy_read_only() {
        use crate::config::keychain::SecretStore as _;

        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            &format!(
                "secrets_backend: keychain\n{}",
                diagnostic_legacy_ssh_yaml("legacy.example")
            ),
        );
        let public_before = std::fs::read(&path).unwrap();
        let store = keychain::InMemorySecretStore::default();
        let authority = credentials::Credentials {
            ssh_tunnels: Some(vec![diagnostic_keychain_tunnel()]),
            ..Default::default()
        };
        store
            .set(
                "ssh_tunnels",
                &keychain::ssh_tunnels_secret(&authority).unwrap().unwrap(),
            )
            .unwrap();

        let snapshot =
            load_runtime_config_diagnostic_snapshot_using_store(&path, Some(&store)).unwrap();

        assert!(snapshot.config_error.is_none());
        let config = snapshot.config.expect("keychain-backed config");
        assert_eq!(config.ssh_tunnels.len(), 1);
        assert_eq!(config.ssh_tunnels[0].endpoint.host, "keychain.example");
        assert_eq!(std::fs::read(&path).unwrap(), public_before);
        assert!(!dir.path().join("credentials.yaml").exists());
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
    fn load_or_default_defaults_only_for_a_missing_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");

        let config = FreedomConfig::load_from_path_or_default(&path).unwrap();

        assert_eq!(
            serde_yaml::to_value(config).unwrap(),
            serde_yaml::to_value(FreedomConfig::default()).unwrap()
        );
    }

    #[test]
    fn load_or_default_rejects_malformed_existing_config() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: [unterminated\n");
        let before = std::fs::read(&path).unwrap();

        let error = FreedomConfig::load_from_path_or_default(&path).unwrap_err();

        assert!(format!("{error:#}").contains("parse YAML"));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "failed load must preserve the operator config as evidence"
        );
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
        assert!(
            cfg.profile.communication.enabled,
            "local communication adaptation is independent from paid LLM fact learning"
        );
        assert_eq!(cfg.profile.communication.min_observations, 5);
        assert_eq!(cfg.profile.communication.min_distinct_sessions, 3);
        assert_eq!(
            cfg.profile.communication.prompt_export,
            CommunicationPromptExport::AccommodationsOnly
        );
        assert!(!cfg.profile.communication.cluster_sync);
    }

    #[test]
    fn communication_profile_policy_round_trips_and_validates() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               communication:\n    \
                 enabled: false\n    \
                 min_observations: 8\n    \
                 min_distinct_sessions: 4\n    \
                 min_confidence: 0.8\n    \
                 full_auto_min_observations: 12\n    \
                 full_auto_min_distinct_sessions: 6\n    \
                 full_auto_min_confidence: 0.9\n    \
                 prompt_export: none\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.profile.communication.enabled);
        assert_eq!(cfg.profile.communication.min_observations, 8);
        assert_eq!(cfg.profile.communication.min_distinct_sessions, 4);
        assert_eq!(
            cfg.profile.communication.prompt_export,
            CommunicationPromptExport::None
        );
    }

    #[test]
    fn communication_profile_rejects_weaker_full_auto_thresholds() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               communication:\n    \
                 min_observations: 10\n    \
                 full_auto_min_observations: 5\n",
        );
        let error = FreedomConfig::load_from_path(&path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("full_auto_min_observations must be >= min_observations")
        );
    }

    #[test]
    fn communication_profile_rejects_unreachable_or_non_finite_thresholds() {
        let mut policy = CommunicationProfileConfig {
            min_observations: 3,
            min_distinct_sessions: 4,
            ..CommunicationProfileConfig::default()
        };
        assert_eq!(
            policy.validate().unwrap_err(),
            "min_distinct_sessions must be <= min_observations"
        );

        policy = CommunicationProfileConfig {
            min_confidence: f32::NAN,
            ..CommunicationProfileConfig::default()
        };
        assert_eq!(
            policy.validate().unwrap_err(),
            "min_confidence must be within 0.5..=1.0"
        );

        policy = CommunicationProfileConfig {
            full_auto_min_observations: 40,
            max_evidence_per_dimension: 32,
            ..CommunicationProfileConfig::default()
        };
        assert_eq!(
            policy.validate().unwrap_err(),
            "max_evidence_per_dimension must be >= full_auto_min_observations"
        );

        policy = CommunicationProfileConfig {
            full_auto_min_confidence: f32::NAN,
            ..CommunicationProfileConfig::default()
        };
        assert_eq!(
            policy.validate().unwrap_err(),
            "full_auto_min_confidence must be within min_confidence..=1.0"
        );
    }

    #[test]
    fn communication_profile_rejects_unwired_cluster_sync() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               communication:\n    \
                 cluster_sync: true\n",
        );
        let error = FreedomConfig::load_from_path(&path).unwrap_err();
        assert!(error.to_string().contains("cluster_sync is not available"));
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
        assert_eq!(cfg.channel, ReleaseChannel::Stable);
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
        assert_eq!(cfg.auto_update.channel, ReleaseChannel::Stable);
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
        assert_eq!(cfg.auto_update.channel, ReleaseChannel::Rc);
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
                channel: ReleaseChannel::Stable,
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

    #[test]
    fn auto_update_config_rejects_unknown_channel_at_parse_time() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nauto_update:\n  channel: beta\n",
        );
        let error = FreedomConfig::load_from_path(&path).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("unknown variant") || error.contains("stable"));
    }

    #[test]
    fn auto_update_config_rejects_target_outside_release_matrix() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nauto_update:\n  target_triple: riscv64gc-unknown-linux-gnu\n",
        );
        let error = FreedomConfig::load_from_path(&path).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("unsupported auto_update.target_triple"));
        assert!(error.contains("x86_64-unknown-linux-gnu"));
    }

    #[test]
    fn auto_update_config_rejects_invalid_release_repo() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nauto_update:\n  repo: example/fork/releases\n",
        );
        let error = FreedomConfig::load_from_path(&path).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("invalid auto_update.repo"));
        assert!(error.contains("owner/repo"));
    }

    // ── GOLD-FEAT-06 — SwarmConfig live wiring ───────────────────────────

    #[test]
    fn swarm_config_defaults_and_round_trips() {
        let defaults = SwarmConfig::default();
        assert!(defaults.enabled);
        assert_eq!(defaults.interval_secs, 30);
        assert_eq!(defaults.stale_after_secs, 300);
        assert_eq!(
            defaults.interval_duration(),
            std::time::Duration::from_secs(30)
        );

        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nswarm:\n  enabled: false\n  interval_secs: 45\n  stale_after_secs: 900\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(
            cfg.swarm,
            SwarmConfig {
                enabled: false,
                interval_secs: 45,
                stale_after_secs: 900,
            }
        );
        assert_eq!(
            cfg.swarm.interval_duration(),
            std::time::Duration::from_secs(45)
        );
    }

    #[test]
    fn swarm_config_rejects_non_positive_intervals() {
        let dir = tempdir().unwrap();
        for (name, body) in [
            (
                "zero-interval.yaml",
                "operator_id: alice\nswarm:\n  interval_secs: 0\n",
            ),
            (
                "zero-stale.yaml",
                "operator_id: alice\nswarm:\n  stale_after_secs: 0\n",
            ),
            (
                "negative-stale.yaml",
                "operator_id: alice\nswarm:\n  stale_after_secs: -1\n",
            ),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, body).unwrap();
            let error = FreedomConfig::load_from_path(&path)
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid swarm config"), "{error}");
            assert!(error.contains("greater than zero"), "{error}");
        }
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
        assert_eq!(cfg.cron_at, "03:00");
        assert!(cfg.timezone.is_none());
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
        let path = write_yaml(dir.path(), "dream:\n  merge_cross_themes: true\n");
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
    fn dream_canonical_schedule_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\n\
                    dream:\n  \
                    cron_enabled: true\n  \
                    cron_at: \"04:15\"\n  \
                    timezone: Europe/Berlin\n  \
                    window_secs: 86400\n  \
                    max_events: 100\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.dreaming.enabled);
        assert_eq!(cfg.dreaming.cron_at, "04:15");
        assert_eq!(cfg.dreaming.timezone.as_deref(), Some("Europe/Berlin"));
        assert_eq!(cfg.dreaming.window_secs, Some(86_400));
        assert_eq!(cfg.dreaming.max_events, Some(100));
    }

    #[test]
    fn legacy_dreaming_root_and_enabled_alias_load() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "dreaming:\n  enabled: true\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.dreaming.enabled);
        assert_eq!(cfg.dreaming.cron_at, "03:00");
        assert!(cfg.dreaming.interval_secs.is_none());
        assert!(cfg.dreaming.window_secs.is_none());
        assert!(cfg.dreaming.max_events.is_none());
    }

    #[test]
    fn dream_alias_duplicates_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root_duplicate = write_yaml(
            dir.path(),
            "dream:\n  cron_enabled: true\ndreaming:\n  enabled: true\n",
        );
        assert!(FreedomConfig::load_from_path(&root_duplicate).is_err());

        let field_duplicate = write_yaml(
            dir.path(),
            "dream:\n  cron_enabled: true\n  enabled: true\n",
        );
        assert!(FreedomConfig::load_from_path(&field_duplicate).is_err());
    }

    #[test]
    fn dream_schedule_validation_rejects_bad_time_timezone_and_bounds() {
        for body in [
            "dream:\n  cron_at: \"3:00\"\n",
            "dream:\n  cron_at: \"24:00\"\n",
            "dream:\n  timezone: Mars/Olympus\n",
            "dream:\n  window_secs: 0\n",
            "dream:\n  max_events: 0\n",
            "dream:\n  interval_secs: 3600\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = write_yaml(dir.path(), body);
            assert!(
                FreedomConfig::load_from_path(&path).is_err(),
                "invalid dream config unexpectedly loaded: {body}"
            );
        }
    }

    #[test]
    fn legacy_dream_update_publishes_one_canonical_key_and_preserves_unknowns() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "dreaming:\n  enabled: true\n  interval_secs: 86400\n  future_knob: keep-me\n",
        );
        FreedomConfig::update_at(&path, |config| {
            config.dreaming.enabled = false;
            Ok(())
        })
        .unwrap();
        let body = std::fs::read_to_string(path).unwrap();
        assert!(body.contains("dream:"));
        assert!(body.contains("cron_enabled: false"));
        assert!(body.contains("future_knob: keep-me"));
        assert!(!body.contains("dreaming:"));
        assert!(!body.contains("interval_secs:"));
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

    #[test]
    fn proactive_validation_bounds_hours_and_idle_nanoseconds() {
        let mut cfg = ProactiveConfig::default();
        cfg.quiet_hours_utc = Some([24, 7]);
        assert!(cfg.validate().is_err());

        cfg.quiet_hours_utc = Some([22, 7]);
        cfg.idle_only_window_secs = ProactiveConfig::MAX_IDLE_WINDOW_SECS + 1;
        assert!(cfg.validate().is_err());

        cfg.idle_only_window_secs = ProactiveConfig::MAX_IDLE_WINDOW_SECS;
        cfg.validate().unwrap();
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

    // ── GOLD-ADAPT-OH-11 tests ────────────────────────────────────────────────

    /// OH-11 Test 1 — `chat_onboarding_completed` defaults to `true` for old
    /// freedom.yaml files that omit the field. This prevents the first-chat hint
    /// from firing retroactively for existing operators on upgrade.
    #[test]
    fn chat_onboarding_completed_defaults_true_for_old_config() {
        let cfg: FreedomConfig =
            serde_yaml::from_str("operator_id: alice\n").expect("parse minimal config");
        assert!(
            cfg.chat_onboarding_completed,
            "missing field must default to true (default_true fn) so existing operators \
             are not shown the first-chat hint retroactively"
        );
    }

    /// OH-11 Test 2 — explicit `false` in yaml is respected (new wizard run).
    #[test]
    fn chat_onboarding_completed_explicit_false_round_trips() {
        let cfg: FreedomConfig =
            serde_yaml::from_str("operator_id: alice\nchat_onboarding_completed: false\n")
                .expect("parse");
        assert!(
            !cfg.chat_onboarding_completed,
            "explicit false must survive serde round-trip so write_config re-arms the hint"
        );
    }

    /// OH-11 Test 4 — branch condition check: hint is suppressed when flag is true.
    #[test]
    fn first_chat_hint_suppressed_when_flag_true() {
        let cfg: FreedomConfig =
            serde_yaml::from_str("operator_id: alice\nchat_onboarding_completed: true\n")
                .expect("parse");
        // The gate condition in run_chat_with is `!config.chat_onboarding_completed`.
        // When the flag is true the hint must NOT fire — assert the flag is true
        // (i.e. the gate would evaluate to false).
        assert!(
            cfg.chat_onboarding_completed,
            "hint gate must be false (suppressed) when chat_onboarding_completed=true"
        );
    }

    /// OH-11 Test 3 — serialized public-config round-trip for the flag.
    /// Proves the schema path: set flag true → serialize → reload → assert true.
    #[test]
    fn chat_onboarding_completed_flag_persists_via_save_reload() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().expect("tempdir");
        // Build a config with the flag set to true and write it.
        let mut cfg = FreedomConfig {
            operator_id: Some("bob".into()),
            chat_onboarding_completed: true,
            ..Default::default()
        };
        // Write manually to the injected temp path without process-global HOME
        // side effects; update_at behaviour has dedicated lossless RMW tests.
        let path = dir.path().join("freedom.yaml");
        let body = serde_yaml::to_string(&cfg).expect("serialize");
        std::fs::File::create(&path)
            .expect("create")
            .write_all(body.as_bytes())
            .expect("write");
        // Reload and assert flag is preserved.
        let reloaded = FreedomConfig::load_from_path(&path).expect("load");
        assert!(
            reloaded.chat_onboarding_completed,
            "chat_onboarding_completed=true must survive save→reload round-trip"
        );
        // Also verify false round-trips (write_config path).
        cfg.chat_onboarding_completed = false;
        let body2 = serde_yaml::to_string(&cfg).expect("serialize false");
        std::fs::write(&path, body2).expect("write false");
        let reloaded2 = FreedomConfig::load_from_path(&path).expect("load false");
        assert!(
            !reloaded2.chat_onboarding_completed,
            "chat_onboarding_completed=false must survive save→reload (write_config re-arms hint)"
        );
    }

    // ── FIX-4: resolve_model_alias single-level contract ─────────────────────

    #[test]
    fn resolve_model_alias_maps_known_alias() {
        let mut cfg = FreedomConfig::default();
        cfg.models_aliases
            .insert("@fast".to_string(), "gpt-5.5".to_string());
        assert_eq!(cfg.resolve_model_alias("@fast"), "gpt-5.5");
    }

    #[test]
    fn resolve_model_alias_unknown_passes_through() {
        let mut cfg = FreedomConfig::default();
        cfg.models_aliases
            .insert("@fast".to_string(), "gpt-5.5".to_string());
        // Unknown key goes through verbatim — no error at this layer.
        assert_eq!(cfg.resolve_model_alias("gpt-4o"), "gpt-4o");
    }

    #[test]
    fn resolve_model_alias_single_level_only() {
        // Alias→alias chains resolve ONE level; the intermediate is NOT
        // recursively expanded — it lands at the provider as-is.
        let mut cfg = FreedomConfig::default();
        cfg.models_aliases
            .insert("@a".to_string(), "@b".to_string());
        cfg.models_aliases
            .insert("@b".to_string(), "real-model".to_string());
        // @a → @b (one step); @b is NOT further resolved here.
        assert_eq!(cfg.resolve_model_alias("@a"), "@b");
    }

    #[test]
    fn resolve_model_alias_key_shadowing_a_real_id_redirects_it() {
        // Documents the honest contract: if an alias key == a real model id
        // the alias WINS (config layer has no catalog access). Operators must
        // use distinct names (e.g. @-prefixed) to avoid this.
        let mut cfg = FreedomConfig::default();
        cfg.models_aliases
            .insert("gpt-5.5".to_string(), "gpt-4o".to_string());
        assert_eq!(
            cfg.resolve_model_alias("gpt-5.5"),
            "gpt-4o",
            "alias key that equals a real id WILL redirect it at the config layer"
        );
    }

    /// GOLD-ADAPT-RMAS-01 — the sidecar config ships default-OFF and
    /// round-trips YAML (absent section = defaults; explicit section
    /// parses every field).
    #[test]
    fn recursive_mas_config_default_is_disabled() {
        let cfg = FreedomConfig::default();
        assert!(!cfg.recursive_mas.enabled, "RMAS must be opt-in");
        assert_eq!(cfg.recursive_mas.style, "sequential_light");
        assert_eq!(cfg.recursive_mas.num_recursive_rounds, 3);
        assert_eq!(cfg.recursive_mas.min_vram_gib, 12);
        assert!(cfg.recursive_mas.sidecar_repo.is_none());
        assert!(cfg.recursive_mas.sidecar_python.is_none());
    }

    #[test]
    fn recursive_mas_config_round_trips_yaml() {
        let yaml = "enabled: true\nstyle: sequential_light\nnum_recursive_rounds: 5\nmin_vram_gib: 24\nsidecar_repo: /opt/rmas\n";
        let parsed: crate::config::RecursiveMasConfig =
            serde_yaml::from_str(yaml).expect("explicit section parses");
        assert!(parsed.enabled);
        assert_eq!(parsed.num_recursive_rounds, 5);
        assert_eq!(parsed.min_vram_gib, 24);
        assert_eq!(
            parsed.sidecar_repo.as_deref(),
            Some(std::path::Path::new("/opt/rmas"))
        );
        // sidecar_python absent → default None survives partial sections.
        assert!(parsed.sidecar_python.is_none());
        let back = serde_yaml::to_string(&parsed).expect("serializes");
        let re: crate::config::RecursiveMasConfig =
            serde_yaml::from_str(&back).expect("round-trips");
        assert_eq!(re, parsed);
    }
}

#[cfg(test)]
mod council_weighting_tests {
    use super::super::*;
    use crate::config::inference::CouncilConfig;

    /// CW-01 / 26c3c903 bug-class pin: absent `council:` yaml block,
    /// empty block, and `CouncilConfig::default()` must yield identical
    /// locality field values.
    #[test]
    fn council_locality_serde_default_matches_rust_default() {
        let rust_default = CouncilConfig::default();

        let absent: FreedomConfig =
            serde_yaml::from_str("operator_id: a\n").expect("parse absent council");
        let empty_block: FreedomConfig = serde_yaml::from_str("operator_id: a\ncouncil: {}\n")
            .expect("parse empty council block");
        let explicit: FreedomConfig = serde_yaml::from_str(
            "operator_id: a\ncouncil:\n  locality_tie_break: true\n  locality_tie_epsilon: 0.05\n  local_score_bonus: 0.0\n",
        )
        .expect("parse explicit locality defaults");

        for (label, cfg) in [
            ("absent", &absent.council),
            ("empty_block", &empty_block.council),
            ("explicit", &explicit.council),
        ] {
            assert_eq!(
                cfg.locality_tie_break, rust_default.locality_tie_break,
                "{label}: locality_tie_break mismatch"
            );
            assert!(
                (cfg.locality_tie_epsilon - rust_default.locality_tie_epsilon).abs() < 1e-9,
                "{label}: locality_tie_epsilon mismatch (got {}, want {})",
                cfg.locality_tie_epsilon,
                rust_default.locality_tie_epsilon
            );
            assert!(
                (cfg.local_score_bonus - rust_default.local_score_bonus).abs() < 1e-9,
                "{label}: local_score_bonus mismatch"
            );
        }

        // pin the concrete default values so regressions are obvious
        assert!(
            rust_default.locality_tie_break,
            "tie_break must default true"
        );
        assert!(
            (rust_default.locality_tie_epsilon - 0.05).abs() < 1e-9,
            "epsilon must default to 0.05"
        );
        assert_eq!(
            rust_default.local_score_bonus, 0.0,
            "bonus must default to 0.0"
        );
    }
}

#[cfg(test)]
mod locked_update_tests {
    use std::sync::{Arc, Barrier};

    use super::super::FreedomConfig;

    fn write_default(path: &std::path::Path) {
        let body = serde_yaml::to_string(&FreedomConfig::default()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn update_at_preserves_malformed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let malformed = b"operator_id: [unterminated\n";
        std::fs::write(&path, malformed).unwrap();

        let err = FreedomConfig::update_at(&path, |cfg| {
            cfg.operator_id = Some("must-not-land".into());
            Ok(())
        })
        .unwrap_err();

        assert!(err.to_string().contains("parse YAML"));
        assert_eq!(std::fs::read(&path).unwrap(), malformed);
    }

    #[test]
    fn raw_update_paths_validate_target_before_publication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        write_default(&path);
        let original = std::fs::read(&path).unwrap();

        let direct_error = super::super::update_raw_freedom_at(&path, |_| {
            Ok(("cluster:\n  listen_port: 0\n".to_string(), ()))
        })
        .unwrap_err();
        assert!(direct_error.to_string().contains("validate transformed"));
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let prepared_error = super::super::prepare_raw_freedom_update(&path, |_| {
            Ok(("cluster:\n  listen_port: 0\n".to_string(), ()))
        })
        .err()
        .expect("invalid prepared target must fail before a plan escapes");
        assert!(prepared_error.to_string().contains("validate prepared"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn update_at_preserves_future_yaml_aliases_and_legacy_inline_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let credentials = b"provider_key: dedicated-secret\nfuture_secret: keep-me\n";
        std::fs::write(
            &path,
            r#"operator_id: old
provider_key: legacy-provider
telegram_token: legacy-telegram
inference:
  left:
    key: legacy-left
    future_slot_field: keep-slot
loop_config:
  enabled: true
  token_budget: 7
  future_loop_field: keep-loop
proactive:
  enabled: false
  future_proactive_field: keep-proactive
future_extension:
  nested: keep-root
"#,
        )
        .unwrap();
        std::fs::write(&credentials_path, credentials).unwrap();

        FreedomConfig::update_at(&path, |config| {
            config.operator_id = Some("new".to_string());
            config.proactive.enabled = true;
            Ok(())
        })
        .unwrap();

        let raw: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["operator_id"].as_str(), Some("new"));
        assert_eq!(raw["proactive"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            raw["future_extension"]["nested"].as_str(),
            Some("keep-root")
        );
        assert_eq!(
            raw["proactive"]["future_proactive_field"].as_str(),
            Some("keep-proactive")
        );
        assert_eq!(
            raw["loop_config"]["future_loop_field"].as_str(),
            Some("keep-loop")
        );
        assert_eq!(
            raw["inference"]["left"]["future_slot_field"].as_str(),
            Some("keep-slot")
        );
        assert_eq!(raw["provider_key"].as_str(), Some("legacy-provider"));
        assert_eq!(raw["telegram_token"].as_str(), Some("legacy-telegram"));
        assert_eq!(
            raw["inference"]["left"]["key"].as_str(),
            Some("legacy-left")
        );
        assert!(raw["loop_config"].get("token_budget").is_none());
        assert_eq!(raw["loop_config"]["tool_call_budget"].as_u64(), Some(7));
        assert_eq!(std::fs::read(&credentials_path).unwrap(), credentials);
    }

    #[test]
    fn prepared_update_cas_rejects_a_newer_generation_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "operator_id: old\nfuture_extension: keep-me\n").unwrap();
        let (prepared, ()) = FreedomConfig::prepare_update_at(&path, |config| {
            config.operator_id = Some("stale-prepared".to_string());
            Ok(())
        })
        .unwrap();

        FreedomConfig::update_at(&path, |config| {
            config.language_primary = Some("de".to_string());
            Ok(())
        })
        .unwrap();
        let before_failed_commit = std::fs::read(&path).unwrap();

        let error = prepared.commit().unwrap_err();
        assert!(error.to_string().contains("changed after review"));
        assert_eq!(std::fs::read(&path).unwrap(), before_failed_commit);
        let raw: serde_yaml::Value = serde_yaml::from_slice(&before_failed_commit).unwrap();
        assert_eq!(raw["operator_id"].as_str(), Some("old"));
        assert_eq!(raw["language_primary"].as_str(), Some("de"));
        assert_eq!(raw["future_extension"].as_str(), Some("keep-me"));
    }

    #[cfg(windows)]
    #[test]
    fn update_at_replaces_a_weak_file_with_process_token_only_dacl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        write_default(&path);

        FreedomConfig::update_at(&path, |cfg| {
            cfg.operator_id = Some("windows-private-update".into());
            Ok(())
        })
        .unwrap();

        crate::wal::win_native::verify_private_dacl(&path).unwrap();
        assert_eq!(
            FreedomConfig::load_from_path(&path)
                .unwrap()
                .operator_id
                .as_deref(),
            Some("windows-private-update")
        );
    }

    #[test]
    fn update_at_serialises_concurrent_read_modify_write_cycles() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("freedom.yaml"));
        write_default(&path);
        let start = Arc::new(Barrier::new(3));

        let operator_path = Arc::clone(&path);
        let operator_start = Arc::clone(&start);
        let operator = std::thread::spawn(move || {
            operator_start.wait();
            for n in 0..16 {
                FreedomConfig::update_at(&operator_path, |cfg| {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    cfg.operator_id = Some(format!("operator-{n}"));
                    Ok(())
                })
                .unwrap();
            }
        });

        let language_path = Arc::clone(&path);
        let language_start = Arc::clone(&start);
        let language = std::thread::spawn(move || {
            language_start.wait();
            for n in 0..16 {
                FreedomConfig::update_at(&language_path, |cfg| {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    cfg.language_primary = Some(format!("lang-{n}"));
                    Ok(())
                })
                .unwrap();
            }
        });

        start.wait();
        operator.join().unwrap();
        language.join().unwrap();

        let final_config = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(final_config.operator_id.as_deref(), Some("operator-15"));
        assert_eq!(final_config.language_primary.as_deref(), Some("lang-15"));
    }
}

#[cfg(test)]
mod cluster_config_tests {
    use super::super::{
        ClusterConfig, ClusterTransport, DEFAULT_CLUSTER_LISTEN_PORT, FreedomConfig,
    };

    #[test]
    fn cluster_defaults_are_typed_and_privacy_gated() {
        let cluster = ClusterConfig::default();
        assert!(!cluster.enabled);
        assert_eq!(cluster.transport, ClusterTransport::Peeroxide);
        assert!(cluster.peers.is_empty());
        assert!(cluster.mdns.enabled);
        assert!(!cluster.policy.announce_on_untrusted_wifi);
        assert!(cluster.policy.trusted_ssids.is_empty());
        assert_eq!(cluster.listen_port, DEFAULT_CLUSTER_LISTEN_PORT);
        cluster.validate().expect("cluster defaults must be valid");
    }

    #[test]
    fn cluster_full_shape_round_trips_through_freedom_config() {
        let yaml = r#"
cluster:
  name: studio
  enabled: true
  transport: iroh
  peers: [peer-a, peer-b]
  mdns:
    enabled: false
  policy:
    announce_on_untrusted_wifi: true
    trusted_ssids: [home]
  listen_port: 4242
"#;
        let config: FreedomConfig = serde_yaml::from_str(yaml).expect("typed cluster parse");
        assert_eq!(config.cluster.name.as_deref(), Some("studio"));
        assert!(config.cluster.enabled);
        assert_eq!(config.cluster.transport, ClusterTransport::Iroh);
        assert_eq!(config.cluster.peers, ["peer-a", "peer-b"]);
        assert!(!config.cluster.mdns.enabled);
        assert!(config.cluster.policy.announce_on_untrusted_wifi);
        assert_eq!(config.cluster.policy.trusted_ssids, ["home"]);
        assert_eq!(config.cluster.listen_port, 4242);
        if cfg!(feature = "cluster-iroh") {
            assert!(
                config.cluster.validate().is_err(),
                "fixture peer ids are deliberately not real iroh endpoint ids"
            );
        } else {
            assert!(
                config
                    .cluster
                    .validate()
                    .unwrap_err()
                    .contains("cluster-iroh")
            );
        }

        let encoded = serde_yaml::to_string(&config).expect("serialize freedom config");
        let decoded: FreedomConfig = serde_yaml::from_str(&encoded).expect("round trip");
        assert_eq!(decoded.cluster.transport, ClusterTransport::Iroh);
        assert_eq!(decoded.cluster.listen_port, 4242);
    }

    #[test]
    fn cluster_rejects_unknown_transport_and_invalid_values() {
        let error = serde_yaml::from_str::<FreedomConfig>("cluster:\n  transport: magic\n")
            .expect_err("unknown transport must not silently select peeroxide");
        assert!(error.to_string().contains("unknown variant"));

        let mut zero_port = ClusterConfig::default();
        zero_port.listen_port = 0;
        assert_eq!(
            zero_port.validate().unwrap_err(),
            "listen_port must be greater than zero"
        );

        let mut blank_peer = ClusterConfig::default();
        blank_peer.peers.push("  ".to_string());
        assert_eq!(
            blank_peer.validate().unwrap_err(),
            "peers must not contain empty endpoint ids"
        );

        let mut unnamed = ClusterConfig::default();
        unnamed.enabled = true;
        assert_eq!(
            unnamed.validate().unwrap_err(),
            "name is required when cluster.enabled is true"
        );
    }
}
