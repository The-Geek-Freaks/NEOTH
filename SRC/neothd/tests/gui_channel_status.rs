//! Headless coverage for the production GUI channel-status parser.
//!
//! This integration target shares the desktop's actual pure-Rust modules by
//! path. It deliberately does not duplicate any parser or spawn Slint, so a
//! core test gate exercises the same account-status and account-test binding
//! code that the desktop will use.

#[path = "../../neothd-gui/src/code_map_impact_controller.rs"]
pub mod code_map_impact_controller;

#[path = "../../neothd-gui/src/gui_action.rs"]
pub mod gui_action;

#[expect(
    clippy::len_without_is_empty,
    reason = "headless import exposes a private desktop module for parser tests"
)]
#[path = "../../neothd-gui/src/panel_logic.rs"]
pub mod panel_logic;

#[test]
fn mapped_pairing_gui_command_parses_with_the_real_cli_for_both_states() {
    use clap::Parser as _;
    use neothd::cli::{ChannelAccountAction, ChannelAction, Cli, Commands, OutputFormat};

    for requested in [true, false] {
        let command = panel_logic::telegram_account_dm_pairing_command(
            std::path::Path::new("neoth"),
            "telegram",
            "ops_b",
            requested,
        )
        .expect("build the production GUI command");
        let parsed =
            Cli::try_parse_from(std::iter::once(command.get_program()).chain(command.get_args()))
                .expect("the real CLI must accept the GUI's enable and disable argv");
        assert!(matches!(parsed.output, OutputFormat::Json));
        match parsed.command {
            Commands::Channel {
                action:
                    ChannelAction::Account(ChannelAccountAction::SetDmPairing {
                        channel,
                        account,
                        enabled,
                    }),
            } => {
                assert_eq!(channel, "telegram");
                assert_eq!(account.as_str(), "ops_b");
                assert_eq!(enabled, requested);
            }
            _ => panic!("GUI command must select the exact account pairing transaction"),
        }
    }
}

#[test]
fn pending_pairing_gui_commands_parse_with_the_real_cli() {
    use clap::Parser as _;
    use neothd::cli::{ChannelAction, ChannelPairingAction, Cli, Commands, OutputFormat};

    let request_id = "0123456789abcdef0123456789abcdef";
    let commands = [
        panel_logic::telegram_pairing_list_command(
            std::path::Path::new("neoth"),
            "telegram",
            "ops_b",
        )
        .expect("build the production GUI list command"),
        panel_logic::telegram_pairing_dismiss_command(
            std::path::Path::new("neoth"),
            "telegram",
            "ops_b",
            request_id,
        )
        .expect("build the production GUI dismiss command"),
    ];

    for command in commands {
        let parsed =
            Cli::try_parse_from(std::iter::once(command.get_program()).chain(command.get_args()))
                .expect("the real CLI must accept the GUI pairing argv");
        assert!(matches!(parsed.output, OutputFormat::Json));
        match parsed.command {
            Commands::Channel {
                action: ChannelAction::Pairing(ChannelPairingAction::List { channel, account }),
            } => {
                assert_eq!(channel, "telegram");
                assert_eq!(account.as_str(), "ops_b");
            }
            Commands::Channel {
                action:
                    ChannelAction::Pairing(ChannelPairingAction::Dismiss {
                        channel,
                        account,
                        request_id: parsed_request,
                    }),
            } => {
                assert_eq!(channel, "telegram");
                assert_eq!(account.as_str(), "ops_b");
                assert_eq!(parsed_request, request_id);
            }
            _ => panic!("GUI command must select an exact Telegram pairing action"),
        }
    }
}

#[test]
fn private_pairing_approval_gui_command_parses_without_secrets_in_argv() {
    use clap::Parser as _;
    use neothd::cli::{ChannelAction, ChannelPairingAction, Cli, Commands, OutputFormat};

    let request_id = "0123456789abcdef0123456789abcdef";
    let code = "ABCDEFGH";
    let command = panel_logic::telegram_pairing_approve_command(
        std::path::Path::new("neoth"),
        "telegram",
        "ops_b",
    )
    .expect("build the production GUI private approval command");
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        !args.iter().any(|arg| arg == request_id || arg == code),
        "request id and pairing code belong only in the private stdin body"
    );
    let parsed =
        Cli::try_parse_from(std::iter::once(command.get_program()).chain(command.get_args()))
            .expect("the real CLI must accept the GUI's hidden approval argv");
    assert!(matches!(parsed.output, OutputFormat::Json));
    match parsed.command {
        Commands::Channel {
            action:
                ChannelAction::Pairing(ChannelPairingAction::ApproveRequest { channel, account }),
        } => {
            assert_eq!(channel, "telegram");
            assert_eq!(account.as_str(), "ops_b");
        }
        _ => panic!("GUI command must select the hidden private approval action"),
    }
}

#[test]
fn private_pairing_approval_body_and_receipt_bind_the_exact_request() {
    let request_id = "0123456789abcdef0123456789abcdef";
    let code = "ABCDEFGH";
    let body = panel_logic::telegram_pairing_approve_body("telegram", "ops_b", request_id, code)
        .expect("valid selected request and sender code form a private body");
    assert!(body.len() <= 1024);
    assert_eq!(
        body.as_slice(),
        br#"{"schema_version":1,"channel":"telegram","account":"ops_b","request_id":"0123456789abcdef0123456789abcdef","code":"ABCDEFGH"}"#
    );
    for invalid_code in [
        "",
        "ABCDEFG",
        "ABCDEFGHI",
        "abcdefgh",
        "ABCDEFG0",
        "ABCD-EFG",
    ] {
        assert!(
            panel_logic::telegram_pairing_approve_body(
                "telegram",
                "ops_b",
                request_id,
                invalid_code
            )
            .is_err(),
            "invalid pairing code must not form a private approval body"
        );
    }
    assert!(
        panel_logic::telegram_pairing_approve_body(
            "telegram",
            "ops_b",
            "0123456789ABCDEF0123456789abcdef",
            code,
        )
        .is_err(),
        "noncanonical request ids cannot form a private approval body"
    );

    assert_eq!(
        panel_logic::parse_telegram_pairing_approved(
            format!(r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}","approved":true}}"#).as_bytes(),
            "ops_b",
            request_id,
        ),
        Some(true)
    );
    for receipt in [
        format!(
            r#"{{"channel":"telegram","account":"ops_a","request_id":"{request_id}","approved":true}}"#
        ),
        format!(
            r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}","approved":false}}"#
        ),
        format!(
            r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}","approved":true,"extra":true}}"#
        ),
        format!(r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}"}}"#),
        format!(
            r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}","approved":"true"}}"#
        ),
    ] {
        assert_eq!(
            panel_logic::parse_telegram_pairing_approved(receipt.as_bytes(), "ops_b", request_id),
            None,
            "only an exact strict private approval receipt is actionable"
        );
    }
}

#[test]
fn legacy_telegram_migration_gui_command_parses_with_the_real_cli() {
    use clap::Parser as _;
    use neothd::cli::{ChannelAction, Cli, Commands, OutputFormat};

    let command = panel_logic::telegram_migrate_legacy_command(
        std::path::Path::new("neoth"),
        "telegram",
        "default",
    )
    .expect("build the production GUI legacy migration command");
    let parsed =
        Cli::try_parse_from(std::iter::once(command.get_program()).chain(command.get_args()))
            .expect("the real CLI must accept the GUI legacy migration argv");
    assert!(matches!(parsed.output, OutputFormat::Json));
    match parsed.command {
        Commands::Channel {
            action: ChannelAction::MigrateLegacy { channel, account },
        } => {
            assert_eq!(channel, "telegram");
            assert_eq!(account.as_str(), "default");
        }
        _ => panic!("GUI command must select the canonical legacy migration action"),
    }
    for (channel, account) in [
        ("slack", "default"),
        ("telegram", ""),
        ("telegram", "DEFAULT"),
    ] {
        assert!(
            panel_logic::telegram_migrate_legacy_command(
                std::path::Path::new("neoth"),
                channel,
                account,
            )
            .is_err(),
            "only canonical Telegram and a canonical destination account can migrate"
        );
    }
}

#[test]
fn legacy_telegram_migration_receipt_binds_all_terminal_fields() {
    let accepted = br#"{"channel":"telegram","account":"default","inbound":"configured_account","account_probe":"available","migrated_legacy_singleton":true}"#;
    assert_eq!(
        panel_logic::parse_telegram_legacy_migrated(accepted, "default"),
        Some(true)
    );
    for receipt in [
        br#"{"channel":"slack","account":"default","inbound":"configured_account","account_probe":"available","migrated_legacy_singleton":true}"#.as_slice(),
        br#"{"channel":"telegram","account":"ops_b","inbound":"configured_account","account_probe":"available","migrated_legacy_singleton":true}"#.as_slice(),
        br#"{"channel":"telegram","account":"default","inbound":"legacy","account_probe":"available","migrated_legacy_singleton":true}"#.as_slice(),
        br#"{"channel":"telegram","account":"default","inbound":"configured_account","account_probe":"unknown","migrated_legacy_singleton":true}"#.as_slice(),
        br#"{"channel":"telegram","account":"default","inbound":"configured_account","account_probe":"available","migrated_legacy_singleton":false}"#.as_slice(),
        br#"{"channel":"telegram","account":"default","inbound":"configured_account","account_probe":"available","migrated_legacy_singleton":true,"extra":true}"#.as_slice(),
        br#"{"channel":"telegram","account":"default","inbound":"configured_account","account_probe":"available"}"#.as_slice(),
        br#"not-json"#.as_slice(),
    ] {
        assert_eq!(
            panel_logic::parse_telegram_legacy_migrated(receipt, "default"),
            None,
            "only the complete exact legacy migration receipt triggers an inventory refresh"
        );
    }
    let oversized = vec![b' '; 16 * 1024 + 1];
    assert_eq!(
        panel_logic::parse_telegram_legacy_migrated(&oversized, "default"),
        None,
        "migration receipts beyond the bounded GUI response budget are rejected"
    );
}

#[test]
fn pending_pairing_parser_and_dismissal_receipt_reject_foreign_or_malformed_data() {
    let request_id = "0123456789abcdef0123456789abcdef";
    let accepted = panel_logic::parse_telegram_pairing_list(
        format!(
            r#"{{"channel":"telegram","account":"ops_b","pending":[{{"request_id":"{request_id}","created_at":42}}]}}"#
        )
        .as_bytes(),
        "ops_b",
    )
    .expect("canonical bounded list is accepted");
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].request_id, request_id);

    for payload in [
        r#"{"channel":"slack","account":"ops_b","pending":[]}"#.to_owned(),
        r#"{"channel":"telegram","account":"ops_a","pending":[]}"#.to_owned(),
        format!(r#"{{"channel":"telegram","account":"ops_b","pending":[{{"request_id":"{request_id}","created_at":-1}}]}}"#),
        format!(r#"{{"channel":"telegram","account":"ops_b","pending":[{{"request_id":"{request_id}","created_at":1}},{{"request_id":"{request_id}","created_at":2}}]}}"#),
        r#"{"channel":"telegram","account":"ops_b","pending":[{"request_id":"0123456789ABCDEF0123456789abcdef","created_at":1}]}"#.to_owned(),
        r#"{"channel":"telegram","account":"ops_b","pending":[{"request_id":"short","created_at":1}]}"#.to_owned(),
        r#"{"channel":"telegram","account":"ops_b","pending":[{"request_id":"0123456789abcdef0123456789abcdef"}]}"#.to_owned(),
        r#"{"channel":"telegram","account":"ops_b","pending":[],"extra":true}"#.to_owned(),
    ] {
        assert!(
            panel_logic::parse_telegram_pairing_list(payload.as_bytes(), "ops_b").is_err(),
            "invalid list payload must not supply actionable rows"
        );
    }
    let oversized = vec![b' '; 16 * 1024 + 1];
    assert!(
        panel_logic::parse_telegram_pairing_list(&oversized, "ops_b").is_err(),
        "responses beyond the fixed inventory budget are rejected before parsing"
    );
    assert!(
        panel_logic::parse_telegram_pairing_list(
            br#"{"channel":"telegram","account":"ops_b","pending":[
                {"request_id":"00000000000000000000000000000000","created_at":1},
                {"request_id":"11111111111111111111111111111111","created_at":2},
                {"request_id":"22222222222222222222222222222222","created_at":3},
                {"request_id":"33333333333333333333333333333333","created_at":4}
            ]}"#,
            "ops_b",
        )
        .is_err(),
        "the GUI refuses more rows than the current backend limit"
    );

    assert_eq!(
        panel_logic::parse_telegram_pairing_dismissed(
            format!(r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}","dismissed":true}}"#).as_bytes(),
            "ops_b",
            request_id,
        ),
        Some(true)
    );
    for receipt in [
        format!(r#"{{"channel":"telegram","account":"ops_a","request_id":"{request_id}","dismissed":true}}"#),
        r#"{"channel":"telegram","account":"ops_b","request_id":"ffffffffffffffffffffffffffffffff","dismissed":true}"#.to_owned(),
        format!(r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}","dismissed":false}}"#),
        format!(r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}","dismissed":true,"extra":true}}"#),
        format!(r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}"}}"#),
        format!(r#"{{"channel":"telegram","account":"ops_b","request_id":"{request_id}","dismissed":"true"}}"#),
        r#"{"channel":"telegram","account":"ops_b","request_id":"0123456789ABCDEF0123456789abcdef","dismissed":true}"#.to_owned(),
    ] {
        assert_eq!(
            panel_logic::parse_telegram_pairing_dismissed(receipt.as_bytes(), "ops_b", request_id),
            None,
            "only the exact strict dismissal receipt is actionable"
        );
    }
}

#[test]
fn mapped_telegram_account_result_binds_to_the_selected_account_headlessly() {
    let result = neothd::cli::channel::ChannelTestResult {
        channel: "telegram".to_owned(),
        account: Some(
            neothd::channels::registry::ChannelAccountId::new("ops_b")
                .expect("ops_b is a canonical account id"),
        ),
        status: "ok",
        detail: "reachable".to_owned(),
    };
    let accepted = panel_logic::parse_telegram_account_test_status(
        &serde_json::to_string(&result).expect("core result serializes"),
        "ops_b",
    )
    .expect("the exact selected account is accepted");
    assert_eq!(accepted.status, "ok");

    let other_result = neothd::cli::channel::ChannelTestResult {
        account: Some(
            neothd::channels::registry::ChannelAccountId::new("ops_a")
                .expect("ops_a is a canonical account id"),
        ),
        ..result
    };

    assert!(
        panel_logic::parse_telegram_account_test_status(
            &serde_json::to_string(&other_result).expect("core result serializes"),
            "ops_b",
        )
        .is_err(),
        "a result for another configured account must not be presented as ops_b"
    );
}
