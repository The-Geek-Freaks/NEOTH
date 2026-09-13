//! Headless coverage for the production GUI channel-status parser.
//!
//! This integration target shares the desktop's actual pure-Rust modules by
//! path. It deliberately does not duplicate any parser or spawn Slint, so a
//! core test gate exercises the same account-status and account-test binding
//! code that the desktop will use.

#[expect(
    dead_code,
    reason = "headless harness omits desktop callers checked by the GUI gate"
)]
#[path = "../../neothd-gui/src/gui_action.rs"]
pub mod gui_action;

#[expect(
    clippy::len_without_is_empty,
    reason = "headless import exposes a private desktop module for parser tests"
)]
#[path = "../../neothd-gui/src/panel_logic.rs"]
pub mod panel_logic;

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
