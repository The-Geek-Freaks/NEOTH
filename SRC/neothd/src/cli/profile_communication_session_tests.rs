use super::*;
use crate::profile::communication::{PreferenceValue, ProcessingLoadPreference};
use clap::Parser;

fn config(home: &std::path::Path) {
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&FreedomConfig::default()).unwrap(),
    )
    .unwrap();
}

#[test]
fn session_cli_parses_show_set_and_scoped_reset() {
    for (arguments, expected) in [
        (vec!["show"], "show"),
        (vec!["set", "processing-load", "compact"], "set"),
        (vec!["reset", "processing-load"], "reset"),
    ] {
        let mut command = vec![
            "neoth",
            "profile",
            "communication",
            "session",
            "retained-chat",
        ];
        command.extend(arguments);
        let cli = crate::cli::Cli::try_parse_from(command).unwrap();
        let crate::cli::Commands::Profile(args) = cli.command else {
            panic!("profile expected")
        };
        let ProfileAction::Communication {
            sub: CommunicationSub::Session { session_id, sub },
        } = args.action
        else {
            panic!("session controls expected")
        };
        assert_eq!(session_id, "retained-chat");
        match sub {
            CommunicationSessionSub::Show => assert_eq!(expected, "show"),
            CommunicationSessionSub::Set { dimension, value } => {
                assert_eq!(expected, "set");
                assert_eq!(dimension, CommunicationDimensionArg::ProcessingLoad);
                assert_eq!(value, "compact");
            }
            CommunicationSessionSub::Reset { dimension } => {
                assert_eq!(expected, "reset");
                assert_eq!(dimension, CommunicationDimensionArg::ProcessingLoad);
            }
        }
    }
}

#[tokio::test]
async fn session_cli_persists_exact_scope_and_redacted_control_receipt() {
    let dir = tempfile::tempdir().unwrap();
    config(dir.path());
    set_communication_preference_at(dir.path(), CommunicationDimension::ProcessingLoad, "deep")
        .unwrap();
    let id = "private-session-marker";
    run(
        dir.path(),
        id,
        CommunicationSessionSub::Set {
            dimension: CommunicationDimensionArg::ProcessingLoad,
            value: "compact".into(),
        },
        &OutputFormat::Json,
    )
    .await
    .unwrap();
    let policy = crate::config::CommunicationProfileConfig::default();
    assert_eq!(
        session::inspect(
            dir.path(),
            &policy,
            LocalProfileCommunicationOperator::mint(),
            id,
            false
        )
        .unwrap()[&CommunicationDimension::ProcessingLoad],
        PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Compact)
    );
    let segments = std::fs::read_dir(dir.path().join("wal"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("wal"))
        .collect::<Vec<_>>();
    assert_eq!(segments.len(), 1);
    let bytes = std::fs::read(&segments[0]).unwrap();
    let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let frame = crate::wal::frame::decode_frame(&bytes[header.header_len()..]).unwrap();
    assert_eq!(
        frame.header.event_subtype,
        crate::wal::events::ExtendedSubtype::CommunicationProfileControlled as u8
    );
    let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
    assert_eq!(
        payload["action_code"],
        CommunicationControlAction::SetSessionPreference as u8
    );
    assert_eq!(payload["scope"], "session");
    assert_eq!(payload["dimension"], "processing_load");
    assert_eq!(payload["session_sha256"].as_str().unwrap().len(), 64);
    let text = std::str::from_utf8(frame.payload).unwrap();
    assert!(!text.contains(id));
    assert!(!text.contains("compact"));
    run(
        dir.path(),
        id,
        CommunicationSessionSub::Show,
        &OutputFormat::Json,
    )
    .await
    .unwrap();
    run(
        dir.path(),
        id,
        CommunicationSessionSub::Reset {
            dimension: CommunicationDimensionArg::ProcessingLoad,
        },
        &OutputFormat::Json,
    )
    .await
    .unwrap();
    assert!(
        session::inspect(
            dir.path(),
            &policy,
            LocalProfileCommunicationOperator::mint(),
            id,
            false
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        communication::load_redacted_export(dir.path())
            .unwrap()
            .active_accommodations,
        vec![PreferenceValue::ProcessingLoad(
            ProcessingLoadPreference::Deep
        )]
    );
}

#[tokio::test]
async fn session_cli_rejects_private_ids_before_io_and_reports_postcommit_audit_failure() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("freedom.yaml"), b"malformed: [").unwrap();
    let error = run(
        dir.path(),
        "incognito-private",
        CommunicationSessionSub::Show,
        &OutputFormat::Json,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("non-private canonical session id")
    );
    assert!(!dir.path().join(communication::STATE_RELATIVE_PATH).exists());
    config(dir.path());
    std::fs::write(dir.path().join("wal"), b"unavailable-directory").unwrap();
    let error = run(
        dir.path(),
        "target",
        CommunicationSessionSub::Set {
            dimension: CommunicationDimensionArg::ProcessingLoad,
            value: "compact".into(),
        },
        &OutputFormat::Json,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("state committed; required post-commit audit failed")
    );
    let selected = session::inspect(
        dir.path(),
        &crate::config::CommunicationProfileConfig::default(),
        LocalProfileCommunicationOperator::mint(),
        "target",
        false,
    )
    .unwrap();
    assert_eq!(
        selected[&CommunicationDimension::ProcessingLoad],
        PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Compact)
    );
    assert_eq!(
        std::fs::read(dir.path().join("wal")).unwrap(),
        b"unavailable-directory"
    );
}
