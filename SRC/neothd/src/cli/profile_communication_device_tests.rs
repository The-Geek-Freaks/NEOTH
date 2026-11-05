use super::*;
use clap::Parser;

fn view(id: uuid::Uuid, revision: u64, state: &str) -> crate::daemon::companion_runtime::CompanionV3DeviceView {
    crate::daemon::companion_runtime::CompanionV3DeviceView {
        device_id: crate::daemon::companion_protocol::CompanionDeviceId(id),
        label: "local test device".into(),
        revision,
        grant_state: state.into(),
    }
}

#[test]
fn device_cli_resolves_only_unique_active_grant_and_parses_old_revision_controls() {
    let id = uuid::Uuid::from_u128(123);
    assert_eq!(active_device_scope(&[view(id, 3, "active")], id).unwrap(), format!("{id}@3"));
    for devices in [
        vec![],
        vec![view(id, 3, "revoked")],
        vec![view(id, 3, "pending_revoke")],
        vec![view(id, 0, "active")],
        vec![view(uuid::Uuid::from_u128(124), 3, "active")],
        vec![view(id, 3, "active"), view(id, 3, "active")],
    ] {
        assert!(active_device_scope(&devices, id).is_err());
    }
    let id = id.to_string();
    let cli = crate::cli::Cli::try_parse_from([
        "neoth", "profile", "communication", "device", &id, "--revision", "1",
        "reset", "processing-load",
    ]).unwrap();
    let crate::cli::Commands::Profile(args) = cli.command else { panic!("profile expected") };
    let ProfileAction::Communication { sub: CommunicationSub::Device { device_id, revision, sub } } = args.action else {
        panic!("device control expected")
    };
    assert_eq!(device_id, id);
    assert_eq!(revision, Some(1));
    assert!(matches!(sub, CommunicationSessionSub::Reset { dimension: CommunicationDimensionArg::ProcessingLoad }));
}

#[tokio::test]
async fn device_cli_old_revision_reset_reclaims_pin_and_writes_redacted_audit() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("freedom.yaml"), serde_yaml::to_string(&FreedomConfig::default()).unwrap()).unwrap();
    let id = uuid::Uuid::from_u128(123).to_string();
    let epoch = format!("{id}@1");
    let policy = crate::config::CommunicationProfileConfig::default();
    set_at(home.path(), &policy, &epoch, CommunicationDimension::ProcessingLoad, "compact").unwrap();
    run(home.path(), &id, Some(1), CommunicationSessionSub::Reset {
        dimension: CommunicationDimensionArg::ProcessingLoad,
    }, &OutputFormat::Json).await.unwrap();
    assert!(device::inspect(home.path(), &policy, LocalProfileCommunicationOperator::mint(), &epoch, false).unwrap().is_empty());
    let segments = std::fs::read_dir(home.path().join("wal")).unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("wal"))
        .collect::<Vec<_>>();
    assert_eq!(segments.len(), 1);
    let bytes = std::fs::read(&segments[0]).unwrap();
    let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let frame = crate::wal::frame::decode_frame(&bytes[header.header_len()..]).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
    assert_eq!(payload["action_code"], CommunicationControlAction::ResetDevicePreference as u8);
    assert_eq!(payload["scope"], "device");
    assert_eq!(payload["device_sha256"].as_str().unwrap().len(), 64);
    let text = std::str::from_utf8(frame.payload).unwrap();
    assert!(!text.contains(&id));
    assert!(!text.contains("compact"));
    let before = std::fs::read(home.path().join(communication::STATE_RELATIVE_PATH)).unwrap();
    assert!(run(home.path(), &id, Some(1), CommunicationSessionSub::Set {
        dimension: CommunicationDimensionArg::ProcessingLoad,
        value: "deep".into(),
    }, &OutputFormat::Json).await.is_err());
    assert_eq!(std::fs::read(home.path().join(communication::STATE_RELATIVE_PATH)).unwrap(), before);
}
