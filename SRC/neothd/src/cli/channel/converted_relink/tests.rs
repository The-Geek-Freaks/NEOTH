use super::*;

use std::path::Path;

use crate::channels::registry::{ChannelId, ChannelRef};
use crate::channels::relink::{self, RelinkGate};
use crate::cli::channel::{ChannelAddFields, ChannelTestResult};
#[cfg(feature = "gchat-product-canary")]
use crate::config::{Credentials, FreedomConfig};

fn source_body(channel: ConvertedRelinkChannel) -> &'static str {
    match channel {
        ConvertedRelinkChannel::IMessage => {
            r#"{"channels":{"imessage":{"accounts":{"personal":{"cliPath":"/usr/bin/imsg"}}}}}"#
        }
        ConvertedRelinkChannel::GoogleChat => {
            "{ channels: { googlechat: { accounts: { work: { serviceAccount: { source: 'env', provider: 'default', id: 'test' } } } } } }"
        }
    }
}

fn write_encrypted_first_use_home(home: &Path) {
    let mut config = serde_yaml::to_value(crate::config::FreedomConfig::default()).unwrap();
    config.as_mapping_mut().unwrap().insert(
        serde_yaml::Value::String("wal".into()),
        serde_yaml::from_str("encryption: aes256_gcm_siv\n").unwrap(),
    );
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&config).unwrap(),
    )
    .unwrap();
    crate::wal::master_key::load_or_init_master_key(&crate::wal::master_key::master_key_path(home))
        .unwrap();
    assert!(!home.join("credentials.yaml").exists());
}

fn select_source(path: &Path, channel: ConvertedRelinkChannel) -> SelectedConvertedRelinkAccount {
    neoth_openclaw_custody::select_converted_relink_account(
        path,
        channel,
        match channel {
            ConvertedRelinkChannel::IMessage => "personal",
            ConvertedRelinkChannel::GoogleChat => "work",
        },
        &neoth_openclaw_custody::canonical_known_channel_inventory_sha256(),
    )
    .unwrap()
}

fn request(
    source_path: &Path,
    channel: ConvertedRelinkChannel,
    service_account: Option<&Path>,
    target: &str,
) -> ConvertedRelinkRequest {
    let (destination, fields) = match channel {
        ConvertedRelinkChannel::IMessage => (
            ChannelId::IMessageBlueBubbles,
            ChannelAddFields {
                url: Some("http://127.0.0.1:1234".into()),
                password: Some("not-a-real-bluebubbles-password".into()),
                allowed_sender: Some("+491701234567".into()),
                channels_csv: Some("iMessage;-;+491701234567".into()),
                ..Default::default()
            },
        ),
        ConvertedRelinkChannel::GoogleChat => (
            ChannelId::GoogleChat,
            ChannelAddFields {
                url: Some(service_account.unwrap().display().to_string()),
                server: Some("projects/neoth-test/subscriptions/converted-relink".into()),
                allowed_sender: Some("users/123456789".into()),
                ..Default::default()
            },
        ),
    };
    ConvertedRelinkRequest {
        source: select_source(source_path, channel),
        source_config: source_path.to_owned(),
        destination: ChannelRef::default_account(destination),
        fields,
        target: target.into(),
    }
}

fn probe_ok(channel: String) -> ChannelTestResult {
    ChannelTestResult {
        channel,
        account: None,
        status: "ok",
        detail: "mock exact target accepted".into(),
    }
}

async fn prepare_ok(home: &Path, request: ConvertedRelinkRequest) -> PreparedConvertedRelink {
    prepare_converted_relink_with_probe_at(home, request, |candidate, _target| {
        Box::pin(async move { Ok(probe_ok(candidate.channel_id.as_str().into())) })
    })
    .await
    .unwrap()
}

fn assert_no_publication(home: &Path, destination: ChannelId) {
    assert!(!home.join("credentials.yaml").exists());
    assert!(
        !home
            .join(crate::channels::routing::CHANNEL_ROUTING_FILE)
            .exists()
    );
    assert!(!matches!(
        relink::gate_for_at(home, &ChannelRef::default_account(destination)).unwrap(),
        RelinkGate::Ready(_)
    ));
}

#[tokio::test]
async fn every_durable_checkpoint_recovers_the_same_encrypted_first_use_request() {
    let checkpoints = [
        RelinkCommitCheckpoint::RequestReserved,
        RelinkCommitCheckpoint::Prepared,
        RelinkCommitCheckpoint::PairPublished,
        RelinkCommitCheckpoint::PairRecorded,
        RelinkCommitCheckpoint::RoutingPublished,
        RelinkCommitCheckpoint::RoutingRecorded,
        RelinkCommitCheckpoint::Ready,
    ];
    for stop_at in checkpoints {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        write_encrypted_first_use_home(&home);
        let source = temp.path().join("openclaw.json");
        std::fs::write(&source, source_body(ConvertedRelinkChannel::IMessage)).unwrap();
        let prepared = prepare_ok(
            &home,
            request(
                &source,
                ConvertedRelinkChannel::IMessage,
                None,
                "iMessage;-;+491701234567",
            ),
        )
        .await;
        let stopped =
            commit_prepared_converted_relink_with_checkpoint_at(&home, prepared, |checkpoint| {
                if checkpoint == stop_at {
                    anyhow::bail!("injected crash at {checkpoint:?}");
                }
                Ok(())
            });
        assert!(
            stopped.is_err(),
            "checkpoint {stop_at:?} did not stop the coordinator"
        );
        let resumed = prepare_ok(
            &home,
            request(
                &source,
                ConvertedRelinkChannel::IMessage,
                None,
                "iMessage;-;+491701234567",
            ),
        )
        .await;
        let outcome = commit_prepared_converted_relink_at(&home, resumed).unwrap();
        assert_eq!(
            outcome.already_ready(),
            stop_at == RelinkCommitCheckpoint::Ready,
            "only a stop after the terminal Ready transition may resume idempotently"
        );
        assert!(matches!(
            relink::gate_for_at(
                &home,
                &ChannelRef::default_account(ChannelId::IMessageBlueBubbles)
            )
            .unwrap(),
            RelinkGate::Ready(_)
        ));
        let encrypted = std::fs::read(home.join("credentials.yaml")).unwrap();
        assert!(encrypted.starts_with(b"NEOTH_CONF_ENCv1\n"));
    }
}

#[tokio::test]
async fn ready_retry_is_idempotent_but_changed_request_material_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::IMessage)).unwrap();
    let same = || {
        request(
            &source,
            ConvertedRelinkChannel::IMessage,
            None,
            "iMessage;-;+491701234567",
        )
    };
    commit_prepared_converted_relink_at(&home, prepare_ok(&home, same()).await).unwrap();
    let pair = std::fs::read(home.join("credentials.yaml")).unwrap();
    let retry =
        commit_prepared_converted_relink_at(&home, prepare_ok(&home, same()).await).unwrap();
    assert!(retry.already_ready());
    assert_eq!(std::fs::read(home.join("credentials.yaml")).unwrap(), pair);

    let mut changed_credentials = same();
    changed_credentials.fields.password = Some("a-different-private-password".into());
    let changed_candidate = prepare_ok(&home, changed_credentials).await;
    assert!(commit_prepared_converted_relink_at(&home, changed_candidate).is_err());
    let changed_target = prepare_ok(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::IMessage,
            None,
            "iMessage;-;+491700000000",
        ),
    )
    .await;
    assert!(commit_prepared_converted_relink_at(&home, changed_target).is_err());
    std::fs::write(
        &source,
        r#"{"channels":{"imessage":{"accounts":{"personal":{"cliPath":"/usr/local/bin/imsg"}}}}}"#,
    )
    .unwrap();
    assert!(
        prepare_converted_relink_with_probe_at(&home, same(), |candidate, _| {
            Box::pin(async move { Ok(probe_ok(candidate.channel_id.as_str().into())) })
        })
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(home.join("credentials.yaml")).unwrap(), pair);
}

#[tokio::test]
async fn drift_while_probe_runs_or_a_failed_or_expired_probe_never_publishes() {
    for drift in ["freedom", "credentials", "routing"] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        write_encrypted_first_use_home(&home);
        let source = temp.path().join("openclaw.json");
        std::fs::write(&source, source_body(ConvertedRelinkChannel::IMessage)).unwrap();
        let home_for_probe = home.clone();
        let prepared = prepare_converted_relink_with_probe_at(
            &home,
            request(
                &source,
                ConvertedRelinkChannel::IMessage,
                None,
                "iMessage;-;+491701234567",
            ),
            move |candidate, _| {
                Box::pin(async move {
                    match drift {
                        "freedom" => std::fs::write(
                            home_for_probe.join("freedom.yaml"),
                            "# changed during probe\n",
                        )
                        .unwrap(),
                        "credentials" => std::fs::write(
                            home_for_probe.join("credentials.yaml"),
                            "unknown: changed\n",
                        )
                        .unwrap(),
                        "routing" => std::fs::write(
                            home_for_probe.join(crate::channels::routing::CHANNEL_ROUTING_FILE),
                            "{\"destinations\":{}}\n",
                        )
                        .unwrap(),
                        _ => unreachable!(),
                    }
                    Ok(probe_ok(candidate.channel_id.as_str().into()))
                })
            },
        )
        .await
        .unwrap();
        assert!(
            commit_prepared_converted_relink_at(&home, prepared).is_err(),
            "{drift} drift during the exact target probe must prevent publication"
        );
        assert!(!matches!(
            relink::gate_for_at(
                &home,
                &ChannelRef::default_account(ChannelId::IMessageBlueBubbles)
            )
            .unwrap(),
            RelinkGate::Ready(_)
        ));
    }

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::IMessage)).unwrap();
    let failed = prepare_converted_relink_with_probe_at(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::IMessage,
            None,
            "iMessage;-;+491701234567",
        ),
        |candidate, _| {
            Box::pin(async move {
                Ok(ChannelTestResult {
                    channel: candidate.channel_id.as_str().into(),
                    account: None,
                    status: "fail",
                    detail: "mock target refusal".into(),
                })
            })
        },
    )
    .await;
    assert!(failed.is_err());
    assert_no_publication(&home, ChannelId::IMessageBlueBubbles);

    let mut expired = prepare_ok(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::IMessage,
            None,
            "iMessage;-;+491701234567",
        ),
    )
    .await;
    expired.probe_started = Instant::now() - PROBE_VALIDITY;
    assert!(commit_prepared_converted_relink_at(&home, expired).is_err());
    assert_no_publication(&home, ChannelId::IMessageBlueBubbles);
}

#[tokio::test]
async fn sequential_imessage_and_gchat_relinks_remain_independently_ready() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let imessage_source_root = temp.path().join("imessage-source");
    std::fs::create_dir(&imessage_source_root).unwrap();
    let imessage_source = imessage_source_root.join("openclaw.json");
    std::fs::write(
        &imessage_source,
        source_body(ConvertedRelinkChannel::IMessage),
    )
    .unwrap();
    commit_prepared_converted_relink_at(
        &home,
        prepare_ok(
            &home,
            request(
                &imessage_source,
                ConvertedRelinkChannel::IMessage,
                None,
                "iMessage;-;+491701234567",
            ),
        )
        .await,
    )
    .unwrap();
    let gchat_source_root = temp.path().join("gchat-source");
    std::fs::create_dir(&gchat_source_root).unwrap();
    let gchat_source = gchat_source_root.join("openclaw.json");
    std::fs::write(
        &gchat_source,
        source_body(ConvertedRelinkChannel::GoogleChat),
    )
    .unwrap();
    let service_account = temp.path().join("service-account.json");
    std::fs::write(
        &service_account,
        "{\"type\":\"service_account\",\"project_id\":\"neoth-test\"}",
    )
    .unwrap();
    commit_prepared_converted_relink_at(
        &home,
        prepare_ok(
            &home,
            request(
                &gchat_source,
                ConvertedRelinkChannel::GoogleChat,
                Some(&service_account),
                "spaces/AAAA-converted-relink",
            ),
        )
        .await,
    )
    .unwrap();
    for destination in [ChannelId::IMessageBlueBubbles, ChannelId::GoogleChat] {
        assert!(
            relink::traffic_binding_at(&home, &ChannelRef::default_account(destination))
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn guidless_imessage_relink_is_valid_but_a_later_guid_filter_invalidates_ready() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::IMessage)).unwrap();

    let mut guidless = request(
        &source,
        ConvertedRelinkChannel::IMessage,
        None,
        "iMessage;-;+491701234567",
    );
    guidless.fields.channels_csv = None;
    commit_prepared_converted_relink_at(&home, prepare_ok(&home, guidless).await).unwrap();
    let pair = std::fs::read(home.join("credentials.yaml")).unwrap();

    let with_guid = prepare_ok(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::IMessage,
            None,
            "iMessage;-;+491701234567",
        ),
    )
    .await;
    assert!(commit_prepared_converted_relink_at(&home, with_guid).is_err());
    assert_eq!(std::fs::read(home.join("credentials.yaml")).unwrap(), pair);
    assert!(matches!(
        relink::gate_for_at(
            &home,
            &ChannelRef::default_account(ChannelId::IMessageBlueBubbles),
        )
        .unwrap(),
        RelinkGate::Ready(_)
    ));
    crate::config::credentials::Credentials::update_with_freedom_read_at(
        &home.join("freedom.yaml"),
        &home.join("credentials.yaml"),
        |_, credentials| {
            credentials.bluebubbles_chat_guid = Some("iMessage;-;+491700000000".into());
            Ok(())
        },
    )
    .unwrap();
    assert!(
        relink::traffic_binding_at(
            &home,
            &ChannelRef::default_account(ChannelId::IMessageBlueBubbles),
        )
        .is_err()
    );
}

#[tokio::test]
async fn gchat_key_replaced_during_successful_probe_is_rejected_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::GoogleChat)).unwrap();
    let service_account = temp.path().join("service-account.json");
    std::fs::write(&service_account, "{\"private_key_id\":\"before\"}").unwrap();
    let key_for_probe = service_account.clone();

    let result = prepare_converted_relink_with_probe_at(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::GoogleChat,
            Some(&service_account),
            "spaces/AAAA-converted-relink",
        ),
        move |candidate, _| {
            Box::pin(async move {
                std::fs::write(&key_for_probe, "{\"private_key_id\":\"after\"}").unwrap();
                Ok(probe_ok(candidate.channel_id.as_str().into()))
            })
        },
    )
    .await;
    assert!(result.is_err());
    assert!(!home.join("credentials.yaml").exists());
    assert!(
        !home
            .join(crate::channels::routing::CHANNEL_ROUTING_FILE)
            .exists()
    );
}

#[cfg(not(feature = "gchat-product-canary"))]
#[tokio::test]
async fn failed_gchat_probe_keeps_generic_error_outside_canary() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::GoogleChat)).unwrap();
    let service_account = temp.path().join("service-account.json");
    std::fs::write(&service_account, "{}").unwrap();
    let secret_adjacent_detail = "gchat token POST failed at https://private.invalid/token";

    let error = prepare_converted_relink_with_probe_at(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::GoogleChat,
            Some(&service_account),
            "spaces/AAAA-converted-relink",
        ),
        |_, _| {
            Box::pin(async move {
                Ok(ChannelTestResult {
                    channel: "gchat".into(),
                    account: None,
                    status: "fail",
                    detail: secret_adjacent_detail.into(),
                })
            })
        },
    )
    .await
    .err()
    .expect("injected failed Google Chat probe must refuse publication");
    let rendered = format!("{error:#}");
    assert_eq!(rendered, "converted relink exact target probe did not pass");
    assert!(!rendered.contains("private.invalid"));
}

#[cfg(feature = "gchat-product-canary")]
#[test]
fn gchat_canary_diagnostic_codes_are_fixed_and_complete() {
    let cases = [
        (
            "NEOTH_GCHAT_CANARY_ORIGIN is not Unicode",
            "constructor-origin-not-unicode",
        ),
        (
            "NEOTH_GCHAT_CANARY_ORIGIN must be canonical",
            "constructor-origin-invalid",
        ),
        ("gchat canary feature is not enabled", "constructor-feature"),
        (
            "this binary lacks the `gchat-channel` runtime feature",
            "constructor-feature",
        ),
        (
            "gchat canary key must use synthetic identity",
            "constructor-identity",
        ),
        ("official Google OAuth endpoint", "constructor-token-uri"),
        (
            "gchat subscription must be canonical",
            "constructor-subscription",
        ),
        ("read gchat service-account key", "constructor-key-read"),
        (
            "parse gchat service-account JSON key",
            "constructor-key-json",
        ),
        (
            "build reqwest client for gchat adapter",
            "constructor-http-client",
        ),
        (
            "gchat: service-account private_key is not a valid RSA PEM",
            "bearer-rsa-pem",
        ),
        ("gchat: claims serialization", "bearer-claims"),
        ("gchat: JWT signing failed", "bearer-jwt-sign"),
        ("gchat token POST failed", "token-post"),
        ("gchat token grant response body read failed", "token-body"),
        ("gchat token grant rejected", "token-status"),
        ("gchat token response parse", "token-json"),
        (
            "gchat token response omitted access_token",
            "token-access-token",
        ),
        ("gchat subscription probe failed", "subscription-request"),
        (
            "gchat subscription probe response exceeds",
            "subscription-body",
        ),
        (
            "Google Chat service account cannot read the Pub/Sub subscription",
            "subscription-forbidden",
        ),
        (
            "Google Chat subscription probe returned HTTP",
            "subscription-status",
        ),
        (
            "Google Chat subscription probe returned malformed JSON",
            "subscription-json",
        ),
        (
            "Google Chat subscription probe returned `wrong`",
            "subscription-identity",
        ),
        (
            "gchat space target contains an unsafe path identity",
            "space-path",
        ),
        ("gchat space target probe failed", "space-request"),
        (
            "gchat space target probe response body read failed",
            "space-body",
        ),
        (
            "Google Chat service account cannot read the configured space",
            "space-forbidden",
        ),
        (
            "Google Chat space target probe returned HTTP",
            "space-status",
        ),
        (
            "Google Chat space target probe returned malformed JSON",
            "space-json",
        ),
        (
            "Google Chat space target probe returned a different space",
            "space-identity",
        ),
    ];
    for (detail, expected) in cases {
        assert_eq!(gchat_canary_probe_diagnostic_code(detail), expected);
    }
    assert_eq!(
        gchat_canary_probe_diagnostic_code("https://private.invalid/unknown"),
        "unknown"
    );
}

#[cfg(feature = "gchat-product-canary")]
#[test]
fn gchat_canary_preparation_codes_are_fixed_and_discard_the_error_chain() {
    for code in [
        "validate-request",
        "recheck-source",
        "begin-pending",
        "prepare-candidate",
        "prepare-material",
        "prepare-routing",
        "probe-execution",
        "recheck-candidate",
    ] {
        let error = gchat_canary_stage(
            ChannelId::GoogleChat,
            code,
            Err::<(), anyhow::Error>(anyhow::anyhow!("https://private.invalid/secret-adjacent")),
        )
        .err()
        .expect("failed canary preparation must produce a fixed diagnostic");
        let rendered = format!("{error:#}");
        assert_eq!(
            rendered,
            format!("gchat canary exact target preparation diagnostic: {code}")
        );
        assert!(!rendered.contains("private.invalid"));
    }
}

#[cfg(feature = "gchat-product-canary")]
#[tokio::test]
async fn gchat_canary_pre_reservation_failures_are_fixed_and_do_not_create_pending() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::GoogleChat)).unwrap();
    let service_account = temp.path().join("service-account.json");
    std::fs::write(&service_account, "{}").unwrap();

    let mut invalid = request(
        &source,
        ConvertedRelinkChannel::GoogleChat,
        Some(&service_account),
        "spaces/AAAA-converted-relink",
    );
    invalid.target = "\u{0007}".into();
    let validation = prepare_converted_relink_with_probe_at(&home, invalid, |_, _| {
        Box::pin(async { panic!("invalid request must fail before the probe") })
    })
    .await
    .err()
    .expect("invalid request must fail");
    assert_eq!(
        format!("{validation:#}"),
        "gchat canary exact target preparation diagnostic: validate-request"
    );
    assert!(!home.join("channel_relinks.json").exists());

    let stale = request(
        &source,
        ConvertedRelinkChannel::GoogleChat,
        Some(&service_account),
        "spaces/AAAA-converted-relink",
    );
    std::fs::write(
        &source,
        source_body(ConvertedRelinkChannel::GoogleChat).replace("id: 'test'", "id: 'changed'"),
    )
    .unwrap();
    let source_error = prepare_converted_relink_with_probe_at(&home, stale, |_, _| {
        Box::pin(async { panic!("changed source must fail before the probe") })
    })
    .await
    .err()
    .expect("changed source must fail");
    assert_eq!(
        format!("{source_error:#}"),
        "gchat canary exact target preparation diagnostic: recheck-source"
    );
    assert!(!home.join("channel_relinks.json").exists());
}

#[cfg(feature = "gchat-product-canary")]
#[tokio::test]
async fn gchat_canary_real_candidate_constructor_failure_survives_redaction_as_fixed_code() {
    let temp = tempfile::tempdir().unwrap();
    let service_account = temp.path().join("private-service-account.json");
    std::fs::write(&service_account, "{not-json").unwrap();
    let mut credentials = Credentials::default();
    credentials.gchat_service_account_json = Some(service_account.display().to_string());
    credentials.gchat_subscription =
        Some("projects/neoth-test/subscriptions/converted-relink".into());

    let result = super::super::test_channel_candidate_for_id(
        ChannelId::GoogleChat,
        &FreedomConfig::default(),
        &credentials,
        Some("spaces/AAAA-converted-relink"),
    )
    .await
    .expect("a configured candidate returns a typed failed probe");
    assert_eq!(result.status, "fail");
    assert_eq!(
        gchat_canary_probe_diagnostic_code(&result.detail),
        "constructor-key-json"
    );
    assert!(!result.detail.contains("private-service-account.json"));
}

#[cfg(feature = "gchat-product-canary")]
#[tokio::test]
async fn gchat_canary_begin_pending_conflict_is_fixed_without_rewriting_index_or_pair() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::GoogleChat)).unwrap();
    let service_account = temp.path().join("service-account.json");
    std::fs::write(&service_account, "{}").unwrap();
    let selected = select_source(&source, ConvertedRelinkChannel::GoogleChat);
    relink::begin_pending_at(
        &home,
        &selected,
        ChannelRef::default_account(ChannelId::GoogleChat),
    )
    .unwrap();
    let index_before = std::fs::read(home.join("channel_relinks.json")).unwrap();
    let pair_before = relink::pair_commitment_at(&home).unwrap();
    std::fs::write(
        &source,
        source_body(ConvertedRelinkChannel::GoogleChat).replace("id: 'test'", "id: 'changed'"),
    )
    .unwrap();
    let error = prepare_converted_relink_with_probe_at(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::GoogleChat,
            Some(&service_account),
            "spaces/AAAA-converted-relink",
        ),
        |_, _| Box::pin(async { panic!("conflicting pending must fail before the probe") }),
    )
    .await
    .err()
    .expect("conflicting pending must fail");
    assert_eq!(
        format!("{error:#}"),
        "gchat canary exact target preparation diagnostic: begin-pending"
    );
    assert_eq!(
        std::fs::read(home.join("channel_relinks.json")).unwrap(),
        index_before
    );
    assert_eq!(relink::pair_commitment_at(&home).unwrap(), pair_before);
    assert_no_publication(&home, ChannelId::GoogleChat);
}

#[cfg(feature = "gchat-product-canary")]
#[tokio::test]
async fn failed_gchat_candidate_preparation_emits_only_fixed_canary_code_after_reservation() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::GoogleChat)).unwrap();
    let service_account_directory = temp.path().join("private-service-account-directory");
    std::fs::create_dir(&service_account_directory).unwrap();

    let error = prepare_converted_relink_with_probe_at(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::GoogleChat,
            Some(&service_account_directory),
            "spaces/AAAA-converted-relink",
        ),
        |_, _| {
            Box::pin(async { panic!("candidate preparation must fail before the injected probe") })
        },
    )
    .await
    .err()
    .expect("a directory cannot become a Google Chat service-account file");
    let rendered = format!("{error:#}");
    assert_eq!(
        rendered,
        "gchat canary exact target preparation diagnostic: prepare-candidate"
    );
    assert!(!rendered.contains("private-service-account-directory"));
    assert!(matches!(
        relink::gate_for_at(&home, &ChannelRef::default_account(ChannelId::GoogleChat)).unwrap(),
        RelinkGate::Pending(_)
    ));
}

#[cfg(feature = "gchat-product-canary")]
#[tokio::test]
async fn failed_gchat_probe_emits_only_fixed_canary_code() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::GoogleChat)).unwrap();
    let service_account = temp.path().join("service-account.json");
    std::fs::write(&service_account, "{}").unwrap();
    let secret_adjacent_detail = "gchat token POST failed at https://private.invalid/token";

    let error = prepare_converted_relink_with_probe_at(
        &home,
        request(
            &source,
            ConvertedRelinkChannel::GoogleChat,
            Some(&service_account),
            "spaces/AAAA-converted-relink",
        ),
        |_, _| {
            Box::pin(async move {
                Ok(ChannelTestResult {
                    channel: "gchat".into(),
                    account: None,
                    status: "fail",
                    detail: secret_adjacent_detail.into(),
                })
            })
        },
    )
    .await
    .err()
    .expect("injected failed Google Chat probe must emit a canary diagnostic");
    let rendered = format!("{error:#}");
    assert_eq!(
        rendered,
        "gchat canary exact target probe diagnostic: token-post"
    );
    assert!(!rendered.contains("private.invalid"));
}

#[tokio::test]
async fn reserved_ambiguous_request_rejects_changed_password_but_recovers_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_first_use_home(&home);
    let source = temp.path().join("openclaw.json");
    std::fs::write(&source, source_body(ConvertedRelinkChannel::IMessage)).unwrap();
    let same = || {
        request(
            &source,
            ConvertedRelinkChannel::IMessage,
            None,
            "iMessage;-;+491701234567",
        )
    };

    let first = prepare_ok(&home, same()).await;
    assert!(
        commit_prepared_converted_relink_with_checkpoint_at(&home, first, |checkpoint| {
            if checkpoint == RelinkCommitCheckpoint::RequestReserved {
                anyhow::bail!("injected interruption after durable request reservation");
            }
            Ok(())
        },)
        .is_err()
    );

    let mut changed = same();
    changed.fields.password = Some("different-after-ambiguous-reservation".into());
    let changed = prepare_ok(&home, changed).await;
    assert!(commit_prepared_converted_relink_at(&home, changed).is_err());
    assert!(!home.join("credentials.yaml").exists());
    assert!(
        !home
            .join(crate::channels::routing::CHANNEL_ROUTING_FILE)
            .exists()
    );

    commit_prepared_converted_relink_at(&home, prepare_ok(&home, same()).await).unwrap();
    assert!(matches!(
        relink::gate_for_at(
            &home,
            &ChannelRef::default_account(ChannelId::IMessageBlueBubbles),
        )
        .unwrap(),
        RelinkGate::Ready(_)
    ));
}
