#![cfg(test)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;

use super::*;
use crate::config::inference::{HemisphereRole, InferenceProvider};
use crate::config::role_policy::{RolePolicyConfig, RolePolicyRule};
use crate::permissions::AutonomyLevel;
use crate::providers::{ChatTurnEffectKind, Completion, Provider, ProviderRetryReason, Request};

struct RecordingLeaf {
    calls: AtomicUsize,
    model: &'static str,
}

#[async_trait]
impl Provider for RecordingLeaf {
    fn name(&self) -> &'static str {
        "local_ollama"
    }

    fn default_model(&self) -> Option<&str> {
        Some(self.model)
    }

    fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
        Some(64)
    }

    async fn complete(&self, req: Request) -> anyhow::Result<Completion> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Completion {
            text: "authenticated leaf response".into(),
            model: req.model.unwrap_or_default(),
            latency: Duration::ZERO,
            ..Completion::default()
        })
    }
}

fn configured_role_policy(
    provider: InferenceProvider,
    model: &str,
) -> Arc<crate::config::FreedomConfig> {
    let mut config = crate::config::FreedomConfig::default();
    config.inference.role_policy = Some(RolePolicyConfig {
        rules: vec![RolePolicyRule {
            role: HemisphereRole::Left,
            provider,
            model: Some(model.to_owned()),
        }],
    });
    Arc::new(config)
}

fn council_authorizer(
    config: Arc<crate::config::FreedomConfig>,
    provider: InferenceProvider,
) -> ProviderCallAuthorizer {
    ProviderCallAuthorizer::test_only(AutonomyLevel::Full).with_role_dispatch(
        HemisphereRole::Left,
        provider,
        config,
    )
}

fn lifecycle_frames(segment: &std::path::Path) -> Vec<(u8, serde_json::Value)> {
    let bytes = std::fs::read(segment).expect("read lifecycle WAL");
    let header = crate::wal::segment_header::parse_segment_header(&bytes)
        .expect("parse lifecycle WAL header");
    let mut cursor = header.header_len();
    let mut frames = Vec::new();
    while cursor < bytes.len() {
        let frame =
            crate::wal::frame::decode_frame(&bytes[cursor..]).expect("decode lifecycle WAL frame");
        if frame.header.event_type != crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
            frames.push((
                frame.header.event_type,
                serde_json::from_slice(frame.payload).expect("provider lifecycle JSON payload"),
            ));
        }
        cursor += frame.header.total_len as usize;
    }
    frames
}

#[tokio::test]
async fn configured_role_denial_blocks_raw_transport() {
    let inner = RecordingLeaf {
        calls: AtomicUsize::new(0),
        model: "qwen-allowed",
    };
    let provider = CostAuthorizingProvider::new(
        &inner,
        council_authorizer(
            configured_role_policy(InferenceProvider::OpenAi, "qwen-allowed"),
            InferenceProvider::LocalOllama,
        ),
        None,
        "w213.role_denied",
    );

    let error = provider
        .complete(Request::default())
        .await
        .expect_err("configured role/provider mismatch must deny the leaf");
    assert!(
        error.to_string().contains("role dispatch denied"),
        "{error:#}"
    );
    assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn allowed_council_leaf_returns_response_and_audits_typed_role_identity() {
    let dir = tempfile::tempdir().expect("temporary WAL directory");
    let segment = dir.path().join("w213-role-dispatch-000001.wal");
    let (writer, join) = crate::wal::writer::spawn(segment.clone()).expect("start WAL writer");
    let policy = configured_role_policy(InferenceProvider::LocalOllama, "qwen-allowed");
    let inner = RecordingLeaf {
        calls: AtomicUsize::new(0),
        model: "qwen-allowed",
    };
    let authorizer = ProviderCallAuthorizer::fail_closed(
        AutonomyLevel::Full,
        Some(writer.clone()),
        crate::config::TokensConfig::default_max_per_request(),
    )
    .with_role_dispatch(HemisphereRole::Left, InferenceProvider::LocalOllama, policy);
    let provider = CostAuthorizingProvider::new(&inner, authorizer, None, "w213.role_allowed");

    let response = provider
        .complete(Request::default())
        .await
        .expect("allowed leaf response");
    assert_eq!(response.text, "authenticated leaf response");
    assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    drop(provider);
    drop(writer);
    join.await.expect("WAL writer drained");

    let lifecycle = lifecycle_frames(&segment);
    let request = lifecycle
        .iter()
        .find(|(event, _)| *event == crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST)
        .expect("durable provider-request lifecycle audit")
        .1
        .clone();
    assert_eq!(request["hemisphere_role"], "left");
    assert_eq!(request["hemisphere_provider"], "local_ollama");
    assert_eq!(request["hemisphere_model"], "qwen-allowed");
    assert!(
        request["hemisphere_policy"]["configured_policy"]["digest"]
            .as_str()
            .is_some_and(|digest| !digest.is_empty()),
        "configured policy digest must be retained in lifecycle audit: {}",
        request["hemisphere_policy"]
    );
}

#[tokio::test]
async fn resolved_leaf_model_outside_role_policy_is_denied_before_raw_transport() {
    let inner = RecordingLeaf {
        calls: AtomicUsize::new(0),
        model: "qwen-allowed",
    };
    let provider = CostAuthorizingProvider::new(
        &inner,
        council_authorizer(
            configured_role_policy(InferenceProvider::LocalOllama, "qwen-allowed"),
            InferenceProvider::LocalOllama,
        ),
        None,
        "w213.model_drift",
    );

    let error = provider
        .complete(Request {
            model: Some("qwen-drift".into()),
            ..Request::default()
        })
        .await
        .expect_err("resolved final model outside role policy must deny the leaf");
    assert!(error.to_string().contains("model_not_allowed"), "{error:#}");
    assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn accepted_role_policy_reload_between_authorization_and_raw_send_is_blocked() {
    let dir = tempfile::tempdir().expect("temporary reload directory");
    let config_path = dir.path().join("freedom.yaml");
    let initial = (*configured_role_policy(InferenceProvider::LocalOllama, "qwen-allowed")).clone();
    std::fs::write(
        &config_path,
        serde_yaml::to_string(&initial).expect("serialize initial config"),
    )
    .expect("write initial config");
    let reload = Arc::new(crate::config::reload::ReloadController::new(
        initial.clone(),
        config_path.clone(),
    ));

    let segment = dir.path().join("w213-role-policy-reload-000001.wal");
    let (writer, join) = crate::wal::writer::spawn(segment.clone()).expect("start WAL writer");
    let ack_gate =
        crate::wal::writer::TestAckGate::once(crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST);
    let writer = writer.with_test_ack_gate(ack_gate.clone());
    let inner = RecordingLeaf {
        calls: AtomicUsize::new(0),
        model: "qwen-allowed",
    };
    let authorizer = ProviderCallAuthorizer::fail_closed(
        AutonomyLevel::Full,
        Some(writer.clone()),
        crate::config::TokensConfig::default_max_per_request(),
    )
    .with_role_dispatch(
        HemisphereRole::Left,
        InferenceProvider::LocalOllama,
        Arc::new(initial),
    )
    .with_role_policy_reload(reload.clone());
    let provider = CostAuthorizingProvider::new(&inner, authorizer, None, "w213.policy_reload");

    {
        let pending = provider.complete(Request::default());
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => panic!("raw transport completed before request lifecycle ack: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), ack_gate.wait_until_durable()) => {
                result.expect("provider request did not become durable");
            }
        }

        let mut reloaded = reload.latest().as_ref().clone();
        reloaded
            .inference
            .role_policy
            .as_mut()
            .expect("initial role policy")
            .rules
            .push(RolePolicyRule {
                role: HemisphereRole::Right,
                provider: InferenceProvider::OpenAi,
                model: Some("gpt-5".into()),
            });
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&reloaded).expect("serialize reloaded config"),
        )
        .expect("write reloaded config");
        assert!(matches!(
            reload.try_reload().expect("reload role-policy generation"),
            crate::config::reload::ReloadResult::Reloaded { .. }
        ));

        ack_gate.release();
        let error = pending
            .await
            .expect_err("accepted changed role policy must block raw transport");
        assert!(
            error
                .to_string()
                .contains("role dispatch policy changed after authorization"),
            "{error:#}"
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    }
    drop(provider);
    drop(writer);
    join.await.expect("WAL writer drained");
    assert!(lifecycle_frames(&segment).iter().any(|(event, payload)| {
        *event == crate::wal::events::EVENT_TYPE_PROVIDER_ERROR
            && payload["error_kind"] == "role_dispatch_policy_changed"
    }));
}

#[tokio::test]
async fn w225_effect_start_role_rejection_closes_admitted_retry_with_denial_receipt() {
    let home = tempfile::tempdir().expect("temporary authenticated home");
    let config_path = home.path().join("freedom.yaml");
    let initial = (*configured_role_policy(InferenceProvider::LocalOllama, "qwen-allowed")).clone();
    std::fs::write(
        &config_path,
        serde_yaml::to_string(&initial).expect("serialize initial config"),
    )
    .expect("write initial config");
    let reload = Arc::new(crate::config::reload::ReloadController::new(
        initial.clone(),
        config_path.clone(),
    ));
    let wal = home.path().join("wal");
    std::fs::create_dir_all(&wal).expect("create home WAL directory");
    let segment = wal.join("000001.wal");
    let (writer, join, ready) =
        crate::wal::writer::spawn_for_home_ready(segment.clone(), home.path().to_path_buf())
            .expect("start authenticated WAL writer");
    ready.wait().await.expect("ready authenticated WAL writer");
    let gate = Arc::new(
        crate::providers::effect_test_support::RecordingEffectGate::new(Duration::from_secs(5)),
    );

    let authorizer = ProviderCallAuthorizer::fail_closed(
        AutonomyLevel::Full,
        Some(writer.clone()),
        crate::config::TokensConfig::default_max_per_request(),
    )
    .with_usage_home(home.path())
    .with_turn_effect_gate(Some(gate.clone()))
    .with_role_dispatch(
        HemisphereRole::Left,
        InferenceProvider::LocalOllama,
        Arc::new(initial),
    )
    .with_role_policy_reload(reload.clone());
    let req = Request {
        model: Some("qwen-allowed".into()),
        ..Request::default()
    };
    let mut authorized = authorizer
        .authorize_leaf("local_ollama", &req, "w225.effect_start", false, Some(128))
        .await
        .expect("admit initial retry-capable leaf");
    let role_dispatch = authorized.take_role_dispatch();
    let provider_subject = authorized.take_provider_subject();
    let effect = authorized.effect_context();
    let audit = authorized
        .begin_dispatch()
        .await
        .expect("write initial lifecycle");
    let permit = ProviderDispatchPermit::authorized(
        audit,
        authorizer,
        "local_ollama",
        None,
        req.clone(),
        "w225.effect_start",
        Some(128),
        provider_subject,
        effect,
        true,
        role_dispatch,
    );
    permit
        .finish_attempt_for_retry(ProviderRetryReason::Transient)
        .await
        .expect("close first retry intent");
    permit
        .begin_retry_attempt()
        .await
        .expect("admit second retry lifecycle");
    let effect = permit
        .prepare_effect(ChatTurnEffectKind::Provider {
            call_scope: "w225.effect_start",
            streaming: false,
        })
        .await
        .expect("actual permit reserves the effect before policy reload")
        .expect("gated retry permit yields a preparing effect");

    let mut reloaded = reload.latest().as_ref().clone();
    reloaded
        .inference
        .role_policy
        .as_mut()
        .expect("initial role policy")
        .rules
        .clear();
    std::fs::write(
        &config_path,
        serde_yaml::to_string(&reloaded).expect("serialize reloaded config"),
    )
    .expect("write changed role policy");
    assert!(matches!(
        reload.try_reload().expect("reload changed role policy"),
        crate::config::reload::ReloadResult::Reloaded { .. }
    ));

    let error = match crate::providers::claude_cli::test_only_begin_effect_start_or_role_terminal(
        &permit, &req, effect,
    )
    .await
    {
        Ok(_) => panic!("changed role policy must stop before effect start"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("role dispatch"), "{error:#}");
    assert_eq!(
        gate.phase(),
        crate::providers::effect_test_support::RecordedPhase::Aborted,
        "live role authority rejects the preparing effect before a started lease"
    );

    drop(permit);
    drop(writer);
    join.await.expect("authenticated WAL writer drained");
    let lifecycle = lifecycle_frames(&segment);
    assert_eq!(
        lifecycle
            .iter()
            .map(|(event, _)| *event)
            .collect::<Vec<_>>(),
        [
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
        ]
    );
    assert_eq!(
        lifecycle[1].1["retry_receipt"]["disposition"],
        "retry_intent_closed"
    );
    assert_eq!(lifecycle[3].1["error_kind"], "role_dispatch_policy_changed");
    assert_eq!(
        lifecycle[3].1["retry_receipt"]["disposition"],
        "authorization_denied"
    );
    assert_eq!(lifecycle[3].1["retry_receipt"]["class"], "transient");
    assert_eq!(lifecycle[3].1["retry_receipt"]["attempt"], 2);
}

#[tokio::test]
async fn w278_immediate_before_send_role_rejection_closes_admitted_retry_with_denial_receipt() {
    let home = tempfile::tempdir().expect("temporary authenticated home");
    let config_path = home.path().join("freedom.yaml");
    let initial = (*configured_role_policy(InferenceProvider::LocalOllama, "qwen-allowed")).clone();
    std::fs::write(
        &config_path,
        serde_yaml::to_string(&initial).expect("serialize initial config"),
    )
    .expect("write initial config");
    let reload = Arc::new(crate::config::reload::ReloadController::new(
        initial.clone(),
        config_path.clone(),
    ));
    let wal = home.path().join("wal");
    std::fs::create_dir_all(&wal).expect("create home WAL directory");
    let segment = wal.join("000001.wal");
    let (writer, join, ready) =
        crate::wal::writer::spawn_for_home_ready(segment.clone(), home.path().to_path_buf())
            .expect("start authenticated WAL writer");
    ready.wait().await.expect("ready authenticated WAL writer");

    let authorizer = ProviderCallAuthorizer::fail_closed(
        AutonomyLevel::Full,
        Some(writer.clone()),
        crate::config::TokensConfig::default_max_per_request(),
    )
    .with_usage_home(home.path())
    .with_role_dispatch(
        HemisphereRole::Left,
        InferenceProvider::LocalOllama,
        Arc::new(initial),
    )
    .with_role_policy_reload(reload.clone());
    let req = Request {
        model: Some("qwen-allowed".into()),
        ..Request::default()
    };
    let mut authorized = authorizer
        .authorize_leaf("local_ollama", &req, "w278.before_send", false, Some(128))
        .await
        .expect("admit initial retry-capable leaf");
    let role_dispatch = authorized.take_role_dispatch();
    let provider_subject = authorized.take_provider_subject();
    let effect = authorized.effect_context();
    let audit = authorized
        .begin_dispatch()
        .await
        .expect("write initial lifecycle");
    let permit = ProviderDispatchPermit::authorized(
        audit,
        authorizer,
        "local_ollama",
        None,
        req.clone(),
        "w278.before_send",
        Some(128),
        provider_subject,
        effect,
        true,
        role_dispatch,
    );
    permit
        .finish_attempt_for_retry(ProviderRetryReason::Transient)
        .await
        .expect("close first retry intent");
    permit
        .begin_retry_attempt()
        .await
        .expect("admit second retry lifecycle before the send fence");

    let mut reloaded = reload.latest().as_ref().clone();
    reloaded
        .inference
        .role_policy
        .as_mut()
        .expect("initial role policy")
        .rules
        .clear();
    std::fs::write(
        &config_path,
        serde_yaml::to_string(&reloaded).expect("serialize changed config"),
    )
    .expect("write changed role policy");
    assert!(matches!(
        reload.try_reload().expect("reload changed role policy"),
        crate::config::reload::ReloadResult::Reloaded { .. }
    ));

    let error = crate::providers::claude_cli::test_only_ensure_role_dispatch_before_send_or_retry_terminal(
        &permit, &req,
    )
    .await
    .expect_err("changed role policy must stop the admitted retry before raw send");
    assert!(error.to_string().contains("role dispatch"), "{error:#}");

    drop(permit);
    drop(writer);
    join.await.expect("authenticated WAL writer drained");
    let lifecycle = lifecycle_frames(&segment);
    assert_eq!(
        lifecycle.iter().map(|(event, _)| *event).collect::<Vec<_>>(),
        [
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
        ],
        "the direct role fence must close the admitted retry without a raw response or duplicate terminal"
    );
    let first = &lifecycle[1].1["retry_receipt"];
    let denied = &lifecycle[3].1["retry_receipt"];
    assert_eq!(first["disposition"], "retry_intent_closed");
    assert_eq!(denied["disposition"], "authorization_denied");
    assert_eq!(denied["class"], "transient");
    assert_eq!(denied["attempt"], 2);
    let first_chain = first["retry_chain_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .expect("the initial terminal must bind a nonempty retry chain");
    let denied_chain = denied["retry_chain_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .expect("the denied retry must retain a nonempty retry chain");
    assert_eq!(denied_chain, first_chain);
    assert_eq!(denied["provider"], first["provider"]);
    assert_eq!(denied["wire_model"], first["wire_model"]);
    assert_eq!(denied["provider"], "local_ollama");
    assert_eq!(denied["wire_model"], "qwen-allowed");
}

#[tokio::test]
async fn non_council_leaf_ignores_a_closed_policy_without_role_binding() {
    let dir = tempfile::tempdir().expect("temporary compatibility config directory");
    let closed_config = (*configured_role_policy(InferenceProvider::OpenAi, "gpt-5")).clone();
    let reload = Arc::new(crate::config::reload::ReloadController::new(
        closed_config,
        dir.path().join("freedom.yaml"),
    ));
    let inner = RecordingLeaf {
        calls: AtomicUsize::new(0),
        model: "legacy-model",
    };
    let provider = CostAuthorizingProvider::new(
        &inner,
        ProviderCallAuthorizer::test_only_reload(reload),
        None,
        "w213.compatibility",
    );

    let response = provider
        .complete(Request::default())
        .await
        .expect("legacy leaf remains compatible");
    assert_eq!(response.text, "authenticated leaf response");
    assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
}
