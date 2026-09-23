//! `neoth context import` — authenticated same-user Context Evidence import.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::{cli::OutputFormat, config::FreedomConfig};

#[derive(Args, Debug, Clone)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub action: ContextAction,
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ContextAction {
    /// Inspect status or plan and apply a capability-bound local import.
    Import {
        #[command(subcommand)]
        action: ContextImportAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ContextImportAction {
    /// Read the daemon's content-free lifecycle and revision view for Context Import.
    Status,
    /// Validate one approved root and return a short-lived confirmation handle.
    Plan {
        /// Absolute local directory presented for capability-bound approval.
        root: String,
        /// Relative regular-file path below the approved root.
        relative_path: String,
    },
    /// Consume exactly one plan confirmation and persist its Context Evidence.
    Apply {
        /// Opaque handle returned by `context import plan`.
        plan_id: String,
        /// Opaque confirmation returned by `context import plan`.
        confirmation_nonce: String,
    },
    /// Durably pause Local Import after confirming the current policy and lifecycle revisions.
    Pause {
        #[arg(long)]
        policy_revision: u64,
        #[arg(long)]
        lifecycle_revision: u64,
    },
    /// Durably resume Local Import after confirming the current policy and lifecycle revisions.
    Resume {
        #[arg(long)]
        policy_revision: u64,
        #[arg(long)]
        lifecycle_revision: u64,
    },
}

pub async fn run(args: ContextArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    run_at(&home, args).await
}

pub(crate) async fn run_at(home: &std::path::Path, args: ContextArgs) -> Result<()> {
    let response = request_at(home, &args).await?;
    let value: serde_json::Value = serde_json::from_str(&response)
        .context("connector-control returned a non-JSON response body")?;
    match args.output {
        OutputFormat::Table => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Json | OutputFormat::Jsonl => println!("{response}"),
    }
    Ok(())
}

pub(crate) async fn request_at(home: &std::path::Path, args: &ContextArgs) -> Result<String> {
    let (route, body) = request_route_and_body(args)?;
    #[cfg(windows)]
    {
        let audit_nonce = crate::daemon::audit_rpc::verified_daemon_endpoint_nonce(home)?;
        let response = crate::connectors::control_plane::rpc::windows_client(home, &audit_nonce)
            .context("discover authenticated connector-control endpoint")?
            .post(route, &body)
            .await?;
        let response =
            std::str::from_utf8(&response).context("connector-control response is not UTF-8")?;
        let (_, body) = response
            .split_once("\r\n\r\n")
            .context("connector-control response has no body")?;
        Ok(body.to_owned())
    }
    #[cfg(not(windows))]
    {
        let _ = (home, route, body, args.output);
        anyhow::bail!("context import client is currently available only on Windows")
    }
}

fn request_route_and_body(args: &ContextArgs) -> Result<(&'static str, Vec<u8>)> {
    match &args.action {
        ContextAction::Import {
            action: ContextImportAction::Status,
        } => Ok(("/cc/accounts/status", Vec::new())),
        ContextAction::Import {
            action:
                ContextImportAction::Plan {
                    root,
                    relative_path,
                },
        } => Ok((
            "/cc/local-import/plan",
            serde_json::to_vec(&serde_json::json!({"root": root, "relative_path": relative_path}))?,
        )),
        ContextAction::Import {
            action:
                ContextImportAction::Apply {
                    plan_id,
                    confirmation_nonce,
                },
        } => Ok((
            "/cc/local-import/apply",
            serde_json::to_vec(
                &serde_json::json!({"plan_id": plan_id, "confirmation_nonce": confirmation_nonce}),
            )?,
        )),
        ContextAction::Import {
            action:
                ContextImportAction::Pause {
                    policy_revision,
                    lifecycle_revision,
                },
        } => Ok((
            "/cc/local-import/pause",
            serde_json::to_vec(&serde_json::json!({
                "policy_revision": policy_revision,
                "lifecycle_revision": lifecycle_revision,
            }))?,
        )),
        ContextAction::Import {
            action:
                ContextImportAction::Resume {
                    policy_revision,
                    lifecycle_revision,
                },
        } => Ok((
            "/cc/local-import/resume",
            serde_json::to_vec(&serde_json::json!({
                "policy_revision": policy_revision,
                "lifecycle_revision": lifecycle_revision,
            }))?,
        )),
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;
    use clap::{Command, FromArgMatches};

    #[test]
    fn context_import_status_parses_and_uses_the_existing_content_free_status_route() {
        let command = ContextArgs::augment_args(Command::new("context"));
        let matches = command
            .try_get_matches_from(["context", "import", "status"])
            .unwrap();
        let args = ContextArgs::from_arg_matches(&matches).unwrap();

        let (route, body) = request_route_and_body(&args).unwrap();

        assert_eq!(route, "/cc/accounts/status");
        assert!(
            body.is_empty(),
            "status must not send import content or handles"
        );
    }

    #[test]
    fn context_import_lifecycle_routes_bind_both_expected_revisions() {
        for (action, expected_route) in [
            (
                ContextImportAction::Pause {
                    policy_revision: 7,
                    lifecycle_revision: 11,
                },
                "/cc/local-import/pause",
            ),
            (
                ContextImportAction::Resume {
                    policy_revision: 7,
                    lifecycle_revision: 12,
                },
                "/cc/local-import/resume",
            ),
        ] {
            let args = ContextArgs {
                action: ContextAction::Import { action },
                output: OutputFormat::Json,
            };
            let (route, body) = request_route_and_body(&args).unwrap();
            assert_eq!(route, expected_route);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"policy_revision": 7, "lifecycle_revision": if expected_route.ends_with("pause") { 11 } else { 12 }}),
                "lifecycle request must contain only the exact expected revisions"
            );
        }
    }
}

#[cfg(windows)]
#[cfg(test)]
mod windows_tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        connectors::{
            ConnectorConfiguration, ConnectorId, ConnectorInstanceId, ConnectorPolicySnapshot,
            SubjectId,
            control_plane::{ConnectorControlPlane, test_context_import_runtime_fixture},
            control_state::{
                CONNECTOR_CONTROL_STATE_SCHEMA_VERSION, ConnectorControlConfig, ConnectorLifecycle,
                RegisteredConnectorAccount,
            },
            runtime_local_import::ContextEvidenceReplayRuntime,
        },
        config::FreedomConfig,
        context_graph::{ContextImportApplyKey, ContextStore},
        daemon::{audit_rpc, pidfile},
        wal::{
            master_key::{load_or_init_master_key, master_key_path},
            writer::spawn_for_home,
        },
    };

    fn active_config() -> ConnectorControlConfig {
        ConnectorControlConfig {
            schema_version: CONNECTOR_CONTROL_STATE_SCHEMA_VERSION,
            enabled: true,
            registered_accounts: vec![RegisteredConnectorAccount {
                configuration: ConnectorConfiguration {
                    connector_id: ConnectorId::LocalImport,
                    account_id: None,
                    subject_id: SubjectId::new("operator").unwrap(),
                    credential_ref: None,
                    policy: ConnectorPolicySnapshot::local_read_only(7),
                },
                lifecycle: ConnectorLifecycle::Active,
                lifecycle_revision: 11,
            }],
        }
    }

    fn active_plane() -> Arc<ConnectorControlPlane> {
        Arc::new(ConnectorControlPlane::from_config(&active_config()).unwrap())
    }

    fn write_active_config(home: &std::path::Path) {
        let mut config = FreedomConfig::default();
        config.context_connectors = active_config();
        std::fs::write(home.join("freedom.yaml"), serde_yaml::to_string(&config).unwrap())
            .unwrap();
    }

    fn args(action: ContextImportAction) -> ContextArgs {
        ContextArgs {
            action: ContextAction::Import { action },
            output: OutputFormat::Json,
        }
    }

    #[tokio::test]
    async fn windows_context_cli_client_status_plan_apply_reopen_and_shutdown_are_bound_to_live_daemon()
     {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let source = crate::test_env::canonical_tempdir().unwrap();
        write_active_config(home.path());
        std::fs::write(
            source.path().join("selected.txt"),
            "Windows CC VFS evidence",
        )
        .unwrap();
        let master_key = load_or_init_master_key(&master_key_path(home.path())).unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let (writer, writer_task) = spawn_for_home(
            wal_dir.join("windows-context-cli-000001.wal"),
            home.path().to_path_buf(),
        )
        .unwrap();

        let audit_nonce = "0123456789abcdef0123456789abcdef";
        let audit_endpoint = audit_rpc::endpoint_for_home(home.path(), audit_nonce).unwrap();
        let mut pid_guard = pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        audit_rpc::write_sidecar(
            home.path(),
            &audit_endpoint,
            std::process::id(),
            audit_nonce,
        )
        .unwrap();
        pid_guard.publish_endpoint_nonce(audit_nonce).unwrap();

        let (listener_task, guard) = crate::connectors::control_plane::rpc::bind_and_serve(
            home.path(),
            &home.path().join("freedom.yaml"),
            audit_nonce,
            active_plane(),
            Some(SubjectId::new("operator").unwrap()),
            writer.clone(),
        )
        .await
        .unwrap();

        let authenticated =
            crate::connectors::control_plane::rpc::windows_client(home.path(), audit_nonce)
                .unwrap();
        let rejected = crate::connectors::control_plane::rpc::windows_client_with_token_for_test(
            home.path(),
            audit_nonce,
            "wrong-token".to_owned(),
        )
        .unwrap();
        assert!(
            rejected.post("/cc/health", b"").await.is_err(),
            "a client with an invalid CC token must not reach a route"
        );

        let status = request_at(home.path(), &args(ContextImportAction::Status))
            .await
            .unwrap();
        let status: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(
            status,
            serde_json::json!({
                "accounts": [{
                    "connector": "local_import",
                    "lifecycle": "active",
                    "policy_revision": 7,
                    "lifecycle_revision": 11,
                }],
            }),
            "status exposes the daemon-owned, content-free lifecycle contract"
        );

        let plan = request_at(
            home.path(),
            &args(ContextImportAction::Plan {
                root: source.path().display().to_string(),
                relative_path: "selected.txt".to_owned(),
            }),
        )
        .await
        .unwrap();
        let plan: serde_json::Value = serde_json::from_str(&plan).unwrap();
        let plan_id = plan["data"]["plan_id"].as_str().unwrap().to_owned();
        let confirmation_nonce = plan["data"]["confirmation_nonce"]
            .as_str()
            .unwrap()
            .to_owned();

        let applied = request_at(
            home.path(),
            &args(ContextImportAction::Apply {
                plan_id: plan_id.clone(),
                confirmation_nonce: confirmation_nonce.clone(),
            }),
        )
        .await
        .unwrap();
        let applied: serde_json::Value = serde_json::from_str(&applied).unwrap();
        assert_eq!(applied["ok"], true);
        assert_eq!(applied["data"]["accepted"], true);

        let paused = request_at(
            home.path(),
            &args(ContextImportAction::Pause {
                policy_revision: 7,
                lifecycle_revision: 11,
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&paused).unwrap(),
            serde_json::json!({
                "ok": true,
                "data": {
                    "connector": "local_import",
                    "lifecycle": "paused",
                    "policy_revision": 7,
                    "lifecycle_revision": 12,
                },
            })
        );
        let paused_config: FreedomConfig =
            serde_yaml::from_slice(&std::fs::read(home.path().join("freedom.yaml")).unwrap())
                .unwrap();
        assert_eq!(
            paused_config.context_connectors.registered_accounts[0].lifecycle,
            ConnectorLifecycle::Paused
        );
        assert_eq!(
            paused_config.context_connectors.registered_accounts[0].lifecycle_revision,
            12
        );
        let paused_plan = request_at(
            home.path(),
            &args(ContextImportAction::Plan {
                root: source.path().display().to_string(),
                relative_path: "selected.txt".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&paused_plan).unwrap(),
            serde_json::json!({"ok": false, "code": "local_import_unavailable"}),
            "paused lifecycle must block new Context Import planning"
        );

        let resumed = request_at(
            home.path(),
            &args(ContextImportAction::Resume {
                policy_revision: 7,
                lifecycle_revision: 12,
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&resumed).unwrap(),
            serde_json::json!({
                "ok": true,
                "data": {
                    "connector": "local_import",
                    "lifecycle": "active",
                    "policy_revision": 7,
                    "lifecycle_revision": 13,
                },
            })
        );
        let resumed_config: FreedomConfig =
            serde_yaml::from_slice(&std::fs::read(home.path().join("freedom.yaml")).unwrap())
                .unwrap();
        let restarted = ConnectorControlPlane::from_config(&resumed_config.context_connectors)
            .unwrap();
        assert_eq!(
            restarted.status().unwrap()[0].lifecycle,
            ConnectorLifecycle::Active,
            "a restarted projection must recover the persisted lifecycle"
        );

        let apply_key = ContextImportApplyKey::new(
            hex::decode(plan_id).unwrap().try_into().unwrap(),
            hex::decode(confirmation_nonce).unwrap().try_into().unwrap(),
        );
        drop(guard);
        listener_task.await.unwrap().unwrap();
        assert!(
            authenticated.post("/cc/health", b"").await.is_err(),
            "listener teardown must withdraw the pipe after draining admitted work"
        );

        let reopened = ContextStore::open_at(home.path().join("context.db"), &master_key).unwrap();
        let binding = test_context_import_runtime_fixture(
            ConnectorInstanceId::accountless(ConnectorId::LocalImport),
            SubjectId::new("operator").unwrap(),
            7,
            11,
        )
        .unwrap();
        let recovery = ContextEvidenceReplayRuntime::new(binding, reopened);
        assert!(
            recovery
                .query_apply_outcome(&apply_key)
                .unwrap()
                .is_some_and(|outcome| outcome.accepted()),
            "the VFS-backed ContextStore must retain the applied outcome after listener shutdown"
        );

        drop(writer);
        writer_task.await.unwrap();
        drop(pid_guard);
    }
}
