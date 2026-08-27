//! Durable, content-free CC-01 connector-control state.
//!
//! This module is deliberately a configuration schema and validator, not a
//! runnable connector registry.  In particular, loading an account record
//! never starts a sync, opens `context.db`, reads a credential, or grants a
//! planner capability.

use serde::{Deserialize, Serialize};

use super::{
    ConnectorConfiguration, ConnectorConfigurationError, ConnectorId, ConnectorInstanceId,
    validate_configurations,
};

pub const CONNECTOR_CONTROL_STATE_SCHEMA_VERSION: u32 = 1;
const MAX_REGISTERED_CONNECTOR_ACCOUNTS: usize = 64;

const fn default_connector_control_state_schema_version() -> u32 {
    CONNECTOR_CONTROL_STATE_SCHEMA_VERSION
}

/// Persistent lifecycle state for one registered connector account.
///
/// A state transition is durable only after the enclosing `freedom.yaml`
/// update has been atomically published.  The later daemon control plane uses
/// the exact same state to retire in-memory authority before it admits work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorLifecycle {
    Active,
    Paused,
    Revoked,
}

impl ConnectorLifecycle {
    pub const fn admits_context_import(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// One operator-registered connector account.  This is content-free: it
/// contains only a descriptor/configuration reference and lifecycle metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredConnectorAccount {
    pub configuration: ConnectorConfiguration,
    pub lifecycle: ConnectorLifecycle,
    /// Monotonic account-control generation.  Replacing policy, pausing, or
    /// revoking must increase this value so queued authority cannot revive.
    pub lifecycle_revision: u64,
}

impl RegisteredConnectorAccount {
    pub fn instance_id(&self) -> ConnectorInstanceId {
        self.configuration.instance_id()
    }

    pub fn validate(&self) -> Result<(), ConnectorControlStateError> {
        if self.lifecycle_revision == 0 {
            return Err(ConnectorControlStateError::InvalidLifecycleRevision(
                self.configuration.connector_id,
            ));
        }
        validate_configurations(std::slice::from_ref(&self.configuration))
            .map_err(ConnectorControlStateError::Configuration)
    }
}

/// Default-off persistent connector control configuration.
///
/// Accounts may be staged while disabled, but no runtime may use them until
/// `enabled` is true and the account is individually admitted by the control
/// plane.  This keeps config presence distinct from runtime readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConnectorControlConfig {
    #[serde(default = "default_connector_control_state_schema_version")]
    pub schema_version: u32,
    pub enabled: bool,
    pub registered_accounts: Vec<RegisteredConnectorAccount>,
}

impl Default for ConnectorControlConfig {
    fn default() -> Self {
        Self {
            schema_version: CONNECTOR_CONTROL_STATE_SCHEMA_VERSION,
            enabled: false,
            registered_accounts: Vec::new(),
        }
    }
}

impl ConnectorControlConfig {
    pub fn validate(&self) -> Result<(), ConnectorControlStateError> {
        if self.schema_version != CONNECTOR_CONTROL_STATE_SCHEMA_VERSION {
            return Err(ConnectorControlStateError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.registered_accounts.len() > MAX_REGISTERED_CONNECTOR_ACCOUNTS {
            return Err(ConnectorControlStateError::TooManyRegisteredAccounts);
        }

        let configurations = self
            .registered_accounts
            .iter()
            .map(|account| {
                account.validate()?;
                Ok(account.configuration.clone())
            })
            .collect::<Result<Vec<_>, ConnectorControlStateError>>()?;
        validate_configurations(&configurations).map_err(ConnectorControlStateError::Configuration)
    }

    pub fn account(&self, instance: &ConnectorInstanceId) -> Option<&RegisteredConnectorAccount> {
        self.registered_accounts
            .iter()
            .find(|account| account.instance_id() == *instance)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorControlStateError {
    #[error("unsupported connector control-state schema version {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("connector control state exceeds the registered-account safety cap")]
    TooManyRegisteredAccounts,
    #[error("connector `{0}` has a zero lifecycle revision")]
    InvalidLifecycleRevision(ConnectorId),
    #[error("registered connector configuration is invalid: {0}")]
    Configuration(ConnectorConfigurationError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::{ConnectorPolicySnapshot, SubjectId};

    fn local_import_account(lifecycle: ConnectorLifecycle) -> RegisteredConnectorAccount {
        RegisteredConnectorAccount {
            configuration: ConnectorConfiguration {
                connector_id: ConnectorId::LocalImport,
                account_id: None,
                subject_id: SubjectId::new("operator").unwrap(),
                credential_ref: None,
                policy: ConnectorPolicySnapshot::local_read_only(1),
            },
            lifecycle,
            lifecycle_revision: 1,
        }
    }

    fn populated_v1_config_value() -> serde_json::Value {
        serde_json::to_value(ConnectorControlConfig {
            enabled: true,
            registered_accounts: vec![local_import_account(ConnectorLifecycle::Active)],
            ..ConnectorControlConfig::default()
        })
        .unwrap()
    }

    #[test]
    fn default_is_disabled_and_empty() {
        let config = ConnectorControlConfig::default();
        assert!(!config.enabled);
        assert!(config.registered_accounts.is_empty());
        config.validate().unwrap();
    }

    #[test]
    fn schema_and_account_revision_are_fail_closed() {
        let mut config = ConnectorControlConfig::default();
        config.schema_version = CONNECTOR_CONTROL_STATE_SCHEMA_VERSION + 1;
        assert!(matches!(
            config.validate(),
            Err(ConnectorControlStateError::UnsupportedSchemaVersion(_))
        ));

        let mut account = local_import_account(ConnectorLifecycle::Active);
        account.lifecycle_revision = 0;
        config.schema_version = CONNECTOR_CONTROL_STATE_SCHEMA_VERSION;
        config.registered_accounts = vec![account];
        assert!(matches!(
            config.validate(),
            Err(ConnectorControlStateError::InvalidLifecycleRevision(
                ConnectorId::LocalImport
            ))
        ));
    }

    #[test]
    fn duplicate_instances_are_rejected_even_when_disabled_or_revoked() {
        let mut config = ConnectorControlConfig::default();
        config.registered_accounts = vec![
            local_import_account(ConnectorLifecycle::Revoked),
            local_import_account(ConnectorLifecycle::Paused),
        ];
        assert!(matches!(
            config.validate(),
            Err(ConnectorControlStateError::Configuration(
                ConnectorConfigurationError::DuplicateOrAmbiguousInstance(ConnectorId::LocalImport)
            ))
        ));
    }

    #[test]
    fn serde_defaults_old_config_to_disabled_and_rejects_unknown_schema() {
        let omitted: ConnectorControlConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(omitted, ConnectorControlConfig::default());

        let unsupported: ConnectorControlConfig =
            serde_yaml::from_str("schema_version: 99\nenabled: false\nregistered_accounts: []\n")
                .unwrap();
        assert!(matches!(
            unsupported.validate(),
            Err(ConnectorControlStateError::UnsupportedSchemaVersion(99))
        ));

        let partial: ConnectorControlConfig = serde_yaml::from_str("enabled: true\n").unwrap();
        assert_eq!(
            partial.schema_version,
            CONNECTOR_CONTROL_STATE_SCHEMA_VERSION
        );
        assert!(partial.enabled);
        partial.validate().unwrap();
    }

    #[test]
    fn serde_control_config_accepts_empty_and_minimal_v1_documents() {
        let empty: ConnectorControlConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, ConnectorControlConfig::default());
        empty.validate().unwrap();

        let minimal: ConnectorControlConfig = serde_json::from_str(
            r#"{"schema_version":1,"enabled":false,"registered_accounts":[]}"#,
        )
        .unwrap();
        assert_eq!(
            minimal.schema_version,
            CONNECTOR_CONTROL_STATE_SCHEMA_VERSION
        );
        assert!(!minimal.enabled);
        assert!(minimal.registered_accounts.is_empty());
        minimal.validate().unwrap();
    }

    #[test]
    fn serde_control_config_rejects_unknown_root_fields() {
        let mut value = populated_v1_config_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown_root".to_owned(), serde_json::Value::Bool(true));

        assert!(serde_json::from_value::<ConnectorControlConfig>(value).is_err());
    }

    #[test]
    fn serde_control_config_rejects_unknown_registered_account_fields() {
        let mut value = populated_v1_config_value();
        value["registered_accounts"][0]
            .as_object_mut()
            .unwrap()
            .insert("unknown_account".to_owned(), serde_json::Value::Bool(true));

        assert!(serde_json::from_value::<ConnectorControlConfig>(value).is_err());
    }

    #[test]
    fn serde_control_config_rejects_unknown_connector_configuration_fields() {
        let mut value = populated_v1_config_value();
        value["registered_accounts"][0]["configuration"]
            .as_object_mut()
            .unwrap()
            .insert(
                "unknown_connector_configuration".to_owned(),
                serde_json::Value::Bool(true),
            );

        assert!(serde_json::from_value::<ConnectorControlConfig>(value).is_err());
    }

    #[test]
    fn serde_control_config_rejects_unknown_policy_snapshot_fields() {
        let mut value = populated_v1_config_value();
        value["registered_accounts"][0]["configuration"]["policy"]
            .as_object_mut()
            .unwrap()
            .insert("unknown_policy".to_owned(), serde_json::Value::Bool(true));

        assert!(serde_json::from_value::<ConnectorControlConfig>(value).is_err());
    }

    #[test]
    fn serde_control_config_rejects_unknown_resource_limit_fields() {
        let mut value = populated_v1_config_value();
        value["registered_accounts"][0]["configuration"]["policy"]["limits"]
            .as_object_mut()
            .unwrap()
            .insert("unknown_limit".to_owned(), serde_json::Value::Bool(true));

        assert!(serde_json::from_value::<ConnectorControlConfig>(value).is_err());
    }
}
