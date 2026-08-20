//! In-crate, revocable CC-01 account authority.
//!
//! No client-facing value can construct an [`AuthenticatedControlSession`] or
//! an [`AccountAuthority`].  This is intentionally only the policy/control
//! plane: it starts no work and exposes no store, planner, credential, action,
//! MCP, or GroundTruth capability.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
};

use super::{
    ConnectorEntryPoint, ConnectorInstanceId, SubjectId, admit_entry_point,
    control_state::{ConnectorControlConfig, ConnectorLifecycle, RegisteredConnectorAccount},
};

/// Capability representing a principal already authenticated by a later local
/// control transport.  There is deliberately no production issuer in this
/// slice: fields, seal, and the only test constructor remain module-private so
/// SubjectId text received from a client cannot become authority.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedControlSession {
    subject_id: SubjectId,
    _unforgeable: AuthenticatedControlSessionSeal,
}

#[derive(Clone, Debug)]
struct AuthenticatedControlSessionSeal(());

impl AuthenticatedControlSession {
    fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    #[cfg(test)]
    fn test_authenticated(subject_id: SubjectId) -> Self {
        Self {
            subject_id,
            _unforgeable: AuthenticatedControlSessionSeal(()),
        }
    }
}

#[derive(Debug)]
struct AuthorityState {
    active: bool,
    generation: u64,
}

/// A revocable, exact-binding authority for one admitted ContextImport entry
/// point.  It intentionally has no `Deref`, no principal getter, and no effect
/// methods; later runtime code can only ask whether this binding remains live.
#[derive(Clone, Debug)]
pub(crate) struct AccountAuthority {
    instance_id: ConnectorInstanceId,
    subject_id: SubjectId,
    policy_revision: u64,
    lifecycle_revision: u64,
    state: Weak<Mutex<AuthorityState>>,
    generation: u64,
}

impl AccountAuthority {
    pub(crate) fn ensure_live(&self) -> Result<(), ConnectorControlPlaneError> {
        let state = self
            .state
            .upgrade()
            .ok_or(ConnectorControlPlaneError::AuthorityRetired)?;
        let state = state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.active || state.generation != self.generation {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        Ok(())
    }

    pub(crate) fn binding_matches(
        &self,
        instance_id: &ConnectorInstanceId,
        subject_id: &SubjectId,
        policy_revision: u64,
        lifecycle_revision: u64,
    ) -> bool {
        self.instance_id == *instance_id
            && self.subject_id == *subject_id
            && self.policy_revision == policy_revision
            && self.lifecycle_revision == lifecycle_revision
    }
}

#[derive(Debug)]
struct AccountSlot {
    account: RegisteredConnectorAccount,
    state: Arc<Mutex<AuthorityState>>,
}

#[derive(Debug)]
struct ConnectorControlPlaneState {
    enabled: bool,
    accounts: BTreeMap<ConnectorInstanceId, AccountSlot>,
}

/// In-memory projection of one validated, durable connector-control config.
///
/// Constructing this type validates the entire config but does not grant an
/// account authority.  `authorize_context_import` requires a non-forgeable
/// authenticated session and repeats CC-01 admission for the exact account.
#[derive(Debug)]
pub(crate) struct ConnectorControlPlane {
    state: Mutex<ConnectorControlPlaneState>,
}

impl ConnectorControlPlane {
    pub(crate) fn from_config(
        config: &ConnectorControlConfig,
    ) -> Result<Self, ConnectorControlPlaneError> {
        Ok(Self {
            state: Mutex::new(Self::state_from_durable_config(config)?),
        })
    }

    fn state_from_durable_config(
        config: &ConnectorControlConfig,
    ) -> Result<ConnectorControlPlaneState, ConnectorControlPlaneError> {
        config
            .validate()
            .map_err(ConnectorControlPlaneError::InvalidConfig)?;
        let accounts = config
            .registered_accounts
            .iter()
            .cloned()
            .map(|account| {
                let instance = account.instance_id();
                let active = account.lifecycle.admits_context_import();
                Ok((
                    instance,
                    AccountSlot {
                        account,
                        state: Arc::new(Mutex::new(AuthorityState {
                            active,
                            generation: 1,
                        })),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ConnectorControlPlaneError>>()?;
        Ok(ConnectorControlPlaneState {
            enabled: config.enabled,
            accounts,
        })
    }

    /// Atomically replace the in-memory projection after its matching durable
    /// config update committed.  Admission serializes on this mutex, so a
    /// caller observes either the former policy or the complete new policy,
    /// never a pause/revoke window with a still-admitting old account map.
    pub(crate) fn replace_after_durable_config_commit(
        &self,
        config: &ConnectorControlConfig,
    ) -> Result<(), ConnectorControlPlaneError> {
        let next = Self::state_from_durable_config(config)?;
        let mut current = self
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::ControlPlaneStatePoisoned)?;
        for slot in current.accounts.values() {
            let mut authority = slot
                .state
                .lock()
                .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
            authority.active = false;
            authority.generation = authority
                .generation
                .checked_add(1)
                .ok_or(ConnectorControlPlaneError::AuthorityGenerationExhausted)?;
        }
        *current = next;
        Ok(())
    }

    pub(crate) fn authorize_context_import(
        &self,
        session: &AuthenticatedControlSession,
        instance_id: &ConnectorInstanceId,
    ) -> Result<AccountAuthority, ConnectorControlPlaneError> {
        let control = self
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::ControlPlaneStatePoisoned)?;
        if !control.enabled {
            return Err(ConnectorControlPlaneError::ControlPlaneDisabled);
        }
        let slot = control
            .accounts
            .get(instance_id)
            .ok_or(ConnectorControlPlaneError::UnknownAccount)?;
        if slot.account.configuration.subject_id != *session.subject_id() {
            return Err(ConnectorControlPlaneError::SubjectBindingMismatch);
        }
        if !slot.account.lifecycle.admits_context_import() {
            return Err(ConnectorControlPlaneError::AccountNotActive(
                slot.account.lifecycle,
            ));
        }
        admit_entry_point(
            &slot.account.configuration,
            ConnectorEntryPoint::ContextImport,
        )
        .map_err(ConnectorControlPlaneError::Admission)?;
        let state = slot
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.active {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        Ok(AccountAuthority {
            instance_id: instance_id.clone(),
            subject_id: slot.account.configuration.subject_id.clone(),
            policy_revision: slot.account.configuration.policy.revision,
            lifecycle_revision: slot.account.lifecycle_revision,
            state: Arc::downgrade(&slot.state),
            generation: state.generation,
        })
    }

    /// Retires only the in-memory authority.  This is an emergency fail-closed
    /// stop; durable pause/revoke must instead commit its config revision and
    /// call [`Self::replace_after_durable_config_commit`] as one reload step.
    pub(crate) fn retire_account(
        &self,
        instance_id: &ConnectorInstanceId,
    ) -> Result<(), ConnectorControlPlaneError> {
        let control = self
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::ControlPlaneStatePoisoned)?;
        let slot = control
            .accounts
            .get(instance_id)
            .ok_or(ConnectorControlPlaneError::UnknownAccount)?;
        let mut state = slot
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        state.active = false;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(ConnectorControlPlaneError::AuthorityGenerationExhausted)?;
        Ok(())
    }

    pub(crate) fn status(&self) -> Result<Vec<ConnectorAccountStatus>, ConnectorControlPlaneError> {
        let control = self
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::ControlPlaneStatePoisoned)?;
        Ok(control
            .accounts
            .iter()
            .map(|(instance_id, slot)| ConnectorAccountStatus {
                instance_id: instance_id.clone(),
                lifecycle: slot.account.lifecycle,
                policy_revision: slot.account.configuration.policy.revision,
                lifecycle_revision: slot.account.lifecycle_revision,
            })
            .collect())
    }
}

/// A content-free status view for later CLI/GUI/Buddy/Doctor consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectorAccountStatus {
    pub(crate) instance_id: ConnectorInstanceId,
    pub(crate) lifecycle: ConnectorLifecycle,
    pub(crate) policy_revision: u64,
    pub(crate) lifecycle_revision: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConnectorControlPlaneError {
    #[error("connector control configuration is invalid: {0}")]
    InvalidConfig(#[source] super::control_state::ConnectorControlStateError),
    #[error("connector control plane is disabled")]
    ControlPlaneDisabled,
    #[error("registered connector account is unknown")]
    UnknownAccount,
    #[error("authenticated subject is not bound to this connector account")]
    SubjectBindingMismatch,
    #[error("connector account is not active ({0:?})")]
    AccountNotActive(ConnectorLifecycle),
    #[error("connector entry point admission failed: {0}")]
    Admission(#[source] super::ConnectorAdmissionError),
    #[error("connector account authority is retired")]
    AuthorityRetired,
    #[error("connector account authority mutex is poisoned")]
    AuthorityPoisoned,
    #[error("connector control-plane state mutex is poisoned")]
    ControlPlaneStatePoisoned,
    #[error("connector account authority generation is exhausted")]
    AuthorityGenerationExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::{
        ConnectorConfiguration, ConnectorId, ConnectorPolicySnapshot,
        control_state::{ConnectorControlConfig, RegisteredConnectorAccount},
    };

    fn account(subject: &str, lifecycle: ConnectorLifecycle) -> RegisteredConnectorAccount {
        RegisteredConnectorAccount {
            configuration: ConnectorConfiguration {
                connector_id: ConnectorId::LocalImport,
                account_id: None,
                subject_id: SubjectId::new(subject).unwrap(),
                credential_ref: None,
                policy: ConnectorPolicySnapshot::local_read_only(7),
            },
            lifecycle,
            lifecycle_revision: 11,
        }
    }

    fn plane(lifecycle: ConnectorLifecycle) -> ConnectorControlPlane {
        ConnectorControlPlane::from_config(&ConnectorControlConfig {
            schema_version: super::super::control_state::CONNECTOR_CONTROL_STATE_SCHEMA_VERSION,
            enabled: true,
            registered_accounts: vec![account("operator", lifecycle)],
        })
        .unwrap()
    }

    #[test]
    fn only_matching_authenticated_subject_receives_live_authority() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = ConnectorInstanceId::accountless(ConnectorId::LocalImport);
        let authority = plane
            .authorize_context_import(
                &AuthenticatedControlSession::test_authenticated(
                    SubjectId::new("operator").unwrap(),
                ),
                &instance,
            )
            .unwrap();
        authority.ensure_live().unwrap();
        assert!(authority.binding_matches(&instance, &SubjectId::new("operator").unwrap(), 7, 11));

        assert!(matches!(
            plane.authorize_context_import(
                &AuthenticatedControlSession::test_authenticated(SubjectId::new("other").unwrap(),),
                &instance,
            ),
            Err(ConnectorControlPlaneError::SubjectBindingMismatch)
        ));
    }

    #[test]
    fn disabled_paused_and_revoked_records_never_admit() {
        let instance = ConnectorInstanceId::accountless(ConnectorId::LocalImport);
        let session =
            AuthenticatedControlSession::test_authenticated(SubjectId::new("operator").unwrap());

        let disabled = ConnectorControlPlane::from_config(&ConnectorControlConfig {
            schema_version: super::super::control_state::CONNECTOR_CONTROL_STATE_SCHEMA_VERSION,
            enabled: false,
            registered_accounts: vec![account("operator", ConnectorLifecycle::Active)],
        })
        .unwrap();
        assert!(matches!(
            disabled.authorize_context_import(&session, &instance),
            Err(ConnectorControlPlaneError::ControlPlaneDisabled)
        ));

        for lifecycle in [ConnectorLifecycle::Paused, ConnectorLifecycle::Revoked] {
            assert!(matches!(
                plane(lifecycle).authorize_context_import(&session, &instance),
                Err(ConnectorControlPlaneError::AccountNotActive(actual)) if actual == lifecycle
            ));
        }
    }

    #[test]
    fn retirement_invalidates_an_already_issued_authority() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = ConnectorInstanceId::accountless(ConnectorId::LocalImport);
        let authority = plane
            .authorize_context_import(
                &AuthenticatedControlSession::test_authenticated(
                    SubjectId::new("operator").unwrap(),
                ),
                &instance,
            )
            .unwrap();
        plane.retire_account(&instance).unwrap();
        assert!(matches!(
            authority.ensure_live(),
            Err(ConnectorControlPlaneError::AuthorityRetired)
        ));
    }

    #[test]
    fn durable_reload_retires_old_authority_before_new_policy_can_admit() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = ConnectorInstanceId::accountless(ConnectorId::LocalImport);
        let session =
            AuthenticatedControlSession::test_authenticated(SubjectId::new("operator").unwrap());
        let authority = plane.authorize_context_import(&session, &instance).unwrap();

        plane
            .replace_after_durable_config_commit(&ConnectorControlConfig {
                schema_version: super::super::control_state::CONNECTOR_CONTROL_STATE_SCHEMA_VERSION,
                enabled: true,
                registered_accounts: vec![account("operator", ConnectorLifecycle::Revoked)],
            })
            .unwrap();

        assert!(matches!(
            authority.ensure_live(),
            Err(ConnectorControlPlaneError::AuthorityRetired)
        ));
        assert!(matches!(
            plane.authorize_context_import(&session, &instance),
            Err(ConnectorControlPlaneError::AccountNotActive(
                ConnectorLifecycle::Revoked
            ))
        ));
    }
}
