//! In-crate, revocable CC-01 account authority.
//!
//! No client-facing value can construct an [`AuthenticatedControlSession`], an
//! [`AccountAuthority`], or a [`ContextImportOperationLease`]. This is only a
//! policy/control substrate: it starts no work and exposes no store, planner,
//! credential, action, MCP, or GroundTruth capability.

use std::{
    collections::BTreeMap,
    sync::{Arc, Condvar, Mutex, Weak},
};

use crate::config::PreparedFreedomUpdate;

use super::{
    ConnectorEntryPoint, ConnectorInstanceId, SubjectId, admit_entry_point,
    control_state::{ConnectorControlConfig, ConnectorLifecycle, RegisteredConnectorAccount},
};

/// Capability representing a principal already authenticated by a later local
/// control transport. There is deliberately no production issuer in this
/// slice: fields, seal, and the only test constructor remain module-private so
/// a SubjectId supplied by a client cannot become authority.
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
    accepting_leases: bool,
    generation: u64,
    live_leases: usize,
}

#[derive(Debug)]
struct AccountLeaseGate {
    state: Mutex<AuthorityState>,
    drained: Condvar,
}

impl AccountLeaseGate {
    fn new(accepting_leases: bool) -> Self {
        Self {
            state: Mutex::new(AuthorityState {
                accepting_leases,
                generation: 1,
                live_leases: 0,
            }),
            drained: Condvar::new(),
        }
    }

    fn retire_and_drain(&self) -> Result<(), ConnectorControlPlaneError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        state.accepting_leases = false;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(ConnectorControlPlaneError::AuthorityGenerationExhausted)?;
        while state.live_leases != 0 {
            state = self
                .drained
                .wait(state)
                .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        }
        Ok(())
    }

    fn reopen(&self, accepting_leases: bool) -> Result<(), ConnectorControlPlaneError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        state.accepting_leases = accepting_leases;
        Ok(())
    }
}

/// A revocable, exact-binding authority for one admitted ContextImport entry
/// point. It intentionally has no `Deref`, principal getter, or effect method.
/// A future runtime must turn it into the non-cloneable operation lease and
/// retain that lease through its final storage commit.
#[derive(Clone, Debug)]
pub(crate) struct AccountAuthority {
    instance_id: ConnectorInstanceId,
    subject_id: SubjectId,
    policy_revision: u64,
    lifecycle_revision: u64,
    plane_state: Weak<Mutex<ConnectorControlPlaneState>>,
    gate: Weak<AccountLeaseGate>,
    generation: u64,
}

impl AccountAuthority {
    pub(crate) fn ensure_live(&self) -> Result<(), ConnectorControlPlaneError> {
        let gate = self
            .gate
            .upgrade()
            .ok_or(ConnectorControlPlaneError::AuthorityRetired)?;
        let state = gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases || state.generation != self.generation {
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

    /// Acquire the non-cloneable lease which future import code must keep
    /// through its final durable commit. This re-enters the plane lock before
    /// the account gate, closing the race where a transition has begun but has
    /// not yet retired the account gate.
    pub(crate) fn acquire_context_import_operation_lease(
        &self,
    ) -> Result<ContextImportOperationLease, ConnectorControlPlaneError> {
        let plane = self
            .plane_state
            .upgrade()
            .ok_or(ConnectorControlPlaneError::AuthorityRetired)?;
        let control = plane
            .lock()
            .map_err(|_| ConnectorControlPlaneError::ControlPlaneStatePoisoned)?;
        if control.failed_closed {
            return Err(ConnectorControlPlaneError::ProjectionFailedClosed);
        }
        if control.transition_in_progress {
            return Err(ConnectorControlPlaneError::TransitionInProgress);
        }
        let slot = control
            .accounts
            .get(&self.instance_id)
            .ok_or(ConnectorControlPlaneError::AuthorityRetired)?;
        let authority_gate = self
            .gate
            .upgrade()
            .ok_or(ConnectorControlPlaneError::AuthorityRetired)?;
        if slot.account.configuration.subject_id != self.subject_id
            || slot.account.configuration.policy.revision != self.policy_revision
            || slot.account.lifecycle_revision != self.lifecycle_revision
            || !Arc::ptr_eq(&slot.gate, &authority_gate)
        {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        let gate = slot.gate.clone();
        let mut state = gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases || state.generation != self.generation {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        state.live_leases = state
            .live_leases
            .checked_add(1)
            .ok_or(ConnectorControlPlaneError::LeaseCountExhausted)?;
        drop(state);
        drop(control);
        Ok(ContextImportOperationLease {
            instance_id: self.instance_id.clone(),
            subject_id: self.subject_id.clone(),
            policy_revision: self.policy_revision,
            lifecycle_revision: self.lifecycle_revision,
            gate,
            generation: self.generation,
        })
    }
}

/// A non-cloneable, exact-generation lease for one future ContextImport
/// operation. It carries no filesystem, database, planner, credential,
/// network, action, MCP, or GroundTruth capability. The later runtime must
/// call `ensure_live` immediately before each durable import commit and retain
/// this value until that commit has completed or failed.
#[derive(Debug)]
pub(crate) struct ContextImportOperationLease {
    instance_id: ConnectorInstanceId,
    subject_id: SubjectId,
    policy_revision: u64,
    lifecycle_revision: u64,
    gate: Arc<AccountLeaseGate>,
    generation: u64,
}

impl ContextImportOperationLease {
    pub(crate) fn ensure_live(&self) -> Result<(), ConnectorControlPlaneError> {
        let state = self
            .gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases || state.generation != self.generation {
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

impl Drop for ContextImportOperationLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.state.lock() {
            debug_assert!(state.live_leases > 0, "operation lease count underflow");
            if state.live_leases > 0 {
                state.live_leases -= 1;
                if state.live_leases == 0 {
                    self.gate.drained.notify_all();
                }
            }
        }
    }
}

#[derive(Debug)]
struct AccountSlot {
    account: RegisteredConnectorAccount,
    gate: Arc<AccountLeaseGate>,
}

#[derive(Debug)]
struct ConnectorControlPlaneState {
    durable_config: ConnectorControlConfig,
    accounts: BTreeMap<ConnectorInstanceId, AccountSlot>,
    transition_in_progress: bool,
    failed_closed: bool,
}

/// In-memory projection of one validated, durable connector-control config.
/// Constructing this type validates the complete config but grants no account
/// authority. `authorize_context_import` needs a non-forgeable authenticated
/// session and repeats CC-01 admission for the exact account.
#[derive(Debug)]
pub(crate) struct ConnectorControlPlane {
    state: Arc<Mutex<ConnectorControlPlaneState>>,
}

impl ConnectorControlPlane {
    pub(crate) fn from_config(
        config: &ConnectorControlConfig,
    ) -> Result<Self, ConnectorControlPlaneError> {
        Ok(Self {
            state: Arc::new(Mutex::new(Self::state_from_durable_config(config)?)),
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
                let accepting_leases = config.enabled && account.lifecycle.admits_context_import();
                Ok((
                    instance,
                    AccountSlot {
                        account,
                        gate: Arc::new(AccountLeaseGate::new(accepting_leases)),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ConnectorControlPlaneError>>()?;
        Ok(ConnectorControlPlaneState {
            durable_config: config.clone(),
            accounts,
            transition_in_progress: false,
            failed_closed: false,
        })
    }

    /// Close admission and drain all active import leases before any caller
    /// publishes its CAS-bound durable successor. The returned transition owns
    /// the only path to install that exact successor. Dropping an unpublished
    /// transition safely reopens the former generation; publishing followed by
    /// a failed install instead leaves the entire plane fail-closed.
    pub(crate) fn begin_durable_transition(
        &self,
        next_config: ConnectorControlConfig,
    ) -> Result<ConnectorControlTransition, ConnectorControlPlaneError> {
        next_config
            .validate()
            .map_err(ConnectorControlPlaneError::InvalidConfig)?;

        let gates = {
            let mut control = self
                .state
                .lock()
                .map_err(|_| ConnectorControlPlaneError::ControlPlaneStatePoisoned)?;
            if control.failed_closed {
                return Err(ConnectorControlPlaneError::ProjectionFailedClosed);
            }
            if control.transition_in_progress {
                return Err(ConnectorControlPlaneError::TransitionInProgress);
            }
            validate_successor_config(&control.durable_config, &next_config)?;
            control.transition_in_progress = true;
            control
                .accounts
                .values()
                .map(|slot| slot.gate.clone())
                .collect::<Vec<_>>()
        };

        for gate in &gates {
            if let Err(error) = gate.retire_and_drain() {
                self.cancel_transition_after_prepare_failure(&gates);
                return Err(error);
            }
        }

        Ok(ConnectorControlTransition {
            state: Arc::clone(&self.state),
            previous_gates: gates,
            next_config,
            durable_published: false,
            completed: false,
        })
    }

    fn cancel_transition_after_prepare_failure(&self, gates: &[Arc<AccountLeaseGate>]) {
        if let Ok(mut control) = self.state.lock() {
            for gate in gates {
                let accepting = control
                    .accounts
                    .values()
                    .find(|slot| Arc::ptr_eq(&slot.gate, gate))
                    .is_some_and(|slot| {
                        control.durable_config.enabled
                            && slot.account.lifecycle.admits_context_import()
                    });
                let _ = gate.reopen(accepting);
            }
            control.transition_in_progress = false;
        }
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
        if control.failed_closed {
            return Err(ConnectorControlPlaneError::ProjectionFailedClosed);
        }
        if control.transition_in_progress {
            return Err(ConnectorControlPlaneError::TransitionInProgress);
        }
        if !control.durable_config.enabled {
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
            .gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        Ok(AccountAuthority {
            instance_id: instance_id.clone(),
            subject_id: slot.account.configuration.subject_id.clone(),
            policy_revision: slot.account.configuration.policy.revision,
            lifecycle_revision: slot.account.lifecycle_revision,
            plane_state: Arc::downgrade(&self.state),
            gate: Arc::downgrade(&slot.gate),
            generation: state.generation,
        })
    }

    /// Retire only in-memory authority as an emergency, fail-closed stop.
    /// Durable pause/revoke/policy replacement must use
    /// `begin_durable_transition` and its CAS-bound publication path.
    pub(crate) fn retire_account(
        &self,
        instance_id: &ConnectorInstanceId,
    ) -> Result<(), ConnectorControlPlaneError> {
        let control = self
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::ControlPlaneStatePoisoned)?;
        if control.failed_closed {
            return Err(ConnectorControlPlaneError::ProjectionFailedClosed);
        }
        // Keep the plane lock until the selected gate is fully drained. This
        // makes emergency retirement and durable replacement one state-machine
        // boundary: a transition cannot select/replace a generation after this
        // call has reported success, while a lease Drop needs only the gate
        // lock and can therefore always let this drain complete.
        if control.transition_in_progress {
            return Err(ConnectorControlPlaneError::TransitionInProgress);
        }
        control
            .accounts
            .get(instance_id)
            .ok_or(ConnectorControlPlaneError::UnknownAccount)?
            .gate
            .retire_and_drain()
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

/// Exclusive successor transaction for connector-control state. It is private
/// to the crate and accepts only a CAS-bound `PreparedFreedomUpdate`; no RPC
/// client can ask the projection to install arbitrary control state.
#[derive(Debug)]
pub(crate) struct ConnectorControlTransition {
    state: Arc<Mutex<ConnectorControlPlaneState>>,
    previous_gates: Vec<Arc<AccountLeaseGate>>,
    next_config: ConnectorControlConfig,
    durable_published: bool,
    completed: bool,
}

impl ConnectorControlTransition {
    /// Publish the exact reviewed config generation first, then install its
    /// matching projection. If installation cannot complete after publication,
    /// every connector account remains globally fail-closed rather than using
    /// a stale projection against newer durable policy.
    pub(crate) fn commit_durable_update(
        mut self,
        update: PreparedFreedomUpdate,
    ) -> Result<(), ConnectorControlPlaneError> {
        update
            .commit_context_connectors_if_matches(&self.next_config)
            .map_err(ConnectorControlPlaneError::DurablePublication)?;
        self.durable_published = true;
        self.install_after_durable_commit()
    }

    fn install_after_durable_commit(&mut self) -> Result<(), ConnectorControlPlaneError> {
        let next = ConnectorControlPlane::state_from_durable_config(&self.next_config)?;
        let mut control = self
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::ControlPlaneStatePoisoned)?;
        if !control.transition_in_progress || control.failed_closed {
            self.fail_closed_locked(&mut control);
            return Err(ConnectorControlPlaneError::ProjectionInstallRejected);
        }
        *control = next;
        self.completed = true;
        Ok(())
    }

    fn fail_closed_locked(&self, control: &mut ConnectorControlPlaneState) {
        control.failed_closed = true;
        control.transition_in_progress = false;
        for slot in control.accounts.values() {
            let _ = slot.gate.reopen(false);
        }
    }

    fn cancel_unpublished(&mut self) {
        if let Ok(mut control) = self.state.lock() {
            if !control.transition_in_progress || control.failed_closed {
                return;
            }
            for gate in &self.previous_gates {
                let accepting = control
                    .accounts
                    .values()
                    .find(|slot| Arc::ptr_eq(&slot.gate, gate))
                    .is_some_and(|slot| {
                        control.durable_config.enabled
                            && slot.account.lifecycle.admits_context_import()
                    });
                let _ = gate.reopen(accepting);
            }
            control.transition_in_progress = false;
        }
    }
}

impl Drop for ConnectorControlTransition {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.durable_published {
            if let Ok(mut control) = self.state.lock() {
                self.fail_closed_locked(&mut control);
            }
        } else {
            self.cancel_unpublished();
        }
    }
}

fn validate_successor_config(
    current: &ConnectorControlConfig,
    next: &ConnectorControlConfig,
) -> Result<(), ConnectorControlPlaneError> {
    for previous in &current.registered_accounts {
        let instance = previous.instance_id();
        let candidate = next.account(&instance);
        match candidate {
            Some(candidate) => {
                let policy_changed =
                    previous.configuration.policy != candidate.configuration.policy;
                let configuration_changed = previous.configuration != candidate.configuration;
                let lifecycle_changed = previous.lifecycle != candidate.lifecycle;
                if (configuration_changed || lifecycle_changed)
                    && candidate.lifecycle_revision <= previous.lifecycle_revision
                {
                    return Err(ConnectorControlPlaneError::StaleLifecycleRevision { instance });
                }
                if policy_changed
                    && candidate.configuration.policy.revision
                        <= previous.configuration.policy.revision
                {
                    return Err(ConnectorControlPlaneError::StalePolicyRevision { instance });
                }
                if !configuration_changed
                    && !lifecycle_changed
                    && candidate.lifecycle_revision != previous.lifecycle_revision
                {
                    return Err(ConnectorControlPlaneError::UnexpectedLifecycleRevision {
                        instance,
                    });
                }
            }
            None if previous.lifecycle != ConnectorLifecycle::Revoked => {
                return Err(ConnectorControlPlaneError::RemovalRequiresRevocation { instance });
            }
            None => {}
        }
    }
    Ok(())
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
    #[error("connector control transition is in progress")]
    TransitionInProgress,
    #[error("connector control projection is fail-closed after a durable update")]
    ProjectionFailedClosed,
    #[error("connector control projection rejected durable-install ordering")]
    ProjectionInstallRejected,
    #[error("connector durable config publication failed: {0}")]
    DurablePublication(#[source] anyhow::Error),
    #[error("connector account authority mutex is poisoned")]
    AuthorityPoisoned,
    #[error("connector control-plane state mutex is poisoned")]
    ControlPlaneStatePoisoned,
    #[error("connector account authority generation is exhausted")]
    AuthorityGenerationExhausted,
    #[error("connector operation lease count is exhausted")]
    LeaseCountExhausted,
    #[error("connector account `{instance:?}` changed without a newer lifecycle revision")]
    StaleLifecycleRevision { instance: ConnectorInstanceId },
    #[error("connector account `{instance:?}` changed policy without a newer policy revision")]
    StalePolicyRevision { instance: ConnectorInstanceId },
    #[error("connector account `{instance:?}` changed lifecycle revision without a state change")]
    UnexpectedLifecycleRevision { instance: ConnectorInstanceId },
    #[error("connector account `{instance:?}` must be durably revoked before removal")]
    RemovalRequiresRevocation { instance: ConnectorInstanceId },
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};

    use super::*;
    use crate::connectors::{
        ConnectorConfiguration, ConnectorId, ConnectorPolicySnapshot,
        control_state::{CONNECTOR_CONTROL_STATE_SCHEMA_VERSION, RegisteredConnectorAccount},
    };

    fn account(
        subject: &str,
        lifecycle: ConnectorLifecycle,
        policy_revision: u64,
        lifecycle_revision: u64,
    ) -> RegisteredConnectorAccount {
        RegisteredConnectorAccount {
            configuration: ConnectorConfiguration {
                connector_id: ConnectorId::LocalImport,
                account_id: None,
                subject_id: SubjectId::new(subject).unwrap(),
                credential_ref: None,
                policy: ConnectorPolicySnapshot::local_read_only(policy_revision),
            },
            lifecycle,
            lifecycle_revision,
        }
    }

    fn config(lifecycle: ConnectorLifecycle) -> ConnectorControlConfig {
        ConnectorControlConfig {
            schema_version: CONNECTOR_CONTROL_STATE_SCHEMA_VERSION,
            enabled: true,
            registered_accounts: vec![account("operator", lifecycle, 7, 11)],
        }
    }

    fn plane(lifecycle: ConnectorLifecycle) -> ConnectorControlPlane {
        ConnectorControlPlane::from_config(&config(lifecycle)).unwrap()
    }

    fn session() -> AuthenticatedControlSession {
        AuthenticatedControlSession::test_authenticated(SubjectId::new("operator").unwrap())
    }

    fn instance() -> ConnectorInstanceId {
        ConnectorInstanceId::accountless(ConnectorId::LocalImport)
    }

    #[test]
    fn only_matching_authenticated_subject_receives_live_authority() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = instance();
        let authority = plane
            .authorize_context_import(&session(), &instance)
            .unwrap();
        authority.ensure_live().unwrap();
        assert!(authority.binding_matches(&instance, &SubjectId::new("operator").unwrap(), 7, 11));

        assert!(matches!(
            plane.authorize_context_import(
                &AuthenticatedControlSession::test_authenticated(SubjectId::new("other").unwrap()),
                &instance,
            ),
            Err(ConnectorControlPlaneError::SubjectBindingMismatch)
        ));
    }

    #[test]
    fn operation_lease_is_exactly_bound_and_retirement_invalidates_it() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = instance();
        let authority = plane
            .authorize_context_import(&session(), &instance)
            .unwrap();
        let lease = authority.acquire_context_import_operation_lease().unwrap();
        assert!(lease.binding_matches(&instance, &SubjectId::new("operator").unwrap(), 7, 11));
        assert!(lease.ensure_live().is_ok());

        drop(lease);
        plane.retire_account(&instance).unwrap();
        assert!(matches!(
            authority.acquire_context_import_operation_lease(),
            Err(ConnectorControlPlaneError::AuthorityRetired)
        ));
    }

    #[test]
    fn transition_blocks_new_leases_then_drains_existing_leases() {
        let plane = Arc::new(plane(ConnectorLifecycle::Active));
        let instance = instance();
        let authority = plane
            .authorize_context_import(&session(), &instance)
            .unwrap();
        let lease = authority.acquire_context_import_operation_lease().unwrap();
        let mut next = config(ConnectorLifecycle::Paused);
        next.registered_accounts[0].lifecycle_revision = 12;

        let (started_tx, started_rx) = mpsc::channel();
        let transition_plane = Arc::clone(&plane);
        let transition = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            transition_plane.begin_durable_transition(next).unwrap()
        });
        started_rx.recv().unwrap();
        while !matches!(
            plane.authorize_context_import(&session(), &instance),
            Err(ConnectorControlPlaneError::TransitionInProgress)
        ) {
            std::thread::yield_now();
        }
        assert!(matches!(
            lease.ensure_live(),
            Err(ConnectorControlPlaneError::AuthorityRetired)
        ));
        drop(lease);
        let transition = transition.join().unwrap();
        drop(transition);

        // Publication did not happen, so Drop restores only fresh authorities
        // from the former durable config; the stale authority remains dead.
        assert!(authority.ensure_live().is_err());
        assert!(
            plane
                .authorize_context_import(&session(), &instance)
                .is_ok()
        );
    }

    #[test]
    fn stale_revision_and_unrevoked_removal_are_rejected_before_transition() {
        let plane = plane(ConnectorLifecycle::Active);
        let mut stale_policy = config(ConnectorLifecycle::Active);
        stale_policy.registered_accounts[0]
            .configuration
            .policy
            .revision = 6;
        stale_policy.registered_accounts[0].lifecycle_revision = 12;
        assert!(matches!(
            plane.begin_durable_transition(stale_policy),
            Err(ConnectorControlPlaneError::StalePolicyRevision { .. })
        ));

        let mut stale_lifecycle = config(ConnectorLifecycle::Paused);
        stale_lifecycle.registered_accounts[0].lifecycle_revision = 11;
        assert!(matches!(
            plane.begin_durable_transition(stale_lifecycle),
            Err(ConnectorControlPlaneError::StaleLifecycleRevision { .. })
        ));

        let mut removed = ConnectorControlConfig::default();
        removed.enabled = true;
        assert!(matches!(
            plane.begin_durable_transition(removed),
            Err(ConnectorControlPlaneError::RemovalRequiresRevocation { .. })
        ));
    }

    #[test]
    fn emergency_retirement_cannot_be_acknowledged_during_a_transition() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = instance();
        let next = ConnectorControlConfig {
            enabled: false,
            ..config(ConnectorLifecycle::Active)
        };
        let transition = plane.begin_durable_transition(next).unwrap();

        assert!(matches!(
            plane.retire_account(&instance),
            Err(ConnectorControlPlaneError::TransitionInProgress)
        ));
        drop(transition);
        assert!(
            plane
                .authorize_context_import(&session(), &instance)
                .is_ok()
        );
    }

    #[test]
    fn disabled_paused_and_revoked_records_never_admit() {
        let instance = instance();
        let disabled = ConnectorControlPlane::from_config(&ConnectorControlConfig {
            enabled: false,
            ..config(ConnectorLifecycle::Active)
        })
        .unwrap();
        assert!(matches!(
            disabled.authorize_context_import(&session(), &instance),
            Err(ConnectorControlPlaneError::ControlPlaneDisabled)
        ));
        for lifecycle in [ConnectorLifecycle::Paused, ConnectorLifecycle::Revoked] {
            assert!(matches!(
                plane(lifecycle).authorize_context_import(&session(), &instance),
                Err(ConnectorControlPlaneError::AccountNotActive(actual)) if actual == lifecycle
            ));
        }
    }
}
