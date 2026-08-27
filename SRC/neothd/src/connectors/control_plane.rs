//! In-crate, revocable CC-01 account authority.
//!
//! No client-facing value can construct an [`AuthenticatedControlSession`], an
//! [`AccountAuthority`], [`ContextImportRuntimeBinding`], or a
//! [`ContextImportOperationLease`]. This is only a policy/control substrate:
//! it starts no work and exposes no store, planner, credential, action, MCP,
//! or GroundTruth capability.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Condvar, Mutex, Weak},
};

use crate::config::PreparedFreedomUpdate;

use super::{
    ConnectorEntryPoint, ConnectorInstanceId, SubjectId, admit_entry_point,
    control_state::{ConnectorControlConfig, ConnectorLifecycle, RegisteredConnectorAccount},
};

// The private same-user transport remains Unix-only. Its module also owns the
// platform-neutral guard and the fail-closed non-Unix stub, which the daemon
// needs to represent Windows as unavailable without a weaker transport.
pub(crate) mod rpc;

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
    next_runtime_id: u64,
    next_operation_id: u64,
    active_operation_ids: BTreeSet<u64>,
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
                next_runtime_id: 1,
                next_operation_id: 1,
                active_operation_ids: BTreeSet::new(),
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

    fn accepting_leases(&self) -> Result<bool, ConnectorControlPlaneError> {
        self.state
            .lock()
            .map(|state| state.accepting_leases)
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)
    }
}

#[derive(Debug)]
struct GateRestore {
    gate: Arc<AccountLeaseGate>,
    accepting_leases: bool,
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
    /// through its final durable commit. The plane check is its admission
    /// linearization point; it is deliberately released before acquiring the
    /// account gate. A transition which wins that subsequent gate race rejects
    /// this lease, while a lease which increments the live count first is
    /// drained by that transition. No broad plane mutex is held across a
    /// per-account gate wait.
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
        if slot.emergency_retirement_in_progress {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
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
        // Do not invert the permit's gate-only lock ordering. The exact slot
        // and generation were bound while `control` was locked above; if a
        // transition starts after that point, it must retire this same gate
        // before it can finish and either wins this gate race (rejecting us) or
        // drains the live lease recorded below.
        drop(control);
        let mut state = gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases || state.generation != self.generation {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        let operation_id = state.next_operation_id;
        state.next_operation_id = state
            .next_operation_id
            .checked_add(1)
            .ok_or(ConnectorControlPlaneError::OperationIdExhausted)?;
        state.live_leases = state
            .live_leases
            .checked_add(1)
            .ok_or(ConnectorControlPlaneError::LeaseCountExhausted)?;
        if !state.active_operation_ids.insert(operation_id) {
            state.live_leases -= 1;
            return Err(ConnectorControlPlaneError::OperationIdCollision);
        }
        drop(state);
        Ok(ContextImportOperationLease {
            instance_id: self.instance_id.clone(),
            subject_id: self.subject_id.clone(),
            policy_revision: self.policy_revision,
            lifecycle_revision: self.lifecycle_revision,
            gate,
            generation: self.generation,
            runtime_id: 0,
            operation_id,
        })
    }

    /// Mint a non-live runtime-root binding. It does not increment the gate's
    /// live-operation count, so an idle coordinator cannot block pause/revoke
    /// or a durable transition. Each effectful operation must later acquire a
    /// short-lived lease from this exact binding.
    pub(crate) fn acquire_context_import_runtime(
        &self,
    ) -> Result<ContextImportRuntimeBinding, ConnectorControlPlaneError> {
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
        if slot.emergency_retirement_in_progress {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
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
        let gate = Arc::clone(&slot.gate);
        drop(control);
        let mut state = gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases || state.generation != self.generation {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        let runtime_id = state.next_runtime_id;
        state.next_runtime_id = state
            .next_runtime_id
            .checked_add(1)
            .ok_or(ConnectorControlPlaneError::RuntimeIdExhausted)?;
        drop(state);
        Ok(ContextImportRuntimeBinding {
            instance_id: self.instance_id.clone(),
            subject_id: self.subject_id.clone(),
            policy_revision: self.policy_revision,
            lifecycle_revision: self.lifecycle_revision,
            plane_state: Arc::clone(&plane),
            gate,
            generation: self.generation,
            runtime_id,
        })
    }
}

/// Test-only fixture for runtime/store behavioral tests. It deliberately
/// reaches the same authenticated-session -> authority -> runtime-pair path
/// as production will, but exports no production session issuer or mint.
#[cfg(test)]
pub(crate) fn test_context_import_runtime_fixture(
    instance_id: ConnectorInstanceId,
    subject_id: SubjectId,
    policy_revision: u64,
    lifecycle_revision: u64,
) -> anyhow::Result<ContextImportRuntimeBinding> {
    anyhow::ensure!(
        instance_id.connector_id == super::ConnectorId::LocalImport,
        "the context-import runtime fixture supports only local_import"
    );
    anyhow::ensure!(
        policy_revision != 0 && lifecycle_revision != 0,
        "the context-import runtime fixture requires nonzero revisions"
    );
    let config = ConnectorControlConfig {
        schema_version: super::control_state::CONNECTOR_CONTROL_STATE_SCHEMA_VERSION,
        enabled: true,
        registered_accounts: vec![RegisteredConnectorAccount {
            configuration: super::ConnectorConfiguration {
                connector_id: instance_id.connector_id,
                account_id: instance_id.account_id.clone(),
                subject_id: subject_id.clone(),
                credential_ref: None,
                policy: super::ConnectorPolicySnapshot::local_read_only(policy_revision),
            },
            lifecycle: ConnectorLifecycle::Active,
            lifecycle_revision,
        }],
    };
    let plane = ConnectorControlPlane::from_config(&config)?;
    let session = AuthenticatedControlSession::test_authenticated(subject_id);
    let authority = plane.authorize_context_import(&session, &instance_id)?;
    authority
        .acquire_context_import_runtime()
        .map_err(anyhow::Error::from)
}

/// Non-cloneable runtime-root binding for the ContextImport vertical slice.
/// It is a construction-time capability only: it has no Store, path, planner,
/// credential, action, MCP, or GroundTruth method. Runtime construction must
/// use it to obtain one short-lived exact operation lease for each operation.
#[derive(Debug)]
pub(crate) struct ContextImportRuntimeBinding {
    instance_id: ConnectorInstanceId,
    subject_id: SubjectId,
    policy_revision: u64,
    lifecycle_revision: u64,
    plane_state: Arc<Mutex<ConnectorControlPlaneState>>,
    gate: Arc<AccountLeaseGate>,
    generation: u64,
    runtime_id: u64,
}

impl ContextImportRuntimeBinding {
    /// Read-only identity accessors for a runtime which already owns this
    /// non-forgeable binding. They expose no constructor or authority mint and
    /// must not be accepted as a replacement for this binding or its lease.
    pub(crate) fn instance_id(&self) -> &ConnectorInstanceId {
        &self.instance_id
    }

    pub(crate) fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    pub(crate) const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    pub(crate) const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Derive the opaque, non-forgeable witness which an approved local-import
    /// root may retain. The runtime itself keeps this binding; the witness is
    /// intentionally insufficient to mint a runtime or lease on its own.
    pub(crate) fn capability_binding(&self) -> ContextImportCapabilityBinding {
        ContextImportCapabilityBinding {
            instance_id: self.instance_id.clone(),
            subject_id: self.subject_id.clone(),
            policy_revision: self.policy_revision,
            lifecycle_revision: self.lifecycle_revision,
            gate: Arc::clone(&self.gate),
            generation: self.generation,
            runtime_id: self.runtime_id,
        }
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

    /// Acquire one short-lived exact operation lease. Its live count is held
    /// only until the caller completes or abandons the operation, so idle
    /// runtimes never hold up transition drainage.
    pub(crate) fn acquire_context_import_operation_lease(
        &self,
    ) -> Result<ContextImportOperationLease, ConnectorControlPlaneError> {
        let control = self
            .plane_state
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
        if slot.emergency_retirement_in_progress
            || slot.account.configuration.subject_id != self.subject_id
            || slot.account.configuration.policy.revision != self.policy_revision
            || slot.account.lifecycle_revision != self.lifecycle_revision
            || !Arc::ptr_eq(&slot.gate, &self.gate)
        {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        let gate = Arc::clone(&slot.gate);
        drop(control);
        let mut state = gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases || state.generation != self.generation {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        let operation_id = state.next_operation_id;
        state.next_operation_id = state
            .next_operation_id
            .checked_add(1)
            .ok_or(ConnectorControlPlaneError::OperationIdExhausted)?;
        state.live_leases = state
            .live_leases
            .checked_add(1)
            .ok_or(ConnectorControlPlaneError::LeaseCountExhausted)?;
        if !state.active_operation_ids.insert(operation_id) {
            state.live_leases -= 1;
            return Err(ConnectorControlPlaneError::OperationIdCollision);
        }
        drop(state);
        Ok(ContextImportOperationLease {
            instance_id: self.instance_id.clone(),
            subject_id: self.subject_id.clone(),
            policy_revision: self.policy_revision,
            lifecycle_revision: self.lifecycle_revision,
            gate,
            generation: self.generation,
            runtime_id: self.runtime_id,
            operation_id,
        })
    }

    pub(crate) fn matches_operation_lease(&self, lease: &ContextImportOperationLease) -> bool {
        self.binding_matches(
            &lease.instance_id,
            &lease.subject_id,
            lease.policy_revision,
            lease.lifecycle_revision,
        ) && self.generation == lease.generation
            && self.runtime_id == lease.runtime_id
            && Arc::ptr_eq(&self.gate, &lease.gate)
    }
}

/// Opaque capability-side witness of one runtime binding. It has no
/// constructor, identity tuple accessor, capability mint, or effect surface.
/// The runtime must retain the original [`ContextImportRuntimeBinding`] and
/// recheck both that binding and this witness against every operation lease.
#[derive(Debug)]
pub(crate) struct ContextImportCapabilityBinding {
    instance_id: ConnectorInstanceId,
    subject_id: SubjectId,
    policy_revision: u64,
    lifecycle_revision: u64,
    gate: Arc<AccountLeaseGate>,
    generation: u64,
    runtime_id: u64,
}

impl ContextImportCapabilityBinding {
    /// Produce an opaque plan/evidence witness from an already-bound approved
    /// root. The copy remains non-constructible and has the same exact
    /// runtime identity; it lets a retained plan prove that its root and a
    /// runtime's original binding are the same pair.
    pub(crate) fn for_evidence(&self) -> Self {
        Self {
            instance_id: self.instance_id.clone(),
            subject_id: self.subject_id.clone(),
            policy_revision: self.policy_revision,
            lifecycle_revision: self.lifecycle_revision,
            gate: Arc::clone(&self.gate),
            generation: self.generation,
            runtime_id: self.runtime_id,
        }
    }

    pub(crate) fn matches_runtime_binding(&self, binding: &ContextImportRuntimeBinding) -> bool {
        self.instance_id == binding.instance_id
            && self.subject_id == binding.subject_id
            && self.policy_revision == binding.policy_revision
            && self.lifecycle_revision == binding.lifecycle_revision
            && self.generation == binding.generation
            && self.runtime_id == binding.runtime_id
            && Arc::ptr_eq(&self.gate, &binding.gate)
    }

    pub(crate) fn matches_operation_lease(&self, lease: &ContextImportOperationLease) -> bool {
        self.instance_id == lease.instance_id
            && self.subject_id == lease.subject_id
            && self.policy_revision == lease.policy_revision
            && self.lifecycle_revision == lease.lifecycle_revision
            && self.generation == lease.generation
            && self.runtime_id == lease.runtime_id
            && Arc::ptr_eq(&self.gate, &lease.gate)
    }
}

/// A non-cloneable, exact-generation lease for one future ContextImport
/// operation. It carries no filesystem, database, planner, credential,
/// network, action, MCP, or GroundTruth capability. The later runtime must
/// retain this value until its work has completed or failed. Final SQLite and
/// receipt-ack mutations must execute through
/// `with_context_import_commit_permit`, not a preceding `ensure_live` probe.
#[derive(Debug)]
pub(crate) struct ContextImportOperationLease {
    instance_id: ConnectorInstanceId,
    subject_id: SubjectId,
    policy_revision: u64,
    lifecycle_revision: u64,
    gate: Arc<AccountLeaseGate>,
    generation: u64,
    runtime_id: u64,
    operation_id: u64,
}

impl ContextImportOperationLease {
    pub(crate) fn ensure_live(&self) -> Result<(), ConnectorControlPlaneError> {
        let state = self
            .gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases
            || state.generation != self.generation
            || !state.active_operation_ids.contains(&self.operation_id)
        {
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

    /// Admit one final ContextImport commit boundary against the exact account
    /// gate. The gate lock is released after that linearized check, before the
    /// closure runs. Because this method borrows the sole non-cloneable lease,
    /// its operation ID and live count remain registered for the entire SQLite
    /// transaction or paired outbox-ACK/delete. A pause, revoke, or replacement
    /// which wins before the check rejects the commit; one which starts
    /// afterwards must drain this live lease before it can complete or replace
    /// the generation.
    ///
    /// This deliberately does not hold the broad control-plane mutex during
    /// SQLite or WAL work. The operation lease's live-count and this per-account
    /// gate provide the required transition serialization without blocking
    /// unrelated control-plane inspection.
    pub(crate) fn with_context_import_commit_permit<T>(
        &self,
        commit: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let state = self
            .gate
            .state
            .lock()
            // `PoisonError<MutexGuard<_>>` is not Send, so never carry its
            // guard into anyhow. The owned domain error preserves fail-closed
            // behavior without leaking poisoned-lock internals.
            .map_err(|_| anyhow::Error::from(ConnectorControlPlaneError::AuthorityPoisoned))?;
        if !state.accepting_leases
            || state.generation != self.generation
            || !state.active_operation_ids.contains(&self.operation_id)
        {
            return Err(anyhow::Error::from(
                ConnectorControlPlaneError::AuthorityRetired,
            ));
        }
        drop(state);
        commit()
    }
}

impl Drop for ContextImportOperationLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.state.lock() {
            debug_assert!(state.live_leases > 0, "operation lease count underflow");
            let removed = state.active_operation_ids.remove(&self.operation_id);
            debug_assert!(removed, "operation lease id was not active on drop");
            if removed && state.live_leases > 0 {
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
    emergency_retirement_in_progress: bool,
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
                        emergency_retirement_in_progress: false,
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
            if control
                .accounts
                .values()
                .any(|slot| slot.emergency_retirement_in_progress)
            {
                return Err(ConnectorControlPlaneError::EmergencyRetirementInProgress);
            }
            validate_successor_config(&control.durable_config, &next_config)?;
            control.transition_in_progress = true;
            control
                .accounts
                .values()
                .map(|slot| slot.gate.clone())
                .collect::<Vec<_>>()
        };

        let previous_gates = match gates
            .iter()
            .map(|gate| {
                Ok(GateRestore {
                    gate: Arc::clone(gate),
                    accepting_leases: gate.accepting_leases()?,
                })
            })
            .collect::<Result<Vec<_>, ConnectorControlPlaneError>>()
        {
            Ok(previous_gates) => previous_gates,
            Err(error) => {
                if let Ok(mut control) = self.state.lock() {
                    control.transition_in_progress = false;
                }
                return Err(error);
            }
        };

        for restore in &previous_gates {
            if let Err(error) = restore.gate.retire_and_drain() {
                // Gate failure means this transition cannot prove that every
                // old generation is safely drained. Reopening captured gates
                // after that error could resurrect authority, including an
                // emergency-retired account, so globally fail closed instead.
                self.fail_closed_after_prepare_failure();
                return Err(error);
            }
        }

        Ok(ConnectorControlTransition {
            state: Arc::clone(&self.state),
            previous_gates,
            next_config,
            durable_published: false,
            completed: false,
        })
    }

    fn fail_closed_after_prepare_failure(&self) {
        // The state flag is the only authority admission root, so this is
        // fail-closed even if an individual gate is poisoned. Do not re-enter
        // any account gate while holding the broad plane mutex.
        if let Ok(mut control) = self.state.lock() {
            control.failed_closed = true;
            control.transition_in_progress = false;
        }
    }

    pub(crate) fn authorize_context_import(
        &self,
        session: &AuthenticatedControlSession,
        instance_id: &ConnectorInstanceId,
    ) -> Result<AccountAuthority, ConnectorControlPlaneError> {
        let (subject_id, policy_revision, lifecycle_revision, gate) = {
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
            if slot.emergency_retirement_in_progress {
                return Err(ConnectorControlPlaneError::AuthorityRetired);
            }
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
            (
                slot.account.configuration.subject_id.clone(),
                slot.account.configuration.policy.revision,
                slot.account.lifecycle_revision,
                Arc::clone(&slot.gate),
            )
        };

        // Keep every broad-plane -> account-gate handoff non-blocking. A
        // transition that starts after the admission snapshot either retires
        // this gate before we read it (rejecting the authority) or must later
        // drain any lease minted from it; lease acquisition rechecks the plane
        // state before it increments that live count.
        let state = gate
            .state
            .lock()
            .map_err(|_| ConnectorControlPlaneError::AuthorityPoisoned)?;
        if !state.accepting_leases {
            return Err(ConnectorControlPlaneError::AuthorityRetired);
        }
        Ok(AccountAuthority {
            instance_id: instance_id.clone(),
            subject_id,
            policy_revision,
            lifecycle_revision,
            plane_state: Arc::downgrade(&self.state),
            gate: Arc::downgrade(&gate),
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
        let gate = {
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
            let slot = control
                .accounts
                .get_mut(instance_id)
                .ok_or(ConnectorControlPlaneError::UnknownAccount)?;
            if slot.emergency_retirement_in_progress {
                return Err(ConnectorControlPlaneError::EmergencyRetirementInProgress);
            }
            // Linearize against transition and new lease admission, then drop
            // the broad plane lock before waiting on the account gate. A final
            // commit permit may safely inspect the plane while it holds that
            // gate; the marker keeps a transition from replacing the slot.
            slot.emergency_retirement_in_progress = true;
            Arc::clone(&slot.gate)
        };

        let result = gate.retire_and_drain();
        if result.is_ok()
            && let Ok(mut control) = self.state.lock()
            && let Some(slot) = control.accounts.get_mut(instance_id)
            && Arc::ptr_eq(&slot.gate, &gate)
        {
            slot.emergency_retirement_in_progress = false;
        }
        result
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
    previous_gates: Vec<GateRestore>,
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
        // A durable transition has already retired and drained every old gate
        // before this object exists. Marking the plane failed is therefore
        // sufficient to deny all new authority without re-entering account
        // gates while holding the broad plane mutex.
        control.failed_closed = true;
        control.transition_in_progress = false;
    }

    fn cancel_unpublished(&mut self) {
        let restore = self
            .state
            .lock()
            .map(|control| control.transition_in_progress && !control.failed_closed)
            .unwrap_or(false);
        if !restore {
            return;
        }
        // Keep `transition_in_progress` true until every gate has returned to
        // its captured pre-transition state. This avoids both plane->gate
        // inversion with a commit permit and resurrection of an emergency stop.
        for restore in &self.previous_gates {
            let _ = restore.gate.reopen(restore.accepting_leases);
        }
        if let Ok(mut control) = self.state.lock()
            && control.transition_in_progress
            && !control.failed_closed
        {
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
    #[error("connector account emergency retirement is in progress")]
    EmergencyRetirementInProgress,
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
    #[error("connector runtime binding identity is exhausted")]
    RuntimeIdExhausted,
    #[error("connector operation lease identity is exhausted")]
    OperationIdExhausted,
    #[error("connector operation lease identity unexpectedly collided")]
    OperationIdCollision,
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
    use std::{
        sync::{Arc, mpsc},
        time::{Duration, Instant},
    };

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

    fn wait_until(label: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready() {
            assert!(Instant::now() < deadline, "timed out waiting for {label}");
            std::thread::yield_now();
        }
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
    fn authenticated_authority_mints_only_a_matching_runtime_root_and_commit_permit() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = instance();
        let authority = plane
            .authorize_context_import(&session(), &instance)
            .unwrap();
        let binding = authority.acquire_context_import_runtime().unwrap();
        let lease = binding.acquire_context_import_operation_lease().unwrap();

        assert!(binding.binding_matches(&instance, &SubjectId::new("operator").unwrap(), 7, 11,));
        assert!(binding.matches_operation_lease(&lease));
        let capability_binding = binding.capability_binding();
        assert!(capability_binding.matches_runtime_binding(&binding));
        assert!(capability_binding.matches_operation_lease(&lease));
        let evidence_binding = capability_binding.for_evidence();
        assert!(evidence_binding.matches_runtime_binding(&binding));
        assert!(evidence_binding.matches_operation_lease(&lease));
        assert!(
            lease
                .with_context_import_commit_permit(|| -> anyhow::Result<()> { Ok(()) })
                .is_ok()
        );

        let independently_acquired = authority.acquire_context_import_operation_lease().unwrap();
        assert!(
            !binding.matches_operation_lease(&independently_acquired),
            "a runtime root must not accept another lease from the same generation"
        );
        assert!(
            !capability_binding.matches_operation_lease(&independently_acquired),
            "a capability witness must not accept another lease from the same generation"
        );
        drop(independently_acquired);
        let next_runtime_lease = binding.acquire_context_import_operation_lease().unwrap();
        assert!(binding.matches_operation_lease(&next_runtime_lease));
        assert!(capability_binding.matches_operation_lease(&next_runtime_lease));
        assert!(
            lease.operation_id != next_runtime_lease.operation_id,
            "each runtime operation must receive its own operation identity"
        );
        drop(next_runtime_lease);
    }

    #[test]
    fn commit_permit_fails_closed_when_its_account_gate_is_poisoned() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = instance();
        let authority = plane
            .authorize_context_import(&session(), &instance)
            .unwrap();
        let lease = authority.acquire_context_import_operation_lease().unwrap();
        let gate = Arc::clone(&lease.gate);
        assert!(
            std::thread::spawn(move || {
                let _guard = gate.state.lock().expect("fresh test gate must lock");
                panic!("deliberately poison the account gate");
            })
            .join()
            .is_err()
        );

        let error = lease
            .with_context_import_commit_permit(|| -> anyhow::Result<()> { Ok(()) })
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ConnectorControlPlaneError>(),
            Some(ConnectorControlPlaneError::AuthorityPoisoned)
        ));
    }

    #[test]
    fn idle_runtime_binding_does_not_block_or_survive_a_transition() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = instance();
        let authority = plane
            .authorize_context_import(&session(), &instance)
            .unwrap();
        let binding = authority.acquire_context_import_runtime().unwrap();
        let mut next = config(ConnectorLifecycle::Paused);
        next.registered_accounts[0].lifecycle_revision = 12;

        // No operation lease is live, so this cannot wait for an idle runtime.
        let transition = plane.begin_durable_transition(next).unwrap();
        drop(transition);
        assert!(matches!(
            binding.acquire_context_import_operation_lease(),
            Err(ConnectorControlPlaneError::AuthorityRetired)
        ));
    }

    #[test]
    fn operation_id_is_live_only_until_its_lease_drops() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = instance();
        let authority = plane
            .authorize_context_import(&session(), &instance)
            .unwrap();
        let binding = authority.acquire_context_import_runtime().unwrap();
        let lease = binding.acquire_context_import_operation_lease().unwrap();
        let operation_id = lease.operation_id;
        {
            let state = binding.gate.state.lock().unwrap();
            assert!(state.active_operation_ids.contains(&operation_id));
            assert_eq!(state.live_leases, 1);
        }
        drop(lease);
        {
            let state = binding.gate.state.lock().unwrap();
            assert!(!state.active_operation_ids.contains(&operation_id));
            assert_eq!(state.live_leases, 0);
        }
    }

    #[test]
    fn commit_permit_never_deadlocks_an_emergency_retirement_plane_probe() {
        let plane = Arc::new(plane(ConnectorLifecycle::Active));
        let instance = instance();
        let authority = plane
            .authorize_context_import(&session(), &instance)
            .unwrap();
        let lease = authority.acquire_context_import_operation_lease().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (retired_tx, retired_rx) = mpsc::channel();
        let probe_plane = Arc::clone(&plane);
        let probe_instance = instance.clone();

        lease
            .with_context_import_commit_permit(|| -> anyhow::Result<()> {
                let retire_plane = Arc::clone(&probe_plane);
                std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    retired_tx
                        .send(retire_plane.retire_account(&probe_instance))
                        .unwrap();
                });
                started_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("retirement worker must start");

                wait_until(
                    "emergency retirement to close the account gate",
                    || match lease.gate.state.try_lock() {
                        Ok(state) => !state.accepting_leases,
                        Err(std::sync::TryLockError::WouldBlock) => false,
                        Err(std::sync::TryLockError::Poisoned(_)) => {
                            panic!("account gate was unexpectedly poisoned")
                        }
                    },
                );
                {
                    let state = lease.gate.state.lock().unwrap();
                    assert!(state.active_operation_ids.contains(&lease.operation_id));
                    assert_eq!(state.live_leases, 1);
                }

                assert!(matches!(
                    probe_plane.authorize_context_import(&session(), &instance),
                    Err(ConnectorControlPlaneError::AuthorityRetired)
                ));
                assert!(matches!(
                    lease.ensure_live(),
                    Err(ConnectorControlPlaneError::AuthorityRetired)
                ));
                assert!(matches!(
                    authority.acquire_context_import_operation_lease(),
                    Err(ConnectorControlPlaneError::AuthorityRetired)
                ));
                assert!(matches!(
                    retired_rx.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));

                probe_plane.status().map_err(anyhow::Error::from)?;
                Ok(())
            })
            .unwrap();

        assert!(matches!(
            retired_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(lease);
        retired_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("retirement must finish after the live lease drops")
            .unwrap();
    }

    #[test]
    fn aborted_same_config_transition_cannot_reopen_an_emergency_retirement() {
        let plane = plane(ConnectorLifecycle::Active);
        let instance = instance();
        plane.retire_account(&instance).unwrap();
        let transition = plane
            .begin_durable_transition(config(ConnectorLifecycle::Active))
            .unwrap();
        drop(transition);
        assert!(matches!(
            plane.authorize_context_import(&session(), &instance),
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
        let (transition_tx, transition_rx) = mpsc::channel();
        let transition_plane = Arc::clone(&plane);
        let transition_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            transition_tx
                .send(transition_plane.begin_durable_transition(next))
                .unwrap();
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("transition worker must start");
        wait_until("transition admission to close", || {
            match plane.state.try_lock() {
                Ok(control) => control.transition_in_progress,
                Err(std::sync::TryLockError::WouldBlock) => false,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    panic!("control plane was unexpectedly poisoned")
                }
            }
        });

        assert!(matches!(
            authority.acquire_context_import_operation_lease(),
            Err(ConnectorControlPlaneError::TransitionInProgress)
        ));
        assert!(matches!(
            transition_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(lease);
        let transition = transition_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("transition must finish after the existing lease drains")
            .unwrap();
        transition_thread.join().unwrap();
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
