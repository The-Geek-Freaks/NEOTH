//! Authenticated, operator-directed transfer of secret-bearing data.
//!
//! This module is deliberately transport-agnostic. CLI, GUI, and channel
//! adapters must all produce the same [`OperatorCommand`], execute the resulting
//! single-use permit, and supply independently verified delivery evidence before
//! a move may delete its source.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use std::collections::HashSet;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

const KEY_DERIVATION_DOMAIN: &[u8] = b"neoth.secret-transfer.authority-key.v1";
const COMMAND_DOMAIN: &[u8] = b"neoth.secret-transfer.command.v1";
const MAX_BINDING_COMPONENT_BYTES: usize = 4096;

/// Errors produced by the secret-transfer authority and state machine.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretTransferError {
    #[error("{field} must not be empty")]
    EmptyBinding { field: &'static str },
    #[error("{field} exceeds the 4096-byte binding limit")]
    BindingTooLong { field: &'static str },
    #[error("{field} contains control characters")]
    InvalidBinding { field: &'static str },
    #[error("transfer expiry must be later than its issue time")]
    InvalidLifetime,
    #[error("secret-transfer HMAC keys must contain at least 32 bytes")]
    WeakAuthorityKey,
    #[error("transfer permit is not valid before its issue time")]
    NotYetValid,
    #[error("transfer permit has expired")]
    Expired,
    #[error("transfer permit does not match the exact command binding")]
    BindingMismatch,
    #[error("transfer permit authentication failed")]
    InvalidPermitAuthentication,
    #[error("transfer permit nonce has already been consumed")]
    Replay,
    #[error("durable permit-consumption store is unavailable")]
    ConsumptionStoreUnavailable,
    #[error("cannot transition a transfer from {from:?} via {attempted}")]
    IllegalTransition {
        from: TransferPhase,
        attempted: &'static str,
    },
    #[error("delivery receipt does not match the authorised transfer")]
    ReceiptBindingMismatch,
    #[error("delivery receipt was not independently verified")]
    ReceiptUnverified,
    #[error("copy transfers must not delete their source")]
    SourceDeletionForbiddenForCopy,
    #[error("a move cannot delete its source before verified delivery")]
    MoveDeletionRequiresVerifiedReceipt,
}

/// A secret-bearing payload with consuming access only.
///
/// The type is intentionally neither `Clone` nor `Serialize`. Its `Debug`
/// representation is redacted and its allocation is zeroed on drop, including
/// during unwinding from the consuming callback.
pub struct SecretPayload {
    bytes: Vec<u8>,
}

impl SecretPayload {
    /// Wrap bytes without copying them.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Number of payload bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// SHA-256 digest used to bind the source without exposing its bytes.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    /// Expose the bytes to exactly one consuming callback.
    ///
    /// The payload is dropped and zeroized immediately after the callback
    /// returns (or unwinds).
    pub fn expose_once<R>(self, consume: impl FnOnce(&[u8]) -> R) -> R {
        consume(&self.bytes)
    }
}

impl From<Vec<u8>> for SecretPayload {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<String> for SecretPayload {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl fmt::Debug for SecretPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPayload")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SecretPayload {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Operator identity metadata supplied by an already-authenticated caller.
///
/// This value does not authenticate anybody. The upstream local/session
/// boundary authenticates the operator; crate-private permit minting then binds
/// this non-secret metadata to that decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPrincipal {
    principal_id: String,
    operator_session_id: String,
}

impl OperatorPrincipal {
    /// Create exact, non-secret principal/session metadata.
    pub fn new_metadata(
        principal_id: impl Into<String>,
        operator_session_id: impl Into<String>,
    ) -> Result<Self, SecretTransferError> {
        let value = Self {
            principal_id: principal_id.into(),
            operator_session_id: operator_session_id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Stable operator identifier.
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Stable operator-session identifier (never a bearer token).
    pub fn operator_session_id(&self) -> &str {
        &self.operator_session_id
    }

    fn validate(&self) -> Result<(), SecretTransferError> {
        validate_component("principal_id", &self.principal_id)?;
        validate_component("operator_session_id", &self.operator_session_id)
    }
}

/// Exact origin of an operator command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandOrigin {
    surface: String,
    instance_id: String,
    conversation_id: String,
}

impl CommandOrigin {
    /// Bind the command to one UI/channel surface, NEOTH instance, and
    /// conversation.
    pub fn new(
        surface: impl Into<String>,
        instance_id: impl Into<String>,
        conversation_id: impl Into<String>,
    ) -> Result<Self, SecretTransferError> {
        let value = Self {
            surface: surface.into(),
            instance_id: instance_id.into(),
            conversation_id: conversation_id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Origin surface, for example `cli`, `gui`, or `telegram`.
    pub fn surface(&self) -> &str {
        &self.surface
    }

    /// NEOTH instance from which the command originated.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Exact conversation/session in which the command was issued.
    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    fn validate(&self) -> Result<(), SecretTransferError> {
        validate_component("origin.surface", &self.surface)?;
        validate_component("origin.instance_id", &self.instance_id)?;
        validate_component("origin.conversation_id", &self.conversation_id)
    }
}

/// Exact source object and content identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceBinding {
    source_id: String,
    content_sha256: [u8; 32],
    byte_len: u64,
}

impl SourceBinding {
    /// Bind an immutable source identifier to the bytes observed at planning.
    pub fn new(
        source_id: impl Into<String>,
        content_sha256: [u8; 32],
        byte_len: u64,
    ) -> Result<Self, SecretTransferError> {
        let value = Self {
            source_id: source_id.into(),
            content_sha256,
            byte_len,
        };
        value.validate()?;
        Ok(value)
    }

    /// Canonical source identifier (path, vault item ID, or provider object ID).
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Digest of the exact source bytes authorised for transfer.
    pub fn content_sha256(&self) -> &[u8; 32] {
        &self.content_sha256
    }

    /// Length of the exact source bytes.
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    fn validate(&self) -> Result<(), SecretTransferError> {
        validate_component("source.source_id", &self.source_id)
    }
}

/// Exact destination, with no wildcard or inferred recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationBinding {
    transport: String,
    account_id: String,
    destination_id: String,
}

impl DestinationBinding {
    /// Create an exact transport/account/recipient binding.
    pub fn new(
        transport: impl Into<String>,
        account_id: impl Into<String>,
        destination_id: impl Into<String>,
    ) -> Result<Self, SecretTransferError> {
        let value = Self {
            transport: transport.into(),
            account_id: account_id.into(),
            destination_id: destination_id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Transport adapter identifier.
    pub fn transport(&self) -> &str {
        &self.transport
    }

    /// Exact sending account or local connector identity.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Exact recipient/object locator understood by that transport.
    pub fn destination_id(&self) -> &str {
        &self.destination_id
    }

    /// Stable digest used in receipts and audit records.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(encode_destination(self)).into()
    }

    fn validate(&self) -> Result<(), SecretTransferError> {
        validate_component("destination.transport", &self.transport)?;
        validate_component("destination.account_id", &self.account_id)?;
        validate_component("destination.destination_id", &self.destination_id)
    }
}

/// Copy preserves the source; move may delete it only after verified delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferOperation {
    Copy,
    Move,
}

impl TransferOperation {
    const fn wire_tag(self) -> u8 {
        match self {
            Self::Copy => 1,
            Self::Move => 2,
        }
    }
}

/// Caller-supplied unique nonce for one operator command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferNonce([u8; 32]);

impl TransferNonce {
    /// Wrap a cryptographically random nonce.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Fully typed operator intent. It contains metadata only, never secret bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCommand {
    principal: OperatorPrincipal,
    origin: CommandOrigin,
    turn_request_id: String,
    source: SourceBinding,
    destination: DestinationBinding,
    operation: TransferOperation,
    issued_at_unix: i64,
    expires_at_unix: i64,
    nonce: TransferNonce,
}

impl OperatorCommand {
    /// Build an explicit, time-bounded transfer command.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: OperatorPrincipal,
        origin: CommandOrigin,
        turn_request_id: impl Into<String>,
        source: SourceBinding,
        destination: DestinationBinding,
        operation: TransferOperation,
        issued_at_unix: i64,
        expires_at_unix: i64,
        nonce: TransferNonce,
    ) -> Result<Self, SecretTransferError> {
        let value = Self {
            principal,
            origin,
            turn_request_id: turn_request_id.into(),
            source,
            destination,
            operation,
            issued_at_unix,
            expires_at_unix,
            nonce,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn principal(&self) -> &OperatorPrincipal {
        &self.principal
    }

    pub fn origin(&self) -> &CommandOrigin {
        &self.origin
    }

    /// Exact user turn/request ID that produced this command.
    pub fn turn_request_id(&self) -> &str {
        &self.turn_request_id
    }

    pub fn source(&self) -> &SourceBinding {
        &self.source
    }

    pub fn destination(&self) -> &DestinationBinding {
        &self.destination
    }

    pub const fn operation(&self) -> TransferOperation {
        self.operation
    }

    pub const fn issued_at_unix(&self) -> i64 {
        self.issued_at_unix
    }

    pub const fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }

    pub const fn nonce(&self) -> TransferNonce {
        self.nonce
    }

    fn validate(&self) -> Result<(), SecretTransferError> {
        self.principal.validate()?;
        self.origin.validate()?;
        validate_component("turn_request_id", &self.turn_request_id)?;
        self.source.validate()?;
        self.destination.validate()?;
        if self.expires_at_unix <= self.issued_at_unix {
            return Err(SecretTransferError::InvalidLifetime);
        }
        Ok(())
    }
}

/// HMAC-authenticated, non-clone permit for one exact command.
pub struct TransferPermit {
    command_digest: [u8; 32],
    authentication_tag: [u8; 32],
    nonce: TransferNonce,
}

impl fmt::Debug for TransferPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferPermit")
            .field("command_digest", &hex::encode(self.command_digest))
            .field("authentication_tag", &"[REDACTED]")
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// An authenticated plan waiting for its single permitted execution.
pub struct TransferPlan {
    command: OperatorCommand,
    permit: TransferPermit,
}

impl TransferPlan {
    /// The exact command covered by the authenticated permit.
    pub fn command(&self) -> &OperatorCommand {
        &self.command
    }

    /// Non-secret plan fingerprint suitable for receipts and audit.
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.permit.command_digest
    }

    /// Turn the plan into the pure state machine in [`TransferPhase::Planned`].
    pub fn into_execution(self) -> TransferExecution {
        let plan_fingerprint = self.permit.command_digest;
        TransferExecution {
            command: self.command,
            permit: Some(self.permit),
            plan_fingerprint,
            state: TransferState::Planned,
            verified_receipt: None,
        }
    }
}

/// HMAC authority derived from the active instance key or a test/injected key.
pub struct TransferAuthority {
    derived_key: Zeroizing<Vec<u8>>,
}

impl TransferAuthority {
    /// Domain-separate the active NEOTH instance HMAC key for transfers.
    ///
    /// Crate-private by design: only the daemon's authenticated operator
    /// boundary may obtain the active instance key and mint permits.
    pub(crate) fn from_active_instance_hmac_key(
        key: impl AsRef<[u8]>,
    ) -> Result<Self, SecretTransferError> {
        Self::derive(key.as_ref())
    }

    /// Inject a root HMAC key (primarily for isolated runtimes and tests).
    #[cfg(test)]
    fn from_injected_key(key: impl AsRef<[u8]>) -> Result<Self, SecretTransferError> {
        Self::derive(key.as_ref())
    }

    fn derive(root_key: &[u8]) -> Result<Self, SecretTransferError> {
        if root_key.len() < 32 {
            return Err(SecretTransferError::WeakAuthorityKey);
        }
        Ok(Self {
            derived_key: Zeroizing::new(
                crate::util::hmac::sha256(root_key, KEY_DERIVATION_DOMAIN).to_vec(),
            ),
        })
    }

    /// Authenticate an exact command into a single-use transfer plan.
    pub(crate) fn authorize(
        &self,
        command: OperatorCommand,
    ) -> Result<TransferPlan, SecretTransferError> {
        command.validate()?;
        let encoded = encode_command(&command);
        let command_digest = Sha256::digest(&encoded).into();
        let authentication_tag = crate::util::hmac::sha256(&self.derived_key, &encoded);
        let nonce = command.nonce;
        Ok(TransferPlan {
            command,
            permit: TransferPermit {
                command_digest,
                authentication_tag,
                nonce,
            },
        })
    }

    /// Verify an unconsumed permit against the exact command and current time.
    fn verify_permit(
        &self,
        permit: &TransferPermit,
        command: &OperatorCommand,
        now_unix: i64,
    ) -> Result<(), SecretTransferError> {
        command.validate()?;
        if now_unix < command.issued_at_unix {
            return Err(SecretTransferError::NotYetValid);
        }
        if now_unix >= command.expires_at_unix {
            return Err(SecretTransferError::Expired);
        }

        let encoded = encode_command(command);
        let command_digest: [u8; 32] = Sha256::digest(&encoded).into();
        if permit.nonce != command.nonce
            || !bool::from(permit.command_digest.ct_eq(&command_digest))
        {
            return Err(SecretTransferError::BindingMismatch);
        }
        let expected_tag = crate::util::hmac::sha256(&self.derived_key, &encoded);
        if !bool::from(permit.authentication_tag.ct_eq(&expected_tag)) {
            return Err(SecretTransferError::InvalidPermitAuthentication);
        }
        Ok(())
    }
}

impl fmt::Debug for TransferAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferAuthority")
            .field("derived_key", &"[REDACTED]")
            .finish()
    }
}

/// Metadata-only record a durable store must atomically consume before any
/// transfer effect begins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermitConsumptionRecord {
    pub plan_fingerprint: [u8; 32],
    pub nonce: TransferNonce,
    pub principal_id: String,
    pub origin_instance_id: String,
    pub turn_request_id: String,
    pub consumed_at_unix: i64,
}

/// Error contract for an atomic permit-consumption store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermitConsumptionError {
    /// The nonce was committed by an earlier execution.
    Replay,
    /// The store could not durably commit or prove the nonce.
    Unavailable,
}

/// Durable single-use boundary invoked after HMAC validation and before effect.
///
/// Production implementations must atomically persist the nonce (WAL/database
/// transaction plus required durability barrier) before returning `Ok(())`.
/// Returning `Unavailable` leaves the transfer planned and fail-closed.
pub trait PermitConsumptionStore {
    fn consume_once(
        &mut self,
        record: &PermitConsumptionRecord,
    ) -> Result<(), PermitConsumptionError>;
}

/// Process-local replay ledger for tests and explicitly ephemeral runtimes.
///
/// It does not survive restart and is therefore insufficient for production.
/// Production wiring must pass a durable [`PermitConsumptionStore`] to
/// [`TransferExecution::begin`].
#[derive(Debug, Default)]
#[cfg(test)]
pub struct PermitUseLedger {
    consumed: HashSet<TransferNonce>,
}

#[cfg(test)]
impl PermitUseLedger {
    /// Create an empty replay ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of consumed permits.
    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    /// Whether no permit has been consumed.
    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }
}

#[cfg(test)]
impl PermitConsumptionStore for PermitUseLedger {
    fn consume_once(
        &mut self,
        record: &PermitConsumptionRecord,
    ) -> Result<(), PermitConsumptionError> {
        if !self.consumed.insert(record.nonce) {
            return Err(PermitConsumptionError::Replay);
        }
        Ok(())
    }
}

/// Observable states of the transfer state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPhase {
    Planned,
    Executing,
    Delivered,
    SourceDeleted,
    Failed,
    Indeterminate,
}

/// Fixed, non-secret failure categories safe for receipts and audit logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferFailureReason {
    Authentication,
    SourceChanged,
    Transport,
    DestinationRejected,
    ReceiptRejected,
}

/// Fixed, non-secret uncertainty categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndeterminateReason {
    DeliveryOutcomeUnknown,
    SourceDeletionOutcomeUnknown,
    ProcessInterrupted,
}

/// Internal state; transitions are only available through [`TransferExecution`].
#[derive(Clone, Debug, PartialEq, Eq)]
enum TransferState {
    Planned,
    Executing,
    Delivered,
    SourceDeleted,
    Failed(TransferFailureReason),
    Indeterminate(IndeterminateReason),
}

impl TransferState {
    const fn phase(&self) -> TransferPhase {
        match self {
            Self::Planned => TransferPhase::Planned,
            Self::Executing => TransferPhase::Executing,
            Self::Delivered => TransferPhase::Delivered,
            Self::SourceDeleted => TransferPhase::SourceDeleted,
            Self::Failed(_) => TransferPhase::Failed,
            Self::Indeterminate(_) => TransferPhase::Indeterminate,
        }
    }
}

/// Receipt metadata safe to serialize: only bindings, lengths, and digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    plan_fingerprint: [u8; 32],
    source_sha256: [u8; 32],
    destination_digest: [u8; 32],
    byte_len: u64,
    operation: TransferOperation,
    delivered_at_unix: i64,
    transport_evidence_sha256: [u8; 32],
}

impl DeliveryReceipt {
    /// Build the normalized receipt that a transport verifier must validate.
    pub fn for_execution(
        execution: &TransferExecution,
        delivered_at_unix: i64,
        transport_evidence_sha256: [u8; 32],
    ) -> Result<Self, SecretTransferError> {
        execution.require_phase(TransferPhase::Executing, "create_delivery_receipt")?;
        Ok(Self {
            plan_fingerprint: execution.plan_fingerprint,
            source_sha256: execution.command.source.content_sha256,
            destination_digest: execution.command.destination.digest(),
            byte_len: execution.command.source.byte_len,
            operation: execution.command.operation,
            delivered_at_unix,
            transport_evidence_sha256,
        })
    }

    pub const fn plan_fingerprint(&self) -> &[u8; 32] {
        &self.plan_fingerprint
    }

    pub const fn source_sha256(&self) -> &[u8; 32] {
        &self.source_sha256
    }

    pub const fn destination_digest(&self) -> &[u8; 32] {
        &self.destination_digest
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn operation(&self) -> TransferOperation {
        self.operation
    }

    pub const fn delivered_at_unix(&self) -> i64 {
        self.delivered_at_unix
    }

    pub const fn transport_evidence_sha256(&self) -> &[u8; 32] {
        &self.transport_evidence_sha256
    }
}

/// Trust boundary implemented by each transport after checking its real remote
/// acknowledgement (message ID lookup, object HEAD, checksum, and so on).
pub trait DeliveryReceiptVerifier {
    /// Return true only for a receipt proven by the destination transport.
    fn verify_delivery(&self, receipt: &DeliveryReceipt) -> bool;
}

impl<F> DeliveryReceiptVerifier for F
where
    F: Fn(&DeliveryReceipt) -> bool,
{
    fn verify_delivery(&self, receipt: &DeliveryReceipt) -> bool {
        self(receipt)
    }
}

/// Stateful execution of one authenticated transfer plan.
pub struct TransferExecution {
    command: OperatorCommand,
    permit: Option<TransferPermit>,
    plan_fingerprint: [u8; 32],
    state: TransferState,
    verified_receipt: Option<DeliveryReceipt>,
}

impl TransferExecution {
    /// Current state-machine phase.
    pub const fn phase(&self) -> TransferPhase {
        self.state.phase()
    }

    /// Exact authenticated command.
    pub fn command(&self) -> &OperatorCommand {
        &self.command
    }

    /// Start once, after verifying expiry/HMAC and durably consuming the permit.
    pub fn begin<S: PermitConsumptionStore>(
        &mut self,
        authority: &TransferAuthority,
        consumption_store: &mut S,
        now_unix: i64,
    ) -> Result<(), SecretTransferError> {
        self.require_phase(TransferPhase::Planned, "begin")?;
        let permit = self
            .permit
            .as_ref()
            .expect("planned transfer always retains its permit");
        authority.verify_permit(permit, &self.command, now_unix)?;
        let consumption = PermitConsumptionRecord {
            plan_fingerprint: self.plan_fingerprint,
            nonce: self.command.nonce,
            principal_id: self.command.principal.principal_id.clone(),
            origin_instance_id: self.command.origin.instance_id.clone(),
            turn_request_id: self.command.turn_request_id.clone(),
            consumed_at_unix: now_unix,
        };
        consumption_store
            .consume_once(&consumption)
            .map_err(|error| match error {
                PermitConsumptionError::Replay => SecretTransferError::Replay,
                PermitConsumptionError::Unavailable => {
                    SecretTransferError::ConsumptionStoreUnavailable
                }
            })?;
        self.permit = None;
        self.state = TransferState::Executing;
        Ok(())
    }

    /// Accept a receipt only after exact binding and transport verification.
    pub fn record_delivered(
        &mut self,
        receipt: DeliveryReceipt,
        verifier: &impl DeliveryReceiptVerifier,
    ) -> Result<(), SecretTransferError> {
        self.require_phase(TransferPhase::Executing, "record_delivered")?;
        if receipt.plan_fingerprint != self.plan_fingerprint
            || receipt.source_sha256 != self.command.source.content_sha256
            || receipt.destination_digest != self.command.destination.digest()
            || receipt.byte_len != self.command.source.byte_len
            || receipt.operation != self.command.operation
        {
            return Err(SecretTransferError::ReceiptBindingMismatch);
        }
        if !verifier.verify_delivery(&receipt) {
            return Err(SecretTransferError::ReceiptUnverified);
        }
        self.verified_receipt = Some(receipt);
        self.state = TransferState::Delivered;
        Ok(())
    }

    /// Mark source deletion after verified delivery of a move.
    pub fn mark_source_deleted(&mut self) -> Result<(), SecretTransferError> {
        if self.command.operation == TransferOperation::Copy {
            return Err(SecretTransferError::SourceDeletionForbiddenForCopy);
        }
        if self.phase() != TransferPhase::Delivered || self.verified_receipt.is_none() {
            return Err(SecretTransferError::MoveDeletionRequiresVerifiedReceipt);
        }
        self.state = TransferState::SourceDeleted;
        Ok(())
    }

    /// Finish a planned or executing transfer with a fixed failure category.
    pub fn fail(&mut self, reason: TransferFailureReason) -> Result<(), SecretTransferError> {
        match self.phase() {
            TransferPhase::Planned | TransferPhase::Executing => {
                self.state = TransferState::Failed(reason);
                Ok(())
            }
            from => Err(SecretTransferError::IllegalTransition {
                from,
                attempted: "fail",
            }),
        }
    }

    /// Finish an executing or delivered transfer with an unknown outcome.
    pub fn mark_indeterminate(
        &mut self,
        reason: IndeterminateReason,
    ) -> Result<(), SecretTransferError> {
        match self.phase() {
            TransferPhase::Executing | TransferPhase::Delivered => {
                self.state = TransferState::Indeterminate(reason);
                Ok(())
            }
            from => Err(SecretTransferError::IllegalTransition {
                from,
                attempted: "mark_indeterminate",
            }),
        }
    }

    /// Verified receipt, if the destination has acknowledged the transfer.
    pub fn verified_receipt(&self) -> Option<&DeliveryReceipt> {
        self.verified_receipt.as_ref()
    }

    /// Build a metadata-only audit record.
    pub fn audit_record(&self) -> TransferAuditRecord {
        TransferAuditRecord {
            plan_fingerprint: self.plan_fingerprint,
            principal_id: self.command.principal.principal_id.clone(),
            operator_session_id: self.command.principal.operator_session_id.clone(),
            origin_surface: self.command.origin.surface.clone(),
            origin_instance_id: self.command.origin.instance_id.clone(),
            turn_request_id: self.command.turn_request_id.clone(),
            source_sha256: self.command.source.content_sha256,
            destination_digest: self.command.destination.digest(),
            byte_len: self.command.source.byte_len,
            operation: self.command.operation,
            phase: self.phase(),
            failure_reason: match &self.state {
                TransferState::Failed(reason) => Some(*reason),
                _ => None,
            },
            indeterminate_reason: match &self.state {
                TransferState::Indeterminate(reason) => Some(*reason),
                _ => None,
            },
            delivered_at_unix: self
                .verified_receipt
                .as_ref()
                .map(DeliveryReceipt::delivered_at_unix),
        }
    }

    fn require_phase(
        &self,
        expected: TransferPhase,
        attempted: &'static str,
    ) -> Result<(), SecretTransferError> {
        let from = self.phase();
        if from != expected {
            return Err(SecretTransferError::IllegalTransition { from, attempted });
        }
        Ok(())
    }
}

impl fmt::Debug for TransferExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferExecution")
            .field("command", &self.command)
            .field("permit", &self.permit)
            .field("plan_fingerprint", &hex::encode(self.plan_fingerprint))
            .field("state", &self.state)
            .field("verified_receipt", &self.verified_receipt)
            .finish()
    }
}

/// Metadata-only transfer audit payload. It cannot contain the transferred
/// bytes or arbitrary transport response text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferAuditRecord {
    pub plan_fingerprint: [u8; 32],
    pub principal_id: String,
    pub operator_session_id: String,
    pub origin_surface: String,
    pub origin_instance_id: String,
    pub turn_request_id: String,
    pub source_sha256: [u8; 32],
    pub destination_digest: [u8; 32],
    pub byte_len: u64,
    pub operation: TransferOperation,
    pub phase: TransferPhase,
    pub failure_reason: Option<TransferFailureReason>,
    pub indeterminate_reason: Option<IndeterminateReason>,
    pub delivered_at_unix: Option<i64>,
}

fn validate_component(field: &'static str, value: &str) -> Result<(), SecretTransferError> {
    if value.is_empty() {
        return Err(SecretTransferError::EmptyBinding { field });
    }
    if value.len() > MAX_BINDING_COMPONENT_BYTES {
        return Err(SecretTransferError::BindingTooLong { field });
    }
    if value.chars().any(char::is_control) {
        return Err(SecretTransferError::InvalidBinding { field });
    }
    Ok(())
}

fn encode_destination(destination: &DestinationBinding) -> Vec<u8> {
    let mut encoded = Vec::new();
    push_bytes(&mut encoded, destination.transport.as_bytes());
    push_bytes(&mut encoded, destination.account_id.as_bytes());
    push_bytes(&mut encoded, destination.destination_id.as_bytes());
    encoded
}

fn encode_command(command: &OperatorCommand) -> Vec<u8> {
    let mut encoded = Vec::new();
    push_bytes(&mut encoded, COMMAND_DOMAIN);
    push_bytes(&mut encoded, command.principal.principal_id.as_bytes());
    push_bytes(
        &mut encoded,
        command.principal.operator_session_id.as_bytes(),
    );
    push_bytes(&mut encoded, command.origin.surface.as_bytes());
    push_bytes(&mut encoded, command.origin.instance_id.as_bytes());
    push_bytes(&mut encoded, command.origin.conversation_id.as_bytes());
    push_bytes(&mut encoded, command.turn_request_id.as_bytes());
    push_bytes(&mut encoded, command.source.source_id.as_bytes());
    encoded.extend_from_slice(&command.source.content_sha256);
    encoded.extend_from_slice(&command.source.byte_len.to_be_bytes());
    encoded.extend_from_slice(&encode_destination(&command.destination));
    encoded.push(command.operation.wire_tag());
    encoded.extend_from_slice(&command.issued_at_unix.to_be_bytes());
    encoded.extend_from_slice(&command.expires_at_unix.to_be_bytes());
    encoded.extend_from_slice(command.nonce.as_bytes());
    encoded
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let len = u64::try_from(value.len()).expect("binding component length fits u64");
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn authority() -> TransferAuthority {
        TransferAuthority::from_injected_key([0x42; 32]).unwrap()
    }

    /// Mint a nonce from the operating system for each independent test command.
    ///
    /// A literal nonce makes the test fixture look like a production reuse to
    /// static analysis, and can accidentally hide uniqueness regressions. Tests
    /// that exercise replay protection explicitly retain and reuse the one
    /// generated value they intend to replay.
    fn fresh_nonce() -> TransferNonce {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .expect("OS entropy source unavailable while minting test transfer nonce");
        TransferNonce::new(bytes)
    }

    fn command(operation: TransferOperation, destination_id: &str) -> OperatorCommand {
        command_with_nonce(operation, destination_id, fresh_nonce())
    }

    fn command_with_nonce(
        operation: TransferOperation,
        destination_id: &str,
        nonce: TransferNonce,
    ) -> OperatorCommand {
        OperatorCommand::new(
            OperatorPrincipal::new_metadata("admin:alex", "os-session:7").unwrap(),
            CommandOrigin::new("cli", "instance:desktop", "conversation:42").unwrap(),
            "request:42",
            SourceBinding::new("vault:item:mail", Sha256::digest(b"secret").into(), 6).unwrap(),
            DestinationBinding::new("telegram", "account:personal", destination_id).unwrap(),
            operation,
            NOW,
            NOW + 60,
            nonce,
        )
        .unwrap()
    }

    fn executing(operation: TransferOperation) -> TransferExecution {
        let authority = authority();
        let mut ledger = PermitUseLedger::new();
        let mut execution = authority
            .authorize(command(operation, "chat:123"))
            .unwrap()
            .into_execution();
        execution.begin(&authority, &mut ledger, NOW).unwrap();
        execution
    }

    #[test]
    fn payload_debug_is_redacted_and_access_is_consuming() {
        let payload = SecretPayload::from("top-secret-password".to_owned());
        let debug = format!("{payload:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("top-secret-password"));
        let observed = payload.expose_once(|bytes| bytes == b"top-secret-password");
        assert!(observed);
    }

    #[test]
    fn permit_rejects_any_destination_binding_mutation() {
        let authority = authority();
        let nonce = fresh_nonce();
        let original = command_with_nonce(TransferOperation::Copy, "chat:123", nonce);
        let plan = authority.authorize(original).unwrap();
        let mutated = command_with_nonce(TransferOperation::Copy, "chat:999", nonce);
        assert_eq!(
            authority
                .verify_permit(&plan.permit, &mutated, NOW)
                .unwrap_err(),
            SecretTransferError::BindingMismatch
        );
    }

    #[test]
    fn permit_binds_the_exact_turn_request_id() {
        let authority = authority();
        let original = command(TransferOperation::Copy, "chat:123");
        let plan = authority.authorize(original.clone()).unwrap();
        let mut mutated = original;
        mutated.turn_request_id = "request:other-turn".to_owned();
        assert_eq!(
            authority
                .verify_permit(&plan.permit, &mutated, NOW)
                .unwrap_err(),
            SecretTransferError::BindingMismatch
        );
    }

    #[test]
    fn permit_expiry_is_exclusive_and_fail_closed() {
        let authority = authority();
        let command = command(TransferOperation::Copy, "chat:123");
        let plan = authority.authorize(command.clone()).unwrap();
        assert_eq!(
            authority
                .verify_permit(&plan.permit, &command, command.expires_at_unix())
                .unwrap_err(),
            SecretTransferError::Expired
        );
    }

    #[test]
    fn consumed_nonce_rejects_reissued_permit_replay() {
        let authority = authority();
        let command = command(TransferOperation::Copy, "chat:123");
        let plan_one = authority.authorize(command.clone()).unwrap();
        let plan_two = authority.authorize(command).unwrap();
        let mut ledger = PermitUseLedger::new();

        let mut first = plan_one.into_execution();
        first.begin(&authority, &mut ledger, NOW).unwrap();
        let mut replay = plan_two.into_execution();
        assert_eq!(
            replay.begin(&authority, &mut ledger, NOW).unwrap_err(),
            SecretTransferError::Replay
        );
        assert_eq!(replay.phase(), TransferPhase::Planned);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn unavailable_durable_consumption_keeps_transfer_planned() {
        struct Unavailable;
        impl PermitConsumptionStore for Unavailable {
            fn consume_once(
                &mut self,
                _record: &PermitConsumptionRecord,
            ) -> Result<(), PermitConsumptionError> {
                Err(PermitConsumptionError::Unavailable)
            }
        }

        let authority = authority();
        let mut execution = authority
            .authorize(command(TransferOperation::Copy, "chat:123"))
            .unwrap()
            .into_execution();
        assert_eq!(
            execution
                .begin(&authority, &mut Unavailable, NOW)
                .unwrap_err(),
            SecretTransferError::ConsumptionStoreUnavailable
        );
        assert_eq!(execution.phase(), TransferPhase::Planned);
    }

    #[test]
    fn illegal_state_transitions_are_rejected() {
        let authority = authority();
        let mut execution = authority
            .authorize(command(TransferOperation::Copy, "chat:123"))
            .unwrap()
            .into_execution();
        assert_eq!(
            execution
                .mark_indeterminate(IndeterminateReason::ProcessInterrupted)
                .unwrap_err(),
            SecretTransferError::IllegalTransition {
                from: TransferPhase::Planned,
                attempted: "mark_indeterminate",
            }
        );
        execution
            .fail(TransferFailureReason::SourceChanged)
            .unwrap();
        assert_eq!(execution.phase(), TransferPhase::Failed);
        assert!(matches!(
            execution.fail(TransferFailureReason::Transport),
            Err(SecretTransferError::IllegalTransition { .. })
        ));
    }

    #[test]
    fn move_cannot_delete_until_receipt_is_verified() {
        let mut execution = executing(TransferOperation::Move);
        assert_eq!(
            execution.mark_source_deleted().unwrap_err(),
            SecretTransferError::MoveDeletionRequiresVerifiedReceipt
        );

        let receipt = DeliveryReceipt::for_execution(
            &execution,
            NOW + 1,
            Sha256::digest(b"remote-ack").into(),
        )
        .unwrap();
        assert_eq!(
            execution
                .record_delivered(receipt.clone(), &|_: &DeliveryReceipt| false)
                .unwrap_err(),
            SecretTransferError::ReceiptUnverified
        );
        assert_eq!(
            execution.mark_source_deleted().unwrap_err(),
            SecretTransferError::MoveDeletionRequiresVerifiedReceipt
        );

        execution
            .record_delivered(receipt, &|_: &DeliveryReceipt| true)
            .unwrap();
        assert_eq!(execution.phase(), TransferPhase::Delivered);
        execution.mark_source_deleted().unwrap();
        assert_eq!(execution.phase(), TransferPhase::SourceDeleted);
    }

    #[test]
    fn receipt_and_audit_never_contain_payload_bytes() {
        let payload = SecretPayload::from("credential-value-never-log".to_owned());
        let digest = payload.digest();
        let authority = authority();
        let command = OperatorCommand::new(
            OperatorPrincipal::new_metadata("admin:alex", "os-session:7").unwrap(),
            CommandOrigin::new("gui", "instance:desktop", "conversation:99").unwrap(),
            "request:99",
            SourceBinding::new("vault:item:1", digest, payload.len() as u64).unwrap(),
            DestinationBinding::new("local-file", "profile:alex", "backup:item:1").unwrap(),
            TransferOperation::Copy,
            NOW,
            NOW + 60,
            fresh_nonce(),
        )
        .unwrap();
        let mut ledger = PermitUseLedger::new();
        let mut execution = authority.authorize(command).unwrap().into_execution();
        execution.begin(&authority, &mut ledger, NOW).unwrap();
        let receipt =
            DeliveryReceipt::for_execution(&execution, NOW + 1, Sha256::digest(b"ack").into())
                .unwrap();
        execution
            .record_delivered(receipt.clone(), &|_: &DeliveryReceipt| true)
            .unwrap();

        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let audit_json = serde_json::to_string(&execution.audit_record()).unwrap();
        assert!(!receipt_json.contains("credential-value-never-log"));
        assert!(!audit_json.contains("credential-value-never-log"));
        assert!(!format!("{execution:?}").contains("credential-value-never-log"));
        payload.expose_once(|bytes| assert_eq!(bytes, b"credential-value-never-log"));
    }

    #[test]
    fn copy_can_never_enter_source_deleted() {
        let mut execution = executing(TransferOperation::Copy);
        let receipt =
            DeliveryReceipt::for_execution(&execution, NOW + 1, Sha256::digest(b"ack").into())
                .unwrap();
        execution
            .record_delivered(receipt, &|_: &DeliveryReceipt| true)
            .unwrap();
        assert_eq!(
            execution.mark_source_deleted().unwrap_err(),
            SecretTransferError::SourceDeletionForbiddenForCopy
        );
        assert_eq!(execution.phase(), TransferPhase::Delivered);
    }
}
