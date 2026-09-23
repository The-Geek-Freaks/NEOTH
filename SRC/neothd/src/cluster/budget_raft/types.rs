//! Replicated command and receipt types for the fixed-voter budget authority.
//!
//! These types are durable Raft state. They intentionally contain receipts, not
//! an executable provider capability: the integration layer may turn only the
//! first `NewClaimed` reply from the current committed invocation into its
//! private move-only dispatch permit.

use crate::cluster::membership::{StableNodeId, TransportIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);
    };
}

opaque_id!(BudgetGrantId);
opaque_id!(ScopeHash);
opaque_id!(GrantFence);
opaque_id!(DispatchFence);
opaque_id!(DispatchAttemptId);
opaque_id!(TerminalFence);

/// A committed position, retained forever with its command instead of being
/// replaced by the position of a later idempotent replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommittedLogPosition {
    pub term: u64,
    pub index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BudgetClusterConfig {
    pub cluster_id: String,
    pub membership_epoch: u64,
    pub voters: BTreeMap<StableNodeId, TransportIdentity>,
    pub cap_usd_nanos: u64,
    pub utc_window: i64,
    /// SHA-256 of the canonical immutable configuration, excluding this field.
    pub scope_hash: ScopeHash,
}

impl BudgetClusterConfig {
    pub fn new(
        cluster_id: String,
        membership_epoch: u64,
        voters: BTreeMap<StableNodeId, TransportIdentity>,
        cap_usd_nanos: u64,
        utc_window: i64,
    ) -> Result<Self, BudgetRejection> {
        let mut config = Self {
            cluster_id,
            membership_epoch,
            voters,
            cap_usd_nanos,
            utc_window,
            scope_hash: ScopeHash(String::new()),
        };
        config.validate_shape()?;
        config.scope_hash = config.expected_scope_hash();
        Ok(config)
    }

    pub fn expected_scope_hash(&self) -> ScopeHash {
        let mut hasher = Sha256::new();
        hasher.update(b"neoth.budget.scope.v1\0");
        update_part(&mut hasher, self.cluster_id.as_bytes());
        update_part(&mut hasher, &self.membership_epoch.to_le_bytes());
        update_part(&mut hasher, &self.cap_usd_nanos.to_le_bytes());
        update_part(&mut hasher, &self.utc_window.to_le_bytes());
        for (node, transport) in &self.voters {
            update_part(&mut hasher, node.as_str().as_bytes());
            update_part(&mut hasher, transport.as_str().as_bytes());
        }
        ScopeHash(hex::encode(hasher.finalize()))
    }

    pub fn validate(&self) -> Result<(), BudgetRejection> {
        self.validate_shape()?;
        if !is_sha256_hex(&self.scope_hash.0) || self.scope_hash != self.expected_scope_hash() {
            return Err(BudgetRejection::InvalidConfig);
        }
        Ok(())
    }

    /// The fixed Raft ids are the one-based rank of the canonical
    /// `StableNodeId` ordering. This has no hash-collision path and changes
    /// whenever the frozen membership binding changes (which also changes the
    /// scope hash and makes recovery unavailable).
    pub fn raft_node_id(&self, stable_node_id: &StableNodeId) -> Option<u64> {
        self.voters
            .keys()
            .position(|candidate| candidate == stable_node_id)
            .map(|index| index as u64 + 1)
    }

    /// The exact OpenRaft bootstrap map for the immutable three-voter set.
    pub fn raft_voters(&self) -> BTreeMap<u64, openraft::BasicNode> {
        self.voters
            .keys()
            .enumerate()
            .map(|(index, stable_node_id)| {
                (
                    index as u64 + 1,
                    openraft::BasicNode::new(format!("frozen:{stable_node_id}")),
                )
            })
            .collect()
    }

    fn validate_shape(&self) -> Result<(), BudgetRejection> {
        if !is_identifier(&self.cluster_id) || self.membership_epoch == 0 || self.cap_usd_nanos == 0
        {
            return Err(BudgetRejection::InvalidConfig);
        }
        if self.voters.len() != 3 {
            return Err(BudgetRejection::InvalidConfig);
        }
        let mut transports = BTreeSet::new();
        for (node, transport) in &self.voters {
            if !is_sha256_hex(node.as_str())
                || !is_identifier(transport.as_str())
                || !transports.insert(transport.as_str())
            {
                return Err(BudgetRejection::InvalidConfig);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReserveBudget {
    pub grant_id: BudgetGrantId,
    pub provider_intent_id: String,
    pub request_fingerprint: String,
    pub scope_hash: ScopeHash,
    pub reserved_usd_nanos: u64,
    pub utc_window: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeginDispatch {
    pub grant_id: BudgetGrantId,
    pub reserve_fence: GrantFence,
    pub owner: StableNodeId,
    pub attempt_id: DispatchAttemptId,
    pub provider_intent_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SettleBudget {
    pub grant_id: BudgetGrantId,
    pub dispatch_fence: DispatchFence,
    pub owner: StableNodeId,
    pub attempt_id: DispatchAttemptId,
    /// `None` means the outcome is unknown and the whole original bound stays held.
    pub actual_usd_nanos: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BudgetCommand {
    Reserve(ReserveBudget),
    BeginDispatch(BeginDispatch),
    Settle(SettleBudget),
    ReleaseBeforeClaim {
        grant_id: BudgetGrantId,
        reserve_fence: GrantFence,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReservedGrant {
    pub grant_id: BudgetGrantId,
    pub reserve_fence: GrantFence,
    pub committed_at: CommittedLogPosition,
    pub scope_hash: ScopeHash,
    pub provider_intent_id: String,
    pub request_fingerprint: String,
    pub reserved_usd_nanos: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimReceipt {
    pub grant_id: BudgetGrantId,
    pub dispatch_fence: DispatchFence,
    pub committed_at: CommittedLogPosition,
    pub owner: StableNodeId,
    pub attempt_id: DispatchAttemptId,
    pub provider_intent_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GrantReceipt {
    pub grant_id: BudgetGrantId,
    /// Original committed terminal command position; retries never replace it.
    pub committed_at: CommittedLogPosition,
    /// Binds the terminal command identity and its committed position.
    pub terminal_fence: TerminalFence,
    pub terminal: GrantTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GrantTerminal {
    Settled {
        /// The amount charged to the budget. It equals the bound for unknown cost.
        charged_usd_nanos: u64,
        actual_cost_was_unknown: bool,
    },
    ReleasedBeforeClaim,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BudgetReply {
    Reserved(ReservedGrant),
    AlreadyReserved(ReservedGrant),
    /// A durable claim receipt. The caller that observes this reply may mint the
    /// private move-only permit; this serializable receipt is not a permit.
    NewClaimed(ClaimReceipt),
    AlreadyClaimed(ClaimReceipt),
    ReconcileOnly(ClaimReceipt),
    Settled(GrantReceipt),
    Released(GrantReceipt),
    Rejected(BudgetRejection),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BudgetRejection {
    InvalidConfig,
    InvalidCommand,
    GrantConflict,
    CapExceeded,
    UnknownGrant,
    FenceMismatch,
    OwnerMismatch,
    UnauthorizedOwner,
    AttemptMismatch,
    IntentMismatch,
    NotClaimed,
    ReleaseAfterClaim,
    AlreadyReleased,
    Overrun,
    ScopeMismatch,
    WindowMismatch,
}

pub(crate) fn fence_hash(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        update_part(&mut hasher, part);
    }
    hex::encode(hasher.finalize())
}

pub(crate) fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value == value.to_ascii_lowercase()
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn is_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 || bytes[14] != b'7' || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_digit() && !matches!(*byte, b'a'..=b'f') {
            return false;
        }
    }
    true
}

fn update_part(hasher: &mut Sha256, part: &[u8]) {
    hasher.update((part.len() as u64).to_le_bytes());
    hasher.update(part);
}
