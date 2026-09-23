//! Deterministic replicated budget ledger.
//!
//! This module neither elects a leader nor authorizes a provider request by
//! itself. OpenRaft applies each command exactly once at its committed log
//! position; the provider boundary may use only the first `NewClaimed` result.

use super::types::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GrantState {
    Reserved,
    Claimed(ClaimReceipt),
    Settled {
        claim: ClaimReceipt,
        settlement: SettleBudget,
        receipt: GrantReceipt,
    },
    /// Durable reconciliation state. It never expands the cap or frees the bound.
    Overrun {
        claim: ClaimReceipt,
        reported_at: CommittedLogPosition,
        terminal_fence: TerminalFence,
        settlement: SettleBudget,
    },
    Released(GrantReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GrantRecord {
    pub reserve: ReserveBudget,
    pub reserve_fence: GrantFence,
    pub reserved_at: CommittedLogPosition,
    pub state: GrantState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BudgetLedger {
    config: BudgetClusterConfig,
    pub grants: BTreeMap<BudgetGrantId, GrantRecord>,
}

impl BudgetLedger {
    pub fn new(config: BudgetClusterConfig) -> Result<Self, BudgetRejection> {
        config.validate()?;
        Ok(Self { config, grants: BTreeMap::new() })
    }

    pub fn config(&self) -> &BudgetClusterConfig {
        &self.config
    }

    /// Validate recovered durable state before it can vote, lead, or admit work.
    /// The hard ceiling totals every original bound, including released and settled
    /// grants, so a saving or cancellation cannot become hidden extra headroom.
    pub fn validate(&self) -> Result<(), BudgetRejection> {
        self.config.validate()?;
        let mut total = 0_u64;
        for (id, record) in &self.grants {
            if id != &record.reserve.grant_id || !valid_reserve(&self.config, &record.reserve) {
                return Err(BudgetRejection::InvalidConfig);
            }
            if record.reserve_fence != expected_reserve_fence(&self.config, &record.reserve, record.reserved_at) {
                return Err(BudgetRejection::InvalidConfig);
            }
            total = total.checked_add(record.reserve.reserved_usd_nanos).ok_or(BudgetRejection::CapExceeded)?;
            validate_state(&self.config, record)?;
        }
        if total > self.config.cap_usd_nanos {
            return Err(BudgetRejection::CapExceeded);
        }
        Ok(())
    }

    pub fn apply(&mut self, log_term: u64, log_index: u64, command: BudgetCommand) -> BudgetReply {
        if self.validate().is_err() {
            return BudgetReply::Rejected(BudgetRejection::InvalidConfig);
        }
        let position = CommittedLogPosition { term: log_term, index: log_index };
        match command {
            BudgetCommand::Reserve(command) => self.reserve(position, command),
            BudgetCommand::BeginDispatch(command) => self.begin_dispatch(position, command),
            BudgetCommand::Settle(command) => self.settle(position, command),
            BudgetCommand::ReleaseBeforeClaim { grant_id, reserve_fence } => {
                self.release_before_claim(position, grant_id, reserve_fence)
            }
        }
    }

    fn reserve(&mut self, position: CommittedLogPosition, command: ReserveBudget) -> BudgetReply {
        if command.scope_hash != self.config.scope_hash {
            return BudgetReply::Rejected(BudgetRejection::ScopeMismatch);
        }
        if command.utc_window != self.config.utc_window {
            return BudgetReply::Rejected(BudgetRejection::WindowMismatch);
        }
        if !valid_reserve(&self.config, &command) {
            return BudgetReply::Rejected(BudgetRejection::InvalidCommand);
        }
        if let Some(existing) = self.grants.get(&command.grant_id) {
            return if existing.reserve == command {
                BudgetReply::AlreadyReserved(reserved_grant(existing))
            } else {
                BudgetReply::Rejected(BudgetRejection::GrantConflict)
            };
        }
        let Some(total) = self.reserved_total().and_then(|used| used.checked_add(command.reserved_usd_nanos)) else {
            return BudgetReply::Rejected(BudgetRejection::CapExceeded);
        };
        if total > self.config.cap_usd_nanos {
            return BudgetReply::Rejected(BudgetRejection::CapExceeded);
        }
        let reserve_fence = expected_reserve_fence(&self.config, &command, position);
        let reply = ReservedGrant {
            grant_id: command.grant_id.clone(),
            reserve_fence: reserve_fence.clone(),
            committed_at: position,
            scope_hash: command.scope_hash.clone(),
            provider_intent_id: command.provider_intent_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            reserved_usd_nanos: command.reserved_usd_nanos,
        };
        self.grants.insert(command.grant_id.clone(), GrantRecord {
            reserve: command,
            reserve_fence,
            reserved_at: position,
            state: GrantState::Reserved,
        });
        BudgetReply::Reserved(reply)
    }

    fn begin_dispatch(&mut self, position: CommittedLogPosition, command: BeginDispatch) -> BudgetReply {
        let config = self.config.clone();
        if !config.voters.contains_key(&command.owner) {
            return BudgetReply::Rejected(BudgetRejection::UnauthorizedOwner);
        }
        if !is_identifier(&command.attempt_id.0) {
            return BudgetReply::Rejected(BudgetRejection::InvalidCommand);
        }
        let Some(record) = self.grants.get_mut(&command.grant_id) else {
            return BudgetReply::Rejected(BudgetRejection::UnknownGrant);
        };
        if record.reserve_fence != command.reserve_fence {
            return BudgetReply::Rejected(BudgetRejection::FenceMismatch);
        }
        if record.reserve.provider_intent_id != command.provider_intent_id {
            return BudgetReply::Rejected(BudgetRejection::IntentMismatch);
        }
        match &record.state {
            GrantState::Reserved => {
                let receipt = ClaimReceipt {
                    grant_id: command.grant_id.clone(),
                    dispatch_fence: expected_dispatch_fence(&config, record, position, &command),
                    committed_at: position,
                    owner: command.owner,
                    attempt_id: command.attempt_id,
                    provider_intent_id: command.provider_intent_id,
                };
                record.state = GrantState::Claimed(receipt.clone());
                BudgetReply::NewClaimed(receipt)
            }
            GrantState::Claimed(receipt) => replay_claim_reply(receipt, &command, false),
            GrantState::Settled { claim: receipt, .. } | GrantState::Overrun { claim: receipt, .. } => {
                replay_claim_reply(receipt, &command, true)
            }
            GrantState::Released(_) => BudgetReply::Rejected(BudgetRejection::AlreadyReleased),
        }
    }

    fn settle(&mut self, position: CommittedLogPosition, command: SettleBudget) -> BudgetReply {
        let Some(record) = self.grants.get_mut(&command.grant_id) else {
            return BudgetReply::Rejected(BudgetRejection::UnknownGrant);
        };
        let claim = match &record.state {
            GrantState::Claimed(claim)
            | GrantState::Settled { claim, .. }
            | GrantState::Overrun { claim, .. } => claim.clone(),
            GrantState::Reserved => return BudgetReply::Rejected(BudgetRejection::NotClaimed),
            GrantState::Released(_) => return BudgetReply::Rejected(BudgetRejection::AlreadyReleased),
        };
        if claim.dispatch_fence != command.dispatch_fence {
            return BudgetReply::Rejected(BudgetRejection::FenceMismatch);
        }
        if claim.owner != command.owner {
            return BudgetReply::Rejected(BudgetRejection::OwnerMismatch);
        }
        if claim.attempt_id != command.attempt_id {
            return BudgetReply::Rejected(BudgetRejection::AttemptMismatch);
        }
        match &record.state {
            GrantState::Settled { settlement, receipt, .. } => return if settlement == &command {
                BudgetReply::Settled(receipt.clone())
            } else {
                BudgetReply::Rejected(BudgetRejection::GrantConflict)
            },
            GrantState::Overrun { settlement, .. } => return if settlement == &command {
                BudgetReply::Rejected(BudgetRejection::Overrun)
            } else {
                BudgetReply::Rejected(BudgetRejection::GrantConflict)
            },
            GrantState::Claimed(_) => {}
            GrantState::Reserved | GrantState::Released(_) => unreachable!("covered above"),
        }
        if command.actual_usd_nanos.is_some_and(|actual| actual > record.reserve.reserved_usd_nanos) {
            let terminal_fence = expected_settlement_fence(&self.config, record, &claim, position, &command);
            record.state = GrantState::Overrun { claim, reported_at: position, terminal_fence, settlement: command };
            return BudgetReply::Rejected(BudgetRejection::Overrun);
        }
        let receipt = GrantReceipt {
            grant_id: command.grant_id.clone(),
            committed_at: position,
            terminal_fence: expected_settlement_fence(&self.config, record, &claim, position, &command),
            terminal: GrantTerminal::Settled {
                charged_usd_nanos: command.actual_usd_nanos.unwrap_or(record.reserve.reserved_usd_nanos),
                actual_cost_was_unknown: command.actual_usd_nanos.is_none(),
            },
        };
        record.state = GrantState::Settled { claim, settlement: command, receipt: receipt.clone() };
        BudgetReply::Settled(receipt)
    }

    fn release_before_claim(&mut self, position: CommittedLogPosition, grant_id: BudgetGrantId, reserve_fence: GrantFence) -> BudgetReply {
        let Some(record) = self.grants.get_mut(&grant_id) else {
            return BudgetReply::Rejected(BudgetRejection::UnknownGrant);
        };
        if record.reserve_fence != reserve_fence {
            return BudgetReply::Rejected(BudgetRejection::FenceMismatch);
        }
        match &record.state {
            GrantState::Reserved => {
                let receipt = GrantReceipt {
                    grant_id,
                    committed_at: position,
                    terminal_fence: expected_release_fence(&self.config, record, position),
                    terminal: GrantTerminal::ReleasedBeforeClaim,
                };
                record.state = GrantState::Released(receipt.clone());
                BudgetReply::Released(receipt)
            }
            GrantState::Released(receipt) => BudgetReply::Released(receipt.clone()),
            GrantState::Claimed(_) | GrantState::Settled { .. } | GrantState::Overrun { .. } => {
                BudgetReply::Rejected(BudgetRejection::ReleaseAfterClaim)
            }
        }
    }

    fn reserved_total(&self) -> Option<u64> {
        self.grants.values().try_fold(0_u64, |sum, record| sum.checked_add(record.reserve.reserved_usd_nanos))
    }
}

fn reserved_grant(record: &GrantRecord) -> ReservedGrant {
    ReservedGrant {
        grant_id: record.reserve.grant_id.clone(),
        reserve_fence: record.reserve_fence.clone(),
        committed_at: record.reserved_at,
        scope_hash: record.reserve.scope_hash.clone(),
        provider_intent_id: record.reserve.provider_intent_id.clone(),
        request_fingerprint: record.reserve.request_fingerprint.clone(),
        reserved_usd_nanos: record.reserve.reserved_usd_nanos,
    }
}

fn replay_claim_reply(receipt: &ClaimReceipt, command: &BeginDispatch, reconcile_only: bool) -> BudgetReply {
    if receipt.owner == command.owner
        && receipt.attempt_id == command.attempt_id
        && receipt.provider_intent_id == command.provider_intent_id
    {
        if reconcile_only { BudgetReply::ReconcileOnly(receipt.clone()) } else { BudgetReply::AlreadyClaimed(receipt.clone()) }
    } else {
        BudgetReply::Rejected(BudgetRejection::GrantConflict)
    }
}

fn valid_reserve(config: &BudgetClusterConfig, reserve: &ReserveBudget) -> bool {
    reserve.scope_hash == config.scope_hash
        && reserve.utc_window == config.utc_window
        && reserve.reserved_usd_nanos > 0
        && is_uuid_v7(&reserve.grant_id.0)
        && is_identifier(&reserve.provider_intent_id)
        && is_sha256_hex(&reserve.request_fingerprint)
}

fn expected_reserve_fence(config: &BudgetClusterConfig, reserve: &ReserveBudget, position: CommittedLogPosition) -> GrantFence {
    GrantFence(fence_hash(b"neoth.budget.reserve-fence.v2\0", &[
        config.cluster_id.as_bytes(), config.scope_hash.0.as_bytes(), &config.membership_epoch.to_le_bytes(),
        &position.term.to_le_bytes(), &position.index.to_le_bytes(), reserve.grant_id.0.as_bytes(),
        reserve.provider_intent_id.as_bytes(), reserve.request_fingerprint.as_bytes(),
        &reserve.reserved_usd_nanos.to_le_bytes(), &reserve.utc_window.to_le_bytes(),
    ]))
}

fn expected_dispatch_fence(config: &BudgetClusterConfig, record: &GrantRecord, position: CommittedLogPosition, command: &BeginDispatch) -> DispatchFence {
    DispatchFence(fence_hash(b"neoth.budget.dispatch-fence.v2\0", &[
        config.cluster_id.as_bytes(), config.scope_hash.0.as_bytes(), &config.membership_epoch.to_le_bytes(),
        &record.reserved_at.term.to_le_bytes(), &record.reserved_at.index.to_le_bytes(), record.reserve_fence.0.as_bytes(),
        &position.term.to_le_bytes(), &position.index.to_le_bytes(), command.grant_id.0.as_bytes(),
        command.owner.as_str().as_bytes(), command.attempt_id.0.as_bytes(), command.provider_intent_id.as_bytes(),
    ]))
}

fn expected_settlement_fence(
    config: &BudgetClusterConfig,
    record: &GrantRecord,
    claim: &ClaimReceipt,
    position: CommittedLogPosition,
    settlement: &SettleBudget,
) -> TerminalFence {
    let actual = settlement.actual_usd_nanos.map(|value| value.to_le_bytes());
    let actual_marker = if actual.is_some() { [1_u8] } else { [0_u8] };
    TerminalFence(fence_hash(b"neoth.budget.settlement-fence.v2\0", &[
        config.cluster_id.as_bytes(), config.scope_hash.0.as_bytes(), &config.membership_epoch.to_le_bytes(),
        record.reserve_fence.0.as_bytes(), claim.dispatch_fence.0.as_bytes(), &claim.committed_at.term.to_le_bytes(),
        &claim.committed_at.index.to_le_bytes(), &position.term.to_le_bytes(), &position.index.to_le_bytes(),
        settlement.grant_id.0.as_bytes(), settlement.owner.as_str().as_bytes(), settlement.attempt_id.0.as_bytes(),
        &actual_marker, actual.as_ref().map_or(&[][..], |value| &value[..]),
    ]))
}

fn expected_release_fence(config: &BudgetClusterConfig, record: &GrantRecord, position: CommittedLogPosition) -> TerminalFence {
    TerminalFence(fence_hash(b"neoth.budget.release-fence.v2\0", &[
        config.cluster_id.as_bytes(), config.scope_hash.0.as_bytes(), &config.membership_epoch.to_le_bytes(),
        &record.reserved_at.term.to_le_bytes(), &record.reserved_at.index.to_le_bytes(), record.reserve_fence.0.as_bytes(),
        &position.term.to_le_bytes(), &position.index.to_le_bytes(), record.reserve.grant_id.0.as_bytes(),
    ]))
}

fn validate_state(config: &BudgetClusterConfig, record: &GrantRecord) -> Result<(), BudgetRejection> {
    match &record.state {
        GrantState::Reserved => Ok(()),
        GrantState::Claimed(claim) => validate_claim(config, record, claim),
        GrantState::Settled { claim, settlement, receipt } => {
            validate_claim(config, record, claim)?;
            validate_settlement(config, record, claim, settlement, receipt)
        }
        GrantState::Overrun { claim, reported_at, terminal_fence, settlement } => {
            validate_claim(config, record, claim)?;
            if !matches_settlement(claim, settlement)
                || settlement.actual_usd_nanos.is_none_or(|actual| actual <= record.reserve.reserved_usd_nanos)
                || *terminal_fence != expected_settlement_fence(config, record, claim, *reported_at, settlement)
            { return Err(BudgetRejection::InvalidConfig); }
            Ok(())
        }
        GrantState::Released(receipt) => {
            if receipt.grant_id != record.reserve.grant_id || receipt.terminal != GrantTerminal::ReleasedBeforeClaim
                || receipt.terminal_fence != expected_release_fence(config, record, receipt.committed_at) {
                return Err(BudgetRejection::InvalidConfig);
            }
            Ok(())
        }
    }
}

fn validate_claim(config: &BudgetClusterConfig, record: &GrantRecord, claim: &ClaimReceipt) -> Result<(), BudgetRejection> {
    let command = BeginDispatch {
        grant_id: claim.grant_id.clone(), reserve_fence: record.reserve_fence.clone(), owner: claim.owner.clone(),
        attempt_id: claim.attempt_id.clone(), provider_intent_id: claim.provider_intent_id.clone(),
    };
    if claim.grant_id != record.reserve.grant_id || !config.voters.contains_key(&claim.owner)
        || !is_identifier(&claim.attempt_id.0) || claim.provider_intent_id != record.reserve.provider_intent_id
        || claim.dispatch_fence != expected_dispatch_fence(config, record, claim.committed_at, &command)
    { return Err(BudgetRejection::InvalidConfig); }
    Ok(())
}

fn validate_settlement(config: &BudgetClusterConfig, record: &GrantRecord, claim: &ClaimReceipt, settlement: &SettleBudget, receipt: &GrantReceipt) -> Result<(), BudgetRejection> {
    if !matches_settlement(claim, settlement) || settlement.actual_usd_nanos.is_some_and(|actual| actual > record.reserve.reserved_usd_nanos)
        || receipt.grant_id != record.reserve.grant_id { return Err(BudgetRejection::InvalidConfig); }
    let expected = GrantTerminal::Settled {
        charged_usd_nanos: settlement.actual_usd_nanos.unwrap_or(record.reserve.reserved_usd_nanos),
        actual_cost_was_unknown: settlement.actual_usd_nanos.is_none(),
    };
    if receipt.terminal != expected
        || receipt.terminal_fence != expected_settlement_fence(config, record, claim, receipt.committed_at, settlement)
    { return Err(BudgetRejection::InvalidConfig); }
    Ok(())
}

fn matches_settlement(claim: &ClaimReceipt, settlement: &SettleBudget) -> bool {
    settlement.grant_id == claim.grant_id && settlement.dispatch_fence == claim.dispatch_fence
        && settlement.owner == claim.owner && settlement.attempt_id == claim.attempt_id
}
