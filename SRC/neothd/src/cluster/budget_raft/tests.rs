use super::state_machine::{BudgetLedger, GrantState};
use super::types::*;
use crate::cluster::membership::{StableNodeId, TransportIdentity};
use std::collections::BTreeMap;

fn node(byte: &str) -> StableNodeId {
    StableNodeId::parse(byte.repeat(32)).unwrap()
}

fn voters() -> BTreeMap<StableNodeId, TransportIdentity> {
    ["11", "22", "33"]
        .into_iter()
        .map(|byte| {
            (
                node(byte),
                TransportIdentity::parse(format!("peeroxide-{byte}")).unwrap(),
            )
        })
        .collect()
}

fn ledger(cap: u64) -> BudgetLedger {
    BudgetLedger::new(
        BudgetClusterConfig::new("budget-cluster".into(), 9, voters(), cap, 20_260_923).unwrap(),
    )
    .unwrap()
}

fn reserve(ledger: &BudgetLedger, id: &str, bound: u64) -> ReserveBudget {
    ReserveBudget {
        grant_id: BudgetGrantId(format!("018f0000-0000-7000-8000-{id:0>12}")),
        provider_intent_id: format!("intent-{id}"),
        request_fingerprint: format!("{id:0>64}"),
        scope_hash: ledger.config().scope_hash.clone(),
        reserved_usd_nanos: bound,
        utc_window: ledger.config().utc_window,
    }
}

fn reserve_grant(ledger: &mut BudgetLedger, id: &str, bound: u64) -> ReservedGrant {
    let command = reserve(ledger, id, bound);
    match ledger.apply(4, 11, BudgetCommand::Reserve(command)) {
        BudgetReply::Reserved(grant) => grant,
        reply => panic!("expected reserve, got {reply:?}"),
    }
}

fn claim_command(grant: &ReservedGrant, owner: StableNodeId) -> BeginDispatch {
    BeginDispatch {
        grant_id: grant.grant_id.clone(),
        reserve_fence: grant.reserve_fence.clone(),
        owner,
        attempt_id: DispatchAttemptId(format!("attempt-{}", grant.grant_id.0)),
        provider_intent_id: grant.provider_intent_id.clone(),
    }
}

fn claim_grant(ledger: &mut BudgetLedger, grant: &ReservedGrant) -> ClaimReceipt {
    let claim = claim_command(grant, node("11"));
    match ledger.apply(4, 12, BudgetCommand::BeginDispatch(claim)) {
        BudgetReply::NewClaimed(receipt) => receipt,
        reply => panic!("expected first committed claim, got {reply:?}"),
    }
}

fn settlement(claim: &ClaimReceipt, actual_usd_nanos: Option<u64>) -> SettleBudget {
    SettleBudget {
        grant_id: claim.grant_id.clone(),
        dispatch_fence: claim.dispatch_fence.clone(),
        owner: claim.owner.clone(),
        attempt_id: claim.attempt_id.clone(),
        actual_usd_nanos,
    }
}

#[test]
fn frozen_membership_scope_and_config_tampering_fail_closed() {
    let config = BudgetClusterConfig::new("budget-cluster".into(), 9, voters(), 10, 4).unwrap();
    assert!(config.validate().is_ok());

    let mut forged_scope = config.clone();
    forged_scope.scope_hash = ScopeHash("00".repeat(32));
    assert_eq!(Err(BudgetRejection::InvalidConfig), forged_scope.validate());

    let mut duplicate_transport = config.clone();
    let identity = duplicate_transport.voters.values().next().unwrap().clone();
    duplicate_transport.voters.insert(node("44"), identity);
    duplicate_transport.voters.remove(&node("33"));
    assert_eq!(Err(BudgetRejection::InvalidConfig), duplicate_transport.validate());
}

#[test]
fn reserve_replay_keeps_original_position_and_cap_never_rebates_release() {
    let mut ledger = ledger(10);
    let grant = reserve_grant(&mut ledger, "1", 6);
    assert_eq!(CommittedLogPosition { term: 4, index: 11 }, grant.committed_at);

    let replay_command = reserve(&ledger, "1", 6);
    let replay = ledger.apply(99, 777, BudgetCommand::Reserve(replay_command));
    assert_eq!(BudgetReply::AlreadyReserved(grant.clone()), replay);

    assert!(matches!(
        ledger.apply(4, 13, BudgetCommand::ReleaseBeforeClaim {
            grant_id: grant.grant_id.clone(),
            reserve_fence: grant.reserve_fence.clone(),
        }),
        BudgetReply::Released(_)
    ));
    let new_reservation = reserve(&ledger, "2", 5);
    assert!(matches!(
        ledger.apply(4, 14, BudgetCommand::Reserve(new_reservation)),
        BudgetReply::Rejected(BudgetRejection::CapExceeded)
    ));
    assert!(matches!(
        ledger.apply(4, 15, BudgetCommand::ReleaseBeforeClaim {
            grant_id: grant.grant_id,
            reserve_fence: grant.reserve_fence,
        }),
        BudgetReply::Released(_)
    ));
    assert!(ledger.validate().is_ok());
}

#[test]
fn claim_ack_loss_is_reconcile_only_and_never_changes_first_claim_position() {
    let mut ledger = ledger(20);
    let grant = reserve_grant(&mut ledger, "1", 6);
    let command = claim_command(&grant, node("11"));
    let first = match ledger.apply(7, 12, BudgetCommand::BeginDispatch(command.clone())) {
        BudgetReply::NewClaimed(receipt) => receipt,
        reply => panic!("expected first claim, got {reply:?}"),
    };
    assert_eq!(CommittedLogPosition { term: 7, index: 12 }, first.committed_at);
    assert_eq!(
        BudgetReply::AlreadyClaimed(first.clone()),
        ledger.apply(99, 888, BudgetCommand::BeginDispatch(command))
    );

    let mut competing = claim_command(&grant, node("22"));
    competing.attempt_id = DispatchAttemptId("competing-attempt".into());
    assert_eq!(
        BudgetReply::Rejected(BudgetRejection::GrantConflict),
        ledger.apply(7, 13, BudgetCommand::BeginDispatch(competing))
    );
    assert!(matches!(
        ledger.apply(7, 14, BudgetCommand::ReleaseBeforeClaim {
            grant_id: grant.grant_id,
            reserve_fence: grant.reserve_fence,
        }),
        BudgetReply::Rejected(BudgetRejection::ReleaseAfterClaim)
    ));
}

#[test]
fn unauthorized_owner_and_changed_reserve_replay_are_rejected() {
    let mut ledger = ledger(20);
    let grant = reserve_grant(&mut ledger, "1", 6);
    let outsider = claim_command(&grant, node("44"));
    assert_eq!(
        BudgetReply::Rejected(BudgetRejection::UnauthorizedOwner),
        ledger.apply(1, 12, BudgetCommand::BeginDispatch(outsider))
    );
    let changed_replay = reserve(&ledger, "1", 7);
    assert_eq!(
        BudgetReply::Rejected(BudgetRejection::GrantConflict),
        ledger.apply(1, 13, BudgetCommand::Reserve(changed_replay))
    );
}

#[test]
fn unknown_settlement_holds_full_bound_and_terminal_replay_is_exact() {
    let mut ledger = ledger(10);
    let grant = reserve_grant(&mut ledger, "1", 6);
    let claim = claim_grant(&mut ledger, &grant);
    let unknown = settlement(&claim, None);
    let receipt = match ledger.apply(4, 13, BudgetCommand::Settle(unknown.clone())) {
        BudgetReply::Settled(receipt) => receipt,
        reply => panic!("expected unknown-cost settlement, got {reply:?}"),
    };
    assert_eq!(
        GrantTerminal::Settled { charged_usd_nanos: 6, actual_cost_was_unknown: true },
        receipt.terminal
    );
    assert_eq!(BudgetReply::Settled(receipt.clone()), ledger.apply(8, 99, BudgetCommand::Settle(unknown)));
    assert_eq!(
        BudgetReply::Rejected(BudgetRejection::GrantConflict),
        ledger.apply(4, 14, BudgetCommand::Settle(settlement(&claim, Some(1))))
    );
    let over_cap_reservation = reserve(&ledger, "2", 5);
    assert!(matches!(
        ledger.apply(4, 15, BudgetCommand::Reserve(over_cap_reservation)),
        BudgetReply::Rejected(BudgetRejection::CapExceeded)
    ));
    assert!(ledger.validate().is_ok());
}

#[test]
fn overrun_is_durable_reconciliation_and_changed_retry_is_conflict() {
    let mut ledger = ledger(20);
    let grant = reserve_grant(&mut ledger, "1", 6);
    let claim = claim_grant(&mut ledger, &grant);
    let overrun = settlement(&claim, Some(7));
    assert_eq!(
        BudgetReply::Rejected(BudgetRejection::Overrun),
        ledger.apply(4, 13, BudgetCommand::Settle(overrun.clone()))
    );
    assert!(matches!(
        &ledger.grants[&grant.grant_id].state,
        GrantState::Overrun { .. }
    ));
    assert_eq!(
        BudgetReply::Rejected(BudgetRejection::Overrun),
        ledger.apply(4, 14, BudgetCommand::Settle(overrun))
    );
    assert_eq!(
        BudgetReply::Rejected(BudgetRejection::GrantConflict),
        ledger.apply(4, 15, BudgetCommand::Settle(settlement(&claim, Some(8))))
    );
    assert!(matches!(
        ledger.apply(4, 16, BudgetCommand::ReleaseBeforeClaim {
            grant_id: grant.grant_id,
            reserve_fence: grant.reserve_fence,
        }),
        BudgetReply::Rejected(BudgetRejection::ReleaseAfterClaim)
    ));
    assert!(ledger.validate().is_ok());
}

#[test]
fn corrupted_recovery_state_is_not_admissible() {
    let mut ledger = ledger(20);
    let grant = reserve_grant(&mut ledger, "1", 6);
    ledger.grants.get_mut(&grant.grant_id).unwrap().reserve_fence = GrantFence("00".repeat(32));
    assert_eq!(Err(BudgetRejection::InvalidConfig), ledger.validate());
    assert_eq!(
        BudgetReply::Rejected(BudgetRejection::InvalidConfig),
        ledger.apply(4, 12, BudgetCommand::BeginDispatch(claim_command(&grant, node("11"))))
    );
}

#[test]
fn corrupted_terminal_position_or_fence_is_not_admissible() {
    let mut ledger = ledger(20);
    let grant = reserve_grant(&mut ledger, "1", 6);
    let claim = claim_grant(&mut ledger, &grant);
    assert!(matches!(
        ledger.apply(4, 13, BudgetCommand::Settle(settlement(&claim, Some(3)))),
        BudgetReply::Settled(_)
    ));
    let record = ledger.grants.get_mut(&grant.grant_id).unwrap();
    let GrantState::Settled { receipt, .. } = &mut record.state else {
        panic!("settlement must be durable before corruption test");
    };
    receipt.committed_at.index += 1;
    assert_eq!(Err(BudgetRejection::InvalidConfig), ledger.validate());
}
