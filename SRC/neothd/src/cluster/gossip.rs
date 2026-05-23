//! Cluster Phase 6 — gossip state-sync primitives.
//!
//! Per the Session 21 architect verdict (`neoth_open_decisions_verdicts`):
//!   - **Per-event `do_not_gossip` tag** (highest operator visibility):
//!     without it, paired peers silently receive every conversation —
//!     privacy breach the moment the operator realises their home
//!     node holds their work node's client chats.
//!   - **Episodes-only replication** (semantic content, no raw PII):
//!     channel-ingress frames stay local; episodes carry the
//!     consolidated meaning without the raw payload. Operators who
//!     want full-frame mirroring flip
//!     `cluster.gossip.replicate_raw_ingress: true`.
//!   - **Replay budget capped at 30 days**: peers offline longer
//!     drop local state + re-pair fresh. Unbounded replay = DoS
//!     vector against the relay + LLM-cost blow-up on the catching-
//!     up peer. 30 days aligns with the warm-memory tier window
//!     already in the codebase.
//!
//! v0.1 scope = **primitives + policy types + tests**. The wire
//! protocol (vector-clock gossip + BudgetToken Raft consensus + JSONL
//! append-stream) ships in follow-up bites per
//! `PLAN/SPEC_cluster_phase6_gossip_state_sync_2026-05-22.md`.

use serde::{Deserialize, Serialize};

/// Per-event tag the operator (or upstream skill) attaches to a
/// WAL event to opt that event out of cross-peer gossip. Default
/// is "replicate" — operators opt OUT, not IN. Aligns with the
/// "replicate-most, exclude-some" pattern operators expect from
/// chat surfaces (Signal, iMessage, etc).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GossipTag {
    /// Replicate this event to every paired peer (default).
    #[default]
    Replicate,
    /// Operator-flagged "do not gossip" — never crosses the peer
    /// boundary. Common cases: a private chat with a client, a
    /// secret entered into a credential prompt, anything tagged
    /// by the future `neoth tag privacy <event_id>` operator CLI.
    DoNotGossip,
}

impl GossipTag {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replicate => "replicate",
            Self::DoNotGossip => "do_not_gossip",
        }
    }

    pub fn is_replicable(self) -> bool {
        matches!(self, Self::Replicate)
    }
}

/// Operator-tweakable cluster gossip policy (lives at
/// `freedom.yaml::cluster.gossip`). Defaults align with the
/// architect verdict — privacy-first.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct GossipPolicy {
    /// When true, replicate raw channel-ingress frames (Telegram /
    /// Slack / WhatsApp messages verbatim) to paired peers. Default
    /// `false`: only semantic episodes cross the peer boundary.
    /// Operators on a single-operator-multi-device topology may
    /// flip this on to mirror every conversation.
    pub replicate_raw_ingress: bool,
    /// Replay budget in days. Peers offline longer than this drop
    /// local state + re-pair as a fresh node on next contact.
    /// Default 30 (matches warm-tier window).
    #[serde(default = "default_replay_budget_days")]
    pub replay_budget_days: u32,
}

impl Default for GossipPolicy {
    fn default() -> Self {
        // Hand-roll Default — derive(Default) on u32 gives 0,
        // bypassing #[serde(default = ...)] which only fires on
        // deserialise paths. We want 30 days in both code-side
        // and YAML-side default-construction paths.
        Self {
            replicate_raw_ingress: false,
            replay_budget_days: default_replay_budget_days(),
        }
    }
}

fn default_replay_budget_days() -> u32 {
    30
}

/// Hard ceiling — even an operator override is clamped here to
/// avoid pathological replay loads. 90 days = ~3 months of WAL
/// frames; beyond that the catching-up peer's LLM-cost blow-up
/// becomes a real concern.
pub const MAX_REPLAY_BUDGET_DAYS: u32 = 90;

/// Resolved replay budget — `from_policy(&policy)` clamps the
/// operator's value into the safe range + exposes the convenience
/// `is_within_budget(event_ts, now)` predicate the future gossip
/// receiver uses to drop too-old frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayBudget {
    pub days: u32,
    pub cap_age_secs: i64,
}

impl ReplayBudget {
    /// Build from the operator's `GossipPolicy`. Clamps days to
    /// `[1, MAX_REPLAY_BUDGET_DAYS]` with tracing-warn on clamp.
    pub fn from_policy(policy: &GossipPolicy) -> Self {
        let mut days = policy.replay_budget_days;
        if days == 0 {
            tracing::warn!(
                "GossipPolicy: replay_budget_days=0 disables gossip entirely; \
                 clamping to default 30"
            );
            days = default_replay_budget_days();
        }
        if days > MAX_REPLAY_BUDGET_DAYS {
            tracing::warn!(
                requested = days,
                ceiling = MAX_REPLAY_BUDGET_DAYS,
                "GossipPolicy: replay_budget_days above ceiling; clamping"
            );
            days = MAX_REPLAY_BUDGET_DAYS;
        }
        Self {
            days,
            cap_age_secs: days as i64 * 86_400,
        }
    }

    /// Returns `true` when an event with timestamp `event_ts_unix`
    /// should be replicated to a catching-up peer at `now_ts_unix`.
    /// Events older than the budget window are dropped: the gossip
    /// receiver tells the sender "I'm too far behind, force a
    /// re-pair instead of trying to replay months of WAL".
    pub fn is_within_budget(&self, event_ts_unix: i64, now_ts_unix: i64) -> bool {
        let age = now_ts_unix.saturating_sub(event_ts_unix);
        // Clock-skew defence: future-dated event (negative age)
        // is clamped to 0 and accepted as "now"-equivalent.
        // Never silently drop an event because the operator's
        // clock drifted.
        let age = age.max(0);
        age <= self.cap_age_secs
    }

    /// Boundary helper for the future gossip wire: "is this peer
    /// too far behind to catch up?". Returns `true` when the
    /// peer's last_seen is older than the budget — caller asks
    /// the peer to drop state + re-pair.
    pub fn peer_force_repair(&self, peer_last_seen_unix: i64, now_ts_unix: i64) -> bool {
        !self.is_within_budget(peer_last_seen_unix, now_ts_unix)
    }
}

/// Default tag-and-replicate decision for a single WAL event.
/// Composes:
///   - the event's `GossipTag` (operator may have tagged
///     `DoNotGossip` upstream)
///   - the policy's `replicate_raw_ingress` flag
///   - the event's "is this raw channel ingress?" classification
///     (caller passes the bool — typically derived from the WAL
///     event type / band)
///
/// Returns `true` ⇔ replicate to peers.
pub fn should_replicate(tag: GossipTag, policy: &GossipPolicy, is_raw_ingress: bool) -> bool {
    if !tag.is_replicable() {
        return false;
    }
    if is_raw_ingress && !policy.replicate_raw_ingress {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_privacy_first() {
        let p = GossipPolicy::default();
        assert!(!p.replicate_raw_ingress);
        assert_eq!(p.replay_budget_days, 30);
    }

    #[test]
    fn gossip_tag_serde_round_trip() {
        for tag in [GossipTag::Replicate, GossipTag::DoNotGossip] {
            let yaml = serde_yaml::to_string(&tag).unwrap();
            let back: GossipTag = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(tag, back);
        }
    }

    #[test]
    fn gossip_tag_wire_form_pinned() {
        assert_eq!(GossipTag::Replicate.as_str(), "replicate");
        assert_eq!(GossipTag::DoNotGossip.as_str(), "do_not_gossip");
    }

    #[test]
    fn gossip_tag_is_replicable_predicate() {
        assert!(GossipTag::Replicate.is_replicable());
        assert!(!GossipTag::DoNotGossip.is_replicable());
    }

    #[test]
    fn replay_budget_default_30_days() {
        let p = GossipPolicy::default();
        let b = ReplayBudget::from_policy(&p);
        assert_eq!(b.days, 30);
        assert_eq!(b.cap_age_secs, 30 * 86_400);
    }

    #[test]
    fn replay_budget_clamps_zero_to_default() {
        let mut p = GossipPolicy::default();
        p.replay_budget_days = 0;
        let b = ReplayBudget::from_policy(&p);
        assert_eq!(b.days, 30, "zero clamps to default 30");
    }

    #[test]
    fn replay_budget_clamps_excessive_to_ceiling() {
        let mut p = GossipPolicy::default();
        p.replay_budget_days = 365;
        let b = ReplayBudget::from_policy(&p);
        assert_eq!(b.days, MAX_REPLAY_BUDGET_DAYS);
    }

    #[test]
    fn within_budget_passes_for_recent_event() {
        let p = GossipPolicy::default();
        let b = ReplayBudget::from_policy(&p);
        // 1 hour ago — well within 30 days.
        assert!(b.is_within_budget(1_000, 1_000 + 3_600));
    }

    #[test]
    fn within_budget_passes_at_exact_boundary() {
        let p = GossipPolicy::default();
        let b = ReplayBudget::from_policy(&p);
        // Event ts at exactly 30 days ago — inclusive, must pass.
        let now = 100_000_i64;
        let event_ts = now - b.cap_age_secs;
        assert!(b.is_within_budget(event_ts, now));
    }

    #[test]
    fn within_budget_rejects_outside_window() {
        let p = GossipPolicy::default();
        let b = ReplayBudget::from_policy(&p);
        // 31 days ago — outside the 30-day budget.
        let now = 100_000_i64;
        let event_ts = now - b.cap_age_secs - 1;
        assert!(!b.is_within_budget(event_ts, now));
    }

    #[test]
    fn within_budget_accepts_future_event_clock_skew_defence() {
        // Event timestamp in the future — operator clock drift.
        // Treated as "now"-equivalent, never silently dropped.
        let p = GossipPolicy::default();
        let b = ReplayBudget::from_policy(&p);
        assert!(b.is_within_budget(100_100, 100_000));
    }

    #[test]
    fn peer_force_repair_inverse_of_within_budget() {
        let p = GossipPolicy::default();
        let b = ReplayBudget::from_policy(&p);
        let now = 1_000_000_i64;
        // Recent peer — no force-repair.
        assert!(!b.peer_force_repair(now - 86_400, now));
        // Stale peer (31 days) — force-repair.
        assert!(b.peer_force_repair(now - 32 * 86_400, now));
    }

    #[test]
    fn should_replicate_default_replicable_event() {
        let policy = GossipPolicy::default();
        // Default tag (Replicate) + non-ingress event → replicate.
        assert!(should_replicate(GossipTag::Replicate, &policy, false));
    }

    #[test]
    fn should_replicate_blocks_do_not_gossip_tag() {
        let policy = GossipPolicy::default();
        // DoNotGossip wins regardless of policy or ingress flag.
        assert!(!should_replicate(GossipTag::DoNotGossip, &policy, false));
        assert!(!should_replicate(GossipTag::DoNotGossip, &policy, true));
        let mut open = policy.clone();
        open.replicate_raw_ingress = true;
        assert!(!should_replicate(GossipTag::DoNotGossip, &open, false));
    }

    #[test]
    fn should_replicate_blocks_raw_ingress_by_default() {
        let policy = GossipPolicy::default(); // replicate_raw_ingress = false
        assert!(!should_replicate(GossipTag::Replicate, &policy, true));
    }

    #[test]
    fn should_replicate_passes_raw_ingress_when_policy_opens() {
        let mut policy = GossipPolicy::default();
        policy.replicate_raw_ingress = true;
        assert!(should_replicate(GossipTag::Replicate, &policy, true));
    }

    #[test]
    fn policy_serde_round_trip_via_yaml() {
        let original = GossipPolicy {
            replicate_raw_ingress: true,
            replay_budget_days: 14,
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        let back: GossipPolicy = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn constants_pinned() {
        assert_eq!(MAX_REPLAY_BUDGET_DAYS, 90);
        assert_eq!(default_replay_budget_days(), 30);
    }
}
