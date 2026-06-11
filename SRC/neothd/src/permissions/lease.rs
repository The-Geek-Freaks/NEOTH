//! SL-01a — Capability Lease primitive.
//!
//! A **TTL-bounded, scoped grant**: the operator (or, later, a cluster
//! master) hands a specific subject — a paired peer or a plugin — the
//! right to perform ONE capability for a bounded window. After
//! `expires_unix` the lease is dead and the autonomy gate falls back to
//! its default (fail-closed) decision; there is no silent renewal.
//!
//! Why this is the foundation of the cluster + proactive lanes: delegating
//! a task to a slave node (SL-01) or letting the proactive loop write
//! without re-prompting (G-01) both need "this subject may do X until T,
//! and the WAL records exactly that." A lease is that record — auditable
//! via `neoth wal show --type lease_granted` and revocable at any time.
//!
//! This module is the **pure primitive + persisted store**. It does NOT
//! wire the autonomy gate to honour leases yet (that is SL-01a-b — the
//! gate consumer); keeping the grant/check/revoke surface pure makes the
//! whole thing trivially testable.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The leasable capability classes. Deliberately a COARSE, serde-stable
/// subset of [`super::Action`] — a lease grants a *category* of action,
/// not a single parameterised call, so the wire form stays small and the
/// `--type lease_granted` audit stays scannable. New leasable surfaces are
/// added as variants (the autonomy gate maps a concrete `Action` to the
/// scope it would need).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LeaseScope {
    /// Read operator memory / config (no mutation).
    Read,
    /// Write inside `~/.neoth/` (daemon state).
    WriteNeothHome,
    /// Send a message out through a channel adapter.
    ChannelSend,
    /// Accept a delegated task from a cluster master (the SL-01 slave path).
    ClusterTaskAccept,
    /// Invoke a specific MCP tool (the inner string is the tool id).
    McpTool(String),
    /// GOLD-ADOPT-23 P1 — lift the risk-gate block on a Critical dangerous
    /// command (`rm -rf /`, …) for a TTL window. The operationalised "confirm":
    /// `neoth lease grant operator dangerous_command --ttl 300`. Scoped +
    /// auto-expiring, so it can't degenerate into a global policy=warn flip.
    DangerousCommand,
    /// GOLD-ADOPT-23 P1 — lift the risk-gate block on an outbound egress to a
    /// non-allowlisted destination for a TTL window.
    Egress,
}

/// GR-032 — hard cap on the TTL of a risk-override grant (`dangerous_command` /
/// `egress`). Those scopes lift a hard SAFETY block, so the operator confirm
/// window must auto-close — a `--ttl 9999d` can't degenerate into a
/// permanently-open override. 24 hours: long enough for a maintenance session,
/// short enough that a forgotten grant lapses within a day.
pub const MAX_RISK_OVERRIDE_TTL_SECS: i64 = 24 * 60 * 60;

impl LeaseScope {
    /// Stable operator-facing label for the audit log + CLI.
    pub fn as_str(&self) -> &'static str {
        match self {
            LeaseScope::Read => "read",
            LeaseScope::WriteNeothHome => "write_neoth_home",
            LeaseScope::ChannelSend => "channel_send",
            LeaseScope::ClusterTaskAccept => "cluster_task_accept",
            LeaseScope::McpTool(_) => "mcp_tool",
            LeaseScope::DangerousCommand => "dangerous_command",
            LeaseScope::Egress => "egress",
        }
    }

    /// Parse a CLI token into a scope. `mcp_tool:<id>` carries the tool id.
    pub fn parse(token: &str) -> Result<Self> {
        if let Some(tool) = token.strip_prefix("mcp_tool:") {
            if tool.is_empty() {
                anyhow::bail!("mcp_tool scope needs a tool id: `mcp_tool:<id>`");
            }
            return Ok(LeaseScope::McpTool(tool.to_string()));
        }
        match token {
            "read" => Ok(LeaseScope::Read),
            "write_neoth_home" => Ok(LeaseScope::WriteNeothHome),
            "channel_send" => Ok(LeaseScope::ChannelSend),
            "cluster_task_accept" => Ok(LeaseScope::ClusterTaskAccept),
            "dangerous_command" => Ok(LeaseScope::DangerousCommand),
            "egress" => Ok(LeaseScope::Egress),
            other => anyhow::bail!(
                "unknown lease scope `{other}` — use read / write_neoth_home / \
                 channel_send / cluster_task_accept / mcp_tool:<id> / \
                 dangerous_command / egress"
            ),
        }
    }

    /// GR-032 — the maximum TTL (seconds) a grant of this scope may request, or
    /// `None` when the scope is uncapped. The risk-override scopes
    /// (`DangerousCommand` / `Egress`) lift a hard SAFETY block, so they are
    /// hard-capped at [`MAX_RISK_OVERRIDE_TTL_SECS`] — the override window must
    /// auto-expire. Other scopes (cluster task accept, channel send, read, …)
    /// have legitimate long-lived windows and stay uncapped.
    pub fn max_ttl_secs(&self) -> Option<i64> {
        match self {
            LeaseScope::DangerousCommand | LeaseScope::Egress => Some(MAX_RISK_OVERRIDE_TTL_SECS),
            _ => None,
        }
    }

    /// GR-032 — validate a requested TTL against this scope's cap. `Ok(())` when
    /// allowed; an actionable error when a risk-override grant exceeds
    /// [`MAX_RISK_OVERRIDE_TTL_SECS`]. Both `neoth lease grant` and `neoth
    /// risk-confirm` call this so a `--ttl 9999d` can't leave a safety block
    /// permanently lifted.
    pub fn check_ttl(&self, ttl_secs: i64) -> Result<()> {
        if let Some(max) = self.max_ttl_secs() {
            if ttl_secs > max {
                anyhow::bail!(
                    "{} lease TTL {ttl_secs}s exceeds the {}h maximum for a risk-override \
                     window — a safety-block override must auto-expire; request a shorter --ttl",
                    self.as_str(),
                    max / 3600
                );
            }
        }
        Ok(())
    }
}

/// One capability lease. `lease_id` is a UUID v7 (time-ordered, so leases
/// sort by grant time). All times are unix seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLease {
    pub lease_id: String,
    /// Subject the lease is granted to — a peer pub-key-hex or a plugin id.
    pub granted_to: String,
    pub scope: LeaseScope,
    pub granted_at_unix: i64,
    pub expires_unix: i64,
}

impl CapabilityLease {
    /// Mint a fresh lease valid for `ttl_secs` from `now_unix`.
    pub fn new(
        granted_to: impl Into<String>,
        scope: LeaseScope,
        ttl_secs: i64,
        now_unix: i64,
    ) -> Self {
        Self {
            lease_id: uuid::Uuid::now_v7().to_string(),
            granted_to: granted_to.into(),
            scope,
            granted_at_unix: now_unix,
            expires_unix: now_unix.saturating_add(ttl_secs.max(0)),
        }
    }

    /// A lease is active while `now_unix < expires_unix`. The boundary is
    /// exclusive — at the expiry second the lease is already dead
    /// (fail-closed: never grant on the exact tick a lease lapses).
    pub fn is_active(&self, now_unix: i64) -> bool {
        now_unix < self.expires_unix
    }

    /// True when this lease authorises `subject` to perform `scope` right
    /// now. The single predicate the autonomy gate will call.
    ///
    /// Fail-closed against the empty string on BOTH sides: a lease minted
    /// with `granted_to == ""` (or a caller passing an empty `subject`)
    /// must never match — otherwise an empty grant would behave as a
    /// match-all wildcard for any caller that produced an empty subject
    /// (a parsing edge case or a `--subject ""` probe). The authentic
    /// identities this is compared against (peer pub-key-hex, plugin id)
    /// are never empty.
    pub fn covers(&self, subject: &str, scope: &LeaseScope, now_unix: i64) -> bool {
        !subject.is_empty()
            && !self.granted_to.is_empty()
            && self.is_active(now_unix)
            && self.granted_to == subject
            && &self.scope == scope
    }

    /// Seconds left before expiry (0 once dead).
    pub fn ttl_remaining_secs(&self, now_unix: i64) -> i64 {
        (self.expires_unix - now_unix).max(0)
    }
}

/// The operator's persisted lease set (`~/.neoth/leases.json`). Pure
/// in-memory operations; persistence is explicit via [`Self::load`] /
/// [`Self::save`] so callers control when disk is touched.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LeaseStore {
    #[serde(default)]
    pub leases: Vec<CapabilityLease>,
}

impl LeaseStore {
    /// Default filename under `~/.neoth/`.
    pub fn default_path(home: &Path) -> std::path::PathBuf {
        home.join("leases.json")
    }

    /// Read the store. A missing file is an empty store (a fresh install
    /// has no leases); a CORRUPT file is a hard error — silently
    /// defaulting would drop the operator's active grants without a trace.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read leases at {}", path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse leases JSON at {}", path.display()))
    }

    /// Write atomically (tmp + rename) so a crash mid-write can't truncate
    /// the operator's lease set.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create leases dir {}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(self).context("serialise leases")?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    /// Add a lease.
    pub fn grant(&mut self, lease: CapabilityLease) {
        self.leases.push(lease);
    }

    /// Remove a lease by id (full or unique prefix). Returns the removed
    /// lease, or `None` when no lease matches.
    pub fn revoke(&mut self, lease_id_or_prefix: &str) -> Option<CapabilityLease> {
        let idx = self
            .leases
            .iter()
            .position(|l| l.lease_id == lease_id_or_prefix)
            .or_else(|| {
                // Unique-prefix match (operators paste the short head).
                let matches: Vec<usize> = self
                    .leases
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| l.lease_id.starts_with(lease_id_or_prefix))
                    .map(|(i, _)| i)
                    .collect();
                if matches.len() == 1 {
                    Some(matches[0])
                } else {
                    None
                }
            })?;
        Some(self.leases.remove(idx))
    }

    /// True when SOME active lease authorises `subject` for `scope`. The
    /// fail-closed default (no covering lease) is `false`.
    pub fn active_for(&self, subject: &str, scope: &LeaseScope, now_unix: i64) -> bool {
        self.find_covering(subject, scope, now_unix).is_some()
    }

    /// The first active lease authorising `subject` for `scope`, or `None`.
    /// Unlike [`Self::active_for`] this hands the caller the lease itself so
    /// the autonomy gate can record WHICH lease drove a `Confirm → Allow`
    /// upgrade in the WAL audit frame (the verifiable-loyalty grant chain).
    /// Fail-closed default (no covering lease) is `None`.
    pub fn find_covering(
        &self,
        subject: &str,
        scope: &LeaseScope,
        now_unix: i64,
    ) -> Option<&CapabilityLease> {
        self.leases
            .iter()
            .find(|l| l.covers(subject, scope, now_unix))
    }

    /// Every currently-active lease, newest grant first.
    pub fn active(&self, now_unix: i64) -> Vec<&CapabilityLease> {
        let mut v: Vec<&CapabilityLease> = self
            .leases
            .iter()
            .filter(|l| l.is_active(now_unix))
            .collect();
        v.sort_by_key(|l| std::cmp::Reverse(l.granted_at_unix));
        v
    }

    /// Remove every expired lease, returning the removed set so the caller
    /// can emit a `LEASE_EXPIRED` audit frame per lease.
    pub fn prune_expired(&mut self, now_unix: i64) -> Vec<CapabilityLease> {
        let (expired, live): (Vec<_>, Vec<_>) = std::mem::take(&mut self.leases)
            .into_iter()
            .partition(|l| !l.is_active(now_unix));
        self.leases = live;
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_700_000_000;

    #[test]
    fn lease_scope_parse_round_trips_and_rejects_garbage() {
        for s in [
            LeaseScope::Read,
            LeaseScope::WriteNeothHome,
            LeaseScope::ChannelSend,
            LeaseScope::ClusterTaskAccept,
            LeaseScope::DangerousCommand,
            LeaseScope::Egress,
        ] {
            // round-trip via the snake_case label (mcp_tool handled below)
            assert_eq!(LeaseScope::parse(s.as_str()).unwrap(), s);
        }
        assert_eq!(
            LeaseScope::parse("mcp_tool:fetch").unwrap(),
            LeaseScope::McpTool("fetch".into())
        );
        assert!(LeaseScope::parse("mcp_tool:").is_err());
        assert!(LeaseScope::parse("nonsense").is_err());
    }

    #[test]
    fn risk_override_scopes_are_ttl_capped() {
        // GR-032: dangerous_command / egress (safety-block overrides) are
        // hard-capped; other scopes stay uncapped.
        assert_eq!(
            LeaseScope::DangerousCommand.max_ttl_secs(),
            Some(MAX_RISK_OVERRIDE_TTL_SECS)
        );
        assert_eq!(
            LeaseScope::Egress.max_ttl_secs(),
            Some(MAX_RISK_OVERRIDE_TTL_SECS)
        );
        assert_eq!(LeaseScope::Read.max_ttl_secs(), None);
        assert_eq!(LeaseScope::ClusterTaskAccept.max_ttl_secs(), None);

        // Within the cap is allowed; the exact boundary is allowed; over is not.
        assert!(LeaseScope::DangerousCommand.check_ttl(3600).is_ok());
        assert!(
            LeaseScope::DangerousCommand
                .check_ttl(MAX_RISK_OVERRIDE_TTL_SECS)
                .is_ok()
        );
        let err = LeaseScope::DangerousCommand
            .check_ttl(MAX_RISK_OVERRIDE_TTL_SECS + 1)
            .unwrap_err();
        assert!(err.to_string().contains("maximum"));
        // An uncapped scope accepts a long window (e.g. a cluster task lease).
        assert!(
            LeaseScope::ClusterTaskAccept
                .check_ttl(MAX_RISK_OVERRIDE_TTL_SECS * 30)
                .is_ok()
        );
    }

    #[test]
    fn new_lease_expires_after_ttl_exclusive_boundary() {
        let l = CapabilityLease::new("peerA", LeaseScope::Read, 3600, T0);
        assert!(l.is_active(T0));
        assert!(l.is_active(T0 + 3599));
        assert!(
            !l.is_active(T0 + 3600),
            "expiry boundary is exclusive — dead at the tick"
        );
        assert!(!l.is_active(T0 + 7200));
        assert_eq!(l.ttl_remaining_secs(T0), 3600);
        assert_eq!(l.ttl_remaining_secs(T0 + 3600), 0);
    }

    #[test]
    fn covers_requires_subject_scope_and_liveness() {
        let l = CapabilityLease::new("peerA", LeaseScope::ChannelSend, 100, T0);
        assert!(l.covers("peerA", &LeaseScope::ChannelSend, T0 + 50));
        // wrong subject
        assert!(!l.covers("peerB", &LeaseScope::ChannelSend, T0 + 50));
        // wrong scope
        assert!(!l.covers("peerA", &LeaseScope::Read, T0 + 50));
        // expired
        assert!(!l.covers("peerA", &LeaseScope::ChannelSend, T0 + 200));
    }

    #[test]
    fn covers_is_fail_closed_against_empty_subject() {
        // An empty granted_to must NOT behave as a match-all wildcard, and
        // an empty caller subject must never match. Both directions deny.
        let empty_grant = CapabilityLease::new("", LeaseScope::ChannelSend, 100, T0);
        assert!(
            !empty_grant.covers("", &LeaseScope::ChannelSend, T0 + 50),
            "empty == empty must NOT authorise"
        );
        assert!(!empty_grant.covers("peerA", &LeaseScope::ChannelSend, T0 + 50));
        let real = CapabilityLease::new("peerA", LeaseScope::ChannelSend, 100, T0);
        assert!(
            !real.covers("", &LeaseScope::ChannelSend, T0 + 50),
            "empty subject must never match a real lease"
        );
    }

    #[test]
    fn lease_ids_are_unique_and_time_ordered() {
        let a = CapabilityLease::new("p", LeaseScope::Read, 60, T0);
        let b = CapabilityLease::new("p", LeaseScope::Read, 60, T0);
        assert_ne!(a.lease_id, b.lease_id, "uuid v7 ids must be unique");
        // v7 ids are totally ordered: sorting two distinct ids is deterministic.
        let mut ids = [a.lease_id.clone(), b.lease_id.clone()];
        ids.sort();
        assert!(ids[0] < ids[1], "v7 ids must be totally ordered");
    }

    #[test]
    fn store_active_for_is_fail_closed_by_default() {
        let mut s = LeaseStore::default();
        // No lease → deny.
        assert!(!s.active_for("peerA", &LeaseScope::Read, T0));
        s.grant(CapabilityLease::new("peerA", LeaseScope::Read, 100, T0));
        assert!(s.active_for("peerA", &LeaseScope::Read, T0 + 50));
        assert!(
            !s.active_for("peerA", &LeaseScope::Read, T0 + 100),
            "expired → deny"
        );
        assert!(
            !s.active_for("peerB", &LeaseScope::Read, T0 + 50),
            "other subject → deny"
        );
    }

    #[test]
    fn store_revoke_by_full_id_and_unique_prefix() {
        let mut s = LeaseStore::default();
        let l = CapabilityLease::new("peerA", LeaseScope::Read, 100, T0);
        let id = l.lease_id.clone();
        s.grant(l);
        // unique prefix
        let revoked = s.revoke(&id[..8]).expect("prefix revoke");
        assert_eq!(revoked.lease_id, id);
        assert!(s.leases.is_empty());
        // revoking a gone id → None
        assert!(s.revoke(&id).is_none());
    }

    #[test]
    fn store_prune_expired_returns_and_removes_only_dead() {
        let mut s = LeaseStore::default();
        s.grant(CapabilityLease::new("a", LeaseScope::Read, 10, T0)); // dead at T0+10
        s.grant(CapabilityLease::new("b", LeaseScope::Read, 1000, T0)); // alive
        let pruned = s.prune_expired(T0 + 100);
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].granted_to, "a");
        assert_eq!(s.leases.len(), 1);
        assert_eq!(s.leases[0].granted_to, "b");
    }

    #[test]
    fn store_load_save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = LeaseStore::default_path(dir.path());
        let mut s = LeaseStore::default();
        s.grant(CapabilityLease::new(
            "peerA",
            LeaseScope::ClusterTaskAccept,
            3600,
            T0,
        ));
        s.save(&path).unwrap();
        let back = LeaseStore::load(&path).unwrap();
        assert_eq!(back.leases, s.leases);
        // missing file → empty
        assert!(
            LeaseStore::load(&dir.path().join("nope.json"))
                .unwrap()
                .leases
                .is_empty()
        );
    }
}
