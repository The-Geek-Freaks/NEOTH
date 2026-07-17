//! Atomic UTC-day USD budget for concrete Council provider leaves.
//!
//! A read-only usage-log check cannot enforce a hard cap: concurrent leaves can
//! all observe the same headroom and overspend it. This store therefore uses a
//! two-phase reservation ledger. Every concrete leaf reserves its reviewed
//! worst-case USD bound under one process mutex plus one cross-process file
//! lock before dispatch. Its terminal edge atomically replaces the reservation
//! with actual cost; when actual cost is unavailable the full reservation is
//! retained as settled spend. Missing state starts a new ledger, while an
//! existing unreadable or malformed ledger blocks admission without modifying
//! the evidence.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const LEDGER_SCHEMA_VERSION: u8 = 1;
const SECONDS_PER_UTC_DAY: i64 = 86_400;
const USD_NANOS_PER_USD: f64 = 1_000_000_000.0;

static DAILY_BUDGET_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug)]
pub(crate) struct DailyBudgetPolicy {
    ledger_path: PathBuf,
    cap_usd_nanos: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct DailyBudgetReservationPlan {
    policy: DailyBudgetPolicy,
    reservation_id: String,
    provider: &'static str,
    model: String,
    reserved_usd_nanos: u64,
}

#[derive(Debug)]
pub(crate) struct DailyBudgetReservation {
    ledger_path: PathBuf,
    reservation_id: String,
    utc_day: i64,
    reserved_usd_nanos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingReservation {
    provider: String,
    model: String,
    reserved_usd_nanos: u64,
    created_at_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DailyBudgetLedger {
    schema_version: u8,
    utc_day: i64,
    settled_usd_nanos: u64,
    pending: BTreeMap<String, PendingReservation>,
}

impl DailyBudgetLedger {
    fn empty(utc_day: i64) -> Self {
        Self {
            schema_version: LEDGER_SCHEMA_VERSION,
            utc_day,
            settled_usd_nanos: 0,
            pending: BTreeMap::new(),
        }
    }

    fn committed_usd_nanos(&self) -> Result<u64> {
        self.pending
            .values()
            .try_fold(self.settled_usd_nanos, |total, reservation| {
                total
                    .checked_add(reservation.reserved_usd_nanos)
                    .context("council daily-budget ledger total overflow")
            })
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != LEDGER_SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported council daily-budget ledger schema {} (expected {})",
                self.schema_version,
                LEDGER_SCHEMA_VERSION
            );
        }
        self.committed_usd_nanos()?;
        Ok(())
    }
}

impl DailyBudgetPolicy {
    pub(crate) fn new(home: &Path, cap_usd: f32) -> Result<Self> {
        let cap_usd_nanos = usd_to_nanos_floor(f64::from(cap_usd), "daily USD cap")?;
        Ok(Self {
            ledger_path: home.join("budget").join("daily.json"),
            cap_usd_nanos,
        })
    }

    pub(crate) fn plan(
        &self,
        reservation_id: String,
        provider: &'static str,
        model: String,
        reserved_usd: f64,
    ) -> Result<DailyBudgetReservationPlan> {
        Ok(DailyBudgetReservationPlan {
            policy: self.clone(),
            reservation_id,
            provider,
            model,
            reserved_usd_nanos: usd_to_nanos_ceil(reserved_usd, "provider cost bound")?,
        })
    }

    fn remaining_usd(&self, now_unix: i64) -> Result<f32> {
        let current_day = utc_day(now_unix);
        let _process_guard = DAILY_BUDGET_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _file_guard = crate::util::locked_file::lock_file_blocking(
            &lock_path(&self.ledger_path),
            "council daily-budget ledger",
        )?;
        let ledger = match load_existing(&self.ledger_path) {
            Ok(ledger) => ledger,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(nanos_to_usd(self.cap_usd_nanos) as f32);
            }
            Err(error) => return Err(error),
        };
        if ledger.utc_day > current_day {
            anyhow::bail!(
                "council daily-budget ledger is from future UTC day {}; current day is {}",
                ledger.utc_day,
                current_day
            );
        }
        if ledger.utc_day < current_day {
            return Ok(nanos_to_usd(self.cap_usd_nanos) as f32);
        }
        let committed = ledger.committed_usd_nanos()?;
        Ok(nanos_to_usd(self.cap_usd_nanos.saturating_sub(committed)) as f32)
    }
}

/// Snapshot the exact headroom used by the atomic Council leaf ledger. The
/// smart trigger uses this advisory read so its budget multiplier is evaluated
/// before fan-out; concrete leaves still reserve atomically at dispatch time.
pub(crate) fn remaining_daily_budget_usd(home: &Path, cap_usd: f32, now_unix: i64) -> Result<f32> {
    DailyBudgetPolicy::new(home, cap_usd)?.remaining_usd(now_unix)
}

impl DailyBudgetReservationPlan {
    pub(crate) fn reserve(self, now_unix: i64) -> Result<DailyBudgetReservation> {
        let utc_day = utc_day(now_unix);
        let ledger_path = self.policy.ledger_path.clone();
        let reservation_id = self.reservation_id.clone();
        let reserved_usd_nanos = self.reserved_usd_nanos;
        update_ledger(&ledger_path, |ledger| {
            if ledger.utc_day > utc_day {
                anyhow::bail!(
                    "council daily-budget ledger is from future UTC day {}; current day is {}",
                    ledger.utc_day,
                    utc_day
                );
            }
            if ledger.utc_day < utc_day {
                *ledger = DailyBudgetLedger::empty(utc_day);
            }
            if ledger.pending.contains_key(&reservation_id) {
                anyhow::bail!("duplicate council daily-budget reservation `{reservation_id}`");
            }
            let committed = ledger.committed_usd_nanos()?;
            let projected = committed
                .checked_add(reserved_usd_nanos)
                .context("council daily-budget reservation overflow")?;
            if projected > self.policy.cap_usd_nanos {
                anyhow::bail!(
                    "council daily USD cap exceeded: committed ${:.9} + reserve ${:.9} > cap ${:.9}",
                    nanos_to_usd(committed),
                    nanos_to_usd(reserved_usd_nanos),
                    nanos_to_usd(self.policy.cap_usd_nanos)
                );
            }
            ledger.pending.insert(
                reservation_id.clone(),
                PendingReservation {
                    provider: self.provider.to_owned(),
                    model: self.model,
                    reserved_usd_nanos,
                    created_at_unix: now_unix,
                },
            );
            Ok(())
        })?;
        Ok(DailyBudgetReservation {
            ledger_path,
            reservation_id,
            utc_day,
            reserved_usd_nanos,
        })
    }
}

impl DailyBudgetReservation {
    /// Replace this pending bound with the reported actual cost. `None` keeps
    /// the full bound: an unmetered/failed response must never be interpreted
    /// as free after the provider may already have billed it.
    pub(crate) fn settle(self, actual_cost_usd: Option<f64>) -> Result<()> {
        let actual_usd_nanos = match actual_cost_usd {
            Some(actual) => usd_to_nanos_ceil(actual, "actual provider cost")?,
            None => self.reserved_usd_nanos,
        };
        update_existing_ledger(&self.ledger_path, |ledger| {
            // A reservation admitted on the previous UTC day may finish after
            // the new-day ledger has already been opened. It belongs to its
            // admission day and must not mutate the new day's allowance.
            // Logged so an operator auditing spend can explain the gap: the
            // actual cost of a call that straddles midnight lands in NO
            // ledger (day N's admission stays correct; day N+1 is untouched).
            if ledger.utc_day > self.utc_day {
                tracing::info!(
                    reservation = %self.reservation_id,
                    admitted_day = self.utc_day,
                    ledger_day = ledger.utc_day,
                    "council daily-budget settlement crossed UTC midnight — cost not recorded in the new day's ledger"
                );
                return Ok(());
            }
            if ledger.utc_day < self.utc_day {
                anyhow::bail!(
                    "council daily-budget ledger day {} precedes reservation day {}",
                    ledger.utc_day,
                    self.utc_day
                );
            }
            let pending = ledger
                .pending
                .remove(&self.reservation_id)
                .with_context(|| {
                    format!(
                        "council daily-budget reservation `{}` disappeared before settlement",
                        self.reservation_id
                    )
                })?;
            if pending.reserved_usd_nanos != self.reserved_usd_nanos {
                anyhow::bail!(
                    "council daily-budget reservation `{}` changed before settlement",
                    self.reservation_id
                );
            }
            ledger.settled_usd_nanos = ledger
                .settled_usd_nanos
                .checked_add(actual_usd_nanos)
                .context("council daily-budget settled total overflow")?;
            Ok(())
        })
    }

    /// Roll back a reservation when dispatch never reached the provider (for
    /// example because the mandatory provider-intent WAL append failed).
    pub(crate) fn release_before_dispatch(self) -> Result<()> {
        update_existing_ledger(&self.ledger_path, |ledger| {
            if ledger.utc_day > self.utc_day {
                return Ok(());
            }
            if ledger.utc_day != self.utc_day {
                anyhow::bail!(
                    "council daily-budget ledger day {} does not match reservation day {}",
                    ledger.utc_day,
                    self.utc_day
                );
            }
            let pending = ledger
                .pending
                .remove(&self.reservation_id)
                .with_context(|| {
                    format!(
                        "council daily-budget reservation `{}` disappeared before dispatch",
                        self.reservation_id
                    )
                })?;
            if pending.reserved_usd_nanos != self.reserved_usd_nanos {
                anyhow::bail!(
                    "council daily-budget reservation `{}` changed before dispatch",
                    self.reservation_id
                );
            }
            Ok(())
        })
    }
}

fn utc_day(now_unix: i64) -> i64 {
    now_unix.div_euclid(SECONDS_PER_UTC_DAY)
}

fn usd_to_nanos_floor(usd: f64, what: &str) -> Result<u64> {
    validate_usd(usd, what)?;
    let scaled = usd * USD_NANOS_PER_USD;
    if scaled > u64::MAX as f64 {
        anyhow::bail!("{what} is too large");
    }
    Ok(scaled.floor() as u64)
}

fn usd_to_nanos_ceil(usd: f64, what: &str) -> Result<u64> {
    validate_usd(usd, what)?;
    let scaled = usd * USD_NANOS_PER_USD;
    if scaled > u64::MAX as f64 {
        anyhow::bail!("{what} is too large");
    }
    Ok(scaled.ceil() as u64)
}

fn validate_usd(usd: f64, what: &str) -> Result<()> {
    if !usd.is_finite() || usd < 0.0 {
        anyhow::bail!("{what} must be a finite non-negative USD amount, got {usd}");
    }
    Ok(())
}

fn nanos_to_usd(nanos: u64) -> f64 {
    nanos as f64 / USD_NANOS_PER_USD
}

fn lock_path(ledger_path: &Path) -> PathBuf {
    let mut path = ledger_path.as_os_str().to_owned();
    path.push(".lock");
    PathBuf::from(path)
}

fn load_existing(ledger_path: &Path) -> Result<DailyBudgetLedger> {
    let bytes = std::fs::read(ledger_path)
        .with_context(|| format!("read council daily-budget ledger {}", ledger_path.display()))?;
    let ledger: DailyBudgetLedger = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse council daily-budget ledger {}",
            ledger_path.display()
        )
    })?;
    ledger.validate()?;
    Ok(ledger)
}

fn update_ledger<T>(
    ledger_path: &Path,
    mutation: impl FnOnce(&mut DailyBudgetLedger) -> Result<T>,
) -> Result<T> {
    update_ledger_inner(ledger_path, true, mutation)
}

fn update_existing_ledger<T>(
    ledger_path: &Path,
    mutation: impl FnOnce(&mut DailyBudgetLedger) -> Result<T>,
) -> Result<T> {
    update_ledger_inner(ledger_path, false, mutation)
}

fn update_ledger_inner<T>(
    ledger_path: &Path,
    allow_missing: bool,
    mutation: impl FnOnce(&mut DailyBudgetLedger) -> Result<T>,
) -> Result<T> {
    let _process_guard = DAILY_BUDGET_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _file_guard = crate::util::locked_file::lock_file_blocking(
        &lock_path(ledger_path),
        "council daily-budget ledger",
    )?;
    let mut ledger = match load_existing(ledger_path) {
        Ok(ledger) => ledger,
        Err(error)
            if allow_missing
                && error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            // The reserving mutation owns the explicit clock value. A
            // sentinel older than every representable UTC day lets it set the
            // first real day without coupling deterministic tests to wall time.
            DailyBudgetLedger::empty(i64::MIN)
        }
        Err(error) => return Err(error),
    };
    let result = mutation(&mut ledger)?;
    ledger.validate()?;
    let bytes =
        serde_json::to_vec_pretty(&ledger).context("serialize council daily-budget ledger")?;
    crate::util::atomic_write::atomic_write_private(ledger_path, &bytes).with_context(|| {
        format!(
            "atomically write private council daily-budget ledger {}",
            ledger_path.display()
        )
    })?;
    Ok(result)
}

#[cfg(test)]
fn test_snapshot(home: &Path) -> DailyBudgetLedger {
    load_existing(&home.join("budget").join("daily.json")).unwrap()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    const DAY_10: i64 = 10 * SECONDS_PER_UTC_DAY + 123;

    fn policy(home: &Path, cap: f32) -> DailyBudgetPolicy {
        DailyBudgetPolicy::new(home, cap).unwrap()
    }

    #[test]
    fn remaining_budget_starts_at_cap_without_a_ledger() {
        let home = tempfile::tempdir().unwrap();
        let remaining = remaining_daily_budget_usd(home.path(), 7.5, DAY_10).unwrap();
        assert!((remaining - 7.5).abs() < f32::EPSILON);
    }

    #[test]
    fn remaining_budget_includes_pending_reservations() {
        let home = tempfile::tempdir().unwrap();
        let policy = policy(home.path(), 10.0);
        let _pending = policy
            .plan("pending".into(), "openai_api", "gpt-5".into(), 2.25)
            .unwrap()
            .reserve(DAY_10)
            .unwrap();
        let remaining = remaining_daily_budget_usd(home.path(), 10.0, DAY_10).unwrap();
        assert!((remaining - 7.75).abs() < 1e-6, "got {remaining}");
    }

    #[test]
    fn remaining_budget_resets_at_the_next_utc_day() {
        let home = tempfile::tempdir().unwrap();
        let policy = policy(home.path(), 10.0);
        let reservation = policy
            .plan("settled".into(), "openai_api", "gpt-5".into(), 4.0)
            .unwrap()
            .reserve(DAY_10)
            .unwrap();
        reservation.settle(Some(4.0)).unwrap();
        let remaining =
            remaining_daily_budget_usd(home.path(), 10.0, DAY_10 + SECONDS_PER_UTC_DAY).unwrap();
        assert!((remaining - 10.0).abs() < f32::EPSILON);
    }

    fn plan(
        policy: &DailyBudgetPolicy,
        id: impl Into<String>,
        amount: f64,
    ) -> DailyBudgetReservationPlan {
        policy
            .plan(id.into(), "openai_api", "gpt-4o".into(), amount)
            .unwrap()
    }

    #[test]
    fn reserve_then_settle_reclaims_unused_bound() {
        let home = tempfile::tempdir().unwrap();
        let policy = policy(home.path(), 1.0);
        let first = plan(&policy, "first", 0.6).reserve(DAY_10).unwrap();
        let reserved = test_snapshot(home.path());
        assert_eq!(reserved.pending.len(), 1);
        assert_eq!(reserved.committed_usd_nanos().unwrap(), 600_000_000);

        first.settle(Some(0.25)).unwrap();
        let settled = test_snapshot(home.path());
        assert!(settled.pending.is_empty());
        assert_eq!(settled.settled_usd_nanos, 250_000_000);

        plan(&policy, "second", 0.75)
            .reserve(DAY_10 + 1)
            .expect("actual settlement must reclaim the unused reservation headroom");
        assert_eq!(
            test_snapshot(home.path()).committed_usd_nanos().unwrap(),
            1_000_000_000
        );
    }

    #[test]
    fn missing_actual_cost_settles_full_reserved_bound() {
        let home = tempfile::tempdir().unwrap();
        let policy = policy(home.path(), 1.0);
        plan(&policy, "unknown-terminal", 0.7)
            .reserve(DAY_10)
            .unwrap()
            .settle(None)
            .unwrap();
        let ledger = test_snapshot(home.path());
        assert!(ledger.pending.is_empty());
        assert_eq!(ledger.settled_usd_nanos, 700_000_000);
        assert!(plan(&policy, "too-much", 0.31).reserve(DAY_10).is_err());
    }

    #[test]
    fn concurrent_reservations_admit_exact_remaining_headroom() {
        let home = tempfile::tempdir().unwrap();
        let policy = Arc::new(policy(home.path(), 1.0));
        let barrier = Arc::new(Barrier::new(10));
        let handles: Vec<_> = (0..10)
            .map(|index| {
                let policy = Arc::clone(&policy);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    plan(&policy, format!("r-{index}"), 0.2)
                        .reserve(DAY_10)
                        .is_ok()
                })
            })
            .collect();
        let admitted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 5);
        let ledger = test_snapshot(home.path());
        assert_eq!(ledger.pending.len(), 5);
        assert_eq!(ledger.committed_usd_nanos().unwrap(), 1_000_000_000);
    }

    #[test]
    fn corrupt_existing_ledger_blocks_retries_and_preserves_bytes() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("budget").join("daily.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let corrupt = b"{not-json";
        std::fs::write(&path, corrupt).unwrap();
        let policy = policy(home.path(), 1.0);

        assert!(plan(&policy, "first", 0.1).reserve(DAY_10).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
        assert!(plan(&policy, "retry", 0.1).reserve(DAY_10).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }

    #[test]
    fn first_reservation_of_new_utc_day_resets_prior_day_only() {
        let home = tempfile::tempdir().unwrap();
        let policy = policy(home.path(), 0.5);
        let old = plan(&policy, "old", 0.5).reserve(DAY_10).unwrap();
        plan(&policy, "new", 0.5)
            .reserve(DAY_10 + SECONDS_PER_UTC_DAY)
            .unwrap();
        let ledger = test_snapshot(home.path());
        assert_eq!(ledger.utc_day, utc_day(DAY_10) + 1);
        assert_eq!(ledger.pending.len(), 1);
        assert!(ledger.pending.contains_key("new"));

        // A prior-day completion after rollover must not consume the new day.
        old.settle(Some(0.5)).unwrap();
        assert_eq!(
            test_snapshot(home.path()).committed_usd_nanos().unwrap(),
            500_000_000
        );
    }

    #[test]
    fn release_before_dispatch_removes_only_exact_reservation() {
        let home = tempfile::tempdir().unwrap();
        let policy = policy(home.path(), 1.0);
        let reservation = plan(&policy, "release", 1.0).reserve(DAY_10).unwrap();
        reservation.release_before_dispatch().unwrap();
        assert_eq!(test_snapshot(home.path()).committed_usd_nanos().unwrap(), 0);
        plan(&policy, "replacement", 1.0).reserve(DAY_10).unwrap();
    }

    #[test]
    fn invalid_cap_and_amounts_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        assert!(DailyBudgetPolicy::new(home.path(), f32::NAN).is_err());
        assert!(DailyBudgetPolicy::new(home.path(), -1.0).is_err());
        let policy = policy(home.path(), 1.0);
        assert!(
            policy
                .plan("nan".into(), "openai_api", "gpt-4o".into(), f64::NAN)
                .is_err()
        );
        assert!(
            policy
                .plan("negative".into(), "openai_api", "gpt-4o".into(), -0.1)
                .is_err()
        );
    }
}
