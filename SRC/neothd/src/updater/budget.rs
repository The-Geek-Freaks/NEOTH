//! One immutable deadline contract shared by every leaf of an updater pass.
//!
//! Absolute milliseconds are authenticated evidence. Runtime enforcement uses
//! the monotonic deadlines captured with that evidence once, at pass admission;
//! a new HTTP request must never restart the pass clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

const MAX_RUN_MILLIS: u64 = 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpdaterDeadlinePhase {
    Effect,
    Quiesce,
    Terminal,
    Operation,
}

impl UpdaterDeadlinePhase {
    const ALL: [Self; 4] = [Self::Effect, Self::Quiesce, Self::Terminal, Self::Operation];

    fn index(self) -> usize {
        match self {
            Self::Effect => 0,
            Self::Quiesce => 1,
            Self::Terminal => 2,
            Self::Operation => 3,
        }
    }
}

/// Offsets from the same pass start, not independent per-phase durations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct UpdaterRunLimits {
    offsets_ms: [u64; 4],
}

impl UpdaterRunLimits {
    pub(crate) fn new(
        effect: Duration,
        quiesce: Duration,
        terminal: Duration,
        operation: Duration,
    ) -> Result<Self> {
        let mut offsets_ms = [0; 4];
        for (target, duration) in offsets_ms
            .iter_mut()
            .zip([effect, quiesce, terminal, operation])
        {
            // Round up once and use the same millisecond value for evidence
            // and runtime enforcement, including sub-millisecond callers.
            let millis = duration.as_nanos().div_ceil(1_000_000);
            *target = u64::try_from(millis).context("updater deadline offset overflow")?;
        }
        ensure!(offsets_ms[0] > 0, "updater effect budget must be positive");
        ensure!(
            offsets_ms.windows(2).all(|pair| pair[0] <= pair[1]),
            "updater deadline offsets must be ordered"
        );
        ensure!(
            offsets_ms[3] <= MAX_RUN_MILLIS,
            "updater operation budget exceeds one hour"
        );
        Ok(Self { offsets_ms })
    }

    pub(crate) fn default_http_probe() -> Result<Self> {
        Self::new(
            Duration::from_secs(120),
            Duration::from_secs(135),
            Duration::from_secs(150),
            Duration::from_secs(165),
        )
    }

    /// Native local CLI version processes are short, but retain time to kill/reap and acknowledge their terminal receipt.
    pub(crate) fn default_cli_installed_version_probe() -> Result<Self> {
        Self::new(
            Duration::from_secs(15),
            Duration::from_secs(20),
            Duration::from_secs(25),
            Duration::from_secs(30),
        )
    }

    /// The contained SelfStage helper gets its own finite pass contract.  The
    /// extra effect time covers archive unpacking, while the later phases
    /// retain enough room to cancel, kill/reap and durably close its WAL edge.
    pub(crate) fn default_owned_self_stage() -> Result<Self> {
        Self::new(
            Duration::from_secs(180),
            Duration::from_secs(195),
            Duration::from_secs(210),
            Duration::from_secs(225),
        )
    }
}

/// Values serialized in the pass and every leaf's Intent/Result.
/// Deserialization validates ordering and the finite maximum as strictly as
/// new admission; historical records cannot smuggle an unbounded timeout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SerializedRunBudgets")]
pub(crate) struct UpdaterRunBudgets {
    started_unix_ms: u64,
    effect_deadline_unix_ms: u64,
    quiesce_deadline_unix_ms: u64,
    terminal_deadline_unix_ms: u64,
    operation_deadline_unix_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedRunBudgets {
    started_unix_ms: u64,
    effect_deadline_unix_ms: u64,
    quiesce_deadline_unix_ms: u64,
    terminal_deadline_unix_ms: u64,
    operation_deadline_unix_ms: u64,
}

impl TryFrom<SerializedRunBudgets> for UpdaterRunBudgets {
    type Error = anyhow::Error;

    fn try_from(value: SerializedRunBudgets) -> Result<Self> {
        Self::from_absolute(
            value.started_unix_ms,
            value.effect_deadline_unix_ms,
            value.quiesce_deadline_unix_ms,
            value.terminal_deadline_unix_ms,
            value.operation_deadline_unix_ms,
        )
    }
}

impl UpdaterRunBudgets {
    pub(crate) fn from_absolute(
        started_unix_ms: u64,
        effect_deadline_unix_ms: u64,
        quiesce_deadline_unix_ms: u64,
        terminal_deadline_unix_ms: u64,
        operation_deadline_unix_ms: u64,
    ) -> Result<Self> {
        let budgets = Self {
            started_unix_ms,
            effect_deadline_unix_ms,
            quiesce_deadline_unix_ms,
            terminal_deadline_unix_ms,
            operation_deadline_unix_ms,
        };
        budgets.validate()?;
        Ok(budgets)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.started_unix_ms < self.effect_deadline_unix_ms
                && self.effect_deadline_unix_ms <= self.quiesce_deadline_unix_ms
                && self.quiesce_deadline_unix_ms <= self.terminal_deadline_unix_ms
                && self.terminal_deadline_unix_ms <= self.operation_deadline_unix_ms,
            "updater absolute deadlines must be ordered after admission"
        );
        ensure!(
            self.operation_deadline_unix_ms - self.started_unix_ms <= MAX_RUN_MILLIS,
            "updater operation budget exceeds one hour"
        );
        Ok(())
    }

    /// Stable fixed-width input for the request's domain-separated hash.
    pub(crate) fn binding_bytes(&self) -> [u8; 40] {
        let mut bytes = [0; 40];
        for (chunk, value) in bytes.chunks_exact_mut(8).zip([
            self.started_unix_ms,
            self.effect_deadline_unix_ms,
            self.quiesce_deadline_unix_ms,
            self.terminal_deadline_unix_ms,
            self.operation_deadline_unix_ms,
        ]) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
}

/// Cloning retains the original admission instant and never extends a leaf.
#[derive(Clone, Debug)]
pub(crate) struct UpdaterRunClock {
    budgets: UpdaterRunBudgets,
    deadlines: [Instant; 4],
}

impl UpdaterRunClock {
    pub(crate) fn start(limits: UpdaterRunLimits) -> Result<Self> {
        let monotonic_start = Instant::now();
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("updater admission wall clock precedes Unix epoch")?;
        Self::from_clock_sample(elapsed, monotonic_start, limits)
    }

    fn from_clock_sample(
        elapsed: Duration,
        monotonic_start: Instant,
        limits: UpdaterRunLimits,
    ) -> Result<Self> {
        // The wall sample follows the monotonic sample. Round its timestamp
        // upwards so runtime enforcement cannot extend beyond the recorded
        // deadline by the discarded fraction of an admission millisecond.
        let started_unix_ms = u64::try_from(elapsed.as_nanos().div_ceil(1_000_000))
            .context("updater admission timestamp overflow")?;
        Self::at(started_unix_ms, monotonic_start, limits)
    }

    fn at(
        started_unix_ms: u64,
        monotonic_start: Instant,
        limits: UpdaterRunLimits,
    ) -> Result<Self> {
        let mut absolute = [0; 4];
        let mut deadlines = [monotonic_start; 4];
        for (phase, offset) in UpdaterDeadlinePhase::ALL.into_iter().zip(limits.offsets_ms) {
            let index = phase.index();
            absolute[index] = started_unix_ms
                .checked_add(offset)
                .context("updater absolute deadline overflow")?;
            deadlines[index] = monotonic_start
                .checked_add(Duration::from_millis(offset))
                .context("updater monotonic deadline overflow")?;
        }
        let budgets = UpdaterRunBudgets::from_absolute(
            started_unix_ms,
            absolute[0],
            absolute[1],
            absolute[2],
            absolute[3],
        )?;
        Ok(Self { budgets, deadlines })
    }

    pub(crate) fn budgets(&self) -> &UpdaterRunBudgets {
        &self.budgets
    }

    pub(crate) fn deadline(&self, phase: UpdaterDeadlinePhase) -> Instant {
        self.deadlines[phase.index()]
    }

    pub(crate) fn remaining(&self, phase: UpdaterDeadlinePhase) -> Duration {
        self.deadline(phase)
            .saturating_duration_since(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_leaf_clocks_preserve_all_four_deadlines() {
        let start = Instant::now();
        let clock = UpdaterRunClock::at(
            1_000,
            start,
            UpdaterRunLimits::default_http_probe().unwrap(),
        )
        .unwrap();
        let leaf = clock.clone();
        for phase in [
            UpdaterDeadlinePhase::Effect,
            UpdaterDeadlinePhase::Quiesce,
            UpdaterDeadlinePhase::Terminal,
            UpdaterDeadlinePhase::Operation,
        ] {
            assert_eq!(leaf.deadline(phase), clock.deadline(phase));
        }
        assert_eq!(clock.budgets().effect_deadline_unix_ms, 121_000);
        assert_eq!(clock.budgets().quiesce_deadline_unix_ms, 136_000);
        assert_eq!(clock.budgets().terminal_deadline_unix_ms, 151_000);
        assert_eq!(clock.budgets().operation_deadline_unix_ms, 166_000);
        assert_eq!(clock.budgets().started_unix_ms, 1_000);
    }

    #[test]
    fn persisted_budget_rejects_reordering_unknown_fields_and_unbounded_span() {
        let valid = UpdaterRunBudgets::from_absolute(100, 200, 300, 400, 500).unwrap();
        let json = serde_json::to_value(&valid).unwrap();
        assert_eq!(
            serde_json::from_value::<UpdaterRunBudgets>(json.clone()).unwrap(),
            valid
        );
        let mut reordered = json.clone();
        reordered["terminal_deadline_unix_ms"] = serde_json::json!(250);
        assert!(serde_json::from_value::<UpdaterRunBudgets>(reordered).is_err());
        let mut unknown = json.clone();
        unknown["extend_on_retry"] = serde_json::json!(true);
        assert!(serde_json::from_value::<UpdaterRunBudgets>(unknown).is_err());
        let mut unbounded = json;
        unbounded["operation_deadline_unix_ms"] = serde_json::json!(u64::MAX);
        assert!(serde_json::from_value::<UpdaterRunBudgets>(unbounded).is_err());
    }

    #[test]
    fn every_absolute_deadline_is_part_of_the_canonical_binding() {
        let original = UpdaterRunBudgets::from_absolute(100, 200, 300, 400, 500).unwrap();
        for changed in [
            [101, 200, 300, 400, 500],
            [100, 201, 300, 400, 500],
            [100, 200, 301, 400, 500],
            [100, 200, 300, 401, 500],
            [100, 200, 300, 400, 501],
        ] {
            let other = UpdaterRunBudgets::from_absolute(
                changed[0], changed[1], changed[2], changed[3], changed[4],
            )
            .unwrap();
            assert_ne!(original.binding_bytes(), other.binding_bytes());
        }
    }

    #[test]
    fn admission_rejects_zero_reversed_oversized_and_overflowing_limits() {
        let one = Duration::from_secs(1);
        let two = Duration::from_secs(2);
        assert!(UpdaterRunLimits::new(Duration::ZERO, one, one, one).is_err());
        assert!(UpdaterRunLimits::new(two, one, two, two).is_err());
        assert!(UpdaterRunLimits::new(one, one, one, Duration::from_secs(3_601)).is_err());
        assert!(
            UpdaterRunClock::at(
                u64::MAX,
                Instant::now(),
                UpdaterRunLimits::default_http_probe().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn fractional_wall_sample_never_records_an_earlier_deadline_than_runtime() {
        let monotonic_start = Instant::now();
        let wall_sample = Duration::from_nanos(1_000_999_999);
        let limits = UpdaterRunLimits::new(
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
            Duration::from_millis(4),
        )
        .unwrap();
        let clock =
            UpdaterRunClock::from_clock_sample(wall_sample, monotonic_start, limits).unwrap();
        assert_eq!(clock.budgets().started_unix_ms, 1_001);
        let runtime_offset = clock.deadline(UpdaterDeadlinePhase::Effect) - monotonic_start;
        let persisted_deadline = Duration::from_millis(clock.budgets().effect_deadline_unix_ms);
        assert!(wall_sample + runtime_offset <= persisted_deadline);
        assert!(persisted_deadline - (wall_sample + runtime_offset) < Duration::from_millis(1));
    }

    #[test]
    fn exhausted_monotonic_budget_has_no_remaining_time() {
        let start = Instant::now() - Duration::from_secs(200);
        let clock = UpdaterRunClock::at(
            1_000,
            start,
            UpdaterRunLimits::default_http_probe().unwrap(),
        )
        .unwrap();
        assert_eq!(
            clock.remaining(UpdaterDeadlinePhase::Effect),
            Duration::ZERO
        );
        assert_eq!(
            clock.remaining(UpdaterDeadlinePhase::Operation),
            Duration::ZERO
        );
    }
}
