//! Data types for `neoth doctor` (GOLD-ARCH-06): check status, outcome,
//! and runbook doc entry. Pure data, no I/O. Split out of `cli/doctor.rs`.

/// V03-07 2026-05-17: operator-facing documentation for each check.
/// Triggered via `neoth doctor --explain <name>`. Each entry holds:
///   - `name` — exact check identifier (matches `CheckOutcome.name`).
///   - `purpose` — one-paragraph operator-readable description of what
///     the check verifies + why it matters.
///   - `common_failures` — typical WARN/FAIL causes.
///   - `fix` — concrete commands or edits an operator can run to
///     remediate.
pub struct CheckDoc {
    pub name: &'static str,
    pub purpose: &'static str,
    pub common_failures: &'static str,
    pub fix: &'static str,
}

/// One diagnostic outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    /// Soft problem — operator should look, but daemon will start.
    Warn,
    /// Hard problem — daemon refuses to start, or behaviour will be wrong.
    Fail,
}

impl CheckStatus {
    pub fn tag(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckOutcome {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}
