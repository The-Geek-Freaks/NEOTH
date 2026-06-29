//! Domain-grouped diagnostic checks for `neoth doctor` (GOLD-ARCH-06).
//!
//! Each submodule owns the checks for one system domain. Adding a new
//! check means editing exactly one domain file (the check fn + its
//! registration there).

pub(crate) mod capabilities;
pub(crate) mod cluster;
pub(crate) mod config;
pub(crate) mod integrations;
pub(crate) mod live_probes;
pub(crate) mod onboarding;
pub(crate) mod providers;
pub(crate) mod storage;
pub(crate) mod tooling;
