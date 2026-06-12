//! Domain-grouped diagnostic checks for `neoth doctor` (GOLD-ARCH-06).
//!
//! Each submodule owns the checks for one system domain. Adding a new
//! check means editing exactly one domain file (the check fn + its
//! registration there).

pub(crate) mod cluster;
pub(crate) mod config;
pub(crate) mod integrations;
pub(crate) mod providers;
pub(crate) mod storage;
pub(crate) mod tooling;

pub(crate) use cluster::*;
pub(crate) use config::*;
pub(crate) use integrations::*;
pub(crate) use providers::*;
pub(crate) use storage::*;
pub(crate) use tooling::*;
