//! Quorum-backed budget accounting for a fixed, authenticated voter set.

pub mod carrier;
pub mod membership_validator;
pub mod network;
pub mod raft_types;
pub mod service;
pub mod state_machine;
pub mod store;
pub mod types;

pub use carrier::BudgetPeerCarrier;
pub(crate) use membership_validator::DurableBudgetMembershipValidator;
pub use service::BudgetRaftService;

#[cfg(test)]
pub(crate) mod service_tests;
#[cfg(test)]
mod store_tests;
#[cfg(test)]
mod tests;
