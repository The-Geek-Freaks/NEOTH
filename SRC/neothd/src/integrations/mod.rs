//! Capability and adoption-job contract foundation.
//!
//! The catalog, lifecycle state, durable store and event primitives are
//! implemented. Production daemon ownership, adapters, permission/WAL
//! orchestration, IPC and public CLI/GUI/Buddy/Doctor consumers are not wired
//! yet; these types must not be described as a completed control plane.

pub mod catalog;
pub mod events;
pub mod jobs;
pub mod state;

pub use catalog::{
    CapabilityCatalog, CapabilityCategory, CapabilityDescriptor, CapabilityId, CapabilitySurface,
    SupportTier, TargetAvailability, TargetSelector, TargetSupport, UnavailableReason,
};
pub use events::{
    IntegrationJobEvent, IntegrationJobEventKind, IntegrationJobReceiveError,
    IntegrationJobSubscription,
};
pub use jobs::{
    EnqueueIntegrationJob, EnqueueResult, IntegrationJobService, JobServiceError, RestartValidator,
    StartupRecovery,
};
pub use state::{
    CancellationEvidence, IntegrationJob, JobEvidenceContract, JobFailure, JobId, JobOperation,
    JobProgress, JobRequester, JobState, ProgressEvidence, ProgressEvidenceReceipt, ReadyEvidence,
    ReadyEvidenceReceipt, RecoveryDispositionEvidence, RestartDecision, ResumeEvidence,
    Sha256Digest,
};
