//! Feature-matrix façade for the v3 mobile companion.
//!
//! Peeroxide is an optional `cluster` dependency.  This module keeps the
//! same daemon/RPC/CLI type surface in no-cluster builds but refuses every
//! v3 operation before it can create a listener, key, writer, or authority.

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    daemon::{
        chat_runtime::DaemonChatRuntime,
        companion_protocol::{CompanionDeviceId, CompanionScope},
    },
    wal::writer::WalWriterHandle,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompanionV3Invite {
    pub(crate) schema_version: u8,
    pub(crate) pair_url: String,
    pub(crate) expires_in_secs: u64,
    pub(crate) requested_scope: CompanionScope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompanionV3DeviceView {
    pub(crate) device_id: CompanionDeviceId,
    pub(crate) label: String,
    pub(crate) revision: u64,
    pub(crate) grant_state: String,
}

/// Private no-cluster placeholder for the RPC-owned prepared invite.
///
/// `prepare_pair_invite` always fails before generating a key, listener, or
/// authority. Its private field has no no-cluster constructor, so shared RPC
/// cleanup paths remain type-checkable without providing a success path.
#[derive(Debug)]
pub(crate) struct PreparedCompanionV3Invite {
    invite: CompanionV3Invite,
}

/// No-cluster builds have no pairing listener owner to retain or clean up.
pub(crate) enum AuditPairInvitePreparation {
    // Shared RPC matching requires this shape; no-cluster builds cannot create it.
    #[expect(
        dead_code,
        reason = "no-cluster pairing has no successful preparation path"
    )]
    Prepared(PreparedCompanionV3Invite),
    Refused,
}

impl PreparedCompanionV3Invite {
    pub(crate) fn invite(&self) -> &CompanionV3Invite {
        &self.invite
    }
}

#[derive(Clone)]
pub(crate) struct CompanionRuntime;

impl CompanionRuntime {
    pub(crate) fn load(
        _home: PathBuf,
        _writer: WalWriterHandle,
        _chat_runtime: Arc<DaemonChatRuntime>,
        _daemon_boot_id: String,
        _listener_generation: u64,
    ) -> Result<Arc<Self>> {
        bail!("companion v3 requires the cluster feature")
    }

    pub(crate) async fn start(self: &Arc<Self>) -> Result<()> {
        bail!("companion v3 requires the cluster feature")
    }

    pub(crate) async fn shutdown_and_drain(&self) -> Result<()> {
        bail!("companion v3 requires the cluster feature")
    }

    #[cfg(test)]
    pub(crate) async fn prepare_pair_invite(
        self: &Arc<Self>,
        _requested_scope: CompanionScope,
        _readiness_budget: Duration,
        _cancellation: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<PreparedCompanionV3Invite> {
        bail!("companion v3 requires the cluster feature")
    }

    pub(crate) async fn prepare_pair_invite_for_audit_rpc(
        self: &Arc<Self>,
        _requested_scope: CompanionScope,
        _readiness_budget: Duration,
        _cancellation: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<AuditPairInvitePreparation> {
        Ok(AuditPairInvitePreparation::Refused)
    }

    pub(crate) async fn cancel_prepared_pair_invite(
        &self,
        _prepared: PreparedCompanionV3Invite,
    ) -> Result<()> {
        bail!("companion v3 requires the cluster feature")
    }

    pub(crate) fn publish_prepared_pair_invite(
        &self,
        prepared: PreparedCompanionV3Invite,
    ) -> CompanionV3Invite {
        prepared.invite
    }

    pub(crate) fn list_devices(&self) -> Result<Vec<CompanionV3DeviceView>> {
        bail!("companion v3 requires the cluster feature")
    }

    pub(crate) async fn revoke_device(&self, _device_id: CompanionDeviceId) -> Result<bool> {
        bail!("companion v3 requires the cluster feature")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_cluster_prepare_pair_invite_refuses_before_any_invite_exists() {
        let runtime = Arc::new(CompanionRuntime);
        let (_cancel_tx, mut cancellation) = tokio::sync::watch::channel(false);

        let error = runtime
            .prepare_pair_invite(
                CompanionScope::StatusRead,
                Duration::from_secs(1),
                &mut cancellation,
            )
            .await
            .expect_err("no-cluster pairing must fail before any prepared invite exists");

        assert!(error.to_string().contains("requires the cluster feature"));
    }
}
