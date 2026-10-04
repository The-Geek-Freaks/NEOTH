//! Feature-matrix façade for the v3 mobile companion.
//!
//! Peeroxide is an optional `cluster` dependency.  This module keeps the
//! same daemon/RPC/CLI type surface in no-cluster builds but refuses every
//! v3 operation before it can create a listener, key, writer, or authority.

use std::{path::PathBuf, sync::Arc};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::{daemon::{chat_runtime::DaemonChatRuntime, companion_protocol::{CompanionDeviceId, CompanionScope}}, wal::writer::WalWriterHandle};

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

    pub(crate) async fn mint_pair_invite(self: &Arc<Self>, _requested_scope: CompanionScope) -> Result<CompanionV3Invite> {
        bail!("companion v3 requires the cluster feature")
    }

    pub(crate) fn list_devices(&self) -> Result<Vec<CompanionV3DeviceView>> {
        bail!("companion v3 requires the cluster feature")
    }

    pub(crate) async fn revoke_device(&self, _device_id: CompanionDeviceId) -> Result<bool> {
        bail!("companion v3 requires the cluster feature")
    }
}
