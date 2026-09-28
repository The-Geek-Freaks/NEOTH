//! Probed, recoverable publication of converted OpenClaw channel credentials.
//! Source custody never supplies credentials or grants transport authority.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use neoth_openclaw_custody::{
    ConvertedRelinkChannel, SelectedConvertedRelinkAccount, SourceSetBinding,
};
use sha2::{Digest as _, Sha256};

use super::{
    ChannelAddFields, ChannelTestResult, PreparedChannelAdd,
    commit_prepared_channel_add_with_relink_before_publish_at, prepare_channel_add_with_fields_at,
    test_channel_candidate_for_id,
};
use crate::channels::registry::{ChannelId, ChannelRef};
use crate::channels::relink::{self, BeginPendingOutcome, RelinkGate};
use crate::channels::routing::ChannelRouting;

const PROBE_VALIDITY: Duration = Duration::from_secs(60);

/// Secret-bearing input has no Debug implementation. The source path stays
/// private and is never copied into the durable provenance records.
pub(crate) struct ConvertedRelinkRequest {
    pub source: SelectedConvertedRelinkAccount,
    pub source_config: PathBuf,
    pub destination: ChannelRef,
    pub fields: ChannelAddFields,
    pub target: String,
}

pub(crate) struct PreparedConvertedRelink {
    prepared: PreparedChannelAdd,
    destination: ChannelRef,
    target: String,
    pending_id: String,
    request_material_sha256: String,
    expected_routing_after_sha256: String,
    routing_before: Vec<u8>,
    routing_after: ChannelRouting,
    source_config: PathBuf,
    source_channel: ConvertedRelinkChannel,
    source_label: String,
    source_binding: SourceSetBinding,
    probe_started: Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConvertedRelinkCommitOutcome {
    pending_id: String,
    already_ready: bool,
}

impl ConvertedRelinkCommitOutcome {
    pub(crate) fn pending_id(&self) -> &str {
        &self.pending_id
    }

    pub(crate) fn already_ready(&self) -> bool {
        self.already_ready
    }
}

type ProbeFuture<'a> = Pin<Box<dyn Future<Output = Result<ChannelTestResult>> + 'a>>;

pub(crate) async fn prepare_converted_relink_at(
    home: &Path,
    request: ConvertedRelinkRequest,
) -> Result<PreparedConvertedRelink> {
    prepare_converted_relink_with_probe_at(home, request, |candidate, target| {
        Box::pin(test_channel_candidate_for_id(
            candidate.channel_id,
            &candidate.candidate_config,
            &candidate.candidate_credentials,
            Some(target),
        ))
    })
    .await
}

// Tests substitute only the external transport probe. All custody reads,
// credential rendering, journals, routing CAS and Ready transitions are real.
async fn prepare_converted_relink_with_probe_at<P>(
    home: &Path,
    request: ConvertedRelinkRequest,
    probe: P,
) -> Result<PreparedConvertedRelink>
where
    P: for<'a> FnOnce(&'a PreparedChannelAdd, &'a str) -> ProbeFuture<'a>,
{
    validate_request(&request)?;
    let source_channel = request.source.channel();
    let source_label = request.source.source_account_label().to_owned();
    let source_binding = request.source.source_set().clone();
    recheck_source(
        &request.source_config,
        source_channel,
        &source_label,
        &source_binding,
    )?;
    let pending_id =
        match relink::begin_pending_at(home, &request.source, request.destination.clone())? {
            BeginPendingOutcome::Created(id) | BeginPendingOutcome::AlreadyPending(id) => {
                id.as_str().to_owned()
            }
        };
    let prepared =
        prepare_channel_add_with_fields_at(home, request.destination.channel_id, request.fields)?;
    let request_material_sha256 = relink::candidate_material_commitment(
        &prepared.candidate_credentials,
        &request.destination,
        &request.target,
    )?;
    // Capture the route before awaiting the probe, so an ordinary routing
    // mutation during verification cannot be silently folded into our commit.
    let (routing_before, mut routing_after) =
        crate::channels::routing::load_for_converted_relink_at(home)?;
    ensure!(
        routing_after.destinations.set_for_channel(
            request.destination.channel_id.as_str(),
            request.target.clone(),
        ),
        "converted relink destination cannot have an outbound route"
    );
    let expected_routing_after_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec_pretty(&routing_after)?)
    );
    let probe_started = Instant::now();
    let result = tokio::time::timeout(PROBE_VALIDITY, probe(&prepared, &request.target))
        .await
        .context("converted relink exact target probe timed out")??;
    // Provider detail can contain private endpoints. Keep this failure redacted.
    ensure!(
        result.status == "ok",
        "converted relink exact target probe did not pass"
    );
    let candidate = PreparedConvertedRelink {
        prepared,
        destination: request.destination,
        target: request.target,
        pending_id,
        request_material_sha256,
        expected_routing_after_sha256,
        routing_before,
        routing_after,
        source_config: request.source_config,
        source_channel,
        source_label,
        source_binding,
        probe_started,
    };
    recheck_candidate(&candidate)?;
    Ok(candidate)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelinkCommitCheckpoint {
    RequestReserved,
    Prepared,
    PairPublished,
    PairRecorded,
    RoutingPublished,
    RoutingRecorded,
    Ready,
}

pub(crate) fn commit_prepared_converted_relink_at(
    home: &Path,
    prepared: PreparedConvertedRelink,
) -> Result<ConvertedRelinkCommitOutcome> {
    commit_prepared_converted_relink_with_checkpoint_at(home, prepared, |_| Ok(()))
}

fn commit_prepared_converted_relink_with_checkpoint_at(
    home: &Path,
    candidate: PreparedConvertedRelink,
    mut checkpoint: impl FnMut(RelinkCommitCheckpoint) -> Result<()>,
) -> Result<ConvertedRelinkCommitOutcome> {
    // Recovery and the reentrant pair authority exclude channel/routing writers
    // through Ready publication. No network probe runs under this lock.
    crate::config::credentials::with_coherent_pair_transaction_at(
        &home.join("freedom.yaml"),
        || {
            recheck_candidate(&candidate)?;
            if let RelinkGate::Ready(id) = relink::gate_for_at(home, &candidate.destination)? {
                ensure!(
                    id.as_str() == candidate.pending_id,
                    "converted relink Ready identity differs from source custody"
                );
                ensure!(
                    relink::traffic_binding_at(home, &candidate.destination)?.as_deref()
                        == Some(candidate.request_material_sha256.as_str()),
                    "converted relink Ready material differs from the requested candidate"
                );
                return Ok(ConvertedRelinkCommitOutcome {
                    pending_id: candidate.pending_id,
                    already_ready: true,
                });
            }
            relink::reserve_request_at(
                home,
                &candidate.destination,
                &candidate.pending_id,
                &candidate.request_material_sha256,
            )?;
            checkpoint(RelinkCommitCheckpoint::RequestReserved)?;
            let token = match relink::resume_completion_at(
                home,
                &candidate.destination,
                &candidate.pending_id,
                &candidate.target,
                &candidate.request_material_sha256,
            )? {
                Some(token) => token,
                None => {
                    let actual_route =
                        crate::channels::routing::load_for_converted_relink_at(home)?.0;
                    ensure!(
                        actual_route == candidate.routing_before,
                        "converted relink routing changed during target verification"
                    );
                    let mut token = None;
                    commit_prepared_channel_add_with_relink_before_publish_at(
                        home,
                        candidate.prepared,
                        |pair| {
                            ensure!(
                                relink::pair_commitment_at(home)? == pair.before_sha256,
                                "converted relink pair changed before receipt preparation"
                            );
                            token = Some(relink::prepare_completion_at(
                                home,
                                &candidate.destination,
                                &candidate.pending_id,
                                &candidate.target,
                                &candidate.request_material_sha256,
                                &candidate.routing_before,
                                &pair.after_sha256,
                                &candidate.expected_routing_after_sha256,
                            )?);
                            checkpoint(RelinkCommitCheckpoint::Prepared)
                        },
                    )?;
                    checkpoint(RelinkCommitCheckpoint::PairPublished)?;
                    let token =
                        token.context("converted relink exact pair callback did not run")?;
                    relink::record_pair_committed_at(home, &token)?;
                    checkpoint(RelinkCommitCheckpoint::PairRecorded)?;
                    token
                }
            };
            if relink::completion_stage_at(home, &token)?
                == relink::RelinkCompletionStage::PairCommitted
            {
                let postimage =
                    crate::channels::routing::save_for_converted_relink_if_raw_matches_at(
                        home,
                        &candidate.routing_before,
                        &candidate.routing_after,
                    )?;
                checkpoint(RelinkCommitCheckpoint::RoutingPublished)?;
                relink::record_routing_committed_at(home, &token, &postimage)?;
                checkpoint(RelinkCommitCheckpoint::RoutingRecorded)?;
            }
            ensure!(
                candidate.probe_started.elapsed() < PROBE_VALIDITY,
                "converted relink target probe expired before publication; retry with a fresh probe"
            );
            recheck_source(
                &candidate.source_config,
                candidate.source_channel,
                &candidate.source_label,
                &candidate.source_binding,
            )?;
            // Ready re-reads effective credentials, exact target and GChat key
            // bytes and compares them with the reserved semantic request.
            let id = relink::mark_ready_at(home, &token)?;
            ensure!(
                id.as_str() == candidate.pending_id,
                "converted relink pending identity changed during publication"
            );
            checkpoint(RelinkCommitCheckpoint::Ready)?;
            Ok(ConvertedRelinkCommitOutcome {
                pending_id: id.as_str().to_owned(),
                already_ready: false,
            })
        },
    )
}

fn recheck_candidate(candidate: &PreparedConvertedRelink) -> Result<()> {
    ensure!(
        candidate.probe_started.elapsed() < PROBE_VALIDITY,
        "converted relink target probe expired; retry with a fresh probe"
    );
    recheck_source(
        &candidate.source_config,
        candidate.source_channel,
        &candidate.source_label,
        &candidate.source_binding,
    )?;
    ensure!(
        relink::candidate_material_commitment(
            &candidate.prepared.candidate_credentials,
            &candidate.destination,
            &candidate.target,
        )? == candidate.request_material_sha256,
        "converted relink candidate material changed after target verification"
    );
    Ok(())
}

fn validate_request(request: &ConvertedRelinkRequest) -> Result<()> {
    ensure!(
        request.destination.account_id.is_default(),
        "converted relink requires the canonical default destination"
    );
    ensure!(
        !request.target.trim().is_empty() && !request.target.chars().any(|ch| ch.is_control()),
        "converted relink target must be a non-empty control-free destination"
    );
    let expected = match request.source.channel() {
        ConvertedRelinkChannel::IMessage => ChannelId::IMessageBlueBubbles,
        ConvertedRelinkChannel::GoogleChat => ChannelId::GoogleChat,
    };
    ensure!(
        request.destination.channel_id == expected,
        "converted OpenClaw source does not match requested NEOTH destination"
    );
    Ok(())
}

fn recheck_source(
    config: &Path,
    channel: ConvertedRelinkChannel,
    label: &str,
    expected: &SourceSetBinding,
) -> Result<()> {
    let inventory = neoth_openclaw_custody::canonical_known_channel_inventory_sha256();
    let current =
        neoth_openclaw_custody::select_converted_relink_account(config, channel, label, &inventory)
            .context("reinspect converted OpenClaw source")?;
    ensure!(
        current.channel() == channel
            && current.source_account_label() == label
            && current.source_set() == expected,
        "OpenClaw source changed during converted relink; traffic remains blocked until an exact retry"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
